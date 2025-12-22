#!/usr/bin/env python3
"""
Enclave Verifier - Secure station verification with key-based identity.

Endpoints:
    POST /register - Register station with Ed25519 public key and cookie
    POST /submit_key - Submit double-signed API key for ownership verification
    GET /station/{public_key} - Get station info
    GET /broadcast - Get all verified stations

Security:
    - Three-way binding: station_id (registry) <-> email (cookie) <-> public_key (station)
    - Anti-Squatting: Email extracted server-side from cookie
    - Identity Migration: Same email can move to new key (device recovery)
    - DoS Protection: Verification runs internally, not via public endpoint
    - No /update endpoint: Cookie changes require re-registration to re-verify binding
"""

import asyncio
import hashlib
import hmac
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import httpx
from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger

from config import config, OPENROUTER_API_URL
from logging_config import setup_logging
from models import RegisterRequest, SubmitKeyRequest
from openrouter_api import OpenRouterAuth, fetch_activity_data, create_provisioning_key, cleanup_provisioning_keys
from banned import banned_manager, notify_org_banned
from challenge import check_privacy_toggles, get_random_interval, should_ban
from registry import fetch_registry_stations

# Setup logging
setup_logging()


def get_next_challenge_time() -> float:
    """Get next challenge time (current time + random interval)."""
    return time.time() + get_random_interval()


# Helper functions

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def validate_public_key(pk_hex: str) -> bool:
    """Validate Ed25519 public key format (64 hex chars = 32 bytes)."""
    if len(pk_hex) != 64:
        return False
    try:
        bytes.fromhex(pk_hex)
        return True
    except ValueError:
        return False


def generate_prov_label(station_id: str) -> str:
    """Generate deterministic provisioning key label from station_id using HMAC-SHA256."""
    return hmac.new(config.PROVISIONING_KEY_SALT, station_id.encode(), hashlib.sha256).hexdigest()[:16]


def extract_email(data: dict) -> str | None:
    """Extract email from activity data."""
    return data.get("email")


def verify_ed25519_signature(public_key_hex: str, message: str, signature_hex: str) -> bool:
    """Verify Ed25519 signature. Returns True if valid."""
    try:
        from nacl.signing import VerifyKey
        from nacl.exceptions import BadSignature
        
        public_key_bytes = bytes.fromhex(public_key_hex)
        signature_bytes = bytes.fromhex(signature_hex)
        message_bytes = message.encode()
        
        verify_key = VerifyKey(public_key_bytes)
        verify_key.verify(message_bytes, signature_bytes)
        return True
    except (BadSignature, ValueError, Exception) as e:
        logger.debug(f"Signature verification failed: {e}")
        return False


def compute_key_hash(api_key: str) -> str:
    """Compute SHA256 hash of API key (matches OpenRouter key hash format)."""
    return hashlib.sha256(api_key.encode()).hexdigest()


# Cached org public key
_org_public_key: str | None = None
_org_pk_lock = asyncio.Lock()


async def fetch_org_public_key() -> str | None:
    """Fetch org's public key from /verifier/pub_key endpoint. Cached after first fetch."""
    global _org_public_key
    
    async with _org_pk_lock:
        if _org_public_key:
            return _org_public_key
        
        if not config.REGISTRY_URL:
            logger.error("REGISTRY_URL not configured")
            return None
        
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(f"{config.REGISTRY_URL}/verifier/pub_key", timeout=15)
                if resp.status_code == 200:
                    data = resp.json()
                    _org_public_key = data.get("public_key")
                    if _org_public_key:
                        logger.info(f"Fetched org public key: {_org_public_key[:16]}...")
                        return _org_public_key
                logger.error(f"Failed to fetch org public key: {resp.status_code}")
        except Exception as e:
            logger.error(f"Error fetching org public key: {e}")
        return None


async def verify_key_ownership(provisioning_key: str, key_hash: str) -> bool:
    """
    Verify that a key belongs to the station's OR account.
    
    Calls: GET https://openrouter.ai/api/v1/keys/{key_hash}
    with the station's provisioning key for authorization.
    
    Returns True if key is found (owned by account), False otherwise.
    """
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(
                f"{OPENROUTER_API_URL}/keys/{key_hash}",
                headers={"Authorization": f"Bearer {provisioning_key}"},
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("data", {}).get("hash") == key_hash:
                    logger.debug(f"Key ownership verified for hash {key_hash[:16]}...")
                    return True
                logger.warning(f"Key hash mismatch: expected {key_hash[:16]}")
                return False
            elif resp.status_code == 404:
                logger.warning(f"Key not found for hash {key_hash[:16]}...")
                return False
            else:
                logger.error(f"Key verification failed: {resp.status_code}")
                return False
        except Exception as e:
            logger.error(f"Key verification error: {e}")
            return False


# In-memory storage (never persisted for enclave security)
_stations: dict = {}
_email_to_pk: dict = {}
_station_id_to_pk: dict = {}  # station_id -> public_key mapping
_lock = asyncio.Lock()


async def _challenge_one_station(pk: str, station_data: dict) -> None:
    """Challenge a single station by checking privacy toggles. Runs concurrently."""
    station_id = station_data.get("station_id", pk[:16])
    station_email = station_data.get("email", "")
    cookie_data = station_data.get("cookie_data")
    
    # Skip if banned
    if await banned_manager.is_banned(station_id=station_id, public_key=pk):
        async with _lock:
            if pk in _stations:
                del _stations[pk]
                if station_email and station_email in _email_to_pk:
                    del _email_to_pk[station_email]
                if station_id and station_id in _station_id_to_pk:
                    del _station_id_to_pk[station_id]
                logger.info(f"Removed banned station {station_id} from registry")
        return
    
    logger.info(f"Checking privacy toggles for station {station_id}...")
    
    # Only check privacy toggles
    passed = False
    reason = ""
    try:
        if not cookie_data:
            reason = "no_cookie_data"
        else:
            auth = await asyncio.to_thread(OpenRouterAuth.from_dict, cookie_data, False)
            activity_data = await fetch_activity_data(auth)
            if not activity_data:
                reason = "activity_fetch_failed"
            else:
                privacy_ok, invalid_toggles = check_privacy_toggles(activity_data)
                if privacy_ok:
                    passed = True
                else:
                    reason = f"privacy_toggles_invalid:[{','.join(invalid_toggles)}]"
                    logger.error(f"Station {station_id} failed privacy toggle check: {invalid_toggles}")
    except Exception as e:
        logger.error(f"Challenge error for {station_id}: {e}")
        reason = f"challenge_exception:{e}"
    
    async with _lock:
        if pk in _stations:
            # Schedule next challenge (independent per station)
            _stations[pk]["next_challenge_at"] = get_next_challenge_time()
            
            if passed:
                _stations[pk]["last_verified"] = utc_now()
                logger.info(f"Privacy toggles OK for {station_id}")
            else:
                _stations[pk]["last_verified"] = None
                logger.warning(f"Verification FAILED for {station_id}: {reason}")
                
                if should_ban(reason):
                    await banned_manager.ban_station(station_id, pk, station_email, reason)


async def verification_loop():
    """Background task that challenges stations on their individual schedules."""
    logger.info(f"Verification loop started (interval: {config.CHALLENGE_MIN_INTERVAL}-{config.CHALLENGE_MAX_INTERVAL}s per station)")
    
    while True:
        await asyncio.sleep(1)  # Check every second for due challenges
        
        now = time.time()
        stations_due = []
        
        # Find all stations due for challenge
        async with _lock:
            for pk, data in list(_stations.items()):
                next_challenge = data.get("next_challenge_at", 0)
                if now >= next_challenge:
                    stations_due.append((pk, data.copy()))
        
        # Challenge all due stations concurrently
        if stations_due:
            await asyncio.gather(*[
                _challenge_one_station(pk, station_data)
                for pk, station_data in stations_due
            ], return_exceptions=True)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage background task lifecycles."""
    verification_task = asyncio.create_task(verification_loop())
    yield
    verification_task.cancel()
    try:
        await verification_task
    except asyncio.CancelledError:
        pass


app = FastAPI(title="Enclave Verifier", version="1.0.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post("/register")
async def register(req: RegisterRequest):
    """Register a station with key-based identity."""
    if not validate_public_key(req.public_key):
        logger.warning(f"Registration rejected: invalid public key format ({req.public_key[:16]}...)")
        raise HTTPException(status_code=400, detail="Invalid Ed25519 public key (need 64 hex chars)")
    
    # Check if already banned by public key FIRST
    if await banned_manager.is_banned(public_key=req.public_key):
        banned_station_id = await banned_manager.get_station_id_by_pk(req.public_key) or f"pk:{req.public_key[:16]}"
        logger.warning(f"Registration rejected: {banned_station_id} is BANNED")
        await notify_org_banned(banned_station_id, "banned_reregister_attempt")
        raise HTTPException(status_code=403, detail="Station is banned")
    
    try:
        auth = await asyncio.to_thread(OpenRouterAuth.from_dict, req.cookie_data, False)
        data = await fetch_activity_data(auth)
        if not data:
            logger.warning(f"Registration rejected: failed to verify cookie for {req.public_key[:16]}...")
            raise HTTPException(status_code=401, detail="Failed to verify cookie")
        
        email = extract_email(data)
        if not email:
            logger.warning(f"Registration rejected: could not extract email for {req.public_key[:16]}...")
            raise HTTPException(status_code=401, detail="Could not extract email from account")
        
    except HTTPException:
        raise
    except Exception as e:
        logger.warning(f"Registration rejected: cookie verification failed for {req.public_key[:16]}... - {e}")
        raise HTTPException(status_code=401, detail=f"Cookie verification failed: {e}")
    
    # Validate against station registry
    registry_stations = await fetch_registry_stations()
    station_id = None
    if registry_stations:
        logger.info(f"Cookie email: {email}")
        registry_entry = next(
            (s for s in registry_stations if s.get("or_account_email") == email),
            None
        )
        if not registry_entry:
            logger.error(f"No station registered for email: {email}")
            raise HTTPException(status_code=404, detail="No station registered for this email in registry")
        station_id = registry_entry.get("station_id")
        
        if await banned_manager.is_banned(station_id=station_id):
            logger.warning(f"Registration rejected: station {station_id} is BANNED")
            await notify_org_banned(station_id, "banned_reregister_attempt")
            raise HTTPException(status_code=403, detail="Station is banned")
        
        logger.info(f"Three-way binding: {station_id} ↔ {email} ↔ {req.public_key[:16]}...")
    
    # Verify privacy toggles immediately
    privacy_ok, invalid_toggles = check_privacy_toggles(data)

    if not privacy_ok:
        reason = f"privacy_toggles_invalid_on_register:[{','.join(invalid_toggles)}]"
        logger.error(f"Registration rejected: station {station_id} FAILED privacy toggle check - BANNING: {invalid_toggles}")
        await banned_manager.ban_station(station_id or "unknown", req.public_key, email, reason)
        raise HTTPException(status_code=403, detail="Privacy toggles not properly configured. Station banned.")
    
    now = utc_now()
    
    # Check for existing provisioning key
    existing_prov_key = None
    async with _lock:
        if req.public_key in _stations:
            existing_prov_key = _stations[req.public_key].get("provisioning_key")
        elif email in _email_to_pk:
            old_pk = _email_to_pk[email]
            if old_pk in _stations:
                existing_prov_key = _stations[old_pk].get("provisioning_key")
    
    # Create provisioning key if needed
    provisioning_key = existing_prov_key
    if station_id and not provisioning_key:
        label = generate_prov_label(station_id)
        # Cleanup any existing keys with this label before creating new one
        await cleanup_provisioning_keys(auth, label)
        provisioning_key = await create_provisioning_key(auth, label)
        if not provisioning_key:
            raise HTTPException(status_code=500, detail="Failed to create provisioning key")
        logger.info(f"Created provisioning key for {station_id} with label {label}")
    
    async with _lock:
        # Identity migration: if email already registered, remove old entry
        if email in _email_to_pk:
            old_pk = _email_to_pk[email]
            if old_pk != req.public_key and old_pk in _stations:
                old_station_id = _stations[old_pk].get("station_id")
                del _stations[old_pk]
                if old_station_id and old_station_id in _station_id_to_pk:
                    del _station_id_to_pk[old_station_id]
        
        _stations[req.public_key] = {
            "station_id": station_id,
            "email": email,
            "display_name": req.display_name,
            "cookie_data": req.cookie_data,
            "registered_at": now,
            "last_verified": now,
            "provisioning_key": provisioning_key,
            "next_challenge_at": get_next_challenge_time(),  # Independent challenge schedule
        }
        _email_to_pk[email] = req.public_key
        if station_id:
            _station_id_to_pk[station_id] = req.public_key
    
    logger.info(f"Station {station_id} registered successfully")
    
    return {
        "status": "registered",
        "station_id": station_id,
        "public_key": req.public_key,
        "email": email,
        "verified": True,
    }


@app.post("/submit_key")
async def submit_key(req: SubmitKeyRequest):
    """
    Submit a double-signed API key for ownership verification.
    
    Double signature verification:
    1. Inner: station signs "station_id|api_key|key_valid_till" with station's private key
    2. Outer: org signs "station_id|api_key|key_valid_till|station_signature" with org's private key
    
    If signatures are valid, immediately verifies key ownership via OpenRouter API.
    Bans station if key doesn't belong to their account.
    """
    # Look up station data
    async with _lock:
        public_key = _station_id_to_pk.get(req.station_id)
        station_data = None
        if public_key and public_key in _stations:
            station_data = _stations[public_key].copy()
    
    if not public_key or not station_data:
        raise HTTPException(status_code=404, detail="Station not registered")
    
    provisioning_key = station_data.get("provisioning_key")
    station_email = station_data.get("email", "")
    
    if not provisioning_key:
        raise HTTPException(status_code=400, detail="Station has no provisioning key")
    
    # Check if banned
    if await banned_manager.is_banned(station_id=req.station_id):
        raise HTTPException(status_code=403, detail="Station is banned")
    
    # Verify inner signature (station): message = "station_id|api_key|key_valid_till"
    inner_message = f"{req.station_id}|{req.api_key}|{req.key_valid_till}"
    if not verify_ed25519_signature(public_key, inner_message, req.station_signature):
        logger.warning(f"Invalid station signature for key submission from {req.station_id}")
        raise HTTPException(status_code=401, detail="Invalid station signature")
    
    # Verify outer signature (org): message = "station_id|api_key|key_valid_till|station_signature"
    org_public_key = await fetch_org_public_key()
    if not org_public_key:
        raise HTTPException(status_code=503, detail="Could not fetch org public key")
    
    outer_message = f"{req.station_id}|{req.api_key}|{req.key_valid_till}|{req.station_signature}"
    if not verify_ed25519_signature(org_public_key, outer_message, req.org_signature):
        logger.warning(f"Invalid org signature for key submission from {req.station_id}")
        raise HTTPException(status_code=401, detail="Invalid org signature")
    
    # Check key hasn't already expired
    now = int(time.time())
    if req.key_valid_till <= now:
        raise HTTPException(status_code=400, detail="Key already expired")
    
    # Immediately verify key ownership via OpenRouter API
    key_hash = compute_key_hash(req.api_key)
    if not await verify_key_ownership(provisioning_key, key_hash):
        # Key doesn't belong to station - BAN immediately
        reason = "key_not_owned"
        logger.error(f"Key {key_hash[:16]}... not owned by station {req.station_id} - BANNING")
        await banned_manager.ban_station(req.station_id, public_key, station_email, reason)
        
        # Remove from active stations
        async with _lock:
            if public_key in _stations:
                del _stations[public_key]
            if station_email and station_email in _email_to_pk:
                del _email_to_pk[station_email]
            if req.station_id in _station_id_to_pk:
                del _station_id_to_pk[req.station_id]
        
        raise HTTPException(status_code=403, detail="Key not owned by station account. Station banned.")
    
    logger.info(f"Key ownership verified for {req.station_id}: {key_hash[:16]}...")
    return {"status": "verified", "station_id": req.station_id, "key_hash": key_hash[:16]}


@app.get("/station/{public_key}")
async def get_station(public_key: str):
    """Get station info by public key."""
    async with _lock:
        station = _stations.get(public_key)
        if not station:
            raise HTTPException(status_code=404, detail="Station not found")
        return {
            "station_id": station.get("station_id"),
            "public_key": public_key,
            "display_name": station["display_name"],
        }


@app.get("/broadcast")
async def broadcast():
    """Get list of all verified stations and banned stations."""
    async with _lock:
        verified = [
            {
                "station_id": data.get("station_id"),
                "public_key": pk,
                "display_name": data["display_name"],
            }
            for pk, data in _stations.items()
            if data["last_verified"] is not None
        ]
    
    banned = await banned_manager.get_all()
    
    return {
        "verified_stations": verified,
        "banned_stations": banned,
    }


@app.get("/banned-stations")
async def get_banned_stations():
    """Get list of banned stations (station_id and public_key only, no email)."""
    banned = await banned_manager.get_all()
    return {"banned_stations": banned, "count": len(banned)}


@app.post("/reload-config")
async def reload_config(authorization: str = Header(None)):
    """Reload configuration from .env file (requires auth)."""
    if not config.REGISTRY_SECRET:
        raise HTTPException(status_code=503, detail="Registry secret not configured")
    
    expected = f"Bearer {config.REGISTRY_SECRET}"
    if authorization != expected:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    config.reload()
    logger.info("Configuration reloaded from .env")
    return {
        "status": "reloaded",
        "challenge_interval": {
            "min_seconds": config.CHALLENGE_MIN_INTERVAL,
            "max_seconds": config.CHALLENGE_MAX_INTERVAL,
        },
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
