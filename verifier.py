#!/usr/bin/env python3
"""
Enclave Verifier - Secure station verification with key-based identity.

Endpoints:
    POST /register - Register station with Ed25519 public key and cookie
    POST /add-invitation - Add invitation code to get Privacy Pass tickets
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
import json
import logging
import os
import secrets
import sys
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, List

import httpx
from dotenv import load_dotenv
from loguru import logger

# Configure loguru
logger.remove()
logger.add(
    sys.stderr,
    format="<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
    level="DEBUG",
)


class InterceptHandler(logging.Handler):
    """Intercept standard logging and redirect to loguru."""
    def emit(self, record):
        try:
            level = logger.level(record.levelname).name
        except ValueError:
            level = record.levelno
        frame, depth = logging.currentframe(), 2
        while frame.f_code.co_filename == logging.__file__:
            frame = frame.f_back
            depth += 1
        logger.opt(depth=depth, exception=record.exc_info).log(level, record.getMessage())


# Intercept uvicorn and httpx logs
logging.getLogger("uvicorn").handlers = [InterceptHandler()]
logging.getLogger("uvicorn.access").handlers = [InterceptHandler()]
logging.getLogger("uvicorn.error").handlers = [InterceptHandler()]
logging.getLogger("httpx").handlers = [InterceptHandler()]
logging.getLogger("httpx").setLevel(logging.INFO)

from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from openrouter_auth import OpenRouterAuth

# Privacy Pass library for ticket management
try:
    import privacypass_py as pp
    PRIVACY_PASS_AVAILABLE = True
except ImportError:
    PRIVACY_PASS_AVAILABLE = False
    pp = None
    logger.warning("privacypass-py not available - ticket functionality disabled")

load_dotenv()

REGISTRY_URL = os.getenv("STATION_REGISTRY_URL")
REGISTRY_SECRET = os.getenv("STATION_REGISTRY_SECRET")
PROVISIONING_KEY_SALT = os.getenv("PROVISIONING_KEY_SALT", "").encode() or b"default_dev_salt"

# Challenge interval configuration (seconds)
CHALLENGE_MIN_INTERVAL = int(os.getenv("CHALLENGE_MIN_INTERVAL", "300"))  # 5 minutes default
CHALLENGE_MAX_INTERVAL = int(os.getenv("CHALLENGE_MAX_INTERVAL", "600"))  # 10 minutes default



# ============================================================================
# Generation Verification (using OpenRouter API with provisioning key)
# ============================================================================

async def _verify_generation(provisioning_key: str, generation_id: str, retries: int = 3) -> dict | None:
    """
    Verify a generation exists using the station's provisioning key.
    
    Returns the generation data if found, None otherwise.
    Uses: GET https://openrouter.ai/api/v1/generation?id=<generation_id>
    
    Retries with delay since generations may take a moment to be indexed.
    """
    async with httpx.AsyncClient() as client:
        for attempt in range(retries):
            try:
                resp = await client.get(
                    "https://openrouter.ai/api/v1/generation",
                    params={"id": generation_id},
                    headers={"Authorization": f"Bearer {provisioning_key}"},
                    timeout=15,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    return data.get("data")
                elif resp.status_code == 404:
                    if attempt < retries - 1:
                        # Generation might not be indexed yet, wait and retry
                        await asyncio.sleep(2)
                        continue
                    logger.warning(f"Generation {generation_id} not found after {retries} attempts")
                    return None
                else:
                    logger.error(f"Generation verification failed: {resp.status_code}")
                    return None
            except Exception as e:
                logger.error(f"Generation verification error: {e}")
                if attempt < retries - 1:
                    await asyncio.sleep(1)
                    continue
                return None
    return None


# ============================================================================
# Ticket Management (Privacy Pass)
# ============================================================================

@dataclass
class InferenceTicket:
    """Represents a single inference ticket."""
    blinded_request: str
    signed_response: str
    finalized_ticket: str
    used: bool = False
    used_at: Optional[float] = None
    
    def to_dict(self) -> dict:
        return {
            "blinded_request": self.blinded_request,
            "signed_response": self.signed_response,
            "finalized_ticket": self.finalized_ticket,
            "used": self.used,
            "used_at": self.used_at,
        }
    
    @classmethod
    def from_dict(cls, d: dict) -> "InferenceTicket":
        return cls(
            blinded_request=d["blinded_request"],
            signed_response=d["signed_response"],
            finalized_ticket=d["finalized_ticket"],
            used=d.get("used", False),
            used_at=d.get("used_at"),
        )


# Ticket storage file path
TICKETS_FILE = os.getenv("TICKETS_FILE", "tickets.json")


class TicketManager:
    """Persistent ticket storage (survives restarts)."""
    
    def __init__(self, filepath: str = TICKETS_FILE):
        self._filepath = filepath
        self._tickets: List[InferenceTicket] = []
        self._lock = asyncio.Lock()
        self._load()
    
    def _load(self) -> None:
        """Load tickets from file."""
        if os.path.exists(self._filepath):
            try:
                with open(self._filepath, "r") as f:
                    data = json.load(f)
                self._tickets = [InferenceTicket.from_dict(t) for t in data]
                logger.info(f"Loaded {len(self._tickets)} tickets from {self._filepath}")
            except Exception as e:
                logger.error(f"Failed to load tickets: {e}")
                self._tickets = []
    
    def _save(self) -> None:
        """Save tickets to file."""
        try:
            with open(self._filepath, "w") as f:
                json.dump([t.to_dict() for t in self._tickets], f)
        except Exception as e:
            logger.error(f"Failed to save tickets: {e}")
    
    async def add_tickets(self, tickets: List[InferenceTicket]) -> int:
        """Add tickets to the store. Returns new total count."""
        async with self._lock:
            self._tickets.extend(tickets)
            self._save()
            return len(self._tickets)
    
    async def get_next_ticket(self) -> Optional[InferenceTicket]:
        """Get next unused ticket."""
        async with self._lock:
            for ticket in self._tickets:
                if not ticket.used:
                    return ticket
            return None
    
    async def mark_ticket_used(self, ticket: InferenceTicket) -> None:
        """Mark a ticket as used."""
        async with self._lock:
            for t in self._tickets:
                if t.finalized_ticket == ticket.finalized_ticket and not t.used:
                    t.used = True
                    t.used_at = datetime.now(timezone.utc).timestamp()
                    self._save()
                    break
    
    async def get_stats(self) -> dict:
        """Get ticket usage statistics."""
        async with self._lock:
            total = len(self._tickets)
            used = sum(1 for t in self._tickets if t.used)
            return {"total": total, "used": used, "available": total - used}
    
    async def clear(self) -> None:
        """Clear all tickets."""
        async with self._lock:
            self._tickets.clear()
            self._save()


# Global ticket manager instance
_ticket_manager = TicketManager()


# ============================================================================
# Banned Stations Tracking (persistent)
# ============================================================================

BANNED_STATIONS_FILE = os.getenv("BANNED_STATIONS_FILE", "banned_stations.json")


@dataclass
class BannedStation:
    """Represents a banned station."""
    station_id: str
    public_key: str
    email: str  # Stored but not exposed in API
    reason: str
    banned_at: str
    
    def to_dict(self) -> dict:
        """Full dict for file storage (includes email)."""
        return {
            "station_id": self.station_id,
            "public_key": self.public_key,
            "email": self.email,
            "reason": self.reason,
            "banned_at": self.banned_at,
        }
    
    def to_public_dict(self) -> dict:
        """Public dict for API (no email)."""
        return {
            "station_id": self.station_id,
            "public_key": self.public_key,
            "reason": self.reason,
            "banned_at": self.banned_at,
        }
    
    @classmethod
    def from_dict(cls, d: dict) -> "BannedStation":
        return cls(
            station_id=d["station_id"],
            public_key=d["public_key"],
            email=d.get("email", ""),  # Backwards compatible
            reason=d["reason"],
            banned_at=d["banned_at"],
        )


async def _notify_org_banned(station_id: str, reason: str) -> None:
    """Notify org about a banned station or re-registration attempt."""
    if not REGISTRY_URL or not REGISTRY_SECRET:
        return
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{REGISTRY_URL}/resources/banned_stations",
                headers={"Authorization": f"Bearer {REGISTRY_SECRET}", "Content-Type": "application/json"},
                json={"station_id": station_id, "reason": reason},
                timeout=10,
            )
            if resp.status_code == 200:
                logger.info(f"Notified org about banned station {station_id}")
            else:
                logger.warning(f"Failed to notify org about ban: {resp.status_code}")
    except Exception as e:
        logger.warning(f"Failed to notify org about ban: {e}")


class BannedStationManager:
    """Persistent banned station storage."""
    
    def __init__(self, filepath: str = BANNED_STATIONS_FILE):
        self._filepath = filepath
        self._stations: List[BannedStation] = []
        self._lock = asyncio.Lock()
        self._load()
    
    def _load(self) -> None:
        """Load banned stations from file."""
        if os.path.exists(self._filepath):
            try:
                with open(self._filepath, "r") as f:
                    data = json.load(f)
                self._stations = [BannedStation.from_dict(s) for s in data]
                logger.info(f"Loaded {len(self._stations)} banned stations from {self._filepath}")
            except Exception as e:
                logger.error(f"Failed to load banned stations: {e}")
                self._stations = []
    
    def _save(self) -> None:
        """Save banned stations to file."""
        try:
            with open(self._filepath, "w") as f:
                json.dump([s.to_dict() for s in self._stations], f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save banned stations: {e}")
    
    async def ban_station(self, station_id: str, public_key: str, email: str, reason: str) -> None:
        """Add a station to the banned list and notify org."""
        async with self._lock:
            # Check if already banned
            for s in self._stations:
                if s.station_id == station_id and s.public_key == public_key:
                    return  # Already banned
            
            banned = BannedStation(
                station_id=station_id,
                public_key=public_key,
                email=email,
                reason=reason,
                banned_at=datetime.now(timezone.utc).isoformat(),
            )
            self._stations.append(banned)
            self._save()
            logger.warning(f"Banned station {station_id}: {reason}")
        
        # Notify org (outside lock)
        await _notify_org_banned(station_id, reason)
    
    async def get_all(self) -> List[dict]:
        """Get all banned stations (no email exposed)."""
        async with self._lock:
            return [s.to_public_dict() for s in self._stations]
    
    async def is_banned(self, station_id: str = None, public_key: str = None) -> bool:
        """Check if a station is banned by station_id or public_key."""
        async with self._lock:
            for s in self._stations:
                if station_id and s.station_id == station_id:
                    return True
                if public_key and s.public_key == public_key:
                    return True
            return False
    
    async def get_station_id_by_pk(self, public_key: str) -> str | None:
        """Get station_id for a banned public key."""
        async with self._lock:
            for s in self._stations:
                if s.public_key == public_key:
                    return s.station_id
            return None


# Global banned station manager
_banned_manager = BannedStationManager()


async def _register_invitation_code(credential: str) -> dict:
    """
    Register an invitation code and issue Privacy Pass tickets.
    
    The invitation code format: 20 hex chars + 4 hex chars (ticket count).
    """
    if not PRIVACY_PASS_AVAILABLE:
        raise RuntimeError("Privacy Pass library not available")
    
    if len(credential) != 24:
        raise ValueError(f"Invalid invitation code length: expected 24 characters, got {len(credential)}")
    
    # Decode ticket count from last 4 hex chars
    suffix = credential[20:24]
    try:
        ticket_count = int(suffix, 16)
    except ValueError:
        raise ValueError("Invalid invitation code: last 4 characters must be hexadecimal")
    
    if ticket_count == 0:
        raise ValueError("Invalid invitation code: ticket count is zero")
    
    logger.info(f"Registering invitation code for {ticket_count} tickets...")
    
    async with httpx.AsyncClient() as client:
        # Step 1: Get public key
        resp = await client.get(f"{REGISTRY_URL}/api/ticket/issue/public-key", timeout=15)
        if resp.status_code != 200:
            raise RuntimeError(f"Failed to get public key: {resp.status_code}")
        public_key = resp.json()["public_key"]
        
        # Step 2: Create blinded requests
        privacy_client = pp.TokenClient()
        indexed_blinded_requests = []
        client_states = []
        
        for i in range(ticket_count):
            challenge = pp.TokenChallenge.create("oa-station", ["oa-station-api"])
            request, state = privacy_client.create_token_request(public_key, challenge)
            indexed_blinded_requests.append((i, request))
            client_states.append((i, state))
        
        logger.info(f"Created {ticket_count} blinded requests")
        
        # Step 3: Send to server for signing
        timeout_seconds = max(120.0, ticket_count * 0.05)
        resp = await client.post(
            f"{REGISTRY_URL}/api/alpha-register",
            json={"credential": credential, "blinded_requests": indexed_blinded_requests},
            timeout=timeout_seconds,
        )
        if resp.status_code != 200:
            error_detail = resp.json().get("detail", resp.text) if resp.headers.get("content-type", "").startswith("application/json") else resp.text
            raise RuntimeError(f"Alpha register failed: {error_detail}")
        
        issue_response = resp.json()
        indexed_signed_responses = issue_response["signed_responses"]
        
        # Step 4: Finalize tickets
        response_map = {idx: signed_resp for idx, signed_resp in indexed_signed_responses}
        tickets = []
        
        for idx, state in client_states:
            if idx not in response_map:
                raise RuntimeError(f"Missing signed response for ticket index {idx}")
            
            signed_response = response_map[idx]
            blinded_request = indexed_blinded_requests[idx][1]
            finalized_ticket = privacy_client.finalize_token(signed_response, state)
            
            tickets.append(InferenceTicket(
                blinded_request=blinded_request,
                signed_response=signed_response,
                finalized_ticket=finalized_ticket,
            ))
        
        # Step 5: Store tickets
        total = await _ticket_manager.add_tickets(tickets)
        logger.info(f"Added {len(tickets)} tickets. Total available: {total}")
        
        return {
            "success": True,
            "tickets_issued": len(tickets),
            "total_available": total,
            "expires_at": issue_response.get("expires_at"),
        }


# ============================================================================
# Challenge System
# ============================================================================

async def _get_online_stations() -> dict:
    """Fetch online stations from OA Org."""
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(f"{REGISTRY_URL}/api/v2/online", timeout=15)
            if resp.status_code == 200:
                return resp.json()
        except Exception as e:
            logger.error(f"Failed to fetch online stations: {e}")
    return {}


async def _request_api_key(station_url: str, ticket: InferenceTicket) -> dict | None:
    """
    Request an API key from a station using an inference ticket.
    
    Returns the API key response or None on failure.
    """
    normalized_url = station_url.rstrip("/")
    request_key_url = f"{normalized_url}/api/v2/request_key"
    
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"InferenceTicket token={ticket.finalized_ticket}",
    }
    
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(
                request_key_url,
                headers=headers,
                json={"name": "verifier-challenge"},
                timeout=30,
            )
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 401:
                logger.warning(f"Ticket rejected by station (401)")
                return None
            else:
                logger.error(f"Request key failed: {resp.status_code}")
                return None
        except Exception as e:
            logger.error(f"Request key error: {e}")
            return None


async def _make_test_inference(api_key: str, model: str = "openai/gpt-4o-mini") -> str | None:
    """
    Make a minimal test inference request to get a generation ID.
    
    Returns the generation ID from the response header.
    """
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": "ping"}],
                    "max_tokens": 1,
                },
                timeout=30,
            )
            if resp.status_code == 200:
                # Generation ID is in x-request-id or id field in response
                generation_id = resp.headers.get("x-request-id")
                if not generation_id:
                    data = resp.json()
                    generation_id = data.get("id")
                return generation_id
            else:
                logger.error(f"Test inference failed: {resp.status_code}")
                return None
        except Exception as e:
            logger.error(f"Test inference error: {e}")
            return None


async def _challenge_station(public_key: str, station_data: dict) -> tuple[bool, str]:
    """
    Challenge a station by:
    1. Verifying privacy toggles via POST /activity
    2. Getting an API key from the station using a ticket
    3. Making a test inference
    4. Verifying the generation exists via OpenRouter API with provisioning key
    
    Returns (passed: bool, failure_reason: str)
    """
    station_id = station_data.get("station_id", public_key[:16])
    provisioning_key = station_data.get("provisioning_key")
    cookie_data = station_data.get("cookie_data")
    
    if not provisioning_key:
        return False, "no_provisioning_key"
    
    if not cookie_data:
        return False, "no_cookie_data"
    
    # Step 1: Verify privacy toggles
    try:
        auth = await asyncio.to_thread(OpenRouterAuth.from_dict, cookie_data, False)
        activity_data = await _fetch_activity_data(auth)
        if not activity_data:
            return False, "activity_fetch_failed"
        
        privacy_ok, invalid_toggles = _check_privacy_toggles(activity_data)
        if not privacy_ok:
            reason = f"privacy_toggles_invalid:[{','.join(invalid_toggles)}]"
            logger.error(f"Station {station_id} failed privacy toggle check: {invalid_toggles}")
            return False, reason
    except Exception as e:
        logger.error(f"Failed to check privacy toggles for {station_id}: {e}")
        return False, "privacy_check_error"
    
    # Step 2: Get a ticket
    ticket = await _ticket_manager.get_next_ticket()
    if not ticket:
        logger.warning("No tickets available for challenge")
        return False, "no_tickets"  # Don't ban for this - it's our issue
    
    # Step 3: Get online stations to find this station's URL
    online_stations = await _get_online_stations()
    
    station_info = online_stations.get(station_id)
    if not station_info:
        logger.warning(f"Station {station_id} not found in online stations")
        return False, "station_offline"  # Don't ban - station might just be offline
    
    station_url = station_info.get("url")
    if not station_url:
        return False, "no_station_url"
    
    # Step 4: Request API key from station
    # Mark ticket as used BEFORE sending - once sent, it's consumed regardless of response
    await _ticket_manager.mark_ticket_used(ticket)
    
    key_response = await _request_api_key(station_url, ticket)
    if not key_response:
        return False, "api_key_request_failed"
    
    api_key = key_response.get("key")
    if not api_key:
        return False, "no_api_key_in_response"
    
    # Step 5: Make test inference
    generation_id = await _make_test_inference(api_key)
    if not generation_id:
        return False, "test_inference_failed"
    
    # Step 6: Verify generation exists using provisioning key
    gen_data = await _verify_generation(provisioning_key, generation_id)
    if not gen_data:
        logger.error(f"Generation {generation_id} not found for station {station_id}")
        return False, "generation_not_found"
    
    logger.info(f"Challenge passed for station {station_id}: generation {generation_id} verified")
    return True, ""


def _get_random_interval() -> float:
    """Get cryptographically secure random interval between challenges."""
    range_size = CHALLENGE_MAX_INTERVAL - CHALLENGE_MIN_INTERVAL
    if range_size <= 0:
        return float(CHALLENGE_MIN_INTERVAL)
    return float(CHALLENGE_MIN_INTERVAL + secrets.randbelow(range_size + 1))


def _should_ban(reason: str) -> bool:
    """Check if a failure reason should result in banning."""
    # Reasons that should result in banning (station's fault, not ours)
    # Note: api_key_request_failed is NOT a ban reason - could be temporary (503 etc)
    BAN_PREFIXES = ("privacy_toggles_invalid", "generation_not_found", "no_api_key_in_response")
    return reason.startswith(BAN_PREFIXES)


async def _verification_loop():
    """Background task that randomly challenges stations."""
    logger.info(f"Verification loop started (interval: {CHALLENGE_MIN_INTERVAL}-{CHALLENGE_MAX_INTERVAL}s)")
    
    while True:
        interval = _get_random_interval()
        await asyncio.sleep(interval)
        
        async with _lock:
            if not _stations:
                continue
            # Cryptographically secure random station selection, skip banned stations
            station_keys = list(_stations.keys())
            pk = secrets.choice(station_keys)
            station_data = _stations[pk].copy()
        
        station_id = station_data.get("station_id", pk[:16])
        
        # Remove banned stations from pool entirely
        if await _banned_manager.is_banned(station_id=station_id, public_key=pk):
            async with _lock:
                if pk in _stations:
                    del _stations[pk]
                    email = station_data.get("email")
                    if email and email in _email_to_pk:
                        del _email_to_pk[email]
                    logger.info(f"Removed banned station {station_id} from challenge pool")
            continue
        
        station_email = station_data.get("email", "")
        logger.info(f"Challenging station {station_id}...")
        passed, reason = await _challenge_station(pk, station_data)
        
        async with _lock:
            if pk in _stations:
                if passed:
                    _stations[pk]["last_verified"] = _utc_now()
                    logger.info(f"Verification passed for {station_id}")
                else:
                    # Invalidate station - won't appear in broadcast until re-verified
                    _stations[pk]["last_verified"] = None
                    logger.warning(f"Verification FAILED for {station_id}: {reason}")
                    
                    # Ban for serious failures (station's fault)
                    if _should_ban(reason):
                        await _banned_manager.ban_station(station_id, pk, station_email, reason)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage background verification scheduler lifecycle."""
    task = asyncio.create_task(_verification_loop())
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


app = FastAPI(title="Enclave Verifier", version="1.0.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage (never persisted for enclave security)
# {public_key_hex: {"email", "display_name", "cookie_data", "registered_at", "last_verified", "is_official", "provisioning_key"}}
_stations: dict = {}
_email_to_pk: dict = {}  # Reverse lookup for identity migration
_lock = asyncio.Lock()

BASE_URL = "https://openrouter.ai"


# Request/Response models
class RegisterRequest(BaseModel):
    cookie_data: dict  # Same structure as cookies.json
    public_key: str  # Ed25519 public key (hex)
    display_name: str


class InvitationRequest(BaseModel):
    credential: str  # 24-char invitation code


class StationInfo(BaseModel):
    station_id: Optional[str]  # From registry
    public_key: str            # Ed25519 public key
    display_name: str
    is_official: bool
    last_verified: Optional[str]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


# All privacy toggles must be false
REQUIRED_TOGGLES = {
    "enable_logging": False,
    "enable_training": False,
    "enable_free_model_training": False,
    "enable_free_model_publication": False,
    "enforce_zdr": False,
    "always_enforce_allowed": False,
    "is_broadcast_enabled": False,
}


async def _fetch_activity_data(auth: OpenRouterAuth) -> dict | None:
    """POST /activity to get user data including email and privacy toggles."""
    action_hash = auth.get_action_hash("activity")
    if not action_hash:
        logger.error(f"No activity hash found. Available hashes: {auth.get_all_action_hashes()}")
        return None
    logger.debug(f"Using activity hash: {action_hash}")
    
    cookies = auth.get_cookies_dict()
    # Router state for /activity page
    router_state = "%5B%22%22%2C%7B%22children%22%3A%5B%22(user)%22%2C%7B%22children%22%3A%5B%22activity%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%2Ctrue%5D"
    
    headers = {
        "Content-Type": "text/plain;charset=UTF-8",
        "Accept": "text/x-component",
        "Accept-Encoding": "identity",
        "Next-Action": action_hash,
        "Next-Router-State-Tree": router_state,
        "Origin": BASE_URL,
        "Referer": f"{BASE_URL}/activity",
    }
    
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{BASE_URL}/activity",
            headers=headers,
            cookies=cookies,
            content="[]",
            timeout=15,
        )
        if resp.status_code != 200:
            return None
        
        # Parse JSON from Next.js server component response
        # Format: 1:{"__kind":"OK","data":{"email":"...","enable_logging":...}}
        for line in resp.text.split('\n'):
            if '{"__kind":"OK"' in line or '"email"' in line:
                # Extract JSON part after the line prefix (e.g., "1:")
                json_start = line.find('{')
                if json_start >= 0:
                    try:
                        obj = json.loads(line[json_start:])
                        if obj.get("__kind") == "OK" and "data" in obj:
                            return obj["data"]
                        if "email" in obj:
                            return obj
                    except json.JSONDecodeError:
                        continue
    return None


def _check_privacy_toggles(data: dict) -> tuple[bool, list[str]]:
    """
    Check if all privacy toggles are correctly set.
    Returns (passed, list of invalid toggle descriptions).
    """
    invalid = []
    for k, required_val in REQUIRED_TOGGLES.items():
        actual_val = data.get(k)
        if actual_val != required_val:
            invalid.append(f"{k}={actual_val}(expected={required_val})")
    return (len(invalid) == 0, invalid)


def _extract_email(data: dict) -> str | None:
    """Extract email from activity data."""
    return data.get("email")


def _get_email_domain(email: str) -> str:
    """Extract domain from email address."""
    return email.split("@")[-1].lower() if "@" in email else ""


def _check_is_official(display_name: str, email: str) -> bool:
    """Check if display_name domain matches email domain."""
    email_domain = _get_email_domain(email)
    # Simple heuristic: display_name contains the email domain (minus TLD)
    domain_base = email_domain.split(".")[0] if email_domain else ""
    return domain_base.lower() in display_name.lower() if domain_base else False


def _validate_public_key(pk_hex: str) -> bool:
    """Validate Ed25519 public key format (64 hex chars = 32 bytes)."""
    if len(pk_hex) != 64:
        return False
    try:
        bytes.fromhex(pk_hex)
        return True
    except ValueError:
        return False


def _generate_prov_label(station_id: str) -> str:
    """Generate deterministic provisioning key label from station_id using HMAC-SHA256."""
    return hmac.new(PROVISIONING_KEY_SALT, station_id.encode(), hashlib.sha256).hexdigest()[:16]


async def _create_provisioning_key(auth: OpenRouterAuth, label: str) -> str | None:
    """Create a provisioning key via OpenRouter API and return the key string."""
    action_hash = auth.get_action_hash("provisioning_keys")
    if not action_hash:
        logger.error("Could not get action hash for provisioning-keys from auth module")
        return None

    cookies = auth.get_cookies_dict()
    router_state = "%5B%22%22%2C%7B%22children%22%3A%5B%22(user)%22%2C%7B%22children%22%3A%5B%22settings%22%2C%7B%22children%22%3A%5B%22provisioning-keys%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%2Ctrue%5D"
    
    headers = {
        "Content-Type": "text/plain;charset=UTF-8",
        "Accept": "text/x-component",
        "Accept-Encoding": "gzip, deflate, br",
        "Next-Action": action_hash,
        "Next-Router-State-Tree": router_state,
        "Origin": BASE_URL,
        "Referer": f"{BASE_URL}/settings/provisioning-keys",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    }
    payload = json.dumps([{"name": label}])

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{BASE_URL}/settings/provisioning-keys",
            headers=headers,
            cookies=cookies,
            content=payload,
            timeout=15,
        )
        
        if resp.status_code != 200:
            logger.error(f"Provisioning key creation failed: {resp.status_code}")
            return None

        for line in resp.text.split('\n'):
            json_start = line.find('{')
            if json_start >= 0:
                try:
                    obj = json.loads(line[json_start:])
                    if obj.get("__kind") == "OK" and isinstance(obj.get("data"), dict):
                        key = obj["data"].get("key")
                        if key and key.startswith("sk-or-"):
                            logger.info(f"Created provisioning key: {key[:20]}...")
                            return key
                except json.JSONDecodeError:
                    continue
        
        logger.error(f"Could not parse provisioning key from response")
    return None


async def _fetch_registry_stations() -> list[dict]:
    """Fetch authorized stations from registry."""
    if not REGISTRY_URL or not REGISTRY_SECRET:
        logger.warning("Registry not configured (STATION_REGISTRY_URL or STATION_REGISTRY_SECRET missing)")
        return []
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"{REGISTRY_URL}/resources/registered_stations",
            headers={"Authorization": f"Bearer {REGISTRY_SECRET}"},
            timeout=15,
        )
        if resp.status_code == 200:
            data = resp.json()
            logger.info(f"Registry response: {data}")
            stations = data.get("stations", [])
            logger.info(f"Fetched {len(stations)} stations from registry:")
            for s in stations:
                logger.info(f"  - station: {s}")
            return stations
        logger.error(f"Registry fetch failed: {resp.status_code}")
    return []


@app.post("/register")
async def register(req: RegisterRequest):
    """
    Register a station with key-based identity.
    
    - Validates Ed25519 public key format
    - Extracts email from cookie via OpenRouter API
    - Validates station exists in registry with matching email
    - Binds public_key <-> email
    - Handles identity migration (same email, new key)
    """
    # Validate public key format
    if not _validate_public_key(req.public_key):
        logger.warning(f"Registration rejected: invalid public key format ({req.public_key[:16]}...)")
        raise HTTPException(status_code=400, detail="Invalid Ed25519 public key (need 64 hex chars)")
    
    # Check if already banned by public key FIRST - before doing any other work
    if await _banned_manager.is_banned(public_key=req.public_key):
        banned_station_id = await _banned_manager.get_station_id_by_pk(req.public_key) or f"pk:{req.public_key[:16]}"
        logger.warning(f"Registration rejected: {banned_station_id} is BANNED")
        # Notify org about re-registration attempt
        await _notify_org_banned(banned_station_id, "banned_reregister_attempt")
        raise HTTPException(status_code=403, detail="Station is banned")
    
    try:
        # Run blocking OpenRouterAuth initialization in thread pool to not block event loop
        auth = await asyncio.to_thread(OpenRouterAuth.from_dict, req.cookie_data, False)
        data = await _fetch_activity_data(auth)
        if not data:
            logger.warning(f"Registration rejected: failed to verify cookie for {req.public_key[:16]}...")
            raise HTTPException(status_code=401, detail="Failed to verify cookie")
        
        email = _extract_email(data)
        if not email:
            logger.warning(f"Registration rejected: could not extract email for {req.public_key[:16]}...")
            raise HTTPException(status_code=401, detail="Could not extract email from account")
        
    except HTTPException:
        raise
    except Exception as e:
        logger.warning(f"Registration rejected: cookie verification failed for {req.public_key[:16]}... - {e}")
        raise HTTPException(status_code=401, detail=f"Cookie verification failed: {e}")
    
    # Validate against station registry (match by email - the verified identity)
    # Get station_id from registry to create three-way binding: station_id ↔ email ↔ public_key
    registry_stations = await _fetch_registry_stations()
    station_id = None
    if registry_stations:  # Only validate if registry is configured and reachable
        logger.info(f"Cookie email: {email}")
        registry_entry = next(
            (s for s in registry_stations if s.get("or_account_email") == email),
            None
        )
        if not registry_entry:
            logger.error(f"No station registered for email: {email}")
            raise HTTPException(status_code=404, detail="No station registered for this email in registry")
        station_id = registry_entry.get("station_id")
        
        # Also check if banned by station_id
        if await _banned_manager.is_banned(station_id=station_id):
            logger.warning(f"Registration rejected: station {station_id} is BANNED")
            # Notify org about re-registration attempt
            await _notify_org_banned(station_id, "banned_reregister_attempt")
            raise HTTPException(status_code=403, detail="Station is banned")
        
        logger.info(f"Three-way binding: {station_id} ↔ {email} ↔ {req.public_key[:16]}...")
    
    is_official = _check_is_official(req.display_name, email)
    
    # Verify privacy toggles immediately (we already have the activity data)
    privacy_ok, invalid_toggles = _check_privacy_toggles(data)

    # If privacy check fails, ban the station and reject registration
    if not privacy_ok:
        reason = f"privacy_toggles_invalid_on_register:[{','.join(invalid_toggles)}]"
        logger.error(f"Registration rejected: station {station_id} FAILED privacy toggle check - BANNING: {invalid_toggles}")
        await _banned_manager.ban_station(station_id or "unknown", req.public_key, email, reason)
        raise HTTPException(status_code=403, detail="Privacy toggles not properly configured. Station banned.")
    
    now = _utc_now()
    
    # Check for existing provisioning key (same pk re-registering or identity migration)
    existing_prov_key = None
    async with _lock:
        if req.public_key in _stations:
            existing_prov_key = _stations[req.public_key].get("provisioning_key")
        elif email in _email_to_pk:
            old_pk = _email_to_pk[email]
            if old_pk in _stations:
                existing_prov_key = _stations[old_pk].get("provisioning_key")
    
    # Create provisioning key if needed (requires station_id)
    provisioning_key = existing_prov_key
    if station_id and not provisioning_key:
        label = _generate_prov_label(station_id)
        provisioning_key = await _create_provisioning_key(auth, label)
        if not provisioning_key:
            raise HTTPException(status_code=500, detail="Failed to create provisioning key")
        logger.info(f"Created provisioning key for {station_id} with label {label}")
    
    async with _lock:
        # Identity migration: if email already registered, remove old entry
        if email in _email_to_pk:
            old_pk = _email_to_pk[email]
            if old_pk != req.public_key and old_pk in _stations:
                del _stations[old_pk]
        
        # Register new station with three-way binding
        _stations[req.public_key] = {
            "station_id": station_id,  # From registry
            "email": email,            # From cookie
            "display_name": req.display_name,
            "cookie_data": req.cookie_data,
            "registered_at": now,
            "last_verified": now,  # Always verified if we get here (privacy check passed)
            "is_official": is_official,
            "provisioning_key": provisioning_key,
        }
        _email_to_pk[email] = req.public_key
    
    logger.info(f"Station {station_id} registered successfully")
    
    return {
        "status": "registered",
        "station_id": station_id,
        "public_key": req.public_key,
        "email": email,
        "is_official": is_official,
        "verified": True,
    }


@app.get("/station/{public_key}")
async def get_station(public_key: str):
    """Get station info by public key."""
    async with _lock:
        station = _stations.get(public_key)
        if not station:
            raise HTTPException(status_code=404, detail="Station not found")
        return StationInfo(
            station_id=station.get("station_id"),
            public_key=public_key,
            display_name=station["display_name"],
            is_official=station["is_official"],
            last_verified=station["last_verified"],
        )


@app.get("/broadcast")
async def broadcast():
    """Get list of all verified stations and banned stations."""
    async with _lock:
        verified = [
            StationInfo(
                station_id=data.get("station_id"),
                public_key=pk,
                display_name=data["display_name"],
                is_official=data["is_official"],
                last_verified=data["last_verified"],
            ).model_dump()
            for pk, data in _stations.items()
            if data["last_verified"] is not None
        ]
    
    banned = await _banned_manager.get_all()
    
    return {
        "verified_stations": verified,
        "banned_stations": banned,
    }


@app.post("/add-invitation")
async def add_invitation(req: InvitationRequest, authorization: str = Header(None)):
    """
    Add an invitation code to get Privacy Pass tickets for challenges.
    Requires Authorization: Bearer <STATION_REGISTRY_SECRET>
    """
    # Verify authorization
    if not REGISTRY_SECRET:
        raise HTTPException(status_code=503, detail="Registry secret not configured")
    
    expected = f"Bearer {REGISTRY_SECRET}"
    if authorization != expected:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    if not PRIVACY_PASS_AVAILABLE:
        raise HTTPException(status_code=503, detail="Privacy Pass library not available")
    
    try:
        result = await _register_invitation_code(req.credential)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        logger.error(f"Invitation registration failed: {e}")
        raise HTTPException(status_code=500, detail=f"Registration failed: {e}")


@app.get("/tickets")
async def get_tickets():
    """Get ticket usage statistics."""
    stats = await _ticket_manager.get_stats()
    return {
        "tickets": stats,
        "challenge_interval": {
            "min_seconds": CHALLENGE_MIN_INTERVAL,
            "max_seconds": CHALLENGE_MAX_INTERVAL,
        },
    }


@app.get("/banned-stations")
async def get_banned_stations():
    """Get list of banned stations (station_id and public_key only, no email)."""
    banned = await _banned_manager.get_all()
    return {"banned_stations": banned, "count": len(banned)}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

