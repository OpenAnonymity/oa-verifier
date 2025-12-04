#!/usr/bin/env python3
"""
Enclave Verifier - Lightweight station verification service.

Endpoints:
    POST /station/register - Register station with cookie data
    POST /challenge - Challenge a station with generation_id
    GET /station/{station_id} - Check if station is registered
    GET /broadcast - Get all stations' last verified timestamps
"""

import asyncio
import json
import re
from datetime import datetime, timezone
from typing import Optional

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from openrouter_auth import OpenRouterAuth

app = FastAPI(title="Enclave Verifier", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage (never persisted for enclave security)
_stations: dict = {}  # {station_id: {"cookie_data": {...}, "registered_at": str, "last_verified": str}}
_untrustworthy: set = set()
_lock = asyncio.Lock()

BASE_URL = "https://openrouter.ai"
NEXT_ROUTER_STATE = "%5B%22%22%2C%7B%22children%22%3A%5B%22(user)%22%2C%7B%22children%22%3A%5B%22activity%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%2Ctrue%5D"


# Request/Response models
class RegisterRequest(BaseModel):
    station_id: str
    cookie_data: dict  # Same structure as cookies.json


class ChallengeRequest(BaseModel):
    station_id: str
    generation_id: str


class RegisteredResponse(BaseModel):
    registered: bool
    timestamp: Optional[str] = None
    trustworthy: bool = True


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


async def _check_privacy_settings(auth: OpenRouterAuth) -> bool:
    """POST /activity to verify all privacy toggles are false."""
    action_hash = auth.get_action_hash()
    if not action_hash:
        return False
    
    cookies = auth.get_cookies_dict()
    headers = {
        "Content-Type": "text/plain;charset=UTF-8",
        "Accept": "text/x-component",
        "Accept-Encoding": "identity",
        "Next-Action": action_hash,
        "Next-Router-State-Tree": NEXT_ROUTER_STATE,
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
            return False
        
        # Parse JSON from Next.js server component response
        # Find JSON object containing the toggles
        for match in re.finditer(r'\{[^{}]+\}', resp.text):
            try:
                obj = json.loads(match.group(0))
                # Check if this object has our toggle keys
                if "enable_logging" in obj:
                    return all(obj.get(k) == v for k, v in REQUIRED_TOGGLES.items())
            except (json.JSONDecodeError, KeyError):
                continue
    
    return False


async def _check_generation_exists(auth: OpenRouterAuth, generation_id: str) -> bool:
    """GET /api/v1/generation to check if generation exists (not 404)."""
    cookies = auth.get_cookies_dict()
    headers = {
        "Content-Type": "text/plain;charset=UTF-8",
        "Accept-Encoding": "identity",
        "Origin": BASE_URL,
        "Referer": f"{BASE_URL}/activity",
    }
    
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"{BASE_URL}/api/v1/generation",
            params={"id": generation_id},
            headers=headers,
            cookies=cookies,
            timeout=15,
        )
        if resp.status_code == 200:
            try:
                data = resp.json()
                # Generation exists if there's NO error (or error code is not 404)
                return "error" not in data or data.get("error", {}).get("code") != 404
            except Exception:
                pass
    
    return False


@app.post("/station/register")
async def station_register(req: RegisterRequest):
    """Register a station with its cookie data."""
    async with _lock:
        _stations[req.station_id] = {
            "cookie_data": req.cookie_data,
            "registered_at": _utc_now(),
            "last_verified": None,
        }
        _untrustworthy.discard(req.station_id)
    return {"status": "registered", "station_id": req.station_id}


@app.post("/challenge")
async def challenge(req: ChallengeRequest):
    """Challenge a station: verify all privacy toggles are false AND generation_id exists."""
    async with _lock:
        station = _stations.get(req.station_id)
        if not station:
            raise HTTPException(status_code=404, detail="Station not registered")
        cookie_data = station["cookie_data"]
    
    try:
        # Initialize auth from cookie data (no auto-refresh for one-shot check)
        auth = OpenRouterAuth.from_dict(cookie_data, auto_refresh=False)
        
        # Run both checks
        privacy_ok = await _check_privacy_settings(auth)
        gen_found = await _check_generation_exists(auth, req.generation_id)
        
        passed = privacy_ok and gen_found
        
        async with _lock:
            if passed:
                _stations[req.station_id]["last_verified"] = _utc_now()
            else:
                _untrustworthy.add(req.station_id)
        
        return {
            "passed": passed,
            "station_id": req.station_id,
            "privacy_settings_ok": privacy_ok,
            "generation_found": gen_found,
        }
    
    except Exception as e:
        async with _lock:
            _untrustworthy.add(req.station_id)
        return {"passed": False, "station_id": req.station_id, "error": str(e)}


@app.get("/station/{station_id}", response_model=RegisteredResponse)
async def is_registered(station_id: str):
    """Check if a station is registered and trustworthy."""
    async with _lock:
        station = _stations.get(station_id)
        if station:
            return RegisteredResponse(
                registered=True,
                timestamp=station["registered_at"],
                trustworthy=station_id not in _untrustworthy,
            )
        return RegisteredResponse(registered=False, trustworthy=False)


@app.get("/broadcast")
async def broadcast():
    """Get map of all stations with their last verified timestamps."""
    async with _lock:
        return {
            sid: data["last_verified"]
            for sid, data in _stations.items()
            if data["last_verified"] is not None
        }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

