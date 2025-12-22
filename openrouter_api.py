"""OpenRouter API - Authentication and API interactions."""

import asyncio
import json
import re
import threading
import httpx
import requests
from loguru import logger

from config import BASE_URL, OPENROUTER_API_URL

# Retry config for cookie-based API calls
MAX_RETRIES = 5
RETRY_DELAY = 2  # seconds

CLERK_JS_URL = "https://clerk.openrouter.ai/npm/@clerk/clerk-js@5/dist/clerk.browser.js"
CLERK_API = "https://clerk.openrouter.ai/v1/client/sessions/{session_id}/tokens"

PAGES = {
    "activity": "/activity",
    "provisioning_keys": "/settings/provisioning-keys",
}

# Action name -> key in _action_hashes
ACTION_NAME_MAP = {
    "getCurrentUserSA": "activity",
    "createProvisioningAPIKeySA": "provisioning_keys_create",
    "updateAPIKeySA": "provisioning_keys_delete",
}


class OpenRouterAuth:
    """OpenRouter authentication manager (trimmed - dict-based only)."""
    
    @classmethod
    def from_dict(cls, cookie_data: dict, auto_refresh: bool = False):
        """Create auth instance from cookie dict."""
        instance = object.__new__(cls)
        instance._clerk_params = None
        instance._state = None
        instance._session_jwt = None
        instance._action_hashes = {}
        instance._lock = threading.Lock()
        
        # Parse cookie data
        state = {}
        for c in cookie_data.get("cookies", []):
            name, value = c["name"], c["value"]
            domain = c.get("domain", "")
            if name == "__client" and "clerk" in domain:
                state["client_token"] = value
            elif name == "__client_uat":
                state["client_uat"] = value
            elif name == "clerk_active_context":
                parts = value.split(":")
                state["session_id"] = parts[0]
                state["clerk_active_context"] = value
                if len(parts) > 1 and parts[1]:
                    state["org_id"] = parts[1]
        
        if "session_id" not in state or "client_token" not in state:
            raise ValueError("Invalid cookie_data - missing required session data")
        
        instance._state = state
        instance._fetch_clerk_versions()
        instance._refresh_token()
        instance._fetch_action_hashes()
        return instance
    
    def _fetch_clerk_versions(self):
        """Fetch Clerk API and JS versions dynamically."""
        try:
            resp = requests.get(CLERK_JS_URL, timeout=10)
            if resp.status_code == 200:
                js_match = re.search(r'(\d+\.\d+\.\d+)', resp.text[:10000])
                api_match = re.search(r'["\'](\d{4}-\d{2}-\d{2})["\']', resp.text)
                self._clerk_params = {
                    "__clerk_api_version": api_match.group(1) if api_match else "2025-11-10",
                    "_clerk_js_version": js_match.group(1) if js_match else "5.111.0",
                }
                return
        except Exception:
            pass
        self._clerk_params = {"__clerk_api_version": "2025-11-10", "_clerk_js_version": "5.111.0"}
    
    def _refresh_token(self):
        """Refresh session JWT via Clerk API."""
        url = CLERK_API.format(session_id=self._state["session_id"])
        cookies = {
            "__client": self._state["client_token"],
            "__client_uat": self._state["client_uat"],
        }
        data = {}
        if self._state.get("org_id"):
            data["organization_id"] = self._state["org_id"]
        
        headers = {
            "Origin": "https://openrouter.ai",
            "Referer": "https://openrouter.ai/",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        
        try:
            resp = requests.post(url, params=self._clerk_params, cookies=cookies, 
                               headers=headers, data=data, timeout=10)
            if resp.status_code == 200:
                with self._lock:
                    self._session_jwt = resp.json().get("jwt")
                return True
        except Exception as e:
            logger.error(f"Token refresh failed: {e}")
        return False
    
    def _fetch_action_hashes(self):
        """Fetch next-action hashes from JS bundles by action name."""
        cookies = self.get_cookies_dict()
        action_hashes = {}
        fetched_chunks = set()
        
        # Fetch pages to get JS chunks
        for page_path in PAGES.values():
            try:
                resp = requests.get(f"{BASE_URL}{page_path}", cookies=cookies, timeout=15)
                if resp.status_code != 200:
                    continue
                
                js_chunks = set(re.findall(r'/_next/static/chunks/([^"\']+\.js)', resp.text))
                
                for chunk in js_chunks:
                    if chunk in fetched_chunks:
                        continue
                    fetched_chunks.add(chunk)
                    
                    try:
                        r = requests.get(f"{BASE_URL}/_next/static/chunks/{chunk}", 
                                       cookies=cookies, timeout=10)
                        if r.status_code != 200:
                            continue
                        
                        js = r.text
                        # Find hashes by looking at the action name that follows
                        for m in re.finditer(r'"([0-9a-f]{40,42})"', js):
                            hash_val = m.group(1)
                            # Look for action name after the hash
                            after = js[m.end():m.end()+100]
                            name_match = re.search(r'"([a-zA-Z_]+)"[)\]]', after)
                            if name_match:
                                action_name = name_match.group(1)
                                if action_name in ACTION_NAME_MAP:
                                    key = ACTION_NAME_MAP[action_name]
                                    action_hashes[key] = hash_val
                    except Exception:
                        pass
                
                # Stop if we found all needed actions
                if len(action_hashes) >= len(ACTION_NAME_MAP):
                    break
            except Exception:
                pass
        
        with self._lock:
            self._action_hashes = action_hashes
    
    def get_cookies_dict(self) -> dict:
        """Get cookies as dict for requests library."""
        with self._lock:
            return {
                "__client_uat": self._state["client_uat"],
                "clerk_active_context": self._state.get("clerk_active_context", ""),
                "__session": self._session_jwt or "",
            }
    
    def get_action_hash(self, page="activity") -> str | None:
        """Get the next-action hash for a specific page."""
        with self._lock:
            return self._action_hashes.get(page)
    
    def get_all_action_hashes(self) -> dict:
        """Get all available next-action hashes by page."""
        with self._lock:
            return dict(self._action_hashes)


# API Functions

async def fetch_provisioning_keys(auth: OpenRouterAuth) -> list[dict]:
    """Fetch all provisioning keys from the settings page. Returns list of {hash, name, label}."""
    cookies = auth.get_cookies_dict()
    
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    f"{BASE_URL}/settings/provisioning-keys?page=1",
                    cookies=cookies,
                    timeout=15,
                )
                if resp.status_code != 200:
                    logger.warning(f"fetch_provisioning_keys attempt {attempt}/{MAX_RETRIES} failed: status {resp.status_code}")
                    if attempt < MAX_RETRIES:
                        await asyncio.sleep(RETRY_DELAY)
                    continue
                
                # Parse provisioning keys from embedded JSON (handles escaped quotes)
                # Order in HTML: label -> name -> ... -> hash
                keys = []
                for match in re.finditer(
                    r'\\"label\\":\\"([^"\\]+)\\",\\"name\\":\\"([0-9a-f]{16})\\".+?\\"hash\\":\\"([0-9a-f]{64})\\"',
                    resp.text
                ):
                    keys.append({
                        "hash": match.group(3),
                        "name": match.group(2),
                        "label": match.group(1),
                    })
                
                if keys:
                    logger.debug(f"Found {len(keys)} provisioning keys")
                    return keys
                
                # Response 200 but no keys found - might be empty, return empty list
                logger.debug("No provisioning keys found on page")
                return []
        except Exception as e:
            logger.warning(f"fetch_provisioning_keys attempt {attempt}/{MAX_RETRIES} error: {e}")
        
        if attempt < MAX_RETRIES:
            await asyncio.sleep(RETRY_DELAY)
    
    logger.error(f"fetch_provisioning_keys failed after {MAX_RETRIES} attempts")
    return []


async def delete_provisioning_key(auth: OpenRouterAuth, key_hash: str) -> bool:
    """Delete a provisioning key by its hash. Returns True on success."""
    action_hash = auth.get_action_hash("provisioning_keys_delete")
    if not action_hash:
        logger.error("Could not get delete action hash for provisioning-keys")
        return False
    
    cookies = auth.get_cookies_dict()
    router_state = "%5B%22%22%2C%7B%22children%22%3A%5B%22(user)%22%2C%7B%22children%22%3A%5B%22settings%22%2C%7B%22children%22%3A%5B%22provisioning-keys%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%2Ctrue%5D"
    
    headers = {
        "Content-Type": "text/plain;charset=UTF-8",
        "Accept": "text/x-component",
        "Accept-Encoding": "identity",
        "Next-Action": action_hash,
        "Next-Router-State-Tree": router_state,
        "Origin": BASE_URL,
        "Referer": f"{BASE_URL}/settings/provisioning-keys?page=1",
    }
    payload = json.dumps([key_hash, {"deleted": True}, {"isProvisioningKey": True}])
    
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    f"{BASE_URL}/settings/provisioning-keys?page=1",
                    headers=headers,
                    cookies=cookies,
                    content=payload,
                    timeout=15,
                )
                if resp.status_code != 200:
                    logger.warning(f"delete_provisioning_key attempt {attempt}/{MAX_RETRIES} failed: status {resp.status_code}")
                    if attempt < MAX_RETRIES:
                        await asyncio.sleep(RETRY_DELAY)
                    continue
                
                # Check for success response
                if '"deleted":true' in resp.text or '"__kind":"OK"' in resp.text:
                    logger.info(f"Deleted provisioning key: {key_hash[:16]}...")
                    return True
                
                logger.warning(f"delete_provisioning_key attempt {attempt}/{MAX_RETRIES}: unexpected response")
        except Exception as e:
            logger.warning(f"delete_provisioning_key attempt {attempt}/{MAX_RETRIES} error: {e}")
        
        if attempt < MAX_RETRIES:
            await asyncio.sleep(RETRY_DELAY)
    
    logger.error(f"delete_provisioning_key failed after {MAX_RETRIES} attempts for hash {key_hash[:16]}...")
    return False


async def cleanup_provisioning_keys(auth: OpenRouterAuth, label: str) -> int:
    """Delete all provisioning keys matching the given label. Returns count of deleted keys."""
    keys = await fetch_provisioning_keys(auth)
    if not keys:
        return 0
    
    matching = [k for k in keys if k.get("name") == label]
    if not matching:
        logger.debug(f"No existing provisioning keys found with label {label}")
        return 0
    
    logger.info(f"Found {len(matching)} existing provisioning key(s) with label {label}, cleaning up...")
    deleted = 0
    for key in matching:
        if await delete_provisioning_key(auth, key["hash"]):
            deleted += 1
    
    logger.info(f"Cleaned up {deleted}/{len(matching)} provisioning keys for label {label}")
    return deleted


async def fetch_activity_data(auth: OpenRouterAuth) -> dict | None:
    """POST /activity to get user data including email and privacy toggles."""
    action_hash = auth.get_action_hash("activity")
    if not action_hash:
        logger.error(f"No activity hash found. Available hashes: {auth.get_all_action_hashes()}")
        return None
    logger.debug(f"Using activity hash: {action_hash}")
    
    cookies = auth.get_cookies_dict()
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
    
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    f"{BASE_URL}/activity",
                    headers=headers,
                    cookies=cookies,
                    content="[]",
                    timeout=15,
                )
                if resp.status_code != 200:
                    logger.warning(f"fetch_activity_data attempt {attempt}/{MAX_RETRIES} failed: status {resp.status_code}")
                    if attempt < MAX_RETRIES:
                        await asyncio.sleep(RETRY_DELAY)
                    continue
                
                for line in resp.text.split('\n'):
                    if '{"__kind":"OK"' in line or '"email"' in line:
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
                # Response 200 but couldn't parse - still retry
                logger.warning(f"fetch_activity_data attempt {attempt}/{MAX_RETRIES}: could not parse response")
        except Exception as e:
            logger.warning(f"fetch_activity_data attempt {attempt}/{MAX_RETRIES} error: {e}")
        
        if attempt < MAX_RETRIES:
            await asyncio.sleep(RETRY_DELAY)
    
    logger.error(f"fetch_activity_data failed after {MAX_RETRIES} attempts")
    return None


async def create_provisioning_key(auth: OpenRouterAuth, label: str) -> str | None:
    """Create a provisioning key via OpenRouter API and return the key string."""
    action_hash = auth.get_action_hash("provisioning_keys_create")
    if not action_hash:
        logger.error(f"Could not get create action hash for provisioning-keys. Available: {auth.get_all_action_hashes()}")
        return None

    cookies = auth.get_cookies_dict()
    router_state = "%5B%22%22%2C%7B%22children%22%3A%5B%22(user)%22%2C%7B%22children%22%3A%5B%22settings%22%2C%7B%22children%22%3A%5B%22provisioning-keys%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%2Ctrue%5D"
    
    headers = {
        "Content-Type": "text/plain;charset=UTF-8",
        "Accept": "text/x-component",
        "Accept-Encoding": "identity",
        "Next-Action": action_hash,
        "Next-Router-State-Tree": router_state,
        "Origin": BASE_URL,
        "Referer": f"{BASE_URL}/settings/provisioning-keys",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    }
    payload = json.dumps([{"name": label}])

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    f"{BASE_URL}/settings/provisioning-keys",
                    headers=headers,
                    cookies=cookies,
                    content=payload,
                    timeout=15,
                )
                
                if resp.status_code != 200:
                    logger.warning(f"create_provisioning_key attempt {attempt}/{MAX_RETRIES} failed: status {resp.status_code}")
                    if attempt < MAX_RETRIES:
                        await asyncio.sleep(RETRY_DELAY)
                    continue

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
                
                # Response 200 but couldn't parse key - still retry
                logger.warning(f"create_provisioning_key attempt {attempt}/{MAX_RETRIES}: could not parse key from response")
        except Exception as e:
            logger.warning(f"create_provisioning_key attempt {attempt}/{MAX_RETRIES} error: {e}")
        
        if attempt < MAX_RETRIES:
            await asyncio.sleep(RETRY_DELAY)
    
    logger.error(f"create_provisioning_key failed after {MAX_RETRIES} attempts")
    return None
