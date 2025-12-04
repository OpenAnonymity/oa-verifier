#!/usr/bin/env python3
"""
OpenRouter Auth Module - Provides fresh cookies and next-action hashes.

Usage:
    from openrouter_auth import OpenRouterAuth
    
    auth = OpenRouterAuth("cookies.json")
    
    # Get cookie string for requests
    cookie_str = auth.get_cookie_string()
    # "__client_uat=xxx; clerk_active_context=xxx; __session=xxx"
    
    # Get next-action hash
    action_hash = auth.get_action_hash()
    # "00d6e8fb45f9a136d6470f2a49c8d0e2c843cabf92"
    
    # Get both
    cookie_str, action_hash = auth.get_auth()
"""

import json
import re
import time
import os
import threading
import requests

CLERK_JS_URL = "https://clerk.openrouter.ai/npm/@clerk/clerk-js@5/dist/clerk.browser.js"
CLERK_API = "https://clerk.openrouter.ai/v1/client/sessions/{session_id}/tokens"
BASE_URL = "https://openrouter.ai"


class OpenRouterAuth:
    """OpenRouter authentication manager."""
    
    def __init__(self, cookies_file="cookies.json", auto_refresh=True, refresh_interval=50):
        """
        Initialize the auth manager.
        
        Args:
            cookies_file: Path to cookies.json file
            auto_refresh: Whether to auto-refresh tokens in background
            refresh_interval: Seconds between token refreshes (default 50, JWT expires at 60)
        """
        self.cookies_file = cookies_file
        self.refresh_interval = refresh_interval
        
        self._clerk_params = None
        self._state = None
        self._session_jwt = None
        self._action_hashes = []
        self._lock = threading.Lock()
        self._refresh_thread = None
        
        # Initial load
        self._load_state()
        self._fetch_clerk_versions()
        self._refresh_token()
        self._fetch_action_hashes()
        
        # Start background refresh
        if auto_refresh:
            self._start_auto_refresh()
    
    @classmethod
    def from_dict(cls, cookie_data, auto_refresh=False, refresh_interval=50):
        """
        Initialize from cookie dict (same structure as cookies.json content).
        
        Args:
            cookie_data: Dict with "cookies" array (same format as cookies.json)
            auto_refresh: Whether to auto-refresh tokens in background
            refresh_interval: Seconds between token refreshes
        """
        instance = object.__new__(cls)
        instance.cookies_file = None
        instance.refresh_interval = refresh_interval
        instance._clerk_params = None
        instance._state = None
        instance._session_jwt = None
        instance._action_hashes = []
        instance._lock = threading.Lock()
        instance._refresh_thread = None
        
        # Parse cookie data directly
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
        
        if auto_refresh:
            instance._start_auto_refresh()
        
        return instance
    
    def _load_state(self):
        """Load session state from cookies.json."""
        if not os.path.exists(self.cookies_file):
            raise FileNotFoundError(f"Cookies file not found: {self.cookies_file}")
        
        with open(self.cookies_file) as f:
            data = json.load(f)
        
        state = {}
        for c in data.get("cookies", []):
            name = c["name"]
            value = c["value"]
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
            raise ValueError("Invalid cookies.json - missing required session data")
        
        self._state = state
    
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
        
        # Fallback
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
            print(f"Token refresh failed: {e}")
        
        return False
    
    def _fetch_action_hashes(self):
        """Fetch next-action hashes from JS bundles."""
        try:
            cookies = self._get_cookies_dict()
            resp = requests.get(f"{BASE_URL}/activity", cookies=cookies, timeout=15)
            
            if resp.status_code != 200:
                return
            
            js_chunks = list(set(re.findall(r'/_next/static/chunks/([^"\']+\.js)', resp.text)))
            all_hashes = set()
            
            for chunk in js_chunks:
                try:
                    r = requests.get(f"{BASE_URL}/_next/static/chunks/{chunk}", 
                                   cookies=cookies, timeout=10)
                    if r.status_code == 200:
                        hashes = re.findall(r'"(00[0-9a-f]{40})"', r.text)
                        all_hashes.update(hashes)
                except Exception:
                    pass
            
            with self._lock:
                self._action_hashes = sorted(list(all_hashes))
                
        except Exception as e:
            print(f"Hash fetch failed: {e}")
    
    def _get_cookies_dict(self):
        """Get cookies as dict for requests library."""
        with self._lock:
            return {
                "__client_uat": self._state["client_uat"],
                "clerk_active_context": self._state.get("clerk_active_context", ""),
                "__session": self._session_jwt or "",
            }
    
    def _auto_refresh_loop(self):
        """Background thread for auto-refresh."""
        while True:
            time.sleep(self.refresh_interval)
            self._refresh_token()
    
    def _start_auto_refresh(self):
        """Start background token refresh thread."""
        self._refresh_thread = threading.Thread(target=self._auto_refresh_loop, daemon=True)
        self._refresh_thread.start()
    
    # Public API
    
    def get_cookie_string(self):
        """
        Get cookies as a string for use in HTTP headers.
        
        Returns:
            str: Cookie string like "__client_uat=xxx; clerk_active_context=xxx; __session=xxx"
        """
        with self._lock:
            parts = [
                f"__client_uat={self._state['client_uat']}",
                f"clerk_active_context={self._state.get('clerk_active_context', '')}",
                f"__session={self._session_jwt or ''}",
            ]
            return "; ".join(parts)
    
    def get_cookies_dict(self):
        """
        Get cookies as a dict for use with requests library.
        
        Returns:
            dict: {"__client_uat": "...", "clerk_active_context": "...", "__session": "..."}
        """
        return self._get_cookies_dict()
    
    def get_action_hash(self):
        """
        Get the primary next-action hash.
        
        Returns:
            str: Action hash like "00d6e8fb45f9a136d6470f2a49c8d0e2c843cabf92"
        """
        with self._lock:
            return self._action_hashes[0] if self._action_hashes else None
    
    def get_all_action_hashes(self):
        """
        Get all available next-action hashes.
        
        Returns:
            list: List of action hashes
        """
        with self._lock:
            return list(self._action_hashes)
    
    def get_auth(self):
        """
        Get both cookie string and action hash.
        
        Returns:
            tuple: (cookie_string, action_hash)
        """
        return self.get_cookie_string(), self.get_action_hash()
    
    def refresh(self):
        """Manually refresh token and hashes."""
        self._refresh_token()
        self._fetch_action_hashes()
    
    def get_session_id(self):
        """Get the current session ID."""
        return self._state.get("session_id")
    
    def get_org_id(self):
        """Get the current organization ID (if any)."""
        return self._state.get("org_id")


# Convenience functions for simple usage

_default_auth = None


def init(cookies_file="cookies.json", **kwargs):
    """Initialize the default auth instance."""
    global _default_auth
    _default_auth = OpenRouterAuth(cookies_file, **kwargs)
    return _default_auth


def get_cookie_string():
    """Get cookie string from default auth instance."""
    if not _default_auth:
        raise RuntimeError("Call init() first")
    return _default_auth.get_cookie_string()


def get_action_hash():
    """Get action hash from default auth instance."""
    if not _default_auth:
        raise RuntimeError("Call init() first")
    return _default_auth.get_action_hash()


def get_auth():
    """Get both cookie string and action hash from default auth instance."""
    if not _default_auth:
        raise RuntimeError("Call init() first")
    return _default_auth.get_auth()


if __name__ == "__main__":
    # Demo usage
    print("OpenRouter Auth Module Demo")
    print("=" * 40)
    
    auth = OpenRouterAuth("cookies.json")
    
    print(f"\nSession ID: {auth.get_session_id()}")
    print(f"Org ID: {auth.get_org_id()}")
    
    print(f"\nAction Hash: {auth.get_action_hash()}")
    print(f"\nCookie String:\n{auth.get_cookie_string()}")
    
    print("\n\nExample curl command:")
    cookie_str, action_hash = auth.get_auth()
    print(f"""
curl 'https://openrouter.ai/activity' \\
  -X POST \\
  -H 'content-type: text/plain;charset=UTF-8' \\
  -H 'accept: text/x-component' \\
  -H 'next-action: {action_hash}' \\
  -H 'cookie: {cookie_str}' \\
  --data-raw '[]'
""")



