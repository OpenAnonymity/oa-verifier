#!/usr/bin/env python3
"""
OpenRouter Auth Module - Provides fresh cookies and next-action hashes.

Usage:
    from openrouter_auth import OpenRouterAuth
    
    auth = OpenRouterAuth("cookies.json")
    
    # Get cookie string for requests
    cookie_str = auth.get_cookie_string()
    # "__client_uat=xxx; clerk_active_context=xxx; __session=xxx"
    
    # Get next-action hash for specific page
    hash = auth.get_action_hash("activity")
    hash = auth.get_action_hash("provisioning_keys")
    
    # Get both
    cookie_str, hashes = auth.get_auth()
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

# Supported pages and their paths
PAGES = {
    "activity": "/activity",
    "provisioning_keys": "/settings/provisioning-keys",
    "keys": "/settings/keys",
    "broadcast": "/settings/broadcast",
}


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
        self._action_hashes = {}  # {page_name: hash}
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
    def from_dict(cls, cookie_data: dict, auto_refresh: bool = False):
        """Create auth instance from cookie dict (same format as cookies.json content)."""
        instance = object.__new__(cls)
        instance.cookies_file = None
        instance.refresh_interval = 50
        instance._clerk_params = None
        instance._state = None
        instance._session_jwt = None
        instance._action_hashes = {}
        instance._lock = threading.Lock()
        instance._refresh_thread = None
        
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
        """Fetch next-action hashes from JS bundles for all pages."""
        cookies = self._get_cookies_dict()
        page_hashes = {}
        
        for page_name, page_path in PAGES.items():
            try:
                resp = requests.get(f"{BASE_URL}{page_path}", cookies=cookies, timeout=15)
                if resp.status_code != 200:
                    continue
                
                js_chunks = list(set(re.findall(r'/_next/static/chunks/([^"\']+\.js)', resp.text)))
                page_hash = None
                
                # Find page-specific chunk (e.g., app/(user)/activity/page-*.js)
                page_key = page_path.strip('/').split('/')[-1]  # "activity" or "provisioning-keys"
                for chunk in js_chunks:
                    if f"/{page_key}/page-" in chunk:
                        try:
                            r = requests.get(f"{BASE_URL}/_next/static/chunks/{chunk}", 
                                           cookies=cookies, timeout=10)
                            if r.status_code == 200:
                                hashes = re.findall(r'"([0-9a-f]{42})"', r.text)
                                # Prefer 00-prefix hash if available
                                prefix_00 = [h for h in hashes if h.startswith('00')]
                                if prefix_00:
                                    page_hash = prefix_00[0]
                                elif hashes:
                                    page_hash = hashes[0]
                                break
                        except Exception:
                            pass
                
                # Fallback: search all chunks for 00-prefix hashes
                if not page_hash:
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
                    if all_hashes:
                        page_hash = sorted(list(all_hashes))[0]
                
                if page_hash:
                    page_hashes[page_name] = page_hash
                    
            except Exception:
                pass
        
        with self._lock:
            self._action_hashes = page_hashes
    
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
    
    def get_action_hash(self, page="activity"):
        """
        Get the next-action hash for a specific page.
        
        Args:
            page: Page name (activity, provisioning_keys, keys, broadcast)
        
        Returns:
            str: Action hash like "409cb4b7890ec13be27525a5ec301c1d4852000762"
        """
        with self._lock:
            return self._action_hashes.get(page)
    
    def get_all_action_hashes(self):
        """
        Get all available next-action hashes by page.
        
        Returns:
            dict: {page_name: hash, ...}
        """
        with self._lock:
            return dict(self._action_hashes)
    
    def get_auth(self, page="activity"):
        """
        Get cookie string and action hash for a specific page.
        
        Args:
            page: Page name (activity, provisioning_keys, keys, broadcast)
        
        Returns:
            tuple: (cookie_string, action_hash)
        """
        return self.get_cookie_string(), self.get_action_hash(page)
    
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
    
    @staticmethod
    def get_available_pages():
        """Get list of supported pages."""
        return list(PAGES.keys())


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


def get_action_hash(page="activity"):
    """Get action hash from default auth instance."""
    if not _default_auth:
        raise RuntimeError("Call init() first")
    return _default_auth.get_action_hash(page)


def get_auth(page="activity"):
    """Get both cookie string and action hash from default auth instance."""
    if not _default_auth:
        raise RuntimeError("Call init() first")
    return _default_auth.get_auth(page)


if __name__ == "__main__":
    print("OpenRouter Auth Module Demo")
    print("=" * 50)
    
    auth = OpenRouterAuth("cookies.json")
    
    print(f"\nSession ID: {auth.get_session_id()}")
    print(f"Org ID: {auth.get_org_id()}")
    
    print(f"\nAvailable pages: {auth.get_available_pages()}")
    
    print("\nAction Hashes by page:")
    for page, hash in auth.get_all_action_hashes().items():
        print(f"  {page}: {hash}")
    
    print(f"\nCookie String:\n{auth.get_cookie_string()}")
    
    # Example for provisioning_keys
    cookie_str, action_hash = auth.get_auth("provisioning_keys")
    if action_hash:
        print(f"\n\nExample curl for /settings/provisioning-keys:")
        print(f"""
curl 'https://openrouter.ai/settings/provisioning-keys' \\
  -X POST \\
  -H 'content-type: text/plain;charset=UTF-8' \\
  -H 'accept: text/x-component' \\
  -H 'next-action: {action_hash}' \\
  -H 'cookie: {cookie_str}' \\
  --data-raw '[]'
""")
