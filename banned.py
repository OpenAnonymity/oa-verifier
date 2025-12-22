"""Banned station management - Persistent banned station tracking."""

import asyncio
import json
import os
from typing import List
from datetime import datetime, timezone

import httpx
from loguru import logger

from config import config
from models import BannedStation


async def notify_org_banned(station_id: str, reason: str) -> None:
    """Notify org about a banned station or re-registration attempt."""
    if not config.REGISTRY_URL or not config.REGISTRY_SECRET:
        return
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{config.REGISTRY_URL}/verifier/ban_station",
                headers={"Authorization": f"Bearer {config.REGISTRY_SECRET}", "Content-Type": "application/json"},
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
    
    def __init__(self, filepath: str = None):
        self._filepath = filepath or config.BANNED_STATIONS_FILE
        self._stations: List[BannedStation] = []
        self._lock = asyncio.Lock()
        self._load_sync()  # Sync load on init is fine (before event loop)
    
    def _load_sync(self) -> None:
        """Load banned stations from file (sync, for init only)."""
        if os.path.exists(self._filepath):
            try:
                with open(self._filepath, "r") as f:
                    data = json.load(f)
                self._stations = [BannedStation.from_dict(s) for s in data]
                logger.info(f"Loaded {len(self._stations)} banned stations from {self._filepath}")
            except Exception as e:
                logger.error(f"Failed to load banned stations: {e}")
                self._stations = []
    
    def _write_file(self, data: list) -> None:
        """Write data to file (runs in thread pool)."""
        with open(self._filepath, "w") as f:
            json.dump(data, f, indent=2)
    
    async def _save(self) -> None:
        """Save banned stations to file (non-blocking)."""
        data = [s.to_dict() for s in self._stations]
        try:
            await asyncio.to_thread(self._write_file, data)
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
            await self._save()
            logger.warning(f"Banned station {station_id}: {reason}")
        
        # Notify org (outside lock)
        await notify_org_banned(station_id, reason)
    
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
banned_manager = BannedStationManager()
