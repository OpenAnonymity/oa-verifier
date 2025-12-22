"""Station registry - Fetch stations from registry service."""

import httpx
from loguru import logger

from config import config


async def fetch_registry_stations() -> list[dict]:
    """Fetch authorized stations from registry."""
    if not config.REGISTRY_URL or not config.REGISTRY_SECRET:
        logger.warning("Registry not configured (STATION_REGISTRY_URL or STATION_REGISTRY_SECRET missing)")
        return []
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"{config.REGISTRY_URL}/verifier/registered_stations",
            headers={"Authorization": f"Bearer {config.REGISTRY_SECRET}"},
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
