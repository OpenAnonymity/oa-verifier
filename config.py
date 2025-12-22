"""Configuration - Hot-reloadable environment variables and constants."""

import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Hot-reloadable configuration. Reads from env on each access."""
    
    @property
    def REGISTRY_URL(self) -> str | None:
        return os.getenv("STATION_REGISTRY_URL")
    
    @property
    def REGISTRY_SECRET(self) -> str | None:
        return os.getenv("STATION_REGISTRY_SECRET")
    
    @property
    def PROVISIONING_KEY_SALT(self) -> bytes:
        salt = os.getenv("PROVISIONING_KEY_SALT", "")
        return salt.encode() if salt else b"default_dev_salt"
    
    @property
    def CHALLENGE_MIN_INTERVAL(self) -> int:
        return int(os.getenv("CHALLENGE_MIN_INTERVAL", "300"))
    
    @property
    def CHALLENGE_MAX_INTERVAL(self) -> int:
        return int(os.getenv("CHALLENGE_MAX_INTERVAL", "600"))
    
    @property
    def BANNED_STATIONS_FILE(self) -> str:
        return os.getenv("BANNED_STATIONS_FILE", "banned_stations.json")
    
    def reload(self) -> None:
        """Force reload .env file."""
        load_dotenv(override=True)


# Singleton instance
config = Config()

# =============================================================================
# HARDCODED CONSTANTS (proved with attestation)
# =============================================================================

BASE_URL = "https://openrouter.ai"
OPENROUTER_API_URL = "https://openrouter.ai/api/v1"

# Privacy toggles - HARDCODED, all must be False
# These are security-critical and MUST NOT be configurable and attested in enclave.
REQUIRED_TOGGLES: dict[str, bool] = {
    "enable_logging": False,
    "enable_training": False,
    "enable_free_model_training": False,
    "enable_free_model_publication": False,
    "enforce_zdr": False,
    "always_enforce_allowed": False,
    "is_broadcast_enabled": False,
}
