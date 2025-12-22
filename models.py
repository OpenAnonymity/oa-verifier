"""Data models - Dataclasses and Pydantic models."""

from dataclasses import dataclass
from pydantic import BaseModel


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


# Pydantic request/response models

class RegisterRequest(BaseModel):
    cookie_data: dict  # Same structure as cookies.json
    public_key: str    # Ed25519 public key (hex)
    display_name: str


class SubmitKeyRequest(BaseModel):
    station_id: str
    api_key: str
    key_valid_till: int       # Unix timestamp
    station_signature: str    # Hex-encoded Ed25519 signature from station
    org_signature: str        # Hex-encoded Ed25519 signature from org





