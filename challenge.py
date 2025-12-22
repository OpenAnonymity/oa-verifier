"""Challenge system - Privacy toggle verification helpers."""

import secrets

from config import config, REQUIRED_TOGGLES


def check_privacy_toggles(data: dict) -> tuple[bool, list[str]]:
    """Check if all privacy toggles are correctly set."""
    invalid = []
    for k, required_val in REQUIRED_TOGGLES.items():
        actual_val = data.get(k)
        if actual_val != required_val:
            invalid.append(f"{k}={actual_val}(expected={required_val})")
    return (len(invalid) == 0, invalid)


def get_random_interval() -> float:
    """Get cryptographically secure random interval between challenges."""
    min_interval = config.CHALLENGE_MIN_INTERVAL
    max_interval = config.CHALLENGE_MAX_INTERVAL
    range_size = max_interval - min_interval
    if range_size <= 0:
        return float(min_interval)
    return float(min_interval + secrets.randbelow(range_size + 1))


def should_ban(reason: str) -> bool:
    """Check if a failure reason should result in banning."""
    BAN_PREFIXES = (
        "privacy_toggles_invalid",
        "key_not_owned",
    )
    return reason.startswith(BAN_PREFIXES)
