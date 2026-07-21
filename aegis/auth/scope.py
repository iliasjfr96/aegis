"""Unified scope check: global admin whitelist OR user-verified target."""

from aegis.auth.targets import is_verified_for
from aegis.config import get_settings


def is_allowed(url: str, owner: str | None = None) -> bool:
    if get_settings().is_target_allowed(url):
        return True
    if owner:
        return is_verified_for(owner, url)
    return False
