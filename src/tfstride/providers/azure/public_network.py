from __future__ import annotations

PUBLIC_NETWORK_FALLBACK_ENABLED = "enabled"
PUBLIC_NETWORK_FALLBACK_DISABLED = "disabled"
PUBLIC_NETWORK_FALLBACK_UNKNOWN = "unknown"


def public_network_fallback_state(public_network_access_enabled: bool | None) -> str:
    if public_network_access_enabled is True:
        return PUBLIC_NETWORK_FALLBACK_ENABLED
    if public_network_access_enabled is False:
        return PUBLIC_NETWORK_FALLBACK_DISABLED
    return PUBLIC_NETWORK_FALLBACK_UNKNOWN
