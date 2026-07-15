from __future__ import annotations

from urllib.parse import urlsplit

_UNRESOLVED_MARKERS = ("$" + "{", "<known after apply>", "(known after apply)", "known after apply")


def normalize_container_registry_login_server(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or any(marker in text.lower() for marker in _UNRESOLVED_MARKERS):
        return None

    if "://" in text:
        parsed = urlsplit(text)
        if not parsed.netloc or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            return None
        return parsed.netloc.lower()

    normalized = text.rstrip("/").lower()
    if not normalized or "/" in normalized:
        return None
    return normalized
