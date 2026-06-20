from __future__ import annotations


def normalize_provider_name(provider: str) -> str:
    return str(provider).strip().lower()
