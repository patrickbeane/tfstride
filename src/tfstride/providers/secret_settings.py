from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

_CAMEL_ACRONYM_BOUNDARY_RE = re.compile(r"([A-Z]+)([A-Z][a-z])")
_CAMEL_WORD_BOUNDARY_RE = re.compile(r"([a-z0-9])([A-Z])")
_NON_ALPHANUMERIC_RE = re.compile(r"[^A-Za-z0-9]+")
_UNRESOLVED_MARKERS = ("${", "<known after apply>", "(known after apply)", "known after apply")


class SensitiveSettingCategory(str, Enum):
    """High-confidence categories inferred from setting names only."""

    PASSWORD = "password"
    CLIENT_SECRET = "client-secret"
    API_KEY = "api-key"
    TOKEN = "token"
    PRIVATE_KEY = "private-key"
    CONNECTION_STRING = "connection-string"
    SECRET_ACCESS_KEY = "secret-access-key"


@dataclass(frozen=True, slots=True)
class SensitiveSettingClassification:
    """A syntax-only classification that cannot retain setting values."""

    normalized_name: str
    category: SensitiveSettingCategory


_SENSITIVE_SUFFIXES: tuple[tuple[tuple[str, ...], SensitiveSettingCategory], ...] = (
    (("secret", "access", "key"), SensitiveSettingCategory.SECRET_ACCESS_KEY),
    (("connection", "string"), SensitiveSettingCategory.CONNECTION_STRING),
    (("client", "secret"), SensitiveSettingCategory.CLIENT_SECRET),
    (("private", "key"), SensitiveSettingCategory.PRIVATE_KEY),
    (("api", "key"), SensitiveSettingCategory.API_KEY),
    (("access", "token"), SensitiveSettingCategory.TOKEN),
    (("refresh", "token"), SensitiveSettingCategory.TOKEN),
    (("auth", "token"), SensitiveSettingCategory.TOKEN),
    (("bearer", "token"), SensitiveSettingCategory.TOKEN),
    (("id", "token"), SensitiveSettingCategory.TOKEN),
    (("password",), SensitiveSettingCategory.PASSWORD),
    (("passwd",), SensitiveSettingCategory.PASSWORD),
)


def classify_sensitive_setting_name(value: object) -> SensitiveSettingClassification | None:
    """Classify a deterministic setting name without inspecting its value."""

    normalized_name = _normalize_setting_name(value)
    if normalized_name is None:
        return None

    parts = tuple(normalized_name.split("_"))
    for suffix, category in _SENSITIVE_SUFFIXES:
        if parts[-len(suffix) :] == suffix:
            return SensitiveSettingClassification(
                normalized_name=normalized_name,
                category=category,
            )
    return None


def redacted_sensitive_setting_evidence(
    classification: SensitiveSettingClassification,
    *,
    path: str | None = None,
) -> str:
    """Describe a classified setting without accepting or exposing its value."""

    parts = []
    if path and path.strip():
        parts.append(f"path={path.strip()}")
    parts.extend(
        (
            f"setting={classification.normalized_name}",
            f"category={classification.category.value}",
            "value=<redacted>",
        )
    )
    return "; ".join(parts)


def _normalize_setting_name(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    name = value.strip()
    if not name or any(marker in name.lower() for marker in _UNRESOLVED_MARKERS):
        return None
    name = _CAMEL_ACRONYM_BOUNDARY_RE.sub(r"\1_\2", name)
    name = _CAMEL_WORD_BOUNDARY_RE.sub(r"\1_\2", name)
    name = _NON_ALPHANUMERIC_RE.sub("_", name).strip("_").lower()
    return name or None
