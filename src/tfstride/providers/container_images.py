from __future__ import annotations

import re
from dataclasses import dataclass

_DIGEST_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+_.-]*:[A-Za-z0-9=_-]+$")
_UNRESOLVED_MARKERS = ("${", "<known after apply>", "(known after apply)", "known after apply")


@dataclass(frozen=True, slots=True)
class ContainerImageReference:
    """Syntax-only representation of a container image reference."""

    raw: str | None
    registry_host: str | None
    repository: str | None
    tag: str | None
    digest: str | None
    digest_pinned: bool | None
    unresolved_value: object | None = None
    unresolved_reason: str | None = None

    @property
    def is_resolved(self) -> bool:
        return self.unresolved_reason is None and self.raw is not None


def parse_container_image_reference(value: object) -> ContainerImageReference:
    """Parse an explicit container image reference without provider semantics."""

    if value is None:
        return _unresolved(None, "image reference is not represented")
    if not isinstance(value, str):
        return _unresolved(value, "image reference is not a string")

    raw = value
    reference = value.strip()
    if not reference:
        return _unresolved(raw, "image reference is empty")
    if any(marker in reference.lower() for marker in _UNRESOLVED_MARKERS):
        return _unresolved(raw, "image reference is unresolved")
    if any(character.isspace() for character in reference):
        return _unresolved(raw, "image reference contains whitespace")

    name, digest = _split_digest(reference)
    if digest is not None and not _DIGEST_RE.fullmatch(digest):
        return _unresolved(raw, "image digest has invalid syntax")

    name, tag = _split_tag(name)
    parts = name.split("/")
    if any(not part for part in parts):
        return _unresolved(raw, "image repository path is empty")

    registry_host = parts[0] if _has_explicit_registry(parts[0]) else None
    repository_parts = parts[1:] if registry_host is not None else parts
    if not repository_parts:
        return _unresolved(raw, "image repository path is missing")

    return ContainerImageReference(
        raw=raw,
        registry_host=registry_host,
        repository="/".join(repository_parts),
        tag=tag,
        digest=digest,
        digest_pinned=digest is not None,
    )


def _split_digest(reference: str) -> tuple[str, str | None]:
    if "@" not in reference:
        return reference, None
    name, separator, digest = reference.rpartition("@")
    if not separator or not name or not digest:
        return reference, ""
    return name, digest


def _split_tag(name: str) -> tuple[str, str | None]:
    last_slash = name.rfind("/")
    last_colon = name.rfind(":")
    if last_colon <= last_slash:
        return name, None
    tag = name[last_colon + 1 :]
    if not tag:
        return name, ""
    return name[:last_colon], tag


def _has_explicit_registry(first_path_part: str) -> bool:
    return first_path_part == "localhost" or "." in first_path_part or ":" in first_path_part


def _unresolved(value: object | None, reason: str) -> ContainerImageReference:
    return ContainerImageReference(
        raw=value if isinstance(value, str) else None,
        registry_host=None,
        repository=None,
        tag=None,
        digest=None,
        digest_pinned=None,
        unresolved_value=value,
        unresolved_reason=reason,
    )
