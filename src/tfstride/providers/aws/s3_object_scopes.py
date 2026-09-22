from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True, slots=True)
class S3ObjectScope:
    """An exact key, a literal key prefix, or the object namespace of one bucket."""

    bucket_arn: str
    kind: Literal["exact", "prefix", "all"]
    key: str | None

    @property
    def resource(self) -> str:
        if self.kind == "all":
            return f"{self.bucket_arn}/*"
        assert self.key is not None
        suffix = "*" if self.kind == "prefix" else ""
        return f"{self.bucket_arn}/{self.key}{suffix}"


def object_scope_from_resource(resource: str, bucket_arn: str) -> S3ObjectScope | None:
    prefix = f"{bucket_arn}/"
    if not resource.startswith(prefix):
        return None
    object_pattern = resource[len(prefix) :]
    if not object_pattern:
        return None
    if object_pattern == "*":
        return S3ObjectScope(bucket_arn, "all", None)
    if "?" in object_pattern or "*" in object_pattern[:-1]:
        return None
    if object_pattern.endswith("*"):
        bounded_prefix = object_pattern[:-1]
        if not bounded_prefix:
            return S3ObjectScope(bucket_arn, "all", None)
        return S3ObjectScope(bucket_arn, "prefix", bounded_prefix)
    return S3ObjectScope(bucket_arn, "exact", object_pattern)


def object_scope_intersection(left: S3ObjectScope, right: S3ObjectScope) -> S3ObjectScope | None:
    if left.bucket_arn != right.bucket_arn:
        return None
    if left.kind == "all":
        return right
    if right.kind == "all":
        return left
    assert left.key is not None
    assert right.key is not None
    if left.kind == "exact" and right.kind == "exact":
        return left if left.key == right.key else None
    if left.kind == "exact" and right.kind == "prefix":
        return left if left.key.startswith(right.key) else None
    if left.kind == "prefix" and right.kind == "exact":
        return right if right.key.startswith(left.key) else None
    if left.key.startswith(right.key):
        return left
    if right.key.startswith(left.key):
        return right
    return None


def object_scopes_overlap(left: S3ObjectScope, right: S3ObjectScope) -> bool:
    return object_scope_intersection(left, right) is not None


def object_scope_contains(container: S3ObjectScope, target: S3ObjectScope) -> bool:
    intersection = object_scope_intersection(container, target)
    return intersection == target
