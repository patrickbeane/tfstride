from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Literal


def is_exact_s3_bucket_arn(value: str | None) -> bool:
    if not value or any(marker in value for marker in ("*", "?", "[", "]", "${")):
        return False
    parts = value.split(":", 5)
    return bool(
        len(parts) == 6
        and parts[0] == "arn"
        and parts[1]
        and parts[2:5] == ["s3", "", ""]
        and parts[5]
        and "/" not in parts[5]
        and ":" not in parts[5]
    )


def s3_resource_for_bucket(
    resource: str,
    bucket_arn: str,
    resource_kind: Literal["bucket_level", "object_level"],
) -> str | None:
    """Bind a grant to a guaranteed scope in one exact modeled bucket.

    A wildcard bucket selector may also consume key separators. For object
    grants we retain the namespace guaranteed by matching the selector to the
    bucket itself; we never expand that namespace to those additional matches.
    Deny callers must retain uncertainty for such additional matches.
    """
    if not is_exact_s3_bucket_arn(bucket_arn) or "${" in resource:
        return None
    if resource == "*":
        return bucket_arn if resource_kind == "bucket_level" else bucket_arn + "/*"
    parts = resource.split(":", 5)
    if len(parts) != 6 or parts[:5] != bucket_arn.split(":", 5)[:5]:
        return None
    selector, separator, key = parts[5].partition("/")
    # IAM supports * and ?, not fnmatch's bracket character classes.
    if "[" in selector or "]" in selector:
        return None
    if resource_kind == "bucket_level":
        return bucket_arn if fnmatchcase(bucket_arn, resource) else None
    if separator:
        if key and fnmatchcase(bucket_arn.split(":", 5)[5], selector):
            return bucket_arn + "/" + key
    elif resource.endswith("*") and fnmatchcase(bucket_arn + "/", resource):
        return bucket_arn + "/*"
    return None


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
    if "${" in resource:
        return None
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
