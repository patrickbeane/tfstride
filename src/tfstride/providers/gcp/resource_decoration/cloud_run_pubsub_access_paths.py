from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from tfstride.models import NormalizedResource
from tfstride.providers.coercion import dedupe
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_index import GcpDecorationContext
from tfstride.providers.gcp.resource_types import GCP_CLOUD_RUN_RESOURCE_TYPES, GcpResourceType
from tfstride.providers.gcp.resource_utils import (
    GCP_ROLE_REFERENCE_SUFFIXES,
    binding_members,
    gcp_reference_key,
)

if TYPE_CHECKING:
    from tfstride.providers.gcp.custom_roles import GcpCustomRoleIndex

_ACCESS_CLASS_ORDER = ("read", "publish", "consume", "delete", "administrative")
_TOPIC_BUILT_IN_ROLE_ACCESS: dict[str, tuple[str, tuple[str, ...]]] = {
    "roles/pubsub.publisher": ("publisher", ("publish",)),
    "roles/pubsub.subscriber": ("subscriber", ("administrative",)),
    "roles/pubsub.viewer": ("viewer", ("read",)),
    "roles/pubsub.editor": ("editor", ("read", "publish", "delete", "administrative")),
    "roles/pubsub.admin": ("admin", ("read", "publish", "delete", "administrative")),
}
_SUBSCRIPTION_BUILT_IN_ROLE_ACCESS: dict[str, tuple[str, tuple[str, ...]]] = {
    "roles/pubsub.subscriber": ("subscriber", ("consume",)),
    "roles/pubsub.viewer": ("viewer", ("read",)),
    "roles/pubsub.editor": ("editor", ("read", "consume", "delete", "administrative")),
    "roles/pubsub.admin": ("admin", ("read", "consume", "delete", "administrative")),
}
_TOPIC_PERMISSION_CLASSES = {
    "pubsub.topics.get": "read",
    "pubsub.topics.getiampolicy": "read",
    "pubsub.topics.publish": "publish",
    "pubsub.topics.delete": "delete",
    "pubsub.topics.attachsubscription": "administrative",
    "pubsub.topics.detachsubscription": "administrative",
    "pubsub.topics.setiampolicy": "administrative",
    "pubsub.topics.update": "administrative",
}
_SUBSCRIPTION_PERMISSION_CLASSES = {
    "pubsub.subscriptions.get": "read",
    "pubsub.subscriptions.getiampolicy": "read",
    "pubsub.subscriptions.consume": "consume",
    "pubsub.subscriptions.delete": "delete",
    "pubsub.subscriptions.setiampolicy": "administrative",
    "pubsub.subscriptions.update": "administrative",
}


@dataclass(frozen=True, slots=True)
class _PubsubRoleAccess:
    role_kind: str
    access_classes: tuple[str, ...]
    custom_role_permissions: tuple[str, ...] = ()
    matched_permissions: tuple[str, ...] = ()


class ModelCloudRunPubsubAccessPathsStage:
    name = "model_cloud_run_pubsub_access_paths"

    def apply(self, resources: list[NormalizedResource], context: GcpDecorationContext) -> None:
        # Delay this provider-local import to keep normalizer/plugin initialization acyclic.
        from tfstride.providers.gcp.custom_roles import build_gcp_custom_role_index

        del context
        custom_roles = build_gcp_custom_role_index(resources)
        targets = tuple(
            resource
            for resource in resources
            if resource.resource_type in {GcpResourceType.PUBSUB_TOPIC, GcpResourceType.PUBSUB_SUBSCRIPTION}
        )
        for workload in resources:
            if workload.resource_type not in GCP_CLOUD_RUN_RESOURCE_TYPES:
                continue
            paths, uncertainties = _cloud_run_pubsub_access_paths(workload, targets, custom_roles)
            facts = gcp_facts(workload)
            facts.set_cloud_run_pubsub_access_paths(paths)
            facts.extend_cloud_run_pubsub_access_path_uncertainties(uncertainties)


def _cloud_run_pubsub_access_paths(
    workload: NormalizedResource,
    targets: tuple[NormalizedResource, ...],
    custom_roles: GcpCustomRoleIndex,
) -> tuple[list[dict[str, Any]], list[str]]:
    workload_facts = gcp_facts(workload)
    service_account_member = workload_facts.service_account_member
    if not service_account_member:
        return [], [f"{workload.address}: Cloud Run service account is unresolved"]

    paths: list[dict[str, Any]] = []
    uncertainties: list[str] = []
    seen: set[tuple[str, str, str, str]] = set()
    for target in targets:
        target_kind = _target_kind(target)
        for binding in gcp_facts(target).bindings:
            if service_account_member not in binding_members(binding):
                continue
            role = _known_string(binding.get("role"))
            source = _known_string(binding.get("source"))
            if role is None or role == "unknown role":
                uncertainties.append(f"{workload.address}: {source or target.address} IAM role is unresolved")
                continue
            role_access = _role_access(role, target_kind, custom_roles)
            if role_access is None:
                if _looks_like_custom_role(role):
                    uncertainties.append(
                        f"{workload.address}: {source or target.address} custom IAM role {role} "
                        "does not resolve to deterministic Pub/Sub permissions"
                    )
                continue

            condition = _condition(binding.get("condition"))
            condition_state = _condition_state(binding, condition)
            if condition_state == "unknown":
                uncertainties.append(
                    f"{workload.address}: {source or target.address} IAM condition is unknown after planning"
                )
            fingerprint = (
                target.address,
                source or "",
                role,
                json.dumps(
                    {"condition": condition, "condition_state": condition_state},
                    sort_keys=True,
                    default=str,
                ),
            )
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            paths.append(
                _access_path_record(
                    workload,
                    target,
                    target_kind,
                    service_account_member,
                    source,
                    role,
                    role_access,
                    condition,
                    condition_state,
                )
            )

    return paths, dedupe(uncertainties)


def _target_kind(target: NormalizedResource) -> str:
    return "topic" if target.resource_type == GcpResourceType.PUBSUB_TOPIC else "subscription"


def _role_access(
    role: str,
    target_kind: str,
    custom_roles: GcpCustomRoleIndex,
) -> _PubsubRoleAccess | None:
    built_in_roles = _TOPIC_BUILT_IN_ROLE_ACCESS if target_kind == "topic" else _SUBSCRIPTION_BUILT_IN_ROLE_ACCESS
    built_in = built_in_roles.get(role)
    if built_in is not None:
        role_kind, access_classes = built_in
        return _PubsubRoleAccess(role_kind, access_classes)

    permissions = custom_roles.permissions_by_reference.get(
        gcp_reference_key(role, GCP_ROLE_REFERENCE_SUFFIXES),
        (),
    )
    matched_permissions = tuple(
        sorted(permission for permission in permissions if _permission_class(permission, target_kind) is not None)
    )
    if not matched_permissions:
        return None
    return _PubsubRoleAccess(
        "custom",
        _custom_access_classes(matched_permissions, target_kind),
        custom_role_permissions=permissions,
        matched_permissions=matched_permissions,
    )


def _custom_access_classes(permissions: tuple[str, ...], target_kind: str) -> tuple[str, ...]:
    classes = {
        access_class
        for permission in permissions
        if (access_class := _permission_class(permission, target_kind)) is not None
    }
    if _has_target_wildcard(permissions, target_kind):
        classes.update(_applicable_access_classes(target_kind))
    return tuple(access_class for access_class in _ACCESS_CLASS_ORDER if access_class in classes)


def _permission_class(permission: str, target_kind: str) -> str | None:
    normalized = permission.strip().lower()
    if normalized in {"*", "pubsub.*"}:
        return "administrative"
    if target_kind == "topic":
        if normalized == "pubsub.topics.*":
            return "administrative"
        return _TOPIC_PERMISSION_CLASSES.get(normalized)
    if normalized == "pubsub.subscriptions.*":
        return "administrative"
    return _SUBSCRIPTION_PERMISSION_CLASSES.get(normalized)


def _has_target_wildcard(permissions: tuple[str, ...], target_kind: str) -> bool:
    target_wildcard = "pubsub.topics.*" if target_kind == "topic" else "pubsub.subscriptions.*"
    return any(permission.strip().lower() in {"*", "pubsub.*", target_wildcard} for permission in permissions)


def _applicable_access_classes(target_kind: str) -> tuple[str, ...]:
    if target_kind == "topic":
        return ("read", "publish", "delete", "administrative")
    return ("read", "consume", "delete", "administrative")


def _access_path_record(
    workload: NormalizedResource,
    target: NormalizedResource,
    target_kind: str,
    service_account_member: str,
    iam_resource_address: str | None,
    role: str,
    role_access: _PubsubRoleAccess,
    condition: dict[str, Any] | None,
    condition_state: str,
) -> dict[str, Any]:
    workload_facts = gcp_facts(workload)
    target_facts = gcp_facts(target)
    target_reference = (
        target_facts.pubsub_topic_reference if target_kind == "topic" else target_facts.pubsub_subscription_reference
    )
    return {
        "workload_address": workload.address,
        "workload_type": workload.resource_type,
        "service_account_email": workload_facts.service_account_email,
        "service_account_member": service_account_member,
        "identity_kind": "cloud_run_service_account",
        "credential_context": "workload_runtime",
        "messaging_service": "pubsub",
        "messaging_resource_kind": target_kind,
        "messaging_resource_address": target.address,
        "messaging_resource_type": target.resource_type,
        "messaging_resource_name": target_facts.resource_name or target.name,
        "messaging_resource_project": target_facts.project,
        "messaging_resource_reference": target_reference or target.identifier,
        "iam_resource_address": iam_resource_address,
        "role": role,
        "role_kind": role_access.role_kind,
        "access_classes": list(role_access.access_classes),
        "custom_role_permissions": list(role_access.custom_role_permissions),
        "matched_permissions": list(role_access.matched_permissions),
        "grant_basis": f"pubsub_{target_kind}_iam",
        "resource_scope": f"exact_{target_kind}",
        "condition": condition,
        "condition_state": condition_state,
        "access_state": _access_state(condition_state),
    }


def _condition_state(binding: Mapping[str, Any], condition: dict[str, Any] | None) -> str:
    raw_state = _known_string(binding.get("condition_state"))
    if raw_state == "unknown":
        return "unknown"
    return "configured" if condition else "not_configured"


def _access_state(condition_state: str) -> str:
    if condition_state == "unknown":
        return "unknown"
    if condition_state == "configured":
        return "conditional"
    return "granted"


def _condition(value: object) -> dict[str, Any] | None:
    if isinstance(value, Mapping):
        return {str(key): item for key, item in value.items()}
    return None


def _known_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None


def _looks_like_custom_role(role: str) -> bool:
    return role.startswith(("projects/", "organizations/")) or "iam_custom_role." in role
