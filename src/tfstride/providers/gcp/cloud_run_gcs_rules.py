from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    dedupe_addresses,
    evidence_item,
)
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import BoundaryType, Finding, NormalizedResource
from tfstride.providers.gcp.constants import PUBLIC_GCP_IAM_MEMBERS
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_types import (
    GCP_CLOUD_RUN_RESOURCE_TYPES,
    GCP_STORAGE_BUCKET_IAM_RESOURCE_TYPES,
    GcpResourceType,
)
from tfstride.providers.gcp.resource_utils import binding_members

_MUTATION_ACCESS_CLASSES = frozenset({"write", "delete", "administrative"})
_MUTATING_ROLE_KINDS = frozenset({"creator", "user", "admin", "custom"})
_PUBLIC_INVOKER_ROLES = frozenset({"roles/run.invoker"})


class GcpCloudRunGcsAccessRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_cloud_run_gcs_mutation_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for workload in context.inventory.by_type(*GCP_CLOUD_RUN_RESOURCE_TYPES):
            public_invokers = _unconditional_public_invokers(workload)
            if not workload.public_exposure or not public_invokers:
                continue

            mutation_paths = [
                path
                for path in gcp_facts(workload).cloud_run_gcs_access_paths
                if _is_deterministic_mutation_path(path, workload, context)
            ]
            if not mutation_paths:
                continue

            bucket_addresses = _path_string_values(mutation_paths, "bucket_address")
            iam_resource_addresses = _path_string_values(mutation_paths, "iam_resource_address")
            public_source_addresses = sorted({binding["source"] for binding in public_invokers})
            mutation_classes = _mutation_classes(mutation_paths)
            has_read_access = _has_deterministic_read_access(
                gcp_facts(workload).cloud_run_gcs_access_paths,
                set(bucket_addresses),
            )
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=2 if {"delete", "administrative"} & set(mutation_classes) else 1,
                data_sensitivity=2,
                lateral_movement=1,
                blast_radius=2 if len(bucket_addresses) > 1 else 1,
            )
            boundary = context.boundary_index.get((BoundaryType.INTERNET_TO_SERVICE, "internet", workload.address))
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=dedupe_addresses(
                        [
                            workload.address,
                            *public_source_addresses,
                            *bucket_addresses,
                            *iam_resource_addresses,
                        ]
                    ),
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rationale=_mutation_rationale(
                        workload,
                        mutation_classes,
                        bucket_addresses,
                        has_read_access=has_read_access,
                    ),
                    evidence=collect_evidence(
                        evidence_item(
                            "public_invoker_bindings",
                            _public_invoker_evidence(public_invokers),
                        ),
                        evidence_item(
                            "public_exposure_reasons",
                            workload.public_exposure_reasons,
                        ),
                        evidence_item(
                            "runtime_identity",
                            _runtime_identity_evidence(mutation_paths),
                        ),
                        evidence_item(
                            "gcs_mutation_paths",
                            _mutation_path_evidence(mutation_paths),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _unconditional_public_invokers(resource: NormalizedResource) -> list[dict[str, str]]:
    invokers: list[dict[str, str]] = []
    for binding in gcp_facts(resource).bindings:
        role = _known_string(binding.get("role"))
        source = _known_string(binding.get("source"))
        if role not in _PUBLIC_INVOKER_ROLES or source is None or binding.get("condition"):
            continue
        for member in binding_members(binding):
            if member in PUBLIC_GCP_IAM_MEMBERS:
                invokers.append({"source": source, "role": role, "member": member})
    return invokers


def _is_deterministic_mutation_path(
    path: Mapping[str, Any],
    workload: NormalizedResource,
    context: RuleEvaluationContext,
) -> bool:
    if (
        path.get("workload_address") != workload.address
        or path.get("workload_type") != workload.resource_type
        or path.get("identity_kind") != "cloud_run_service_account"
        or path.get("credential_context") != "workload_runtime"
        or path.get("grant_basis") != "storage_bucket_iam"
        or path.get("resource_scope") != "exact_bucket"
        or path.get("access_state") != "granted"
        or path.get("condition_state") != "not_configured"
        or path.get("condition") is not None
        or path.get("role_kind") not in _MUTATING_ROLE_KINDS
        or not _path_mutation_classes(path)
    ):
        return False

    service_account_member = _known_string(path.get("service_account_member"))
    role = _known_string(path.get("role"))
    bucket_address = _known_string(path.get("bucket_address"))
    iam_resource_address = _known_string(path.get("iam_resource_address"))
    if not all((service_account_member, role, bucket_address, iam_resource_address)):
        return False

    bucket = context.inventory.get_by_address(bucket_address)
    iam_resource = context.inventory.get_by_address(iam_resource_address)
    if (
        bucket is None
        or bucket.resource_type != GcpResourceType.STORAGE_BUCKET
        or iam_resource is None
        or iam_resource.resource_type not in GCP_STORAGE_BUCKET_IAM_RESOURCE_TYPES
    ):
        return False

    if path.get("role_kind") == "custom" and not _string_values(path.get("matched_permissions")):
        return False
    return True


def _mutation_rationale(
    workload: NormalizedResource,
    mutation_classes: list[str],
    bucket_addresses: list[str],
    *,
    has_read_access: bool,
) -> str:
    rationale = (
        f"{workload.display_name} is publicly invokable and its Cloud Run runtime service account has "
        f"deterministic {', '.join(mutation_classes)} access to {len(bucket_addresses)} exact modeled GCS "
        f"bucket(s). A compromise of the public workload could tamper with stored data by "
        f"{_mutation_impact(mutation_classes)} within the modeled grants. "
        "This path does not mean that the GCS bucket itself is public."
    )
    if not has_read_access:
        rationale += (
            " The modeled grant is write-only: it represents tampering risk and does not establish read access "
            "or information disclosure."
        )
    return rationale


def _mutation_impact(mutation_classes: list[str]) -> str:
    impacts = {
        "write": "writing objects",
        "delete": "deleting objects",
        "administrative": "changing bucket or object controls",
    }
    values = [impacts[access_class] for access_class in mutation_classes]
    if len(values) == 1:
        return values[0]
    return ", ".join(values[:-1]) + f", or {values[-1]}"


def _has_deterministic_read_access(
    paths: list[dict[str, Any]],
    bucket_addresses: set[str],
) -> bool:
    return any(
        path.get("bucket_address") in bucket_addresses
        and path.get("access_state") == "granted"
        and path.get("condition_state") == "not_configured"
        and "read" in _string_values(path.get("access_classes"))
        for path in paths
    )


def _mutation_classes(paths: list[dict[str, Any]]) -> list[str]:
    classes = {access_class for path in paths for access_class in _path_mutation_classes(path)}
    return [access_class for access_class in ("write", "delete", "administrative") if access_class in classes]


def _path_mutation_classes(path: Mapping[str, Any]) -> list[str]:
    return [
        access_class
        for access_class in _string_values(path.get("access_classes"))
        if access_class in _MUTATION_ACCESS_CLASSES
    ]


def _path_string_values(paths: list[dict[str, Any]], key: str) -> list[str]:
    return sorted({value for path in paths if (value := _known_string(path.get(key))) is not None})


def _public_invoker_evidence(invokers: list[dict[str, str]]) -> list[str]:
    return sorted(
        {
            f"source={invoker['source']}; role={invoker['role']}; member={invoker['member']}; condition=none"
            for invoker in invokers
        }
    )


def _runtime_identity_evidence(paths: list[dict[str, Any]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"service_account={path.get('service_account_email') or 'unknown'}",
                    f"member={path['service_account_member']}",
                    f"role={path['role']}",
                    f"role_kind={path['role_kind']}",
                    "credential_context=workload_runtime",
                )
            )
            for path in paths
        }
    )


def _mutation_path_evidence(paths: list[dict[str, Any]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"bucket_address={path['bucket_address']}",
                    f"bucket_name={path.get('bucket_name') or 'unknown'}",
                    f"iam_resource={path['iam_resource_address']}",
                    f"role={path['role']}",
                    f"role_kind={path['role_kind']}",
                    f"mutation_classes={','.join(_path_mutation_classes(path))}",
                    f"access_classes={','.join(_string_values(path.get('access_classes')))}",
                    f"matched_permissions={','.join(_string_values(path.get('matched_permissions'))) or 'built-in-role'}",
                    "resource_scope=exact_bucket",
                    "access_state=granted",
                    "condition_state=not_configured",
                )
            )
            for path in paths
        }
    )


def _string_values(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


def _known_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None
