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
    GCP_PUBSUB_SUBSCRIPTION_IAM_RESOURCE_TYPES,
    GCP_PUBSUB_TOPIC_IAM_RESOURCE_TYPES,
    GcpResourceType,
)
from tfstride.providers.gcp.resource_utils import binding_members

_MUTATION_ACCESS_CLASSES = frozenset({"publish", "delete", "administrative"})
_PUBLIC_INVOKER_ROLES = frozenset({"roles/run.invoker", "roles/run.servicesInvoker"})
_PUBSUB_TARGET_TYPES = frozenset(
    {
        GcpResourceType.PUBSUB_TOPIC,
        GcpResourceType.PUBSUB_SUBSCRIPTION,
    }
)
_PUBSUB_IAM_RESOURCE_TYPES = GCP_PUBSUB_TOPIC_IAM_RESOURCE_TYPES | GCP_PUBSUB_SUBSCRIPTION_IAM_RESOURCE_TYPES


class GcpCloudRunPubsubAccessRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_cloud_run_pubsub_mutation_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for workload in context.inventory.by_type(*GCP_CLOUD_RUN_RESOURCE_TYPES):
            public_invokers = _unconditional_public_invokers(workload)
            invoker_iam_check_disabled = gcp_facts(workload).cloud_run_invoker_iam_disabled is True
            if not workload.public_exposure or (not public_invokers and not invoker_iam_check_disabled):
                continue

            mutation_paths = [
                path
                for path in gcp_facts(workload).cloud_run_pubsub_access_paths
                if _is_deterministic_mutation_path(path, workload, context)
            ]
            if not mutation_paths:
                continue

            target_addresses = _path_string_values(mutation_paths, "messaging_resource_address")
            iam_resource_addresses = _path_string_values(mutation_paths, "iam_resource_address")
            public_source_addresses = sorted({binding["source"] for binding in public_invokers})
            mutation_classes = _mutation_classes(mutation_paths)
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=(2 if {"delete", "administrative"} & set(mutation_classes) else 1),
                data_sensitivity=1,
                lateral_movement=1,
                blast_radius=2 if len(target_addresses) > 1 else 1,
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
                            *target_addresses,
                            *iam_resource_addresses,
                        ]
                    ),
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rationale=_mutation_rationale(workload, mutation_classes, target_addresses),
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
                            "public_exposure_configuration",
                            _public_exposure_configuration(workload),
                        ),
                        evidence_item(
                            "runtime_identity",
                            _runtime_identity_evidence(mutation_paths),
                        ),
                        evidence_item(
                            "pubsub_mutation_paths",
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
        if (
            role not in _PUBLIC_INVOKER_ROLES
            or source is None
            or binding.get("condition")
            or binding.get("condition_state") == "unknown"
        ):
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
        or path.get("messaging_service") != "pubsub"
        or path.get("grant_basis") not in {"pubsub_topic_iam", "pubsub_subscription_iam"}
        or path.get("resource_scope") not in {"exact_topic", "exact_subscription"}
        or path.get("access_state") != "granted"
        or path.get("condition_state") != "not_configured"
        or path.get("condition") is not None
        or not _path_mutation_classes(path)
    ):
        return False

    service_account_member = _known_string(path.get("service_account_member"))
    role = _known_string(path.get("role"))
    target_address = _known_string(path.get("messaging_resource_address"))
    iam_resource_address = _known_string(path.get("iam_resource_address"))
    if not all((service_account_member, role, target_address, iam_resource_address)):
        return False

    target = context.inventory.get_by_address(target_address)
    iam_resource = context.inventory.get_by_address(iam_resource_address)
    if (
        target is None
        or target.resource_type not in _PUBSUB_TARGET_TYPES
        or iam_resource is None
        or iam_resource.resource_type not in _PUBSUB_IAM_RESOURCE_TYPES
    ):
        return False

    if path.get("role_kind") == "custom" and not _string_values(path.get("matched_permissions")):
        return False
    return True


def _mutation_rationale(
    workload: NormalizedResource,
    mutation_classes: list[str],
    target_addresses: list[str],
) -> str:
    rationale = (
        f"{workload.display_name} is publicly invokable and its Cloud Run runtime service account has "
        f"deterministic {', '.join(mutation_classes)} access to {len(target_addresses)} exact modeled "
        f"Pub/Sub target(s). A compromise of the public workload could {_mutation_impact(mutation_classes)} "
        "within the modeled grants."
    )
    if "administrative" in mutation_classes:
        rationale += (
            " Some administrative operations require companion permissions that this path does not claim are present."
        )
    return rationale + " This path does not mean that the Pub/Sub topic or subscription itself is public."


def _mutation_impact(mutation_classes: list[str]) -> str:
    impacts = {
        "publish": "inject messages into a topic",
        "delete": "delete Pub/Sub topics or subscriptions",
        "administrative": "exercise administrative Pub/Sub permissions",
    }
    values = [impacts[access_class] for access_class in mutation_classes]
    if len(values) == 1:
        return values[0]
    return " or ".join(values)


def _mutation_classes(paths: list[dict[str, Any]]) -> list[str]:
    classes = {access_class for path in paths for access_class in _path_mutation_classes(path)}
    return [access_class for access_class in ("publish", "delete", "administrative") if access_class in classes]


def _path_mutation_classes(path: Mapping[str, Any]) -> list[str]:
    return [
        access_class
        for access_class in _string_values(path.get("access_classes"))
        if access_class in _MUTATION_ACCESS_CLASSES
    ]


def _path_string_values(paths: list[dict[str, Any]], key: str) -> list[str]:
    return sorted({value for path in paths if (value := _known_string(path.get(key))) is not None})


def _public_exposure_configuration(resource: NormalizedResource) -> list[str]:
    if gcp_facts(resource).cloud_run_invoker_iam_disabled is not True:
        return []
    ingress = gcp_facts(resource).serverless_ingress or "unknown"
    return [f"invoker_iam_check=disabled; ingress={ingress}"]


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
                    f"target_address={path['messaging_resource_address']}",
                    f"target_kind={path['messaging_resource_kind']}",
                    f"target_name={path.get('messaging_resource_name') or 'unknown'}",
                    f"iam_resource={path['iam_resource_address']}",
                    f"role={path['role']}",
                    f"role_kind={path['role_kind']}",
                    f"mutation_classes={','.join(_path_mutation_classes(path))}",
                    f"access_classes={','.join(_string_values(path.get('access_classes')))}",
                    f"matched_permissions={','.join(_string_values(path.get('matched_permissions'))) or 'built-in-role'}",
                    f"resource_scope={path['resource_scope']}",
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
