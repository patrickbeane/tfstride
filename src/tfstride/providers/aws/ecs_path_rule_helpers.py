from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, TypeVar

from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import BoundaryType, EvidenceItem, NormalizedResource
from tfstride.providers.aws.analysis_indexes import aws_analysis_indexes

_Path = TypeVar("_Path", bound=Mapping[str, Any])


def path_string_values(paths: Iterable[Mapping[str, Any]], key: str) -> list[str]:
    values: set[str] = set()
    for path in paths:
        value = path.get(key)
        if isinstance(value, str) and value:
            values.add(value)
        elif isinstance(value, list):
            values.update(item for item in value if isinstance(item, str) and item)
    return sorted(values)


def verified_public_service_ingress(
    service: NormalizedResource,
    context: RuleEvaluationContext,
) -> EcsPublicIngress:
    indexes = context.analysis_indexes
    assert indexes is not None
    paths = aws_analysis_indexes(indexes, context.inventory).ecs_public_ingress.get(service.address, ())
    return EcsPublicIngress(service.address, paths)


def internet_boundary_id(
    load_balancer_addresses: list[str],
    context: RuleEvaluationContext,
) -> str | None:
    return next(
        (
            boundary.identifier
            for address in load_balancer_addresses
            if (boundary := context.boundary_index.get((BoundaryType.INTERNET_TO_SERVICE, "internet", address)))
            is not None
        ),
        None,
    )


@dataclass(frozen=True, slots=True)
class EcsPublicIngress:
    service_address: str
    paths: tuple[dict[str, Any], ...]

    def current_workload_paths(self, paths: Iterable[_Path]) -> list[_Path]:
        task_addresses = {
            proof["task_definition_address"]
            for path in self.paths
            for proof in path["checks"]["container_binding"]["evidence"]
        }
        return [
            path
            for path in paths
            if path.get("workload_address") == self.service_address
            and path.get("task_definition_address") in task_addresses
        ]

    @property
    def load_balancer_addresses(self) -> list[str]:
        return path_string_values(self.paths, "load_balancer_address")

    @property
    def resource_addresses(self) -> list[str]:
        return list(
            dict.fromkeys(
                path[key]
                for path in self.paths
                for key in (
                    "load_balancer_address",
                    "listener_address",
                    "action_source_address",
                    "target_group_address",
                )
            )
        )

    @property
    def network_path(self) -> list[str]:
        return [
            line
            for path in self.paths
            for line in (
                f"internet reaches {path['load_balancer_address']} through {path['listener_address']} "
                f"({path['listener_protocol']} TCP {path['listener_port']})",
                f"{path['action_source_address']} forwards through {path['target_group_address']} to "
                f"{self.service_address} container={path['container_name']} "
                f"({path['backend_protocol']} TCP {path['backend_port']})",
            )
        ]

    @property
    def evidence(self) -> list[EvidenceItem]:
        forwarding: list[str] = []
        permissions: list[str] = []
        for path in self.paths:
            forwarding.append(
                "; ".join(
                    (
                        f"listener={path['listener_address']}",
                        f"action_source={path['action_source_address']}",
                        f"target_group={path['target_group_address']}",
                        f"service={self.service_address}",
                        f"container={path['container_name']}:{path['backend_port']}",
                        f"target_weight={path['target_weight']}",
                        f"conditions={_json(path['conditions'])}",
                        f"request_witness={_json(path['request_witness'])}",
                        f"authentication_actions={_json(path['authentication_actions'])}",
                        f"evaluation_scope={path['evaluation_scope']}",
                    )
                )
            )
            for name, check in path["checks"].items():
                for proof in check["evidence"]:
                    permissions.append(
                        f"listener={path['listener_address']}; target_group={path['target_group_address']}; "
                        f"check={name}; state=allowed; evidence={_json(proof)}"
                    )
        return [
            EvidenceItem(key="public_ingress", values=list(dict.fromkeys(forwarding))),
            EvidenceItem(key="network_permissions", values=list(dict.fromkeys(permissions))),
        ]


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))
