from __future__ import annotations

from tfstride.models import (
    NormalizedResource,
    ResourceCategory,
    SecurityGroupRule,
    TerraformResource,
)
from tfstride.providers.gcp.metadata import GcpResourceMetadata


def _org_policy_policy(
    address: str,
    *,
    constraint: str,
    parent: str = "projects/tfstride-demo",
    enforced: bool | None = None,
    inherit_from_parent: bool | None = None,
    restore_default: bool | None = None,
    allowed_values: list[str] | None = None,
    denied_values: list[str] | None = None,
) -> TerraformResource:
    rule: dict[str, object] = {}
    if enforced is not None:
        rule["enforce"] = enforced
    values: dict[str, object] = {}
    if allowed_values is not None:
        values["allowed_values"] = allowed_values
    if denied_values is not None:
        values["denied_values"] = denied_values
    if values:
        rule["values"] = [values]
    spec: dict[str, object] = {"rules": [rule]}
    if inherit_from_parent is not None:
        spec["inherit_from_parent"] = inherit_from_parent
    resource_values: dict[str, object] = {
        "name": f"{parent}/policies/{constraint}",
        "parent": parent,
        "spec": [spec],
    }
    if restore_default is not None:
        resource_values["reset"] = restore_default
    return TerraformResource(
        address=address,
        mode="managed",
        resource_type="google_org_policy_policy",
        name=address.rsplit(".", 1)[-1],
        provider_name="registry.terraform.io/hashicorp/google",
        values=resource_values,
    )


def _load_balancer_fronted_metadata(
    path: list[str],
    *,
    forwarding_rule: str = "google_compute_global_forwarding_rule.web",
) -> dict[str, object]:
    return {
        GcpResourceMetadata.FRONTED_BY_INTERNET_FACING_LOAD_BALANCER: True,
        GcpResourceMetadata.INTERNET_FACING_LOAD_BALANCER_ADDRESSES: [forwarding_rule],
        GcpResourceMetadata.LOAD_BALANCER_FRONTENDS: [
            {
                "forwarding_rule": forwarding_rule,
                "load_balancing_scheme": "EXTERNAL_MANAGED",
                "ip_address": "35.1.2.3",
                "ports": ["443"],
                "path": path,
            }
        ],
    }


def _normalized_gcp_resource(
    address: str,
    resource_type: str,
    category: ResourceCategory,
    *,
    identifier: str | None = None,
    vpc_id: str | None = None,
    network_rules: list[SecurityGroupRule] | None = None,
    public_access_configured: bool = False,
    data_sensitivity: str = "standard",
    metadata: dict[str, object] | None = None,
) -> NormalizedResource:
    return NormalizedResource(
        address=address,
        provider="gcp",
        resource_type=resource_type,
        name=address.rsplit(".", 1)[-1],
        category=category,
        identifier=identifier,
        vpc_id=vpc_id,
        network_rules=network_rules or [],
        public_access_configured=public_access_configured,
        data_sensitivity=data_sensitivity,
        metadata=metadata,
    )
