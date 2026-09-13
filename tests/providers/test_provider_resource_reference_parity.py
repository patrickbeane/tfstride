from __future__ import annotations

import json
import unittest
from itertools import permutations
from pathlib import Path
from typing import Any

from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import (
    AnalysisResult,
    Finding,
    IAMPolicyStatement,
    NormalizedResource,
    ResourceCategory,
    ResourceInventory,
)
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.resource_decoration.resource_policies import MergeResourcePolicyResourcesStage
from tfstride.providers.aws.resource_decorator import AwsResourceDecorator
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import AwsResourceIndexBuilder
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.resource_decoration.storage import DecorateStorageRelationshipsStage
from tfstride.providers.azure.resource_decorator import AzureResourceDecorator
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_index import AzureResourceIndexBuilder
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_decoration.load_balancer import DeriveLoadBalancerReachabilityStage
from tfstride.providers.gcp.resource_decorator import GcpResourceDecorator
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_index import GcpResourceIndexBuilder
from tfstride.providers.gcp.resource_types import GcpResourceType
from tfstride.providers.resource_reference_index import ResourceReferenceResolution
from tfstride.reporting.json_report import render_json

_GOLDEN_PATH = Path(__file__).resolve().parents[1] / "golden" / "provider_resource_reference_parity_snapshot.json"
_PROVIDERS = ("aws", "gcp", "azure")
_RESOURCE_KEYS = ("primary", "secondary", "wrong_type", "source")
_UNIQUE_TYPED_RESOURCE_KEYS = ("primary", "wrong_type", "source")
_RULE_IDS = {
    "aws": "aws-sensitive-resource-policy-external-access",
    "gcp": "gcp-public-load-balanced-workload",
    "azure": "azure-storage-container-public-access",
}
_RELEVANT_METADATA_KEYS = frozenset(
    {
        "fronted_by_internet_facing_load_balancer",
        "internet_facing_load_balancer_addresses",
        "load_balancer_frontends",
        "load_balancer_reachable_backends",
        "public_container_addresses",
        "resolved_storage_account_address",
        "resource_policy_source_addresses",
        "unresolved_secret_arns",
        "unresolved_storage_account_references",
    }
)


def _aws_resources(*, scoped: bool) -> dict[str, NormalizedResource]:
    def secret(label: str, provider_config_key: str, account_id: str) -> NormalizedResource:
        return NormalizedResource(
            address=f"aws_secretsmanager_secret.{label}",
            provider="aws",
            resource_type="aws_secretsmanager_secret",
            name=label,
            category=ResourceCategory.DATA,
            identifier="shared",
            arn=f"arn:aws:secretsmanager:us-east-1:{account_id}:secret:{label}",
            provider_config_key=provider_config_key,
            metadata={AwsResourceMetadata.NAME: "shared"},
        )

    return {
        "primary": secret("primary", "aws.primary", "111122223333"),
        "secondary": secret("secondary", "aws.secondary", "444455556666"),
        "wrong_type": NormalizedResource(
            address="aws_s3_bucket.shared",
            provider="aws",
            resource_type="aws_s3_bucket",
            name="shared",
            category=ResourceCategory.DATA,
            identifier="shared",
            provider_config_key="aws.primary",
        ),
        "source": NormalizedResource(
            address="aws_secretsmanager_secret_policy.shared",
            provider="aws",
            resource_type="aws_secretsmanager_secret_policy",
            name="shared",
            category=ResourceCategory.IAM,
            provider_config_key="aws.primary" if scoped else None,
            metadata={
                AwsResourceMetadata.SECRET_ARN: "shared",
                AwsResourceMetadata.POLICY_DOCUMENT: {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "secretsmanager:GetSecretValue",
                            "Resource": "*",
                        }
                    ]
                },
            },
            policy_statements=(
                IAMPolicyStatement(
                    effect="Allow",
                    actions=["secretsmanager:GetSecretValue"],
                    resources=["*"],
                    principals=["*"],
                ),
            ),
        ),
    }


def _gcp_resources(*, scoped: bool) -> dict[str, NormalizedResource]:
    def backend(label: str, project: str) -> NormalizedResource:
        identifier = f"projects/{project}/global/backendServices/{label}"
        return NormalizedResource(
            address=f"google_compute_backend_service.{label}",
            provider="gcp",
            resource_type=GcpResourceType.COMPUTE_BACKEND_SERVICE,
            name=label,
            category=ResourceCategory.COMPUTE,
            identifier=identifier,
            metadata={
                GcpResourceMetadata.NAME: "shared",
                GcpResourceMetadata.PROJECT: project,
                GcpResourceMetadata.SELF_LINK: identifier,
            },
        )

    source_metadata: dict[object, object] = {
        GcpResourceMetadata.NAME: "frontend",
        GcpResourceMetadata.FORWARDING_RULE_LOAD_BALANCING_SCHEME: "EXTERNAL_MANAGED",
        GcpResourceMetadata.FORWARDING_RULE_BACKEND_SERVICE: "shared",
        GcpResourceMetadata.FORWARDING_RULE_IP_ADDRESS: "35.1.2.3",
        GcpResourceMetadata.FORWARDING_RULE_PORTS: ["443"],
    }
    source_identifier = None
    if scoped:
        source_metadata[GcpResourceMetadata.PROJECT] = "primary"
        source_identifier = "projects/primary/global/forwardingRules/frontend"

    return {
        "primary": backend("primary", "primary"),
        "secondary": backend("secondary", "secondary"),
        "wrong_type": NormalizedResource(
            address="google_kms_crypto_key.shared",
            provider="gcp",
            resource_type=GcpResourceType.KMS_CRYPTO_KEY,
            name="shared",
            category=ResourceCategory.DATA,
            identifier="projects/primary/locations/global/keyRings/app/cryptoKeys/wrong",
            metadata={
                GcpResourceMetadata.NAME: "shared",
                GcpResourceMetadata.PROJECT: "primary",
                GcpResourceMetadata.KMS_KEY_RING: "projects/primary/locations/global/keyRings/app",
            },
        ),
        "source": NormalizedResource(
            address="google_compute_global_forwarding_rule.frontend",
            provider="gcp",
            resource_type=GcpResourceType.COMPUTE_GLOBAL_FORWARDING_RULE,
            name="frontend",
            category=ResourceCategory.NETWORK,
            identifier=source_identifier,
            public_access_configured=True,
            metadata=source_metadata,
        ),
    }


def _azure_arm_id(subscription: str, provider_path: str) -> str:
    return f"/subscriptions/{subscription}/resourceGroups/application/providers/{provider_path}"


def _azure_resources(*, scoped: bool) -> dict[str, NormalizedResource]:
    def account(label: str, subscription: str) -> NormalizedResource:
        identifier = _azure_arm_id(
            subscription,
            f"Microsoft.Storage/storageAccounts/{label}",
        )
        return NormalizedResource(
            address=f"azurerm_storage_account.{label}",
            provider="azure",
            resource_type=AzureResourceType.STORAGE_ACCOUNT,
            name=label,
            category=ResourceCategory.DATA,
            identifier=identifier,
            metadata={
                AzureResourceMetadata.NAME: "shared",
                AzureResourceMetadata.STORAGE_ACCOUNT_ID: identifier,
                AzureResourceMetadata.ALLOW_NESTED_ITEMS_TO_BE_PUBLIC: True,
                AzureResourceMetadata.PUBLIC_NETWORK_ACCESS_ENABLED: True,
                AzureResourceMetadata.NETWORK_DEFAULT_ACTION: "Allow",
            },
        )

    return {
        "primary": account("primary", "sub-primary"),
        "secondary": account("secondary", "sub-secondary"),
        "wrong_type": NormalizedResource(
            address="azurerm_key_vault.shared",
            provider="azure",
            resource_type=AzureResourceType.KEY_VAULT,
            name="shared",
            category=ResourceCategory.DATA,
            identifier=_azure_arm_id(
                "sub-primary",
                "Microsoft.KeyVault/vaults/wrong",
            ),
            metadata={AzureResourceMetadata.NAME: "shared"},
        ),
        "source": NormalizedResource(
            address="azurerm_storage_container.public",
            provider="azure",
            resource_type=AzureResourceType.STORAGE_CONTAINER,
            name="public",
            category=ResourceCategory.DATA,
            identifier=(
                _azure_arm_id(
                    "sub-primary",
                    "Microsoft.Storage/storageAccounts/source/blobServices/default/containers/public",
                )
                if scoped
                else None
            ),
            metadata={
                AzureResourceMetadata.STORAGE_ACCOUNT_REFERENCE: "shared",
                AzureResourceMetadata.CONTAINER_ACCESS_TYPE: "blob",
            },
        ),
    }


def _resources_for(provider: str, *, scoped: bool) -> dict[str, NormalizedResource]:
    if provider == "aws":
        return _aws_resources(scoped=scoped)
    if provider == "gcp":
        return _gcp_resources(scoped=scoped)
    if provider == "azure":
        return _azure_resources(scoped=scoped)
    raise AssertionError(f"Unsupported provider: {provider}")


def _resolve(
    provider: str,
    resources: list[NormalizedResource],
    source: NormalizedResource,
) -> ResourceReferenceResolution:
    if provider == "aws":
        return (
            AwsResourceIndexBuilder()
            .build(resources)
            .secrets.resolve(
                "shared",
                source=source,
            )
        )
    if provider == "gcp":
        return (
            GcpResourceIndexBuilder()
            .build(resources)
            .resources_by_reference.resolve(
                "shared",
                source=source,
                resource_types={GcpResourceType.COMPUTE_BACKEND_SERVICE},
            )
        )
    if provider == "azure":
        return (
            AzureResourceIndexBuilder()
            .build(resources)
            .resources_by_reference.resolve(
                "shared",
                source=source,
                resource_types={AzureResourceType.STORAGE_ACCOUNT},
            )
        )
    raise AssertionError(f"Unsupported provider: {provider}")


def _decorate(provider: str, resources: list[NormalizedResource]) -> None:
    if provider == "aws":
        AwsResourceDecorator(stages=(MergeResourcePolicyResourcesStage(),)).decorate(resources)
        return
    if provider == "gcp":
        GcpResourceDecorator(stages=(DeriveLoadBalancerReachabilityStage(),)).decorate(resources)
        return
    if provider == "azure":
        AzureResourceDecorator(stages=(DecorateStorageRelationshipsStage(),)).decorate(resources)
        return
    raise AssertionError(f"Unsupported provider: {provider}")


def _relationship_snapshot(
    provider: str,
    resources: dict[str, NormalizedResource],
) -> dict[str, object]:
    primary = resources["primary"]
    secondary = resources["secondary"]
    source = resources["source"]

    if provider == "aws":
        return {
            "primary_policy_sources": list(aws_facts(primary).resource_policy_source_addresses),
            "secondary_policy_sources": list(aws_facts(secondary).resource_policy_source_addresses),
            "source_unresolved_references": source.get_metadata_field(AwsResourceMetadata.UNRESOLVED_SECRET_ARNS),
        }
    if provider == "gcp":
        return {
            "primary_fronted": gcp_facts(primary).fronted_by_internet_facing_load_balancer,
            "secondary_fronted": gcp_facts(secondary).fronted_by_internet_facing_load_balancer,
            "source_reachable_backends": [
                backend["backend"] for backend in gcp_facts(source).load_balancer_reachable_backends
            ],
        }
    if provider == "azure":
        return {
            "resolved_account": azure_facts(source).resolved_storage_account_address,
            "primary_public_containers": list(azure_facts(primary).public_container_addresses),
            "secondary_public_containers": list(azure_facts(secondary).public_container_addresses),
            "source_public_exposure": source.public_exposure,
            "source_unresolved_references": source.get_metadata_field(
                AzureResourceMetadata.UNRESOLVED_STORAGE_ACCOUNT_REFERENCES
            ),
        }
    raise AssertionError(f"Unsupported provider: {provider}")


_EXPECTED_SCOPED_RELATIONSHIPS = {
    "aws": {
        "primary_policy_sources": ["aws_secretsmanager_secret_policy.shared"],
        "secondary_policy_sources": [],
        "source_unresolved_references": [],
    },
    "gcp": {
        "primary_fronted": True,
        "secondary_fronted": False,
        "source_reachable_backends": ["google_compute_backend_service.primary"],
    },
    "azure": {
        "resolved_account": "azurerm_storage_account.primary",
        "primary_public_containers": ["azurerm_storage_container.public"],
        "secondary_public_containers": [],
        "source_public_exposure": True,
        "source_unresolved_references": [],
    },
}
_EXPECTED_AMBIGUOUS_RELATIONSHIPS = {
    "aws": {
        "primary_policy_sources": [],
        "secondary_policy_sources": [],
        "source_unresolved_references": ["shared"],
    },
    "gcp": {
        "primary_fronted": False,
        "secondary_fronted": False,
        "source_reachable_backends": [],
    },
    "azure": {
        "resolved_account": None,
        "primary_public_containers": [],
        "secondary_public_containers": [],
        "source_public_exposure": False,
        "source_unresolved_references": ["shared"],
    },
}
_EXPECTED_SCOPED_FINDINGS = {
    "aws": [
        {
            "rule_id": _RULE_IDS["aws"],
            "affected_resources": [
                "aws_secretsmanager_secret.primary",
                "aws_secretsmanager_secret_policy.shared",
            ],
        }
    ],
    "gcp": [
        {
            "rule_id": _RULE_IDS["gcp"],
            "affected_resources": [
                "google_compute_backend_service.primary",
                "google_compute_global_forwarding_rule.frontend",
            ],
        }
    ],
    "azure": [
        {
            "rule_id": _RULE_IDS["azure"],
            "affected_resources": [
                "azurerm_storage_account.primary",
                "azurerm_storage_container.public",
            ],
        }
    ],
}


def _finding_identity(findings: list[Finding]) -> list[dict[str, object]]:
    return [
        {
            "rule_id": finding.rule_id,
            "affected_resources": finding.affected_resources,
        }
        for finding in findings
    ]


def _analyze(
    provider: str,
    *,
    scoped: bool,
    order: tuple[str, ...],
) -> tuple[dict[str, NormalizedResource], AnalysisResult]:
    resources = _resources_for(provider, scoped=scoped)
    ordered_resources = [resources[key] for key in order]
    _decorate(provider, ordered_resources)
    inventory = ResourceInventory(provider=provider, resources=ordered_resources)
    rule_policy = RulePolicy(enabled_rule_ids=frozenset({_RULE_IDS[provider]}))
    findings = StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=rule_policy,
    )
    return resources, AnalysisResult(
        title="Provider resource reference parity",
        analyzed_file=f"{provider}-reference-parity.tfplan.json",
        analyzed_path=f"{provider}-reference-parity.tfplan.json",
        inventory=inventory,
        trust_boundaries=[],
        findings=findings,
    )


def _report_snapshot(result: AnalysisResult) -> dict[str, object]:
    payload: dict[str, Any] = json.loads(render_json(result))
    resources = []
    for resource in payload["inventory"]["resources"]:
        metadata = {key: value for key, value in resource["metadata"].items() if key in _RELEVANT_METADATA_KEYS}
        resources.append(
            {
                "address": resource["address"],
                "resource_type": resource["resource_type"],
                "public_exposure": resource["public_exposure"],
                "policy_statement_count": len(resource["policy_statements"]),
                "reference_metadata": metadata,
            }
        )
    return {
        "provider": payload["inventory"]["provider"],
        "summary": {
            "normalized_resources": payload["summary"]["normalized_resources"],
            "active_findings": payload["summary"]["active_findings"],
            "severity_counts": payload["summary"]["severity_counts"],
        },
        "resources": resources,
        "findings": [
            {
                "rule_id": finding["rule_id"],
                "category": finding["category"],
                "severity": finding["severity"],
                "affected_resources": finding["affected_resources"],
                "trust_boundary_id": finding["trust_boundary_id"],
                "evidence": finding["evidence"],
            }
            for finding in payload["findings"]
        ],
    }


class ProviderResourceReferenceParityTests(unittest.TestCase):
    maxDiff = None

    def test_scope_collision_matrix_is_typed_and_order_independent(self) -> None:
        for provider in _PROVIDERS:
            for order in permutations(_RESOURCE_KEYS):
                with self.subTest(provider=provider, order=order):
                    resources = _resources_for(provider, scoped=False)
                    ordered_resources = [resources[key] for key in order]
                    resolution = _resolve(
                        provider,
                        ordered_resources,
                        resources["source"],
                    )

                    self.assertEqual(resolution.state, "ambiguous")
                    self.assertEqual(
                        [candidate.address for candidate in resolution.candidates],
                        [
                            resources["primary"].address,
                            resources["secondary"].address,
                        ],
                    )
                    self.assertNotIn(
                        resources["wrong_type"],
                        resolution.candidates,
                    )

    def test_scope_filtering_resolves_the_right_candidate_in_every_resource_order(self) -> None:
        for provider in _PROVIDERS:
            for order in permutations(_RESOURCE_KEYS):
                with self.subTest(provider=provider, order=order):
                    resources = _resources_for(provider, scoped=True)
                    resolution = _resolve(
                        provider,
                        [resources[key] for key in order],
                        resources["source"],
                    )

                    self.assertEqual(resolution.state, "resolved")
                    self.assertIs(
                        resolution.selected_candidate,
                        resources["primary"],
                    )
                    self.assertNotIn(
                        resources["wrong_type"],
                        resolution.candidates,
                    )

    def test_wrong_type_alias_does_not_mask_a_unique_typed_candidate(self) -> None:
        for provider in _PROVIDERS:
            for order in permutations(_UNIQUE_TYPED_RESOURCE_KEYS):
                with self.subTest(provider=provider, order=order):
                    resources = _resources_for(provider, scoped=False)
                    resolution = _resolve(
                        provider,
                        [resources[key] for key in order],
                        resources["source"],
                    )

                    self.assertEqual(resolution.state, "resolved")
                    self.assertIs(
                        resolution.selected_candidate,
                        resources["primary"],
                    )
                    self.assertEqual(
                        resolution.candidates,
                        (resources["primary"],),
                    )

    def test_scoped_downstream_relationships_and_findings_are_order_stable(self) -> None:
        for provider in _PROVIDERS:
            for order in permutations(_RESOURCE_KEYS):
                with self.subTest(provider=provider, order=order):
                    resources, result = _analyze(
                        provider,
                        scoped=True,
                        order=order,
                    )

                    self.assertEqual(
                        _relationship_snapshot(provider, resources),
                        _EXPECTED_SCOPED_RELATIONSHIPS[provider],
                    )
                    self.assertEqual(
                        _finding_identity(result.findings),
                        _EXPECTED_SCOPED_FINDINGS[provider],
                    )
                    self.assertNotIn(
                        resources["wrong_type"].address,
                        {address for finding in result.findings for address in finding.affected_resources},
                    )

    def test_ambiguous_references_do_not_invent_relationships_or_findings(self) -> None:
        for provider in _PROVIDERS:
            for order in permutations(_RESOURCE_KEYS):
                with self.subTest(provider=provider, order=order):
                    resources, result = _analyze(
                        provider,
                        scoped=False,
                        order=order,
                    )

                    self.assertEqual(
                        _relationship_snapshot(provider, resources),
                        _EXPECTED_AMBIGUOUS_RELATIONSHIPS[provider],
                    )
                    self.assertEqual(result.findings, [])

    def test_scoped_and_ambiguous_reports_match_the_golden_contract(self) -> None:
        expected = json.loads(_GOLDEN_PATH.read_text(encoding="utf-8"))
        actual: dict[str, object] = {}

        for provider in _PROVIDERS:
            for scoped in (True, False):
                scenario = "scoped" if scoped else "ambiguous"
                _resources, result = _analyze(
                    provider,
                    scoped=scoped,
                    order=_RESOURCE_KEYS,
                )
                actual[f"{provider}_{scenario}"] = _report_snapshot(result)

        self.assertEqual(actual, expected)


if __name__ == "__main__":
    unittest.main()
