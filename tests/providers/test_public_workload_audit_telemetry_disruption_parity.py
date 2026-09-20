from __future__ import annotations

import json
import unittest
from collections.abc import Mapping, Sequence
from typing import Any, Literal, cast

from tests.providers.aws.test_aws_ecs_cloudtrail_audit_telemetry_disruption_paths import (
    _DELETE_TRAIL as AWS_DELETE_TRAIL,
)
from tests.providers.aws.test_aws_ecs_cloudtrail_audit_telemetry_disruption_paths import (
    _STOP_LOGGING as AWS_STOP_LOGGING,
)
from tests.providers.aws.test_aws_ecs_cloudtrail_audit_telemetry_disruption_paths import (
    _TRAIL_ARN as AWS_TRAIL_ARN,
)
from tests.providers.aws.test_aws_ecs_cloudtrail_audit_telemetry_disruption_paths import (
    _caller_identity as aws_caller_identity,
)
from tests.providers.aws.test_aws_ecs_cloudtrail_audit_telemetry_disruption_paths import (
    _resource as aws_resource,
)
from tests.providers.aws.test_aws_ecs_cloudtrail_audit_telemetry_disruption_paths import (
    _role as aws_role,
)
from tests.providers.aws.test_aws_ecs_cloudtrail_audit_telemetry_disruption_paths import (
    _statement as aws_statement,
)
from tests.providers.aws.test_aws_ecs_cloudtrail_audit_telemetry_disruption_paths import (
    _task_definition as aws_task_definition,
)
from tests.providers.aws.test_aws_public_ecs_dynamodb_mutation_rules import (
    _public_edge as aws_public_edge,
)
from tests.providers.aws.test_aws_public_ecs_dynamodb_mutation_rules import (
    _service as aws_service,
)
from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _resource as azure_resource,
)
from tests.providers.gcp.test_gcp_cloud_run_logging_sink_audit_telemetry_disruption_paths import (
    _AUDIT_FILTER as GCP_AUDIT_FILTER,
)
from tests.providers.gcp.test_gcp_cloud_run_logging_sink_audit_telemetry_disruption_paths import (
    _IAM_ADDRESS as GCP_IAM_ADDRESS,
)
from tests.providers.gcp.test_gcp_cloud_run_logging_sink_audit_telemetry_disruption_paths import (
    _PROJECT as GCP_PROJECT,
)
from tests.providers.gcp.test_gcp_cloud_run_logging_sink_audit_telemetry_disruption_paths import (
    _SERVICE_ACCOUNT_EMAIL as GCP_SERVICE_ACCOUNT_EMAIL,
)
from tests.providers.gcp.test_gcp_cloud_run_logging_sink_audit_telemetry_disruption_paths import (
    _SINK_ADDRESS as GCP_SINK_ADDRESS,
)
from tests.providers.gcp.test_gcp_cloud_run_logging_sink_audit_telemetry_disruption_paths import (
    _SINK_RESOURCE_NAME as GCP_SINK_RESOURCE_NAME,
)
from tests.providers.gcp.test_gcp_cloud_run_logging_sink_audit_telemetry_disruption_paths import (
    _custom_role as gcp_custom_role,
)
from tests.providers.gcp.test_gcp_cloud_run_logging_sink_audit_telemetry_disruption_paths import (
    _project_member as gcp_project_member,
)
from tests.providers.gcp.test_gcp_cloud_run_logging_sink_audit_telemetry_disruption_paths import (
    _sink as gcp_sink,
)
from tests.providers.gcp.test_gcp_public_cloud_run_firestore_mutation_rules import (
    _public_cloud_run as gcp_public_cloud_run,
)
from tests.providers.gcp.test_gcp_public_cloud_run_firestore_mutation_rules import (
    _public_invoker as gcp_public_invoker,
)
from tests.providers.test_public_workload_audit_telemetry_disruption_boundaries import (
    _AZURE_DELETE_DIAGNOSTIC as AZURE_DELETE_DIAGNOSTIC,
)
from tests.providers.test_public_workload_audit_telemetry_disruption_boundaries import (
    _AZURE_DIAGNOSTIC_ID as AZURE_DIAGNOSTIC_ID,
)
from tests.providers.test_public_workload_audit_telemetry_disruption_boundaries import (
    _AZURE_DIAGNOSTIC_STATE_ID as AZURE_DIAGNOSTIC_STATE_ID,
)
from tests.providers.test_public_workload_audit_telemetry_disruption_boundaries import (
    _AZURE_WORKLOAD_ID as AZURE_WORKLOAD_ID,
)
from tests.providers.test_public_workload_audit_telemetry_disruption_boundaries import (
    _azure_assignment as azure_assignment,
)
from tests.providers.test_public_workload_audit_telemetry_disruption_boundaries import (
    _azure_diagnostic_setting as azure_diagnostic_setting,
)
from tests.providers.test_public_workload_audit_telemetry_disruption_boundaries import (
    _azure_role as azure_role,
)
from tests.providers.test_public_workload_audit_telemetry_disruption_boundaries import (
    _azure_workload as azure_workload,
)
from tests.providers.test_public_workload_structured_data_topology_destruction_boundaries import (
    _azure_management_lock as azure_management_lock,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import Finding, ResourceInventory, StrideCategory, TerraformResource
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.rules import AWS_RULE_GROUP_IDS
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.azure.rules import AZURE_RULE_GROUP_IDS
from tfstride.providers.base import ProviderNormalizer
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.rules import GCP_RULE_GROUP_IDS

ProviderName = Literal["aws", "gcp", "azure"]

AWS_RULE = "aws-public-ecs-cloudtrail-disruption"
GCP_RULE = "gcp-public-cloud-run-logging-sink-disruption"
AZURE_RULE = "azure-public-app-service-diagnostic-setting-disruption"

GCP_DELETE_SINK = "logging.sinks.delete"

_PROVIDERS: tuple[ProviderName, ...] = ("aws", "gcp", "azure")
_RULE_IDS = frozenset({AWS_RULE, GCP_RULE, AZURE_RULE})
_RULE_BY_PROVIDER = {
    "aws": AWS_RULE,
    "gcp": GCP_RULE,
    "azure": AZURE_RULE,
}
_WORKLOAD_BY_PROVIDER = {
    "aws": "aws_ecs_service.orders",
    "gcp": "google_cloud_run_v2_service.orders",
    "azure": "azurerm_linux_web_app.orders",
}
_TARGET_BY_PROVIDER = {
    "aws": "aws_cloudtrail.audit",
    "gcp": GCP_SINK_ADDRESS,
    "azure": "azurerm_monitor_diagnostic_setting.audit",
}
_EVIDENCE_KEY_BY_PROVIDER = {
    "aws": "cloudtrail_audit_telemetry_disruption_paths",
    "gcp": "logging_sink_audit_telemetry_disruption_paths",
    "azure": "diagnostic_setting_audit_telemetry_disruption_paths",
}
_AWS_SECURITY_TRAIL_ARN = "arn:aws:cloudtrail:us-east-1:111122223333:trail/security"
_GCP_SECURITY_SINK_ADDRESS = "google_logging_project_sink.security"
_GCP_SECURITY_SINK_RESOURCE_NAME = f"projects/{GCP_PROJECT}/sinks/security"
_AZURE_SECURITY_DIAGNOSTIC_ADDRESS = "azurerm_monitor_diagnostic_setting.security"
_AZURE_SECURITY_DIAGNOSTIC_STATE_ID = f"{AZURE_WORKLOAD_ID}|security"
_AZURE_SECURITY_DIAGNOSTIC_ARM_ID = f"{AZURE_WORKLOAD_ID}/providers/Microsoft.Insights/diagnosticSettings/security"


def _flatten(groups: tuple[tuple[str, ...], ...]) -> frozenset[str]:
    return frozenset(rule_id for group in groups for rule_id in group)


def _normalizer(provider: ProviderName) -> ProviderNormalizer:
    if provider == "aws":
        return AwsNormalizer()
    if provider == "gcp":
        return GcpNormalizer()
    return AzureNormalizer()


def _analyze(
    provider: ProviderName,
    resources: list[TerraformResource],
    *,
    engine: StrideRuleEngine | None = None,
) -> tuple[ResourceInventory, list[Finding]]:
    inventory = _normalizer(provider).normalize(resources)
    return inventory, _evaluate_inventory(inventory, engine=engine)


def _evaluate_inventory(
    inventory: ResourceInventory,
    *,
    engine: StrideRuleEngine | None = None,
) -> list[Finding]:
    return (engine or StrideRuleEngine()).evaluate(
        inventory,
        detect_trust_boundaries(inventory),
        rule_policy=RulePolicy(enabled_rule_ids=_RULE_IDS),
    )


def _evidence(finding: Finding) -> dict[str, list[str]]:
    return {item.key: item.values for item in finding.evidence}


def _finding(findings: Sequence[Finding], provider: ProviderName) -> Finding:
    matches = [finding for finding in findings if finding.rule_id == _RULE_BY_PROVIDER[provider]]
    assert len(matches) == 1
    return matches[0]


def _finding_payload(findings: Sequence[Finding]) -> list[dict[str, object]]:
    return [
        {
            "rule_id": finding.rule_id,
            "category": finding.category.value,
            "affected_resources": finding.affected_resources,
            "rationale": finding.rationale,
            "evidence": _evidence(finding),
        }
        for finding in findings
    ]


def _paths(provider: ProviderName, inventory: ResourceInventory) -> list[Mapping[str, object]]:
    workload = inventory.get_by_address(_WORKLOAD_BY_PROVIDER[provider])
    assert workload is not None
    if provider == "aws":
        raw_paths = aws_facts(workload).ecs_cloudtrail_audit_telemetry_disruption_paths
    elif provider == "gcp":
        raw_paths = gcp_facts(workload).cloud_run_logging_sink_audit_telemetry_disruption_paths
    else:
        raw_paths = azure_facts(workload).app_service_diagnostic_setting_audit_telemetry_disruption_paths
    return [cast(Mapping[str, object], path) for path in raw_paths]


def _replace_paths(
    provider: ProviderName,
    inventory: ResourceInventory,
    paths: Sequence[Mapping[str, object]],
) -> None:
    workload = inventory.get_by_address(_WORKLOAD_BY_PROVIDER[provider])
    assert workload is not None
    records = [dict(path) for path in paths]
    if provider == "aws":
        aws_facts(workload).set_ecs_cloudtrail_audit_telemetry_disruption_paths(cast(Any, records))
    elif provider == "gcp":
        gcp_facts(workload).set_cloud_run_logging_sink_audit_telemetry_disruption_paths(cast(Any, records))
    else:
        azure_facts(workload).set_app_service_diagnostic_setting_audit_telemetry_disruption_paths(cast(Any, records))


def _aws_trail(name: str, arn: str) -> TerraformResource:
    return aws_resource(
        "aws_cloudtrail",
        name,
        {
            "id": name,
            "name": name,
            "arn": arn,
            "enable_logging": True,
            "is_organization_trail": False,
        },
    )


def _aws_resources(
    *,
    public: bool = True,
    multi_target: bool = False,
    actions: str | list[str] | None = None,
) -> list[TerraformResource]:
    trails = [_aws_trail("audit", AWS_TRAIL_ARN)]
    trail_arns = [AWS_TRAIL_ARN]
    if multi_target:
        trails.append(_aws_trail("security", _AWS_SECURITY_TRAIL_ARN))
        trail_arns.append(_AWS_SECURITY_TRAIL_ARN)
    resources = [
        *aws_public_edge(internal=not public),
        aws_caller_identity(),
        *trails,
        aws_role(
            [
                aws_statement(
                    "Allow",
                    actions or [AWS_STOP_LOGGING, AWS_DELETE_TRAIL],
                    trail_arns,
                )
            ]
        ),
        aws_task_definition(execution_role_arn=None),
        aws_service(),
    ]
    for resource in resources:
        resource.provider_config_key = "aws"
    return resources


def _gcp_resources(
    *,
    public: bool = True,
    multi_target: bool = False,
) -> list[TerraformResource]:
    sinks = [gcp_sink()]
    if multi_target:
        sinks.append(
            gcp_sink(
                address=_GCP_SECURITY_SINK_ADDRESS,
                name="security",
                destination="pubsub.googleapis.com/projects/tfstride-demo/topics/security",
            )
        )
    return [
        gcp_public_cloud_run(public_ingress=public),
        gcp_public_invoker(),
        *sinks,
        gcp_custom_role(),
        gcp_project_member(),
    ]


def _azure_security_diagnostic_setting() -> TerraformResource:
    return azure_resource(
        AzureResourceType.MONITOR_DIAGNOSTIC_SETTING,
        {
            "id": _AZURE_SECURITY_DIAGNOSTIC_STATE_ID,
            "name": "security",
            "target_resource_id": AZURE_WORKLOAD_ID,
            "storage_account_id": (
                "/subscriptions/sub-0001/resourceGroups/obs/providers/Microsoft.Storage/storageAccounts/securitylogs"
            ),
            "enabled_log": [{"category": "AppServiceAuditLogs"}],
        },
        name="security",
    )


def _azure_resources(
    *,
    public: bool = True,
    multi_target: bool = False,
) -> list[TerraformResource]:
    diagnostics = [azure_diagnostic_setting()]
    if multi_target:
        diagnostics.append(_azure_security_diagnostic_setting())
    return [
        azure_workload(public=public),
        *diagnostics,
        azure_role(actions=[AZURE_DELETE_DIAGNOSTIC]),
        azure_assignment(scope=AZURE_WORKLOAD_ID if multi_target else AZURE_DIAGNOSTIC_ID),
    ]


def _resources(
    provider: ProviderName,
    *,
    public: bool = True,
    multi_target: bool = False,
    single_operation: bool = False,
) -> list[TerraformResource]:
    if provider == "aws":
        return _aws_resources(
            public=public,
            multi_target=multi_target,
            actions=AWS_DELETE_TRAIL if single_operation else None,
        )
    if provider == "gcp":
        return _gcp_resources(public=public, multi_target=multi_target)
    return _azure_resources(public=public, multi_target=multi_target)


def _remove_current_public_exposure(provider: ProviderName, inventory: ResourceInventory) -> None:
    if provider == "aws":
        load_balancer = inventory.get_by_address("aws_lb.public")
        assert load_balancer is not None
        load_balancer.public_exposure = False
        return
    workload = inventory.get_by_address(_WORKLOAD_BY_PROVIDER[provider])
    assert workload is not None
    if provider == "gcp":
        workload.public_access_configured = False
    else:
        azure_facts(workload).set(AzureResourceMetadata.PUBLIC_NETWORK_ACCESS_ENABLED, False)


def _change_current_runtime_identity(provider: ProviderName, inventory: ResourceInventory) -> None:
    if provider == "aws":
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None
        aws_facts(task_definition).set_task_role_arn("arn:aws:iam::111122223333:role/replacement-task")
        return
    workload = inventory.get_by_address(_WORKLOAD_BY_PROVIDER[provider])
    assert workload is not None
    if provider == "gcp":
        facts = gcp_facts(workload)
        facts.set(
            GcpResourceMetadata.SERVICE_ACCOUNT_EMAIL,
            "replacement@tfstride-demo.iam.gserviceaccount.com",
        )
        facts.set(
            GcpResourceMetadata.SERVICE_ACCOUNT_MEMBER,
            "serviceAccount:replacement@tfstride-demo.iam.gserviceaccount.com",
        )
    else:
        azure_facts(workload).set(AzureResourceMetadata.IDENTITY_TYPE, "None")


def _revoke_current_authority(provider: ProviderName, inventory: ResourceInventory) -> None:
    if provider == "aws":
        role = inventory.get_by_address("aws_iam_role.orders_task")
        assert role is not None
        role.policy_statements = ()
    elif provider == "gcp":
        iam_source = inventory.get_by_address(GCP_IAM_ADDRESS)
        assert iam_source is not None
        facts = gcp_facts(iam_source)
        facts.set(GcpResourceMetadata.IAM_BINDINGS, [])
        facts.set(GcpResourceMetadata.IAM_ROLE, None)
        facts.set(GcpResourceMetadata.IAM_MEMBER, None)
    else:
        role = inventory.get_by_address("azurerm_role_definition.audit_telemetry")
        assert role is not None
        azure_facts(role).set(AzureResourceMetadata.ROLE_DEFINITION_ACTIONS, [])


def _change_current_target_identity(provider: ProviderName, inventory: ResourceInventory) -> None:
    target = inventory.get_by_address(_TARGET_BY_PROVIDER[provider])
    assert target is not None
    if provider == "aws":
        target.arn = "arn:aws:cloudtrail:us-east-1:111122223333:trail/replacement"
    elif provider == "gcp":
        gcp_facts(target).set(GcpResourceMetadata.LOGGING_SINK_NAME, "replacement")
    else:
        azure_facts(target).set(
            AzureResourceMetadata.DIAGNOSTIC_SETTING_ID,
            f"{AZURE_WORKLOAD_ID}|replacement",
        )


def _invalidate_current_target_state(case: str, inventory: ResourceInventory) -> None:
    if case == "aws-disabled-trail":
        trail = inventory.get_by_address(_TARGET_BY_PROVIDER["aws"])
        assert trail is not None
        trail.set_metadata_field(AwsResourceMetadata.CLOUDTRAIL_ENABLE_LOGGING_STATE, "disabled")
        return
    if case.startswith("gcp-"):
        sink = inventory.get_by_address(_TARGET_BY_PROVIDER["gcp"])
        assert sink is not None
        facts = gcp_facts(sink)
        if case == "gcp-disabled-sink":
            facts.set(GcpResourceMetadata.LOGGING_SINK_DISABLED, True)
        elif case == "gcp-missing-destination":
            facts.set(GcpResourceMetadata.LOGGING_SINK_DESTINATION, None)
        elif case == "gcp-irrelevant-filter":
            facts.set(GcpResourceMetadata.LOGGING_SINK_FILTER, "severity>=ERROR")
        else:
            facts.set(
                GcpResourceMetadata.LOGGING_SINK_EXCLUSIONS,
                [
                    {
                        "name": "drop-audit",
                        "filter": GCP_AUDIT_FILTER,
                        "filter_state": "configured",
                        "disabled_state": "configured",
                        "disabled": False,
                    }
                ],
            )
        return
    diagnostic = inventory.get_by_address(_TARGET_BY_PROVIDER["azure"])
    assert diagnostic is not None
    facts = azure_facts(diagnostic)
    if case == "azure-missing-destination":
        facts.set(AzureResourceMetadata.DIAGNOSTIC_LOG_ANALYTICS_WORKSPACE_ID, None)
    elif case == "azure-irrelevant-categories":
        facts.set(AzureResourceMetadata.DIAGNOSTIC_ENABLED_LOG_CATEGORY_GROUPS, [])
        facts.set(AzureResourceMetadata.DIAGNOSTIC_ENABLED_LOG_CATEGORIES, ["AppServiceHTTPLogs"])
        facts.set(AzureResourceMetadata.DIAGNOSTIC_LOG_RECORDS, [{"category": "AppServiceHTTPLogs"}])
    else:
        lock_inventory = AzureNormalizer().normalize(
            [azure_management_lock(scope=AZURE_DIAGNOSTIC_ID, name="audit_parity_lock")]
        )
        inventory.resources = (*inventory.resources, *lock_inventory.resources)


class PublicWorkloadAuditTelemetryDisruptionParityTests(unittest.TestCase):
    """Pin shared Repudiation semantics without flattening native controls."""

    def test_provider_local_rules_are_registered_as_repudiation(self) -> None:
        self.assertIn(AWS_RULE, _flatten(AWS_RULE_GROUP_IDS))
        self.assertIn(GCP_RULE, _flatten(GCP_RULE_GROUP_IDS))
        self.assertIn(AZURE_RULE, _flatten(AZURE_RULE_GROUP_IDS))

        for provider in _PROVIDERS:
            with self.subTest(provider=provider):
                inventory, findings = _analyze(provider, _resources(provider))
                finding = _finding(findings, provider)

                self.assertTrue(_paths(provider, inventory))
                self.assertEqual(finding.category, StrideCategory.REPUDIATION)
                self.assertNotEqual(finding.category, StrideCategory.DENIAL_OF_SERVICE)

    def test_provider_native_runtime_identity_target_and_operation_remain_distinct(self) -> None:
        for provider in _PROVIDERS:
            with self.subTest(provider=provider):
                inventory, findings = _analyze(provider, _resources(provider))
                paths = _paths(provider, inventory)
                finding = _finding(findings, provider)
                evidence = _evidence(finding)[_EVIDENCE_KEY_BY_PROVIDER[provider]]

                if provider == "aws":
                    self.assertEqual(
                        {path["operation"] for path in paths},
                        {AWS_STOP_LOGGING, AWS_DELETE_TRAIL},
                    )
                    self.assertTrue(all(path["role_kind"] == "ecs_task_role" for path in paths))
                    self.assertTrue(all(path["trail_arn"] == AWS_TRAIL_ARN for path in paths))
                    self.assertTrue(all(path["target_scope"] == "exact_cloudtrail_trail" for path in paths))
                    self.assertTrue(all(path["lifecycle_compatibility_state"] == "compatible" for path in paths))
                elif provider == "gcp":
                    self.assertEqual([path["operation"] for path in paths], [GCP_DELETE_SINK])
                    self.assertEqual(paths[0]["service_account_email"], GCP_SERVICE_ACCOUNT_EMAIL)
                    self.assertEqual(paths[0]["logging_sink_resource_name"], GCP_SINK_RESOURCE_NAME)
                    self.assertEqual(paths[0]["target_scope"], "exact_project_logging_sink")
                    self.assertEqual(
                        cast(Mapping[str, object], paths[0]["lifecycle_evidence"])["sink_lifecycle_state"],
                        "active",
                    )
                    self.assertEqual(
                        cast(Mapping[str, object], paths[0]["deletion_constraint_evidence"])["sink_kind"],
                        "user_managed",
                    )
                else:
                    path = paths[0]
                    self.assertEqual(path["operation"], AZURE_DELETE_DIAGNOSTIC)
                    self.assertEqual(path["identity_kind"], "system_assigned")
                    self.assertEqual(path["diagnostic_setting_id"], AZURE_DIAGNOSTIC_STATE_ID)
                    self.assertEqual(path["diagnostic_setting_arm_id"], AZURE_DIAGNOSTIC_ID)
                    self.assertIn("|audit", cast(str, path["diagnostic_setting_id"]))
                    self.assertNotIn("|", cast(str, path["diagnostic_setting_arm_id"]))
                    grant = cast(Mapping[str, object], path["authorization_grant"])
                    self.assertEqual(grant["matched_actions"], [AZURE_DELETE_DIAGNOSTIC])
                    self.assertEqual(
                        grant["diagnostic_settings_data_actions_authorization_effect"],
                        "not_used_for_arm_diagnostic_setting_deletion",
                    )

                payload = " ".join(evidence)
                self.assertIn(cast(str, paths[0]["operation"]), payload)

    def test_private_workloads_keep_authority_paths_without_public_findings(self) -> None:
        for provider in _PROVIDERS:
            with self.subTest(provider=provider):
                inventory, findings = _analyze(provider, _resources(provider, public=False))
                paths = _paths(provider, inventory)

                self.assertTrue(paths)
                self.assertTrue(all(path["credential_context"] == "workload_runtime" for path in paths))
                self.assertNotIn(_RULE_BY_PROVIDER[provider], {finding.rule_id for finding in findings})

    def test_multiple_targets_fan_out_to_exact_provider_native_identities(self) -> None:
        expected_targets = {
            "aws": {"aws_cloudtrail.audit", "aws_cloudtrail.security"},
            "gcp": {GCP_SINK_ADDRESS, _GCP_SECURITY_SINK_ADDRESS},
            "azure": {
                "azurerm_monitor_diagnostic_setting.audit",
                _AZURE_SECURITY_DIAGNOSTIC_ADDRESS,
            },
        }
        unrelated_targets = {
            "aws": "arn:aws:cloudtrail:us-east-1:111122223333:trail/out-of-plan",
            "gcp": f"projects/{GCP_PROJECT}/sinks/out-of-plan",
            "azure": f"{AZURE_WORKLOAD_ID}/providers/Microsoft.Insights/diagnosticSettings/out-of-plan",
        }

        for provider in _PROVIDERS:
            with self.subTest(provider=provider):
                inventory, findings = _analyze(
                    provider,
                    _resources(provider, multi_target=True, single_operation=True),
                )
                paths = _paths(provider, inventory)
                finding = _finding(findings, provider)
                evidence = _evidence(finding)[_EVIDENCE_KEY_BY_PROVIDER[provider]]
                path_targets = {
                    cast(
                        str,
                        path.get("trail_address")
                        or path.get("logging_sink_address")
                        or path.get("diagnostic_setting_address"),
                    )
                    for path in paths
                }

                self.assertEqual(path_targets, expected_targets[provider])
                self.assertEqual(len(paths), 2)
                self.assertEqual(len(evidence), 2)
                assert finding.severity_reasoning is not None
                self.assertEqual(finding.severity_reasoning.blast_radius, 2)
                for target in expected_targets[provider]:
                    self.assertEqual(finding.affected_resources.count(target), 1)

                if provider == "aws":
                    self.assertEqual(
                        {path["trail_arn"] for path in paths},
                        {AWS_TRAIL_ARN, _AWS_SECURITY_TRAIL_ARN},
                    )
                    self.assertEqual(
                        {path["trail_name"] for path in paths},
                        {"audit", "security"},
                    )
                    self.assertTrue(
                        all(path["target_model_evidence_addresses"] == [path["trail_address"]] for path in paths)
                    )
                elif provider == "gcp":
                    self.assertEqual(
                        {path["logging_sink_resource_name"] for path in paths},
                        {GCP_SINK_RESOURCE_NAME, _GCP_SECURITY_SINK_RESOURCE_NAME},
                    )
                    self.assertTrue(all(path["logging_sink_project"] == GCP_PROJECT for path in paths))
                else:
                    self.assertEqual(
                        {path["diagnostic_setting_arm_id"] for path in paths},
                        {AZURE_DIAGNOSTIC_ID, _AZURE_SECURITY_DIAGNOSTIC_ARM_ID},
                    )
                    self.assertEqual(
                        {path["diagnostic_setting_id"] for path in paths},
                        {AZURE_DIAGNOSTIC_STATE_ID, _AZURE_SECURITY_DIAGNOSTIC_STATE_ID},
                    )
                    self.assertTrue(all("|" not in cast(str, path["diagnostic_setting_arm_id"]) for path in paths))

                payload = json.dumps(
                    {"paths": paths, "finding": _finding_payload([finding])},
                    sort_keys=True,
                )
                self.assertNotIn(unrelated_targets[provider], payload)

    def test_removed_current_public_exposure_rejects_cached_candidates(self) -> None:
        for provider in _PROVIDERS:
            with self.subTest(provider=provider):
                inventory, findings = _analyze(provider, _resources(provider))
                self.assertIsNotNone(_finding(findings, provider))
                cached_paths = _paths(provider, inventory)

                _remove_current_public_exposure(provider, inventory)

                self.assertEqual(_paths(provider, inventory), cached_paths)
                self.assertNotIn(
                    _RULE_BY_PROVIDER[provider],
                    {finding.rule_id for finding in _evaluate_inventory(inventory)},
                )

    def test_changed_current_runtime_identity_rejects_cached_candidates(self) -> None:
        for provider in _PROVIDERS:
            with self.subTest(provider=provider):
                inventory, findings = _analyze(provider, _resources(provider))
                self.assertIsNotNone(_finding(findings, provider))
                cached_paths = _paths(provider, inventory)

                _change_current_runtime_identity(provider, inventory)

                self.assertEqual(_paths(provider, inventory), cached_paths)
                self.assertNotIn(
                    _RULE_BY_PROVIDER[provider],
                    {finding.rule_id for finding in _evaluate_inventory(inventory)},
                )

    def test_revoked_current_authority_rejects_cached_candidates(self) -> None:
        for provider in _PROVIDERS:
            with self.subTest(provider=provider):
                inventory, findings = _analyze(provider, _resources(provider))
                self.assertIsNotNone(_finding(findings, provider))
                cached_paths = _paths(provider, inventory)

                _revoke_current_authority(provider, inventory)

                self.assertEqual(_paths(provider, inventory), cached_paths)
                self.assertNotIn(
                    _RULE_BY_PROVIDER[provider],
                    {finding.rule_id for finding in _evaluate_inventory(inventory)},
                )

    def test_changed_current_exact_target_rejects_cached_candidates(self) -> None:
        for provider in _PROVIDERS:
            with self.subTest(provider=provider):
                inventory, findings = _analyze(provider, _resources(provider))
                self.assertIsNotNone(_finding(findings, provider))
                cached_paths = _paths(provider, inventory)

                _change_current_target_identity(provider, inventory)

                self.assertEqual(_paths(provider, inventory), cached_paths)
                self.assertNotIn(
                    _RULE_BY_PROVIDER[provider],
                    {finding.rule_id for finding in _evaluate_inventory(inventory)},
                )

    def test_provider_native_lifecycle_relevance_destination_and_lock_drift_fail_closed(self) -> None:
        cases: tuple[tuple[str, ProviderName], ...] = (
            ("aws-disabled-trail", "aws"),
            ("gcp-disabled-sink", "gcp"),
            ("gcp-missing-destination", "gcp"),
            ("gcp-irrelevant-filter", "gcp"),
            ("gcp-active-audit-exclusion", "gcp"),
            ("azure-missing-destination", "azure"),
            ("azure-irrelevant-categories", "azure"),
            ("azure-new-blocking-lock", "azure"),
        )

        for case, provider in cases:
            with self.subTest(case=case):
                inventory, findings = _analyze(provider, _resources(provider))
                self.assertIsNotNone(_finding(findings, provider))
                cached_paths = _paths(provider, inventory)

                _invalidate_current_target_state(case, inventory)

                self.assertEqual(_paths(provider, inventory), cached_paths)
                self.assertNotIn(
                    _RULE_BY_PROVIDER[provider],
                    {finding.rule_id for finding in _evaluate_inventory(inventory)},
                )

    def test_duplicate_cached_paths_deduplicate_with_stable_ordering(self) -> None:
        for provider in _PROVIDERS:
            with self.subTest(provider=provider):
                inventory, initial_findings = _analyze(
                    provider,
                    _resources(provider, single_operation=True),
                )
                initial_paths = _paths(provider, inventory)
                self.assertEqual(len(initial_paths), 1)
                initial_payload = _finding_payload(initial_findings)

                _replace_paths(provider, inventory, [*initial_paths, dict(initial_paths[0])])
                first = _evaluate_inventory(inventory)
                second = _evaluate_inventory(inventory)
                finding = _finding(first, provider)

                self.assertEqual(_finding_payload(first), initial_payload)
                self.assertEqual(_finding_payload(second), initial_payload)
                self.assertEqual(
                    len(_evidence(finding)[_EVIDENCE_KEY_BY_PROVIDER[provider]]),
                    1,
                )
                self.assertEqual(
                    finding.affected_resources.count(_TARGET_BY_PROVIDER[provider]),
                    1,
                )

    def test_provider_isolation_preserves_rule_and_operation_namespaces(self) -> None:
        foreign_operations = {
            "aws": (GCP_DELETE_SINK, AZURE_DELETE_DIAGNOSTIC),
            "gcp": (AWS_STOP_LOGGING, AWS_DELETE_TRAIL, AZURE_DELETE_DIAGNOSTIC),
            "azure": (AWS_STOP_LOGGING, AWS_DELETE_TRAIL, GCP_DELETE_SINK),
        }
        foreign_evidence_keys = {
            "aws": (
                _EVIDENCE_KEY_BY_PROVIDER["gcp"],
                _EVIDENCE_KEY_BY_PROVIDER["azure"],
            ),
            "gcp": (
                _EVIDENCE_KEY_BY_PROVIDER["aws"],
                _EVIDENCE_KEY_BY_PROVIDER["azure"],
            ),
            "azure": (
                _EVIDENCE_KEY_BY_PROVIDER["aws"],
                _EVIDENCE_KEY_BY_PROVIDER["gcp"],
            ),
        }
        engine = StrideRuleEngine()

        for label, provider in (
            ("aws", "aws"),
            ("gcp", "gcp"),
            ("azure", "azure"),
            ("aws-second-pass", "aws"),
        ):
            with self.subTest(provider=label):
                _inventory, findings = _analyze(
                    provider,
                    _resources(provider),
                    engine=engine,
                )
                finding = _finding(findings, provider)
                self.assertEqual([item.rule_id for item in findings], [_RULE_BY_PROVIDER[provider]])
                self.assertEqual(
                    set(_evidence(finding)).intersection(foreign_evidence_keys[provider]),
                    set(),
                )
                payload = json.dumps(_finding_payload(findings), sort_keys=True)
                for operation in foreign_operations[provider]:
                    self.assertNotIn(operation, payload)

    def test_consequences_preserve_future_repudiation_and_provider_nonclaims(self) -> None:
        for provider in _PROVIDERS:
            with self.subTest(provider=provider):
                inventory, findings = _analyze(provider, _resources(provider))
                finding = _finding(findings, provider)
                paths = _paths(provider, inventory)
                evidence = _evidence(finding)
                wording = " ".join([finding.rationale, *evidence["assessment_scope"]]).casefold()
                outcome = cast(Mapping[str, object], paths[0]["outcome_evidence"])

                self.assertIn("repudiation", wording)
                self.assertIn("future", wording)
                self.assertIn("audit", wording)
                self.assertIn("weaken", wording)
                self.assertIn("auditability", wording)
                self.assertNotIn("denial of service", wording)

                if provider == "aws":
                    self.assertEqual(
                        {path["operation"] for path in paths},
                        {AWS_STOP_LOGGING, AWS_DELETE_TRAIL},
                    )
                    for key in (
                        "successful_operation_observed",
                        "historical_log_object_deletion_authorized_by_operation",
                        "historical_log_object_deletion_observed",
                        "logging_destination_deletion_authorized_by_operation",
                        "logging_destination_deletion_observed",
                        "all_account_audit_trails_evaluated",
                        "out_of_plan_trails_evaluated",
                        "restoration_observed",
                    ):
                        self.assertIs(outcome[key], False)
                    for phrase in (
                        "successful operation",
                        "historical cloudtrail",
                        "logging-destination deletion",
                        "all account trails",
                        "out-of-plan trails",
                        "recovery",
                        "restoration",
                    ):
                        self.assertIn(phrase, wording)
                elif provider == "gcp":
                    self.assertEqual(paths[0]["operation"], GCP_DELETE_SINK)
                    for key in (
                        "successful_operation_observed",
                        "historical_log_entry_deletion_authorized_by_operation",
                        "historical_log_entry_deletion_observed",
                        "destination_resource_deletion_authorized_by_operation",
                        "destination_resource_deletion_observed",
                        "all_project_audit_sinks_evaluated",
                        "out_of_plan_sinks_evaluated",
                        "restoration_observed",
                    ):
                        self.assertIs(outcome[key], False)
                    for phrase in (
                        "successful api",
                        "sink deletion",
                        "retained source logs",
                        "logs already delivered",
                        "destination resource",
                        "every project or out-of-plan sink",
                        "historical audit-log erasure",
                        "recovery/restoration",
                    ):
                        self.assertIn(phrase, wording)
                else:
                    self.assertEqual(paths[0]["operation"], AZURE_DELETE_DIAGNOSTIC)
                    for key in (
                        "successful_operation_observed",
                        "historical_log_deletion_authorized_by_operation",
                        "historical_log_deletion_observed",
                        "destination_resource_deletion_authorized_by_operation",
                        "destination_resource_deletion_observed",
                        "all_resource_diagnostic_settings_evaluated",
                        "out_of_plan_diagnostic_settings_evaluated",
                        "restoration_observed",
                    ):
                        self.assertIs(outcome[key], False)
                    for phrase in (
                        "successful api",
                        "diagnostic-setting deletion",
                        "historical/source telemetry",
                        "logs already delivered to log analytics",
                        "logs already delivered to storage",
                        "logs already delivered to event hubs",
                        "marketplace/partner",
                        "destination resource",
                        "every parent-resource, subscription, or tenant diagnostic setting",
                        "out-of-plan settings",
                        "recovery/restoration",
                    ):
                        self.assertIn(phrase, wording)


if __name__ == "__main__":
    unittest.main()
