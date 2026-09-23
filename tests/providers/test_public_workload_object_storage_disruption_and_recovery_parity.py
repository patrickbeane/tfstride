from __future__ import annotations

import json
import unittest
from collections.abc import Mapping, Sequence
from typing import cast

from tests.providers.aws.test_aws_ecs_s3_access_paths import (
    _BUCKET_ARN,
    _TASK_ROLE_ARN,
)
from tests.providers.aws.test_aws_ecs_s3_access_paths import (
    _bucket as aws_bucket,
)
from tests.providers.aws.test_aws_ecs_s3_access_paths import (
    _resource as aws_resource,
)
from tests.providers.aws.test_aws_ecs_s3_access_paths import (
    _role as aws_role,
)
from tests.providers.aws.test_aws_ecs_s3_access_paths import (
    _role_policy_attachment as aws_role_policy_attachment,
)
from tests.providers.aws.test_aws_ecs_s3_access_paths import (
    _statement as aws_statement,
)
from tests.providers.aws.test_aws_ecs_s3_access_paths import (
    _task_definition as aws_task_definition,
)
from tests.providers.aws.test_aws_ecs_s3_object_deletion_paths import (
    _caller_identity as aws_caller_identity,
)
from tests.providers.aws.test_aws_ecs_s3_object_deletion_paths import (
    _object_lock as aws_object_lock,
)
from tests.providers.aws.test_aws_ecs_s3_object_deletion_paths import (
    _versioning as aws_versioning,
)
from tests.providers.aws.test_aws_public_ecs_s3_mutation_rules import (
    _load_balancer as aws_load_balancer,
)
from tests.providers.aws.test_aws_public_ecs_s3_mutation_rules import (
    _service as aws_service,
)
from tests.providers.azure.test_azure_app_service_blob_deletion_paths import (
    _storage_account as azure_storage_account,
)
from tests.providers.azure.test_azure_app_service_blob_deletion_paths import (
    _storage_container as azure_storage_container,
)
from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _custom_role as azure_custom_role,
)
from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _custom_role_assignment as azure_custom_role_assignment,
)
from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _resource as azure_resource,
)
from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _role_assignment as azure_role_assignment,
)
from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _web_app as azure_web_app,
)
from tests.providers.gcp.normalizer_support import _terraform_resource as gcp_resource
from tests.providers.gcp.test_gcp_cloud_run_gcs_object_deletion_paths import (
    _BUCKET_NAME as GCP_BUCKET_NAME,
)
from tests.providers.gcp.test_gcp_cloud_run_gcs_object_deletion_paths import (
    _PROJECT as GCP_PROJECT,
)
from tests.providers.gcp.test_gcp_cloud_run_gcs_object_deletion_paths import (
    _SERVICE_ACCOUNT_MEMBER as GCP_SERVICE_ACCOUNT_MEMBER,
)
from tests.providers.gcp.test_gcp_cloud_run_gcs_object_deletion_paths import (
    _bucket as gcp_bucket,
)
from tests.providers.gcp.test_gcp_cloud_run_gcs_object_deletion_paths import (
    _bucket_binding as gcp_bucket_binding,
)
from tests.providers.gcp.test_gcp_cloud_run_gcs_object_deletion_paths import (
    _bucket_member as gcp_bucket_member,
)
from tests.providers.gcp.test_gcp_cloud_run_gcs_object_deletion_paths import (
    _custom_role as gcp_custom_role,
)
from tests.providers.gcp.test_gcp_public_cloud_run_gcs_mutation_rules import (
    _cloud_run as gcp_cloud_run,
)
from tests.providers.gcp.test_gcp_public_cloud_run_gcs_mutation_rules import (
    _public_invoker as gcp_public_invoker,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import Finding, ResourceInventory, StrideCategory, TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.rules import AWS_RULE_GROUP_IDS
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.rules import AZURE_RULE_GROUP_IDS
from tfstride.providers.base import ProviderNormalizer
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.rules import GCP_RULE_GROUP_IDS

AWS_TAMPERING_RULE = "aws-public-ecs-s3-mutation-access"
AWS_DISRUPTION_RULE = "aws-public-ecs-s3-object-disruption"
GCP_TAMPERING_RULE = "gcp-public-cloud-run-gcs-mutation-access"
GCP_DISRUPTION_RULE = "gcp-public-cloud-run-gcs-object-disruption"
AZURE_TAMPERING_RULE = "azure-public-app-service-storage-mutation-access"
AZURE_DISRUPTION_RULE = "azure-public-app-service-storage-blob-disruption"
_RULE_IDS = frozenset(
    {
        AWS_TAMPERING_RULE,
        AWS_DISRUPTION_RULE,
        GCP_TAMPERING_RULE,
        GCP_DISRUPTION_RULE,
        AZURE_TAMPERING_RULE,
        AZURE_DISRUPTION_RULE,
    }
)

_AWS_WORKLOAD_ADDRESS = "aws_ecs_service.orders"
_GCP_WORKLOAD_ADDRESS = "google_cloud_run_v2_service.orders"
_AZURE_WORKLOAD_ADDRESS = "azurerm_linux_web_app.orders"

_AZURE_WRITE = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write"
_AZURE_TAGS_WRITE = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/tags/write"
_AZURE_DELETE = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete"
_AZURE_DELETE_VERSION = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/deleteBlobVersion/action"
_AZURE_PERMANENT_DELETE = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/permanentDelete/action"

_AWS_PAYLOAD_SENTINEL = "aws-object-payload-must-not-leak"
_GCP_PAYLOAD_SENTINEL = "gcp-object-payload-must-not-leak"
_AZURE_PAYLOAD_SENTINEL = "azure-object-payload-must-not-leak"


def _flatten(groups: tuple[tuple[str, ...], ...]) -> frozenset[str]:
    return frozenset(rule_id for group in groups for rule_id in group)


def _analyze(
    normalizer: ProviderNormalizer,
    resources: list[TerraformResource],
    *,
    engine: StrideRuleEngine | None = None,
) -> tuple[ResourceInventory, list[Finding]]:
    inventory = normalizer.normalize(resources)
    findings = (engine or StrideRuleEngine()).evaluate(
        inventory,
        detect_trust_boundaries(inventory),
        rule_policy=RulePolicy(enabled_rule_ids=_RULE_IDS),
    )
    return inventory, findings


def _evidence(finding: Finding) -> dict[str, list[str]]:
    return {item.key: item.values for item in finding.evidence}


def _path_state(
    provider: str,
    inventory: ResourceInventory,
) -> tuple[list[Mapping[str, object]], list[str]]:
    if provider == "aws":
        workload = inventory.get_by_address(_AWS_WORKLOAD_ADDRESS)
        assert workload is not None
        facts = aws_facts(workload)
        return (
            [cast(Mapping[str, object], path) for path in facts.ecs_s3_object_deletion_paths],
            list(facts.ecs_s3_object_deletion_path_uncertainties),
        )
    if provider == "gcp":
        workload = inventory.get_by_address(_GCP_WORKLOAD_ADDRESS)
        assert workload is not None
        facts = gcp_facts(workload)
        return (
            [cast(Mapping[str, object], path) for path in facts.cloud_run_gcs_object_deletion_paths],
            list(facts.cloud_run_gcs_object_deletion_path_uncertainties),
        )
    workload = inventory.get_by_address(_AZURE_WORKLOAD_ADDRESS)
    assert workload is not None
    facts = azure_facts(workload)
    return (
        [cast(Mapping[str, object], path) for path in facts.app_service_blob_deletion_paths],
        list(facts.app_service_blob_deletion_path_uncertainties),
    )


def _finding_by_rule(findings: Sequence[Finding], rule_id: str) -> Finding:
    matches = [finding for finding in findings if finding.rule_id == rule_id]
    assert len(matches) == 1
    return matches[0]


def _aws_resources(
    actions: str | list[str],
    *,
    public: bool = True,
    versioning: str | None = None,
    object_lock: bool = False,
    statements: list[dict[str, object]] | None = None,
    extra_resources: Sequence[TerraformResource] = (),
) -> list[TerraformResource]:
    resources = [
        aws_caller_identity(),
        aws_load_balancer(internal=not public),
        aws_bucket(),
    ]
    if versioning is not None:
        resources.append(aws_versioning(versioning))
    if object_lock:
        resources.append(aws_object_lock())
    resources.extend(
        [
            aws_role(
                "orders_task",
                _TASK_ROLE_ARN,
                statements or [aws_statement("Allow", actions, f"{_BUCKET_ARN}/*")],
            ),
            aws_task_definition(execution_role_arn=None),
            aws_service(),
            *extra_resources,
        ]
    )
    return resources


def _gcp_resources(
    *iam_resources: TerraformResource,
    public: bool = True,
    bucket: TerraformResource | None = None,
    extra_resources: Sequence[TerraformResource] = (),
) -> list[TerraformResource]:
    return [
        gcp_cloud_run(public_ingress=public),
        gcp_public_invoker(),
        bucket or cast(TerraformResource, gcp_bucket()),
        *iam_resources,
        *extra_resources,
    ]


def _gcp_custom_permission_resources(
    role_id: str,
    permissions: list[str],
    *,
    public: bool = True,
) -> list[TerraformResource]:
    role_name = f"projects/{GCP_PROJECT}/roles/{role_id}"
    return _gcp_resources(
        cast(
            TerraformResource,
            gcp_custom_role(role_id=role_id, permissions=permissions),
        ),
        cast(TerraformResource, gcp_bucket_member(role=role_name)),
        public=public,
    )


def _azure_resources(
    data_actions: list[str],
    *,
    public: bool = True,
    not_data_actions: list[str] | None = None,
    condition: str | None = None,
    unknown_permissions: bool = False,
    account: TerraformResource | None = None,
    extra_resources: Sequence[TerraformResource] = (),
) -> list[TerraformResource]:
    app = azure_web_app()
    app.values["public_network_access_enabled"] = public
    role = azure_custom_role(
        data_actions=data_actions,
        not_data_actions=not_data_actions,
        unknown_values=({"permissions": [{"data_actions": True}]} if unknown_permissions else None),
    )
    assignment = azure_custom_role_assignment()
    if condition is not None:
        assignment.values["condition"] = condition
    return [
        account or azure_storage_account(),
        azure_storage_container(),
        app,
        role,
        assignment,
        *extra_resources,
    ]


def _azure_owner_resources(*, public: bool = True) -> list[TerraformResource]:
    app = azure_web_app()
    app.values["public_network_access_enabled"] = public
    return [
        azure_storage_account(versioning_enabled=True, blob_delete_days=30),
        azure_storage_container(),
        app,
        azure_role_assignment(
            role_name="Storage Blob Data Owner",
            role_definition_id=(
                "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/"
                "b7e6dc6d-f1e8-4753-8033-0f276bb0955b"
            ),
        ),
    ]


def _path_fingerprint(
    provider: str,
    path: Mapping[str, object],
) -> tuple[object, ...]:
    if provider == "aws":
        identity = path.get("role_arn")
        sources = path.get("authorization_source_addresses")
    elif provider == "gcp":
        identity = path.get("service_account_email")
        sources = path.get("iam_source_addresses")
    else:
        identity = path.get("principal_id")
        sources = path.get("authorization_source_addresses")
    source_tuple = tuple(value for value in sources if isinstance(value, str)) if isinstance(sources, list) else ()
    return (
        provider,
        path.get("operation"),
        # GCS uses one permission for logically distinct live-object and generation targets.
        path.get("operation_class"),
        path.get("target_scope"),
        identity,
        source_tuple,
    )


def _finding_payload(findings: Sequence[Finding]) -> str:
    return json.dumps(
        [
            {
                "rule_id": finding.rule_id,
                "category": finding.category.value,
                "affected_resources": finding.affected_resources,
                "rationale": finding.rationale,
                "evidence": _evidence(finding),
            }
            for finding in findings
        ],
        sort_keys=True,
    )


def _aws_payload_object() -> TerraformResource:
    return aws_resource(
        "aws_s3_object",
        "payload",
        {
            "bucket": "orders-data",
            "key": "payload.json",
            "content": _AWS_PAYLOAD_SENTINEL,
        },
    )


def _gcp_payload_object() -> TerraformResource:
    return gcp_resource(
        "google_storage_bucket_object.payload",
        "google_storage_bucket_object",
        {
            "bucket": GCP_BUCKET_NAME,
            "name": "payload.json",
            "content": _GCP_PAYLOAD_SENTINEL,
        },
    )


def _azure_payload_blob() -> TerraformResource:
    return azure_resource(
        "azurerm_storage_blob",
        {
            "name": "payload.json",
            "storage_account_name": "ordersdata",
            "storage_container_name": "orders",
            "type": "Block",
            "source_content": _AZURE_PAYLOAD_SENTINEL,
        },
        name="payload",
    )


class PublicWorkloadObjectStorageDisruptionAndRecoveryParityTests(unittest.TestCase):
    """Pins shared threat outcomes without flattening native recovery evidence."""

    def test_provider_local_rule_families_are_registered(self) -> None:
        self.assertTrue({AWS_TAMPERING_RULE, AWS_DISRUPTION_RULE} <= _flatten(AWS_RULE_GROUP_IDS))
        self.assertTrue({GCP_TAMPERING_RULE, GCP_DISRUPTION_RULE} <= _flatten(GCP_RULE_GROUP_IDS))
        self.assertTrue({AZURE_TAMPERING_RULE, AZURE_DISRUPTION_RULE} <= _flatten(AZURE_RULE_GROUP_IDS))

    def test_write_only_emits_tampering_only(self) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_resources("s3:PutObject"),
                AWS_TAMPERING_RULE,
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_resources(
                    cast(
                        TerraformResource,
                        gcp_bucket_member(role="roles/storage.objectCreator"),
                    )
                ),
                GCP_TAMPERING_RULE,
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_resources([_AZURE_WRITE]),
                AZURE_TAMPERING_RULE,
            ),
        )

        for provider, normalizer, resources, expected_rule in cases:
            with self.subTest(provider=provider):
                _inventory, findings = _analyze(normalizer, resources)

                self.assertEqual(
                    [finding.rule_id for finding in findings],
                    [expected_rule],
                )
                self.assertEqual(findings[0].category, StrideCategory.TAMPERING)

    def test_delete_only_emits_dos_only(self) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_resources("s3:DeleteObject", versioning="disabled"),
                AWS_DISRUPTION_RULE,
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_custom_permission_resources(
                    "deleteOnly",
                    ["storage.objects.delete"],
                ),
                GCP_DISRUPTION_RULE,
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_resources([_AZURE_DELETE]),
                AZURE_DISRUPTION_RULE,
            ),
        )

        for provider, normalizer, resources, expected_rule in cases:
            with self.subTest(provider=provider):
                _inventory, findings = _analyze(normalizer, resources)

                self.assertEqual(
                    [finding.rule_id for finding in findings],
                    [expected_rule],
                )
                self.assertEqual(
                    findings[0].category,
                    StrideCategory.DENIAL_OF_SERVICE,
                )

    def test_write_and_delete_emit_both_without_cross_effect_evidence(self) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_resources(
                    ["s3:PutObject", "s3:DeleteObject"],
                    versioning="Enabled",
                ),
                AWS_TAMPERING_RULE,
                AWS_DISRUPTION_RULE,
                "s3_mutation_paths",
                "s3_object_deletion_paths",
                "recovery_evidence",
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_resources(
                    cast(
                        TerraformResource,
                        gcp_bucket_member(role="roles/storage.objectUser"),
                    )
                ),
                GCP_TAMPERING_RULE,
                GCP_DISRUPTION_RULE,
                "gcs_mutation_paths",
                "gcs_object_deletion_paths",
                "recovery_posture",
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_resources([_AZURE_WRITE, _AZURE_DELETE]),
                AZURE_TAMPERING_RULE,
                AZURE_DISRUPTION_RULE,
                "storage_mutation_paths",
                "storage_blob_deletion_paths",
                "recovery_posture",
            ),
        )

        for (
            provider,
            normalizer,
            resources,
            tampering_rule,
            disruption_rule,
            mutation_key,
            disruption_key,
            recovery_key,
        ) in cases:
            with self.subTest(provider=provider):
                _inventory, findings = _analyze(normalizer, resources)

                self.assertEqual(
                    {finding.rule_id for finding in findings},
                    {tampering_rule, disruption_rule},
                )
                tampering = _finding_by_rule(findings, tampering_rule)
                disruption = _finding_by_rule(findings, disruption_rule)
                self.assertEqual(tampering.category, StrideCategory.TAMPERING)
                self.assertEqual(
                    disruption.category,
                    StrideCategory.DENIAL_OF_SERVICE,
                )
                tampering_evidence = _evidence(tampering)
                disruption_evidence = _evidence(disruption)
                self.assertIn(mutation_key, tampering_evidence)
                self.assertNotIn(disruption_key, tampering_evidence)
                self.assertNotIn(recovery_key, tampering_evidence)
                self.assertIn(disruption_key, disruption_evidence)
                self.assertIn(recovery_key, disruption_evidence)
                self.assertNotIn(mutation_key, disruption_evidence)

    def test_tag_or_metadata_removal_stays_tampering_only(self) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_resources("s3:DeleteObjectTagging"),
                AWS_TAMPERING_RULE,
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_custom_permission_resources(
                    "metadataEditor",
                    ["storage.objects.update"],
                ),
                GCP_TAMPERING_RULE,
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_resources([_AZURE_TAGS_WRITE]),
                AZURE_TAMPERING_RULE,
            ),
        )

        for provider, normalizer, resources, expected_rule in cases:
            with self.subTest(provider=provider):
                inventory, findings = _analyze(normalizer, resources)
                paths, _uncertainties = _path_state(provider, inventory)

                self.assertEqual(paths, [])
                self.assertEqual(
                    [finding.rule_id for finding in findings],
                    [expected_rule],
                )
                self.assertEqual(findings[0].category, StrideCategory.TAMPERING)

    def test_private_workloads_keep_deletion_paths_without_public_findings(self) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_resources(
                    ["s3:PutObject", "s3:DeleteObject"],
                    public=False,
                    versioning="Enabled",
                ),
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_resources(
                    cast(
                        TerraformResource,
                        gcp_bucket_member(role="roles/storage.objectUser"),
                    ),
                    public=False,
                ),
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_resources(
                    [_AZURE_WRITE, _AZURE_DELETE],
                    public=False,
                ),
            ),
        )

        for provider, normalizer, resources in cases:
            with self.subTest(provider=provider):
                inventory, findings = _analyze(normalizer, resources)
                paths, _uncertainties = _path_state(provider, inventory)

                self.assertTrue(paths)
                self.assertEqual(findings, [])

    def test_nondeterministic_denied_incomplete_ambiguous_and_unresolved_stay_quiet(
        self,
    ) -> None:
        aws_incomplete = _aws_resources(
            "s3:DeleteObject",
            extra_resources=(
                aws_role_policy_attachment(
                    _TASK_ROLE_ARN,
                    "arn:aws:iam::aws:policy/ExternalS3Delete",
                ),
            ),
        )
        gcp_unresolved_workload = gcp_cloud_run()
        templates = gcp_unresolved_workload.values.get("template")
        assert isinstance(templates, list) and templates
        template = templates[0]
        assert isinstance(template, dict)
        template["service_account"] = "${google_service_account.runtime.email}"
        cases = (
            (
                "aws-conditional",
                "aws",
                AwsNormalizer(),
                _aws_resources(
                    "s3:DeleteObject",
                    statements=[
                        aws_statement(
                            "Allow",
                            "s3:DeleteObject",
                            f"{_BUCKET_ARN}/*",
                            condition={"StringEquals": {"aws:PrincipalTag/environment": "production"}},
                        )
                    ],
                ),
                True,
            ),
            (
                "aws-denied",
                "aws",
                AwsNormalizer(),
                _aws_resources(
                    "s3:DeleteObject",
                    statements=[
                        aws_statement(
                            "Allow",
                            "s3:DeleteObject",
                            f"{_BUCKET_ARN}/*",
                        ),
                        aws_statement(
                            "Deny",
                            "s3:DeleteObject",
                            f"{_BUCKET_ARN}/*",
                        ),
                    ],
                ),
                False,
            ),
            (
                "aws-incomplete",
                "aws",
                AwsNormalizer(),
                aws_incomplete,
                True,
            ),
            (
                "gcp-conditional",
                "gcp",
                GcpNormalizer(),
                _gcp_resources(
                    cast(
                        TerraformResource,
                        gcp_bucket_member(
                            condition={
                                "title": "deployment-window",
                                "expression": ("request.time < timestamp('2027-01-01T00:00:00Z')"),
                            }
                        ),
                    )
                ),
                True,
            ),
            (
                "gcp-ambiguous",
                "gcp",
                GcpNormalizer(),
                _gcp_resources(
                    cast(
                        TerraformResource,
                        gcp_custom_role(
                            role_id="ambiguousDelete",
                            permissions=["storage.objects.delete"],
                        ),
                    ),
                    cast(
                        TerraformResource,
                        gcp_bucket_member(role="projects/tfstride-demo/roles/ambiguousDelete"),
                    ),
                    cast(
                        TerraformResource,
                        gcp_bucket_binding(role="projects/tfstride-demo/roles/ambiguousDelete"),
                    ),
                ),
                True,
            ),
            (
                "gcp-unresolved-identity",
                "gcp",
                GcpNormalizer(),
                [
                    gcp_unresolved_workload,
                    gcp_public_invoker(),
                    cast(TerraformResource, gcp_bucket()),
                    cast(TerraformResource, gcp_bucket_member()),
                ],
                True,
            ),
            (
                "azure-conditional",
                "azure",
                AzureNormalizer(),
                _azure_resources(
                    [_AZURE_DELETE],
                    condition=(
                        "@Resource[Microsoft.Storage/storageAccounts/"
                        "blobServices/containers:name] StringEquals 'orders'"
                    ),
                ),
                True,
            ),
            (
                "azure-denied",
                "azure",
                AzureNormalizer(),
                _azure_resources(
                    [_AZURE_DELETE],
                    not_data_actions=[_AZURE_DELETE],
                ),
                False,
            ),
            (
                "azure-incomplete",
                "azure",
                AzureNormalizer(),
                _azure_resources([], unknown_permissions=True),
                True,
            ),
        )

        for label, provider, normalizer, resources, expect_uncertainty in cases:
            with self.subTest(case=label):
                inventory, findings = _analyze(normalizer, resources)
                paths, uncertainties = _path_state(provider, inventory)

                self.assertEqual(paths, [])
                self.assertEqual(findings, [])
                self.assertEqual(bool(uncertainties), expect_uncertainty)

    def test_provider_native_recovery_semantics_remain_operation_specific(self) -> None:
        aws_inventory, aws_findings = _analyze(
            AwsNormalizer(),
            _aws_resources(
                ["s3:DeleteObject", "s3:DeleteObjectVersion"],
                versioning="Enabled",
                object_lock=True,
            ),
        )
        aws_finding = _finding_by_rule(aws_findings, AWS_DISRUPTION_RULE)
        aws_recovery = _evidence(aws_finding)["recovery_evidence"]
        self.assertTrue(
            any(
                "operation=s3:DeleteObject" in value and "recovery_state=versioned_delete_marker" in value
                for value in aws_recovery
            )
        )
        self.assertTrue(
            any(
                "operation=s3:DeleteObjectVersion" in value
                and "object_lock_target_compatibility=unknown" in value
                and "permanent_deletion_not_established=true" in value
                for value in aws_recovery
            )
        )
        aws_paths, _aws_uncertainties = _path_state("aws", aws_inventory)
        self.assertEqual(
            {path["operation"] for path in aws_paths},
            {"s3:DeleteObject", "s3:DeleteObjectVersion"},
        )

        gcp_inventory, gcp_findings = _analyze(
            GcpNormalizer(),
            _gcp_custom_permission_resources(
                "deleteOnly",
                ["storage.objects.delete"],
            ),
        )
        gcp_finding = _finding_by_rule(gcp_findings, GCP_DISRUPTION_RULE)
        gcp_recovery = _evidence(gcp_finding)["recovery_posture"]
        self.assertTrue(
            any(
                "operation_class=logical_object_deletion" in value
                and "recovery_state=live_generation_retained_as_noncurrent" in value
                for value in gcp_recovery
            )
        )
        self.assertTrue(
            any(
                "operation_class=generation_deletion" in value
                and "recovery_state=soft_deleted_recoverable_during_retention" in value
                for value in gcp_recovery
            )
        )
        gcp_paths, _gcp_uncertainties = _path_state("gcp", gcp_inventory)
        self.assertEqual(
            {path["operation_class"] for path in gcp_paths},
            {"logical_object_deletion", "generation_deletion"},
        )

        azure_inventory, azure_findings = _analyze(
            AzureNormalizer(),
            _azure_owner_resources(),
        )
        azure_finding = _finding_by_rule(
            azure_findings,
            AZURE_DISRUPTION_RULE,
        )
        azure_recovery = _evidence(azure_finding)["recovery_posture"]
        self.assertTrue(
            any(
                f"operation={_AZURE_DELETE}" in value
                and "recovery_state=live_blob_delete_may_leave_noncurrent_version" in value
                and "permanent_loss_established=false" in value
                for value in azure_recovery
            )
        )
        self.assertTrue(
            any(
                f"operation={_AZURE_DELETE_VERSION}" in value
                and "recovery_state=soft_delete_recoverable_during_retention" in value
                and "permanent_loss_established=false" in value
                for value in azure_recovery
            )
        )
        azure_paths, _azure_uncertainties = _path_state(
            "azure",
            azure_inventory,
        )
        self.assertEqual(
            {path["operation"] for path in azure_paths},
            {_AZURE_DELETE, _AZURE_DELETE_VERSION},
        )

        permanent_inventory, permanent_findings = _analyze(
            AzureNormalizer(),
            _azure_resources(
                [_AZURE_PERMANENT_DELETE],
                account=azure_storage_account(permanent_delete_enabled=True),
            ),
        )
        permanent_paths, permanent_uncertainties = _path_state(
            "azure",
            permanent_inventory,
        )
        self.assertEqual(permanent_paths, [])
        self.assertEqual(permanent_findings, [])
        self.assertTrue(
            any(
                "requires an exact modeled soft-deleted blob version or snapshot target" in uncertainty
                for uncertainty in permanent_uncertainties
            )
        )

    def test_duplicate_authorization_evidence_deduplicates_by_stable_target_fingerprint(
        self,
    ) -> None:
        duplicate_aws_statement = aws_statement(
            "Allow",
            "s3:DeleteObject",
            f"{_BUCKET_ARN}/*",
        )
        duplicate_gcp_role_name = "projects/tfstride-demo/roles/duplicateDelete"
        duplicate_gcp_role = cast(
            TerraformResource,
            gcp_custom_role(
                role_id="duplicateDelete",
                permissions=["storage.objects.delete"],
            ),
        )
        duplicate_gcp_member = cast(
            TerraformResource,
            gcp_bucket_binding(
                role=duplicate_gcp_role_name,
                members=[GCP_SERVICE_ACCOUNT_MEMBER, GCP_SERVICE_ACCOUNT_MEMBER],
            ),
        )
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_resources(
                    "s3:DeleteObject",
                    statements=[
                        duplicate_aws_statement,
                        dict(duplicate_aws_statement),
                    ],
                    versioning="disabled",
                ),
                1,
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_resources(duplicate_gcp_role, duplicate_gcp_member),
                2,
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_resources([_AZURE_DELETE, _AZURE_DELETE]),
                1,
            ),
        )

        for provider, normalizer, resources, expected_count in cases:
            with self.subTest(provider=provider):
                inventory, findings = _analyze(normalizer, resources)
                paths, _uncertainties = _path_state(provider, inventory)
                fingerprints = [_path_fingerprint(provider, path) for path in paths]

                self.assertEqual(len(paths), expected_count)
                self.assertEqual(len(fingerprints), len(set(fingerprints)))
                self.assertEqual(
                    [finding.rule_id for finding in findings],
                    [
                        {
                            "aws": AWS_DISRUPTION_RULE,
                            "gcp": GCP_DISRUPTION_RULE,
                            "azure": AZURE_DISRUPTION_RULE,
                        }[provider]
                    ],
                )

    def test_reused_rule_engine_preserves_provider_isolation_and_excludes_payloads(
        self,
    ) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_resources(
                    ["s3:PutObject", "s3:DeleteObject"],
                    versioning="Enabled",
                    extra_resources=(_aws_payload_object(),),
                ),
                {AWS_TAMPERING_RULE, AWS_DISRUPTION_RULE},
                ("google_", "azurerm_"),
                _AWS_PAYLOAD_SENTINEL,
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_resources(
                    cast(
                        TerraformResource,
                        gcp_bucket_member(role="roles/storage.objectUser"),
                    ),
                    extra_resources=(_gcp_payload_object(),),
                ),
                {GCP_TAMPERING_RULE, GCP_DISRUPTION_RULE},
                ("aws_", "azurerm_"),
                _GCP_PAYLOAD_SENTINEL,
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_resources(
                    [_AZURE_WRITE, _AZURE_DELETE],
                    extra_resources=(_azure_payload_blob(),),
                ),
                {AZURE_TAMPERING_RULE, AZURE_DISRUPTION_RULE},
                ("aws_", "google_"),
                _AZURE_PAYLOAD_SENTINEL,
            ),
            (
                "aws-second-pass",
                AwsNormalizer(),
                _aws_resources(
                    ["s3:PutObject", "s3:DeleteObject"],
                    versioning="Enabled",
                    extra_resources=(_aws_payload_object(),),
                ),
                {AWS_TAMPERING_RULE, AWS_DISRUPTION_RULE},
                ("google_", "azurerm_"),
                _AWS_PAYLOAD_SENTINEL,
            ),
        )
        engine = StrideRuleEngine()

        for label, normalizer, resources, expected_rules, foreign_prefixes, sentinel in cases:
            with self.subTest(provider=label):
                provider = label.removesuffix("-second-pass")
                inventory, findings = _analyze(
                    normalizer,
                    resources,
                    engine=engine,
                )
                paths, _uncertainties = _path_state(provider, inventory)
                payload = json.dumps(
                    {
                        "paths": paths,
                        "findings": json.loads(_finding_payload(findings)),
                    },
                    sort_keys=True,
                )

                self.assertEqual(
                    {finding.rule_id for finding in findings},
                    expected_rules,
                )
                self.assertNotIn(sentinel, payload)
                for prefix in foreign_prefixes:
                    self.assertNotIn(prefix, payload)


if __name__ == "__main__":
    unittest.main()
