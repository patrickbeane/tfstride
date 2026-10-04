"""Metamorphic invariants for the three plan-local object-storage gap producers."""

from __future__ import annotations

import json
import unittest
from collections.abc import Callable

from tests.providers.aws.test_aws_ecs_s3_access_paths import (
    _BUCKET_ARN,
    _role_policy_attachment,
    _statement,
)
from tests.providers.aws.test_aws_ecs_s3_access_paths import (
    _bucket as aws_bucket,
)
from tests.providers.aws.test_aws_s3_broad_grants import _resources as aws_resources
from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _STORAGE_ACCOUNT_ID,
    _web_app,
)
from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _custom_role as azure_role,
)
from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _role_assignment as azure_assignment,
)
from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _storage_account as azure_account,
)
from tests.providers.gcp.normalizer_support import _terraform_resource
from tests.providers.gcp.test_gcp_cloud_run_gcs_access_paths import (
    _bucket as gcp_bucket,
)
from tests.providers.gcp.test_gcp_cloud_run_gcs_access_paths import (
    _bucket_iam_member,
    _cloud_run,
)
from tests.providers.gcp.test_gcp_cloud_run_gcs_access_paths import (
    _custom_role as gcp_role,
)
from tfstride.analysis.operation_gaps import OperationGapEvidenceState
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.policy_documents import parse_policy_statement
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.s3_gap_evidence import S3_GAP_FAMILIES, S3_MUTATION
from tfstride.providers.azure.blob_operation_gaps import BLOB_GAP_FAMILIES, BLOB_MUTATION
from tfstride.providers.azure.limitations import AZURE_LIMITATIONS
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.catalog import default_provider_operation_gap_factories_by_provider
from tfstride.providers.gcp.gcs_operation_gaps import GCS_GAP_FAMILIES, GCS_MUTATION
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_types import GcpResourceType
from tfstride.reporting.operation_gaps import render_operation_gaps, serialize_operation_gaps

_PROVIDERS = ("aws", "gcp", "azure")
_CONDITION_SENTINEL = "SECRET-GAP-CONDITION"
_AWS_SCOPE = f"{_BUCKET_ARN}/public/*"
_AZURE_WRITE = "microsoft.storage/storageaccounts/blobservices/containers/blobs/write"
_OPERATIONS = {"aws": "s3:PutObject", "gcp": "storage.objects.create", "azure": _AZURE_WRITE}
_TARGETS = {
    "aws": "aws_s3_bucket.orders",
    "gcp": "google_storage_bucket.orders",
    "azure": "azurerm_storage_account.orders",
}
_REASONS = {
    "aws": "policy_condition_unresolved",
    "gcp": "iam_condition_unresolved",
    "azure": "assignment_condition_unresolved",
}
_MISSING_REASONS = {
    "aws": "identity_policy_document_unavailable",
    "gcp": "custom_role_definition_unavailable",
    "azure": "role_definition_unavailable",
}
_FAMILIES = {"aws": S3_GAP_FAMILIES, "gcp": GCS_GAP_FAMILIES, "azure": BLOB_GAP_FAMILIES}
_MUTATION_FAMILIES = {"aws": S3_MUTATION, "gcp": GCS_MUTATION, "azure": BLOB_MUTATION}


def _condition_resources(provider: str, *, condition: bool = True, extra_operation: bool = False):
    if provider == "aws":
        resources = aws_resources(actions="s3:PutObject", resource=_AWS_SCOPE)
        role = next(item for item in resources if item.resource_type == "aws_iam_role")
        statements = [
            _statement(
                "Allow",
                "s3:PutObject",
                _AWS_SCOPE,
                condition={"Bool": {"aws:SecureTransport": _CONDITION_SENTINEL}} if condition else None,
            )
        ]
        if extra_operation:
            statements.append(_statement("Allow", "s3:GetObject", _AWS_SCOPE))
        role.values["inline_policy"][0]["policy"] = json.dumps({"Version": "2012-10-17", "Statement": statements})
        return resources
    if provider == "gcp":
        resources = [
            _cloud_run(),
            gcp_bucket(),
            _bucket_iam_member(
                role="roles/storage.objectCreator",
                condition={"title": "limited", "expression": _CONDITION_SENTINEL} if condition else None,
            ),
        ]
        if extra_operation:
            viewer = _bucket_iam_member(role="roles/storage.objectViewer")
            viewer.address = "google_storage_bucket_iam_member.viewer"
            viewer.name = "viewer"
            resources.append(viewer)
        return resources
    if provider == "azure":
        resources = [
            azure_account(),
            _web_app(),
            azure_role(data_actions=[_AZURE_WRITE]),
            azure_assignment(
                scope=_STORAGE_ACCOUNT_ID,
                role_name=None,
                role_definition_id="azurerm_role_definition.blob_writer.role_definition_resource_id",
                condition=_CONDITION_SENTINEL if condition else None,
            ),
        ]
        if extra_operation:
            resources.append(
                azure_assignment(
                    scope=_STORAGE_ACCOUNT_ID,
                    name="reader",
                    role_name="Storage Blob Data Reader",
                    role_definition_id=(
                        "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/"
                        "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1"
                    ),
                )
            )
        return resources
    raise AssertionError(provider)


def _missing_resources(provider: str, *, missing: bool):
    if provider == "aws":
        resources = aws_resources(actions="s3:PutObject", resource=_AWS_SCOPE)
        if missing:
            role = next(item for item in resources if item.resource_type == "aws_iam_role")
            role.values["inline_policy"] = []
            resources.append(_role_policy_attachment("orders_task", "arn:aws:iam::111122223333:policy/missing"))
        return resources
    if provider == "gcp":
        role = gcp_role(permissions=["storage.objects.create"])
        grant = _bucket_iam_member(role=role.values["name"])
        return [_cloud_run(), gcp_bucket(), *([] if missing else [role]), grant]
    if provider == "azure":
        role = azure_role(data_actions=[_AZURE_WRITE])
        grant = azure_assignment(
            scope=_STORAGE_ACCOUNT_ID,
            role_name=None,
            role_definition_id="azurerm_role_definition.blob_writer.role_definition_resource_id",
        )
        return [azure_account(), _web_app(), *([] if missing else [role]), grant]
    raise AssertionError(provider)


def _unrelated_storage(provider: str):
    if provider == "aws":
        return aws_bucket("unrelated", arn="arn:aws:s3:::unrelated-data")
    if provider == "gcp":
        return _terraform_resource(
            "google_storage_bucket.unrelated",
            GcpResourceType.STORAGE_BUCKET,
            {"name": "unrelated-data", "project": "other-project", "location": "US"},
        )
    if provider == "azure":
        resource = azure_account()
        resource.address = "azurerm_storage_account.unrelated"
        resource.name = "unrelated"
        resource.values["id"] = _STORAGE_ACCOUNT_ID.replace("sub-0001", "other-subscription")
        return resource
    raise AssertionError(provider)


def _inventory(provider: str, resources):
    normalizer = {"aws": AwsNormalizer, "gcp": GcpNormalizer, "azure": AzureNormalizer}[provider]
    return normalizer().normalize(resources)


def _gaps(provider: str, inventory):
    factory = default_provider_operation_gap_factories_by_provider()[provider][0]
    return factory(inventory)


def _proven_access_count(provider: str, inventory) -> int:
    address = {
        "aws": "aws_ecs_task_definition.orders",
        "gcp": "google_cloud_run_v2_service.orders",
        "azure": "azurerm_linux_web_app.orders",
    }[provider]
    workload = inventory.get_by_address(address)
    assert workload is not None
    if provider == "aws":
        paths = aws_facts(workload).ecs_s3_access_paths
    elif provider == "gcp":
        paths = gcp_facts(workload).cloud_run_gcs_access_paths
    else:
        paths = azure_facts(workload).app_service_storage_access_paths
    return sum(path["access_state"] in {"allowed", "granted"} for path in paths)


def _introduce_condition(provider: str, inventory) -> Callable[[], None]:
    if provider == "aws":
        role = inventory.get_by_address("aws_iam_role.orders_task")
        assert role is not None
        original = role.policy_statements
        role.policy_statements = (
            parse_policy_statement(
                _statement(
                    "Allow",
                    "s3:PutObject",
                    _AWS_SCOPE,
                    condition={"Bool": {"aws:SecureTransport": _CONDITION_SENTINEL}},
                )
            ),
        )
        return lambda: setattr(role, "policy_statements", original)
    if provider == "gcp":
        source = inventory.get_by_address("google_storage_bucket_iam_member.orders_access")
        assert source is not None
        facts = gcp_facts(source)
        original = facts.bindings
        facts.set(
            GcpResourceMetadata.IAM_BINDINGS,
            [
                {
                    **binding,
                    "condition": {"title": "limited", "expression": _CONDITION_SENTINEL},
                    "condition_state": "configured",
                }
                for binding in original
            ],
        )
        return lambda: facts.set(GcpResourceMetadata.IAM_BINDINGS, original)
    if provider == "azure":
        source = inventory.get_by_address("azurerm_role_assignment.orders_blob")
        assert source is not None
        facts = azure_facts(source)
        facts.set(AzureResourceMetadata.ROLE_ASSIGNMENT_CONDITION, _CONDITION_SENTINEL)
        return lambda: facts.set(AzureResourceMetadata.ROLE_ASSIGNMENT_CONDITION, None)
    raise AssertionError(provider)


class ObjectStorageGapInvariantTests(unittest.TestCase):
    def test_unrelated_resources_and_resource_order_preserve_existing_gaps(self):
        for provider in _PROVIDERS:
            with self.subTest(provider=provider):
                baseline = _gaps(provider, _inventory(provider, _condition_resources(provider)))
                self.assertTrue(baseline.records)
                self.assertEqual(set(baseline.reporting_families), set(_FAMILIES[provider]))
                for with_unrelated in (False, True):
                    for order in ("forward", "reverse", "rotate"):
                        resources = _condition_resources(provider)
                        if with_unrelated:
                            resources.append(_unrelated_storage(provider))
                        if order == "reverse":
                            resources.reverse()
                        elif order == "rotate":
                            resources = resources[2:] + resources[:2]
                        self.assertEqual(_gaps(provider, _inventory(provider, resources)), baseline)

    def test_unrelated_operation_does_not_expand_a_scoped_gap(self):
        for provider in _PROVIDERS:
            with self.subTest(provider=provider):
                baseline = _gaps(provider, _inventory(provider, _condition_resources(provider)))
                augmented = _gaps(provider, _inventory(provider, _condition_resources(provider, extra_operation=True)))
                self.assertEqual(augmented, baseline)
                self.assertEqual({gap.operation for gap in augmented.records}, {_OPERATIONS[provider]})
                self.assertIn(_MUTATION_FAMILIES[provider], {gap.family for gap in augmented.records})
                self.assertEqual({gap.target_address for gap in augmented.records}, {_TARGETS[provider]})

    def test_missing_authority_evidence_adds_uncertainty_without_adding_access(self):
        for provider in _PROVIDERS:
            with self.subTest(provider=provider):
                complete_inventory = _inventory(provider, _missing_resources(provider, missing=False))
                missing_inventory = _inventory(provider, _missing_resources(provider, missing=True))
                complete = _gaps(provider, complete_inventory)
                missing = _gaps(provider, missing_inventory)
                self.assertEqual(complete.records, ())
                self.assertGreater(_proven_access_count(provider, complete_inventory), 0)
                self.assertEqual(_proven_access_count(provider, missing_inventory), 0)
                self.assertTrue(missing.records)
                self.assertEqual({gap.reason_code for gap in missing.records}, {_MISSING_REASONS[provider]})
                self.assertEqual({gap.evidence_state for gap in missing.records}, {OperationGapEvidenceState.MISSING})
                self.assertTrue(all(gap.operation is None for gap in missing.records))
                self.assertEqual(complete.reporting_families, missing.reporting_families)
                reported = serialize_operation_gaps(missing)["records"]
                self.assertTrue(all("include" in record["next_step"].lower() for record in reported))
                self.assertTrue(
                    all("The reporting family could not complete" not in record["explanation"] for record in reported)
                )

    def test_repeated_evaluation_replaces_gaps_when_current_evidence_changes(self):
        for provider in _PROVIDERS:
            with self.subTest(provider=provider):
                inventory = _inventory(provider, _condition_resources(provider, condition=False))
                self.assertEqual(_gaps(provider, inventory).records, ())
                restore = _introduce_condition(provider, inventory)
                uncertain = _gaps(provider, inventory)
                self.assertEqual({gap.reason_code for gap in uncertain.records}, {_REASONS[provider]})
                self.assertEqual({gap.operation for gap in uncertain.records}, {_OPERATIONS[provider]})
                restore()
                self.assertEqual(_gaps(provider, inventory).records, ())
                self.assertTrue(uncertain.records)  # The prior immutable result was not mutated.

    def test_equivalent_condition_reasons_keep_meaning_and_provider_explanations(self):
        explanations: set[str] = set()
        for provider in _PROVIDERS:
            with self.subTest(provider=provider):
                result = _gaps(provider, _inventory(provider, _condition_resources(provider)))
                payload = serialize_operation_gaps(result)
                self.assertEqual(len(payload["reporting_families"]), len(_FAMILIES[provider]))
                self.assertEqual({record["reason_code"] for record in payload["records"]}, {_REASONS[provider]})
                self.assertEqual({record["evidence_state"] for record in payload["records"]}, {"conditional"})
                self.assertEqual({record["operation"] for record in payload["records"]}, {_OPERATIONS[provider]})
                self.assertEqual({record["target_address"] for record in payload["records"]}, {_TARGETS[provider]})
                self.assertTrue(all(record["scope"] for record in payload["records"]))
                self.assertTrue(all(record["family"]["provider"] == provider for record in payload["records"]))
                self.assertTrue(all("condition" in record["next_step"].lower() for record in payload["records"]))
                self.assertTrue(
                    all(
                        "The reporting family could not complete" not in record["explanation"]
                        for record in payload["records"]
                    )
                )
                self.assertNotIn(_CONDITION_SENTINEL, json.dumps(payload))
                lines = render_operation_gaps(result)
                self.assertTrue(any(_OPERATIONS[provider] in line for line in lines))
                self.assertNotIn(_CONDITION_SENTINEL, "\n".join(lines))
                explanations.update(record["explanation"] for record in payload["records"])
        self.assertGreaterEqual(len(explanations), len(_PROVIDERS))

    def test_standing_azure_deny_limitation_does_not_multiply_resource_gaps(self):
        resources = _condition_resources("azure", condition=False)
        for suffix in ("one", "two", "three"):
            account = _unrelated_storage("azure")
            account.address = f"azurerm_storage_account.{suffix}"
            account.name = suffix
            account.values["id"] = _STORAGE_ACCOUNT_ID.replace("ordersdata", suffix)
            resources.append(account)
        result = _gaps("azure", _inventory("azure", resources))
        self.assertEqual(result.records, ())
        self.assertEqual(set(result.reporting_families), set(BLOB_GAP_FAMILIES))
        self.assertEqual(sum("deny assignments" in limitation for limitation in AZURE_LIMITATIONS), 1)
