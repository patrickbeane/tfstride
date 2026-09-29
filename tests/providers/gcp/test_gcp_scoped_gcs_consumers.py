from __future__ import annotations

import unittest
from dataclasses import replace

from tests.providers.gcp.test_gcp_cloud_run_gcs_object_deletion_paths import (
    _BUCKET_ADDRESS,
    _bucket,
    _bucket_member,
    _bucket_policy,
    _custom_role,
)
from tests.providers.gcp.test_gcp_project_gcs_grants import _deny, _project_grant
from tests.providers.gcp.test_gcp_public_cloud_run_gcs_mutation_rules import (
    _cloud_run,
    _evaluate,
    _public_invoker,
)
from tests.providers.test_protected_data_key_authority_convergence import _gcp_resources
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_types import GCP_STORAGE_BUCKET_IAM_RESOURCE_TYPES

_READ = "gcp-public-workload-sensitive-data-access"
_MUTATE = "gcp-public-cloud-run-gcs-mutation-access"
_DELETE = "gcp-public-cloud-run-gcs-object-disruption"
_BUCKET_DELETE = "gcp-public-cloud-run-gcs-bucket-topology-disruption"
_KMS = "gcp-public-cloud-run-kms-decrypt-access"
_RULES = {_READ, _MUTATE, _DELETE, _BUCKET_DELETE}
_WORKLOAD = "google_cloud_run_v2_service.orders"


def _findings(inventory, rules=_RULES):
    return StrideRuleEngine().evaluate(
        inventory,
        detect_trust_boundaries(inventory),
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rules)),
    )


def _set_deny_permission(inventory, permission):
    deny = inventory.get_by_address("google_iam_deny_policy.deny")
    assert deny is not None
    facts = gcp_facts(deny)
    rules = facts.iam_deny_policy_rules
    rules[0]["denied_permissions"] = [permission]
    facts.set(GcpResourceMetadata.IAM_DENY_POLICY_RULES, rules)


class GcpScopedGcsConsumerTests(unittest.TestCase):
    def test_predefined_operation_families_remain_distinct_at_both_scopes(self) -> None:
        for role, expected in (
            ("roles/storage.objectCreator", {_MUTATE}),
            ("roles/storage.objectViewer", {_READ}),
            ("roles/storage.objectAdmin", {_READ, _MUTATE, _DELETE}),
            ("roles/storage.admin", _RULES),
        ):
            for grant in (_bucket_member(role=role), _project_grant(role=role)):
                with self.subTest(role=role, source=grant.address):
                    _, _, findings = _evaluate([_cloud_run(), _public_invoker(), _bucket(), grant], *_RULES)
                    self.assertEqual({finding.rule_id for finding in findings}, expected)
                    if role == "roles/storage.objectCreator":
                        self.assertIn("operations=storage.objects.create;", str(findings[0].evidence))
                        self.assertNotIn("storage.objects.delete", str(findings[0].evidence))

    def test_object_and_bucket_operations_do_not_imply_each_other(self) -> None:
        for permission, expected in (
            ("storage.objects.create", {_MUTATE}),
            ("storage.objects.update", {_MUTATE}),
            ("storage.objects.delete", {_DELETE}),
            ("storage.objects.setIamPolicy", {_MUTATE}),
            ("storage.buckets.delete", {_BUCKET_DELETE}),
        ):
            with self.subTest(permission=permission):
                _, _, findings = _evaluate(
                    [
                        _cloud_run(),
                        _public_invoker(),
                        _bucket(),
                        _custom_role(role_id="operation", permissions=[permission], stage="GA", deleted=False),
                        _bucket_member(role="projects/tfstride-demo/roles/operation"),
                    ],
                    *_RULES,
                )
                self.assertEqual({finding.rule_id for finding in findings}, expected)

    def test_specific_denies_remove_only_the_affected_consumer(self) -> None:
        for permission, removed in (
            ("storage.googleapis.com/objects.get", _READ),
            ("storage.googleapis.com/objects.delete", _DELETE),
            ("storage.googleapis.com/buckets.delete", _BUCKET_DELETE),
        ):
            for grant in (_bucket_member(role="roles/storage.admin"), _project_grant(role="roles/storage.admin")):
                with self.subTest(permission=permission, source=grant.address):
                    _, _, findings = _evaluate(
                        [
                            _cloud_run(),
                            _public_invoker(),
                            _bucket(),
                            grant,
                            _deny(permission=permission),
                        ],
                        *_RULES,
                    )
                    self.assertEqual({finding.rule_id for finding in findings}, _RULES - {removed})

    def test_unknown_deny_constraints_cannot_be_bypassed_by_any_consumer(self) -> None:
        for grant in (_bucket_member(role="roles/storage.admin"), _project_grant(role="roles/storage.admin")):
            with self.subTest(source=grant.address):
                inventory, _, findings = _evaluate(
                    [
                        _cloud_run(),
                        _public_invoker(),
                        _bucket(),
                        grant,
                        _deny(unknown={"rules": True}),
                    ],
                    *_RULES,
                )
                self.assertEqual(findings, [])
                workload = inventory.get_by_address(_WORKLOAD)
                assert workload is not None
                facts = gcp_facts(workload)
                self.assertTrue(facts.cloud_run_gcs_object_deletion_path_uncertainties)
                self.assertTrue(facts.cloud_run_gcs_bucket_topology_destruction_path_uncertainties)

    def test_deletion_revalidation_rechecks_new_denies_without_trusting_cached_paths(self) -> None:
        for permission, removed in (
            ("storage.googleapis.com/objects.delete", _DELETE),
            ("storage.googleapis.com/buckets.delete", _BUCKET_DELETE),
        ):
            with self.subTest(permission=permission):
                inventory, _, before = _evaluate(
                    [
                        _cloud_run(),
                        _public_invoker(),
                        _bucket(),
                        _project_grant(role="roles/storage.admin"),
                        _deny(permission="logging.googleapis.com/sinks.delete"),
                    ],
                    *_RULES,
                )
                self.assertEqual({finding.rule_id for finding in before}, _RULES)
                _set_deny_permission(inventory, permission)
                workload = inventory.get_by_address(_WORKLOAD)
                assert workload is not None
                self.assertTrue(gcp_facts(workload).cloud_run_gcs_object_deletion_paths)
                self.assertTrue(gcp_facts(workload).cloud_run_gcs_bucket_topology_destruction_paths)
                self.assertEqual({finding.rule_id for finding in _findings(inventory)}, _RULES - {removed})

    def test_current_bucket_grants_override_stale_decorated_binding_copies(self) -> None:
        grant = _bucket_member(role="roles/storage.admin")
        inventory, _, before = _evaluate([_cloud_run(), _public_invoker(), _bucket(), grant], *_RULES)
        self.assertEqual({finding.rule_id for finding in before}, _RULES)
        source = inventory.get_by_address(grant.address)
        bucket = inventory.get_by_address(_BUCKET_ADDRESS)
        assert source is not None and bucket is not None
        gcp_facts(source).set(GcpResourceMetadata.IAM_BINDINGS, [])
        self.assertTrue(gcp_facts(bucket).bindings)
        self.assertEqual(_findings(inventory), [])

    def test_unknown_current_bucket_scope_rejects_stale_target_evidence(self) -> None:
        grant = _bucket_member(role="roles/storage.admin")
        inventory, _, before = _evaluate([_cloud_run(), _public_invoker(), _bucket(), grant], *_RULES)
        self.assertEqual({finding.rule_id for finding in before}, _RULES)
        source = inventory.get_by_address(grant.address)
        assert source is not None
        gcp_facts(source).set(GcpResourceMetadata.IAM_SCOPE_REFERENCE_STATE, "unknown")
        self.assertEqual(_findings(inventory), [])

    def test_policy_for_unmodeled_other_bucket_cannot_override_this_bucket(self) -> None:
        policy = _bucket_policy(bucket="unrelated-bucket", role="roles/storage.admin")
        _, _, findings = _evaluate(
            [
                _cloud_run(),
                _public_invoker(),
                _bucket(),
                _bucket_member(role="roles/storage.admin"),
                policy,
            ],
            *_RULES,
        )
        self.assertEqual({finding.rule_id for finding in findings}, _RULES)

    def test_project_read_authority_participates_in_protected_data_convergence(self) -> None:
        resources = [
            resource
            for resource in _gcp_resources()
            if resource.resource_type not in GCP_STORAGE_BUCKET_IAM_RESOURCE_TYPES
        ] + [_project_grant(role="roles/storage.objectViewer")]
        inventory = GcpNormalizer().normalize(resources)
        workload = inventory.get_by_address(_WORKLOAD)
        assert workload is not None
        convergences = gcp_facts(workload).cloud_run_gcs_protected_data_convergences
        self.assertEqual(len(convergences), 1)
        self.assertEqual(convergences[0]["access_path"]["grant_basis"], "storage_project_iam")
        self.assertIn(_BUCKET_ADDRESS, _findings(inventory, {_KMS})[0].affected_resources)

    def test_payload_read_deny_removes_convergence_but_preserves_key_authority(self) -> None:
        for project_scope in (False, True):
            resources = _gcp_resources()
            if project_scope:
                resources = [
                    resource
                    for resource in resources
                    if resource.resource_type not in GCP_STORAGE_BUCKET_IAM_RESOURCE_TYPES
                ] + [_project_grant(role="roles/storage.objectViewer")]
            for cached in (False, True):
                with self.subTest(project_scope=project_scope, cached=cached):
                    deny = _deny(
                        permission=(
                            "logging.googleapis.com/sinks.delete" if cached else "storage.googleapis.com/objects.get"
                        )
                    )
                    inventory = GcpNormalizer().normalize([*resources, deny])
                    workload = inventory.get_by_address(_WORKLOAD)
                    assert workload is not None
                    if cached:
                        self.assertTrue(gcp_facts(workload).cloud_run_gcs_protected_data_convergences)
                        _set_deny_permission(inventory, "storage.googleapis.com/objects.get")
                    else:
                        self.assertEqual(gcp_facts(workload).cloud_run_gcs_protected_data_convergences, [])
                    findings = _findings(inventory, {_KMS})
                    self.assertEqual(len(findings), 1)
                    self.assertNotIn(_BUCKET_ADDRESS, findings[0].affected_resources)

    def test_unknown_project_scope_does_not_become_bucket_authority(self) -> None:
        grant = _project_grant(role="roles/storage.admin")
        for resource_order in (
            [_cloud_run(), _public_invoker(), _bucket(), replace(grant, unknown_values={"project": True})],
            [replace(grant, unknown_values={"project": True}), _bucket(), _public_invoker(), _cloud_run()],
        ):
            _, _, findings = _evaluate(resource_order, *_RULES)
            self.assertEqual(findings, [])
