from __future__ import annotations

import unittest
from dataclasses import replace
from unittest.mock import patch

from tests.helpers.gcp_gcs_plan import CUSTOM_ROLE, build_gcs_case
from tests.helpers.inventory import inventory_with_resources
from tfstride.analysis.indexes import build_analysis_indexes
from tfstride.analysis.preparation import PreparedAnalysis, prepare_analysis
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import ResourceInventory
from tfstride.providers.gcp.analysis_indexes import GcpAnalysisIndexes, build_gcp_analysis_indexes
from tfstride.providers.gcp.boundaries import GcpBoundaryContributor
from tfstride.providers.gcp.gcs_grant_evaluation import GcsGrantConstraintContext
from tfstride.providers.gcp.gcs_operation_gaps import collect_gcs_operation_gaps
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_index import GcpResourceIndexBuilder

_READ = "gcp-public-workload-sensitive-data-access"
_MUTATE = "gcp-public-cloud-run-gcs-mutation-access"
_DELETE = "gcp-public-cloud-run-gcs-object-disruption"
_TOPOLOGY = "gcp-public-cloud-run-gcs-bucket-topology-disruption"
_KMS = "gcp-public-cloud-run-kms-decrypt-access"
_GCS_RULES = {_READ, _MUTATE, _DELETE, _TOPOLOGY}
_POLICY = RulePolicy(enabled_rule_ids=frozenset({*_GCS_RULES, _KMS}))


def _prepare(engine: StrideRuleEngine, inventory: ResourceInventory) -> PreparedAnalysis:
    return prepare_analysis(
        inventory,
        rule_set=engine.rule_set_for("gcp"),
        provider_extension_factory=build_gcp_analysis_indexes,
        provider_boundary_contributor_factories=(GcpBoundaryContributor,),
    )


def _evaluate(engine: StrideRuleEngine, prepared: PreparedAnalysis):
    return engine.evaluate(
        prepared.inventory,
        prepared.boundaries,
        analysis_indexes=prepared.indexes,
        rule_set=prepared.rule_set,
        rule_policy=_POLICY,
    )


class GcpGcsAnalysisContextTests(unittest.TestCase):
    def test_preparation_builds_one_context_and_rules_reuse_its_indexes(self) -> None:
        engine = StrideRuleEngine()
        for case, expected_rules in (
            ("mixed", _GCS_RULES),
            ("protected_data", {_READ, _KMS}),
            ("no_buckets", set()),
        ):
            with self.subTest(case=case):
                inventory = GcpNormalizer().normalize(build_gcs_case(case))
                with patch.object(GcsGrantConstraintContext, "build", wraps=GcsGrantConstraintContext.build) as builds:
                    prepared = _prepare(engine, inventory)
                self.assertEqual(builds.call_count, 0 if case == "no_buckets" else 1)
                extension = prepared.indexes.require_provider_extension(GcpAnalysisIndexes)
                self.assertEqual(extension.gcs_grant_context is None, case == "no_buckets")
                with (
                    patch.object(
                        GcsGrantConstraintContext, "build", side_effect=AssertionError("rules rebuilt GCS context")
                    ),
                    patch.object(
                        GcpResourceIndexBuilder, "build", side_effect=AssertionError("rules rebuilt GCP indexes")
                    ),
                ):
                    findings = _evaluate(engine, prepared)
                self.assertEqual({finding.rule_id for finding in findings}, expected_rules)

    def test_fresh_preparation_revalidates_cached_paths_after_authorization_changes(self) -> None:
        engine = StrideRuleEngine()
        for change, workload_name, expected_rules in (
            ("removed_binding", "w0", set()),
            ("role_permissions", "w2", {_READ, _MUTATE}),
            ("ambiguous_role", "w2", set()),
            ("new_deny", "w0", {_READ, _MUTATE}),
        ):
            with self.subTest(change=change):
                inventory = GcpNormalizer().normalize(build_gcs_case("mixed"))
                workload = inventory.get_by_address(f"google_cloud_run_v2_service.{workload_name}")
                source = inventory.get_by_address("google_storage_bucket_iam_member.local")
                role = inventory.get_by_address("google_project_iam_custom_role.storage_operator")
                assert workload is not None and source is not None and role is not None
                before = _prepare(engine, inventory)
                before_context = before.indexes.require_provider_extension(GcpAnalysisIndexes).gcs_grant_context
                assert before_context is not None
                self.assertEqual(
                    {
                        finding.rule_id
                        for finding in _evaluate(engine, before)
                        if workload.address in finding.affected_resources
                    },
                    _GCS_RULES,
                )
                cached_paths = workload.metadata_snapshot()
                self.assertTrue(cached_paths["cloud_run_gcs_object_deletion_paths"])
                self.assertTrue(cached_paths["cloud_run_gcs_bucket_topology_destruction_paths"])

                if change == "removed_binding":
                    gcp_facts(source).set(GcpResourceMetadata.IAM_BINDINGS, [])
                elif change == "role_permissions":
                    gcp_facts(role).set(
                        GcpResourceMetadata.CUSTOM_ROLE_PERMISSIONS, ["storage.objects.get", "storage.objects.create"]
                    )
                elif change == "ambiguous_role":
                    duplicate = replace(
                        role, address="google_project_iam_custom_role.duplicate", metadata=role.metadata_snapshot()
                    )
                    inventory = inventory_with_resources(inventory, [*inventory.resources, duplicate])
                else:
                    deny = build_gcs_case("deny")[-1]
                    rule = deny.values["rules"][0]["deny_rule"][0]
                    rule["denied_permissions"] = [
                        "storage.googleapis.com/objects.delete",
                        "storage.googleapis.com/buckets.delete",
                    ]
                    rule["denied_principals"] = [
                        principal.replace("/w1@", "/w0@") for principal in rule["denied_principals"]
                    ]
                    deny_resources = GcpNormalizer().normalize([deny]).resources
                    inventory = inventory_with_resources(inventory, [*inventory.resources, *deny_resources])

                after = _prepare(engine, inventory)
                after_context = after.indexes.require_provider_extension(GcpAnalysisIndexes).gcs_grant_context
                assert after_context is not None
                self.assertIsNot(after_context, before_context)
                self.assertIsNot(after_context.index, before_context.index)
                self.assertIsNot(after_context.custom_roles, before_context.custom_roles)
                if change == "ambiguous_role":
                    self.assertEqual(before_context.custom_roles.resolve(CUSTOM_ROLE).state, "resolved")
                    self.assertEqual(after_context.custom_roles.resolve(CUSTOM_ROLE).state, "ambiguous")
                if change == "new_deny":
                    self.assertEqual(len(before_context.deny_policies), 0)
                    self.assertEqual(len(after_context.deny_policies), 1)
                self.assertEqual(
                    {
                        finding.rule_id
                        for finding in _evaluate(engine, after)
                        if workload.address in finding.affected_resources
                    },
                    expected_rules,
                )
                self.assertEqual(workload.metadata_snapshot(), cached_paths)

    def test_fresh_preparation_rechecks_gcs_read_authority_for_cached_kms_convergence(self) -> None:
        inventory = GcpNormalizer().normalize(build_gcs_case("protected_data"))
        engine = StrideRuleEngine()
        before = _prepare(engine, inventory)
        kms_before = next(finding for finding in _evaluate(engine, before) if finding.rule_id == _KMS)
        self.assertIn("google_storage_bucket.b0", kms_before.affected_resources)
        workload = inventory.get_by_address("google_cloud_run_v2_service.w0")
        source = inventory.get_by_address("google_storage_bucket_iam_member.reader")
        assert workload is not None and source is not None
        cached = gcp_facts(workload).cloud_run_gcs_protected_data_convergences
        self.assertTrue(cached)
        gcp_facts(source).set(GcpResourceMetadata.IAM_BINDINGS, [])
        after = _prepare(engine, inventory)
        findings = _evaluate(engine, after)
        kms_after = next(finding for finding in findings if finding.rule_id == _KMS)
        self.assertNotIn("google_storage_bucket.b0", kms_after.affected_resources)
        self.assertTrue(all("google_storage_bucket.b0" not in finding.affected_resources for finding in findings))
        self.assertEqual(gcp_facts(workload).cloud_run_gcs_protected_data_convergences, cached)

    def test_explicitly_omitted_provider_extension_preserves_rule_results(self) -> None:
        engine = StrideRuleEngine()
        for case in ("mixed", "protected_data", "no_buckets"):
            with self.subTest(case=case):
                inventory = GcpNormalizer().normalize(build_gcs_case(case))
                expected = _evaluate(engine, _prepare(engine, inventory))
                indexes = build_analysis_indexes(inventory, provider_extension_factory=lambda _inventory: None)
                actual = engine.evaluate(
                    inventory,
                    detect_trust_boundaries(inventory, indexes=indexes),
                    analysis_indexes=indexes,
                    rule_policy=_POLICY,
                )
                self.assertEqual(actual, expected)

    def test_operation_gap_collection_uses_a_fresh_context_for_each_invocation(self) -> None:
        inventory = GcpNormalizer().normalize(build_gcs_case("conditional_unknown"))
        prepared = _prepare(StrideRuleEngine(), inventory)
        rule_context = prepared.indexes.require_provider_extension(GcpAnalysisIndexes).gcs_grant_context
        contexts: list[GcsGrantConstraintContext] = []
        build = GcsGrantConstraintContext.build

        def record_build(resources):
            context = build(resources)
            contexts.append(context)
            return context

        with patch.object(GcsGrantConstraintContext, "build", side_effect=record_build):
            first = collect_gcs_operation_gaps(inventory)
            second = collect_gcs_operation_gaps(inventory)
        self.assertTrue(first.records)
        self.assertEqual(first, second)
        self.assertEqual(len(contexts), 2)
        self.assertIsNot(contexts[0], contexts[1])
        self.assertTrue(all(context is not rule_context for context in contexts))


if __name__ == "__main__":
    unittest.main()
