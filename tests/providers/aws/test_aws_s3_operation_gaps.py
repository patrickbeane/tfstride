from __future__ import annotations

import json
import unittest
from dataclasses import asdict
from pathlib import Path
from tempfile import TemporaryDirectory

from tests.helpers.inventory import inventory_with_updated_identity
from tests.providers.aws.test_aws_ecs_s3_access_paths import (
    _BUCKET_ARN,
    _TASK_ROLE_ARN,
    _bucket,
    _role,
    _statement,
)
from tests.providers.aws.test_aws_ecs_s3_object_deletion_paths import (
    _bucket_policy,
    _bucket_statement,
    _unresolved_bucket_policy,
)
from tests.providers.aws.test_aws_s3_broad_grants import _OPERATIONS, _resources
from tests.providers.test_protected_data_key_authority_convergence import _aws_resources
from tfstride.analysis.operation_gaps import OperationGapEvidenceState
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.app import TfStride
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.policy_documents import parse_policy_statement
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.s3_gap_evidence import (
    S3_ACCESS,
    S3_BUCKET_TOPOLOGY,
    S3_GAP_FAMILIES,
    S3_MUTATION,
    S3_OBJECT_DELETION,
    S3_PROTECTED_DATA,
)
from tfstride.providers.aws.s3_operation_gaps import collect_s3_operation_gaps


def _resource(inventory, address):
    resource = inventory.get_by_address(address)
    assert resource is not None
    return resource


def _replace_role_policy(inventory, statements):
    _resource(inventory, "aws_iam_role.orders_task").policy_statements = tuple(
        parse_policy_statement(s) for s in statements
    )


def _signature(results):
    return {(g.family, g.operation, g.target_address, g.scope, g.reason_code) for g in results.records}


class AwsS3OperationGapTests(unittest.TestCase):
    def test_broad_supported_grants_run_all_families_without_gaps_or_path_changes(self):
        inventory = AwsNormalizer().normalize(_resources())
        task = _resource(inventory, "aws_ecs_task_definition.orders")
        before = dict(task.metadata)
        result = collect_s3_operation_gaps(inventory)
        self.assertEqual(set(result.reporting_families), set(S3_GAP_FAMILIES))
        self.assertEqual(result.records, ())
        self.assertEqual(dict(task.metadata), before)

    def test_current_policy_changes_remove_and_introduce_gaps_without_redecoration(self):
        inventory = AwsNormalizer().normalize(_resources(actions="s3:PutObject", resource=f"{_BUCKET_ARN}/public/*"))
        self.assertEqual(collect_s3_operation_gaps(inventory).records, ())
        _replace_role_policy(
            inventory,
            [
                _statement(
                    "Allow",
                    "s3:PutObject",
                    f"{_BUCKET_ARN}/public/*",
                    condition={"StringEquals": {"aws:SourceVpc": "SECRET-SENTINEL"}},
                )
            ],
        )
        result = collect_s3_operation_gaps(inventory)
        self.assertEqual({g.family for g in result.records}, {S3_ACCESS, S3_MUTATION})
        self.assertEqual({g.operation for g in result.records}, {"s3:PutObject"})
        self.assertEqual({g.scope for g in result.records}, {f"{_BUCKET_ARN}/public/*"})
        self.assertEqual({g.evidence_state for g in result.records}, {OperationGapEvidenceState.CONDITIONAL})
        self.assertNotIn("SECRET-SENTINEL", repr(asdict(result)))
        _replace_role_policy(inventory, [_statement("Allow", "s3:PutObject", f"{_BUCKET_ARN}/public/*")])
        self.assertEqual(collect_s3_operation_gaps(inventory).records, ())
        self.assertEqual(len(result.records), 2)

    def test_denied_operations_and_disjoint_conditional_denies_are_not_gaps(self):
        for denied in ("*", f"{_BUCKET_ARN}/private/*"):
            with self.subTest(denied=denied):
                inventory = AwsNormalizer().normalize(_resources(resource=f"{_BUCKET_ARN}/public/*"))
                _replace_role_policy(
                    inventory,
                    [
                        _statement("Allow", _OPERATIONS, f"{_BUCKET_ARN}/public/*"),
                        _statement(
                            "Deny",
                            _OPERATIONS,
                            denied,
                            condition={"Bool": {"aws:SecureTransport": "false"}} if "private" in denied else None,
                        ),
                    ],
                )
                self.assertEqual(collect_s3_operation_gaps(inventory).records, ())

    def test_partial_deny_reports_only_affected_operation_and_original_scope(self):
        inventory = AwsNormalizer().normalize(_resources())
        _replace_role_policy(
            inventory,
            [
                _statement("Allow", _OPERATIONS, "*"),
                _statement("Deny", "s3:DeleteObject", f"{_BUCKET_ARN}/private/*"),
            ],
        )
        result = collect_s3_operation_gaps(inventory)
        self.assertEqual({g.family for g in result.records}, {S3_ACCESS, S3_OBJECT_DELETION})
        self.assertEqual({g.operation for g in result.records}, {"s3:DeleteObject"})
        self.assertEqual({g.scope for g in result.records}, {f"{_BUCKET_ARN}/*"})
        self.assertEqual({g.reason_code for g in result.records}, {"residual_scope_unrepresentable"})

    def test_boundary_and_ownership_gaps_retain_known_operations_and_scopes(self):
        for gate, reason in (
            ("boundary", "permissions_boundary_intersection_unmodeled"),
            ("ownership", "ownership_unresolved"),
        ):
            with self.subTest(gate=gate):
                inventory = AwsNormalizer().normalize(_resources())
                if gate == "boundary":
                    facts = aws_facts(_resource(inventory, "aws_iam_role.orders_task"))
                    facts.set(AwsResourceMetadata.IAM_PERMISSIONS_BOUNDARY_STATE, "configured")
                    facts.set(
                        AwsResourceMetadata.IAM_PERMISSIONS_BOUNDARY_ARN, "arn:aws:iam::111122223333:policy/boundary"
                    )
                else:
                    _resource(inventory, "aws_s3_bucket.orders").provider_config_key = "aws.unknown"
                result = collect_s3_operation_gaps(inventory)
                self.assertEqual({g.reason_code for g in result.records}, {reason})
                self.assertEqual(
                    {g.family for g in result.records}, {S3_ACCESS, S3_MUTATION, S3_OBJECT_DELETION, S3_BUCKET_TOPOLOGY}
                )
                self.assertEqual({g.operation for g in result.records}, set(_OPERATIONS))
                self.assertTrue(all(g.target_address == "aws_s3_bucket.orders" and g.scope for g in result.records))

    def test_missing_policy_document_does_not_invent_operations_or_targets(self):
        resources = _resources()
        resources[2] = _role("orders_task", _TASK_ROLE_ARN)
        inventory = AwsNormalizer().normalize(resources)
        facts = aws_facts(_resource(inventory, "aws_iam_role.orders_task"))
        facts.set(AwsResourceMetadata.UNRESOLVED_ATTACHED_POLICY_ARNS, ["SECRET-SENTINEL-policy"])
        result = collect_s3_operation_gaps(inventory)
        self.assertTrue(result.records)
        self.assertTrue(
            all(g.operation is None and g.target_address is None and g.scope is None for g in result.records)
        )
        self.assertEqual({g.reason_code for g in result.records}, {"identity_policy_document_unavailable"})
        self.assertNotIn("SECRET-SENTINEL", repr(result))
        facts.set(AwsResourceMetadata.UNRESOLVED_ATTACHED_POLICY_ARNS, [])
        self.assertEqual(collect_s3_operation_gaps(inventory).records, ())

    def test_ambiguous_modeled_buckets_preserve_candidates_without_authorizing_them(self):
        inventory = AwsNormalizer().normalize([*_resources(), _bucket("duplicate", arn=_BUCKET_ARN)])
        result = collect_s3_operation_gaps(inventory)
        self.assertEqual({g.reason_code for g in result.records}, {"target_ambiguous"})
        self.assertEqual(
            {g.target_address for g in result.records}, {"aws_s3_bucket.orders", "aws_s3_bucket.duplicate"}
        )
        self.assertEqual({g.operation for g in result.records}, set(_OPERATIONS))

    def test_direct_bucket_policy_deletion_uses_its_native_proof_model(self):
        for conditional in (False, True):
            with self.subTest(conditional=conditional):
                resources = _resources()
                resources[2] = _role("orders_task", _TASK_ROLE_ARN)
                resources.append(
                    _bucket_policy(
                        [
                            _bucket_statement(
                                "Allow",
                                ["s3:DeleteObject", "s3:DeleteBucket"],
                                "*",
                                _TASK_ROLE_ARN,
                                condition={"Bool": {"aws:SecureTransport": "true"}} if conditional else None,
                            )
                        ]
                    )
                )
                result = collect_s3_operation_gaps(AwsNormalizer().normalize(resources))
                if conditional:
                    self.assertEqual({g.family for g in result.records}, {S3_OBJECT_DELETION, S3_BUCKET_TOPOLOGY})
                    self.assertEqual({g.reason_code for g in result.records}, {"policy_condition_unresolved"})
                else:
                    self.assertEqual(result.records, ())

    def test_independent_allowed_prefix_does_not_hide_an_unassessed_deletion_prefix(self):
        inventory = AwsNormalizer().normalize(_resources())
        _replace_role_policy(
            inventory,
            [
                _statement("Allow", "s3:DeleteObject", f"{_BUCKET_ARN}/public/*"),
                _statement(
                    "Allow",
                    "s3:DeleteObject",
                    f"{_BUCKET_ARN}/private/*",
                    condition={"Bool": {"aws:SecureTransport": "true"}},
                ),
            ],
        )
        result = collect_s3_operation_gaps(inventory)
        self.assertEqual({g.family for g in result.records}, {S3_ACCESS, S3_OBJECT_DELETION})
        self.assertEqual({g.scope for g in result.records}, {f"{_BUCKET_ARN}/private/*"})

    def test_protected_data_read_gap_is_current_and_does_not_claim_write_as_read(self):
        inventory = AwsNormalizer().normalize(_aws_resources())
        self.assertEqual(collect_s3_operation_gaps(inventory).records, ())
        role = _resource(inventory, "aws_iam_role.orders_task")
        statements = tuple(role.policy_statements)
        role.policy_statements = tuple(s for s in statements if not any(a.startswith("s3:") for a in s.actions)) + (
            parse_policy_statement(
                _statement("Allow", "s3:GetObject", "*", condition={"Bool": {"aws:SecureTransport": "true"}})
            ),
        )
        result = collect_s3_operation_gaps(inventory)
        self.assertIn(S3_PROTECTED_DATA, {g.family for g in result.records})
        self.assertEqual({g.operation for g in result.records if g.family == S3_PROTECTED_DATA}, {"s3:GetObject"})
        role.policy_statements = statements
        self.assertEqual(collect_s3_operation_gaps(inventory).records, ())

    def test_plan_analysis_connects_gaps_with_zero_findings_and_complete_references(self):
        resources = _resources(actions="s3:PutObject")
        role = next(r for r in resources if r.resource_type == "aws_iam_role")
        role.values["permissions_boundary"] = "arn:aws:iam::111122223333:policy/boundary"
        plan = {
            "terraform_version": "1.9.0",
            "planned_values": {
                "root_module": {
                    "resources": [
                        {
                            "address": r.address,
                            "type": r.resource_type,
                            "name": r.name,
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": r.values,
                        }
                        for r in resources
                    ]
                }
            },
        }
        with TemporaryDirectory() as temp:
            path = Path(temp) / "plan.json"
            path.write_text(json.dumps(plan))
            engine = TfStride(rule_policy=RulePolicy(enabled_rule_ids=frozenset()))
            result = engine.analyze_plan(path)
            self.assertEqual(result.findings, [])
            self.assertEqual(result.analysis_coverage.references.unresolved_reference_count, 0)
            self.assertTrue(result.operation_gaps.records)
            self.assertEqual(set(result.operation_gaps.reporting_families), set(S3_GAP_FAMILIES))
            disabled = TfStride(provider_operation_gap_factories={}).analyze_plan(path)
            self.assertEqual(disabled.operation_gaps.reporting_families, ())

    def test_bucket_policy_constraints_have_current_source_and_operation_provenance(self):
        resources = _resources()
        resources.append(_bucket_policy([_bucket_statement("Allow", "s3:GetObject", "*", _TASK_ROLE_ARN)]))
        inventory = AwsNormalizer().normalize(resources)
        policy = _resource(inventory, "aws_s3_bucket_policy.orders")
        self.assertEqual(collect_s3_operation_gaps(inventory).records, ())
        statements = [
            _bucket_statement(
                "Deny",
                "s3:DeleteObject",
                f"{_BUCKET_ARN}/*",
                _TASK_ROLE_ARN,
                condition={"Bool": {"aws:SecureTransport": "SECRET-SENTINEL"}},
            )
        ]
        policy.policy_statements = tuple(parse_policy_statement(s) for s in statements)
        aws_facts(policy).set(AwsResourceMetadata.POLICY_DOCUMENT, {"Statement": statements})
        result = collect_s3_operation_gaps(inventory)
        self.assertEqual({g.family for g in result.records}, {S3_ACCESS, S3_OBJECT_DELETION})
        self.assertEqual({g.operation for g in result.records}, {"s3:DeleteObject"})
        self.assertTrue(all(policy.address in {p.resource_address for p in g.provenance} for g in result.records))
        self.assertNotIn("SECRET-SENTINEL", repr(result))

    def test_unknown_bucket_policy_constrains_all_relevant_families(self):
        inventory = AwsNormalizer().normalize(_resources())
        bucket = _resource(inventory, "aws_s3_bucket.orders")
        facts = aws_facts(bucket)
        facts.set(AwsResourceMetadata.S3_BUCKET_POLICY_STATE, "unknown")
        facts.set(AwsResourceMetadata.S3_BUCKET_POLICY_COMPLETENESS_STATE, "unknown")
        result = collect_s3_operation_gaps(inventory)
        self.assertEqual(
            {g.family for g in result.records}, {S3_ACCESS, S3_MUTATION, S3_OBJECT_DELETION, S3_BUCKET_TOPOLOGY}
        )
        self.assertTrue(all(g.reason_code == "bucket_policy_incomplete" for g in result.records))
        facts.set(AwsResourceMetadata.S3_BUCKET_POLICY_STATE, "not_configured")
        self.assertEqual(collect_s3_operation_gaps(inventory).records, ())

    def test_denied_grants_do_not_become_boundary_or_principal_gaps(self):
        for source in ("identity", "bucket"):
            with self.subTest(source=source):
                inventory = AwsNormalizer().normalize(_resources())
                role = _resource(inventory, "aws_iam_role.orders_task")
                aws_facts(role).set(AwsResourceMetadata.IAM_PERMISSIONS_BOUNDARY_STATE, "configured")
                _replace_role_policy(
                    inventory, [_statement("Allow", _OPERATIONS, "*"), _statement("Deny", _OPERATIONS, "*")]
                )
                self.assertEqual(collect_s3_operation_gaps(inventory).records, ())
                if source == "bucket":
                    resources = _resources(actions="s3:GetObject")
                    resources.append(
                        _bucket_policy(
                            [
                                _bucket_statement("Allow", ["s3:DeleteObject", "s3:DeleteBucket"], "*", "*"),
                                _bucket_statement("Deny", ["s3:DeleteObject", "s3:DeleteBucket"], "*", _TASK_ROLE_ARN),
                            ]
                        )
                    )
                    self.assertEqual(collect_s3_operation_gaps(AwsNormalizer().normalize(resources)).records, ())

    def test_conditional_deny_without_an_allow_is_not_an_unassessed_operation(self):
        inventory = AwsNormalizer().normalize(_resources())
        _replace_role_policy(
            inventory, [_statement("Deny", _OPERATIONS, "*", condition={"Bool": {"aws:SecureTransport": "false"}})]
        )
        self.assertEqual(collect_s3_operation_gaps(inventory).records, ())

    def test_cross_account_missing_grants_are_non_grants_and_conditions_are_gaps(self):
        from tests.providers.aws.test_aws_s3_broad_grants import _FOREIGN_ROLE

        for resource, condition, expected in (
            (f"{_BUCKET_ARN}/private/*", None, False),
            (f"{_BUCKET_ARN}/public/*", {"Bool": {"aws:SecureTransport": "true"}}, True),
        ):
            with self.subTest(resource=resource):
                resources = _resources(
                    role_arn=_FOREIGN_ROLE,
                    resource=f"{_BUCKET_ARN}/public/*",
                    actions=["s3:PutObject", "s3:DeleteObject"],
                )
                resources.append(
                    _bucket_policy([_bucket_statement("Allow", "s3:*", resource, _FOREIGN_ROLE, condition=condition)])
                )
                result = collect_s3_operation_gaps(AwsNormalizer().normalize(resources))
                self.assertEqual(bool(result.records), expected)
                if expected:
                    self.assertEqual({g.scope for g in result.records}, {f"{_BUCKET_ARN}/public/*"})
                    self.assertEqual({g.family for g in result.records}, {S3_ACCESS, S3_MUTATION, S3_OBJECT_DELETION})

    def test_resource_order_and_unrelated_resources_preserve_gap_results(self):
        from tests.providers.aws.test_aws_ecs_s3_access_paths import _task_definition

        resources = _resources(resource=f"{_BUCKET_ARN}/public/*", actions="s3:PutObject")
        resources[2] = _role(
            "orders_task",
            _TASK_ROLE_ARN,
            [
                _statement(
                    "Allow",
                    "s3:PutObject",
                    f"{_BUCKET_ARN}/public/*",
                    condition={"Bool": {"aws:SecureTransport": "true"}},
                )
            ],
        )
        expected = collect_s3_operation_gaps(AwsNormalizer().normalize(resources))
        unrelated = _task_definition(task_role_arn=None, execution_role_arn=None)
        unrelated.address = "aws_ecs_task_definition.unrelated"
        actual = collect_s3_operation_gaps(
            AwsNormalizer().normalize(
                [
                    *reversed(resources),
                    _bucket("unrelated", arn="arn:aws:s3:::unrelated"),
                    unrelated,
                ]
            )
        )
        self.assertEqual(actual, expected)

    def test_unsupported_scope_retains_modeled_target_without_copying_policy_variables(self):
        inventory = AwsNormalizer().normalize(
            _resources(resource=f"{_BUCKET_ARN}/public/*.json", actions="s3:DeleteObject")
        )
        result = collect_s3_operation_gaps(inventory)
        self.assertEqual({g.family for g in result.records}, {S3_ACCESS, S3_OBJECT_DELETION})
        self.assertTrue(all(g.target_address == "aws_s3_bucket.orders" and g.scope is None for g in result.records))
        self.assertTrue(all(g.reason_code == "resource_scope_unsupported" for g in result.records))

    def test_kms_dependency_gaps_recompute_current_target_resolution(self):
        inventory = AwsNormalizer().normalize(_aws_resources())
        self.assertEqual(collect_s3_operation_gaps(inventory).records, ())
        bucket = _resource(inventory, "aws_s3_bucket.orders")
        facts = aws_facts(bucket)
        old_key = facts.s3_kms_master_key_id
        facts.set(AwsResourceMetadata.S3_KMS_MASTER_KEY_ID, "arn:aws:kms:us-east-1:111122223333:key/missing")
        result = collect_s3_operation_gaps(inventory)
        self.assertTrue(result.records)
        self.assertEqual({g.family for g in result.records}, {S3_PROTECTED_DATA})
        self.assertEqual({g.reason_code for g in result.records}, {"encryption_dependency_unresolved"})
        facts.set(AwsResourceMetadata.S3_KMS_MASTER_KEY_ID, old_key)
        self.assertEqual(collect_s3_operation_gaps(inventory).records, ())

    def test_native_bucket_grants_report_ambiguous_targets_and_unsupported_principals(self):
        for ambiguous in (False, True):
            with self.subTest(ambiguous=ambiguous):
                resources = _resources()
                resources[2] = _role("orders_task", _TASK_ROLE_ARN)
                resources.append(
                    _bucket_policy(
                        [
                            _bucket_statement(
                                "Allow",
                                ["s3:DeleteObject", "s3:DeleteBucket"],
                                "*",
                                _TASK_ROLE_ARN if ambiguous else "*",
                            )
                        ]
                    )
                )
                if ambiguous:
                    resources.append(_bucket("duplicate", arn=_BUCKET_ARN))
                result = collect_s3_operation_gaps(AwsNormalizer().normalize(resources))
                self.assertEqual({g.family for g in result.records}, {S3_OBJECT_DELETION, S3_BUCKET_TOPOLOGY})
                self.assertEqual(
                    {g.reason_code for g in result.records},
                    {"target_ambiguous" if ambiguous else "principal_scope_unsupported"},
                )

    def test_known_cross_account_non_grant_does_not_generate_boundary_gaps(self):
        from tests.providers.aws.test_aws_s3_broad_grants import _FOREIGN_ROLE

        inventory = AwsNormalizer().normalize(_resources(role_arn=_FOREIGN_ROLE, actions="s3:PutObject"))
        facts = aws_facts(_resource(inventory, "aws_iam_role.orders_task"))
        facts.set(AwsResourceMetadata.IAM_PERMISSIONS_BOUNDARY_STATE, "configured")
        facts.set(AwsResourceMetadata.IAM_PERMISSIONS_BOUNDARY_ARN, "arn:aws:iam::444455556666:policy/boundary")
        self.assertEqual(collect_s3_operation_gaps(inventory).records, ())

    def test_runtime_role_ambiguity_does_not_borrow_another_identity(self):
        resources = [*_resources(), _role("duplicate", _TASK_ROLE_ARN)]
        result = collect_s3_operation_gaps(AwsNormalizer().normalize(resources))
        self.assertEqual({g.reason_code for g in result.records}, {"runtime_identity_ambiguous"})
        self.assertTrue(
            all(g.operation is None and g.scope is None and g.target_address is None for g in result.records)
        )

    def test_out_of_plan_targets_are_not_materialized_by_gap_reporting(self):
        for resource in ("arn:aws:s3:::absent/*", "arn:aws:s3:::absent-*/*"):
            with self.subTest(resource=resource):
                inventory = AwsNormalizer().normalize(_resources(resource=resource, actions="s3:PutObject"))
                addresses = tuple(r.address for r in inventory.resources)
                result = collect_s3_operation_gaps(inventory)
                self.assertEqual({g.reason_code for g in result.records}, {"target_not_modeled"})
                self.assertEqual({g.family for g in result.records}, {S3_ACCESS, S3_MUTATION})
                self.assertTrue(all(g.target_address is None and g.scope is None for g in result.records))
                self.assertEqual(tuple(r.address for r in inventory.resources), addresses)

    def test_out_of_plan_allow_is_quiet_when_a_known_deny_covers_its_operation_and_scope(self):
        target = "arn:aws:s3:::absent/public/*"
        for denied_action, denied_resource, expected in (
            ("s3:PutObject", "*", False),
            ("s3:PutObject", "arn:aws:s3:::absent/*", False),
            ("s3:GetObject", "*", True),
            ("s3:PutObject", "arn:aws:s3:::other/*", True),
        ):
            with self.subTest(action=denied_action, resource=denied_resource):
                resources = _resources(resource=target, actions="s3:PutObject")
                resources[2] = _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement("Allow", "s3:PutObject", target),
                        _statement("Deny", denied_action, denied_resource),
                    ],
                )
                gaps = collect_s3_operation_gaps(AwsNormalizer().normalize(resources)).records
                self.assertEqual(bool(gaps), expected)
                if expected:
                    self.assertEqual({gap.reason_code for gap in gaps}, {"target_not_modeled"})

    def test_unresolved_bucket_identity_is_quiet_under_a_global_deny(self):
        inventory = AwsNormalizer().normalize(_resources(actions="s3:PutObject", resource="*"))
        inventory = inventory_with_updated_identity(inventory, _resource(inventory, "aws_s3_bucket.orders"), arn=None)
        self.assertEqual(
            {gap.reason_code for gap in collect_s3_operation_gaps(inventory).records}, {"target_arn_unresolved"}
        )
        _replace_role_policy(
            inventory,
            [_statement("Allow", "s3:PutObject", "*"), _statement("Deny", "s3:PutObject", "*")],
        )
        self.assertEqual(collect_s3_operation_gaps(inventory).records, ())

    def test_unsupported_object_allow_is_quiet_under_a_known_deny(self):
        target = f"{_BUCKET_ARN}/public/*.json"
        for denied_resource, expected in (
            ("*", False),
            (f"{_BUCKET_ARN}/public/*", False),
            (f"{_BUCKET_ARN}/private/*", True),
        ):
            with self.subTest(deny=denied_resource):
                resources = _resources(resource=target, actions="s3:DeleteObject")
                resources[2] = _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement("Allow", "s3:DeleteObject", target),
                        _statement("Deny", "s3:DeleteObject", denied_resource),
                    ],
                )
                gaps = collect_s3_operation_gaps(AwsNormalizer().normalize(resources)).records
                self.assertEqual(bool(gaps), expected)
                if expected:
                    self.assertEqual({gap.reason_code for gap in gaps}, {"resource_scope_unsupported"})

    def test_unresolved_policy_allow_is_quiet_when_a_known_deny_dominates_deletion_and_topology(self):
        operations = ["s3:DeleteObject", "s3:DeleteBucket"]
        for deny_source in ("identity", "bucket"):
            with self.subTest(deny_source=deny_source):
                resources = _resources(actions="s3:GetObject")
                resources[2] = _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [_statement("Deny", operations if deny_source == "identity" else "s3:GetObject", "*")],
                )
                if deny_source == "bucket":
                    resources.append(_bucket_policy([_bucket_statement("Deny", operations, "*", _TASK_ROLE_ARN)]))
                resources.append(
                    _unresolved_bucket_policy("unknown", [_bucket_statement("Allow", operations, "*", _TASK_ROLE_ARN)])
                )
                gaps = collect_s3_operation_gaps(AwsNormalizer().normalize(resources)).records
                self.assertFalse([gap for gap in gaps if gap.family in {S3_OBJECT_DELETION, S3_BUCKET_TOPOLOGY}])

    def test_unrelated_bucket_policy_deny_does_not_suppress_unresolved_source(self):
        resources = _resources(actions="s3:GetObject")
        resources[2] = _role("orders_task", _TASK_ROLE_ARN, [_statement("Deny", "s3:GetObject", "*")])
        resources.append(
            _bucket_policy(
                [
                    _bucket_statement(
                        "Deny", ["s3:DeleteObject", "s3:DeleteBucket"], "*", "arn:aws:iam::444455556666:role/other"
                    )
                ]
            )
        )
        resources.append(
            _unresolved_bucket_policy(
                "unknown",
                [_bucket_statement("Allow", ["s3:DeleteObject", "s3:DeleteBucket"], "*", _TASK_ROLE_ARN)],
            )
        )
        gaps = collect_s3_operation_gaps(AwsNormalizer().normalize(resources)).records
        self.assertEqual({gap.family for gap in gaps}, {S3_OBJECT_DELETION, S3_BUCKET_TOPOLOGY})
        self.assertEqual({gap.reason_code for gap in gaps}, {"bucket_policy_target_unresolved"})
