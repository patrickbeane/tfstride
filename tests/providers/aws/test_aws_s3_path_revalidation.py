from __future__ import annotations

import unittest
from copy import deepcopy

from tests.helpers.inventory import inventory_with_updated_identity
from tests.providers.aws.test_aws_ecs_s3_access_paths import _BUCKET_ARN, _statement
from tests.providers.aws.test_aws_ecs_s3_object_deletion_paths import _bucket_policy, _bucket_statement
from tests.providers.aws.test_aws_public_ecs_kms_rules import _evaluate_inventory as _evaluate_kms
from tests.providers.aws.test_aws_public_ecs_s3_mutation_rules import _load_balancer_path
from tests.providers.aws.test_aws_public_ecs_s3_mutation_rules import _service as _public_service
from tests.providers.aws.test_aws_s3_broad_grants import _FOREIGN_ROLE, _OPERATIONS, _resources
from tests.providers.test_protected_data_key_authority_convergence import _AWS_BUCKET_ARN, _aws_resources
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.policy_documents import parse_policy_statement
from tfstride.providers.aws.resource_decoration.ecs_s3_access_paths import current_ecs_s3_access_path
from tfstride.providers.aws.resource_decoration.ecs_s3_protected_data_convergence import (
    ModelEcsS3ProtectedDataConvergenceStage,
)
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import AwsDecorationContext, AwsResourceIndexBuilder

_MUTATION = "aws-public-ecs-s3-mutation-access"
_DELETION = "aws-public-ecs-s3-object-disruption"
_TOPOLOGY = "aws-public-ecs-s3-bucket-topology-disruption"
_RULES = frozenset({_MUTATION, _DELETION, _TOPOLOGY})


def _inventory(resource="*", actions=_OPERATIONS, *, foreign=False):
    kwargs = {"role_arn": _FOREIGN_ROLE} if foreign else {}
    resources = _resources(resource=resource, actions=actions, **kwargs)
    resources[-1] = _public_service()
    resources.extend(_load_balancer_path())
    if foreign:
        resources.append(_bucket_policy([_bucket_statement("Allow", actions, resource, _FOREIGN_ROLE)]))
    return AwsNormalizer().normalize(resources)


def _resource(inventory, address):
    resource = inventory.get_by_address(address)
    assert resource is not None
    return resource


def _role(inventory):
    return _resource(inventory, "aws_iam_role.orders_task")


def _service(inventory):
    return _resource(inventory, "aws_ecs_service.orders")


def _replace_policy(inventory, actions, resource="*", *, denies=()):
    _role(inventory).policy_statements = tuple(
        parse_policy_statement(statement) for statement in [_statement("Allow", actions, resource), *denies]
    )


def _evaluate(inventory):
    return StrideRuleEngine().evaluate(
        inventory,
        detect_trust_boundaries(inventory),
        rule_policy=RulePolicy(enabled_rule_ids=_RULES),
    )


def _evidence(finding, key):
    return next(item.values for item in finding.evidence if item.key == key)


def _context(inventory):
    return AwsDecorationContext(AwsResourceIndexBuilder().build(list(inventory.resources)))


class AwsS3PathRevalidationTests(unittest.TestCase):
    def test_each_consumer_requires_its_current_operation(self):
        for action, expected in (
            ("s3:GetObject", set()),
            ("s3:PutObject", {_MUTATION}),
            ("s3:DeleteObject", {_DELETION}),
            ("s3:DeleteObjectVersion", {_DELETION}),
            ("s3:DeleteBucket", {_TOPOLOGY}),
            ("s3:DeleteBucketPolicy", set()),
        ):
            with self.subTest(action=action):
                inventory = _inventory()
                self.assertEqual({f.rule_id for f in _evaluate(inventory)}, _RULES)
                _replace_policy(inventory, action)
                findings = _evaluate(inventory)
                self.assertEqual({f.rule_id for f in findings}, expected)
                if expected == {_DELETION}:
                    paths = _evidence(findings[0], "s3_object_deletion_paths")
                    self.assertEqual(len(paths), 1)
                    self.assertIn(f"operation={action};", paths[0])

    def test_revalidation_does_not_add_operations_from_current_broad_grants(self):
        inventory = _inventory(actions="s3:PutObject")
        _replace_policy(inventory, "s3:*")
        findings = _evaluate(inventory)
        self.assertEqual([f.rule_id for f in findings], [_MUTATION])
        self.assertIn("actions=s3:PutObject;", _evidence(findings[0], "s3_mutation_paths")[0])

    def test_object_scope_intersections_in_both_directions_and_disjoint_scopes(self):
        for cached, current, expected in (
            ("public/*", "*", "public/*"),
            ("*", "public/*", "public/*"),
            ("public/*", "public/item", "public/item"),
            ("public/item", "public/*", "public/item"),
            ("public/*", "private/*", None),
            ("public/item", "public/other", None),
        ):
            with self.subTest(cached=cached, current=current):
                inventory = _inventory(resource=f"{_BUCKET_ARN}/{cached}")
                _replace_policy(inventory, _OPERATIONS, f"{_BUCKET_ARN}/{current}")
                findings = _evaluate(inventory)
                if expected is None:
                    self.assertEqual(findings, [])
                    continue
                self.assertEqual({f.rule_id for f in findings}, {_MUTATION, _DELETION})
                for finding in findings:
                    key = "s3_mutation_paths" if finding.rule_id == _MUTATION else "s3_object_deletion_paths"
                    for path in _evidence(finding, key):
                        self.assertIn(f"{_BUCKET_ARN}/{expected}", path)
                        if key == "s3_object_deletion_paths":
                            self.assertIn(f"target_scope={_BUCKET_ARN}/{expected};", path)
                        else:
                            self.assertIn(f"authorized_scopes=s3:PutObject on {_BUCKET_ARN}/{expected};", path)

    def test_cached_scope_is_applied_before_current_denies(self):
        for source in ("identity", "bucket"):
            for denied, survives in (("private/*", True), ("public/*", False), ("public/secret/*", False)):
                with self.subTest(source=source, denied=denied):
                    inventory = _inventory(resource=f"{_BUCKET_ARN}/public/*", foreign=source == "bucket")
                    deny = _statement("Deny", "s3:*", f"{_BUCKET_ARN}/{denied}")
                    _replace_policy(inventory, "s3:*", denies=[deny] if source == "identity" else [])
                    if source == "bucket":
                        policy = _resource(inventory, "aws_s3_bucket_policy.orders")
                        statements = [
                            _bucket_statement("Allow", "s3:*", "*", _FOREIGN_ROLE),
                            _bucket_statement("Deny", "s3:*", f"{_BUCKET_ARN}/{denied}", _FOREIGN_ROLE),
                        ]
                        policy.policy_statements = tuple(parse_policy_statement(s) for s in statements)
                        aws_facts(policy).set(AwsResourceMetadata.POLICY_DOCUMENT, {"Statement": statements})
                    findings = _evaluate(inventory)
                    self.assertEqual({f.rule_id for f in findings}, {_MUTATION, _DELETION} if survives else set())

    def test_added_constraints_and_changed_targets_invalidate_cached_authority(self):
        for gate in ("boundary", "identity_incomplete", "bucket_incomplete", "ownership", "role", "bucket_arn"):
            with self.subTest(gate=gate):
                inventory = _inventory()
                bucket = _resource(inventory, "aws_s3_bucket.orders")
                if gate == "boundary":
                    aws_facts(_role(inventory)).set(AwsResourceMetadata.IAM_PERMISSIONS_BOUNDARY_STATE, "configured")
                elif gate == "identity_incomplete":
                    aws_facts(_role(inventory)).set(AwsResourceMetadata.IAM_POLICY_COMPLETENESS_STATE, "unknown")
                elif gate == "bucket_incomplete":
                    aws_facts(bucket).set(AwsResourceMetadata.S3_BUCKET_POLICY_STATE, "unknown")
                    aws_facts(bucket).set(AwsResourceMetadata.S3_BUCKET_POLICY_COMPLETENESS_STATE, "unknown")
                elif gate == "ownership":
                    bucket.provider_config_key = "aws.unresolved"
                elif gate == "role":
                    inventory = inventory_with_updated_identity(inventory, _role(inventory), arn=_FOREIGN_ROLE)
                else:
                    inventory = inventory_with_updated_identity(inventory, bucket, arn="arn:aws:s3:::unrelated")
                self.assertEqual(_evaluate(inventory), [])

    def test_cross_account_grants_must_still_cover_cached_operation_and_scope(self):
        for actions, resource in (("s3:GetObject", "*"), ("s3:*", f"{_BUCKET_ARN}/private/*")):
            with self.subTest(actions=actions, resource=resource):
                inventory = _inventory(resource=f"{_BUCKET_ARN}/public/*", foreign=True)
                self.assertEqual({f.rule_id for f in _evaluate(inventory)}, {_MUTATION, _DELETION})
                policy = _resource(inventory, "aws_s3_bucket_policy.orders")
                policy.policy_statements = (
                    parse_policy_statement(_bucket_statement("Allow", actions, resource, _FOREIGN_ROLE)),
                )
                self.assertEqual(_evaluate(inventory), [])

    def test_denied_or_unknown_cached_scopes_are_not_restored(self):
        for state in ("denied", "unknown"):
            with self.subTest(state=state):
                inventory = _inventory(actions="s3:PutObject")
                path = aws_facts(_service(inventory)).ecs_s3_access_paths[0]
                path["scope_evaluations"][0]["modeled_access_state"] = state
                aws_facts(_service(inventory)).set_ecs_s3_access_paths([path])
                self.assertEqual(_evaluate(inventory), [])

    def test_unrelated_allowed_action_cannot_cover_a_revoked_scope_pair(self):
        inventory = _inventory(actions=["s3:GetObject", "s3:PutObject"], resource=f"{_BUCKET_ARN}/public/*")
        _role(inventory).policy_statements = tuple(
            parse_policy_statement(s)
            for s in (
                _statement("Allow", "s3:GetObject", f"{_BUCKET_ARN}/public/*"),
                _statement("Allow", "s3:PutObject", f"{_BUCKET_ARN}/private/*"),
            )
        )
        self.assertEqual(_evaluate(inventory), [])

    def test_topology_cached_statement_must_still_describe_delete_bucket_target(self):
        for changes in (
            {"actions": ["s3:DeleteBucketPolicy"], "matching_action_patterns": ["s3:DeleteBucketPolicy"]},
            {"matched_actions": ["s3:DeleteObject"]},
            {"resources": [f"{_BUCKET_ARN}/*"], "matching_resources": [f"{_BUCKET_ARN}/*"]},
            {"resources": ["arn:aws:s3:::unrelated"], "matching_resources": ["arn:aws:s3:::unrelated"]},
            {"conditional": True},
        ):
            with self.subTest(changes=changes):
                inventory = _inventory(actions="s3:DeleteBucket")
                path = aws_facts(_service(inventory)).ecs_s3_bucket_topology_destruction_paths[0]
                path["authorization_statements"][0].update(changes)
                aws_facts(_service(inventory)).set_ecs_s3_bucket_topology_destruction_paths([path])
                self.assertEqual(_evaluate(inventory), [])

    def test_cached_concrete_object_version_is_not_promoted_to_all_versions(self):
        inventory = _inventory(actions="s3:DeleteObjectVersion", resource=f"{_BUCKET_ARN}/item")
        path = aws_facts(_service(inventory)).ecs_s3_object_deletion_paths[0]
        path.update(target_granularity="object_version", object_version="version-1")
        aws_facts(_service(inventory)).set_ecs_s3_object_deletion_paths([path])
        self.assertEqual(_evaluate(inventory), [])

    def test_refreshed_access_evidence_contains_only_the_surviving_scope(self):
        inventory = _inventory(actions="s3:PutObject", resource=f"{_BUCKET_ARN}/public/*")
        cached = aws_facts(_service(inventory)).ecs_s3_access_paths[0]
        original = deepcopy(cached)
        _replace_policy(inventory, "s3:*", "*")
        current = current_ecs_s3_access_path(cached, _service(inventory), _context(inventory))
        assert current is not None
        self.assertEqual(current["matched_actions"], ["s3:PutObject"])
        self.assertEqual(current["resource_scopes"], ["object_prefix"])
        self.assertEqual({s["resource"] for s in current["scope_evaluations"]}, {f"{_BUCKET_ARN}/public/*"})
        self.assertEqual(cached, original)

    def test_protected_data_convergence_requires_current_payload_read(self):
        for replacement in ("s3:PutObject", "s3:GetObjectVersion"):
            with self.subTest(replacement=replacement):
                inventory = AwsNormalizer().normalize(_aws_resources())
                self.assertTrue(aws_facts(_service(inventory)).ecs_s3_protected_data_convergences)
                role = _role(inventory)
                role.policy_statements = tuple(
                    s for s in role.policy_statements if not any(a.startswith("s3:") for a in s.actions)
                ) + (parse_policy_statement(_statement("Allow", replacement, f"{_AWS_BUCKET_ARN}/*")),)
                _, _, findings = _evaluate_kms(inventory)
                self.assertEqual(len(findings), 1)
                self.assertNotIn("aws_s3_bucket.orders", findings[0].affected_resources)
                ModelEcsS3ProtectedDataConvergenceStage().apply(list(inventory.resources), _context(inventory))
                self.assertEqual(aws_facts(_service(inventory)).ecs_s3_protected_data_convergences, [])

    def test_applicable_denies_remain_specific_to_the_requested_operation(self):
        for conditional in (False, True):
            with self.subTest(conditional=conditional):
                inventory = _inventory(resource=f"{_BUCKET_ARN}/public/*")
                condition = {"Bool": {"aws:SecureTransport": "false"}} if conditional else None
                _replace_policy(
                    inventory,
                    "s3:*",
                    denies=[
                        _statement("Deny", "s3:PutObject", f"{_BUCKET_ARN}/public/*", condition=condition),
                    ],
                )
                findings = _evaluate(inventory)
                self.assertEqual([f.rule_id for f in findings], [_DELETION])
                self.assertEqual(len(_evidence(findings[0], "s3_object_deletion_paths")), 2)

    def test_current_cross_account_prefix_narrows_cached_namespace(self):
        inventory = _inventory(foreign=True)
        policy = _resource(inventory, "aws_s3_bucket_policy.orders")
        statements = [_bucket_statement("Allow", _OPERATIONS, f"{_BUCKET_ARN}/public/*", _FOREIGN_ROLE)]
        policy.policy_statements = tuple(parse_policy_statement(s) for s in statements)
        aws_facts(policy).set(AwsResourceMetadata.POLICY_DOCUMENT, {"Statement": statements})
        findings = _evaluate(inventory)
        self.assertEqual({f.rule_id for f in findings}, {_MUTATION, _DELETION})
        for finding in findings:
            key = "s3_mutation_paths" if finding.rule_id == _MUTATION else "s3_object_deletion_paths"
            for path in _evidence(finding, key):
                self.assertIn(f"{_BUCKET_ARN}/public/*", path)

    def test_governance_bypass_recovery_stays_within_deletion_scope(self):
        for bypass_scope, expected in (("public/*", "true"), ("private/*", "false")):
            with self.subTest(bypass_scope=bypass_scope):
                inventory = _inventory(actions="s3:DeleteObjectVersion", resource=f"{_BUCKET_ARN}/public/*")
                _role(inventory).policy_statements = tuple(
                    parse_policy_statement(s)
                    for s in (
                        _statement("Allow", "s3:DeleteObjectVersion", "*"),
                        _statement("Allow", "s3:BypassGovernanceRetention", f"{_BUCKET_ARN}/{bypass_scope}"),
                    )
                )
                findings = _evaluate(inventory)
                self.assertEqual([f.rule_id for f in findings], [_DELETION])
                self.assertIn(
                    f"governance_bypass_authorized={expected};", _evidence(findings[0], "recovery_evidence")[0]
                )

    def test_protected_data_convergence_retains_its_cached_read_prefix(self):
        for current_scope, survives in (("*", True), ("private/*", False)):
            with self.subTest(current_scope=current_scope):
                inventory = AwsNormalizer().normalize(_aws_resources())
                role = _role(inventory)
                other_statements = tuple(
                    s for s in role.policy_statements if not any(a.startswith("s3:") for a in s.actions)
                )
                role.policy_statements = (
                    *other_statements,
                    parse_policy_statement(_statement("Allow", "s3:GetObject", f"{_AWS_BUCKET_ARN}/public/*")),
                )
                ModelEcsS3ProtectedDataConvergenceStage().apply(list(inventory.resources), _context(inventory))
                self.assertTrue(aws_facts(_service(inventory)).ecs_s3_protected_data_convergences)
                role.policy_statements = (
                    *other_statements,
                    parse_policy_statement(_statement("Allow", "s3:*", f"{_AWS_BUCKET_ARN}/{current_scope}")),
                )
                _, _, findings = _evaluate_kms(inventory)
                self.assertEqual(len(findings), 1)
                self.assertEqual("aws_s3_bucket.orders" in findings[0].affected_resources, survives)
                # Reproject with the same cached prefix to inspect the refreshed proof.
                convergence = aws_facts(_service(inventory)).ecs_s3_protected_data_convergences[0]
                aws_facts(_service(inventory)).set_ecs_s3_access_paths([convergence["access_path"]])
                ModelEcsS3ProtectedDataConvergenceStage().apply(list(inventory.resources), _context(inventory))
                current = aws_facts(_service(inventory)).ecs_s3_protected_data_convergences
                self.assertEqual(bool(current), survives)
                if survives:
                    self.assertEqual(current[0]["access_path"]["matched_actions"], ["s3:GetObject"])
                    self.assertEqual(
                        {s["resource"] for s in current[0]["access_path"]["scope_evaluations"]},
                        {f"{_AWS_BUCKET_ARN}/public/*"},
                    )
