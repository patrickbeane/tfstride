from __future__ import annotations

import unittest
from itertools import permutations

from tests.helpers.paths import FIXTURES_DIR
from tfstride.analysis.rule_helpers import subnet_posture
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.app import TfStride
from tfstride.models import NormalizedResource, ResourceCategory, ResourceInventory, TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_index import AwsResourceIndexBuilder

_SUBNET_ID = "subnet-00000001"


def _subnet(name: str, scope: str | None, *, public: bool) -> NormalizedResource:
    subnet = NormalizedResource(
        address=f"aws_subnet.{name}",
        provider="aws",
        resource_type="aws_subnet",
        name=name,
        category=ResourceCategory.NETWORK,
        identifier=_SUBNET_ID,
        provider_config_key=scope,
        arn=f"arn:aws:ec2:us-east-1:{'111122223333' if scope == 'aws.local' else '444455556666'}:subnet/{_SUBNET_ID}",
    )
    subnet.is_public_subnet = public
    subnet.has_public_route = public
    subnet.has_nat_gateway_egress = not public
    return subnet


def _workload(scope: str | None = "aws.local", *references: str) -> NormalizedResource:
    return NormalizedResource(
        address="aws_instance.app",
        provider="aws",
        resource_type="aws_instance",
        name="app",
        category=ResourceCategory.COMPUTE,
        provider_config_key=scope,
        subnet_ids=tuple(references or (_SUBNET_ID,)),
    )


def _posture(source: NormalizedResource | None, resources: list[NormalizedResource]) -> list[str]:
    return subnet_posture(source, AwsResourceIndexBuilder().build(resources).resolve_subnet)


class SubnetPostureTests(unittest.TestCase):
    def test_colliding_identifiers_use_the_workloads_provider_configuration(self) -> None:
        public = _subnet("foreign", "aws.foreign", public=True)
        private = _subnet("local", "aws.local", public=False)
        source = _workload()
        for order in permutations([public, private, source]):
            self.assertEqual(
                _posture(source, list(order)),
                ["aws_instance.app sits in private subnet aws_subnet.local with NAT-backed egress"],
            )

    def test_same_scope_collision_preserves_candidates_without_claiming_posture(self) -> None:
        source = _workload()
        source.in_public_subnet = True
        resources = [source, _subnet("first", "aws.local", public=True), _subnet("second", "aws.local", public=False)]
        expected = [
            "aws_instance.app subnet reference subnet-00000001 is ambiguous in its source context "
            "(candidates: aws_subnet.first, aws_subnet.second); subnet posture is unknown"
        ]
        for order in permutations(resources):
            self.assertEqual(_posture(source, list(order)), expected)

    def test_strong_references_cross_configurations_despite_colliding_local_ids(self) -> None:
        remote = _subnet("remote", "aws.foreign", public=True)
        local = _subnet("local", "aws.local", public=False)
        assert remote.arn is not None
        for reference in (remote.address, f"{remote.address}.id", f"{remote.address}.arn", remote.arn):
            with self.subTest(reference=reference):
                source = _workload("aws.local", reference)
                for order in permutations([source, remote, local]):
                    self.assertEqual(
                        _posture(source, list(order)),
                        ["aws_instance.app sits in public subnet aws_subnet.remote with an internet route"],
                    )

    def test_unknown_scope_does_not_turn_a_unique_weak_reference_into_membership(self) -> None:
        source = _workload(None)
        source.in_public_subnet = True
        for target_scope in (None, "aws.local"):
            with self.subTest(target_scope=target_scope):
                evidence = _posture(source, [source, _subnet("candidate", target_scope, public=True)])
                self.assertEqual(
                    evidence,
                    [
                        "aws_instance.app subnet reference subnet-00000001 is unresolved in its source context; subnet posture is unknown"
                    ],
                )

    def test_exact_reference_can_resolve_with_unknown_source_scope(self) -> None:
        target = _subnet("remote", "aws.foreign", public=True)
        source = _workload(None, target.address)
        self.assertEqual(
            _posture(source, [target, source]),
            ["aws_instance.app sits in public subnet aws_subnet.remote with an internet route"],
        )

    def test_type_constraint_applies_before_candidate_selection(self) -> None:
        source = _workload()
        target = _subnet("local", "aws.local", public=False)
        wrong_type = NormalizedResource(
            address="aws_security_group.wrong",
            provider="aws",
            resource_type="aws_security_group",
            name="wrong",
            category=ResourceCategory.NETWORK,
            identifier=_SUBNET_ID,
            provider_config_key="aws.local",
        )
        for order in permutations([source, target, wrong_type]):
            self.assertEqual(
                _posture(source, list(order)),
                ["aws_instance.app sits in private subnet aws_subnet.local with NAT-backed egress"],
            )
        for reference in (_SUBNET_ID, wrong_type.address):
            source.subnet_ids = (reference,)
            self.assertIn("unresolved", _posture(source, [source, wrong_type])[0])

    def test_unresolved_references_are_not_replaced_by_aggregate_public_posture(self) -> None:
        source = _workload("aws.local", "subnet-missing")
        source.in_public_subnet = True
        self.assertEqual(
            _posture(source, [source]),
            [
                "aws_instance.app subnet reference subnet-missing is unresolved in its source context; subnet posture is unknown"
            ],
        )

    def test_reference_order_and_duplicate_aliases_do_not_change_evidence(self) -> None:
        target = _subnet("local", "aws.local", public=False)
        for references in permutations((_SUBNET_ID, target.address, "subnet-missing")):
            source = _workload("aws.local", *references)
            evidence = _posture(source, [target, source])
            self.assertEqual(
                evidence,
                [
                    "aws_instance.app sits in private subnet aws_subnet.local with NAT-backed egress",
                    "aws_instance.app subnet reference subnet-missing is unresolved in its source context; subnet posture is unknown",
                ],
            )

    def test_missing_resources_and_missing_references_remain_distinct(self) -> None:
        self.assertEqual(_posture(None, []), [])
        source = _workload()
        source.subnet_ids = ()
        self.assertEqual(_posture(source, [source]), [])
        source.in_public_subnet = True
        self.assertEqual(
            _posture(source, [source]),
            [
                "aws_instance.app is classified in a public subnet, but no subnet reference is available to verify membership"
            ],
        )

    def test_normalization_retains_subnet_arn_for_strong_resolution(self) -> None:
        arn = f"arn:aws:ec2:us-east-1:444455556666:subnet/{_SUBNET_ID}"
        raw = TerraformResource(
            address="aws_subnet.remote",
            mode="managed",
            resource_type="aws_subnet",
            name="remote",
            provider_name="registry.terraform.io/hashicorp/aws",
            provider_config_key="aws.foreign",
            values={"id": _SUBNET_ID, "arn": arn},
        )
        subnet = AwsNormalizer().normalize([raw]).resources[0]
        source = _workload("aws.local", arn)
        resolution = AwsResourceIndexBuilder().build([source, subnet]).resolve_subnet(arn, source=source)
        self.assertIs(resolution.selected_candidate, subnet)
        raw.unknown_values = {"arn": True, "id": True}
        unknown = AwsNormalizer().normalize([raw]).resources[0]
        self.assertIsNone(unknown.arn)
        self.assertIsNone(unknown.identifier)
        self.assertIn("unresolved", _posture(source, [source, unknown])[0])


class SubnetFindingEvidenceTests(unittest.TestCase):
    def test_all_subnet_evidence_consumers_name_the_local_subnet(self) -> None:
        scenarios = (
            (
                "sample_aws_plan.json",
                "aws_subnet.public_app",
                (
                    "aws-public-compute-broad-ingress",
                    "aws-database-permissive-ingress",
                    "aws-missing-tier-segmentation",
                ),
            ),
            ("sample_aws_alb_ec2_rds_plan.json", "aws_subnet.private_app", ("aws-private-data-transitive-exposure",)),
        )
        for fixture, subnet_address, rule_ids in scenarios:
            with self.subTest(fixture=fixture):
                result = TfStride().analyze_plan(FIXTURES_DIR / "aws" / fixture)
                subnet = result.inventory.get_by_address(subnet_address)
                assert subnet is not None
                foreign = _subnet("collision", "aws.foreign", public=not subnet.is_public_subnet)
                foreign.identifier = subnet.identifier
                policy = RulePolicy(enabled_rule_ids=frozenset(rule_ids))
                expected = StrideRuleEngine().evaluate(result.inventory, result.trust_boundaries, rule_policy=policy)
                self.assertEqual({finding.rule_id for finding in expected}, set(rule_ids))
                resources = [foreign, *result.inventory.resources]
                for order in (resources, list(reversed(resources))):
                    inventory = ResourceInventory(provider="aws", resources=order)
                    findings = StrideRuleEngine().evaluate(inventory, result.trust_boundaries, rule_policy=policy)
                    self.assertEqual(findings, expected)
                    for finding in findings:
                        evidence = next(item.values for item in finding.evidence if item.key == "subnet_posture")
                        self.assertTrue(any(subnet_address in value for value in evidence))
                        self.assertFalse(any(foreign.address in value for value in evidence))

    def test_ambiguous_and_unresolved_subnets_remain_uncertain_in_finding_evidence(self) -> None:
        result = TfStride().analyze_plan(FIXTURES_DIR / "aws" / "sample_aws_plan.json")
        target = result.inventory.get_by_address("aws_subnet.public_app")
        assert target is not None
        duplicate = _subnet("collision", target.provider_config_key, public=False)
        duplicate.identifier = target.identifier
        for state, resources in (
            ("ambiguous", [duplicate, *result.inventory.resources]),
            ("unresolved", [item for item in result.inventory.resources if item.address != target.address]),
        ):
            for order in (resources, list(reversed(resources))):
                with self.subTest(state=state):
                    findings = StrideRuleEngine().evaluate(
                        ResourceInventory(provider="aws", resources=order),
                        result.trust_boundaries,
                        rule_policy=RulePolicy(enabled_rule_ids=frozenset({"aws-public-compute-broad-ingress"})),
                    )
                    self.assertEqual(len(findings), 1)
                    evidence = next(item.values for item in findings[0].evidence if item.key == "subnet_posture")
                    self.assertEqual(len(evidence), 1)
                    self.assertIn(state, evidence[0])
                    self.assertIn("subnet posture is unknown", evidence[0])
                    self.assertNotIn("sits in", evidence[0])


if __name__ == "__main__":
    unittest.main()
