from __future__ import annotations

import re
import unittest

from tests.helpers.paths import SOURCE_ROOT
from tfstride.models import IAMPolicyStatement, NormalizedResource, ResourceCategory, SecurityGroupRule
from tfstride.providers.aws.resource_mutations import AwsResourceMutations, aws_mutations


def _resource(
    *,
    resource_type: str = "aws_instance",
    metadata: dict[str, object] | None = None,
    vpc_id: str | None = None,
    public_access_configured: bool = False,
) -> NormalizedResource:
    return NormalizedResource(
        address=f"{resource_type}.app",
        provider="aws",
        resource_type=resource_type,
        name="app",
        category=ResourceCategory.COMPUTE,
        metadata=metadata,
        vpc_id=vpc_id,
        public_access_configured=public_access_configured,
    )


class AwsResourceMutationsTests(unittest.TestCase):
    def test_mutation_facade_merges_resource_collections(self) -> None:
        resource = _resource()
        network_rule = SecurityGroupRule(
            direction="ingress",
            protocol="tcp",
            from_port=443,
            to_port=443,
            cidr_blocks=["0.0.0.0/0"],
        )
        policy_statement = IAMPolicyStatement(effect="Allow", actions=["s3:GetObject"])

        mutations = aws_mutations(resource)
        mutations.merge_security_group_rules([network_rule])
        mutations.merge_policy_statements([policy_statement])
        mutations.attach_role_arn("arn:aws:iam::111122223333:role/app")
        mutations.attach_role_arn("arn:aws:iam::111122223333:role/app")
        mutations.attach_role_arn(None)

        self.assertIsInstance(mutations, AwsResourceMutations)
        self.assertEqual(resource.network_rules, [network_rule])
        self.assertEqual(resource.policy_statements, [policy_statement])
        self.assertEqual(resource.attached_role_arns, ["arn:aws:iam::111122223333:role/app"])

    def test_vpc_inference_sets_only_missing_vpc_ids(self) -> None:
        resource = _resource()
        mutations = aws_mutations(resource)

        self.assertFalse(mutations.infer_vpc_id(None))
        self.assertTrue(mutations.infer_vpc_id("vpc-inferred"))
        self.assertFalse(mutations.infer_vpc_id("vpc-other"))
        self.assertEqual(resource.vpc_id, "vpc-inferred")

        existing = _resource(vpc_id="vpc-existing")
        self.assertFalse(aws_mutations(existing).infer_vpc_id("vpc-inferred"))
        self.assertEqual(existing.vpc_id, "vpc-existing")

    def test_subnet_posture_writes_flags_and_route_table_metadata(self) -> None:
        subnet = _resource(resource_type="aws_subnet")

        aws_mutations(subnet).set_subnet_posture(
            is_public=True,
            route_table_ids=("rtb-public",),
            has_public_route=True,
            has_nat_gateway_egress=False,
        )

        self.assertTrue(subnet.is_public_subnet)
        self.assertTrue(subnet.has_public_route)
        self.assertFalse(subnet.has_nat_gateway_egress)
        self.assertEqual(subnet.metadata["route_table_ids"], ["rtb-public"])

    def test_public_exposure_writes_normalized_posture_fields(self) -> None:
        resource = _resource(public_access_configured=True)
        mutations = aws_mutations(resource)

        mutations.ensure_public_reason_lists()
        mutations.sync_public_access_configured()
        mutations.set_internet_ingress(True, ["aws_security_group.app ingress tcp 443 from 0.0.0.0/0"])
        mutations.set_in_public_subnet(True)
        mutations.set_nat_gateway_egress(True)
        mutations.set_public_access_reasons(["instance requests a public IP"])
        mutations.set_publicly_accessible(True)
        mutations.set_storage_encrypted(True)
        mutations.set_public_exposure(True)
        mutations.set_public_exposure_reasons(["instance has a public IP path"])
        mutations.sync_direct_internet_reachable()

        self.assertEqual(resource.metadata["public_access_configured"], True)
        self.assertTrue(resource.internet_ingress_capable)
        self.assertEqual(
            resource.internet_ingress_reasons,
            ["aws_security_group.app ingress tcp 443 from 0.0.0.0/0"],
        )
        self.assertTrue(resource.in_public_subnet)
        self.assertTrue(resource.has_nat_gateway_egress)
        self.assertEqual(resource.public_access_reasons, ["instance requests a public IP"])
        self.assertTrue(resource.publicly_accessible)
        self.assertTrue(resource.storage_encrypted)
        self.assertTrue(resource.public_exposure)
        self.assertEqual(resource.public_exposure_reasons, ["instance has a public IP path"])
        self.assertTrue(resource.direct_internet_reachable)

    def test_aws_decoration_resource_mutations_are_centralized(self) -> None:
        stages_path = SOURCE_ROOT / "providers" / "aws" / "resource_decoration_stages.py"
        text = stages_path.read_text(encoding="utf-8")
        direct_mutation_patterns = (
            r"\.extend_network_rules\(",
            r"\.extend_policy_statements\(",
            r"\.add_attached_role_arn\(",
            r"\.\s*vpc_id\s*=",
            r"\.\s*is_public_subnet\s*=",
            r"\.\s*has_public_route\s*=",
            r"\.\s*has_nat_gateway_egress\s*=",
            r"\.\s*public_access_reasons\s*=",
            r"\.\s*public_exposure_reasons\s*=",
            r"\.\s*internet_ingress_capable\s*=",
            r"\.\s*internet_ingress_reasons\s*=",
            r"\.\s*in_public_subnet\s*=",
            r"\.\s*public_exposure\s*=",
            r"\.\s*direct_internet_reachable\s*=",
        )

        offenders = [pattern for pattern in direct_mutation_patterns if re.search(pattern, text)]

        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()
