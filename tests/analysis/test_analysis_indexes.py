from __future__ import annotations

import inspect
import unittest

from tfstride.analysis import indexes as analysis_indexes_module
from tfstride.analysis.indexes import AnalysisIndexExtensionError, build_analysis_indexes
from tfstride.analysis.role_helpers import resolve_workload_role
from tfstride.models import NormalizedResource, ResourceCategory, ResourceInventory
from tfstride.providers.gcp.analysis_indexes import GcpAnalysisIndexes
from tfstride.providers.gcp.iam_inheritance import GcpIamInheritanceIndex
from tfstride.providers.gcp.org_policy_guardrails import GcpOrgPolicyGuardrailIndex


def _resource(
    *,
    address: str,
    resource_type: str,
    category: ResourceCategory,
    identifier: str | None = None,
    arn: str | None = None,
    security_group_ids: list[str] | None = None,
    public_exposure: bool = False,
) -> NormalizedResource:
    return NormalizedResource(
        address=address,
        provider="aws",
        resource_type=resource_type,
        name=address.rsplit(".", 1)[-1],
        category=category,
        identifier=identifier,
        arn=arn,
        security_group_ids=security_group_ids or [],
        public_exposure=public_exposure,
    )


class AnalysisIndexTests(unittest.TestCase):
    def test_build_analysis_indexes_maps_roles_security_groups_and_public_resources(self) -> None:
        role = _resource(
            address="aws_iam_role.app",
            resource_type="aws_iam_role",
            category=ResourceCategory.IAM,
            identifier="app-role",
            arn="arn:aws:iam::111122223333:role/app",
        )
        security_group = _resource(
            address="aws_security_group.web",
            resource_type="aws_security_group",
            category=ResourceCategory.NETWORK,
            identifier="sg-web",
            arn="arn:aws:ec2:us-east-1:111122223333:security-group/sg-web",
        )
        public_workload = _resource(
            address="aws_instance.web",
            resource_type="aws_instance",
            category=ResourceCategory.COMPUTE,
            security_group_ids=["sg-web"],
            public_exposure=True,
        )
        private_database = _resource(
            address="aws_db_instance.app",
            resource_type="aws_db_instance",
            category=ResourceCategory.DATA,
            security_group_ids=["sg-web"],
        )
        inventory = ResourceInventory(
            provider="aws",
            resources=[role, security_group, public_workload, private_database],
        )

        indexes = build_analysis_indexes(inventory)

        self.assertIs(indexes.role_index.unique_candidate("aws_iam_role.app"), role)
        self.assertIs(indexes.role_index.unique_candidate("app-role"), role)
        self.assertIs(indexes.role_index.unique_candidate("arn:aws:iam::111122223333:role/app"), role)
        self.assertIs(indexes.security_groups_by_reference.unique_candidate("sg-web"), security_group)
        self.assertIs(
            indexes.security_groups_by_reference.unique_candidate("aws_security_group.web"),
            security_group,
        )
        self.assertEqual(
            indexes.resources_by_security_group["sg-web"],
            (public_workload, private_database),
        )
        self.assertEqual(
            indexes.public_workloads_by_security_group["sg-web"],
            (public_workload,),
        )
        self.assertEqual(indexes.attached_security_groups(public_workload), [security_group])

    def test_security_group_type_filtering_precedes_reference_resolution(self) -> None:
        conflicting_resource = _resource(
            address="aws_instance.conflict",
            resource_type="aws_instance",
            category=ResourceCategory.COMPUTE,
            identifier="sg-shared",
        )
        security_group = _resource(
            address="aws_security_group.shared",
            resource_type="aws_security_group",
            category=ResourceCategory.NETWORK,
            identifier="sg-shared",
        )
        workload = _resource(
            address="aws_instance.web",
            resource_type="aws_instance",
            category=ResourceCategory.COMPUTE,
            security_group_ids=["sg-shared"],
        )

        for resources in (
            [conflicting_resource, security_group, workload],
            [security_group, conflicting_resource, workload],
        ):
            with self.subTest(order=[resource.address for resource in resources]):
                indexes = build_analysis_indexes(ResourceInventory(provider="aws", resources=resources))

                self.assertIs(indexes.security_groups_by_reference.unique_candidate("sg-shared"), security_group)
                self.assertEqual(indexes.attached_security_groups(workload), [security_group])

    def test_ambiguous_role_and_security_group_aliases_fail_closed_in_any_input_order(self) -> None:
        first_role = _resource(
            address="aws_iam_role.first",
            resource_type="aws_iam_role",
            category=ResourceCategory.IAM,
            identifier="shared-role",
        )
        second_role = _resource(
            address="aws_iam_role.second",
            resource_type="aws_iam_role",
            category=ResourceCategory.IAM,
            identifier="shared-role",
        )
        first_security_group = _resource(
            address="aws_security_group.first",
            resource_type="aws_security_group",
            category=ResourceCategory.NETWORK,
            identifier="sg-shared",
        )
        second_security_group = _resource(
            address="aws_security_group.second",
            resource_type="aws_security_group",
            category=ResourceCategory.NETWORK,
            identifier="sg-shared",
        )
        workload = _resource(
            address="aws_instance.web",
            resource_type="aws_instance",
            category=ResourceCategory.COMPUTE,
            security_group_ids=["sg-shared"],
        )
        workload.attached_role_arns = ["shared-role"]

        for resources in (
            [first_role, second_role, first_security_group, second_security_group, workload],
            [second_security_group, first_security_group, second_role, first_role, workload],
        ):
            with self.subTest(order=[resource.address for resource in resources]):
                indexes = build_analysis_indexes(ResourceInventory(provider="aws", resources=resources))

                role_resolution = indexes.role_index.resolve("shared-role")
                security_group_resolution = indexes.security_groups_by_reference.resolve("sg-shared")
                self.assertEqual(role_resolution.state, "ambiguous")
                self.assertEqual(role_resolution.candidates, (first_role, second_role))
                self.assertEqual(security_group_resolution.state, "ambiguous")
                self.assertEqual(
                    security_group_resolution.candidates,
                    (first_security_group, second_security_group),
                )
                self.assertIsNone(resolve_workload_role(workload, indexes.role_index))
                self.assertEqual(indexes.attached_security_groups(workload), [])
                self.assertIs(indexes.role_index.unique_candidate(first_role.address), first_role)
                self.assertIs(
                    indexes.security_groups_by_reference.unique_candidate(first_security_group.address),
                    first_security_group,
                )

    def test_index_maps_are_top_level_immutable(self) -> None:
        role = _resource(
            address="aws_iam_role.app",
            resource_type="aws_iam_role",
            category=ResourceCategory.IAM,
        )
        indexes = build_analysis_indexes(ResourceInventory(provider="aws", resources=[role]))

        with self.assertRaises(TypeError):
            indexes.role_index.resources_by_reference["aws_iam_role.other"] = (role,)

    def test_gcp_inventory_builds_both_provider_indexes(self) -> None:
        indexes = build_analysis_indexes(ResourceInventory(provider="gcp", resources=[]))

        extension = indexes.require_provider_extension(GcpAnalysisIndexes)
        self.assertIsInstance(extension.iam_inheritance, GcpIamInheritanceIndex)
        self.assertIsInstance(extension.org_policy_guardrails, GcpOrgPolicyGuardrailIndex)

    def test_provider_extension_factory_receives_inventory(self) -> None:
        inventory = ResourceInventory(provider="custom", resources=[])
        extension = object()
        calls: list[ResourceInventory] = []

        indexes = build_analysis_indexes(
            inventory,
            provider_extension_factory=lambda value: calls.append(value) or extension,
        )

        self.assertEqual(calls, [inventory])
        self.assertIs(indexes.provider_extension, extension)
        with self.assertRaises(AnalysisIndexExtensionError):
            indexes.require_provider_extension(dict)

    def test_shared_index_module_has_no_provider_specific_dependencies(self) -> None:
        source = inspect.getsource(analysis_indexes_module)

        self.assertNotIn("tfstride.analysis.gcp", source)
        self.assertNotIn("tfstride.providers.gcp", source)
        self.assertNotIn("gcp_", source)


if __name__ == "__main__":
    unittest.main()
