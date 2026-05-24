from __future__ import annotations

import unittest

from tfstride.analysis.role_helpers import build_role_index, resolve_workload_role
from tfstride.models import NormalizedResource, ResourceCategory, ResourceInventory


def _resource(
    *,
    address: str,
    resource_type: str,
    category: ResourceCategory,
    identifier: str | None = None,
    arn: str | None = None,
    attached_role_arns: list[str] | None = None,
) -> NormalizedResource:
    return NormalizedResource(
        address=address,
        provider="aws",
        resource_type=resource_type,
        name=address.rsplit(".", 1)[-1],
        category=category,
        identifier=identifier,
        arn=arn,
        attached_role_arns=attached_role_arns or [],
    )


class RoleHelperTests(unittest.TestCase):
    def test_build_role_index_maps_supported_role_aliases(self) -> None:
        role = _resource(
            address="aws_iam_role.app",
            resource_type="aws_iam_role",
            category=ResourceCategory.IAM,
            identifier="app-role",
            arn="arn:aws:iam::111122223333:role/app",
        )
        non_role = _resource(
            address="aws_instance.web",
            resource_type="aws_instance",
            category=ResourceCategory.COMPUTE,
        )
        inventory = ResourceInventory(provider="aws", resources=[role, non_role])

        role_index = build_role_index(inventory)

        self.assertIs(role_index["aws_iam_role.app"], role)
        self.assertIs(role_index["app-role"], role)
        self.assertIs(role_index["arn:aws:iam::111122223333:role/app"], role)
        self.assertNotIn("aws_instance.web", role_index)

    def test_resolve_workload_role_returns_first_matching_attached_role(self) -> None:
        first_role = _resource(
            address="aws_iam_role.first",
            resource_type="aws_iam_role",
            category=ResourceCategory.IAM,
            arn="arn:aws:iam::111122223333:role/first",
        )
        second_role = _resource(
            address="aws_iam_role.second",
            resource_type="aws_iam_role",
            category=ResourceCategory.IAM,
            arn="arn:aws:iam::111122223333:role/second",
        )
        workload = _resource(
            address="aws_lambda_function.worker",
            resource_type="aws_lambda_function",
            category=ResourceCategory.COMPUTE,
            attached_role_arns=[
                "missing-role",
                "arn:aws:iam::111122223333:role/second",
                "arn:aws:iam::111122223333:role/first",
            ],
        )
        role_index = build_role_index(
            ResourceInventory(provider="aws", resources=[first_role, second_role, workload])
        )

        self.assertIs(resolve_workload_role(workload, role_index), second_role)

    def test_resolve_workload_role_returns_none_without_match(self) -> None:
        workload = _resource(
            address="aws_instance.web",
            resource_type="aws_instance",
            category=ResourceCategory.COMPUTE,
            attached_role_arns=["missing-role"],
        )

        self.assertIsNone(resolve_workload_role(workload, {}))


if __name__ == "__main__":
    unittest.main()