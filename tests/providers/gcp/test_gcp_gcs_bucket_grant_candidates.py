"""Pin which bucket-local IAM sources become grants or problems for one (principal, bucket) query.

These cases characterize the local-source selection that grant evaluation performs through
`GcsGrantConstraintContext.bindings`, so optimizations can change how sources are indexed
without changing which sources apply, conflict, or stay unresolved.
"""

from __future__ import annotations

import json
import unittest

from tests.providers.gcp.normalizer_support import _terraform_resource
from tests.providers.gcp.test_gcp_cloud_run_gcs_access_paths import _PROJECT, _SERVICE_ACCOUNT_MEMBER
from tfstride.models import TerraformResource
from tfstride.providers.gcp.gcs_grant_evaluation import GcsGrantConstraintContext
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_types import GcpResourceType

_ORDERS = "google_storage_bucket.orders"
_ORDERS_NAME = "tfstride-orders-data"
_OTHER = "google_storage_bucket.other"
_OTHER_NAME = "other-data"
_VIEWER = "roles/storage.objectViewer"
_CREATOR = "roles/storage.objectCreator"
_OTHER_MEMBER = "serviceAccount:other@tfstride-demo.iam.gserviceaccount.com"


def _bucket(address: str, name: str) -> TerraformResource:
    return _terraform_resource(
        address,
        GcpResourceType.STORAGE_BUCKET,
        {"name": name, "project": _PROJECT, "location": "US"},
    )


def _buckets() -> list[TerraformResource]:
    return [_bucket(_ORDERS, _ORDERS_NAME), _bucket(_OTHER, _OTHER_NAME)]


def _member(
    name: str,
    *,
    bucket: str = f"{_ORDERS}.name",
    role: str = _VIEWER,
    member: str = _SERVICE_ACCOUNT_MEMBER,
    condition: dict[str, str] | None = None,
    unknown: dict[str, object] | None = None,
) -> TerraformResource:
    values: dict[str, object] = {"bucket": bucket, "role": role, "member": member}
    if condition:
        values["condition"] = [condition]
    return _terraform_resource(
        f"google_storage_bucket_iam_member.{name}",
        GcpResourceType.STORAGE_BUCKET_IAM_MEMBER,
        values,
        unknown_values=unknown,
    )


def _binding(
    name: str,
    *,
    bucket: str = f"{_ORDERS}.name",
    role: str = _VIEWER,
    members: tuple[str, ...] = (_SERVICE_ACCOUNT_MEMBER,),
    condition: dict[str, str] | None = None,
) -> TerraformResource:
    values: dict[str, object] = {"bucket": bucket, "role": role, "members": list(members)}
    if condition:
        values["condition"] = [condition]
    return _terraform_resource(
        f"google_storage_bucket_iam_binding.{name}",
        GcpResourceType.STORAGE_BUCKET_IAM_BINDING,
        values,
    )


def _policy(name: str, *, bucket: str = f"{_ORDERS}.name", role: str = _VIEWER) -> TerraformResource:
    policy = {"bindings": [{"role": role, "members": [_SERVICE_ACCOUNT_MEMBER]}]}
    return _terraform_resource(
        f"google_storage_bucket_iam_policy.{name}",
        GcpResourceType.STORAGE_BUCKET_IAM_POLICY,
        {"bucket": bucket, "policy_data": json.dumps(policy)},
    )


def _manager(
    kind: str,
    name: str,
    values: dict[str, object],
    *,
    unknown: dict[str, object] | None = None,
) -> TerraformResource:
    """Build an IAM manager with exactly the supplied values, including partial or unresolved ones."""
    resource_type = f"google_storage_bucket_iam_{kind}"
    return _terraform_resource(
        f"{resource_type}.{name}",
        resource_type,
        {"bucket": f"{_ORDERS}.name", **values},
        unknown_values=unknown,
    )


def _condition(title: str) -> dict[str, str]:
    return {"title": title, "expression": f'request.time < timestamp("{title}")'}


def _query(
    iam_sources: list[TerraformResource],
    *,
    bucket: str = _ORDERS,
    principal: str = _SERVICE_ACCOUNT_MEMBER,
) -> tuple[list[tuple[str, str]], list[str]]:
    inventory = GcpNormalizer().normalize([*_buckets(), *iam_sources])
    target = inventory.get_by_address(bucket)
    assert target is not None
    grants, problems = GcsGrantConstraintContext.build(inventory.resources).bindings(principal, target)
    return sorted((str(grant["source"]), str(grant["role"])) for grant in grants), sorted(problems)


def _address(kind: str, name: str) -> str:
    return f"google_storage_bucket_iam_{kind}.{name}"


class GcpGcsBucketGrantCandidateTests(unittest.TestCase):
    def test_bucket_without_iam_sources_has_no_candidates(self) -> None:
        self.assertEqual(_query([]), ([], []))

    def test_member_for_the_bucket_is_a_grant(self) -> None:
        self.assertEqual(
            _query([_member("viewer")]),
            ([(_address("member", "viewer"), _VIEWER)], []),
        )

    def test_sources_apply_only_to_the_bucket_they_target(self) -> None:
        sources = [_member("orders"), _member("other", bucket=f"{_OTHER}.name", role=_CREATOR)]

        self.assertEqual(_query(sources), ([(_address("member", "orders"), _VIEWER)], []))
        self.assertEqual(
            _query(sources, bucket=_OTHER),
            ([(_address("member", "other"), _CREATOR)], []),
        )

    def test_native_bucket_name_reference_targets_only_the_named_bucket(self) -> None:
        source = _member("native", bucket=f"projects/_/buckets/{_ORDERS_NAME}")

        self.assertEqual(_query([source]), ([(_address("member", "native"), _VIEWER)], []))
        self.assertEqual(_query([source], bucket=_OTHER), ([], []))

    def test_literal_name_of_another_bucket_is_skipped_without_a_problem(self) -> None:
        source = _member("literal", bucket=_OTHER_NAME)

        self.assertEqual(_query([source]), ([], []))

    def test_unknown_bucket_scope_is_reported_as_a_problem_for_every_bucket(self) -> None:
        source = _member("unknown", bucket="", unknown={"bucket": True})
        expected = [f"{_address('member', 'unknown')} for {{bucket}}: bucket scope is unresolved"]

        self.assertEqual(_query([source]), ([], [expected[0].format(bucket=_ORDERS)]))
        self.assertEqual(_query([source], bucket=_OTHER), ([], [expected[0].format(bucket=_OTHER)]))

    def test_members_for_other_principals_are_ignored(self) -> None:
        sources = [
            _member("someone_else", member=_OTHER_MEMBER, role=_CREATOR),
            _binding("group", members=(_OTHER_MEMBER,), role=_VIEWER),
        ]

        self.assertEqual(_query(sources), ([], []))
        self.assertEqual(
            _query(sources, principal=_OTHER_MEMBER),
            (
                [(_address("binding", "group"), _VIEWER), (_address("member", "someone_else"), _CREATOR)],
                [],
            ),
        )

    def test_authoritative_manager_for_another_principal_still_blocks_the_queried_grant(self) -> None:
        # The conflict set is every manager of the bucket, not only those naming the principal.
        sources = [
            _member("mine", role=_VIEWER),
            _binding("theirs", members=(_OTHER_MEMBER,), role=_VIEWER),
        ]

        self.assertEqual(
            _query(sources),
            (
                [],
                [f"{_address('member', 'mine')} for {_ORDERS}: overlapping authoritative bucket IAM managers"],
            ),
        )
        self.assertEqual(
            _query(sources, principal=_OTHER_MEMBER),
            (
                [],
                [f"{_address('binding', 'theirs')} for {_ORDERS}: overlapping authoritative bucket IAM managers"],
            ),
        )

    def test_binding_and_member_for_the_same_role_conflict(self) -> None:
        grants, problems = _query([_binding("managed"), _member("extra")])

        self.assertEqual(grants, [])
        self.assertEqual(
            problems,
            [
                f"{_address('binding', 'managed')} for {_ORDERS}: overlapping authoritative bucket IAM managers",
                f"{_address('member', 'extra')} for {_ORDERS}: overlapping authoritative bucket IAM managers",
            ],
        )

    def test_binding_and_member_for_different_roles_are_independent(self) -> None:
        self.assertEqual(
            _query([_binding("managed", role=_VIEWER), _member("extra", role=_CREATOR)]),
            (
                [(_address("binding", "managed"), _VIEWER), (_address("member", "extra"), _CREATOR)],
                [],
            ),
        )

    def test_binding_and_member_with_different_conditions_are_independent(self) -> None:
        self.assertEqual(
            _query(
                [
                    _binding("managed", condition=_condition("2030-01-01")),
                    _member("extra", condition=_condition("2031-01-01")),
                ]
            ),
            (
                [(_address("binding", "managed"), _VIEWER), (_address("member", "extra"), _VIEWER)],
                [],
            ),
        )

    def test_members_never_conflict_with_each_other(self) -> None:
        self.assertEqual(
            _query([_member("first"), _member("second")]),
            ([(_address("member", "first"), _VIEWER), (_address("member", "second"), _VIEWER)], []),
        )

    def test_authoritative_policy_conflicts_with_every_other_manager(self) -> None:
        grants, problems = _query([_policy("policy", role=_CREATOR), _member("extra")])

        self.assertEqual(grants, [])
        self.assertEqual(len(problems), 2)
        self.assertTrue(all("overlapping authoritative bucket IAM managers" in problem for problem in problems))

    def test_managers_of_other_buckets_do_not_create_conflicts(self) -> None:
        sources = [_binding("other", bucket=f"{_OTHER}.name"), _member("orders")]

        self.assertEqual(_query(sources), ([(_address("member", "orders"), _VIEWER)], []))

    def test_multi_bucket_inventory_resolves_each_bucket_independently(self) -> None:
        sources = [
            _binding("orders_binding", role=_VIEWER),
            _member("orders_member", role=_CREATOR),
            _binding("other_binding", bucket=f"{_OTHER}.name", role=_VIEWER),
            _member("other_member", bucket=f"{_OTHER}.name", role=_VIEWER),
        ]

        self.assertEqual(
            _query(sources),
            (
                [(_address("binding", "orders_binding"), _VIEWER), (_address("member", "orders_member"), _CREATOR)],
                [],
            ),
        )
        grants, problems = _query(sources, bucket=_OTHER)
        self.assertEqual(grants, [])
        self.assertEqual(len(problems), 2)

    def test_binding_with_an_unknown_role_is_unresolved_and_blocks_other_managers(self) -> None:
        unresolved = _manager(
            "binding", "unknown_role", {"role": "", "members": [_SERVICE_ACCOUNT_MEMBER]}, unknown={"role": True}
        )

        self.assertEqual(
            _query([unresolved, _member("extra", role=_CREATOR)]),
            (
                [],
                [
                    f"{_address('binding', 'unknown_role')} for {_ORDERS}: "
                    "bucket IAM role, membership, or condition is unresolved",
                    f"{_address('member', 'extra')} for {_ORDERS}: overlapping authoritative bucket IAM managers",
                ],
            ),
        )

    def test_binding_without_a_role_blocks_other_managers_without_a_problem_of_its_own(self) -> None:
        roleless = _manager("binding", "roleless", {"members": [_SERVICE_ACCOUNT_MEMBER]})

        self.assertEqual(
            _query([roleless, _member("extra", role=_CREATOR)]),
            ([], [f"{_address('member', 'extra')} for {_ORDERS}: overlapping authoritative bucket IAM managers"]),
        )

    def test_binding_with_an_unknown_condition_conflicts_on_the_same_role(self) -> None:
        conditional = _manager(
            "binding",
            "conditional",
            {"role": _VIEWER, "members": [_SERVICE_ACCOUNT_MEMBER], "condition": [_condition("2030-01-01")]},
            unknown={"condition": True},
        )

        self.assertEqual(
            _query([conditional, _member("extra", role=_VIEWER)]),
            (
                [],
                [
                    f"{_address('binding', 'conditional')} for {_ORDERS}: "
                    "bucket IAM role, membership, or condition is unresolved",
                    f"{_address('member', 'extra')} for {_ORDERS}: overlapping authoritative bucket IAM managers",
                ],
            ),
        )

    def test_binding_with_no_members_conflicts_with_every_other_manager_regardless_of_role(self) -> None:
        # Current behavior: an empty authoritative binding has no role to compare, so it blocks all managers.
        empty = _manager("binding", "empty", {"role": _CREATOR, "members": []})

        self.assertEqual(
            _query([empty, _member("extra", role=_VIEWER)]),
            ([], [f"{_address('member', 'extra')} for {_ORDERS}: overlapping authoritative bucket IAM managers"]),
        )

    def test_binding_with_unknown_members_conflicts_only_on_the_same_role(self) -> None:
        for role, expected_grants in ((_CREATOR, [(_address("member", "extra"), _VIEWER)]), (_VIEWER, [])):
            with self.subTest(binding_role=role):
                unknown_members = _manager(
                    "binding", "unknown_members", {"role": role, "members": []}, unknown={"members": True}
                )

                grants, problems = _query([unknown_members, _member("extra", role=_VIEWER)])

                self.assertEqual(grants, expected_grants)
                self.assertEqual(
                    problems,
                    []
                    if expected_grants
                    else [
                        f"{_address('member', 'extra')} for {_ORDERS}: overlapping authoritative bucket IAM managers"
                    ],
                )

    def test_member_with_an_unresolved_role_or_condition_is_a_problem(self) -> None:
        unresolved_fields: list[dict[str, object]] = [{"role": True}, {"condition": True}]
        for unknown in unresolved_fields:
            with self.subTest(unknown=unknown):
                values: dict[str, object] = {"member": _SERVICE_ACCOUNT_MEMBER}
                if "condition" in unknown:
                    values |= {"role": _VIEWER, "condition": [_condition("2030-01-01")]}
                source = _manager("member", "unresolved", values, unknown=unknown)

                self.assertEqual(
                    _query([source]),
                    (
                        [],
                        [
                            f"{_address('member', 'unresolved')} for {_ORDERS}: "
                            "bucket IAM role, membership, or condition is unresolved"
                        ],
                    ),
                )

    def test_member_with_an_unknown_principal_is_ignored_without_a_problem(self) -> None:
        # Current behavior: unresolved membership cannot be matched to the principal, so it reports nothing.
        source = _manager("member", "unknown_member", {"role": _VIEWER}, unknown={"member": True})

        self.assertEqual(_query([source]), ([], []))

    def test_policy_with_a_valid_binding_is_a_grant_when_it_is_the_only_manager(self) -> None:
        self.assertEqual(_query([_policy("policy")]), ([(_address("policy", "policy"), _VIEWER)], []))

    def test_policy_with_unsupported_binding_structure_is_a_problem(self) -> None:
        malformed = _manager(
            "policy",
            "malformed",
            {
                "policy_data": json.dumps(
                    {"bindings": [{"role": _VIEWER, "members": [_SERVICE_ACCOUNT_MEMBER], "extra": 1}]}
                )
            },
        )

        self.assertEqual(
            _query([malformed]),
            (
                [],
                [
                    f"{_address('policy', 'malformed')} for {_ORDERS}: bucket IAM policy contains unsupported binding structure"
                ],
            ),
        )

    def test_policy_with_unknown_data_reports_nothing_alone_but_blocks_other_managers(self) -> None:
        unknown_policy = _manager("policy", "unknown", {}, unknown={"policy_data": True})

        self.assertEqual(_query([unknown_policy]), ([], []))
        self.assertEqual(
            _query([unknown_policy, _member("extra")]),
            ([], [f"{_address('member', 'extra')} for {_ORDERS}: overlapping authoritative bucket IAM managers"]),
        )

    def test_custom_roles_conflict_only_when_their_role_strings_are_identical(self) -> None:
        project_role = f"projects/{_PROJECT}/roles/storageOperator"
        organization_role = "organizations/123/roles/storageOperator"
        conflict = [
            f"{_address('binding', 'managed')} for {_ORDERS}: overlapping authoritative bucket IAM managers",
            f"{_address('member', 'extra')} for {_ORDERS}: overlapping authoritative bucket IAM managers",
        ]

        self.assertEqual(
            _query([_binding("managed", role=project_role), _member("extra", role=project_role)]),
            ([], conflict),
        )
        self.assertEqual(
            _query([_binding("managed", role=project_role), _member("extra", role=organization_role)]),
            (
                [(_address("binding", "managed"), project_role), (_address("member", "extra"), organization_role)],
                [],
            ),
        )

    def test_custom_role_aliases_are_not_recognized_as_conflicts_at_bucket_scope(self) -> None:
        # Current behavior, not an endorsement: bucket-local selection compares role strings without the
        # custom-role index, so a Terraform reference and the native name of one role do not conflict.
        role = _terraform_resource(
            "google_project_iam_custom_role.storage_operator",
            GcpResourceType.PROJECT_IAM_CUSTOM_ROLE,
            {
                "project": _PROJECT,
                "role_id": "storageOperator",
                "name": f"projects/{_PROJECT}/roles/storageOperator",
                "permissions": ["storage.objects.get"],
            },
        )
        by_reference = f"{role.address}.name"
        by_native_name = f"projects/{_PROJECT}/roles/storageOperator"

        self.assertEqual(
            _query([role, _binding("managed", role=by_reference), _member("extra", role=by_native_name)]),
            (
                [(_address("binding", "managed"), by_reference), (_address("member", "extra"), by_native_name)],
                [],
            ),
        )


if __name__ == "__main__":
    unittest.main()
