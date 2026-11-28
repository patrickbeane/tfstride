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


if __name__ == "__main__":
    unittest.main()
