from __future__ import annotations

import unittest

from tests.providers.gcp.normalizer_support import _terraform_resource
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_types import GcpResourceType

_PROJECT_NUMBER = "123456789012"
_POOL_ID = "external"
_POOL_ADDRESS = "google_iam_workload_identity_pool.external"
_POOL_RESOURCE_NAME = f"projects/{_PROJECT_NUMBER}/locations/global/workloadIdentityPools/{_POOL_ID}"
_PROVIDER_ADDRESS = "google_iam_workload_identity_pool_provider.github"
_PROVIDER_RESOURCE_NAME = f"{_POOL_RESOURCE_NAME}/providers/github"
_SERVICE_ACCOUNT_ADDRESS = "google_service_account.deployer"
_SERVICE_ACCOUNT_EMAIL = "deployer@tfstride-demo.iam.gserviceaccount.com"
_IAM_ADDRESS = "google_service_account_iam_member.federated"


def _pool(*, resource_name: str | None = _POOL_RESOURCE_NAME, name: str | None = None):
    values: dict[str, object] = {
        "workload_identity_pool_id": _POOL_ID,
        "mode": "FEDERATION_ONLY",
        "disabled": False,
    }
    if resource_name is not None:
        values["id"] = resource_name
    if name is not None:
        values["name"] = name
    return _terraform_resource(_POOL_ADDRESS, GcpResourceType.WORKLOAD_IDENTITY_POOL, values)


def _provider(
    *,
    resource_name: str | None = _PROVIDER_RESOURCE_NAME,
    mappings: dict[str, str] | None = None,
):
    values: dict[str, object] = {
        "workload_identity_pool_id": _POOL_ID,
        "workload_identity_pool_provider_id": "github",
        "disabled": False,
        "oidc": [
            {
                "issuer_uri": "https://token.actions.githubusercontent.com",
                "allowed_audiences": ["sts.googleapis.com"],
            }
        ],
        "attribute_mapping": mappings
        if mappings is not None
        else {
            "google.subject": "assertion.sub",
            "attribute.repository": "assertion.repository",
        },
        "attribute_condition": "assertion.repository_owner == 'tfstride'",
    }
    if resource_name is not None:
        values["id"] = resource_name
    return _terraform_resource(
        _PROVIDER_ADDRESS,
        GcpResourceType.WORKLOAD_IDENTITY_POOL_PROVIDER,
        values,
    )


def _service_account():
    return _terraform_resource(
        _SERVICE_ACCOUNT_ADDRESS,
        GcpResourceType.SERVICE_ACCOUNT,
        {
            "account_id": "deployer",
            "email": _SERVICE_ACCOUNT_EMAIL,
            "name": f"projects/tfstride-demo/serviceAccounts/{_SERVICE_ACCOUNT_EMAIL}",
        },
    )


def _iam_member(
    member: str,
    *,
    role: str = "roles/iam.workloadIdentityUser",
    service_account_reference: str = f"{_SERVICE_ACCOUNT_ADDRESS}.name",
    condition: list[dict[str, str]] | None = None,
):
    values: dict[str, object] = {
        "service_account_id": service_account_reference,
        "role": role,
        "member": member,
    }
    if condition is not None:
        values["condition"] = condition
    return _terraform_resource(
        _IAM_ADDRESS,
        GcpResourceType.SERVICE_ACCOUNT_IAM_MEMBER,
        values,
    )


def _principal(selector: str) -> str:
    return f"principal://iam.googleapis.com/{_POOL_RESOURCE_NAME}/subject/{selector}"


def _principal_set(selector: str, value: str | None = None) -> str:
    suffix = selector if value is None else f"{selector}/{value}"
    return f"principalSet://iam.googleapis.com/{_POOL_RESOURCE_NAME}/{suffix}"


def _normalize(resources):
    return GcpNormalizer().normalize(resources)


class GcpWorkloadIdentityTrustPathTests(unittest.TestCase):
    def test_exact_subject_principal_connects_provider_pool_and_service_account_grant(self) -> None:
        member = _principal("repo:tfstride/tfstride:ref:refs/heads/main")
        inventory = _normalize([_pool(), _provider(), _service_account(), _iam_member(member)])
        service_account = inventory.get_by_address(_SERVICE_ACCOUNT_ADDRESS)

        self.assertIsNotNone(service_account)
        assert service_account is not None
        facts = gcp_facts(service_account)
        self.assertEqual(
            facts.workload_identity_federation_trust_paths,
            [
                {
                    "service_account_address": _SERVICE_ACCOUNT_ADDRESS,
                    "service_account_email": _SERVICE_ACCOUNT_EMAIL,
                    "iam_resource_address": _IAM_ADDRESS,
                    "role": "roles/iam.workloadIdentityUser",
                    "member": member,
                    "member_kind": "principal",
                    "principal_selector": "subject",
                    "principal_value": "repo:tfstride/tfstride:ref:refs/heads/main",
                    "pool_address": _POOL_ADDRESS,
                    "pool_resource_name": _POOL_RESOURCE_NAME,
                    "pool_mode": "FEDERATION_ONLY",
                    "pool_state": "enabled",
                    "provider_address": _PROVIDER_ADDRESS,
                    "provider_resource_name": _PROVIDER_RESOURCE_NAME,
                    "provider_type": "oidc",
                    "provider_state": "enabled",
                    "provider_issuer_uri": "https://token.actions.githubusercontent.com",
                    "provider_allowed_audiences": ["sts.googleapis.com"],
                    "provider_mapping_key": "google.subject",
                    "provider_attribute_condition": "assertion.repository_owner == 'tfstride'",
                    "iam_condition": None,
                    "grant_basis": "service_account_iam",
                }
            ],
        )
        self.assertEqual(facts.workload_identity_federation_trust_path_uncertainties, [])

    def test_principal_set_attribute_and_iam_condition_are_preserved(self) -> None:
        member = _principal_set("attribute.repository", "tfstride/tfstride")
        condition = [{"title": "main-only", "expression": "request.auth.claims.ref == 'refs/heads/main'"}]
        inventory = _normalize([_pool(), _provider(), _service_account(), _iam_member(member, condition=condition)])
        service_account = inventory.get_by_address(_SERVICE_ACCOUNT_ADDRESS)

        self.assertIsNotNone(service_account)
        assert service_account is not None
        paths = gcp_facts(service_account).workload_identity_federation_trust_paths
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0]["member_kind"], "principal_set")
        self.assertEqual(paths[0]["principal_selector"], "attribute.repository")
        self.assertEqual(paths[0]["principal_value"], "tfstride/tfstride")
        self.assertEqual(paths[0]["provider_mapping_key"], "attribute.repository")
        self.assertEqual(
            paths[0]["iam_condition"],
            {"title": "main-only", "expression": "request.auth.claims.ref == 'refs/heads/main'"},
        )

    def test_pool_wildcard_connects_without_an_attribute_mapping(self) -> None:
        member = _principal_set("*")
        inventory = _normalize([_pool(), _provider(mappings={}), _service_account(), _iam_member(member)])
        service_account = inventory.get_by_address(_SERVICE_ACCOUNT_ADDRESS)

        self.assertIsNotNone(service_account)
        assert service_account is not None
        paths = gcp_facts(service_account).workload_identity_federation_trust_paths
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0]["principal_selector"], "pool")
        self.assertEqual(paths[0]["principal_value"], "*")
        self.assertIsNone(paths[0]["provider_mapping_key"])

    def test_principal_set_group_requires_the_exact_google_groups_mapping(self) -> None:
        member = _principal_set("group", "platform-admins")
        inventory = _normalize(
            [
                _pool(),
                _provider(mappings={"google.groups": "assertion.groups"}),
                _service_account(),
                _iam_member(member),
            ]
        )
        service_account = inventory.get_by_address(_SERVICE_ACCOUNT_ADDRESS)

        self.assertIsNotNone(service_account)
        assert service_account is not None
        paths = gcp_facts(service_account).workload_identity_federation_trust_paths
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0]["principal_selector"], "group")
        self.assertEqual(paths[0]["principal_value"], "platform-admins")
        self.assertEqual(paths[0]["provider_mapping_key"], "google.groups")

    def test_same_pool_id_or_display_name_does_not_create_a_relationship(self) -> None:
        member = _principal("repo:tfstride/tfstride")
        cases = (
            [_pool(resource_name=None, name=_POOL_ID), _provider()],
            [
                _pool(resource_name="projects/999999999999/locations/global/workloadIdentityPools/external"),
                _provider(
                    resource_name="projects/999999999999/locations/global/workloadIdentityPools/external/providers/github"
                ),
            ],
            [_pool(), _provider(resource_name=None)],
        )

        for federation_resources in cases:
            with self.subTest(resources=[resource.address for resource in federation_resources]):
                inventory = _normalize([*federation_resources, _service_account(), _iam_member(member)])
                service_account = inventory.get_by_address(_SERVICE_ACCOUNT_ADDRESS)
                self.assertIsNotNone(service_account)
                assert service_account is not None
                self.assertEqual(gcp_facts(service_account).workload_identity_federation_trust_paths, [])

    def test_unsupported_mapping_unresolved_member_and_non_trust_role_stay_quiet(self) -> None:
        subject_member = _principal("repo:tfstride/tfstride")
        unresolved_member = (
            "principalSet://iam.googleapis.com/projects/${google_project.demo.number}/locations/global/"
            "workloadIdentityPools/external/*"
        )
        cases = (
            (_provider(mappings={"attribute.repository": "assertion.repository"}), subject_member),
            (_provider(), unresolved_member),
        )

        for provider, member in cases:
            with self.subTest(member=member):
                inventory = _normalize([_pool(), provider, _service_account(), _iam_member(member)])
                service_account = inventory.get_by_address(_SERVICE_ACCOUNT_ADDRESS)
                self.assertIsNotNone(service_account)
                assert service_account is not None
                facts = gcp_facts(service_account)
                self.assertEqual(facts.workload_identity_federation_trust_paths, [])
                self.assertTrue(facts.workload_identity_federation_trust_path_uncertainties)

        inventory = _normalize(
            [
                _pool(),
                _provider(),
                _service_account(),
                _iam_member(subject_member, role="roles/iam.serviceAccountViewer"),
            ]
        )
        service_account = inventory.get_by_address(_SERVICE_ACCOUNT_ADDRESS)
        self.assertIsNotNone(service_account)
        assert service_account is not None
        facts = gcp_facts(service_account)
        self.assertEqual(facts.workload_identity_federation_trust_paths, [])
        self.assertEqual(facts.workload_identity_federation_trust_path_uncertainties, [])

    def test_short_service_account_name_does_not_resolve_as_an_exact_target(self) -> None:
        inventory = _normalize(
            [
                _pool(),
                _provider(),
                _service_account(),
                _iam_member(_principal("repo:tfstride/tfstride"), service_account_reference="deployer"),
            ]
        )
        service_account = inventory.get_by_address(_SERVICE_ACCOUNT_ADDRESS)

        self.assertIsNotNone(service_account)
        assert service_account is not None
        self.assertEqual(gcp_facts(service_account).workload_identity_federation_trust_paths, [])


if __name__ == "__main__":
    unittest.main()
