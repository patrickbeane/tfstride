from __future__ import annotations

import unittest

from tests.providers.gcp.normalizer_support import _terraform_resource
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_decoration.cloud_run_secret_access_paths import (
    ModelCloudRunSecretAccessPathsStage,
)
from tfstride.providers.gcp.resource_decorator import GcpResourceDecorator
from tfstride.providers.gcp.resource_types import GcpResourceType
from tfstride.providers.gcp.rules import GCP_RULE_GROUP_IDS

_RULE_ID = "gcp-cloud-run-secret-access-blast-radius"
_PROJECT = "tfstride-demo"
_SERVICE_ACCOUNT_EMAIL = "run-api@tfstride-demo.iam.gserviceaccount.com"
_SERVICE_ACCOUNT_MEMBER = f"serviceAccount:{_SERVICE_ACCOUNT_EMAIL}"
_WORKLOAD_ADDRESS = "google_cloud_run_v2_service.api"
_SECRET_ADDRESS = "google_secret_manager_secret.orders"


def _secret_name(name: str) -> str:
    return f"projects/{_PROJECT}/secrets/{name}"


def _cloud_run(
    secret_names: tuple[str, ...] = ("orders-db",),
    *,
    service_account: str = _SERVICE_ACCOUNT_EMAIL,
) -> object:
    env = [
        {
            "name": f"SECRET_{index}",
            "value_source": [
                {
                    "secret_key_ref": [
                        {
                            "secret": _secret_name(secret_name),
                            "version": "latest",
                        }
                    ]
                }
            ],
        }
        for index, secret_name in enumerate(secret_names)
    ]
    return _terraform_resource(
        _WORKLOAD_ADDRESS,
        GcpResourceType.CLOUD_RUN_V2_SERVICE,
        {
            "name": "api",
            "project": _PROJECT,
            "location": "us-central1",
            "template": [
                {
                    "service_account": service_account,
                    "containers": [{"name": "api", "env": env}],
                }
            ],
        },
    )


def _secret() -> object:
    return _terraform_resource(
        _SECRET_ADDRESS,
        GcpResourceType.SECRET_MANAGER_SECRET,
        {
            "project": _PROJECT,
            "secret_id": "orders-db",
            "name": _secret_name("orders-db"),
            "replication": [{"auto": [{}]}],
        },
    )


def _iam_member(
    resource_type: str,
    name: str,
    *,
    role: str = "roles/secretmanager.secretAccessor",
    member: str = _SERVICE_ACCOUNT_MEMBER,
    condition: list[dict[str, str]] | None = None,
    **scope_values: object,
) -> object:
    values: dict[str, object] = {
        "role": role,
        "member": member,
        **scope_values,
    }
    if condition is not None:
        values["condition"] = condition
    return _terraform_resource(f"{resource_type}.{name}", resource_type, values)


def _project_iam_member(
    *,
    condition: list[dict[str, str]] | None = None,
    member: str = _SERVICE_ACCOUNT_MEMBER,
) -> object:
    return _iam_member(
        GcpResourceType.PROJECT_IAM_MEMBER,
        "secret_access",
        project=_PROJECT,
        member=member,
        condition=condition,
    )


def _secret_iam_member() -> object:
    return _iam_member(
        GcpResourceType.SECRET_MANAGER_SECRET_IAM_MEMBER,
        "secret_access",
        project=_PROJECT,
        secret_id=_secret_name("orders-db"),
    )


def _evaluate(resources: list[object]):
    inventory = GcpNormalizer().normalize(resources)
    return _evaluate_inventory(inventory)


def _evaluate_inventory(inventory):
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
    )


def _evidence_by_key(finding):
    return {item.key: item.values for item in finding.evidence}


class GcpCloudRunSecretAccessBlastRadiusRuleTests(unittest.TestCase):
    def test_rule_id_is_registered(self) -> None:
        registered = {rule_id for group in GCP_RULE_GROUP_IDS for rule_id in group}

        self.assertIn(_RULE_ID, registered)

    def test_project_wide_secret_accessor_is_reported(self) -> None:
        findings = _evaluate([_cloud_run(), _project_iam_member()])

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(
            finding.affected_resources,
            [_WORKLOAD_ADDRESS, "google_project_iam_member.secret_access"],
        )
        evidence = _evidence_by_key(finding)
        self.assertEqual(
            evidence["runtime_identity"],
            [
                f"service_account_email={_SERVICE_ACCOUNT_EMAIL}",
                f"service_account_member={_SERVICE_ACCOUNT_MEMBER}",
                "identity_kind=cloud_run_service_account",
                "credential_context=workload_runtime",
            ],
        )
        self.assertEqual(
            evidence["consumed_secrets"],
            [
                "exact_secret_count=1",
                "small_secret_set_threshold=5",
                f"secret_resource_name={_secret_name('orders-db')}",
            ],
        )
        self.assertEqual(
            evidence["broad_secret_access_grant"],
            [
                "iam_resource_address=google_project_iam_member.secret_access",
                "iam_resource_type=google_project_iam_member",
                "role=roles/secretmanager.secretAccessor",
                "role_kind=built_in",
                "grant_scope_type=project",
                f"grant_scope={_PROJECT}",
                "grant_basis=project_iam",
                "access_state=granted",
                "condition_state=not_configured",
            ],
        )

    def test_multiple_exact_secrets_produce_one_finding_per_broad_grant(self) -> None:
        findings = _evaluate(
            [
                _cloud_run(("orders-db", "payments-api", "fulfillment-token")),
                _project_iam_member(),
            ]
        )

        self.assertEqual(len(findings), 1)
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(evidence["consumed_secrets"][0], "exact_secret_count=3")
        self.assertEqual(len(evidence["consumed_secrets"]), 5)

    def test_secret_scoped_secret_accessor_remains_quiet(self) -> None:
        findings = _evaluate([_cloud_run(), _secret_iam_member()])

        self.assertEqual(findings, [])

    def test_conditional_project_grant_remains_quiet(self) -> None:
        findings = _evaluate(
            [
                _cloud_run(),
                _project_iam_member(
                    condition=[
                        {
                            "title": "runtime-window",
                            "expression": "request.time < timestamp('2027-01-01T00:00:00Z')",
                        }
                    ]
                ),
            ]
        )

        self.assertEqual(findings, [])

    def test_more_than_small_secret_set_threshold_remains_quiet(self) -> None:
        findings = _evaluate(
            [
                _cloud_run(tuple(f"secret-{index}" for index in range(6))),
                _project_iam_member(),
            ]
        )

        self.assertEqual(findings, [])

    def test_unresolved_service_account_identity_remains_quiet(self) -> None:
        findings = _evaluate(
            [
                _cloud_run(service_account="$" + "{google_service_account.run.email}"),
                _project_iam_member(),
            ]
        )

        self.assertEqual(findings, [])

    def test_folder_and_organization_scope_each_produce_one_finding(self) -> None:
        folder_id = "folders/123456"
        organization_id = "organizations/987654"
        inventory = GcpNormalizer().normalize(
            [
                _secret(),
                _cloud_run(),
                _iam_member(
                    GcpResourceType.FOLDER_IAM_MEMBER,
                    "folder_access",
                    folder=folder_id,
                ),
                _iam_member(
                    GcpResourceType.ORGANIZATION_IAM_MEMBER,
                    "organization_access",
                    org_id=organization_id,
                ),
            ]
        )
        secret = inventory.get_by_address(_SECRET_ADDRESS)
        workload = inventory.get_by_address(_WORKLOAD_ADDRESS)
        assert secret is not None
        assert workload is not None
        secret.set_metadata_field(GcpResourceMetadata.FOLDER_ID, folder_id)
        secret.set_metadata_field(GcpResourceMetadata.ORGANIZATION_ID, organization_id)
        workload.set_metadata_field(GcpResourceMetadata.CLOUD_RUN_SECRET_ACCESS_PATHS, [])
        workload.set_metadata_field(GcpResourceMetadata.CLOUD_RUN_SECRET_ACCESS_PATH_UNCERTAINTIES, [])
        GcpResourceDecorator(stages=[ModelCloudRunSecretAccessPathsStage()]).decorate(list(inventory.resources))

        findings = _evaluate_inventory(inventory)

        self.assertEqual(len(findings), 2)
        evidence = [_evidence_by_key(finding)["broad_secret_access_grant"] for finding in findings]
        self.assertEqual(
            [item[4] for item in evidence],
            ["grant_scope_type=folder", "grant_scope_type=organization"],
        )


if __name__ == "__main__":
    unittest.main()
