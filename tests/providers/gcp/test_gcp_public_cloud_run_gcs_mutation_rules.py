from __future__ import annotations

import unittest

from tests.providers.gcp.normalizer_support import _terraform_resource
from tests.providers.gcp.test_gcp_cloud_run_gcs_access_paths import (
    _BUCKET_ADDRESS,
    _IAM_ADDRESS,
    _PROJECT,
    _SERVICE_ACCOUNT_EMAIL,
    _SERVICE_ACCOUNT_MEMBER,
    _bucket,
    _bucket_iam_member,
    _custom_role,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import StrideCategory, TerraformResource
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_types import GcpResourceType
from tfstride.providers.gcp.rules import GCP_RULE_GROUP_IDS

_RULE_ID = "gcp-public-cloud-run-gcs-mutation-access"
_DISCLOSURE_RULE_ID = "gcp-public-workload-sensitive-data-access"
_WORKLOAD_ADDRESS = "google_cloud_run_v2_service.orders"
_PUBLIC_INVOKER_ADDRESS = "google_cloud_run_v2_service_iam_member.public_invoker"


def _cloud_run(*, public_ingress: bool = True) -> TerraformResource:
    return _terraform_resource(
        _WORKLOAD_ADDRESS,
        GcpResourceType.CLOUD_RUN_V2_SERVICE,
        {
            "name": "orders",
            "project": _PROJECT,
            "location": "us-central1",
            "ingress": ("INGRESS_TRAFFIC_ALL" if public_ingress else "INGRESS_TRAFFIC_INTERNAL_ONLY"),
            "template": [{"service_account": _SERVICE_ACCOUNT_EMAIL}],
        },
    )


def _public_invoker(
    *,
    member: str = "allUsers",
    condition: dict[str, str] | None = None,
) -> TerraformResource:
    values: dict[str, object] = {
        "name": "orders",
        "location": "us-central1",
        "role": "roles/run.invoker",
        "member": member,
    }
    if condition is not None:
        values["condition"] = [condition]
    return _terraform_resource(
        _PUBLIC_INVOKER_ADDRESS,
        GcpResourceType.CLOUD_RUN_V2_SERVICE_IAM_MEMBER,
        values,
    )


def _evaluate(
    resources: list[TerraformResource],
    *rule_ids: str,
):
    inventory = GcpNormalizer().normalize(resources)
    boundaries = detect_trust_boundaries(inventory)
    findings = StrideRuleEngine().evaluate(
        inventory,
        boundaries,
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids or {_RULE_ID})),
    )
    return inventory, boundaries, findings


def _evidence(finding):
    return {item.key: item.values for item in finding.evidence}


class GcpPublicCloudRunGcsMutationRuleTests(unittest.TestCase):
    def test_rule_is_registered(self) -> None:
        registered = {rule_id for group in GCP_RULE_GROUP_IDS for rule_id in group}

        self.assertIn(_RULE_ID, registered)

    def test_public_cloud_run_with_write_only_bucket_grant_is_reported_as_tampering(self) -> None:
        _, _, findings = _evaluate(
            [
                _cloud_run(),
                _public_invoker(),
                _bucket(),
                _bucket_iam_member(role="roles/storage.objectCreator"),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        self.assertEqual(finding.category, StrideCategory.TAMPERING)
        self.assertEqual(
            finding.affected_resources,
            [
                _WORKLOAD_ADDRESS,
                _PUBLIC_INVOKER_ADDRESS,
                _BUCKET_ADDRESS,
                _IAM_ADDRESS,
            ],
        )
        self.assertEqual(
            finding.trust_boundary_id,
            f"internet-to-service:internet->{_WORKLOAD_ADDRESS}",
        )
        self.assertIn("could tamper with stored data by writing objects", finding.rationale)
        self.assertIn("modeled grant is write-only", finding.rationale)
        self.assertIn(
            "does not establish read access or information disclosure",
            finding.rationale,
        )
        evidence = _evidence(finding)
        self.assertEqual(
            evidence["public_invoker_bindings"],
            [f"source={_PUBLIC_INVOKER_ADDRESS}; role=roles/run.invoker; member=allUsers; condition=none"],
        )
        self.assertIn(
            f"member={_SERVICE_ACCOUNT_MEMBER}",
            evidence["runtime_identity"][0],
        )
        self.assertIn(
            "role=roles/storage.objectCreator",
            evidence["runtime_identity"][0],
        )
        self.assertIn("role_kind=creator", evidence["runtime_identity"][0])
        self.assertIn(
            f"bucket_address={_BUCKET_ADDRESS}",
            evidence["gcs_mutation_paths"][0],
        )
        self.assertIn("mutation_classes=write", evidence["gcs_mutation_paths"][0])
        self.assertIn("access_classes=write", evidence["gcs_mutation_paths"][0])
        self.assertIn("resource_scope=exact_bucket", evidence["gcs_mutation_paths"][0])
        self.assertIn("access_state=granted", evidence["gcs_mutation_paths"][0])

    def test_user_admin_and_deterministic_custom_mutation_roles_are_detected(self) -> None:
        role_cases = (
            ("roles/storage.objectUser", [], "user", "write,delete"),
            ("roles/storage.objectAdmin", [], "admin", "write,delete"),
            (
                f"projects/{_PROJECT}/roles/cloudRunStorage",
                [_custom_role()],
                "custom",
                "write,delete",
            ),
        )

        for role, extra_resources, role_kind, mutation_classes in role_cases:
            with self.subTest(role=role):
                _, _, findings = _evaluate(
                    [
                        _cloud_run(),
                        _public_invoker(),
                        _bucket(),
                        *extra_resources,
                        _bucket_iam_member(role=role),
                    ]
                )

                self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
                path_evidence = _evidence(findings[0])["gcs_mutation_paths"][0]
                self.assertIn(f"role_kind={role_kind}", path_evidence)
                self.assertIn(
                    f"mutation_classes={mutation_classes}",
                    path_evidence,
                )
                if role_kind == "custom":
                    self.assertIn(
                        "matched_permissions=storage.objects.create,storage.objects.delete,storage.objects.get",
                        path_evidence,
                    )

    def test_read_only_conditional_private_and_non_public_paths_remain_quiet(self) -> None:
        condition = {
            "title": "orders-prefix",
            "expression": ("resource.name.startsWith('projects/_/buckets/tfstride-orders-data/objects/orders/')"),
        }
        cases = {
            "read only": [
                _cloud_run(),
                _public_invoker(),
                _bucket(),
                _bucket_iam_member(role="roles/storage.objectViewer"),
            ],
            "conditional bucket grant": [
                _cloud_run(),
                _public_invoker(),
                _bucket(),
                _bucket_iam_member(
                    role="roles/storage.objectCreator",
                    condition=condition,
                ),
            ],
            "conditional public invoker": [
                _cloud_run(),
                _public_invoker(
                    condition={
                        "title": "temporary",
                        "expression": "request.time < timestamp('2027-01-01T00:00:00Z')",
                    }
                ),
                _bucket(),
                _bucket_iam_member(role="roles/storage.objectCreator"),
            ],
            "private ingress": [
                _cloud_run(public_ingress=False),
                _public_invoker(),
                _bucket(),
                _bucket_iam_member(role="roles/storage.objectCreator"),
            ],
            "non-public invoker": [
                _cloud_run(),
                _public_invoker(member="serviceAccount:caller@tfstride-demo.iam.gserviceaccount.com"),
                _bucket(),
                _bucket_iam_member(role="roles/storage.objectCreator"),
            ],
            "unresolved custom role": [
                _cloud_run(),
                _public_invoker(),
                _bucket(),
                _bucket_iam_member(role=f"projects/{_PROJECT}/roles/externalStorageRole"),
            ],
        }

        for case, resources in cases.items():
            with self.subTest(case=case):
                _, _, findings = _evaluate(resources)
                self.assertEqual(findings, [])

    def test_write_only_path_does_not_emit_sensitive_data_disclosure_finding(self) -> None:
        _, _, findings = _evaluate(
            [
                _cloud_run(),
                _public_invoker(),
                _bucket(),
                _bucket_iam_member(role="roles/storage.objectCreator"),
            ],
            _RULE_ID,
            _DISCLOSURE_RULE_ID,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])


if __name__ == "__main__":
    unittest.main()
