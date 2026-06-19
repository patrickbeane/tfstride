from __future__ import annotations

import unittest

from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.gcp.normalizer import GcpNormalizer


def _resource(address: str, resource_type: str, values: dict[str, object]) -> TerraformResource:
    return TerraformResource(
        address=address,
        mode="managed",
        resource_type=resource_type,
        name=address.rsplit(".", 1)[-1],
        provider_name="registry.terraform.io/hashicorp/google",
        values=values,
    )


def _org_policy_policy(
    address: str,
    *,
    constraint: str,
    parent: str = "projects/tfstride-demo",
    enforced: bool | None = None,
    inherit_from_parent: bool | None = None,
    restore_default: bool | None = None,
    allowed_values: list[str] | None = None,
    denied_values: list[str] | None = None,
) -> TerraformResource:
    rule: dict[str, object] = {}
    if enforced is not None:
        rule["enforce"] = enforced
    values: dict[str, object] = {}
    if allowed_values is not None:
        values["allowed_values"] = allowed_values
    if denied_values is not None:
        values["denied_values"] = denied_values
    if values:
        rule["values"] = [values]
    spec: dict[str, object] = {"rules": [rule]}
    if inherit_from_parent is not None:
        spec["inherit_from_parent"] = inherit_from_parent
    resource_values: dict[str, object] = {
        "name": f"{parent}/policies/{constraint}",
        "parent": parent,
        "spec": [spec],
    }
    if restore_default is not None:
        resource_values["reset"] = restore_default
    return _resource(address, "google_org_policy_policy", resource_values)


def _legacy_project_org_policy(
    address: str,
    *,
    constraint: str,
    enforced: bool = True,
) -> TerraformResource:
    return _resource(
        address,
        "google_project_organization_policy",
        {
            "project": "tfstride-demo",
            "constraint": constraint,
            "boolean_policy": [{"enforced": enforced}],
        },
    )


def _storage_bucket(public_access_prevention: str = "inherited") -> TerraformResource:
    return _resource(
        "google_storage_bucket.logs",
        "google_storage_bucket",
        {
            "name": "tfstride-logs",
            "project": "tfstride-demo",
            "location": "US",
            "public_access_prevention": public_access_prevention,
            "uniform_bucket_level_access": True,
        },
    )


def _storage_bucket_iam_member(member: str = "allUsers") -> TerraformResource:
    return _resource(
        "google_storage_bucket_iam_member.public_logs_reader",
        "google_storage_bucket_iam_member",
        {
            "bucket": "google_storage_bucket.logs.name",
            "role": "roles/storage.objectViewer",
            "member": member,
        },
    )


def _compute_instance_os_login_disabled() -> TerraformResource:
    return _resource(
        "google_compute_instance.app",
        "google_compute_instance",
        {
            "name": "tfstride-app",
            "project": "tfstride-demo",
            "metadata": {"enable-oslogin": "false"},
        },
    )


def _project_iam_member(member: str = "allUsers") -> TerraformResource:
    return _resource(
        "google_project_iam_member.public_viewer",
        "google_project_iam_member",
        {
            "project": "tfstride-demo",
            "role": "roles/viewer",
            "member": member,
        },
    )


def _service_account() -> TerraformResource:
    email = "tfstride-deploy@tfstride-demo.iam.gserviceaccount.com"
    return _resource(
        "google_service_account.deploy",
        "google_service_account",
        {
            "account_id": "tfstride-deploy",
            "email": email,
            "name": f"projects/tfstride-demo/serviceAccounts/{email}",
            "project": "tfstride-demo",
        },
    )


def _service_account_key() -> TerraformResource:
    return _resource(
        "google_service_account_key.deploy",
        "google_service_account_key",
        {
            "name": "projects/tfstride-demo/serviceAccounts/tfstride-deploy@tfstride-demo.iam.gserviceaccount.com/keys/key-id",
            "service_account_id": "google_service_account.deploy.name",
            "key_algorithm": "KEY_ALG_RSA_2048",
            "public_key_type": "TYPE_X509_PEM_FILE",
            "valid_after": "2026-01-01T00:00:00Z",
            "valid_before": "2027-01-01T00:00:00Z",
            "keepers": {},
        },
    )


def _findings_for(resources: list[TerraformResource], enabled_rule_ids: set[str]):
    inventory = GcpNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(enabled_rule_ids)),
    )


def _evidence_by_key(finding):
    return {item.key: item.values for item in finding.evidence}


class GcpOrgPolicyScenarioTests(unittest.TestCase):
    def test_enforced_guardrails_annotate_and_adjust_multiple_finding_types(self) -> None:
        findings = _findings_for(
            [
                _org_policy_policy(
                    "google_org_policy_policy.storage_pap",
                    constraint="constraints/storage.publicAccessPrevention",
                    enforced=True,
                ),
                _org_policy_policy(
                    "google_org_policy_policy.require_os_login",
                    constraint="constraints/compute.requireOsLogin",
                    enforced=True,
                ),
                _org_policy_policy(
                    "google_org_policy_policy.disable_sa_keys",
                    constraint="constraints/iam.disableServiceAccountKeyCreation",
                    enforced=True,
                ),
                _org_policy_policy(
                    "google_org_policy_policy.allowed_domains",
                    constraint="constraints/iam.allowedPolicyMemberDomains",
                    allowed_values=["C01abcd"],
                ),
                _storage_bucket(),
                _storage_bucket_iam_member(),
                _compute_instance_os_login_disabled(),
                _project_iam_member(),
                _service_account(),
                _service_account_key(),
            ],
            {
                "gcp-gcs-public-access",
                "gcp-gcs-public-access-prevention-not-enforced",
                "gcp-compute-os-login-disabled",
                "gcp-project-iam-broad-principal",
                "gcp-service-account-key-hygiene",
            },
        )

        findings_by_rule = {finding.rule_id: finding for finding in findings}

        self.assertEqual(
            set(findings_by_rule),
            {
                "gcp-gcs-public-access",
                "gcp-gcs-public-access-prevention-not-enforced",
                "gcp-compute-os-login-disabled",
                "gcp-project-iam-broad-principal",
                "gcp-service-account-key-hygiene",
            },
        )
        self.assertEqual(
            {rule_id: finding.severity.value for rule_id, finding in findings_by_rule.items()},
            {
                "gcp-gcs-public-access": "low",
                "gcp-gcs-public-access-prevention-not-enforced": "low",
                "gcp-compute-os-login-disabled": "low",
                "gcp-project-iam-broad-principal": "low",
                "gcp-service-account-key-hygiene": "low",
            },
        )
        self.assertEqual(findings_by_rule["gcp-gcs-public-access"].severity_reasoning.final_score, 2)
        self.assertEqual(
            findings_by_rule["gcp-gcs-public-access-prevention-not-enforced"].severity_reasoning.final_score,
            2,
        )
        self.assertEqual(findings_by_rule["gcp-compute-os-login-disabled"].severity_reasoning.final_score, 0)
        self.assertEqual(findings_by_rule["gcp-project-iam-broad-principal"].severity_reasoning.final_score, 1)
        self.assertEqual(findings_by_rule["gcp-service-account-key-hygiene"].severity_reasoning.final_score, 1)

        for finding in findings:
            self.assertIn("organization_guardrails", _evidence_by_key(finding))

    def test_restore_default_policy_is_evidence_but_not_a_severity_mitigation(self) -> None:
        findings = _findings_for(
            [
                _org_policy_policy(
                    "google_org_policy_policy.storage_pap_reset",
                    constraint="constraints/storage.publicAccessPrevention",
                    restore_default=True,
                ),
                _storage_bucket(),
            ],
            {"gcp-gcs-public-access-prevention-not-enforced"},
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        evidence = _evidence_by_key(finding)

        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(finding.severity_reasoning.final_score, 3)
        self.assertEqual(
            evidence["organization_guardrails"],
            [
                "constraint=constraints/storage.publicAccessPrevention; "
                "scope=project:tfstride-demo; "
                "source=google_org_policy_policy.storage_pap_reset; "
                "restore_default=true"
            ],
        )

    def test_child_policy_replaces_inherited_org_policy_for_project_findings(self) -> None:
        findings = _findings_for(
            [
                _org_policy_policy(
                    "google_org_policy_policy.org_allowed_domains",
                    constraint="constraints/iam.allowedPolicyMemberDomains",
                    parent="organizations/1234567890",
                    allowed_values=["C01abcd"],
                ),
                _org_policy_policy(
                    "google_org_policy_policy.project_allowed_domains",
                    constraint="constraints/iam.allowedPolicyMemberDomains",
                    inherit_from_parent=False,
                    allowed_values=["C02wxyz"],
                ),
                _project_iam_member(),
            ],
            {"gcp-project-iam-broad-principal"},
        )

        self.assertEqual(len(findings), 1)
        evidence = _evidence_by_key(findings[0])

        self.assertEqual(findings[0].severity.value, "low")
        self.assertEqual(
            evidence["organization_guardrails"],
            [
                "constraint=constraints/iam.allowedPolicyMemberDomains; "
                "scope=project:tfstride-demo; "
                "source=google_org_policy_policy.project_allowed_domains; "
                "inherit_from_parent=false; "
                "allowed_values=C02wxyz"
            ],
        )

    def test_legacy_project_organization_policy_resources_apply_to_findings(self) -> None:
        findings = _findings_for(
            [
                _legacy_project_org_policy(
                    "google_project_organization_policy.storage_pap",
                    constraint="constraints/storage.publicAccessPrevention",
                ),
                _storage_bucket(),
            ],
            {"gcp-gcs-public-access-prevention-not-enforced"},
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        evidence = _evidence_by_key(finding)

        self.assertEqual(finding.severity.value, "low")
        self.assertEqual(finding.severity_reasoning.final_score, 2)
        self.assertEqual(
            evidence["organization_guardrails"],
            [
                "constraint=constraints/storage.publicAccessPrevention; "
                "scope=project:tfstride-demo; "
                "source=google_project_organization_policy.storage_pap; "
                "enforced=true"
            ],
        )


if __name__ == "__main__":
    unittest.main()
