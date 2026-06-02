from __future__ import annotations

import unittest

from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import TerraformResource
from tfstride.providers.gcp.normalizer import GcpNormalizer



def _compute_network() -> TerraformResource:
    return TerraformResource(
        address="google_compute_network.main",
        mode="managed",
        resource_type="google_compute_network",
        name="main",
        provider_name="registry.terraform.io/hashicorp/google",
        values={"name": "tfstride-main", "id": "google_compute_network.main"},
    )


def _compute_subnetwork() -> TerraformResource:
    return TerraformResource(
        address="google_compute_subnetwork.app",
        mode="managed",
        resource_type="google_compute_subnetwork",
        name="app",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "name": "tfstride-app",
            "id": "google_compute_subnetwork.app",
            "network": "google_compute_network.main.id",
            "ip_cidr_range": "10.10.0.0/24",
        },
    )


def _public_compute_firewall() -> TerraformResource:
    return TerraformResource(
        address="google_compute_firewall.web",
        mode="managed",
        resource_type="google_compute_firewall",
        name="web",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "name": "tfstride-web",
            "network": "google_compute_network.main.id",
            "direction": "INGRESS",
            "source_ranges": ["0.0.0.0/0"],
            "target_tags": ["web"],
            "allow": [{"protocol": "tcp", "ports": ["443"]}],
        },
    )


def _compute_instance(
    *,
    public: bool = True,
    service_account_email: str = "tfstride-web@tfstride-demo.iam.gserviceaccount.com",
    scopes: list[str] | None = None,
) -> TerraformResource:
    network_interface: dict[str, object] = {"subnetwork": "google_compute_subnetwork.app.id"}
    if public:
        network_interface["access_config"] = [{}]
    return TerraformResource(
        address="google_compute_instance.web",
        mode="managed",
        resource_type="google_compute_instance",
        name="web",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "name": "tfstride-web",
            "machine_type": "e2-medium",
            "zone": "us-central1-a",
            "tags": ["web"],
            "network_interface": [network_interface],
            "service_account": [
                {
                    "email": service_account_email,
                    "scopes": scopes or ["https://www.googleapis.com/auth/cloud-platform"],
                }
            ],
        },
    )

def _project_iam_member(role: str, member: str = "serviceAccount:deploy@example.iam.gserviceaccount.com") -> TerraformResource:
    return TerraformResource(
        address="google_project_iam_member.binding",
        mode="managed",
        resource_type="google_project_iam_member",
        name="binding",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "project": "tfstride-demo",
            "role": role,
            "member": member,
        },
    )


def _storage_bucket(
    public_access_prevention: str | None = None,
    *,
    uniform_bucket_level_access: bool = True,
    versioning_enabled: bool = True,
    default_kms_key_name: str | None = "projects/tfstride-demo/locations/global/keyRings/app/cryptoKeys/gcs",
) -> TerraformResource:
    values = {
        "name": "tfstride-logs",
        "location": "US",
        "uniform_bucket_level_access": uniform_bucket_level_access,
        "versioning": [{"enabled": versioning_enabled}],
    }
    if public_access_prevention is not None:
        values["public_access_prevention"] = public_access_prevention
    if default_kms_key_name is not None:
        values["encryption"] = [{"default_kms_key_name": default_kms_key_name}]
    return TerraformResource(
        address="google_storage_bucket.logs",
        mode="managed",
        resource_type="google_storage_bucket",
        name="logs",
        provider_name="registry.terraform.io/hashicorp/google",
        values=values,
    )


def _storage_bucket_iam_member(
    member: str = "allUsers",
    role: str = "roles/storage.objectViewer",
    *,
    bucket: str = "google_storage_bucket.logs.name",
) -> TerraformResource:
    return TerraformResource(
        address="google_storage_bucket_iam_member.public_logs_reader",
        mode="managed",
        resource_type="google_storage_bucket_iam_member",
        name="public_logs_reader",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "bucket": bucket,
            "role": role,
            "member": member,
        },
    )


def _cloud_sql_instance(
    *,
    ipv4_enabled: bool = True,
    authorized_networks: list[dict[str, object]] | None = None,
    backup_enabled: bool = True,
    pitr_enabled: bool = True,
    private_network: str | None = None,
    require_ssl: bool = True,
    ssl_mode: str | None = None,
    deletion_protection: bool = True,
) -> TerraformResource:
    ip_configuration: dict[str, object] = {
        "ipv4_enabled": ipv4_enabled,
        "require_ssl": require_ssl,
        "authorized_networks": authorized_networks if authorized_networks is not None else [],
    }
    if private_network is not None:
        ip_configuration["private_network"] = private_network
    if ssl_mode is not None:
        ip_configuration["ssl_mode"] = ssl_mode
    return TerraformResource(
        address="google_sql_database_instance.app",
        mode="managed",
        resource_type="google_sql_database_instance",
        name="app",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "name": "tfstride-app-db",
            "database_version": "POSTGRES_15",
            "settings": [
                {
                    "backup_configuration": [
                        {
                            "enabled": backup_enabled,
                            "point_in_time_recovery_enabled": pitr_enabled,
                        }
                    ],
                    "ip_configuration": [ip_configuration],
                }
            ],
            "deletion_protection": deletion_protection,
        },
    )


def _secret_manager_secret(project: str = "tfstride-demo") -> TerraformResource:
    return TerraformResource(
        address="google_secret_manager_secret.api_key",
        mode="managed",
        resource_type="google_secret_manager_secret",
        name="api_key",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "secret_id": "tfstride-api-key",
            "id": "projects/tfstride-demo/secrets/tfstride-api-key",
            "project": project,
            "replication": [{"auto": [{}]}],
        },
    )


def _secret_manager_secret_iam_member(
    member: str = "allAuthenticatedUsers",
    role: str = "roles/secretmanager.secretAccessor",
) -> TerraformResource:
    return TerraformResource(
        address="google_secret_manager_secret_iam_member.public_accessor",
        mode="managed",
        resource_type="google_secret_manager_secret_iam_member",
        name="public_accessor",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "secret_id": "google_secret_manager_secret.api_key.id",
            "role": role,
            "member": member,
        },
    )


def _kms_crypto_key() -> TerraformResource:
    return TerraformResource(
        address="google_kms_crypto_key.customer",
        mode="managed",
        resource_type="google_kms_crypto_key",
        name="customer",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "name": "tfstride-customer-key",
            "id": "projects/tfstride-demo/locations/global/keyRings/tfstride-app/cryptoKeys/tfstride-customer-key",
            "key_ring": "projects/tfstride-demo/locations/global/keyRings/tfstride-app",
            "purpose": "ENCRYPT_DECRYPT",
        },
    )


def _kms_crypto_key_iam_member(
    member: str = "serviceAccount:decryptor@partner-project.iam.gserviceaccount.com",
    role: str = "roles/cloudkms.cryptoKeyDecrypter",
) -> TerraformResource:
    return TerraformResource(
        address="google_kms_crypto_key_iam_member.partner_decrypter",
        mode="managed",
        resource_type="google_kms_crypto_key_iam_member",
        name="partner_decrypter",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "crypto_key_id": "google_kms_crypto_key.customer.id",
            "role": role,
            "member": member,
        },
    )


class GcpRuleTests(unittest.TestCase):
    def test_gcs_public_bucket_iam_member_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize([_storage_bucket(), _storage_bucket_iam_member()])

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-gcs-public-access"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-gcs-public-access")
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(finding.affected_resources, ["google_storage_bucket.logs"])
        self.assertIsNone(finding.trust_boundary_id)
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["public_exposure_reasons"],
            [
                "google_storage_bucket_iam_member.public_logs_reader grants "
                "roles/storage.objectViewer to allUsers"
            ],
        )

    def test_gcs_all_authenticated_users_bucket_iam_member_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize(
            [_storage_bucket(), _storage_bucket_iam_member(member="allAuthenticatedUsers")]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-gcs-public-access"})),
        )

        self.assertEqual([finding.rule_id for finding in findings], ["gcp-gcs-public-access"])

    def test_gcs_public_access_prevention_suppresses_public_iam_grant(self) -> None:
        inventory = GcpNormalizer().normalize(
            [_storage_bucket(public_access_prevention="enforced"), _storage_bucket_iam_member()]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-gcs-public-access"})),
        )

        self.assertEqual(findings, [])

    def test_gcs_non_public_member_is_not_flagged(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _storage_bucket(),
                _storage_bucket_iam_member(member="serviceAccount:reader@example.iam.gserviceaccount.com"),
            ]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-gcs-public-access"})),
        )

        self.assertEqual(findings, [])

    def test_gcs_uniform_bucket_level_access_disabled_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize([_storage_bucket(uniform_bucket_level_access=False)])

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(
                enabled_rule_ids=frozenset({"gcp-gcs-uniform-bucket-level-access-disabled"})
            ),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-gcs-uniform-bucket-level-access-disabled")
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(finding.affected_resources, ["google_storage_bucket.logs"])
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(evidence["access_control_posture"], ["uniform_bucket_level_access is false"])

    def test_gcs_public_access_prevention_not_enforced_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize([_storage_bucket(public_access_prevention="inherited")])

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(
                enabled_rule_ids=frozenset({"gcp-gcs-public-access-prevention-not-enforced"})
            ),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-gcs-public-access-prevention-not-enforced")
        self.assertEqual(finding.severity.value, "medium")
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(evidence["access_control_posture"], ["public_access_prevention is inherited"])

    def test_gcs_public_access_prevention_enforced_is_not_flagged(self) -> None:
        inventory = GcpNormalizer().normalize([_storage_bucket(public_access_prevention="enforced")])

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(
                enabled_rule_ids=frozenset({"gcp-gcs-public-access-prevention-not-enforced"})
            ),
        )

        self.assertEqual(findings, [])

    def test_gcs_versioning_disabled_is_detected_for_sensitive_bucket(self) -> None:
        inventory = GcpNormalizer().normalize([_storage_bucket(versioning_enabled=False)])

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-gcs-versioning-disabled"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-gcs-versioning-disabled")
        self.assertEqual(finding.severity.value, "medium")
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["data_protection_posture"],
            ["versioning.enabled is false", "data_sensitivity is sensitive"],
        )

    def test_gcs_customer_managed_encryption_missing_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize([_storage_bucket(default_kms_key_name=None)])

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(
                enabled_rule_ids=frozenset({"gcp-gcs-customer-managed-encryption-missing"})
            ),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-gcs-customer-managed-encryption-missing")
        self.assertEqual(finding.severity.value, "medium")
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["encryption_posture"],
            ["default_kms_key_name is unset", "customer_managed_encryption is false"],
        )

    def test_gcs_customer_managed_encryption_is_not_flagged_when_kms_key_is_configured(self) -> None:
        inventory = GcpNormalizer().normalize([_storage_bucket()])

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(
                enabled_rule_ids=frozenset({"gcp-gcs-customer-managed-encryption-missing"})
            ),
        )

        self.assertEqual(findings, [])

    def test_cloud_sql_public_authorized_network_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _cloud_sql_instance(
                    authorized_networks=[{"name": "anywhere", "value": "0.0.0.0/0"}],
                )
            ]
        )
        boundaries = detect_trust_boundaries(inventory)

        findings = StrideRuleEngine().evaluate(
            inventory,
            boundaries,
            rule_policy=RulePolicy(
                enabled_rule_ids=frozenset({"gcp-cloud-sql-public-authorized-network"})
            ),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-cloud-sql-public-authorized-network")
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(finding.affected_resources, ["google_sql_database_instance.app"])
        self.assertEqual(
            finding.trust_boundary_id,
            "internet-to-service:internet->google_sql_database_instance.app",
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(evidence["authorized_networks"], ["anywhere (0.0.0.0/0)"])
        self.assertEqual(
            evidence["public_exposure_reasons"],
            ["authorized network `anywhere` allows 0.0.0.0/0"],
        )

    def test_cloud_sql_backup_disabled_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _cloud_sql_instance(
                    ipv4_enabled=False,
                    backup_enabled=False,
                    pitr_enabled=False,
                    private_network="google_compute_network.main.id",
                )
            ]
        )

        findings = StrideRuleEngine().evaluate(inventory, [])

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-cloud-sql-backup-disabled")
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(finding.affected_resources, ["google_sql_database_instance.app"])
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["backup_posture"],
            [
                "backup_configuration.enabled is false",
                "point_in_time_recovery_enabled is false",
                "engine is POSTGRES_15",
            ],
        )

    def test_private_backed_up_cloud_sql_instance_is_not_flagged(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _cloud_sql_instance(
                    ipv4_enabled=False,
                    backup_enabled=True,
                    pitr_enabled=True,
                    private_network="google_compute_network.main.id",
                )
            ]
        )

        findings = StrideRuleEngine().evaluate(inventory, [])

        self.assertEqual(findings, [])


    def test_cloud_sql_public_ip_without_private_network_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize([_cloud_sql_instance(ipv4_enabled=True, private_network=None)])

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(
                enabled_rule_ids=frozenset({"gcp-cloud-sql-public-ip-without-private-network"})
            ),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-cloud-sql-public-ip-without-private-network")
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(finding.affected_resources, ["google_sql_database_instance.app"])
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["network_posture"],
            [
                "ipv4_enabled is true",
                "private_network is unset",
                "authorized_networks configured: 0",
            ],
        )
        self.assertEqual(
            evidence["public_access_reasons"],
            ["Cloud SQL public IPv4 access is enabled"],
        )

    def test_cloud_sql_private_network_suppresses_public_ip_without_private_network(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _cloud_sql_instance(
                    ipv4_enabled=True,
                    private_network="google_compute_network.main.id",
                )
            ]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(
                enabled_rule_ids=frozenset({"gcp-cloud-sql-public-ip-without-private-network"})
            ),
        )

        self.assertEqual(findings, [])

    def test_cloud_sql_ssl_not_required_is_detected_for_public_ipv4(self) -> None:
        inventory = GcpNormalizer().normalize([_cloud_sql_instance(require_ssl=False)])

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-cloud-sql-ssl-not-required"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-cloud-sql-ssl-not-required")
        self.assertEqual(finding.severity.value, "medium")
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["ssl_posture"],
            ["require_ssl is false", "ssl_mode is unset", "ipv4_enabled is true"],
        )

    def test_cloud_sql_enforcing_ssl_mode_is_not_flagged(self) -> None:
        inventory = GcpNormalizer().normalize(
            [_cloud_sql_instance(require_ssl=False, ssl_mode="ENCRYPTED_ONLY")]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-cloud-sql-ssl-not-required"})),
        )

        self.assertEqual(findings, [])

    def test_cloud_sql_point_in_time_recovery_disabled_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _cloud_sql_instance(
                    ipv4_enabled=False,
                    backup_enabled=True,
                    pitr_enabled=False,
                    private_network="google_compute_network.main.id",
                )
            ]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(
                enabled_rule_ids=frozenset({"gcp-cloud-sql-point-in-time-recovery-disabled"})
            ),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-cloud-sql-point-in-time-recovery-disabled")
        self.assertEqual(finding.severity.value, "medium")
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["backup_posture"],
            [
                "backup_configuration.enabled is true",
                "point_in_time_recovery_enabled is false",
                "engine is POSTGRES_15",
            ],
        )

    def test_cloud_sql_deletion_protection_disabled_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _cloud_sql_instance(
                    ipv4_enabled=False,
                    private_network="google_compute_network.main.id",
                    deletion_protection=False,
                )
            ]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(
                enabled_rule_ids=frozenset({"gcp-cloud-sql-deletion-protection-disabled"})
            ),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-cloud-sql-deletion-protection-disabled")
        self.assertEqual(finding.severity.value, "medium")
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(evidence["lifecycle_posture"], ["deletion_protection is false"])


    def test_sensitive_secret_public_iam_binding_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize(
            [_secret_manager_secret(), _secret_manager_secret_iam_member()]
        )

        findings = StrideRuleEngine().evaluate(inventory, [])

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-sensitive-resource-iam-external-access")
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(
            finding.affected_resources,
            [
                "google_secret_manager_secret.api_key",
                "google_secret_manager_secret_iam_member.public_accessor",
            ],
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["iam_binding"],
            [
                "source=google_secret_manager_secret_iam_member.public_accessor",
                "role=roles/secretmanager.secretAccessor",
                "member=allAuthenticatedUsers",
            ],
        )
        self.assertEqual(evidence["trust_scope"], ["member is public GCP principal `allAuthenticatedUsers`"])

    def test_sensitive_kms_foreign_service_account_binding_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize([_kms_crypto_key(), _kms_crypto_key_iam_member()])

        findings = StrideRuleEngine().evaluate(inventory, [])

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-sensitive-resource-iam-external-access")
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(
            finding.affected_resources,
            ["google_kms_crypto_key.customer", "google_kms_crypto_key_iam_member.partner_decrypter"],
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["trust_scope"],
            ["service account belongs to project `partner-project`, outside resource project `tfstride-demo`"],
        )

    def test_sensitive_same_project_service_account_binding_is_not_flagged(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _kms_crypto_key(),
                _kms_crypto_key_iam_member(
                    member="serviceAccount:decryptor@tfstride-demo.iam.gserviceaccount.com"
                ),
            ]
        )

        findings = StrideRuleEngine().evaluate(inventory, [])

        self.assertEqual(findings, [])


    def test_public_compute_service_account_secret_access_path_is_detected(self) -> None:
        service_account = "serviceAccount:tfstride-web@tfstride-demo.iam.gserviceaccount.com"
        inventory = GcpNormalizer().normalize(
            [
                _compute_network(),
                _compute_subnetwork(),
                _public_compute_firewall(),
                _compute_instance(),
                _secret_manager_secret(),
                _secret_manager_secret_iam_member(member=service_account),
            ]
        )
        boundaries = detect_trust_boundaries(inventory)

        findings = StrideRuleEngine().evaluate(
            inventory,
            boundaries,
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-public-workload-sensitive-data-access"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-public-workload-sensitive-data-access")
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(
            finding.affected_resources,
            [
                "google_compute_instance.web",
                "google_secret_manager_secret.api_key",
                "google_secret_manager_secret_iam_member.public_accessor",
            ],
        )
        self.assertEqual(
            finding.trust_boundary_id,
            "workload-to-data-store:google_compute_instance.web->google_secret_manager_secret.api_key",
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(evidence["workload_identity"], [service_account])
        self.assertEqual(
            evidence["data_access_path"],
            ["google_compute_instance.web reaches google_secret_manager_secret.api_key"],
        )
        self.assertIn(
            "google_secret_manager_secret_iam_member.public_accessor grants roles/secretmanager.secretAccessor",
            evidence["boundary_rationale"][0],
        )

    def test_project_iam_kms_access_path_is_detected_for_public_compute(self) -> None:
        service_account = "serviceAccount:tfstride-web@tfstride-demo.iam.gserviceaccount.com"
        inventory = GcpNormalizer().normalize(
            [
                _compute_network(),
                _compute_subnetwork(),
                _public_compute_firewall(),
                _compute_instance(),
                _kms_crypto_key(),
                _project_iam_member("roles/cloudkms.cryptoKeyDecrypter", member=service_account),
            ]
        )
        boundaries = detect_trust_boundaries(inventory)

        findings = StrideRuleEngine().evaluate(
            inventory,
            boundaries,
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-public-workload-sensitive-data-access"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.affected_resources, ["google_compute_instance.web", "google_kms_crypto_key.customer"])
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertIn(
            "google_project_iam_member.binding grants roles/cloudkms.cryptoKeyDecrypter",
            evidence["boundary_rationale"][0],
        )

    def test_private_compute_sensitive_data_path_is_not_reported(self) -> None:
        service_account = "serviceAccount:tfstride-web@tfstride-demo.iam.gserviceaccount.com"
        inventory = GcpNormalizer().normalize(
            [
                _compute_network(),
                _compute_subnetwork(),
                _compute_instance(public=False),
                _secret_manager_secret(),
                _secret_manager_secret_iam_member(member=service_account),
            ]
        )
        boundaries = detect_trust_boundaries(inventory)

        findings = StrideRuleEngine().evaluate(
            inventory,
            boundaries,
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-public-workload-sensitive-data-access"})),
        )

        self.assertEqual(findings, [])

    def test_public_compute_to_private_cloud_sql_path_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _compute_network(),
                _compute_subnetwork(),
                _public_compute_firewall(),
                _compute_instance(),
                _cloud_sql_instance(
                    ipv4_enabled=False,
                    private_network="google_compute_network.main.id",
                ),
            ]
        )
        boundaries = detect_trust_boundaries(inventory)

        findings = StrideRuleEngine().evaluate(
            inventory,
            boundaries,
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-public-workload-sensitive-data-access"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(
            finding.affected_resources,
            ["google_compute_instance.web", "google_sql_database_instance.app"],
        )
        self.assertEqual(
            finding.trust_boundary_id,
            "workload-to-data-store:google_compute_instance.web->google_sql_database_instance.app",
        )

    def test_project_iam_broad_principal_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _project_iam_member(
                    "roles/viewer",
                    member="allUsers",
                )
            ]
        )

        findings = StrideRuleEngine().evaluate(inventory, [])

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-project-iam-broad-principal")
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(finding.affected_resources, ["google_project_iam_member.binding"])
        self.assertIsNone(finding.trust_boundary_id)
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(evidence["iam_binding"], ["member=allUsers", "role=roles/viewer"])

    def test_project_iam_privileged_role_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize([_project_iam_member("roles/owner")])

        findings = StrideRuleEngine().evaluate(inventory, [])

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-project-iam-privileged-role")
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(finding.affected_resources, ["google_project_iam_member.binding"])
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["iam_binding"],
            ["member=serviceAccount:deploy@example.iam.gserviceaccount.com", "role=roles/owner"],
        )
        self.assertEqual(evidence["role_risk"], ["full project administration"])

    def test_project_iam_admin_class_role_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize([_project_iam_member("roles/compute.admin")])

        findings = StrideRuleEngine().evaluate(inventory, [])

        self.assertEqual([finding.rule_id for finding in findings], ["gcp-project-iam-privileged-role"])
        evidence = {item.key: item.values for item in findings[0].evidence}
        self.assertEqual(
            evidence["role_risk"],
            ["admin-level control over a GCP service or project security surface"],
        )

    def test_public_principal_with_privileged_role_reports_both_iam_findings(self) -> None:
        inventory = GcpNormalizer().normalize([_project_iam_member("roles/owner", member="allUsers")])

        findings = StrideRuleEngine().evaluate(inventory, [])

        self.assertEqual(
            {finding.rule_id for finding in findings},
            {"gcp-project-iam-privileged-role", "gcp-project-iam-broad-principal"},
        )

    def test_project_iam_viewer_service_account_is_not_flagged(self) -> None:
        inventory = GcpNormalizer().normalize([_project_iam_member("roles/viewer")])

        findings = StrideRuleEngine().evaluate(inventory, [])

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()