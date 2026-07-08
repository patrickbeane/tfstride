from __future__ import annotations

import ast
import unittest
from pathlib import Path

from tests.providers.gcp.rule_support.compute import (
    _compute_instance,
    _compute_network,
    _compute_subnetwork,
    _gke_cluster,
    _public_compute_firewall,
)
from tests.providers.gcp.rule_support.data import (
    _cloud_sql_instance,
    _secret_manager_secret,
    _secret_manager_secret_iam_member,
    _storage_bucket,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import TerraformResource
from tfstride.providers.gcp.normalizer import GcpNormalizer


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _imports_from(path: Path, package_prefix: str) -> list[tuple[str, str]]:
    tree = ast.parse(path.read_text(), filename=str(path))
    imports: list[tuple[str, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == package_prefix or alias.name.startswith(f"{package_prefix}."):
                    imports.append((alias.name, alias.asname or ""))
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            if node.module == package_prefix or node.module.startswith(f"{package_prefix}."):
                for alias in node.names:
                    imports.append((node.module, alias.name))
    return imports


def _relative(path: Path) -> str:
    return path.relative_to(_repo_root()).as_posix()


def _evidence_by_key(finding):
    return {item.key: item.values for item in finding.evidence}


def _evaluate(resources: list[TerraformResource], rule_id: str):
    inventory = GcpNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        detect_trust_boundaries(inventory),
        rule_policy=RulePolicy(enabled_rule_ids=frozenset({rule_id})),
    )


class GcpProviderFactBoundaryCharacterizationTests(unittest.TestCase):
    def test_storage_rule_keeps_provider_fact_evidence_shape(self) -> None:
        findings = _evaluate([_storage_bucket(versioning_enabled=False)], "gcp-gcs-versioning-disabled")

        self.assertEqual([finding.rule_id for finding in findings], ["gcp-gcs-versioning-disabled"])
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["data_protection_posture"],
            ["versioning.enabled is false", "data_sensitivity is sensitive"],
        )

    def test_compute_rule_keeps_provider_fact_evidence_shape(self) -> None:
        findings = _evaluate(
            [
                _compute_network(),
                TerraformResource(
                    address="google_compute_firewall.admin",
                    mode="managed",
                    resource_type="google_compute_firewall",
                    name="admin",
                    provider_name="registry.terraform.io/hashicorp/google",
                    values={
                        "name": "tfstride-admin",
                        "network": "google_compute_network.main.name",
                        "direction": "INGRESS",
                        "source_ranges": ["0.0.0.0/0"],
                        "target_tags": ["web"],
                        "allow": [{"protocol": "tcp", "ports": ["22"]}],
                    },
                ),
                TerraformResource(
                    address="google_compute_instance.web",
                    mode="managed",
                    resource_type="google_compute_instance",
                    name="web",
                    provider_name="registry.terraform.io/hashicorp/google",
                    values={
                        "name": "tfstride-web",
                        "tags": ["web"],
                        "network_interface": [{"network": "google_compute_network.main.id", "access_config": [{}]}],
                    },
                ),
            ],
            "gcp-public-compute-broad-ingress",
        )

        self.assertEqual([finding.rule_id for finding in findings], ["gcp-public-compute-broad-ingress"])
        self.assertEqual(
            findings[0].trust_boundary_id,
            "internet-to-service:internet->google_compute_instance.web",
        )
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["internet_ingress_reasons"],
            ["google_compute_firewall.admin ingress tcp 22 from 0.0.0.0/0"],
        )
        self.assertEqual(
            evidence["public_exposure_reasons"],
            ["compute instance has an external access config and matching firewall rules allow internet ingress"],
        )

    def test_gke_rule_keeps_provider_fact_evidence_shape(self) -> None:
        findings = _evaluate(
            [
                _gke_cluster(
                    authorized_networks=[{"display_name": "anywhere", "cidr_block": "0.0.0.0/0"}],
                    metadata_mode="GKE_METADATA",
                )
            ],
            "gcp-gke-broad-authorized-networks",
        )

        self.assertEqual([finding.rule_id for finding in findings], ["gcp-gke-broad-authorized-networks"])
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(evidence["authorized_networks"], ["anywhere (0.0.0.0/0)"])
        self.assertEqual(evidence["configured_authorized_network_count"], ["1"])

    def test_cloud_sql_rule_keeps_provider_fact_evidence_shape(self) -> None:
        findings = _evaluate(
            [_cloud_sql_instance(authorized_networks=[{"name": "anywhere", "value": "0.0.0.0/0"}])],
            "gcp-cloud-sql-public-authorized-network",
        )

        self.assertEqual([finding.rule_id for finding in findings], ["gcp-cloud-sql-public-authorized-network"])
        self.assertEqual(
            findings[0].trust_boundary_id,
            "internet-to-service:internet->google_sql_database_instance.app",
        )
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(evidence["authorized_networks"], ["anywhere (0.0.0.0/0)"])
        self.assertEqual(
            evidence["public_exposure_reasons"],
            ["authorized network `anywhere` allows 0.0.0.0/0"],
        )

    def test_iam_sensitive_path_rule_keeps_provider_fact_evidence_shape(self) -> None:
        service_account = "serviceAccount:tfstride-web@tfstride-demo.iam.gserviceaccount.com"
        findings = _evaluate(
            [
                _compute_network(),
                _compute_subnetwork(),
                _public_compute_firewall(),
                _compute_instance(),
                _secret_manager_secret(),
                _secret_manager_secret_iam_member(member=service_account),
            ],
            "gcp-public-workload-sensitive-data-access",
        )

        self.assertEqual([finding.rule_id for finding in findings], ["gcp-public-workload-sensitive-data-access"])
        self.assertEqual(
            findings[0].trust_boundary_id,
            "workload-to-data-store:google_compute_instance.web->google_secret_manager_secret.api_key",
        )
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(evidence["workload_identity"], [service_account])
        self.assertEqual(
            evidence["data_access_path"],
            ["google_compute_instance.web reaches google_secret_manager_secret.api_key"],
        )
        self.assertIn(
            "google_secret_manager_secret_iam_member.public_accessor grants roles/secretmanager.secretAccessor",
            evidence["boundary_rationale"][0],
        )


class GcpDetectorOwnershipBoundaryTests(unittest.TestCase):
    def test_analysis_gcp_currently_has_no_direct_provider_imports(self) -> None:
        analysis_dir = _repo_root() / "src" / "tfstride" / "analysis" / "gcp"
        provider_imports = {
            _relative(path): imports
            for path in sorted(analysis_dir.glob("*.py"))
            if (imports := _imports_from(path, "tfstride.providers.gcp"))
        }

        self.assertEqual(provider_imports, {})

    def test_provider_rule_root_documents_analysis_owned_detector_import(self) -> None:
        provider_rule_root = _repo_root() / "src" / "tfstride" / "providers" / "gcp" / "rules.py"

        self.assertEqual(
            _imports_from(provider_rule_root, "tfstride.analysis.gcp"),
            [("tfstride.analysis.gcp.rules", "GcpRuleDetectors")],
        )

    def test_current_analysis_owned_detector_modules_are_pinned(self) -> None:
        analysis_dir = _repo_root() / "src" / "tfstride" / "analysis" / "gcp"
        detector_modules = sorted(
            _relative(path)
            for path in analysis_dir.glob("*.py")
            if path.name.endswith("_rules.py") or path.name in {"rules.py", "iam_inherited.py", "iam_scoped.py"}
        )

        self.assertEqual(
            detector_modules,
            [
                "src/tfstride/analysis/gcp/compute_exposure_rules.py",
                "src/tfstride/analysis/gcp/compute_rules.py",
                "src/tfstride/analysis/gcp/data_rules.py",
                "src/tfstride/analysis/gcp/gke_rules.py",
                "src/tfstride/analysis/gcp/iam_inherited.py",
                "src/tfstride/analysis/gcp/iam_rules.py",
                "src/tfstride/analysis/gcp/iam_scoped.py",
                "src/tfstride/analysis/gcp/rules.py",
                "src/tfstride/analysis/gcp/serverless_rules.py",
            ],
        )


if __name__ == "__main__":
    unittest.main()
