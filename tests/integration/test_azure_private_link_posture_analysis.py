from __future__ import annotations

import unittest
from collections import Counter, defaultdict

from tests.integration.analysis_support import AZURE_PRIVATE_LINK_POSTURE_FIXTURE_PATH
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.app import TfStride
from tfstride.models import AnalysisResult, Finding
from tfstride.providers.azure.private_endpoint_index import build_azure_private_endpoint_index
from tfstride.reporting.markdown import render_markdown

_PRIVATE_LINK_RULE_IDS = frozenset(
    {
        "azure-storage-account-missing-private-endpoint",
        "azure-key-vault-missing-private-endpoint",
        "azure-sql-missing-private-endpoint",
        "azure-private-endpoint-public-fallback",
        "azure-private-endpoint-dns-posture-incomplete",
    }
)


def _analyze_private_link_fixture() -> AnalysisResult:
    return TfStride(rule_policy=RulePolicy(enabled_rule_ids=_PRIVATE_LINK_RULE_IDS)).analyze_plan(
        AZURE_PRIVATE_LINK_POSTURE_FIXTURE_PATH
    )


def _findings_by_rule(result: AnalysisResult) -> dict[str, list[Finding]]:
    findings_by_rule: dict[str, list[Finding]] = defaultdict(list)
    for finding in result.findings:
        findings_by_rule[finding.rule_id].append(finding)
    return findings_by_rule


def _evidence_by_key(finding: Finding) -> dict[str, list[str]]:
    return {item.key: item.values for item in finding.evidence}


def _target_address(finding: Finding) -> str:
    for value in _evidence_by_key(finding).get("target_resource", []):
        if value.startswith("address="):
            return value.removeprefix("address=")
    raise AssertionError(f"finding {finding.rule_id} has no target_resource address evidence")


def _target_addresses(findings: list[Finding]) -> list[str]:
    return [_target_address(finding) for finding in findings]


class AzurePrivateLinkPostureAnalysisTests(unittest.TestCase):
    def test_private_link_posture_fixture_emits_expected_findings(self) -> None:
        result = _analyze_private_link_fixture()

        self.assertEqual(result.inventory.provider, "azure")
        self.assertEqual(len(result.inventory.resources), 13)
        self.assertEqual(result.inventory.unsupported_resources, [])
        self.assertEqual(
            Counter(finding.rule_id for finding in result.findings),
            Counter(
                {
                    "azure-storage-account-missing-private-endpoint": 2,
                    "azure-private-endpoint-public-fallback": 2,
                    "azure-private-endpoint-dns-posture-incomplete": 4,
                    "azure-key-vault-missing-private-endpoint": 1,
                    "azure-sql-missing-private-endpoint": 1,
                }
            ),
        )
        self.assertEqual(
            Counter(finding.severity.value for finding in result.findings),
            Counter({"medium": 5, "low": 5}),
        )

    def test_storage_private_endpoint_cases_are_distinguished(self) -> None:
        result = _analyze_private_link_fixture()
        findings_by_rule = _findings_by_rule(result)

        storage_missing_targets = _target_addresses(findings_by_rule["azure-storage-account-missing-private-endpoint"])
        self.assertEqual(
            storage_missing_targets,
            [
                "azurerm_storage_account.public_no_pe",
                "azurerm_storage_account.unresolved_target",
            ],
        )

        fallback_by_target = {
            _target_address(finding): finding for finding in findings_by_rule["azure-private-endpoint-public-fallback"]
        }
        storage_fallback = fallback_by_target["azurerm_storage_account.pe_public"]
        storage_fallback_evidence = _evidence_by_key(storage_fallback)
        self.assertEqual(storage_fallback.severity.value, "medium")
        self.assertEqual(
            storage_fallback.affected_resources,
            ["azurerm_storage_account.pe_public", "azurerm_private_endpoint.storage_pe_public"],
        )
        self.assertEqual(
            storage_fallback_evidence["private_endpoints"],
            ["azurerm_private_endpoint.storage_pe_public"],
        )
        self.assertEqual(storage_fallback_evidence["private_endpoint_subresources"], ["blob"])
        self.assertNotIn("azurerm_storage_account.pe_public", storage_missing_targets)
        self.assertNotIn("azurerm_storage_account.pe_private", storage_missing_targets)

    def test_key_vault_and_sql_private_endpoint_cases_are_distinguished(self) -> None:
        result = _analyze_private_link_fixture()
        findings_by_rule = _findings_by_rule(result)

        self.assertEqual(
            _target_addresses(findings_by_rule["azure-key-vault-missing-private-endpoint"]),
            ["azurerm_key_vault.public_no_pe"],
        )
        self.assertEqual(
            _target_addresses(findings_by_rule["azure-sql-missing-private-endpoint"]),
            ["azurerm_mssql_server.public_no_pe"],
        )

        fallback_by_target = {
            _target_address(finding): finding for finding in findings_by_rule["azure-private-endpoint-public-fallback"]
        }
        key_vault_fallback = fallback_by_target["azurerm_key_vault.pe_unknown"]
        key_vault_evidence = _evidence_by_key(key_vault_fallback)
        self.assertEqual(key_vault_fallback.severity.value, "low")
        self.assertIn("public_network_fallback_state=unknown", key_vault_evidence["public_network_fallback"])
        self.assertEqual(
            key_vault_evidence["fallback_uncertainty"],
            ["public_network_access_enabled is unknown after planning"],
        )
        self.assertEqual(
            key_vault_evidence["private_endpoints"],
            ["azurerm_private_endpoint.key_vault_pe_unknown"],
        )
        self.assertEqual(key_vault_evidence["private_endpoint_subresources"], ["vault"])
        self.assertNotEqual(key_vault_fallback.severity.value, "high")
        self.assertNotIn(
            "azurerm_mssql_server.pe_private",
            _target_addresses(findings_by_rule["azure-sql-missing-private-endpoint"]),
        )

    def test_private_endpoint_dns_posture_cases_are_distinguished(self) -> None:
        result = _analyze_private_link_fixture()
        findings_by_rule = _findings_by_rule(result)

        dns_findings = findings_by_rule["azure-private-endpoint-dns-posture-incomplete"]
        self.assertEqual(
            _target_addresses(dns_findings),
            [
                "azurerm_storage_account.pe_public",
                "azurerm_storage_account.pe_private",
                "azurerm_key_vault.pe_unknown",
                "azurerm_mssql_server.pe_private",
            ],
        )
        for finding in dns_findings:
            evidence = _evidence_by_key(finding)
            self.assertEqual(finding.severity.value, "low")
            self.assertEqual(
                evidence["private_endpoint_dns_posture"],
                [f"{finding.affected_resources[1]}: no private_dns_zone_group blocks are represented"],
            )

    def test_unresolved_private_endpoint_target_does_not_create_relationship(self) -> None:
        result = _analyze_private_link_fixture()
        findings_by_rule = _findings_by_rule(result)
        fallback_private_endpoint_addresses = {
            value
            for finding in findings_by_rule["azure-private-endpoint-public-fallback"]
            for value in _evidence_by_key(finding).get("private_endpoints", [])
        }

        self.assertNotIn("azurerm_private_endpoint.unresolved_target", fallback_private_endpoint_addresses)
        self.assertIn(
            "azurerm_storage_account.unresolved_target",
            _target_addresses(findings_by_rule["azure-storage-account-missing-private-endpoint"]),
        )

        index = build_azure_private_endpoint_index(result.inventory)
        self.assertEqual(len(index.unresolved_targets), 1)
        self.assertEqual(
            index.unresolved_targets[0].private_endpoint_address, "azurerm_private_endpoint.unresolved_target"
        )
        self.assertEqual(index.unresolved_targets[0].target_resource_id, "${data.azurerm_storage_account.external.id}")

    def test_private_link_posture_report_is_deterministic(self) -> None:
        engine = TfStride(rule_policy=RulePolicy(enabled_rule_ids=_PRIVATE_LINK_RULE_IDS))

        first = render_markdown(engine.analyze_plan(AZURE_PRIVATE_LINK_POSTURE_FIXTURE_PATH))
        second = render_markdown(engine.analyze_plan(AZURE_PRIVATE_LINK_POSTURE_FIXTURE_PATH))

        self.assertEqual(first, second)
        self.assertIn("does not have a resolved private endpoint", first)
        self.assertIn("Private Endpoint coverage does not guarantee private-only access", first)
        self.assertIn("private DNS posture", first)


if __name__ == "__main__":
    unittest.main()
