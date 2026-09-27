from __future__ import annotations

import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from tests.providers.azure.test_azure_app_service_key_vault_access_paths import (
    _role_assignment as _secret_grant,
)
from tests.providers.azure.test_azure_app_service_key_vault_access_paths import (
    _secret,
)
from tests.providers.azure.test_azure_app_service_key_vault_access_paths import (
    _vault as _secret_vault,
)
from tests.providers.azure.test_azure_app_service_key_vault_access_paths import (
    _web_app as _secret_app,
)
from tests.providers.azure.test_azure_app_service_key_vault_operation_paths import (
    _key,
    _vault,
)
from tests.providers.azure.test_azure_app_service_key_vault_operation_paths import (
    _role_assignment as _key_grant,
)
from tests.providers.azure.test_azure_app_service_key_vault_operation_paths import (
    _web_app as _key_app,
)
from tests.providers.azure.test_azure_app_service_rules import _app
from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _role_assignment as _storage_grant,
)
from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _storage_account,
)
from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _web_app as _storage_app,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.input.terraform_plan import load_terraform_plan
from tfstride.providers.azure.app_service_access import evaluate_app_service_access
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts

_STORAGE_RULE = "azure-public-app-service-storage-mutation-access"
_KEY_RULE = "azure-public-app-service-key-vault-decrypt-access"
_IDENTITY_RULE = "azure-public-workload-sensitive-resource-access"
_CONFIG_RULE = "azure-app-service-public-network-access-not-disabled"
_AUTH_RULE = "azure-app-service-platform-authentication-disabled"
_ANONYMOUS_RULE = "azure-app-service-anonymous-platform-access-allowed"
_SCM_RULE = "azure-app-service-scm-access-unrestricted"


def _allow(source="8.8.8.0/24", **values):
    return {"name": "partner", "priority": 100, "action": "Allow", "ip_address": source, **values}


def _paths(kind="storage", config=None, unknown=None):
    if kind == "storage":
        app = _storage_app()
        resources = [_storage_account(), app, _storage_grant()]
        rule = _STORAGE_RULE
    else:
        app = _key_app()
        resources = [_vault(rbac_enabled=True), _key(), app, _key_grant(scope="azurerm_key_vault.orders.id")]
        rule = _KEY_RULE
    app.values.update(public_network_access_enabled=True, site_config=[config or {}])
    app.unknown_values.update(unknown or {})
    return resources, app, rule


def _evaluate(resources, *rules):
    inventory = AzureNormalizer().normalize(resources)
    return inventory, _run(inventory, *rules)


def _run(inventory, *rules):
    return StrideRuleEngine().evaluate(inventory, [], rule_policy=RulePolicy(enabled_rule_ids=frozenset(rules)))


def _evidence(finding):
    return {item.key: item.values for item in finding.evidence}


def _decision(finding):
    values = _evidence(finding)["effective_public_ingress"]
    return json.loads(next(value.removeprefix("decision=") for value in values if value.startswith("decision=")))


class AzureAppServiceIngressFindingTests(unittest.TestCase):
    def test_deny_all_suppresses_key_vault_and_storage_findings_but_retains_authorization(self):
        for kind in ("storage", "key"):
            for config in (
                {"ip_restriction_default_action": "Deny"},
                {
                    "ip_restriction_default_action": "Allow",
                    "ip_restriction": [_allow("0.0.0.0/0", action="Deny"), _allow("::/0", action="Deny")],
                },
            ):
                with self.subTest(kind=kind, config=config):
                    resources, app, rule = _paths(kind, config)
                    inventory, findings = _evaluate(resources, rule, _IDENTITY_RULE)
                    self.assertEqual(findings, [])
                    workload = inventory.get_by_address(app.address)
                    facts = azure_facts(workload)
                    self.assertTrue(workload.public_access_configured)
                    paths = (
                        facts.app_service_storage_access_paths
                        if kind == "storage"
                        else facts.app_service_key_vault_operation_paths
                    )
                    self.assertTrue(paths)

    def test_allowlists_retain_exact_sources_and_winning_rule_evidence(self):
        for kind in ("storage", "key"):
            with self.subTest(kind=kind):
                resources, _, rule = _paths(kind, {"ip_restriction": [_allow()]})
                _, findings = _evaluate(resources, rule)
                self.assertEqual(len(findings), 1)
                decision = _decision(findings[0])
                self.assertEqual(decision["state"], "restricted")
                self.assertEqual(decision["external_access"], "allowed")
                self.assertEqual(decision["allowed_source_cidrs"], ["8.8.8.0/24"])
                allowed = next(scope for scope in decision["source_scopes"] if scope["state"] == "allowed")
                self.assertEqual(allowed["rule_indices"], [0])
                self.assertFalse(allowed["default_possible"])
                self.assertEqual(decision["rule_evidence"][0]["name"], "partner")
                self.assertEqual(findings[0].severity_reasoning.internet_exposure, 2)

    def test_default_allow_keeps_surviving_sources_after_partial_denial(self):
        resources, _, rule = _paths(
            config={"ip_restriction_default_action": "Allow", "ip_restriction": [_allow(action="Deny")]}
        )
        _, findings = _evaluate(resources, rule)
        decision = _decision(findings[0])
        self.assertEqual(decision["state"], "restricted")
        self.assertEqual(decision["blocked_source_cidrs"], ["8.8.8.0/24"])
        self.assertEqual(decision["default_action"], "Allow")
        self.assertTrue(
            all(scope["default_possible"] for scope in decision["source_scopes"] if scope["state"] == "allowed")
        )

    def test_unknown_restrictions_never_supply_definite_exposure(self):
        for kind in ("storage", "key"):
            for unknown in (
                {"site_config": True},
                {"site_config": [{"ip_restriction": True}]},
                {"site_config": [{"ip_restriction": [{"action": True}]}]},
                {"site_config": [{"ip_restriction": [{"headers": True}]}]},
            ):
                with self.subTest(kind=kind, unknown=unknown):
                    resources, _, rule = _paths(kind, {"ip_restriction": [_allow()]}, unknown)
                    _, findings = _evaluate(resources, rule, _IDENTITY_RULE)
                    self.assertEqual(findings, [])

    def test_unknown_disjoint_rule_does_not_erase_known_external_subset(self):
        resources, _, rule = _paths(
            config={"ip_restriction": [_allow(), _allow("8.8.4.0/24")]},
            unknown={"site_config": [{"ip_restriction": [{}, {"action": True}]}]},
        )
        _, findings = _evaluate(resources, rule)
        decision = _decision(findings[0])
        self.assertEqual(decision["allowed_source_cidrs"], ["8.8.8.0/24"])
        self.assertTrue(decision["uncertainties"])

    def test_header_limited_ingress_keeps_the_required_request_witness(self):
        resources, _, rule = _paths(config={"ip_restriction": [_allow(headers=[{"x_azure_fdid": ["reviewed-proxy"]}])]})
        _, findings = _evaluate(resources, rule)
        decision = _decision(findings[0])
        self.assertEqual(decision["allowed_source_cidrs"], [])
        scope = next(scope for scope in decision["source_scopes"] if "allow_witness" in scope)
        self.assertEqual(scope["source_cidrs"], ["8.8.8.0/24"])
        self.assertEqual(scope["allow_witness"]["headers"], {"x_azure_fdid": "reviewed-proxy"})
        self.assertEqual(scope["allow_witness"]["rule_indices"], [0])
        self.assertFalse(scope["allow_witness"]["default_possible"])

    def test_secret_reference_findings_share_the_same_ingress_contract(self):
        for config, expected in (
            ({"ip_restriction": [_allow()]}, True),
            ({"ip_restriction_default_action": "Deny"}, False),
        ):
            app = _secret_app(public_network_access_enabled=True)
            app.values["site_config"] = [config]
            inventory, findings = _evaluate(
                [_secret_vault(rbac_enabled=True), _secret(), app, _secret_grant()], _IDENTITY_RULE
            )
            self.assertEqual(bool(findings), expected)
            self.assertTrue(azure_facts(inventory.get_by_address(app.address)).app_service_key_vault_access_paths)
            if findings:
                self.assertEqual(_decision(findings[0])["allowed_source_cidrs"], ["8.8.8.0/24"])

    def test_shadowed_broad_rule_is_configuration_evidence_without_public_severity(self):
        app = _app(
            public_network=True,
            site_config_overrides={
                "ip_restriction_default_action": "Allow",
                "ip_restriction": [
                    _allow("0.0.0.0/0", action="Deny"),
                    _allow("::/0", action="Deny"),
                    _allow("0.0.0.0/0", priority=200),
                ],
            },
        )
        rules = (
            "azure-app-service-broad-access-restriction-allow",
            "azure-app-service-access-restrictions-not-default-deny",
        )
        _, findings = _evaluate([app], *rules)
        self.assertEqual({finding.rule_id for finding in findings}, set(rules))
        self.assertTrue(all(finding.severity_reasoning.internet_exposure == 0 for finding in findings))
        self.assertTrue(all(_decision(finding)["state"] == "blocked" for finding in findings))

    def test_service_tags_subnets_and_private_sources_do_not_supply_public_proof(self):
        for selector in (
            {"service_tag": "AzureFrontDoor.Backend"},
            {"virtual_network_subnet_id": "azurerm_subnet.clients.id"},
            {"ip_address": "10.0.0.0/24"},
        ):
            with self.subTest(selector=selector):
                resources, _, rule = _paths(
                    config={"ip_restriction": [{"action": "Allow", "priority": 100, **selector}]}
                )
                self.assertEqual(_evaluate(resources, rule)[1], [])

    def test_authentication_qualifies_but_does_not_remove_public_data_paths(self):
        for kind in ("storage", "key"):
            for auth in (
                {"auth_settings": [{"enabled": True, "unauthenticated_client_action": "RedirectToLoginPage"}]},
                {
                    "auth_settings_v2": [
                        {"auth_enabled": True, "require_authentication": True, "unauthenticated_action": "Return401"}
                    ]
                },
            ):
                with self.subTest(kind=kind, auth=auth):
                    resources, app, rule = _paths(kind)
                    app.values.update(auth)
                    _, findings = _evaluate(resources, rule, _AUTH_RULE, _ANONYMOUS_RULE)
                    self.assertEqual([finding.rule_id for finding in findings], [rule])
                    self.assertEqual(_decision(findings[0])["external_access"], "allowed")
                    self.assertEqual(findings[0].severity_reasoning.internet_exposure, 2)
                    self.assertTrue(
                        any(
                            'enabled_state":"enabled"' in line
                            for line in _evidence(findings[0])["app_service_authentication"]
                        )
                    )

    def test_configuration_and_transport_findings_do_not_get_exposure_from_blocked_or_unknown_ingress(self):
        rules = (
            _CONFIG_RULE,
            "azure-app-service-minimum-tls-below-1-2",
            "azure-app-service-managed-identity-missing",
            "azure-app-service-vnet-integration-missing",
            "azure-diagnostic-settings-missing",
        )
        for config, unknown in (
            ({}, None),
            ({"ip_restriction_default_action": "Deny"}, None),
            ({}, {"site_config": [{"ip_restriction": True}]}),
        ):
            with self.subTest(config=config, unknown=unknown):
                app = _app(public_network=True, tls_version="1.0", site_config_overrides=config, unknown_values=unknown)
                _, findings = _evaluate([app], *rules)
                self.assertEqual({finding.rule_id for finding in findings}, set(rules))
                expected = 0 if config or unknown else 2
                self.assertTrue(all(finding.severity_reasoning.internet_exposure == expected for finding in findings))
                configuration = next(finding for finding in findings if finding.rule_id == _CONFIG_RULE)
                self.assertIn("public_network_access_enabled is true", _evidence(configuration)["network_posture"])

    def test_authentication_findings_require_effective_ingress(self):
        for auth, rule in (
            ({"auth_settings_v2": [{"auth_enabled": False}]}, _AUTH_RULE),
            (
                {"auth_settings_v2": [{"auth_enabled": True, "unauthenticated_action": "AllowAnonymous"}]},
                _ANONYMOUS_RULE,
            ),
        ):
            for default in ("Allow", "Deny"):
                app = _app(
                    public_network=True, site_config_overrides={"ip_restriction_default_action": default}, **auth
                )
                findings = _evaluate([app], rule)[1]
                self.assertEqual(bool(findings), default == "Allow")

    def test_scm_ingress_does_not_make_blocked_main_site_data_paths_public(self):
        resources, _, rule = _paths(
            config={"ip_restriction_default_action": "Deny", "scm_ip_restriction_default_action": "Allow"}
        )
        _, findings = _evaluate(resources, rule, _SCM_RULE)
        self.assertEqual([finding.rule_id for finding in findings], [_SCM_RULE])
        self.assertIn("site=scm", _evidence(findings[0])["public_endpoint"])

    def test_scm_inheritance_blocking_allowlists_and_uncertainty_are_not_unrestricted(self):
        for config, unknown in (
            ({"ip_restriction_default_action": "Deny", "scm_use_main_ip_restriction": True}, None),
            ({"scm_ip_restriction": [_allow()]}, None),
            ({"ip_restriction_default_action": "Deny"}, {"site_config": [{"scm_use_main_ip_restriction": True}]}),
            (
                {
                    "scm_ip_restriction_default_action": "Allow",
                    "scm_ip_restriction": [_allow("0.0.0.0/0", action="Deny"), _allow("::/0", action="Deny")],
                },
                None,
            ),
        ):
            app = _app(public_network=True, site_config_overrides=config, unknown_values=unknown)
            self.assertEqual(_evaluate([app], _SCM_RULE)[1], [])

    def test_reanalysis_ignores_stale_cached_exposure_and_forged_public_flags(self):
        resources, app, rule = _paths()
        inventory, findings = _evaluate(resources, rule)
        self.assertEqual(len(findings), 1)
        workload = inventory.get_by_address(app.address)
        facts = azure_facts(workload)
        facts.set(
            AzureResourceMetadata.APP_SERVICE_ACCESS_RESTRICTIONS,
            [_allow("0.0.0.0/0", action="Deny"), _allow("::/0", action="Deny")],
        )
        workload.public_exposure = workload.direct_internet_reachable = True
        self.assertEqual(facts.app_service_effective_ingress["main"]["state"], "unrestricted")
        self.assertEqual(_run(inventory, rule, _IDENTITY_RULE), [])
        facts.set(AzureResourceMetadata.APP_SERVICE_ACCESS_RESTRICTIONS, [])
        facts.set_app_service_effective_ingress({"main": {"state": "blocked", "external_access": "blocked"}})
        self.assertEqual(len(_run(inventory, rule)), 1)

    def test_current_ingress_is_prepared_once_per_app_for_multiple_rules(self):
        resources, _, rule = _paths()
        inventory = AzureNormalizer().normalize(resources)
        with patch(
            "tfstride.providers.azure.analysis_indexes.evaluate_app_service_access", wraps=evaluate_app_service_access
        ) as evaluate:
            self.assertTrue(_run(inventory, rule, _CONFIG_RULE, _IDENTITY_RULE))
        self.assertEqual(evaluate.call_count, 1)

    def test_resource_order_does_not_change_findings_or_evidence(self):
        resources, _, rule = _paths(config={"ip_restriction": [_allow()]})
        expected = _evaluate(resources, rule)[1]
        self.assertTrue(expected)
        self.assertEqual(_evaluate(list(reversed(resources)), rule)[1], expected)

    def test_plan_ingestion_preserves_unknowns_defaults_and_allowlist_evidence(self):
        for config, unknown, expected in (
            ({"ip_restriction": [_allow()]}, {}, True),
            ({"ip_restriction_default_action": "Deny"}, {}, False),
            ({"ip_restriction": [_allow()]}, {"site_config": [{"ip_restriction": True}]}, False),
        ):
            resources, app, rule = _paths(config=config, unknown=unknown)
            # Use a known native grant scope here so the fixture tests actual
            # plan ingestion without relying on manually attached references.
            grant = resources[-1]
            grant.values["scope"] = resources[0].values["id"]
            grant.unknown_values.pop("scope", None)
            payload = {
                "format_version": "1.2",
                "terraform_version": "1.8.5",
                "planned_values": {
                    "root_module": {
                        "resources": [
                            {
                                "address": item.address,
                                "mode": item.mode,
                                "type": item.resource_type,
                                "name": item.name,
                                "provider_name": item.provider_name,
                                "values": deepcopy(item.values),
                            }
                            for item in resources
                        ]
                    }
                },
                "resource_changes": [{"address": app.address, "change": {"after_unknown": app.unknown_values}}],
            }
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "plan.json"
                path.write_text(json.dumps(payload), encoding="utf-8")
                plan = load_terraform_plan(path)
            _, findings = _evaluate(plan.resources, rule)
            self.assertEqual(bool(findings), expected)
            if findings:
                self.assertEqual(_decision(findings[0])["allowed_source_cidrs"], ["8.8.8.0/24"])
