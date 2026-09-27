from __future__ import annotations

import ipaddress
import json
import random
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from typing import Any

from tfstride.input.terraform_plan import load_terraform_plan
from tfstride.models import TerraformResource
from tfstride.providers.azure.app_service_access import evaluate_app_service_access
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AZURE_APP_SERVICE_RESOURCE_TYPES, AzureResourceType


def _rule(source: str = "8.8.8.0/24", action: str = "Allow", priority: int = 100, **fields: Any) -> dict[str, Any]:
    return {"ip_address": source, "action": action, "priority": priority, **fields}


def _resource(config: dict[str, Any] | None = None, *, unknown: dict[str, Any] | None = None) -> TerraformResource:
    return TerraformResource(
        address="azurerm_linux_web_app.api",
        name="api",
        resource_type=AzureResourceType.LINUX_WEB_APP,
        mode="managed",
        provider_name="registry.terraform.io/hashicorp/azurerm",
        provider_config_key="azurerm",
        values={"name": "api", "public_network_access_enabled": True, "site_config": [config or {}]},
        unknown_values=unknown or {},
    )


def _evaluate(config: dict[str, Any] | None = None, *, unknown: dict[str, Any] | None = None) -> dict[str, Any]:
    return _facts(_resource(config, unknown=unknown)).app_service_effective_ingress


def _facts(resource: TerraformResource):
    inventory = AzureNormalizer().normalize([resource])
    app = inventory.get_by_address(resource.address)
    assert app is not None
    return azure_facts(app)


class AzureAppServiceAccessTests(unittest.TestCase):
    def test_implicit_defaults_distinguish_no_rules_from_an_allowlist(self) -> None:
        open_site = _evaluate()["main"]
        self.assertEqual(open_site["state"], "unrestricted")
        self.assertEqual(open_site["default_action_source"], "implicit_allow_without_rules")
        self.assertEqual(open_site["allowed_source_cidrs"], ["0.0.0.0/0", "::/0"])
        restricted = _evaluate({"ip_restriction": [_rule()]})["main"]
        self.assertEqual(restricted["state"], "restricted")
        self.assertEqual(restricted["external_access"], "allowed")
        self.assertEqual(restricted["allowed_source_cidrs"], ["8.8.8.0/24"])
        self.assertEqual(restricted["default_action_source"], "implicit_deny_with_rules")

    def test_explicit_default_actions_override_rule_presence(self) -> None:
        self.assertEqual(_evaluate({"ip_restriction_default_action": "Deny"})["main"]["state"], "blocked")
        self.assertEqual(
            _evaluate({"ip_restriction_default_action": "Allow", "ip_restriction": [_rule()]})["main"]["state"],
            "unrestricted",
        )

    def test_deny_all_and_collective_denies_block_all_access(self) -> None:
        for rules, default in (
            ([_rule("0.0.0.0/0", "Deny"), _rule("::/0", "Deny")], "Allow"),
            ([_rule(priority=300), _rule("8.8.8.0/25", "Deny", 100), _rule("8.8.8.128/25", "Deny", 200)], "Deny"),
        ):
            with self.subTest(default=default):
                result = _evaluate({"ip_restriction": rules, "ip_restriction_default_action": default})["main"]
                self.assertEqual(result["state"], "blocked")
                self.assertEqual(result["external_access"], "blocked")
                self.assertEqual(result["allowed_source_cidrs"], [])

    def test_default_allow_with_partial_deny_keeps_surviving_external_access(self) -> None:
        result = _evaluate({"ip_restriction_default_action": "Allow", "ip_restriction": [_rule(action="Deny")]})["main"]
        self.assertEqual(result["state"], "restricted")
        self.assertEqual(result["external_access"], "allowed")
        self.assertEqual(result["blocked_source_cidrs"], ["8.8.8.0/24"])

    def test_priority_applies_only_to_matching_source_subsets(self) -> None:
        allow, deny = _rule(priority=200), _rule("8.8.8.0/25", "Deny", 100)
        result = _evaluate({"ip_restriction": [allow, deny]})["main"]
        self.assertEqual(result["allowed_source_cidrs"], ["8.8.8.128/25"])
        self.assertEqual(result["state"], "restricted")
        deny["priority"] = 300
        self.assertEqual(_evaluate({"ip_restriction": [allow, deny]})["main"]["allowed_source_cidrs"], ["8.8.8.0/24"])

    def test_equal_priority_uses_preserved_list_order_not_action_or_name(self) -> None:
        allow, deny = _rule(name="z-allow"), _rule(action="Deny", name="a-deny")
        self.assertEqual(_evaluate({"ip_restriction": [allow, deny]})["main"]["allowed_source_cidrs"], ["8.8.8.0/24"])
        self.assertEqual(_evaluate({"ip_restriction": [deny, allow]})["main"]["state"], "blocked")

    def test_legacy_unknown_tie_order_preserves_conflict_but_not_spurious_uncertainty(self) -> None:
        resource = _resource({"ip_restriction": [_rule(), _rule(action="Deny")]})
        resource.resource_type = AzureResourceType.FUNCTION_APP
        resource.address = "azurerm_function_app.api"
        result = _facts(resource).app_service_effective_ingress["main"]
        self.assertEqual(result["state"], "unresolved")
        self.assertEqual(result["rule_order"], "priority_with_unresolved_ties")
        resource.values["site_config"][0]["ip_restriction"][1]["action"] = "Allow"
        self.assertEqual(_facts(resource).app_service_effective_ingress["main"]["state"], "restricted")

    def test_unknown_priority_only_affects_overlapping_sources(self) -> None:
        rules = [_rule(), _rule("8.8.4.0/24", "Deny", 200)]
        unknown = {"site_config": [{"ip_restriction": [{}, {"priority": True}]}]}
        result = _evaluate({"ip_restriction": rules}, unknown=unknown)["main"]
        self.assertEqual(result["allowed_source_cidrs"], ["8.8.8.0/24"])
        self.assertEqual(result["state"], "restricted")
        rules[1]["ip_address"] = "8.8.8.0/24"
        result = _evaluate({"ip_restriction": rules}, unknown=unknown)["main"]
        self.assertEqual(result["state"], "unresolved")
        self.assertEqual(result["external_access"], "unknown")

    def test_later_unresolved_fields_do_not_erase_an_earlier_definite_allow(self) -> None:
        result = _evaluate(
            {"ip_restriction": [_rule(priority=1), _rule(action="Deny", priority=200)]},
            unknown={"site_config": [{"ip_restriction": [{}, {"action": True, "headers": True}]}]},
        )["main"]
        self.assertEqual(result["allowed_source_cidrs"], ["8.8.8.0/24"])
        self.assertEqual(result["uncertainties"], [])

    def test_unknown_rule_matching_cannot_change_an_identical_default_action(self) -> None:
        for action, expected in (("Allow", "unrestricted"), ("Deny", "blocked")):
            with self.subTest(action=action):
                result = _evaluate(
                    {"ip_restriction_default_action": action, "ip_restriction": [_rule(action=action)]},
                    unknown={"site_config": [{"ip_restriction": [{"priority": True, "ip_address": True}]}]},
                )["main"]
                self.assertEqual(result["state"], expected)
                self.assertEqual(result["uncertainties"], [])

    def test_unknown_default_is_irrelevant_when_rules_cover_every_source(self) -> None:
        result = _evaluate(
            {"ip_restriction": [_rule("0.0.0.0/0"), _rule("::/0")]},
            unknown={"site_config": [{"ip_restriction_default_action": True}]},
        )["main"]
        self.assertEqual(result["state"], "unrestricted")
        self.assertEqual(result["uncertainties"], [])

    def test_unknown_rule_collection_and_stale_site_config_do_not_become_open_or_blocked(self) -> None:
        for config, unknown in (
            ({}, {"site_config": [{"ip_restriction": True}]}),
            ({}, {"site_config": [{"ip_restriction": [True]}]}),
            ({}, {"site_config": [{"ip_restriction": [{"ip_address": True}]}]}),
            ({"ip_restriction": [_rule(action="Deny")]}, {"site_config": [{"ip_restriction": True}]}),
            ({"ip_restriction_default_action": "Allow"}, {"site_config": True}),
            ({"ip_restriction_default_action": "Deny"}, {"site_config": [True]}),
        ):
            with self.subTest(unknown=unknown, config=config):
                self.assertEqual(_evaluate(config, unknown=unknown)["main"]["state"], "unresolved")

    def test_headers_remain_required_and_known_request_witnesses_establish_restricted_access(self) -> None:
        result = _evaluate({"ip_restriction": [_rule(headers=[{"x_azure_fdid": ["reviewed-front-door"]}])]})["main"]
        self.assertEqual(result["state"], "restricted")
        self.assertEqual(result["external_access"], "allowed")
        self.assertEqual(result["allowed_source_cidrs"], [])
        scoped = next(scope for scope in result["source_scopes"] if "allow_witness" in scope)
        self.assertEqual(scoped["allow_witness"]["headers"], {"x_azure_fdid": "reviewed-front-door"})
        self.assertEqual(scoped["deny_witness"]["headers"], {})

    def test_header_deny_blocks_only_matching_requests_and_unknown_headers_ignore_stale_values(self) -> None:
        config = {
            "ip_restriction_default_action": "Allow",
            "ip_restriction": [_rule(action="Deny", headers=[{"x_azure_fdid": ["blocked"]}])],
        }
        self.assertEqual(_evaluate(config)["main"]["state"], "restricted")
        result = _evaluate(config, unknown={"site_config": [{"ip_restriction": [{"headers": True}]}]})["main"]
        scoped = next(scope for scope in result["source_scopes"] if scope["source_cidrs"] == ["8.8.8.0/24"])
        self.assertNotIn("allow_witness", scoped)
        self.assertNotIn("deny_witness", scoped)
        self.assertEqual(result["state"], "unresolved")
        self.assertEqual(result["external_access"], "allowed")  # Other source ranges remain open.

    def test_service_tags_subnets_and_anyvnets_remain_constraints(self) -> None:
        for selector in (
            {"service_tag": "AzureFrontDoor.Backend", "headers": [{"x_azure_fdid": ["reviewed"]}]},
            {"virtual_network_subnet_id": "azurerm_subnet.allowed.id"},
            {"ip_address": "AnyVnets"},
        ):
            with self.subTest(selector=selector):
                result = _evaluate({"ip_restriction": [{"action": "Allow", "priority": 100, **selector}]})["main"]
                self.assertEqual(result["state"], "unresolved")
                self.assertEqual(result["external_access"], "unknown")
                self.assertEqual(result["allowed_source_cidrs"], [])
                for key, value in selector.items():
                    self.assertEqual(result["rule_evidence"][0][key], value)

    def test_unsupported_header_does_not_become_an_unrestricted_allow(self) -> None:
        result = _evaluate({"ip_restriction": [_rule(headers=[{"unsupported": ["value"]}])]})["main"]
        self.assertEqual(result["state"], "unresolved")
        self.assertEqual(result["external_access"], "unknown")

    def test_optional_null_header_fields_preserve_the_configured_constraint(self) -> None:
        headers = [
            {"x_azure_fdid": ["selected"], "x_forwarded_for": None, "x_forwarded_host": [], "x_fd_health_probe": None}
        ]
        result = _evaluate({"ip_restriction": [_rule(headers=headers)]})["main"]
        self.assertEqual(result["state"], "restricted")
        self.assertEqual(result["external_access"], "allowed")
        self.assertEqual(result["uncertainties"], [])
        self.assertEqual(result["allowed_source_cidrs"], [])

    def test_partially_unknown_headers_preserve_known_nonmatching_constraints(self) -> None:
        result = _evaluate(
            {
                "ip_restriction": [
                    _rule(action="Deny", headers=[{"x_azure_fdid": ["blocked"], "x_forwarded_host": ["stale"]}]),
                    _rule(priority=200, headers=[{"x_azure_fdid": ["allowed"]}]),
                ]
            },
            unknown={"site_config": [{"ip_restriction": [{"headers": [{"x_forwarded_host": True}]}, {}]}]},
        )["main"]
        self.assertEqual(result["external_access"], "allowed")
        self.assertEqual(result["state"], "restricted")
        self.assertEqual(result["rule_evidence"][0]["unknown_header_fields"], ["x_forwarded_host"])
        scoped = next(scope for scope in result["source_scopes"] if "allow_witness" in scope)
        self.assertEqual(scoped["allow_witness"]["headers"], {"x_azure_fdid": "allowed"})

    def test_identical_header_predicates_do_not_bypass_an_earlier_deny(self) -> None:
        headers = [{"x_azure_fdid": ["selected"]}]
        result = _evaluate(
            {"ip_restriction": [_rule(action="Deny", headers=headers), _rule(priority=200, headers=headers)]}
        )["main"]
        self.assertEqual(result["state"], "blocked")
        self.assertEqual(result["uncertainties"], [])

    def test_bounded_header_partition_never_claims_exhaustive_denial_from_samples(self) -> None:
        headers = [{"x_forwarded_host": [f"host{i}" for i in range(8)], "x_azure_fdid": [f"id{i}" for i in range(8)]}]
        result = _evaluate({"ip_restriction": [_rule(headers=headers)]})["main"]
        self.assertFalse(result["header_partition_complete"])
        self.assertNotEqual(result["state"], "blocked")

    def test_generated_ip_rules_match_a_sequential_first_match_oracle(self) -> None:
        generator = random.Random(1024)
        for case in range(40):
            rules = [
                _rule(
                    generator.choice(("8.8.8.0/28", "8.8.8.0/29", "8.8.8.8/29")),
                    generator.choice(("Allow", "Deny")),
                    generator.choice((10, 20, 30)),
                )
                for _ in range(4)
            ]
            default = generator.choice(("Allow", "Deny"))
            result = _evaluate({"ip_restriction": rules, "ip_restriction_default_action": default})["main"]
            allowed = [ipaddress.ip_network(cidr) for cidr in result["allowed_source_cidrs"]]
            ordered = sorted(enumerate(rules), key=lambda item: (item[1]["priority"], item[0]))
            for offset in range(16):
                source = ipaddress.ip_address(f"8.8.8.{offset}")
                expected = next(
                    (rule["action"] for _, rule in ordered if source in ipaddress.ip_network(rule["ip_address"])),
                    default,
                )
                with self.subTest(case=case, source=source):
                    self.assertEqual(any(source in network for network in allowed), expected == "Allow")

    def test_missing_data_resource_inputs_and_malformed_site_blocks_remain_unresolved(self) -> None:
        resource = _resource()
        resource.mode = "data"
        self.assertEqual(_facts(resource).app_service_effective_ingress["main"]["state"], "unresolved")
        resource.mode = "managed"
        for shape in ("invalid", [{}, {}], ["invalid"]):
            resource.values["site_config"] = shape
            self.assertEqual(_facts(resource).app_service_effective_ingress["main"]["state"], "unresolved")

    def test_trailing_unknown_rule_and_unrelated_unknown_site_fields_keep_their_scope(self) -> None:
        result = _evaluate(
            {"ip_restriction": [_rule("0.0.0.0/0", "Deny", 1), _rule("::/0", "Deny", 1)]},
            unknown={"site_config": [{"ip_restriction": [{}, {}, True], "minimum_tls_version": True}]},
        )["main"]
        self.assertEqual(result["state"], "blocked")
        self.assertEqual(result["uncertainties"], [])

    def test_malformed_fields_do_not_inherit_valid_defaults(self) -> None:
        for field, value in (
            ("priority", True),
            ("priority", "100"),
            ("priority", 1.5),
            ("action", {}),
            ("action", ""),
            ("ip_address", "bad"),
            ("headers", ["bad"]),
            ("headers", [{"x_azure_fdid": [""]}]),
            ("headers", [{"x_azure_fdid": ["x" * 65]}]),
        ):
            with self.subTest(field=field):
                record = _rule()
                record[field] = value
                result = _evaluate({"ip_restriction": [record]})["main"]
                self.assertNotEqual(result["state"], "unrestricted")
                if field != "priority":
                    self.assertEqual(result["external_access"], "unknown")

    def test_missing_rule_fields_use_provider_defaults_and_unknowns_do_not(self) -> None:
        config = {"ip_restriction": [{"ip_address": "8.8.8.0/24"}]}
        result = _evaluate(config)["main"]
        self.assertEqual(result["state"], "restricted")
        self.assertEqual(result["rule_evidence"][0]["effective_priority"], 65000)
        self.assertEqual(result["rule_evidence"][0]["effective_actions"], ["Allow"])
        result = _evaluate(config, unknown={"site_config": [{"ip_restriction": [{"action": True}]}]})["main"]
        self.assertEqual(result["state"], "unresolved")

    def test_main_and_scm_restrictions_are_independent_unless_inherited(self) -> None:
        config = {"ip_restriction_default_action": "Deny", "scm_ip_restriction_default_action": "Allow"}
        result = _evaluate(config)
        self.assertEqual((result["main"]["state"], result["scm"]["state"]), ("blocked", "unrestricted"))
        config["scm_use_main_ip_restriction"] = True
        result = _evaluate(config)
        self.assertEqual(result["scm"]["state"], "blocked")
        self.assertEqual(result["scm"]["inheritance"], "main")

    def test_unknown_scm_inheritance_retains_alternatives_without_poisoning_the_main_site(self) -> None:
        config = {"ip_restriction_default_action": "Deny", "scm_ip_restriction_default_action": "Allow"}
        unknown = {"site_config": [{"scm_use_main_ip_restriction": True}]}
        result = _evaluate(config, unknown=unknown)
        self.assertEqual(result["main"]["state"], "blocked")
        self.assertEqual(result["scm"]["state"], "unresolved")
        self.assertEqual(result["scm"]["alternatives"]["separate"]["state"], "unrestricted")
        config["scm_ip_restriction_default_action"] = "Deny"
        self.assertEqual(_evaluate(config, unknown=unknown)["scm"]["state"], "blocked")

    def test_inherited_scm_ignores_unknown_separate_rules(self) -> None:
        result = _evaluate(
            {"scm_use_main_ip_restriction": True}, unknown={"site_config": [{"scm_ip_restriction": True}]}
        )
        self.assertEqual(result["scm"]["state"], "unrestricted")

    def test_endpoint_configuration_and_authentication_are_separate_dimensions(self) -> None:
        resource = _resource()
        resource.values["auth_settings_v2"] = [{"auth_enabled": True, "require_authentication": True}]
        self.assertEqual(_facts(resource).app_service_effective_ingress["main"]["state"], "unrestricted")
        resource.unknown_values = {"public_network_access_enabled": True}
        self.assertEqual(_facts(resource).app_service_effective_ingress["main"]["state"], "unresolved")
        resource.unknown_values = {"site_config": True}
        resource.values["public_network_access_enabled"] = False
        result = _facts(resource).app_service_effective_ingress
        self.assertEqual((result["main"]["state"], result["scm"]["state"]), ("blocked", "blocked"))

    def test_split_ranges_and_rule_permutations_preserve_effective_scopes(self) -> None:
        variants = (
            [_rule()],
            [_rule("8.8.8.0/25"), _rule("8.8.8.128/25", priority=200)],
            [_rule("8.8.8.128/25", priority=200), _rule("8.8.8.0/25")],
            [_rule("8.8.8.0/25,8.8.8.128/25")],
        )
        for rules in variants:
            with self.subTest(rules=rules):
                result = _evaluate({"ip_restriction": rules})["main"]
                self.assertEqual(result["allowed_source_cidrs"], ["8.8.8.0/24"])
                self.assertEqual(result["state"], "restricted")

    def test_all_supported_app_types_and_resource_order_preserve_results(self) -> None:
        resources = []
        for resource_type in sorted(AZURE_APP_SERVICE_RESOURCE_TYPES):
            resource = _resource({"ip_restriction": [_rule()]})
            resource.resource_type = resource_type
            resource.address = f"{resource_type}.api"
            resources.append(resource)
        expected = None
        for order in (resources, list(reversed(resources))):
            inventory = AzureNormalizer().normalize(order)
            result = {item.address: azure_facts(item).app_service_effective_ingress for item in inventory.resources}
            if expected is not None:
                self.assertEqual(result, expected)
            self.assertTrue(all(item["main"]["state"] == "restricted" for item in result.values()))
            expected = result

    def test_recomputation_uses_current_restrictions_and_does_not_mutate_inputs(self) -> None:
        facts = _facts(_resource({"ip_restriction": [_rule()]}))
        before = deepcopy(facts.resource.metadata_snapshot())
        self.assertEqual(evaluate_app_service_access(facts.resource), facts.app_service_effective_ingress)
        self.assertEqual(before, facts.resource.metadata_snapshot())
        records = facts.app_service_access_restrictions
        records[0]["action"] = "Deny"
        facts.set(AzureResourceMetadata.APP_SERVICE_ACCESS_RESTRICTIONS, records)
        self.assertEqual(evaluate_app_service_access(facts.resource)["main"]["state"], "blocked")
        self.assertEqual(facts.app_service_effective_ingress["main"]["state"], "restricted")

    def test_plan_ingestion_preserves_list_priority_and_partial_unknowns(self) -> None:
        resource = _resource({"ip_restriction": [_rule(), _rule(action="Deny")]})
        payload = {
            "terraform_version": "1.8.5",
            "planned_values": {
                "root_module": {
                    "resources": [
                        {
                            "address": resource.address,
                            "mode": "managed",
                            "type": resource.resource_type,
                            "name": resource.name,
                            "provider_name": resource.provider_name,
                            "values": resource.values,
                        }
                    ]
                }
            },
            "resource_changes": [
                {
                    "address": resource.address,
                    "change": {"after_unknown": {"site_config": [{"ip_restriction": [{"name": True}, {}]}]}},
                }
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            plan = load_terraform_plan(path)
        facts = _facts(plan.resources[0])
        self.assertEqual(facts.app_service_effective_ingress["main"]["allowed_source_cidrs"], ["8.8.8.0/24"])
