from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from tests.providers.gcp.normalizer_support import _terraform_resource
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.input.terraform_plan import load_terraform_plan
from tfstride.providers.gcp.firewall_matches import (
    normalize_firewall_matches,
    normalize_firewall_protocol,
    parse_firewall_port_range,
)
from tfstride.providers.gcp.firewall_normalizers import (
    normalize_compute_firewall,
    normalize_compute_firewall_policy_rule,
)
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.normalizer import GcpNormalizer


def _firewall(action="allow", *, policy=False, protocol="tcp", ports=None, unknown=None, **extra):
    layer4 = {"ip_protocol" if policy else "protocol": protocol}
    if ports is not None:
        layer4["ports"] = ports
    values = {"priority": 1000, "direction": "INGRESS"}
    if policy:
        values.update(
            {
                "firewall_policy": "123",
                "target_resources": ["google_compute_network.main.id"],
                "action": action,
                "match": [{"src_ip_ranges": ["0.0.0.0/0"], "layer4_configs": [layer4]}],
            }
        )
    else:
        values.update({"network": "google_compute_network.main.id", "source_ranges": ["0.0.0.0/0"], action: [layer4]})
    values.update(extra)
    resource_type = "google_compute_firewall_policy_rule" if policy else "google_compute_firewall"
    return _terraform_resource(f"{resource_type}.{action}", resource_type, values, unknown_values=unknown)


def _normalize(resource):
    normalizer = (
        normalize_compute_firewall_policy_rule
        if resource.resource_type == "google_compute_firewall_policy_rule"
        else normalize_compute_firewall
    )
    return normalizer(resource)


def _matches(resource):
    return _normalize(resource).get_metadata_field(GcpResourceMetadata.FIREWALL_MATCHES)


def _inventory(*firewalls):
    return GcpNormalizer().normalize(
        [
            _terraform_resource("google_compute_network.main", "google_compute_network", {"name": "main"}),
            _terraform_resource(
                "google_compute_instance.web",
                "google_compute_instance",
                {
                    "name": "web",
                    "network_interface": [{"network": "google_compute_network.main.id", "access_config": [{}]}],
                },
            ),
            *firewalls,
        ]
    )


def _instance(*firewalls):
    instance = _inventory(*firewalls).get_by_address("google_compute_instance.web")
    assert instance is not None
    return instance


class GcpFirewallMatchTests(unittest.TestCase):
    def test_protocol_aliases_and_non_tcp_udp_protocols(self):
        for value, expected in [
            ("TCP", "tcp"),
            (6, "tcp"),
            ("006", "tcp"),
            ("17", "udp"),
            ("1", "icmp"),
            ("58", "ipv6-icmp"),
            ("icmpv6", "ipv6-icmp"),
            ("esp", "esp"),
            ("132", "sctp"),
            ("99", "99"),
            ("0", "0"),
            ("255", "255"),
            ("all", "-1"),
            (-1, "-1"),
        ]:
            with self.subTest(value=value):
                self.assertEqual(normalize_firewall_protocol(value), expected)
                for policy in (False, True):
                    resource = _firewall(policy=policy, protocol=value)
                    record = _matches(resource)[0]
                    self.assertEqual(record["protocol"], expected)
                    self.assertEqual(
                        record["ports_state"], "all" if expected in {"tcp", "udp", "-1"} else "not_applicable"
                    )
                    self.assertEqual(_normalize(resource).network_rules[0].protocol, expected)

    def test_missing_or_invalid_protocol_is_not_all_protocols(self):
        for value in (None, "", "*", "https", "256", "-2", True, 6.5, {}, "${var.protocol}"):
            with self.subTest(value=value):
                resource = _firewall(protocol=value)
                self.assertIsNone(_matches(resource)[0]["protocol"])
                self.assertTrue(_matches(resource)[0]["uncertainties"])
                self.assertEqual(_normalize(resource).network_rules, ())

    def test_explicit_port_validation(self):
        for value, expected in [
            (0, (0, 0)),
            ("65535", (65535, 65535)),
            (" 22 - 443 ", (22, 443)),
            ("0-65535", (0, 65535)),
        ]:
            with self.subTest(value=value):
                self.assertEqual(parse_firewall_port_range(value), expected)
        for value in (
            "",
            "*",
            "-1",
            "65536",
            "443-22",
            "22-",
            "-443",
            "1-2-3",
            "22.0",
            22.5,
            True,
            None,
            {},
            "${var.port}",
        ):
            with self.subTest(value=value):
                self.assertIsNone(parse_firewall_port_range(value))
                for policy in (False, True):
                    for action in ("allow", "deny"):
                        resource = _firewall(action, policy=policy, ports=[value])
                        record = _matches(resource)[0]
                        self.assertEqual(record["ports_state"], "unknown")
                        self.assertTrue(record["unsupported_fields"])
                        self.assertEqual(_normalize(resource).network_rules, ())

    def test_omitted_and_empty_ports_are_distinct_from_unknown_ports(self):
        for policy in (False, True):
            for ports in (None, []):
                with self.subTest(policy=policy, ports=ports):
                    record = _matches(_firewall(policy=policy, ports=ports))[0]
                    self.assertEqual(record["ports_state"], "all")
                    self.assertEqual(record["uncertainties"], [])
            flags = {"match": [{"layer4_configs": [{"ports": True}]}]} if policy else {"allow": [{"ports": True}]}
            for ports in (None, ["443"]):
                resource = _firewall(policy=policy, ports=ports, unknown=flags)
                self.assertEqual(_matches(resource)[0]["ports_state"], "unknown")
                self.assertEqual(_normalize(resource).network_rules, ())

    def test_ports_on_all_or_non_port_protocols_are_unsupported(self):
        for protocol in ("all", "icmp", "esp", "sctp", "99"):
            with self.subTest(protocol=protocol):
                resource = _firewall(protocol=protocol, ports=["443"])
                self.assertEqual(_matches(resource)[0]["ports_state"], "unknown")
                self.assertEqual(_normalize(resource).network_rules, ())

    def test_port_ranges_are_sorted_deduplicated_and_preserve_known_partial_values(self):
        record = _matches(_firewall(ports=["443", "20-30", "443", "bad"]))[0]
        self.assertEqual(record["port_ranges"], [{"from_port": 20, "to_port": 30}, {"from_port": 443, "to_port": 443}])
        self.assertEqual(record["ports_state"], "unknown")

    def test_sources_preserve_canonical_cidrs_and_address_families(self):
        resource = _firewall(ports=["443"], source_ranges=["2001:db8::1/64", "::/0", "10.1.2.3/8", "0.0.0.0/0"])
        record = _matches(resource)[0]
        self.assertEqual(record["source_ranges"], ["0.0.0.0/0", "10.0.0.0/8", "2001:db8::/64", "::/0"])
        rule = _normalize(resource).network_rules[0]
        self.assertEqual(rule.cidr_blocks, ["0.0.0.0/0", "10.0.0.0/8"])
        self.assertEqual(rule.ipv6_cidr_blocks, ["2001:db8::/64", "::/0"])

    def test_source_default_requires_known_absence_of_source_selectors(self):
        absent = _firewall(source_ranges=None)
        self.assertEqual(_matches(absent)[0]["source_ranges_state"], "default")
        for flags in (
            {"source_ranges": True},
            {"source_ranges": [True]},
            {"source_tags": True},
            {"source_service_accounts": True},
        ):
            with self.subTest(flags=flags):
                resource = _firewall(source_ranges=None, unknown=flags)
                record = _matches(resource)[0]
                self.assertEqual(record["source_ranges_state"], "unknown")
                self.assertEqual(record["source_ranges"], [])
                self.assertEqual(_normalize(resource).network_rules, ())

    def test_unknown_source_discards_stale_known_value(self):
        resource = _firewall(unknown={"source_ranges": True})
        self.assertEqual(_matches(resource)[0]["source_ranges"], [])
        self.assertEqual(_normalize(resource).network_rules, ())

    def test_vpc_source_identity_selectors_do_not_narrow_explicit_cidr_alternatives(self):
        for key in ("source_tags", "source_service_accounts"):
            for unknown in ({}, {key: True}):
                with self.subTest(key=key, unknown=unknown):
                    resource = _firewall(ports=["443"], unknown=unknown, **{key: ["app"]})
                    self.assertEqual(_matches(resource)[0]["source_ranges_state"], "configured")
                    self.assertTrue(_normalize(resource).network_rules[0].allows_internet())
                    self.assertTrue(_instance(resource).public_exposure)

    def test_malformed_sources_do_not_default_to_the_internet(self):
        for source in ("0.0.0.0/0", ["bad"], [None], ["0.0.0.0/0", "bad"]):
            with self.subTest(source=source):
                resource = _firewall(source_ranges=source)
                self.assertEqual(_matches(resource)[0]["source_ranges_state"], "unknown")
                self.assertEqual(_normalize(resource).network_rules, ())

    def test_known_source_and_destination_constraints_remain_explicit(self):
        resource = _firewall(
            policy=True,
            match=[
                {
                    "src_ip_ranges": ["0.0.0.0/0"],
                    "src_region_codes": ["US"],
                    "dest_ip_ranges": ["10.0.0.0/8"],
                    "dest_fqdns": ["example.test"],
                    "layer4_configs": [{"ip_protocol": "tcp", "ports": ["443"]}],
                }
            ],
        )
        record = _matches(resource)[0]
        self.assertEqual(record["source_constraints"], {"src_region_codes": ["US"]})
        self.assertEqual(record["destination_constraints"], {"dest_fqdns": ["example.test"]})
        self.assertEqual(record["destination_ranges"], ["10.0.0.0/8"])
        self.assertIn("match[0].dest_ip_ranges", record["unsupported_fields"])
        self.assertEqual(_normalize(resource).network_rules, ())

    def test_unknown_blocks_remain_records_without_becoming_generic_rules(self):
        cases = [
            (_firewall(), {"allow": True}),
            (_firewall(), {"allow": [True]}),
            (_firewall(policy=True), {"match": True}),
            (_firewall(policy=True), {"match": [True]}),
            (_firewall(policy=True), {"match": [{"layer4_configs": True}]}),
        ]
        for resource, flags in cases:
            with self.subTest(flags=flags):
                resource.unknown_values = flags
                records = _matches(resource)
                self.assertTrue(records)
                self.assertTrue(records[0]["unknown_fields"])
                self.assertEqual(_normalize(resource).network_rules, ())

    def test_unknown_sibling_does_not_discard_known_layer4_block(self):
        resource = _firewall(
            allow=[{"protocol": "tcp", "ports": ["443"]}, {"protocol": "udp", "ports": ["53"]}],
            unknown={"allow": [{}, {"ports": True}]},
        )
        records = _matches(resource)
        self.assertEqual([record["ports_state"] for record in records], ["ranges", "unknown"])
        rules = _normalize(resource).network_rules
        self.assertEqual([(rule.protocol, rule.from_port) for rule in rules], [("tcp", 443)])

    def test_normalization_does_not_mutate_input_or_share_records(self):
        values = {
            "allow": [{"protocol": "tcp", "ports": ["443"]}, {"protocol": "udp", "ports": ["53"]}],
            "source_tags": ["app"],
        }
        original = copy.deepcopy(values)
        records = normalize_firewall_matches(values)
        records[0]["source_constraints"]["source_tags"].append("changed")
        self.assertEqual(values, original)
        self.assertEqual(records[1]["source_constraints"]["source_tags"], ["app"])
        json.dumps(records)

    def test_policy_aliases_preserve_scope_and_do_not_hide_unknown_siblings(self):
        resource = _firewall(
            policy=True,
            match=[
                {
                    "src_ip_ranges": [],
                    "src_ip_range": ["::/0"],
                    "layer4_configs": [],
                    "layer4_config": [{"ip_protocol": "tcp", "ports": ["443"]}],
                }
            ],
        )
        self.assertEqual(_matches(resource)[0]["source_ranges"], ["::/0"])
        self.assertEqual(_normalize(resource).network_rules[0].ipv6_cidr_blocks, ["::/0"])
        resource.unknown_values = {"match": [{"src_ip_ranges": True}]}
        self.assertEqual(_matches(resource)[0]["source_ranges_state"], "unknown")
        self.assertEqual(_normalize(resource).network_rules, ())

    def test_known_policy_layer4_sibling_survives_nested_unknown(self):
        resource = _firewall(
            policy=True,
            match=[
                {"layer4_configs": [{"ip_protocol": "tcp", "ports": ["443"]}, {"ip_protocol": "udp", "ports": ["53"]}]}
            ],
            unknown={"match": [{"layer4_configs": [{}, {"ports": True}]}]},
        )
        self.assertEqual([record["ports_state"] for record in _matches(resource)], ["ranges", "unknown"])
        self.assertEqual(
            [(rule.protocol, rule.from_port) for rule in _normalize(resource).network_rules], [("tcp", 443)]
        )

    def test_extra_layer4_constraints_are_not_silently_ignored(self):
        resource = _firewall(allow=[{"protocol": "tcp", "ports": ["443"], "source_ports": ["12345"]}])
        self.assertIn("allow[0].source_ports", _matches(resource)[0]["unsupported_fields"])
        self.assertEqual(_normalize(resource).network_rules, ())

    def test_malformed_and_unknown_rule_controls_do_not_create_definite_allows(self):
        for key, value in [
            ("priority", True),
            ("priority", -1),
            ("priority", 65536),
            ("priority", "9" * 5000),
            ("disabled", "maybe"),
            ("direction", "SIDEWAYS"),
            ("network", {}),
            ("target_tags", "web"),
        ]:
            with self.subTest(key=key, value_type=type(value)):
                resource = _firewall(**{key: value})
                self.assertIn(key, _matches(resource)[0]["unsupported_fields"])
                self.assertEqual(_normalize(resource).network_rules, ())
        for key in ("priority", "disabled", "direction", "network", "target_tags", "target_service_accounts"):
            with self.subTest(unknown=key):
                resource = _firewall(unknown={key: True})
                self.assertIn(key, _matches(resource)[0]["unknown_fields"])
                self.assertEqual(_normalize(resource).network_rules, ())


class GcpFirewallUncertaintyExposureTests(unittest.TestCase):
    def test_surviving_https_does_not_reintroduce_uncertain_ssh_in_findings(self):
        allow = _firewall(ports=["22", "443"])
        policy = RulePolicy(enabled_rule_ids=frozenset({"gcp-public-compute-broad-ingress"}))
        baseline = _inventory(allow)
        self.assertEqual(
            len(StrideRuleEngine().evaluate(baseline, detect_trust_boundaries(baseline), rule_policy=policy)), 1
        )
        deny = _firewall("deny", ports=["22"], priority=900, unknown={"source_ranges": True})
        inventory = _inventory(allow, deny)
        instance = inventory.get_by_address("google_compute_instance.web")
        assert instance is not None
        self.assertTrue(instance.public_exposure)
        self.assertEqual(
            instance.internet_ingress_reasons, ["google_compute_firewall.allow ingress tcp 443 from 0.0.0.0/0"]
        )
        self.assertEqual(
            StrideRuleEngine().evaluate(inventory, detect_trust_boundaries(inventory), rule_policy=policy), []
        )

    def test_unknown_denies_prevent_unconditional_access_and_preserve_the_reason(self):
        cases = [
            _firewall("deny", ports=["443"], priority=900, unknown={"deny": [{"ports": True}]}),
            _firewall("deny", ports=["bad"], priority=900),
            _firewall("deny", ports=["443"], priority=900, unknown={"deny": True}),
            _firewall("deny", ports=["443"], priority=900, unknown={"source_ranges": True}),
            _firewall("deny", ports=["443"], priority=900, disabled=True, unknown={"disabled": True}),
            _firewall("deny", ports=["443"], priority=900, unknown={"priority": True}),
            _firewall("deny", ports=["443"], priority=900, target_tags=["unrelated"], unknown={"target_tags": True}),
            _firewall("deny", ports=["443"], priority=900, network="unrelated", unknown={"network": True}),
        ]
        for deny in cases:
            with self.subTest(values=deny.values, unknown=deny.unknown_values):
                instance = _instance(_firewall(ports=["443"]), deny)
                self.assertFalse(instance.public_exposure)
                self.assertEqual(instance.get_metadata_field(GcpResourceMetadata.INTERNET_INGRESS_STATE), "unknown")
                reasons = instance.get_metadata_field(GcpResourceMetadata.INTERNET_INGRESS_UNCERTAINTIES)
                self.assertTrue(reasons)
                self.assertTrue(all("google_compute_firewall.deny:" in reason for reason in reasons))

    def test_disjoint_or_lower_priority_uncertain_denies_preserve_known_access(self):
        cases = [
            _firewall("deny", protocol="udp", priority=900, unknown={"deny": [{"ports": True}]}),
            _firewall("deny", ports=["22"], priority=900, unknown={"source_ranges": True}),
            _firewall("deny", ports=["bad"], priority=1100),
            _firewall("deny", ports=["bad"], priority=900, source_ranges=["::/0"]),
            _firewall("deny", ports=["bad"], priority=900, disabled=True),
            _firewall("deny", ports=["bad"], priority=900, direction="EGRESS"),
            _firewall("deny", ports=["bad"], priority=900, network="unrelated"),
            _firewall("deny", ports=["bad"], priority=900, target_tags=["other"]),
        ]
        for deny in cases:
            with self.subTest(values=deny.values, unknown=deny.unknown_values):
                instance = _instance(_firewall(ports=["443"]), deny)
                self.assertTrue(instance.public_exposure)
                self.assertEqual(instance.get_metadata_field(GcpResourceMetadata.INTERNET_INGRESS_STATE), "allowed")

    def test_known_numeric_deny_matches_named_allow_but_not_another_address_family(self):
        for source, expected in [(["0.0.0.0/0"], False), (["::/0"], True)]:
            with self.subTest(source=source):
                instance = _instance(
                    _firewall(ports=["443"]),
                    _firewall("deny", protocol="6", ports=["443"], priority=900, source_ranges=source),
                )
                self.assertEqual(instance.public_exposure, expected)

    def test_policy_unknown_deny_or_delegation_does_not_silently_fall_through(self):
        for action in ("deny", "goto_next", "unmodeled_action"):
            with self.subTest(action=action):
                policy = _firewall(
                    action, policy=True, ports=["443"], unknown={"match": [{"layer4_configs": [{"ports": True}]}]}
                )
                instance = _instance(_firewall(ports=["443"]), policy)
                self.assertFalse(instance.public_exposure)
                self.assertEqual(instance.get_metadata_field(GcpResourceMetadata.INTERNET_INGRESS_STATE), "unknown")

    def test_policy_uncertainty_keeps_known_disjoint_protocol_and_higher_priority_allow(self):
        policy_deny = _firewall("deny", policy=True, protocol="udp", ports=["bad"])
        self.assertTrue(_instance(_firewall(ports=["443"]), policy_deny).public_exposure)
        policy_allow = _firewall("allow", policy=True, ports=["443"], priority=900)
        policy_deny = _firewall("deny", policy=True, ports=["bad"], priority=1000)
        self.assertTrue(_instance(policy_allow, policy_deny).public_exposure)

    def test_unknown_allow_does_not_establish_access_or_invalidate_independent_allow(self):
        unknown_allow = _firewall(policy=True, ports=["443"], unknown={"match": True})
        instance = _instance(unknown_allow)
        self.assertFalse(instance.public_exposure)
        self.assertEqual(instance.get_metadata_field(GcpResourceMetadata.INTERNET_INGRESS_STATE), "unknown")
        self.assertTrue(_instance(_firewall(ports=["443"]), unknown_allow).public_exposure)

    def test_plan_ingestion_preserves_nested_unknown_markers(self):
        resource = _firewall(ports=["443"])
        payload = {
            "format_version": "1.2",
            "terraform_version": "1.9.0",
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
                    "change": {
                        "actions": ["create"],
                        "after": resource.values,
                        "after_unknown": {"allow": [{"ports": True}]},
                    },
                }
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            resources = load_terraform_plan(path).resources
        normalized = _normalize(resources[0])
        self.assertEqual(normalized.network_rules, ())
        self.assertIn(
            "allow[0].ports", normalized.get_metadata_field(GcpResourceMetadata.FIREWALL_MATCHES)[0]["unknown_fields"]
        )
