from __future__ import annotations

import copy
import itertools
import random
import unittest

from tests.providers.gcp.normalizer_support import _terraform_resource
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.providers.gcp.firewall_normalizers import normalize_compute_firewall
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_decoration.compute_firewall_exposure import derive_public_compute_exposure
from tfstride.providers.gcp.resource_index import GcpResourceIndexBuilder


def _firewall(name, action, *, priority=1000, protocol="tcp", ports=None, sources=None, unknown=None):
    return _terraform_resource(
        f"google_compute_firewall.{name}",
        "google_compute_firewall",
        {
            "network": "google_compute_network.main.id",
            "priority": priority,
            "direction": "INGRESS",
            "source_ranges": sources or ["0.0.0.0/0"],
            action: [{"protocol": protocol, "ports": ports}],
        },
        unknown_values=unknown,
    )


def _inventory(firewalls):
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


def _instance(inventory):
    instance = inventory.get_by_address("google_compute_instance.web")
    assert instance is not None
    return instance


def _paths(firewalls):
    return _instance(_inventory(firewalls)).get_metadata_field(GcpResourceMetadata.EFFECTIVE_FIREWALL_INGRESS)


def _port_ranges(paths, protocol="tcp", source="0.0.0.0/0"):
    return sorted(
        (
            path["from_port"] if path["from_port"] is not None else 0,
            path["to_port"] if path["to_port"] is not None else 65535,
        )
        for path in paths
        if source in path["source_ranges"]
        and (path["protocol"] == protocol or (path["protocol"] == "-1" and protocol not in path["excluded_protocols"]))
    )


def _broad_ingress_findings(inventory):
    return StrideRuleEngine().evaluate(
        inventory,
        detect_trust_boundaries(inventory),
        rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-public-compute-broad-ingress"})),
    )


class GcpVpcFirewallPrecedenceTests(unittest.TestCase):
    def test_priority_is_evaluated_only_over_matching_subsets(self):
        cases = [
            (
                "all_tcp_minus_ssh",
                [_firewall("allow", "allow"), _firewall("deny", "deny", priority=900, ports=["22"])],
                [(0, 21), (23, 65535)],
            ),
            (
                "disjoint",
                [_firewall("allow", "allow", ports=["443"]), _firewall("deny", "deny", priority=900, ports=["22"])],
                [(443, 443)],
            ),
            (
                "partial_range",
                [
                    _firewall("allow", "allow", ports=["20-30"]),
                    _firewall("deny", "deny", priority=900, ports=["22-25"]),
                ],
                [(20, 21), (26, 30)],
            ),
            (
                "equal_priority",
                [_firewall("a_allow", "allow", ports=["22"]), _firewall("z_deny", "deny", ports=["22"])],
                [],
            ),
            (
                "collective_denies",
                [
                    _firewall("allow", "allow", ports=["20-30"]),
                    _firewall("deny_a", "deny", priority=900, ports=["20-25"]),
                    _firewall("deny_b", "deny", priority=950, ports=["26-30"]),
                ],
                [],
            ),
            (
                "higher_allow",
                [
                    _firewall("allow", "allow", priority=900, ports=["20-30"]),
                    _firewall("deny", "deny", ports=["22-25"]),
                ],
                [(20, 30)],
            ),
            (
                "port_boundaries",
                [_firewall("allow", "allow"), _firewall("deny", "deny", priority=900, ports=["0", "65535"])],
                [(1, 65534)],
            ),
        ]
        for name, firewalls, expected in cases:
            with self.subTest(name=name):
                inventory = _inventory(firewalls)
                instance = _instance(inventory)
                self.assertEqual(
                    _port_ranges(instance.get_metadata_field(GcpResourceMetadata.EFFECTIVE_FIREWALL_INGRESS)), expected
                )
                self.assertEqual(instance.public_exposure, bool(expected))
                self.assertEqual(instance.internet_ingress_capable, bool(expected))

    def test_protocols_and_address_families_have_independent_decisions(self):
        paths = _paths(
            [
                _firewall("allow_udp", "allow", protocol="udp", ports=["443"]),
                _firewall("allow_v6", "allow", ports=["443"], sources=["::/0"]),
                _firewall("deny_tcp_v4", "deny", protocol="6", ports=["443"], priority=900),
            ]
        )
        self.assertEqual(_port_ranges(paths, "udp"), [(443, 443)])
        self.assertEqual(_port_ranges(paths, "tcp"), [])
        self.assertEqual(_port_ranges(paths, "tcp", "::/0"), [(443, 443)])

    def test_winning_allow_provenance_and_surviving_ranges_are_preserved(self):
        paths = _paths(
            [
                _firewall("high", "allow", ports=["25-27"], priority=800),
                _firewall("deny", "deny", ports=["22-25"], priority=900),
                _firewall("low", "allow", ports=["20-30"]),
            ]
        )
        self.assertEqual(
            [(path["firewall_address"], path["rule_priority"], path["from_port"], path["to_port"]) for path in paths],
            [
                ("google_compute_firewall.high", 800, 25, 27),
                ("google_compute_firewall.low", 1000, 20, 21),
                ("google_compute_firewall.low", 1000, 28, 30),
            ],
        )
        self.assertTrue(all(path["match_paths"] == ["allow[0]"] for path in paths))

    def test_unknown_constraints_consume_only_possible_matching_traffic(self):
        firewalls = [
            _firewall("allow", "allow", ports=["20-30"]),
            _firewall("uncertain_deny", "deny", priority=900, ports=["22-25"], unknown={"source_ranges": True}),
        ]
        instance = _instance(_inventory(firewalls))
        self.assertTrue(instance.public_exposure)
        self.assertEqual(
            _port_ranges(instance.get_metadata_field(GcpResourceMetadata.EFFECTIVE_FIREWALL_INGRESS)),
            [(20, 21), (26, 30)],
        )
        self.assertEqual(instance.get_metadata_field(GcpResourceMetadata.INTERNET_INGRESS_STATE), "allowed")
        self.assertTrue(instance.get_metadata_field(GcpResourceMetadata.INTERNET_INGRESS_UNCERTAINTIES))

    def test_unknown_ports_do_not_remove_other_protocols(self):
        instance = _instance(
            _inventory(
                [
                    _firewall("all", "allow", protocol="all"),
                    _firewall("deny", "deny", ports=["22"], priority=900, unknown={"deny": [{"ports": True}]}),
                ]
            )
        )
        paths = instance.get_metadata_field(GcpResourceMetadata.EFFECTIVE_FIREWALL_INGRESS)
        self.assertTrue(instance.public_exposure)
        self.assertEqual(_port_ranges(paths, "tcp"), [])
        self.assertEqual(_port_ranges(paths, "udp"), [(0, 65535)])
        self.assertEqual(_port_ranges(paths, "icmp"), [(0, 65535)])

    def test_ssh_deny_splits_tcp_without_consuming_the_other_protocols(self):
        paths = _paths(
            [_firewall("allow", "allow", protocol="all"), _firewall("deny", "deny", priority=900, ports=["22"])]
        )
        self.assertEqual(_port_ranges(paths, "tcp"), [(0, 21), (23, 65535)])
        self.assertEqual(_port_ranges(paths, "udp"), [(0, 65535)])
        self.assertEqual(_port_ranges(paths, "icmp"), [(0, 65535)])
        self.assertEqual(paths[0]["excluded_protocols"], ["tcp"])

    def test_policy_uncertainty_respects_vpc_protocol_exclusions(self):
        policy = _terraform_resource(
            "google_compute_firewall_policy_rule.uncertain",
            "google_compute_firewall_policy_rule",
            {
                "firewall_policy": "123",
                "priority": 900,
                "direction": "INGRESS",
                "action": "deny",
                "target_resources": ["google_compute_network.main.id"],
                "match": [
                    {"src_ip_ranges": ["0.0.0.0/0"], "layer4_configs": [{"ip_protocol": "tcp", "ports": ["bad"]}]}
                ],
            },
        )
        inventory = _inventory(
            [_firewall("allow", "allow", protocol="all"), _firewall("deny", "deny", priority=900), policy]
        )
        instance = _instance(inventory)
        self.assertTrue(instance.public_exposure)
        paths = instance.get_metadata_field(GcpResourceMetadata.EFFECTIVE_FIREWALL_INGRESS)
        self.assertEqual(_port_ranges(paths, "tcp"), [])
        self.assertEqual(_port_ranges(paths, "udp"), [(0, 65535)])

    def test_unknown_priority_deny_precedes_known_allows_for_its_subset(self):
        paths = _paths(
            [
                _firewall("allow", "allow", ports=["20-30"], priority=0),
                _firewall("deny", "deny", ports=["22-25"], unknown={"priority": True}),
            ]
        )
        self.assertEqual(_port_ranges(paths), [(20, 21), (26, 30)])

    def test_partial_source_constraints_remain_uncertain_for_their_ports(self):
        instance = _instance(
            _inventory(
                [
                    _firewall("allow", "allow", ports=["20-30"]),
                    _firewall("deny", "deny", priority=900, ports=["22-25"], sources=["10.0.0.0/8"]),
                ]
            )
        )
        self.assertEqual(
            _port_ranges(instance.get_metadata_field(GcpResourceMetadata.EFFECTIVE_FIREWALL_INGRESS)),
            [(20, 21), (26, 30)],
        )
        self.assertTrue(
            any(
                "partial source CIDR" in reason
                for reason in instance.get_metadata_field(GcpResourceMetadata.INTERNET_INGRESS_UNCERTAINTIES)
            )
        )

    def test_non_port_protocols_remain_exposed_without_admin_findings(self):
        inventory = _inventory(
            [
                _firewall("all", "allow", protocol="all"),
                _firewall("tcp", "deny", priority=900),
                _firewall("udp", "deny", protocol="udp", priority=900),
            ]
        )
        instance = _instance(inventory)
        self.assertTrue(instance.public_exposure)
        paths = instance.get_metadata_field(GcpResourceMetadata.EFFECTIVE_FIREWALL_INGRESS)
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0]["protocol"], "-1")
        self.assertEqual(paths[0]["excluded_protocols"], ["tcp", "udp"])
        self.assertIsNone(paths[0]["from_port"])
        self.assertEqual(_broad_ingress_findings(inventory), [])
        self.assertTrue(any(boundary.target == instance.address for boundary in detect_trust_boundaries(inventory)))

    def test_all_protocol_deny_and_specific_non_port_protocols(self):
        self.assertEqual(
            _paths(
                [_firewall("allow", "allow", protocol="all"), _firewall("deny", "deny", protocol="all", priority=900)]
            ),
            [],
        )
        for protocol in ("icmp", "esp", "99", "0"):
            with self.subTest(protocol=protocol):
                paths = _paths(
                    [
                        _firewall("allow", "allow", protocol=protocol),
                        _firewall("deny", "deny", protocol="tcp", priority=900),
                    ]
                )
                self.assertEqual([path["protocol"] for path in paths], [protocol])
                self.assertIsNone(paths[0]["from_port"])

    def test_implicit_ingress_deny_wins_at_priority_65535(self):
        self.assertEqual(_paths([_firewall("allow", "allow", ports=["443"], priority=65535)]), [])
        self.assertEqual(
            _port_ranges(_paths([_firewall("allow", "allow", ports=["443"], priority=65534)])), [(443, 443)]
        )

    def test_resource_order_does_not_change_traffic_or_provenance(self):
        firewalls = [
            _firewall("low", "allow", ports=["20-30"]),
            _firewall("high", "allow", ports=["23-24"], priority=800),
            _firewall("deny", "deny", ports=["22-25"], priority=900),
            _firewall("udp", "allow", protocol="udp", ports=["53"]),
        ]
        original_values = [copy.deepcopy(resource.values) for resource in firewalls]
        expected = _paths(firewalls)
        expected_reasons = _instance(_inventory(firewalls)).internet_ingress_reasons
        for order in itertools.permutations(firewalls):
            with self.subTest(order=[resource.address for resource in order]):
                instance = _instance(_inventory(order))
                self.assertEqual(instance.get_metadata_field(GcpResourceMetadata.EFFECTIVE_FIREWALL_INGRESS), expected)
                self.assertEqual(instance.internet_ingress_reasons, expected_reasons)
        self.assertEqual([resource.values for resource in firewalls], original_values)

    def test_equal_priority_allows_choose_a_stable_witness_per_subset(self):
        first = _firewall("a", "allow", ports=["20-25"])
        second = _firewall("b", "allow", ports=["23-30"])
        expected = _paths([first, second])
        self.assertEqual(
            [(path["firewall_address"], path["from_port"], path["to_port"]) for path in expected],
            [("google_compute_firewall.a", 20, 25), ("google_compute_firewall.b", 26, 30)],
        )
        self.assertEqual(_paths([second, first]), expected)

    def test_redecoration_replaces_stale_ingress_paths_and_reasons(self):
        inventory = _inventory([_firewall("allow", "allow", ports=["443"])])
        instance = _instance(inventory)
        self.assertTrue(instance.public_exposure)
        deny = normalize_compute_firewall(_firewall("deny", "deny", priority=900, ports=["443"]))
        index = GcpResourceIndexBuilder().build([*inventory.resources, deny])
        derive_public_compute_exposure(instance, index)
        self.assertFalse(instance.public_exposure)
        self.assertEqual(instance.internet_ingress_reasons, [])
        self.assertEqual(instance.public_exposure_reasons, [])
        self.assertEqual(instance.get_metadata_field(GcpResourceMetadata.EFFECTIVE_FIREWALL_INGRESS), [])

    def test_split_merged_duplicate_and_reordered_ranges_have_identical_results(self):
        expected = _paths(
            [_firewall("allow", "allow", ports=["20-30"]), _firewall("deny", "deny", priority=900, ports=["22-25"])]
        )
        for allow_ports in (["20-24", "25-30"], ["25-30", "20-24", "22-26"], ["20-30", "20-30"]):
            for deny_ports in (["22-23", "24-25"], ["24-25", "22-23"], ["22-25", "23-24"]):
                with self.subTest(allow=allow_ports, deny=deny_ports):
                    self.assertEqual(
                        _paths(
                            [
                                _firewall("allow", "allow", ports=allow_ports),
                                _firewall("deny", "deny", priority=900, ports=deny_ports),
                            ]
                        ),
                        expected,
                    )

    def test_equivalent_layer4_blocks_preserve_coverage_and_record_all_sources(self):
        allow = _firewall("allow", "allow", ports=["20-30"])
        expected = _paths([allow])
        allow.values["allow"] = [{"protocol": "tcp", "ports": ["20-24"]}, {"protocol": "6", "ports": ["25-30"]}]
        actual = _paths([allow])
        self.assertEqual(_port_ranges(actual), _port_ranges(expected))
        self.assertEqual(actual[0]["match_paths"], ["allow[0]", "allow[1]"])

    def test_downstream_findings_use_surviving_ports(self):
        inventory = _inventory(
            [_firewall("allow", "allow", ports=["20-30"]), _firewall("deny", "deny", priority=900, ports=["22-25"])]
        )
        self.assertTrue(_instance(inventory).public_exposure)
        self.assertEqual(
            _instance(inventory).internet_ingress_reasons,
            [
                "google_compute_firewall.allow ingress tcp 20-21 from 0.0.0.0/0",
                "google_compute_firewall.allow ingress tcp 26-30 from 0.0.0.0/0",
            ],
        )
        self.assertEqual(_broad_ingress_findings(inventory), [])
        retained_admin = _inventory(
            [_firewall("allow", "allow", ports=["20-30"]), _firewall("deny", "deny", priority=900, ports=["25-30"])]
        )
        findings = _broad_ingress_findings(retained_admin)
        self.assertEqual(len(findings), 1)
        evidence = {item.key: item.values for item in findings[0].evidence}
        self.assertEqual(evidence["firewall_rules"], ["google_compute_firewall.allow ingress tcp 20-24 from 0.0.0.0/0"])

    def test_generated_small_plans_match_a_packet_level_priority_oracle(self):
        generator = random.Random(7291)
        for case in range(60):
            specs = []
            firewalls = []
            for index in range(generator.randint(1, 7)):
                action = generator.choice(("allow", "deny"))
                priority = generator.choice((0, 100, 200, 65535))
                protocol = generator.choice(("tcp", "udp", "all", "icmp"))
                start, end = sorted((generator.randint(0, 12), generator.randint(0, 12)))
                ports = [f"{start}-{end}"] if protocol in {"tcp", "udp"} else None
                specs.append((action, priority, protocol, start if ports else 0, end if ports else 65535))
                firewalls.append(_firewall(f"r{index}", action, priority=priority, protocol=protocol, ports=ports))
            paths = _paths(firewalls)
            for protocol in ("tcp", "udp", "icmp", "99"):
                ranges = _port_ranges(paths, protocol)
                for port in range(13):
                    with self.subTest(case=case, protocol=protocol, port=port):
                        matches = [
                            (priority, action)
                            for action, priority, rule_protocol, start, end in specs
                            if rule_protocol in {"all", protocol} and start <= port <= end
                        ]
                        winning_priority = min((priority for priority, _ in matches), default=65535)
                        expected = winning_priority < 65535 and not any(
                            priority == winning_priority and action == "deny" for priority, action in matches
                        )
                        self.assertEqual(any(start <= port <= end for start, end in ranges), expected)
