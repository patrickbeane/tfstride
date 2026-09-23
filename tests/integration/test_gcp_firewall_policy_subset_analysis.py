from __future__ import annotations

import copy
import json
import random
import tempfile
import unittest
from pathlib import Path

from tests.providers.gcp.normalizer_support import _terraform_resource
from tests.providers.gcp.rule_support.compute import _compute_instance, _compute_network, _compute_subnetwork
from tests.providers.gcp.rule_support.data import _secret_manager_secret, _secret_manager_secret_iam_member
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.app import TfStride
from tfstride.providers.gcp.metadata import GcpResourceMetadata as M


def _rule(
    name, action, *, priority=1000, protocol="tcp", ports=("22",), policy="org", sources=("0.0.0.0/0",), unknown=None
):
    return _terraform_resource(
        f"google_compute_firewall_policy_rule.{name}",
        "google_compute_firewall_policy_rule",
        {
            "firewall_policy": f"{policy}-policy",
            "action": action,
            "priority": priority,
            "direction": "INGRESS",
            "match": [
                {
                    "src_ip_ranges": list(sources),
                    "layer4_configs": [{"ip_protocol": protocol, "ports": list(ports) if ports is not None else None}],
                }
            ],
        },
        unknown_values=unknown,
    )


def _vpc(name="https", action="allow", *, priority=1000, protocol="tcp", ports=("443",), sources=("0.0.0.0/0",)):
    return _terraform_resource(
        f"google_compute_firewall.{name}",
        "google_compute_firewall",
        {
            "network": "google_compute_network.main.id",
            "priority": priority,
            "direction": "INGRESS",
            "source_ranges": list(sources),
            action: [{"protocol": protocol, "ports": list(ports) if ports is not None else None}],
        },
    )


def _resources(*rules, data=False):
    resources = [
        _compute_network(),
        _compute_subnetwork(),
        _compute_instance(),
        _terraform_resource(
            "google_project.main", "google_project", {"project_id": "tfstride-demo", "folder_id": "folders/20"}
        ),
        _terraform_resource("google_folder.main", "google_folder", {"name": "folders/20", "parent": "organizations/1"}),
        *[
            _terraform_resource(
                f"google_compute_firewall_policy_association.{name}",
                "google_compute_firewall_policy_association",
                {"firewall_policy": f"{name}-policy", "attachment_target": scope},
            )
            for name, scope in (("org", "organizations/1"), ("folder", "folders/20"))
        ],
        *rules,
    ]
    if data:
        resources.extend(
            [
                _secret_manager_secret(),
                _secret_manager_secret_iam_member(
                    member="serviceAccount:tfstride-web@tfstride-demo.iam.gserviceaccount.com"
                ),
            ]
        )
    return resources


def _analyze(resources):
    # Exercise actual plan JSON ingestion, including after_unknown, rather than
    # passing normalized matches directly into the packet evaluator.
    records = [
        {
            "address": resource.address,
            "mode": resource.mode,
            "type": resource.resource_type,
            "name": resource.name,
            "provider_name": resource.provider_name,
            "values": resource.values,
        }
        for resource in resources
    ]
    payload = {
        "terraform_version": "1.8.5",
        "planned_values": {"root_module": {"resources": records}},
        "resource_changes": [
            {
                **{key: value for key, value in record.items() if key != "values"},
                "change": {"actions": ["create"], "after": resource.values, "after_unknown": resource.unknown_values},
            }
            for resource, record in zip(resources, records, strict=True)
        ],
    }
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "firewall.tfplan.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return TfStride(
            rule_policy=RulePolicy(
                enabled_rule_ids=frozenset(
                    {
                        "gcp-public-workload-sensitive-data-access",
                        "gcp-public-compute-broad-ingress",
                    }
                )
            )
        ).analyze_plan(path)


def _instance(result):
    instance = result.inventory.get_by_address("google_compute_instance.web")
    assert instance is not None
    return instance


def _paths(result):
    return _instance(result).get_metadata_field(M.EFFECTIVE_FIREWALL_INGRESS)


def _ranges(result, protocol="tcp", source="0.0.0.0/0"):
    return sorted(
        (
            path["from_port"] if path["from_port"] is not None else 0,
            path["to_port"] if path["to_port"] is not None else 65535,
        )
        for path in _paths(result)
        if source in path["source_ranges"]
        and (path["protocol"] == protocol or (path["protocol"] == "-1" and protocol not in path["excluded_protocols"]))
    )


class GcpFirewallPolicySubsetIntegrationTests(unittest.TestCase):
    def test_policy_ssh_deny_preserves_https_sensitive_data_finding(self):
        resources = _resources(_rule("ssh", "deny"), _vpc(), data=True)
        result = _analyze(resources)

        self.assertTrue(_instance(result).public_exposure)
        self.assertEqual(_ranges(result), [(443, 443)])
        self.assertEqual(_paths(result)[0]["firewall_address"], "google_compute_firewall.https")
        self.assertEqual(_paths(result)[0]["match_paths"], ["allow[0]"])
        self.assertEqual(
            [finding.rule_id for finding in result.findings], ["gcp-public-workload-sensitive-data-access"]
        )
        finding = result.findings[0]
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
        self.assertEqual(
            evidence["data_access_path"], ["google_compute_instance.web reaches google_secret_manager_secret.api_key"]
        )
        self.assertIn(
            "internet-to-service:internet->google_compute_instance.web",
            [boundary.identifier for boundary in result.trust_boundaries],
        )

        blocked = _analyze(resources + [_rule("https", "deny", priority=900, ports=("443",))])
        self.assertFalse(_instance(blocked).public_exposure)
        self.assertEqual(blocked.findings, [])
        self.assertNotIn(
            "internet-to-service:internet->google_compute_instance.web",
            [boundary.identifier for boundary in blocked.trust_boundaries],
        )

    def test_policy_ssh_allow_and_vpc_https_keep_separate_winners(self):
        result = _analyze(
            _resources(
                _rule("ssh", "allow", priority=70000),
                _vpc(),
                _vpc("deny_ssh", "deny", priority=0, ports=("22",)),
            )
        )
        self.assertEqual(_ranges(result), [(22, 22), (443, 443)])
        paths = {path["firewall_address"]: path for path in _paths(result)}
        self.assertEqual(set(paths), {"google_compute_firewall_policy_rule.ssh", "google_compute_firewall.https"})
        self.assertEqual(paths["google_compute_firewall_policy_rule.ssh"]["rule_priority"], 70000)
        self.assertEqual(
            paths["google_compute_firewall_policy_rule.ssh"]["match_paths"], ["match[0].layer4_configs[0]"]
        )

    def test_partial_delegation_does_not_widen_vpc_or_reenter_current_policy(self):
        result = _analyze(
            _resources(
                _rule("delegate", "goto_next", priority=100, ports=("22-25",)),
                _rule("lower", "allow", ports=("20-30",)),
                _vpc("allow", ports=("22-23",)),
            )
        )
        self.assertEqual(_ranges(result), [(20, 21), (22, 23), (26, 30)])
        policy = [path for path in _paths(result) if path["firewall_address"].endswith(".lower")]
        self.assertEqual([(path["from_port"], path["to_port"]) for path in policy], [(20, 21), (26, 30)])

    def test_tcp_delegation_does_not_skip_lower_udp_rule(self):
        result = _analyze(
            _resources(
                _rule("delegate", "goto_next", priority=100, protocol="6"),
                _rule("dns", "allow", protocol="udp", ports=("53",)),
                _vpc("deny_dns", "deny", protocol="udp", ports=("53",)),
            )
        )
        self.assertEqual(_ranges(result), [])
        self.assertEqual(_ranges(result, "udp"), [(53, 53)])
        self.assertTrue(_instance(result).public_exposure)

    def test_constraints_survive_multiple_policies_and_delegations(self):
        result = _analyze(
            _resources(
                _rule("org_deny", "deny", priority=80000, ports=("22-23",)),
                _rule("org_delegate", "goto_next", priority=90000, ports=("20-30",)),
                _rule("org_allow", "allow", priority=100000, ports=("20-40",)),
                _rule("folder_deny", "deny", priority=10, policy="folder", ports=("24-25",)),
                _rule("folder_delegate", "goto_next", priority=20, policy="folder", ports=("26-27",)),
                _rule("folder_allow", "allow", priority=30, policy="folder", ports=("20-30",)),
                _vpc("allow", ports=("20-40",)),
            )
        )
        self.assertEqual(_ranges(result), [(20, 21), (26, 27), (28, 30), (31, 40)])
        self.assertEqual(
            {(path["firewall_address"], path["from_port"], path["to_port"]) for path in _paths(result)},
            {
                ("google_compute_firewall_policy_rule.org_allow", 31, 40),
                ("google_compute_firewall_policy_rule.folder_allow", 20, 21),
                ("google_compute_firewall_policy_rule.folder_allow", 28, 30),
                ("google_compute_firewall.allow", 26, 27),
            },
        )

    def test_ip_families_and_non_port_protocols_keep_independent_decisions(self):
        result = _analyze(
            _resources(
                _rule("v4_tcp", "deny", ports=None),
                _rule("icmp", "goto_next", protocol="icmp", ports=None, priority=2000),
                _rule("udp", "allow", protocol="udp", ports=("443",), priority=3000),
                _vpc("all", protocol="all", ports=None, sources=("0.0.0.0/0", "::/0")),
            )
        )
        self.assertEqual(_ranges(result), [])
        self.assertEqual(_ranges(result, source="::/0"), [(0, 65535)])
        self.assertEqual(_ranges(result, "icmp"), [(0, 65535)])
        self.assertEqual(_ranges(result, "udp"), [(0, 442), (443, 443), (444, 65535)])

    def test_unknown_policy_deny_ports_restrict_tcp_without_losing_udp(self):
        result = _analyze(
            _resources(
                _rule("unknown", "deny", unknown={"match": [{"layer4_configs": [{"ports": True}]}]}),
                _vpc("tcp", ports=("443",)),
                _vpc("udp", protocol="udp", ports=("443",)),
            )
        )
        self.assertEqual(_ranges(result), [])
        self.assertEqual(_ranges(result, "udp"), [(443, 443)])
        self.assertIn(
            "ports is unknown", " ".join(_instance(result).get_metadata_field(M.INTERNET_INGRESS_UNCERTAINTIES))
        )

    def test_uncertain_deny_and_goto_next_do_not_discard_disjoint_ports(self):
        for action in ("deny", "goto_next"):
            with self.subTest(action=action):
                result = _analyze(
                    _resources(
                        _rule("uncertain", action, priority=100, ports=("22-25",), sources=("10.0.0.0/8",)),
                        _rule("lower", "allow", ports=("20-30",)),
                        _vpc("all", ports=("20-30",)),
                    )
                )
                self.assertEqual(_ranges(result), [(20, 21), (26, 30)])
                self.assertIn(
                    "partial source CIDR",
                    " ".join(_instance(result).get_metadata_field(M.INTERNET_INGRESS_UNCERTAINTIES)),
                )

    def test_unknown_goto_next_cannot_assume_either_same_policy_allow_or_vpc_fallback(self):
        result = _analyze(
            _resources(
                _rule(
                    "delegate", "goto_next", priority=100, unknown={"match": [{"layer4_configs": [{"ports": True}]}]}
                ),
                _rule("allow", "allow", ports=("443",)),
                _vpc("tcp", ports=("443",)),
                _vpc("udp", protocol="udp", ports=("443",)),
            )
        )
        self.assertEqual(_ranges(result), [])
        self.assertEqual(_ranges(result, "udp"), [(443, 443)])

    def test_unknown_allow_does_not_erase_an_independent_allow(self):
        result = _analyze(
            _resources(
                _rule("uncertain", "allow", priority=100, unknown={"match": True}),
                _rule("allow", "allow", ports=("443",)),
            )
        )
        self.assertEqual(_ranges(result), [(443, 443)])
        self.assertEqual(_paths(result)[0]["firewall_address"], "google_compute_firewall_policy_rule.allow")
        self.assertTrue(_instance(result).get_metadata_field(M.INTERNET_INGRESS_UNCERTAINTIES))

    def test_resource_order_and_split_merged_delegation_are_equivalent(self):
        signatures = []
        for ports in (("22-25",), ("22-23", "24-25"), ("22-25", "22-23", "22-25")):
            resources = _resources(
                _rule("delegate", "goto_next", priority=100, ports=ports),
                _rule("lower", "allow", ports=("20-30",)),
                _vpc("allow", ports=("22-23",)),
            )
            original = copy.deepcopy(resources)
            result = _analyze(resources)
            reversed_result = _analyze(list(reversed(resources)))
            self.assertEqual(_paths(result), _paths(reversed_result))
            self.assertEqual(resources, original)
            signatures.append(
                [{key: value for key, value in path.items() if key != "match_paths"} for path in _paths(result)]
            )
        self.assertTrue(all(signature == signatures[0] for signature in signatures))

    def test_generated_layers_agree_with_independent_per_packet_oracle(self):
        rng = random.Random(94831)
        for case in range(24):
            resources = []
            layers = []
            for layer in ("org", "folder", "vpc"):
                specs = []
                for index in range(5):
                    protocol = rng.choice(("tcp", "udp", "icmp", "99", "all"))
                    start, end = (
                        sorted((rng.randrange(9), rng.randrange(9))) if protocol in {"tcp", "udp"} else (0, 65535)
                    )
                    action = rng.choice(("allow", "deny") if layer == "vpc" else ("allow", "deny", "goto_next"))
                    priority = (10000 if layer == "org" else 100 if layer == "folder" else 1) + index
                    sources = rng.choice((("0.0.0.0/0",), ("::/0",), ("0.0.0.0/0", "::/0")))
                    name = f"{layer}_{index}"
                    kwargs = dict(
                        priority=priority,
                        protocol=protocol,
                        sources=sources,
                        ports=(f"{start}-{end}",) if protocol in {"tcp", "udp"} else None,
                    )
                    resource = (
                        _vpc(name, action, **kwargs) if layer == "vpc" else _rule(name, action, policy=layer, **kwargs)
                    )
                    resources.append(resource)
                    specs.append((action, protocol, start, end, sources, resource.address))
                layers.append(specs)
            result = _analyze(_resources(*resources))
            for source in ("0.0.0.0/0", "::/0"):
                for protocol in ("tcp", "udp", "icmp", "99"):
                    for port in range(9):
                        expected = None
                        decided = False
                        for layer in layers:
                            for action, match_protocol, start, end, sources, address in layer:
                                if (
                                    source not in sources
                                    or match_protocol not in {"all", protocol}
                                    or not start <= port <= end
                                ):
                                    continue
                                if action == "goto_next":
                                    break
                                decided = True
                                expected = address if action == "allow" else None
                                break
                            if decided:
                                break
                        actual = [
                            path["firewall_address"]
                            for path in _paths(result)
                            if source in path["source_ranges"]
                            and (
                                path["protocol"] == protocol
                                or (path["protocol"] == "-1" and protocol not in path["excluded_protocols"])
                            )
                            and (path["from_port"] is None or path["from_port"] <= port <= path["to_port"])
                        ]
                        with self.subTest(case=case, source=source, protocol=protocol, port=port):
                            self.assertEqual(actual, [expected] if expected else [])
