from __future__ import annotations

import copy
import random
import unittest

from tests.providers.gcp.normalizer_support import _terraform_resource
from tfstride.providers.gcp.metadata import GcpResourceMetadata as M
from tfstride.providers.gcp.normalizer import GcpNormalizer


def _resource(kind, name, values, unknown=None):
    return _terraform_resource(f"google_{kind}.{name}", f"google_{kind}", values, unknown_values=unknown)


def _base():
    return [
        _resource("compute_network", "main", {"name": "main", "project": "host"}),
        _resource(
            "compute_instance",
            "web",
            {
                "name": "web",
                "project": "host",
                "network_interface": [{"network": "google_compute_network.main.id", "access_config": [{}]}],
            },
        ),
        _resource("project", "host", {"project_id": "host", "folder_id": "google_folder.child.name"}),
        _resource("folder", "child", {"name": "folders/20", "parent": "google_folder.parent.name"}),
        _resource("folder", "parent", {"name": "folders/10", "parent": "organizations/1"}),
        _resource(
            "compute_firewall",
            "vpc",
            {
                "network": "google_compute_network.main.id",
                "source_ranges": ["0.0.0.0/0"],
                "allow": [{"protocol": "tcp", "ports": ["22"]}],
            },
        ),
    ]


def _rule(name, policy, action="allow", priority=1000, unknown=None):
    return _resource(
        "compute_firewall_policy_rule",
        name,
        {
            "firewall_policy": policy,
            "priority": priority,
            "action": action,
            "direction": "INGRESS",
            "match": [{"src_ip_ranges": ["0.0.0.0/0"], "layer4_configs": [{"ip_protocol": "tcp", "ports": ["22"]}]}],
        },
        unknown,
    )


def _policy(name, target, action="allow", priority=1000):
    reference = f"google_compute_firewall_policy.{name}.name"
    return [
        _resource(
            "compute_firewall_policy",
            name,
            {
                "name": f"id-{name}",
                "short_name": name,
                "parent": "organizations/1",
            },
        ),
        _resource(
            "compute_firewall_policy_association",
            name,
            {
                "firewall_policy": reference,
                "attachment_target": target,
            },
        ),
        _rule(name, reference, action, priority),
    ]


def _result(resources):
    instance = GcpNormalizer().normalize(resources).get_by_address("google_compute_instance.web")
    assert instance is not None
    return (
        instance.public_exposure,
        instance.get_metadata_field(M.INTERNET_INGRESS_FIREWALLS),
        instance.get_metadata_field(M.INTERNET_INGRESS_STATE),
        instance.get_metadata_field(M.INTERNET_INGRESS_UNCERTAINTIES),
        instance.get_metadata_field(M.EFFECTIVE_FIREWALL_INGRESS),
    )


class GcpFirewallPolicyOrderTests(unittest.TestCase):
    def assertUnknown(self, resources, reason):
        exposed, sources, state, uncertainties, paths = _result(resources)
        self.assertFalse(exposed)
        self.assertEqual(sources, [])
        self.assertEqual(state, "unknown")
        self.assertEqual(paths, [])
        self.assertIn(reason, " ".join(uncertainties))

    def test_organization_precedes_folder_regardless_of_rule_priorities(self):
        for org_action, folder_action, expected in [("deny", "allow", False), ("allow", "deny", True)]:
            with self.subTest(org_action=org_action):
                result = _result(
                    _base()
                    + _policy("org", "organizations/1", org_action, 50000)
                    + _policy("folder", "folders/20", folder_action, 1)
                )
                self.assertEqual(result[0], expected)
                self.assertEqual(result[1], ["google_compute_firewall_policy_rule.org"] if expected else [])
                self.assertEqual(result[3], [])

    def test_parent_folder_precedes_child_using_native_parent_links(self):
        resources = _base()
        resources[2].values["folder_id"] = "20"
        resources[3].values["parent"] = "folders/10"
        result = _result(
            resources + _policy("parent", "folders/10", "deny", 60000) + _policy("child", "folders/20", "allow", 10)
        )
        self.assertFalse(result[0])
        self.assertEqual(result[3], [])

    def test_native_scope_urls_and_terraform_references_describe_the_same_hierarchy(self):
        resources = _base()
        resources[2].values["folder_id"] = "folders/20"
        resources[3].values["parent"] = "https://cloudresourcemanager.googleapis.com/v3/folders/10"
        resources[4].values["parent"] = "https://cloudresourcemanager.googleapis.com/v3/organizations/1/"
        result = _result(
            resources
            + _policy("org", "https://cloudresourcemanager.googleapis.com/v3/organizations/1/", "deny", 50000)
            + _policy("child", "https://cloudresourcemanager.googleapis.com/v3/folders/20", "allow", 1)
        )
        self.assertFalse(result[0])
        self.assertEqual(result[3], [])

    def test_unknown_native_folder_identity_does_not_match_stale_name(self):
        base = _base()
        base[3].unknown_values["name"] = True
        self.assertUnknown(base + _policy("child", "folders/20", "allow"), "scope cannot be resolved")

    def test_unknown_policy_identity_cannot_resolve_a_native_alias(self):
        policy = _policy("org", "organizations/1")
        policy[0].unknown_values["name"] = True
        policy[2].values["firewall_policy"] = "id-org"
        self.assertUnknown(_base() + policy, "identity is unknown")

    def test_unknown_project_parent_prevents_organization_scope_claim(self):
        base = _base()
        base[2].unknown_values["folder_id"] = True
        self.assertUnknown(base + _policy("org", "organizations/1"), "parent is unknown")

    def test_goto_next_progresses_to_child_policy_then_uses_its_priorities(self):
        result = _result(
            _base()
            + _policy("org", "organizations/1", "goto_next", 50000)
            + [_rule("skipped", "id-org", "deny", 51000)]
            + _policy("parent", "folders/10", "goto_next", 50000)
            + _policy("child", "folders/20", "deny", 100)
            + [_rule("child_allow", "id-child", "allow", 50)]
        )
        self.assertTrue(result[0])
        self.assertEqual(result[1], ["google_compute_firewall_policy_rule.child_allow"])
        self.assertEqual(result[3], [])

    def test_goto_next_through_ordered_policies_reaches_vpc(self):
        result = _result(
            _base()
            + _policy("org", "organizations/1", "goto_next", 50000)
            + _policy("folder", "folders/20", "goto_next", 1)
        )
        self.assertEqual(result[1], ["google_compute_firewall.vpc"])
        self.assertEqual(result[3], [])

    def test_rules_using_native_and_terraform_policy_references_share_one_priority_space(self):
        result = _result(
            _base() + _policy("org", "organizations/1", "allow", 1000) + [_rule("deny", "id-org", "deny", 900)]
        )
        self.assertFalse(result[0])
        self.assertEqual(result[3], [])

    def test_policy_owner_does_not_determine_attachment_order(self):
        folder = _policy("folder", "folders/20", "allow", 10)
        folder[0].values["parent"] = "organizations/999"
        result = _result(_base() + _policy("org", "organizations/1", "deny", 50000) + folder)
        self.assertFalse(result[0])
        self.assertEqual(result[3], [])

    def test_lower_policy_uncertain_deny_cannot_override_earlier_allow(self):
        folder = _policy("folder", "folders/20", "deny", 1)
        folder[2].unknown_values["match"] = True
        result = _result(_base() + _policy("org", "organizations/1", "allow", 50000) + folder)
        self.assertTrue(result[0])
        self.assertEqual(result[1], ["google_compute_firewall_policy_rule.org"])
        self.assertEqual(result[3], [])

    def test_unknown_same_policy_priority_can_override_even_when_raw_priority_is_lower(self):
        uncertain = _rule("uncertain", "id-org", "deny", 1000, {"priority": True})
        result = _result(_base() + _policy("org", "organizations/1", "allow", 10) + [uncertain])
        self.assertFalse(result[0])
        self.assertEqual(result[2], "unknown")

    def test_same_scope_policies_have_no_address_based_order(self):
        resources = _base() + _policy("a", "folders/20", "allow", 1) + _policy("z", "folders/20", "deny", 50000)
        self.assertUnknown(resources, "order is ambiguous")
        self.assertEqual(_result(resources), _result(list(reversed(resources))))

    def test_multiple_applicable_associations_for_one_policy_are_uncertain(self):
        resources = _base() + _policy("org", "organizations/1")
        resources.append(
            _resource(
                "compute_firewall_policy_association",
                "second",
                {
                    "firewall_policy": "id-org",
                    "attachment_target": "folders/20",
                },
            )
        )
        self.assertUnknown(resources, "multiple applicable")

    def test_ambiguous_policy_alias_is_not_joined_to_an_arbitrary_policy(self):
        policies = _policy("first", "folders/20") + _policy("second", "folders/10")
        policies[0].values["short_name"] = policies[3].values["short_name"] = "collision"
        policies[1].values["firewall_policy"] = "collision"
        self.assertUnknown(_base() + policies, "reference is ambiguous")

    def test_unknown_association_target_or_reference_does_not_fall_back_to_vpc(self):
        for field in ("attachment_target", "firewall_policy"):
            with self.subTest(field=field):
                policy = _policy("org", "organizations/1")
                policy[1].unknown_values[field] = True
                self.assertUnknown(_base() + policy, "unknown")

    def test_missing_attachment_target_is_not_ignored(self):
        policy = _policy("org", "organizations/1")
        del policy[1].values["attachment_target"]
        self.assertUnknown(_base() + policy, "attachment target is missing")

    def test_unknown_rule_policy_reference_is_not_given_a_fallback_group(self):
        policy = _policy("org", "organizations/1")
        policy[2].unknown_values["firewall_policy"] = True
        self.assertUnknown(_base() + policy, "reference is missing or unknown")

    def test_missing_association_does_not_prove_policy_scope(self):
        policy = _policy("org", "organizations/1")
        self.assertUnknown(_base() + [policy[0], policy[2]], "association is not modeled")

    def test_incomplete_ancestry_does_not_exclude_possible_parent_policy(self):
        base = _base()
        base = [resource for resource in base if resource.address != "google_folder.parent"]
        self.assertUnknown(base + _policy("org", "organizations/1", "deny"), "parent is unresolved")

    def test_unknown_parent_does_not_use_stale_known_parent(self):
        base = _base()
        base[3].unknown_values["parent"] = True
        self.assertUnknown(base + _policy("org", "organizations/1", "deny"), "parent is unknown")

    def test_cycle_cannot_establish_an_attachment_order(self):
        base = _base()
        base[4].values["parent"] = "folders/20"
        self.assertUnknown(base + _policy("child", "folders/20"), "cycle")

    def test_ambiguous_project_scope_prevents_fallback(self):
        base = _base()
        base.append(_resource("project", "duplicate", {"project_id": "host", "org_id": "2"}))
        self.assertUnknown(base + _policy("org", "organizations/1"), "ambiguous")

    def test_known_unrelated_scopes_do_not_suppress_vpc(self):
        for target in ("organizations/2", "folders/999", "projects/other", "projects/other/global/networks/other"):
            with self.subTest(target=target):
                result = _result(_base() + _policy("unrelated", target, "deny"))
                self.assertTrue(result[0])
                self.assertEqual(result[1], ["google_compute_firewall.vpc"])
                self.assertEqual(result[3], [])

    def test_unrelated_association_unknown_policy_reference_is_irrelevant(self):
        policy = _policy("unrelated", "organizations/2", "deny")
        policy[1].unknown_values["firewall_policy"] = True
        # No rule referring to an unidentified policy: the unrelated association alone.
        result = _result(_base() + [policy[1]])
        self.assertTrue(result[0])
        self.assertEqual(result[3], [])

    def test_shared_vpc_uses_network_project_ancestry(self):
        base = _base()
        base[1].values["project"] = "service"
        base.append(_resource("project", "service", {"project_id": "service", "org_id": "2"}))
        result = _result(
            base + _policy("host", "organizations/1", "deny", 50000) + _policy("service", "organizations/2", "allow", 1)
        )
        self.assertFalse(result[0])
        self.assertEqual(result[3], [])

    def test_association_and_hierarchy_order_are_resource_order_independent(self):
        resources = _base() + _policy("org", "organizations/1", "goto_next", 50000)
        resources += _policy("parent", "folders/10", "goto_next", 50000)
        resources += _policy("child", "folders/20", "allow", 1000)
        expected = _result(resources)
        original = copy.deepcopy(resources)
        rng = random.Random(174)
        for iteration in range(25):
            with self.subTest(iteration=iteration):
                shuffled = list(resources)
                rng.shuffle(shuffled)
                self.assertEqual(_result(shuffled), expected)
        self.assertEqual(resources, original)
