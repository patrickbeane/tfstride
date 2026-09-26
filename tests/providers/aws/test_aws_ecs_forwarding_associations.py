from __future__ import annotations

import json
import tempfile
import unittest
from copy import deepcopy
from itertools import permutations
from pathlib import Path
from typing import Any

from tfstride.input.terraform_plan import load_terraform_plan
from tfstride.models import TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_decoration.ecs import MarkEcsLoadBalancerExposureStage
from tfstride.providers.aws.resource_decorator import AwsResourceDecorator
from tfstride.providers.aws.resource_facts import aws_facts


def _resource(kind: str, name: str, values: dict[str, Any]) -> TerraformResource:
    return TerraformResource(
        address=f"{kind}.{name}",
        resource_type=kind,
        name=name,
        mode="managed",
        provider_name="registry.terraform.io/hashicorp/aws",
        provider_config_key="aws",
        values=values,
    )


def _chain() -> list[TerraformResource]:
    return [
        _resource("aws_lb", "public", {"internal": False, "load_balancer_type": "application"}),
        _resource("aws_lb_target_group", "app", {"port": 8080, "protocol": "HTTP", "target_type": "ip"}),
        _resource(
            "aws_lb_listener",
            "https",
            {
                "load_balancer_arn": "aws_lb.public",
                "port": 443,
                "protocol": "HTTPS",
                "default_action": [{"type": "forward", "target_group_arn": "aws_lb_target_group.app"}],
            },
        ),
        _resource(
            "aws_ecs_service",
            "app",
            {
                "load_balancer": [
                    {
                        "target_group_arn": "aws_lb_target_group.app",
                        "container_name": "app",
                        "container_port": 8080,
                    }
                ]
            },
        ),
    ]


def _rule(name: str = "app", priority: int = 10, pattern: str = "/app/*") -> TerraformResource:
    return _resource(
        "aws_lb_listener_rule",
        name,
        {
            "listener_arn": "aws_lb_listener.https",
            "priority": priority,
            "condition": [{"path_pattern": [{"values": [pattern]}]}],
            "action": [{"type": "forward", "target_group_arn": "aws_lb_target_group.app"}],
        },
    )


def _facts(resources: list[TerraformResource]):
    inventory = AwsNormalizer().normalize(deepcopy(resources))
    service = inventory.get_by_address("aws_ecs_service.app")
    assert service is not None
    return aws_facts(service)


class AwsEcsForwardingAssociationTests(unittest.TestCase):
    def test_complete_forwarding_chain_is_independent_of_resource_order(self) -> None:
        baseline = _facts(_chain()).ecs_forwarding_associations
        self.assertEqual(len(baseline), 1)
        self.assertEqual(baseline[0]["target_group_address"], "aws_lb_target_group.app")
        for resources in permutations(_chain()):
            self.assertEqual(_facts(list(resources)).ecs_forwarding_associations, baseline)

    def test_missing_listener_or_target_group_cannot_establish_forwarding(self) -> None:
        for removed in ("aws_lb_listener", "aws_lb_target_group"):
            with self.subTest(removed=removed):
                self.assertEqual(
                    _facts(
                        [item for item in _chain() if item.resource_type != removed]
                    ).internet_facing_load_balancer_addresses,
                    [],
                )

    def test_unrelated_target_group_is_not_a_service_association(self) -> None:
        resources = _chain()
        resources.append(_resource("aws_lb_target_group", "other", {}))
        resources[2].values["default_action"][0]["target_group_arn"] = "aws_lb_target_group.other"
        self.assertEqual(_facts(resources).internet_facing_load_balancer_addresses, [])

    def test_legacy_elb_name_cannot_identify_an_alb_forwarding_chain(self) -> None:
        resources = _chain()
        resources[3].values["load_balancer"][0] = {
            "elb_name": "aws_lb.public",
            "container_name": "app",
            "container_port": 8080,
        }
        self.assertEqual(_facts(resources).internet_facing_load_balancer_addresses, [])

    def test_non_forwarding_or_unknown_action_cannot_use_a_target_reference(self) -> None:
        for action_type in ("redirect", "fixed-response", "authenticate-oidc", None):
            with self.subTest(action_type=action_type):
                resources = _chain()
                resources[2].values["default_action"][0]["type"] = action_type
                self.assertEqual(_facts(resources).internet_facing_load_balancer_addresses, [])

    def test_unknown_actions_and_stale_binding_values_fail_closed(self) -> None:
        for index, unknown in (
            (2, {"default_action": True}),
            (2, {"default_action": [{"type": True}]}),
            (2, {"default_action": [{"target_group_arn": True}]}),
            (2, {"load_balancer_arn": True}),
            (3, {"load_balancer": True}),
            (3, {"load_balancer": [{"target_group_arn": True}]}),
            (3, {"load_balancer": [{"container_port": True}]}),
            (0, {"internal": True}),
        ):
            with self.subTest(index=index, unknown=unknown):
                resources = _chain()
                resources[index].unknown_values = unknown
                self.assertEqual(_facts(resources).internet_facing_load_balancer_addresses, [])

    def test_weighted_targets_require_a_known_positive_weight(self) -> None:
        for weight, expected in ((0, False), (1, True), (999, True), (-1, False), (True, False), ("1", False)):
            with self.subTest(weight=weight):
                resources = _chain()
                resources[2].values["default_action"] = [
                    {
                        "type": "forward",
                        "forward": [{"target_group": [{"arn": "aws_lb_target_group.app", "weight": weight}]}],
                    }
                ]
                self.assertEqual(bool(_facts(resources).internet_facing_load_balancer_addresses), expected)
        resources[2].unknown_values = {"default_action": [{"forward": [{"target_group": [{"weight": True}]}]}]}
        self.assertEqual(_facts(resources).internet_facing_load_balancer_addresses, [])

    def test_zero_weight_target_does_not_hide_another_positive_target(self) -> None:
        resources = _chain()
        resources.append(_resource("aws_lb_target_group", "other", {}))
        resources[2].values["default_action"] = [
            {
                "type": "forward",
                "forward": [
                    {
                        "target_group": [
                            {"arn": "aws_lb_target_group.app", "weight": 1},
                            {"arn": "aws_lb_target_group.other", "weight": 0},
                        ]
                    }
                ],
            }
        ]
        self.assertEqual(_facts(resources).internet_facing_load_balancer_addresses, ["aws_lb.public"])

    def test_ambiguous_references_never_select_the_first_candidate(self) -> None:
        for index, reference_field in ((0, "load_balancer_arn"), (1, "target_group_arn")):
            for reverse in (False, True):
                with self.subTest(index=index, reverse=reverse):
                    resources = _chain()
                    resources[index].values["name"] = "shared"
                    resources[index].values["id"] = "shared"
                    duplicate = deepcopy(resources[index])
                    duplicate.address += "_duplicate"
                    resources.append(duplicate)
                    if index == 0:
                        resources[2].values[reference_field] = "shared"
                    else:
                        resources[2].values["default_action"][0][reference_field] = "shared"
                        resources[3].values["load_balancer"][0][reference_field] = "shared"
                    self.assertEqual(
                        _facts(
                            list(reversed(resources)) if reverse else resources
                        ).internet_facing_load_balancer_addresses,
                        [],
                    )

    def test_weak_alias_requires_known_source_scope(self) -> None:
        resources = _chain()
        resources[1].values["id"] = "shared"
        resources[2].values["default_action"][0]["target_group_arn"] = "shared"
        resources[3].values["load_balancer"][0]["target_group_arn"] = "shared"
        for item in resources:
            item.provider_config_key = None
        self.assertEqual(_facts(resources).internet_facing_load_balancer_addresses, [])

    def test_exact_addresses_can_cross_provider_configurations(self) -> None:
        resources = _chain()
        for index, item in enumerate(resources):
            item.provider_config_key = f"aws.alias{index}"
        self.assertEqual(_facts(resources).internet_facing_load_balancer_addresses, ["aws_lb.public"])

    def test_rule_conditions_and_priority_constrain_forwarding(self) -> None:
        resources = _chain()
        resources[2].values["default_action"] = [{"type": "fixed-response"}]
        resources.append(_rule())
        facts = _facts(resources)
        self.assertEqual(facts.internet_facing_load_balancer_addresses, ["aws_lb.public"])
        self.assertTrue(facts.ecs_forwarding_associations[0]["request_witness"]["path_pattern"].startswith("/app/"))
        earlier = _rule("earlier", priority=1, pattern="/*")
        earlier.values["action"] = [{"type": "fixed-response"}]
        resources.append(earlier)
        self.assertEqual(_facts(resources).internet_facing_load_balancer_addresses, [])
        earlier.values["condition"][0]["path_pattern"][0]["values"] = ["/elsewhere/*"]
        self.assertEqual(_facts(resources).internet_facing_load_balancer_addresses, ["aws_lb.public"])

    def test_unknown_or_unsupported_conditions_do_not_prove_a_rule_reachable(self) -> None:
        for condition in (
            [],
            [{"source_ip": [{"values": ["10.0.0.0/8"]}]}],
            [{"path_pattern": [{"regex_values": [".*"]}]}],
        ):
            resources = _chain()
            resources[2].values["default_action"] = [{"type": "fixed-response"}]
            rule = _rule()
            rule.values["condition"] = condition
            resources.append(rule)
            self.assertEqual(_facts(resources).internet_facing_load_balancer_addresses, [])
        rule.values["condition"] = [{"path_pattern": [{"values": ["/*"]}]}]
        rule.unknown_values = {"condition": True}
        self.assertEqual(_facts(resources).internet_facing_load_balancer_addresses, [])

    def test_default_forwarding_cannot_bypass_a_prior_rule(self) -> None:
        resources = _chain()
        earlier = _rule(pattern="/*")
        earlier.values["action"] = [{"type": "fixed-response"}]
        resources.append(earlier)
        self.assertEqual(_facts(resources).internet_facing_load_balancer_addresses, [])
        earlier.values["condition"] = [{"path_pattern": [{"values": ["/restricted/*"]}]}]
        self.assertEqual(_facts(resources).internet_facing_load_balancer_addresses, ["aws_lb.public"])

    def test_authentication_does_not_erase_a_known_forwarding_relationship(self) -> None:
        resources = _chain()
        resources[2].values["default_action"] = [
            {"type": "authenticate-oidc", "order": 1},
            {"type": "forward", "order": 2, "target_group_arn": "aws_lb_target_group.app"},
        ]
        self.assertEqual(
            _facts(resources).ecs_forwarding_associations[0]["authentication_actions"], ["authenticate-oidc"]
        )

    def test_redecoration_clears_a_removed_listener(self) -> None:
        inventory = AwsNormalizer().normalize(_chain())
        resources = [item for item in inventory.resources if item.resource_type != "aws_lb_listener"]
        AwsResourceDecorator(stages=[MarkEcsLoadBalancerExposureStage()]).decorate(resources)
        service = next(item for item in resources if item.resource_type == "aws_ecs_service")
        self.assertEqual(aws_facts(service).internet_facing_load_balancer_addresses, [])
        self.assertEqual(aws_facts(service).ecs_forwarding_associations, [])

    def test_rule_order_does_not_depend_on_resource_order(self) -> None:
        resources = _chain()
        resources[2].values["default_action"] = [{"type": "fixed-response"}]
        resources.extend([_rule("app", 20), _rule("blocker", 10, "/app/*")])
        resources[-1].values["action"] = [{"type": "fixed-response"}]
        for rules in permutations(resources[-2:]):
            self.assertEqual(_facts([*resources[:-2], *rules]).internet_facing_load_balancer_addresses, [])
        resources[-1].values["priority"] = 30
        for rules in permutations(resources[-2:]):
            self.assertEqual(
                _facts([*resources[:-2], *rules]).internet_facing_load_balancer_addresses, ["aws_lb.public"]
            )

    def test_unknown_rule_priority_cannot_be_sorted_after_known_rules(self) -> None:
        resources = _chain()
        resources[2].values["default_action"] = [{"type": "fixed-response"}]
        rule = _rule()
        blocker = _rule("blocker", 30, "/*")
        blocker.values["action"] = [{"type": "fixed-response"}]
        blocker.unknown_values = {"priority": True}
        resources.extend([rule, blocker])
        facts = _facts(resources)
        self.assertEqual(facts.internet_facing_load_balancer_addresses, [])
        self.assertTrue(any("preceding listener rules" in reason for reason in facts.ecs_forwarding_uncertainties))

    def test_unknown_listener_association_cannot_enable_default_fallback(self) -> None:
        resources = _chain()
        blocker = _rule(pattern="/*")
        blocker.values["action"] = [{"type": "fixed-response"}]
        blocker.unknown_values = {"listener_arn": True}
        resources.append(blocker)
        self.assertEqual(_facts(resources).internet_facing_load_balancer_addresses, [])
        blocker.provider_config_key = "aws.unrelated"
        self.assertEqual(_facts(resources).internet_facing_load_balancer_addresses, ["aws_lb.public"])

    def test_ambiguous_listener_association_cannot_enable_default_fallback(self) -> None:
        resources = _chain()
        resources[2].values["id"] = "shared-listener"
        duplicate = deepcopy(resources[2])
        duplicate.address = "aws_lb_listener.duplicate"
        blocker = _rule(pattern="/*")
        blocker.values.update(listener_arn="shared-listener", action=[{"type": "fixed-response"}])
        resources.extend([duplicate, blocker])
        self.assertEqual(_facts(resources).internet_facing_load_balancer_addresses, [])

    def test_unknown_forward_collection_cannot_fall_back_to_direct_target(self) -> None:
        resources = _chain()
        resources[2].unknown_values = {"default_action": [{"forward": [{"target_group": True}]}]}
        self.assertEqual(_facts(resources).internet_facing_load_balancer_addresses, [])

    def test_host_and_path_conditions_must_both_match_the_request(self) -> None:
        resources = _chain()
        resources[2].values["default_action"] = [{"type": "fixed-response"}]
        rule = _rule(pattern="/app/*")
        rule.values["condition"].append({"host_header": [{"values": ["APP.EXAMPLE.COM"]}]})
        resources.append(rule)
        witness = _facts(resources).ecs_forwarding_associations[0]["request_witness"]
        self.assertEqual(witness["host_header"].lower(), "app.example.com")
        self.assertTrue(witness["path_pattern"].startswith("/app/"))

    def test_symbolic_target_resolution_preserves_action_and_weight_uncertainty(self) -> None:
        resources = _chain()
        resources[2].values.update(
            load_balancer_arn=None, default_action=[{"type": "forward", "forward": [{"target_group": [{"weight": 1}]}]}]
        )
        resources[3].values["load_balancer"][0].pop("target_group_arn")
        reference = {"references": ["aws_lb_target_group.app.arn", "aws_lb_target_group.app"]}
        payload: dict[str, Any] = {
            "terraform_version": "1.8.5",
            "planned_values": {
                "root_module": {
                    "resources": [
                        {
                            "address": item.address,
                            "type": item.resource_type,
                            "name": item.name,
                            "mode": "managed",
                            "provider_name": item.provider_name,
                            "values": item.values,
                        }
                        for item in resources
                    ]
                }
            },
            "configuration": {
                "root_module": {
                    "resources": [
                        {
                            "address": item.address,
                            "type": item.resource_type,
                            "name": item.name,
                            "mode": "managed",
                            "provider_config_key": "aws",
                            "expressions": {},
                        }
                        for item in resources
                    ]
                }
            },
        }
        declarations = payload["configuration"]["root_module"]["resources"]
        declarations[2]["expressions"] = {
            "load_balancer_arn": {"references": ["aws_lb.public.arn", "aws_lb.public"]},
            "default_action": [{"forward": [{"target_group": [{"arn": reference}]}]}],
        }
        declarations[3]["expressions"] = {"load_balancer": [{"target_group_arn": reference}]}
        for unresolved in (None, "type", "weight"):
            with self.subTest(unresolved=unresolved):
                unknown: dict[str, Any] = {
                    "load_balancer_arn": True,
                    "default_action": [{"forward": [{"target_group": [{"arn": True}]}]}],
                }
                if unresolved == "type":
                    unknown["default_action"][0]["type"] = True
                elif unresolved == "weight":
                    unknown["default_action"][0]["forward"][0]["target_group"][0]["weight"] = True
                payload["resource_changes"] = [
                    {"address": resources[2].address, "change": {"after_unknown": unknown}},
                    {
                        "address": resources[3].address,
                        "change": {"after_unknown": {"load_balancer": [{"target_group_arn": True}]}},
                    },
                ]
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "plan.json"
                    path.write_text(json.dumps(payload))
                    self.assertEqual(
                        bool(_facts(load_terraform_plan(path).resources).internet_facing_load_balancer_addresses),
                        unresolved is None,
                    )

    def test_plan_ingestion_preserves_unknown_action_constraints(self) -> None:
        resources = _chain()
        payload = {
            "terraform_version": "1.8.5",
            "planned_values": {
                "root_module": {
                    "resources": [
                        {
                            "address": item.address,
                            "type": item.resource_type,
                            "name": item.name,
                            "mode": "managed",
                            "provider_name": item.provider_name,
                            "values": item.values,
                        }
                        for item in resources
                    ]
                }
            },
            "resource_changes": [
                {"address": resources[2].address, "change": {"after_unknown": {"default_action": [{"type": True}]}}}
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.json"
            path.write_text(json.dumps(payload))
            self.assertEqual(_facts(load_terraform_plan(path).resources).internet_facing_load_balancer_addresses, [])
