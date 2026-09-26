from __future__ import annotations

import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from typing import Any

from tests.providers.aws.test_aws_ecs_forwarding_associations import _chain, _resource
from tfstride.input.terraform_plan import load_terraform_plan
from tfstride.models import TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_decoration.ecs_public_ingress import DeriveEcsPublicIngressStage
from tfstride.providers.aws.resource_decorator import AwsResourceDecorator
from tfstride.providers.aws.resource_facts import aws_facts


def _rule(port: int, *, peer: str | None = None, cidr: str | None = None, protocol: str = "tcp") -> dict[str, Any]:
    return {
        "protocol": protocol,
        "from_port": port,
        "to_port": port,
        "security_groups": [peer] if peer else [],
        "cidr_blocks": [cidr] if cidr else [],
    }


def _resources() -> list[TerraformResource]:
    resources = _chain()
    resources[0].values["security_groups"] = ["aws_security_group.alb"]
    resources[3].values.update(
        task_definition="aws_ecs_task_definition.app",
        network_configuration=[{"security_groups": ["aws_security_group.tasks"]}],
    )
    resources.extend(
        [
            _resource(
                "aws_ecs_task_definition",
                "app",
                {
                    "family": "app",
                    "revision": 1,
                    "network_mode": "awsvpc",
                    "container_definitions": [
                        {"name": "app", "portMappings": [{"containerPort": 8080, "protocol": "tcp"}]}
                    ],
                },
            ),
            _resource(
                "aws_security_group",
                "alb",
                {
                    "id": "sg-alb",
                    "ingress": [_rule(443, cidr="0.0.0.0/0")],
                    "egress": [_rule(8080, peer="aws_security_group.tasks")],
                },
            ),
            _resource(
                "aws_security_group",
                "tasks",
                {"id": "sg-tasks", "ingress": [_rule(8080, peer="aws_security_group.alb")], "egress": []},
            ),
        ]
    )
    return resources


def _get(resources: list[TerraformResource], address: str) -> TerraformResource:
    return next(item for item in resources if item.address == address)


def _facts(resources: list[TerraformResource]):
    inventory = AwsNormalizer().normalize(deepcopy(resources))
    service = inventory.get_by_address("aws_ecs_service.app")
    assert service is not None
    return aws_facts(service)


def _plan_resources(resources: list[TerraformResource], expressions: dict[str, Any]) -> list[TerraformResource]:
    declarations = [
        {"address": item.address, "type": item.resource_type, "name": item.name, "mode": item.mode}
        for item in resources
    ]
    payload = {
        "terraform_version": "1.8.5",
        "planned_values": {
            "root_module": {
                "resources": [
                    {**declaration, "provider_name": item.provider_name, "values": item.values}
                    for declaration, item in zip(declarations, resources, strict=True)
                ]
            }
        },
        "configuration": {
            "root_module": {
                "resources": [
                    {
                        **declaration,
                        "provider_config_key": item.provider_config_key,
                        "expressions": expressions.get(item.address, {}),
                    }
                    for declaration, item in zip(declarations, resources, strict=True)
                ]
            }
        },
        "resource_changes": [
            {"address": item.address, "change": {"after_unknown": item.unknown_values}}
            for item in resources
            if item.unknown_values
        ],
    }
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "plan.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return load_terraform_plan(path).resources


class AwsEcsPublicIngressTests(unittest.TestCase):
    def test_https_listener_to_http_container_has_three_permission_proofs(self) -> None:
        facts = _facts(_resources())
        self.assertEqual(len(facts.ecs_public_ingress_paths), 1)
        path = facts.ecs_public_ingress_paths[0]
        self.assertEqual((path["listener_port"], path["backend_port"]), (443, 8080))
        self.assertEqual((path["listener_protocol"], path["backend_protocol"]), ("HTTPS", "HTTP"))
        for check in ("container_binding", "listener_ingress", "load_balancer_egress", "service_ingress"):
            self.assertEqual(path["checks"][check]["state"], "allowed")
            self.assertTrue(path["checks"][check]["evidence"])
        self.assertEqual(
            path["checks"]["service_ingress"]["evidence"][0]["peer_security_group_addresses"],
            ["aws_security_group.alb"],
        )
        # Security groups are stateful; reply traffic needs no additional task egress grant.
        self.assertEqual(facts.ecs_public_ingress_uncertainties, [])

    def test_incompatible_listener_ingress_is_blocked(self) -> None:
        for port, protocol in ((80, "tcp"), (443, "udp")):
            with self.subTest(port=port, protocol=protocol):
                resources = _resources()
                _get(resources, "aws_security_group.alb").values["ingress"] = [
                    _rule(port, cidr="0.0.0.0/0", protocol=protocol)
                ]
                facts = _facts(resources)
                self.assertEqual(facts.ecs_public_ingress_paths, [])
                self.assertEqual(
                    facts.ecs_public_ingress_decisions[0]["checks"]["listener_ingress"]["state"], "blocked"
                )

    def test_backend_port_and_alb_egress_are_independently_required(self) -> None:
        for group, direction, check in (
            ("tasks", "ingress", "service_ingress"),
            ("alb", "egress", "load_balancer_egress"),
        ):
            for replacement in ([], [_rule(9090, cidr="0.0.0.0/0")]):
                with self.subTest(group=group, replacement=replacement):
                    resources = _resources()
                    _get(resources, f"aws_security_group.{group}").values[direction] = replacement
                    facts = _facts(resources)
                    self.assertEqual(facts.ecs_public_ingress_paths, [])
                    self.assertEqual(facts.ecs_public_ingress_decisions[0]["checks"][check]["state"], "blocked")

    def test_blocked_listener_retains_forwarding_without_widening_existing_exposure_flags(self) -> None:
        resources = _resources()
        _get(resources, "aws_security_group.alb").values["ingress"] = []
        facts = _facts(resources)
        self.assertEqual(len(facts.ecs_forwarding_associations), 1)
        self.assertEqual(facts.ecs_public_ingress_decisions[0]["state"], "blocked")
        self.assertEqual(facts.ecs_public_ingress_paths, [])
        self.assertEqual(facts.internet_facing_load_balancer_addresses, [])

    def test_target_group_default_port_does_not_override_ecs_registration(self) -> None:
        resources = _resources()
        _get(resources, "aws_lb_target_group.app").values["port"] = 9090
        self.assertEqual(_facts(resources).ecs_public_ingress_paths[0]["backend_port"], 8080)

    def test_unknown_attachments_do_not_reuse_stale_values(self) -> None:
        for address, unknown in (
            ("aws_lb.public", {"security_groups": True}),
            ("aws_ecs_service.app", {"network_configuration": [{"security_groups": True}]}),
        ):
            with self.subTest(address=address):
                resources = _resources()
                _get(resources, address).unknown_values = unknown
                facts = _facts(resources)
                self.assertEqual(facts.ecs_public_ingress_paths, [])
                self.assertEqual(facts.ecs_public_ingress_decisions[0]["state"], "unknown")
                self.assertTrue(any("attachments" in reason for reason in facts.ecs_public_ingress_uncertainties))

    def test_additional_unknown_group_does_not_cancel_a_known_allow(self) -> None:
        resources = _resources()
        _get(resources, "aws_lb.public").values["security_groups"].append("aws_security_group.unmodeled")
        self.assertEqual(len(_facts(resources).ecs_public_ingress_paths), 1)

    def test_one_valid_listener_survives_another_blocked_listener(self) -> None:
        resources = _resources()
        other = deepcopy(_get(resources, "aws_lb_listener.https"))
        other.address = "aws_lb_listener.http"
        other.values.update(port=80, protocol="HTTP")
        resources.append(other)
        baseline = _facts(resources).ecs_public_ingress_decisions
        self.assertEqual(
            {decision["listener_address"]: decision["state"] for decision in baseline},
            {"aws_lb_listener.http": "blocked", "aws_lb_listener.https": "allowed"},
        )
        for permutation in (list(reversed(resources)), resources[3:] + resources[:3]):
            facts = _facts(permutation)
            self.assertEqual(facts.ecs_public_ingress_decisions, baseline)
            self.assertEqual(len(facts.ecs_public_ingress_paths), 1)

    def test_unknown_mapping_inputs_remain_uncertain(self) -> None:
        for address, unknown in (
            ("aws_lb_listener.https", {"port": True}),
            ("aws_lb_listener.https", {"protocol": True}),
            ("aws_lb.public", {"load_balancer_type": True}),
            ("aws_lb_target_group.app", {"target_type": True}),
            ("aws_lb_target_group.app", {"protocol": True}),
            ("aws_ecs_task_definition.app", {"network_mode": True}),
            ("aws_ecs_task_definition.app", {"container_definitions": True}),
            ("aws_ecs_service.app", {"task_definition": True}),
        ):
            with self.subTest(address=address, unknown=unknown):
                resources = _resources()
                _get(resources, address).unknown_values = unknown
                facts = _facts(resources)
                self.assertEqual(facts.ecs_public_ingress_paths, [])
                self.assertEqual(facts.ecs_public_ingress_decisions[0]["state"], "unknown")
                self.assertTrue(facts.ecs_public_ingress_uncertainties)

    def test_unsupported_network_mode_and_conflicting_host_port_are_uncertain(self) -> None:
        for mode, host_port in (("bridge", 8080), ("host", 8080), ("awsvpc", 9090)):
            with self.subTest(mode=mode, host_port=host_port):
                resources = _resources()
                task = _get(resources, "aws_ecs_task_definition.app")
                task.values["network_mode"] = mode
                task.values["container_definitions"][0]["portMappings"][0]["hostPort"] = host_port
                self.assertEqual(_facts(resources).ecs_public_ingress_decisions[0]["state"], "unknown")

    def test_missing_or_ambiguous_bound_container_is_uncertain(self) -> None:
        for containers in (
            [],
            [{"name": "other", "portMappings": [{"containerPort": 8080}]}],
            [{"name": "app"}, {"name": "app"}],
        ):
            resources = _resources()
            _get(resources, "aws_ecs_task_definition.app").values["container_definitions"] = containers
            self.assertEqual(_facts(resources).ecs_public_ingress_decisions[0]["state"], "unknown")

    def test_awsvpc_container_port_range_and_json_definitions(self) -> None:
        resources = _resources()
        _get(resources, "aws_ecs_task_definition.app").values["container_definitions"] = json.dumps(
            [{"name": "app", "portMappings": [{"containerPortRange": "8000-8100"}]}]
        )
        self.assertEqual(len(_facts(resources).ecs_public_ingress_paths), 1)

    def test_standalone_rules_preserve_the_rule_resource_as_evidence(self) -> None:
        resources = _resources()
        _get(resources, "aws_security_group.alb").values["ingress"] = []
        resources.append(
            _resource(
                "aws_security_group_rule",
                "internet",
                {
                    "security_group_id": "aws_security_group.alb",
                    "type": "ingress",
                    "protocol": "6",
                    "from_port": 443,
                    "to_port": 443,
                    "cidr_blocks": ["0.0.0.0/0"],
                },
            )
        )
        path = _facts(resources).ecs_public_ingress_paths[0]
        self.assertEqual(
            path["checks"]["listener_ingress"]["evidence"][0]["rule_source_address"], "aws_security_group_rule.internet"
        )

    def test_unknown_security_group_rule_fields_cannot_grant_traffic(self) -> None:
        for unknown in (True, [{"protocol": True}], [{"from_port": True}], [{"cidr_blocks": True}]):
            with self.subTest(unknown=unknown):
                resources = _resources()
                _get(resources, "aws_security_group.alb").unknown_values = {"ingress": unknown}
                facts = _facts(resources)
                self.assertEqual(facts.ecs_public_ingress_paths, [])
                self.assertEqual(
                    facts.ecs_public_ingress_decisions[0]["checks"]["listener_ingress"]["state"], "unknown"
                )

    def test_security_group_alias_ambiguity_never_selects_a_permission(self) -> None:
        resources = _resources()
        other = _resource("aws_security_group", "other", {"id": "sg-alb", "ingress": [], "egress": []})
        resources.append(other)
        _get(resources, "aws_lb.public").values["security_groups"] = ["sg-alb"]
        for permutation in (resources, list(reversed(resources))):
            self.assertEqual(_facts(permutation).ecs_public_ingress_decisions[0]["state"], "unknown")

    def test_standalone_peer_reference_uses_the_rule_provider_scope(self) -> None:
        resources = _resources()
        _get(resources, "aws_security_group.tasks").values["ingress"] = []
        other = _resource("aws_security_group", "foreign", {"id": "sg-alb"})
        other.provider_config_key = "aws.foreign"
        rule = _resource(
            "aws_security_group_rule",
            "backend",
            {
                "security_group_id": "aws_security_group.tasks",
                "type": "ingress",
                "protocol": "tcp",
                "from_port": 8080,
                "to_port": 8080,
                "source_security_group_id": "sg-alb",
            },
        )
        rule.provider_config_key = "aws.foreign"
        resources.extend([other, rule])
        self.assertEqual(
            _facts(resources).ecs_public_ingress_decisions[0]["checks"]["service_ingress"]["state"], "blocked"
        )
        rule.values["source_security_group_id"] = "aws_security_group.alb"
        self.assertEqual(len(_facts(resources).ecs_public_ingress_paths), 1)

    def test_cidr_backend_grants_require_peer_address_coverage(self) -> None:
        resources = _resources()
        _get(resources, "aws_security_group.alb").values["egress"] = [_rule(8080, cidr="10.0.2.0/24")]
        _get(resources, "aws_security_group.tasks").values["ingress"] = [_rule(8080, cidr="10.0.1.0/24")]
        self.assertEqual(_facts(resources).ecs_public_ingress_decisions[0]["state"], "unknown")
        resources.extend(
            [
                _resource("aws_subnet", "alb", {"cidr_block": "10.0.1.0/24"}),
                _resource("aws_subnet", "tasks", {"cidr_block": "10.0.2.0/24"}),
            ]
        )
        _get(resources, "aws_lb.public").values["subnets"] = ["aws_subnet.alb"]
        _get(resources, "aws_ecs_service.app").values["network_configuration"][0]["subnets"] = ["aws_subnet.tasks"]
        self.assertEqual(len(_facts(resources).ecs_public_ingress_paths), 1)
        _get(resources, "aws_security_group.alb").values["egress"] = [_rule(8080, cidr="10.0.2.0/25")]
        self.assertEqual(_facts(resources).ecs_public_ingress_decisions[0]["state"], "unknown")
        _get(resources, "aws_security_group.alb").values["egress"].append(_rule(8080, cidr="10.0.2.128/25"))
        self.assertEqual(len(_facts(resources).ecs_public_ingress_paths), 1)
        _get(resources, "aws_security_group.alb").values["egress"] = [_rule(8080, cidr="10.0.3.0/24")]
        self.assertEqual(_facts(resources).ecs_public_ingress_decisions[0]["state"], "blocked")

    def test_unrestricted_backend_cidrs_need_no_guessed_task_ip(self) -> None:
        resources = _resources()
        _get(resources, "aws_security_group.alb").values["egress"] = [_rule(8080, cidr="0.0.0.0/0")]
        _get(resources, "aws_security_group.tasks").values["ingress"] = [_rule(8080, cidr="0.0.0.0/0")]
        self.assertEqual(len(_facts(resources).ecs_public_ingress_paths), 1)

    def test_internet_address_family_must_match_the_load_balancer(self) -> None:
        resources = _resources()
        rule = _rule(443)
        rule["ipv6_cidr_blocks"] = ["::/0"]
        _get(resources, "aws_security_group.alb").values["ingress"] = [rule]
        self.assertEqual(_facts(resources).ecs_public_ingress_decisions[0]["state"], "blocked")
        _get(resources, "aws_lb.public").values["ip_address_type"] = "dualstack"
        self.assertEqual(len(_facts(resources).ecs_public_ingress_paths), 1)

    def test_redecoration_clears_ingress_when_a_listener_disappears(self) -> None:
        inventory = AwsNormalizer().normalize(_resources())
        resources = [item for item in inventory.resources if item.resource_type != "aws_lb_listener"]
        AwsResourceDecorator(stages=[DeriveEcsPublicIngressStage()]).decorate(resources)
        service = next(item for item in resources if item.resource_type == "aws_ecs_service")
        self.assertEqual(aws_facts(service).ecs_public_ingress_paths, [])
        self.assertEqual(aws_facts(service).ecs_public_ingress_decisions[0]["state"], "unknown")

    def test_unknown_container_port_constraints_cannot_use_stale_mappings(self) -> None:
        for field in ("containerPort", "containerPortRange", "hostPort", "protocol"):
            with self.subTest(field=field):
                resources = _resources()
                _get(resources, "aws_ecs_task_definition.app").unknown_values = {
                    "container_definitions": [{"portMappings": [{field: True}]}]
                }
                self.assertEqual(_facts(resources).ecs_public_ingress_decisions[0]["state"], "unknown")

    def test_all_protocol_rule_covers_tcp_without_port_fields(self) -> None:
        resources = _resources()
        for address, direction in (
            ("aws_security_group.alb", "ingress"),
            ("aws_security_group.alb", "egress"),
            ("aws_security_group.tasks", "ingress"),
        ):
            rule = _get(resources, address).values[direction][0]
            rule.update(protocol="-1", from_port=None, to_port=None)
        self.assertEqual(len(_facts(resources).ecs_public_ingress_paths), 1)

    def test_valid_ingress_rule_survives_an_uncertain_additional_rule(self) -> None:
        resources = _resources()
        group = _get(resources, "aws_security_group.alb")
        group.values["ingress"].append(_rule(9090, cidr="0.0.0.0/0"))
        group.unknown_values = {"ingress": [{}, {"from_port": True}]}
        self.assertEqual(len(_facts(resources).ecs_public_ingress_paths), 1)

    def test_restricted_internet_source_is_preserved_in_evidence(self) -> None:
        resources = _resources()
        _get(resources, "aws_security_group.alb").values["ingress"] = [_rule(443, cidr="8.8.8.0/24")]
        proof = _facts(resources).ecs_public_ingress_paths[0]["checks"]["listener_ingress"]["evidence"][0]
        self.assertEqual(proof["cidr"], "8.8.8.0/24")
        self.assertTrue(proof["internet_source_witness"].startswith("8.8.8."))
        _get(resources, "aws_security_group.alb").values["ingress"] = [_rule(443, cidr="10.0.0.0/8")]
        self.assertEqual(_facts(resources).ecs_public_ingress_decisions[0]["state"], "blocked")

    def test_unknown_standalone_rule_attachment_prevents_a_false_block(self) -> None:
        resources = _resources()
        _get(resources, "aws_security_group.alb").values["egress"] = []
        rule = _resource(
            "aws_security_group_rule",
            "egress",
            {
                "security_group_id": "sg-alb",
                "type": "egress",
                "protocol": "tcp",
                "from_port": 8080,
                "to_port": 8080,
                "cidr_blocks": ["0.0.0.0/0"],
            },
        )
        rule.unknown_values = {"security_group_id": True}
        resources.append(rule)
        self.assertEqual(
            _facts(resources).ecs_public_ingress_decisions[0]["checks"]["load_balancer_egress"]["state"], "unknown"
        )

    def test_first_apply_symbolic_group_attachments_and_peer_rules(self) -> None:
        resources = _resources()
        _get(resources, "aws_lb.public").unknown_values = {"security_groups": True}
        _get(resources, "aws_ecs_service.app").unknown_values = {
            "network_configuration": [{"security_groups": True}],
            "task_definition": True,
        }
        _get(resources, "aws_security_group.alb").unknown_values = {"egress": [{"security_groups": True}]}
        _get(resources, "aws_security_group.tasks").unknown_values = {"ingress": [{"security_groups": True}]}
        alb = {"references": ["aws_security_group.alb.id", "aws_security_group.alb"]}
        tasks = {"references": ["aws_security_group.tasks.id", "aws_security_group.tasks"]}
        expressions = {
            "aws_lb.public": {"security_groups": alb},
            "aws_ecs_service.app": {
                "network_configuration": [{"security_groups": tasks}],
                "task_definition": {"references": ["aws_ecs_task_definition.app.arn", "aws_ecs_task_definition.app"]},
            },
            "aws_security_group.alb": {"egress": [{"security_groups": tasks}]},
            "aws_security_group.tasks": {"ingress": [{"security_groups": alb}]},
        }
        self.assertEqual(len(_facts(_plan_resources(resources, expressions)).ecs_public_ingress_paths), 1)
        # An unknown port cannot be repaired by resolving the security-group identity.
        _get(resources, "aws_security_group.tasks").unknown_values["ingress"][0]["from_port"] = True
        self.assertEqual(
            _facts(_plan_resources(resources, expressions)).ecs_public_ingress_decisions[0]["state"], "unknown"
        )

    def test_realistic_ecs_fixture_has_verified_ingress(self) -> None:
        resources = load_terraform_plan(Path("fixtures/aws/sample_aws_ecs_fargate_plan.json")).resources
        self.assertEqual(len(_facts(resources).ecs_public_ingress_paths), 1)
