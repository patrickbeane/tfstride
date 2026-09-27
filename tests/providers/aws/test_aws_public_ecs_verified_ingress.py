from __future__ import annotations

import random
import unittest
from copy import deepcopy
from dataclasses import replace
from unittest.mock import patch

from tests.providers.aws.ecs_forwarding_support import TARGET_GROUP_ARN, load_balancer_path
from tests.providers.aws.test_aws_ecs_s3_access_paths import _BUCKET_ARN, _TASK_ROLE_ARN, _bucket, _role, _statement
from tests.providers.aws.test_aws_ecs_secret_access_paths import (
    _EXECUTION_ROLE_ARN,
    _SECRET_ARN,
    _task_definition,
)
from tests.providers.aws.test_aws_public_ecs_secret_access_rules import _secret, _service
from tfstride.analysis.indexes import build_analysis_indexes
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import ResourceInventory
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_decoration.ecs_public_ingress import current_ecs_public_ingress
from tfstride.providers.aws.resource_facts import aws_facts

_RULES = frozenset({"aws-public-ecs-s3-mutation-access", "aws-public-ecs-secret-access"})


def _resources():
    resources = [
        *load_balancer_path(),
        _bucket(),
        _secret(),
        _task_definition(task_role_arn=_TASK_ROLE_ARN),
        _service(),
        _role("orders_task", _TASK_ROLE_ARN, [_statement("Allow", "s3:PutObject", f"{_BUCKET_ARN}/*")]),
        _role("execution", _EXECUTION_ROLE_ARN, [_statement("Allow", "secretsmanager:GetSecretValue", _SECRET_ARN)]),
    ]
    for resource in resources:
        resource.provider_config_key = "aws"
    return resources


def _findings(inventory):
    indexes = build_analysis_indexes(inventory)
    return StrideRuleEngine().evaluate(
        inventory,
        detect_trust_boundaries(inventory, indexes=indexes),
        analysis_indexes=indexes,
        rule_policy=RulePolicy(enabled_rule_ids=_RULES),
    )


def _get(inventory, address):
    resource = inventory.get_by_address(address)
    assert resource is not None
    return resource


class AwsPublicEcsVerifiedIngressTests(unittest.TestCase):
    def test_rule_conditions_and_authentication_remain_visible_on_a_reachable_path(self):
        resources = _resources()
        listener = next(item for item in resources if item.resource_type == "aws_lb_listener")
        listener.values["default_action"] = [{"type": "fixed-response"}]
        rule = replace(
            listener,
            address="aws_lb_listener_rule.application",
            resource_type="aws_lb_listener_rule",
            name="application",
            values={
                "listener_arn": listener.address,
                "priority": 10,
                "condition": [{"path_pattern": [{"values": ["/app/*"]}]}],
                "action": [
                    {"type": "authenticate-oidc", "order": 1},
                    {"type": "forward", "order": 2, "target_group_arn": TARGET_GROUP_ARN},
                ],
            },
        )
        findings = _findings(AwsNormalizer().normalize([*resources, rule]))
        self.assertEqual(len(findings), 2)
        for finding in findings:
            self.assertIn(rule.address, finding.affected_resources)
            evidence = next(item.values for item in finding.evidence if item.key == "public_ingress")
            self.assertIn('authentication_actions=["authenticate-oidc"]', evidence[0])
            self.assertIn("/app/*", evidence[0])
            self.assertIn("request_witness=", evidence[0])

    def test_s3_and_secret_findings_explain_the_actual_forwarding_and_permissions(self):
        inventory = AwsNormalizer().normalize(_resources())
        findings = _findings(inventory)
        self.assertEqual({item.rule_id for item in findings}, _RULES)
        for finding in findings:
            with self.subTest(rule=finding.rule_id):
                self.assertIn("aws_lb_listener.public", finding.affected_resources)
                self.assertIn("aws_lb_target_group.public", finding.affected_resources)
                evidence = {item.key: item.values for item in finding.evidence}
                self.assertIn("(HTTPS TCP 443)", evidence["network_path"][0])
                self.assertIn("container=orders (HTTP TCP 8080)", evidence["network_path"][1])
                self.assertIn("target_group=aws_lb_target_group.public", evidence["public_ingress"][0])
                self.assertIn("authentication_actions=[]", evidence["public_ingress"][0])
                permissions = "\n".join(evidence["network_permissions"])
                for check in ("container_binding", "listener_ingress", "load_balancer_egress", "service_ingress"):
                    self.assertIn(f"check={check}; state=allowed", permissions)
                self.assertIn("aws_security_group.public_alb", permissions)
                self.assertIn("aws_security_group.public_tasks", permissions)
                self.assertIn('"port":8080', permissions)

    def test_forwarding_removal_drops_findings_but_keeps_authorization_and_stale_paths_cannot_restore_them(self):
        original = AwsNormalizer().normalize(_resources())
        self.assertEqual(len(_findings(original)), 2)
        original_service = _get(original, "aws_ecs_service.orders")
        before = deepcopy(aws_facts(original_service).ecs_s3_access_paths)
        for resource_type in ("aws_lb_listener", "aws_lb_target_group", "aws_lb"):
            with self.subTest(removed=resource_type):
                inventory = ResourceInventory(
                    "aws", [item for item in original.resources if item.resource_type != resource_type]
                )
                service = _get(inventory, "aws_ecs_service.orders")
                facts = aws_facts(service)
                self.assertTrue(facts.ecs_public_ingress_paths)  # Deliberately stale decoration.
                self.assertEqual(_findings(inventory), [])
                self.assertEqual(facts.ecs_s3_access_paths, before)
                self.assertTrue(any(p["access_state"] == "allowed" for p in facts.ecs_secret_access_paths))

    def test_current_permissions_and_bindings_override_cached_ingress(self):
        for change in ("listener", "egress", "service_ingress", "binding", "unknown_attachments"):
            with self.subTest(change=change):
                inventory = AwsNormalizer().normalize(_resources())
                service = _get(inventory, "aws_ecs_service.orders")
                facts = aws_facts(service)
                self.assertTrue(facts.ecs_public_ingress_paths)
                if change == "binding":
                    facts.set(AwsResourceMetadata.ECS_LOAD_BALANCERS, [])
                elif change == "unknown_attachments":
                    facts.set(AwsResourceMetadata.NETWORK_ATTACHMENTS, {})
                else:
                    group = _get(
                        inventory,
                        "aws_security_group.public_tasks"
                        if change == "service_ingress"
                        else "aws_security_group.public_alb",
                    )
                    direction = "egress" if change == "egress" else "ingress"
                    group_facts = aws_facts(group)
                    group_facts.set(
                        AwsResourceMetadata.SECURITY_GROUP_TRAFFIC_RULES,
                        [
                            rule
                            for rule in group_facts.security_group_traffic_rules
                            if rule["rule_direction"] != direction
                        ],
                    )
                self.assertEqual(_findings(inventory), [])
                self.assertTrue(any(p["access_state"] == "allowed" for p in facts.ecs_s3_access_paths))

    def test_another_services_verified_ingress_cannot_be_borrowed(self):
        resources = _resources()
        other = deepcopy(next(item for item in resources if item.resource_type == "aws_ecs_service"))
        other.address = "aws_ecs_service.unrelated"
        other.name = "unrelated"
        original = next(item for item in resources if item.resource_type == "aws_ecs_service")
        original.values["load_balancer"] = []
        inventory = AwsNormalizer().normalize([*resources, other])
        original_facts = aws_facts(_get(inventory, original.address))
        other_facts = aws_facts(_get(inventory, other.address))
        original_facts.set_ecs_public_ingress(deepcopy(other_facts.ecs_public_ingress_decisions), [])
        original_facts.set_internet_facing_load_balancer_addresses(["aws_lb.public"])
        findings = _findings(inventory)
        self.assertEqual(len(findings), 2)
        for finding in findings:
            self.assertIn(other.address, finding.affected_resources)
            self.assertNotIn(original.address, finding.affected_resources)

    def test_cached_authorization_for_a_previous_task_cannot_join_current_ingress(self):
        inventory = AwsNormalizer().normalize(_resources())
        task = replace(_get(inventory, "aws_ecs_task_definition.orders"))
        task.address = "aws_ecs_task_definition.replacement"
        task.name = "replacement"
        service = _get(inventory, "aws_ecs_service.orders")
        aws_facts(service).set(AwsResourceMetadata.TASK_DEFINITION_REFERENCE, task.address)
        changed = ResourceInventory("aws", [*inventory.resources, task])
        self.assertEqual(_findings(changed), [])
        self.assertTrue(aws_facts(service).ecs_s3_access_paths)

    def test_current_listener_evidence_replaces_stale_details_and_valid_alternate_survives(self):
        inventory = AwsNormalizer().normalize(_resources())
        original = _get(inventory, "aws_lb_listener.public")
        replacement = replace(original)
        replacement.address = "aws_lb_listener.replacement"
        replacement.name = "replacement"
        aws_facts(original).set(AwsResourceMetadata.LOAD_BALANCER_LISTENER_PORT, 9090)
        changed = ResourceInventory("aws", [*inventory.resources, replacement])
        findings = _findings(changed)
        self.assertEqual(len(findings), 2)
        for finding in findings:
            self.assertIn(replacement.address, finding.affected_resources)
            self.assertNotIn(original.address, finding.affected_resources)
            text = str(finding.evidence)
            self.assertIn(replacement.address, text)
            self.assertNotIn(original.address, text)

    def test_resource_permutations_preserve_findings_and_ingress_is_prepared_once(self):
        expected = None
        for seed in range(5):
            resources = _resources()
            random.Random(seed).shuffle(resources)
            inventory = AwsNormalizer().normalize(resources)
            with patch(
                "tfstride.providers.aws.analysis_indexes.current_ecs_public_ingress", wraps=current_ecs_public_ingress
            ) as prepare:
                findings = _findings(inventory)
                self.assertEqual(prepare.call_count, 1)
            if expected is not None:
                self.assertEqual(findings, expected)
            expected = findings
