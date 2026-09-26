from __future__ import annotations

import unittest
from pathlib import Path

from tests.providers.aws.ecs_forwarding_support import forwarding_action
from tfstride.input.terraform_plan import load_terraform_plan
from tfstride.models import (
    IAMPolicyStatement,
    NormalizedResource,
    ResourceCategory,
    SecurityGroupRule,
    TerraformReferenceProvenance,
    TerraformReferenceResolution,
    TerraformReferenceResolutionState,
    TerraformReferenceTarget,
)
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_decoration.ecs import (
    MarkEcsLoadBalancerExposureStage,
    ResolveEcsServiceRelationshipsStage,
)
from tfstride.providers.aws.resource_decoration.ecs_dynamodb_access_paths import (
    ModelEcsDynamoDbAccessPathsStage,
)
from tfstride.providers.aws.resource_decoration.ecs_messaging_access_paths import (
    ModelEcsMessagingAccessPathsStage,
)
from tfstride.providers.aws.resource_decoration.kms import DecorateKmsRelationshipsStage
from tfstride.providers.aws.resource_decoration.resource_policies import ApplySqsRedrivePolicyResourcesStage
from tfstride.providers.aws.resource_decoration.symbolic_relationships import ResolveAwsSymbolicRelationshipsStage
from tfstride.providers.aws.resource_decorator import AwsResourceDecorator
from tfstride.providers.aws.resource_facts import aws_facts


def _resource(
    address: str,
    resource_type: str,
    category: ResourceCategory,
    *,
    identifier: str | None = None,
    arn: str | None = None,
    security_group_ids: tuple[str, ...] = (),
    network_rules: list[SecurityGroupRule] | None = None,
    policy_statements: tuple[IAMPolicyStatement, ...] = (),
    metadata: dict | None = None,
    public_access_configured: bool = False,
    public_exposure: bool = False,
    reference_resolutions: tuple[TerraformReferenceResolution, ...] = (),
) -> NormalizedResource:
    return NormalizedResource(
        address=address,
        provider="aws",
        resource_type=resource_type,
        name=address.rsplit(".", 1)[-1],
        category=category,
        identifier=identifier,
        arn=arn,
        security_group_ids=security_group_ids,
        network_rules=network_rules or [],
        policy_statements=policy_statements,
        public_access_configured=public_access_configured,
        public_exposure=public_exposure,
        metadata=metadata or {},
        reference_resolutions=reference_resolutions,
    )


def _symbolic_resolution(
    path: tuple[str | int, ...],
    target_address: str,
    target_attribute: str = ".id",
) -> TerraformReferenceResolution:
    reference = f"{target_address}{target_attribute}"
    return TerraformReferenceResolution(
        path=path,
        state=TerraformReferenceResolutionState.SYMBOLIC,
        provenance=TerraformReferenceProvenance.CONFIGURATION_REFERENCE,
        references=(reference,),
        targets=(TerraformReferenceTarget(address=target_address, reference=reference),),
    )


def _security_group_rule(group_id: str) -> SecurityGroupRule:
    return SecurityGroupRule(
        direction="ingress",
        protocol="tcp",
        from_port=80,
        to_port=80,
        referenced_security_group_ids=[group_id],
    )


class AwsSymbolicRelationshipTests(unittest.TestCase):
    def test_symbolic_ecs_alb_relationships_resolve_on_first_apply(self) -> None:
        load_balancer = _resource(
            "aws_lb.web",
            "aws_lb",
            ResourceCategory.EDGE,
            public_access_configured=True,
            public_exposure=True,
        )
        target_group = _resource(
            "aws_lb_target_group.app",
            "aws_lb_target_group",
            ResourceCategory.EDGE,
        )
        listener = _resource(
            "aws_lb_listener.https",
            "aws_lb_listener",
            ResourceCategory.EDGE,
            metadata={"load_balancer_actions": [forwarding_action(None)]},
            reference_resolutions=(
                _symbolic_resolution(
                    ("load_balancer_arn",),
                    load_balancer.address,
                    ".arn",
                ),
                _symbolic_resolution(
                    ("default_action", 0, "target_group_arn"),
                    target_group.address,
                    ".arn",
                ),
            ),
        )
        service = _resource(
            "aws_ecs_service.app",
            "aws_ecs_service",
            ResourceCategory.COMPUTE,
            metadata={"load_balancers": [{"container_name": "app", "container_port": 8080}]},
            reference_resolutions=(
                _symbolic_resolution(
                    ("load_balancer", 0, "target_group_arn"),
                    target_group.address,
                    ".arn",
                ),
            ),
        )

        AwsResourceDecorator(
            stages=[ResolveAwsSymbolicRelationshipsStage(), MarkEcsLoadBalancerExposureStage()]
        ).decorate([load_balancer, listener, target_group, service])

        self.assertEqual(aws_facts(listener).load_balancer_arn, load_balancer.address)
        self.assertEqual(aws_facts(listener).load_balancer_target_group_arns, [target_group.address])
        self.assertEqual(aws_facts(service).ecs_load_balancers[0]["target_group_arn"], target_group.address)
        self.assertTrue(service.metadata["fronted_by_internet_facing_load_balancer"])
        self.assertEqual(service.metadata["internet_facing_load_balancer_addresses"], [load_balancer.address])

    def test_symbolic_listener_rule_relationships_resolve_on_first_apply(self) -> None:
        listener = _resource(
            "aws_lb_listener.https",
            "aws_lb_listener",
            ResourceCategory.EDGE,
        )
        target_group = _resource(
            "aws_lb_target_group.app",
            "aws_lb_target_group",
            ResourceCategory.EDGE,
        )
        listener_rule = _resource(
            "aws_lb_listener_rule.app",
            "aws_lb_listener_rule",
            ResourceCategory.EDGE,
            metadata={"load_balancer_actions": [forwarding_action(None, "action")]},
            reference_resolutions=(
                _symbolic_resolution(("listener_arn",), listener.address, ".arn"),
                _symbolic_resolution(
                    ("action", 0, "target_group_arn"),
                    target_group.address,
                    ".arn",
                ),
            ),
        )

        AwsResourceDecorator(stages=[ResolveAwsSymbolicRelationshipsStage()]).decorate(
            [listener, target_group, listener_rule]
        )

        self.assertEqual(aws_facts(listener_rule).listener_arn, listener.address)
        self.assertEqual(
            aws_facts(listener_rule).load_balancer_target_group_arns,
            [target_group.address],
        )

    def test_symbolic_ecs_security_group_relationship_does_not_establish_fronting(self) -> None:
        load_balancer = _resource(
            "aws_lb.web",
            "aws_lb",
            ResourceCategory.EDGE,
            security_group_ids=("sg-lb",),
            public_exposure=True,
        )
        load_balancer_security_group = _resource(
            "aws_security_group.lb",
            "aws_security_group",
            ResourceCategory.NETWORK,
            identifier="sg-lb",
        )
        service_security_group = _resource(
            "aws_security_group.service",
            "aws_security_group",
            ResourceCategory.NETWORK,
            network_rules=[_security_group_rule("sg-lb")],
        )
        service = _resource(
            "aws_ecs_service.app",
            "aws_ecs_service",
            ResourceCategory.COMPUTE,
            reference_resolutions=(
                _symbolic_resolution(
                    ("network_configuration", 0, "security_groups"),
                    service_security_group.address,
                ),
            ),
        )

        AwsResourceDecorator(
            stages=[ResolveAwsSymbolicRelationshipsStage(), MarkEcsLoadBalancerExposureStage()]
        ).decorate([load_balancer, load_balancer_security_group, service_security_group, service])

        self.assertEqual(aws_facts(service).ecs_symbolic_security_group_addresses, [service_security_group.address])
        self.assertFalse(service.metadata["fronted_by_internet_facing_load_balancer"])

    def test_aws_normalizer_carries_plan_symbolic_relationships_into_decoration(self) -> None:
        fixture = Path("fixtures/aws/sample_aws_first_apply_symbolic_plan.json")
        inventory = AwsNormalizer().normalize(load_terraform_plan(fixture).resources)
        service = inventory.get_by_address("aws_ecs_service.direct")

        self.assertIsNotNone(service)
        assert service is not None
        resolution = service.reference_resolution("load_balancer", 0, "target_group_arn")
        self.assertEqual(resolution.state.value, "symbolic")
        self.assertEqual(
            aws_facts(service).ecs_load_balancers[0]["target_group_arn"],
            "aws_lb_target_group.direct",
        )

    def test_symbolic_sqs_dynamodb_and_kms_references_resolve_by_exact_address(self) -> None:
        key = _resource(
            "aws_kms_key.data",
            "aws_kms_key",
            ResourceCategory.DATA,
        )
        alias = _resource(
            "aws_kms_alias.data",
            "aws_kms_alias",
            ResourceCategory.DATA,
            reference_resolutions=(_symbolic_resolution(("target_key_id",), key.address, ".key_id"),),
        )
        table = _resource(
            "aws_dynamodb_table.orders",
            "aws_dynamodb_table",
            ResourceCategory.DATA,
            reference_resolutions=(
                _symbolic_resolution(
                    ("server_side_encryption", 0, "kms_key_arn"),
                    key.address,
                    ".arn",
                ),
            ),
        )
        queue = _resource(
            "aws_sqs_queue.jobs",
            "aws_sqs_queue",
            ResourceCategory.DATA,
            metadata={"sqs_queue_url": "https://sqs.us-east-1.amazonaws.com/111122223333/jobs"},
        )
        dead_letter_queue = _resource(
            "aws_sqs_queue.dead_letter",
            "aws_sqs_queue",
            ResourceCategory.DATA,
        )
        redrive_policy = _resource(
            "aws_sqs_queue_redrive_policy.jobs",
            "aws_sqs_queue_redrive_policy",
            ResourceCategory.DATA,
            metadata={"sqs_redrive_state": "configured"},
            reference_resolutions=(
                _symbolic_resolution(("queue_url",), queue.address, ".id"),
                _symbolic_resolution(("redrive_policy",), dead_letter_queue.address, ".arn"),
            ),
        )

        AwsResourceDecorator(
            stages=[
                ResolveAwsSymbolicRelationshipsStage(),
                DecorateKmsRelationshipsStage(),
                ApplySqsRedrivePolicyResourcesStage(),
            ]
        ).decorate([key, alias, table, queue, dead_letter_queue, redrive_policy])

        self.assertEqual(aws_facts(alias).kms_alias_resolved_key_address, key.address)
        self.assertEqual(aws_facts(table).dynamodb_kms_key_arn, key.address)
        self.assertEqual(aws_facts(redrive_policy).sqs_queue_url, queue.address)
        self.assertEqual(aws_facts(redrive_policy).sqs_redrive_target_arn, dead_letter_queue.address)
        self.assertEqual(aws_facts(queue).sqs_redrive_source_address, redrive_policy.address)

    def test_dynamodb_kms_key_id_is_not_promoted_to_kms_key_arn(self) -> None:
        key = _resource(
            "aws_kms_key.data",
            "aws_kms_key",
            ResourceCategory.DATA,
        )
        table = _resource(
            "aws_dynamodb_table.orders",
            "aws_dynamodb_table",
            ResourceCategory.DATA,
            reference_resolutions=(_symbolic_resolution(("kms_key_arn",), key.address, ".id"),),
        )

        AwsResourceDecorator(stages=[ResolveAwsSymbolicRelationshipsStage()]).decorate([key, table])

        self.assertIsNone(aws_facts(table).dynamodb_kms_key_arn)

    def test_kms_alias_target_key_arn_rejects_key_id_reference(self) -> None:
        key = _resource(
            "aws_kms_key.data",
            "aws_kms_key",
            ResourceCategory.DATA,
        )
        alias = _resource(
            "aws_kms_alias.data",
            "aws_kms_alias",
            ResourceCategory.DATA,
            reference_resolutions=(_symbolic_resolution(("target_key_arn",), key.address, ".key_id"),),
        )

        AwsResourceDecorator(
            stages=[
                ResolveAwsSymbolicRelationshipsStage(),
                DecorateKmsRelationshipsStage(),
            ]
        ).decorate([key, alias])

        self.assertIsNone(aws_facts(alias).kms_alias_resolved_key_address)

    def test_arn_shaped_policy_literals_do_not_establish_symbolic_access_paths(self) -> None:
        queue = _resource(
            "aws_sqs_queue.jobs",
            "aws_sqs_queue",
            ResourceCategory.DATA,
        )
        table = _resource(
            "aws_dynamodb_table.orders",
            "aws_dynamodb_table",
            ResourceCategory.DATA,
            identifier="orders",
        )
        task_role = _resource(
            "aws_iam_role.task",
            "aws_iam_role",
            ResourceCategory.IAM,
            policy_statements=(
                IAMPolicyStatement(
                    effect="Allow",
                    actions=["sqs:SendMessage"],
                    resources=["aws_sqs_queue.jobs.arn"],
                ),
                IAMPolicyStatement(
                    effect="Allow",
                    actions=["dynamodb:PutItem"],
                    resources=["aws_dynamodb_table.orders.arn"],
                ),
            ),
        )
        task_definition = _resource(
            "aws_ecs_task_definition.app",
            "aws_ecs_task_definition",
            ResourceCategory.COMPUTE,
            metadata={"task_role_arn": task_role.address},
        )

        AwsResourceDecorator(
            stages=[
                ModelEcsMessagingAccessPathsStage(),
                ModelEcsDynamoDbAccessPathsStage(),
            ]
        ).decorate([queue, table, task_role, task_definition])

        self.assertEqual(aws_facts(task_definition).ecs_messaging_access_paths, [])
        self.assertEqual(aws_facts(task_definition).ecs_dynamodb_access_paths, [])

    def test_target_group_id_reference_is_not_promoted_to_target_group_arn(self) -> None:
        target_group = _resource(
            "aws_lb_target_group.app",
            "aws_lb_target_group",
            ResourceCategory.EDGE,
        )
        listener = _resource(
            "aws_lb_listener.https",
            "aws_lb_listener",
            ResourceCategory.EDGE,
            reference_resolutions=(
                _symbolic_resolution(
                    ("default_action", 0, "target_group_arn"),
                    target_group.address,
                    ".id",
                ),
            ),
        )
        service = _resource(
            "aws_ecs_service.app",
            "aws_ecs_service",
            ResourceCategory.COMPUTE,
            metadata={"load_balancers": [{"container_name": "app", "container_port": 8080}]},
            reference_resolutions=(
                _symbolic_resolution(
                    ("load_balancer", 0, "target_group_arn"),
                    target_group.address,
                    ".id",
                ),
            ),
        )

        AwsResourceDecorator(stages=[ResolveAwsSymbolicRelationshipsStage()]).decorate(
            [target_group, listener, service]
        )

        self.assertEqual(aws_facts(listener).load_balancer_target_group_arns, [])
        self.assertNotIn("target_group_arn", aws_facts(service).ecs_load_balancers[0])

    def test_listener_wrong_attribute_reference_is_not_resolved(self) -> None:
        load_balancer = _resource(
            "aws_lb.web",
            "aws_lb",
            ResourceCategory.EDGE,
        )
        listener = _resource(
            "aws_lb_listener.https",
            "aws_lb_listener",
            ResourceCategory.EDGE,
            reference_resolutions=(
                _symbolic_resolution(
                    ("load_balancer_arn",),
                    load_balancer.address,
                    ".id",
                ),
            ),
        )

        AwsResourceDecorator(stages=[ResolveAwsSymbolicRelationshipsStage()]).decorate([load_balancer, listener])

        self.assertIsNone(aws_facts(listener).load_balancer_arn)

    def test_task_role_id_reference_is_not_promoted_to_role_arn(self) -> None:
        task_role = _resource(
            "aws_iam_role.task",
            "aws_iam_role",
            ResourceCategory.IAM,
        )
        task_definition = _resource(
            "aws_ecs_task_definition.app",
            "aws_ecs_task_definition",
            ResourceCategory.COMPUTE,
            reference_resolutions=(
                _symbolic_resolution(
                    ("task_role_arn",),
                    task_role.address,
                    ".id",
                ),
            ),
        )

        AwsResourceDecorator(stages=[ResolveAwsSymbolicRelationshipsStage()]).decorate([task_role, task_definition])

        self.assertIsNone(aws_facts(task_definition).task_role_arn)

    def test_symbolic_wrong_target_type_is_ignored(self) -> None:
        target_group = _resource(
            "aws_lb_target_group.app",
            "aws_lb_target_group",
            ResourceCategory.EDGE,
        )
        listener = _resource(
            "aws_lb_listener.https",
            "aws_lb_listener",
            ResourceCategory.EDGE,
            reference_resolutions=(
                _symbolic_resolution(
                    ("load_balancer_arn",),
                    target_group.address,
                    ".arn",
                ),
            ),
        )

        AwsResourceDecorator(stages=[ResolveAwsSymbolicRelationshipsStage()]).decorate([target_group, listener])

        self.assertIsNone(aws_facts(listener).load_balancer_arn)

    def test_symbolic_ecs_task_definition_and_roles_resolve(self) -> None:
        task_role = _resource(
            "aws_iam_role.task",
            "aws_iam_role",
            ResourceCategory.IAM,
            arn="arn:aws:iam::111122223333:role/task",
        )
        task_definition = _resource(
            "aws_ecs_task_definition.app",
            "aws_ecs_task_definition",
            ResourceCategory.COMPUTE,
            reference_resolutions=(
                _symbolic_resolution(
                    ("task_role_arn",),
                    task_role.address,
                    ".arn",
                ),
            ),
        )
        service = _resource(
            "aws_ecs_service.app",
            "aws_ecs_service",
            ResourceCategory.COMPUTE,
            reference_resolutions=(
                _symbolic_resolution(
                    ("task_definition",),
                    task_definition.address,
                    ".arn",
                ),
            ),
        )

        AwsResourceDecorator(
            stages=[ResolveAwsSymbolicRelationshipsStage(), ResolveEcsServiceRelationshipsStage()]
        ).decorate([task_role, task_definition, service])

        self.assertEqual(aws_facts(service).resolved_task_definition_addresses, [task_definition.address])
        self.assertEqual(aws_facts(task_definition).task_role_arn, task_role.address)
        self.assertEqual(service.metadata["resolved_task_role_addresses"], [task_role.address])


if __name__ == "__main__":
    unittest.main()
