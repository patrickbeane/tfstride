from __future__ import annotations

from collections.abc import Mapping

from tfstride.models import NormalizedResource
from tfstride.providers.aws.load_balancer_forwarding import action_target_references
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.reference_resolution import (
    resource_reference_value,
    symbolic_reference_target,
    symbolic_reference_target_records,
)
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import AwsDecorationContext
from tfstride.resource_metadata import MetadataField


class ResolveAwsSymbolicRelationshipsStage:
    name = "resolve_aws_symbolic_relationships"

    def apply(self, resources: list[NormalizedResource], context: AwsDecorationContext) -> None:
        for resource in resources:
            if resource.resource_type == "aws_ecs_service":
                self._resolve_ecs_service(resource, context)
            elif resource.resource_type == "aws_ecs_task_definition":
                self._resolve_ecs_task_definition(resource, context)
            elif resource.resource_type == "aws_lb_listener":
                self._resolve_listener(resource, context)
            elif resource.resource_type == "aws_lb_listener_rule":
                self._resolve_listener_rule(resource, context)
            elif resource.resource_type == "aws_kms_alias":
                self._resolve_kms_alias(resource, context)
            elif resource.resource_type == "aws_kms_grant":
                self._resolve_kms_grant(resource, context)
            elif resource.resource_type == "aws_kms_key_policy":
                self._resolve_kms_key_policy(resource, context)
            elif resource.resource_type in {"aws_sqs_queue", "aws_sqs_queue_redrive_policy"}:
                self._resolve_sqs_redrive_policy(resource, context)
            self._resolve_direct_kms_reference(resource, context)

    def _resolve_ecs_service(self, resource: NormalizedResource, context: AwsDecorationContext) -> None:
        facts = aws_facts(resource)
        if not facts.cluster_reference:
            cluster = symbolic_reference_target(
                resource,
                context.index,
                "cluster",
                expected_resource_types={"aws_ecs_cluster"},
                expected_reference_suffixes={".arn", ".id", ".name"},
            )
            if cluster is not None:
                facts.set(AwsResourceMetadata.CLUSTER_REFERENCE, resource_reference_value(cluster))

        if not facts.task_definition_reference:
            task_definition = symbolic_reference_target(
                resource,
                context.index,
                "task_definition",
                expected_resource_types={"aws_ecs_task_definition"},
                expected_reference_suffixes={".arn", ".id"},
            )
            if task_definition is not None:
                facts.set(
                    AwsResourceMetadata.TASK_DEFINITION_REFERENCE,
                    resource_reference_value(task_definition),
                )

        load_balancers = facts.ecs_load_balancers
        changed = False
        for path, target_group in symbolic_reference_target_records(
            resource,
            context.index,
            path_prefix=("load_balancer",),
            terminal_segments={"target_group_arn"},
            expected_resource_types={"aws_lb_target_group"},
            expected_reference_suffixes={".arn"},
        ):
            if len(path) < 3 or not isinstance(path[1], int) or path[1] >= len(load_balancers):
                continue
            block = load_balancers[path[1]]
            if not isinstance(block, Mapping) or block.get("target_group_arn"):
                continue
            updated = dict(block)
            updated["target_group_arn"] = resource_reference_value(target_group)
            load_balancers[path[1]] = updated
            changed = True
        if changed:
            facts.set(AwsResourceMetadata.ECS_LOAD_BALANCERS, load_balancers)

        security_groups = [
            target.address
            for _, target in symbolic_reference_target_records(
                resource,
                context.index,
                path_prefix=("network_configuration",),
                terminal_segments={"security_groups"},
                expected_resource_types={"aws_security_group"},
                expected_reference_suffixes={".id"},
            )
        ]
        if security_groups:
            facts.set(AwsResourceMetadata.ECS_SYMBOLIC_SECURITY_GROUP_ADDRESSES, security_groups)

    def _resolve_ecs_task_definition(self, resource: NormalizedResource, context: AwsDecorationContext) -> None:
        facts = aws_facts(resource)
        role_fields = (
            ("task_role_arn", AwsResourceMetadata.TASK_ROLE_ARN),
            ("execution_role_arn", AwsResourceMetadata.EXECUTION_ROLE_ARN),
        )
        for path_name, metadata_field in role_fields:
            if facts.get(metadata_field):
                continue
            role = symbolic_reference_target(
                resource,
                context.index,
                path_name,
                expected_resource_types={"aws_iam_role"},
                expected_reference_suffixes={".arn"},
            )
            if role is not None:
                facts.set(metadata_field, resource_reference_value(role))

    def _resolve_listener(self, resource: NormalizedResource, context: AwsDecorationContext) -> None:
        facts = aws_facts(resource)
        if not facts.load_balancer_arn:
            load_balancer = symbolic_reference_target(
                resource,
                context.index,
                "load_balancer_arn",
                expected_resource_types={"aws_lb"},
                expected_reference_suffixes={".arn"},
            )
            if load_balancer is not None:
                facts.set(
                    AwsResourceMetadata.LOAD_BALANCER_ARN,
                    resource_reference_value(load_balancer),
                )

        self._resolve_action_targets(resource, context, "default_action")

    def _resolve_listener_rule(self, resource: NormalizedResource, context: AwsDecorationContext) -> None:
        facts = aws_facts(resource)
        if not facts.listener_arn:
            listener = symbolic_reference_target(
                resource,
                context.index,
                "listener_arn",
                expected_resource_types={"aws_lb_listener"},
                expected_reference_suffixes={".arn"},
            )
            if listener is not None:
                facts.set(AwsResourceMetadata.LISTENER_ARN, resource_reference_value(listener))

        self._resolve_action_targets(resource, context, "action")

    def _resolve_action_targets(self, resource: NormalizedResource, context: AwsDecorationContext, field: str) -> None:
        facts = aws_facts(resource)
        actions = facts.load_balancer_actions
        targets_by_path = {
            tuple(target["configuration_path"]): target for action in actions for target in action["targets"]
        }
        for path, target_group in symbolic_reference_target_records(
            resource,
            context.index,
            path_prefix=(field,),
            terminal_segments={"target_group_arn", "arn"},
            expected_resource_types={"aws_lb_target_group"},
            expected_reference_suffixes={".arn"},
        ):
            target = targets_by_path.get(path)
            if target is not None and not target["reference"]:
                target["reference"] = resource_reference_value(target_group)
        facts.set(AwsResourceMetadata.LOAD_BALANCER_ACTIONS, actions)
        facts.set(AwsResourceMetadata.LOAD_BALANCER_TARGET_GROUP_ARNS, action_target_references(actions))

    def _resolve_kms_alias(self, resource: NormalizedResource, context: AwsDecorationContext) -> None:
        facts = aws_facts(resource)
        if facts.kms_alias_target_key_reference:
            return
        key = symbolic_reference_target(
            resource,
            context.index,
            "target_key_id",
            expected_resource_types={"aws_kms_key"},
            expected_reference_suffixes={".key_id", ".id", ".arn"},
        ) or symbolic_reference_target(
            resource,
            context.index,
            "target_key_arn",
            expected_resource_types={"aws_kms_key"},
            expected_reference_suffixes={".arn"},
        )
        if key is not None:
            facts.set(
                AwsResourceMetadata.KMS_ALIAS_TARGET_KEY_REFERENCE,
                resource_reference_value(key),
            )

    def _resolve_kms_grant(self, resource: NormalizedResource, context: AwsDecorationContext) -> None:
        self._resolve_kms_key_reference(resource, context, AwsResourceMetadata.KMS_GRANT_KEY_REFERENCE)

    def _resolve_kms_key_policy(self, resource: NormalizedResource, context: AwsDecorationContext) -> None:
        self._resolve_kms_key_reference(resource, context, AwsResourceMetadata.KMS_KEY_POLICY_KEY_REFERENCE)

    def _resolve_kms_key_reference(
        self,
        resource: NormalizedResource,
        context: AwsDecorationContext,
        metadata_field: MetadataField[str | None],
    ) -> None:
        facts = aws_facts(resource)
        if facts.get(metadata_field):
            return
        key = symbolic_reference_target(
            resource,
            context.index,
            "key_id",
            expected_resource_types={"aws_kms_key"},
            expected_reference_suffixes={".key_id", ".id", ".arn"},
        )
        if key is not None:
            facts.set(metadata_field, resource_reference_value(key))

    def _resolve_sqs_redrive_policy(self, resource: NormalizedResource, context: AwsDecorationContext) -> None:
        facts = aws_facts(resource)
        if not facts.sqs_queue_url:
            queue = symbolic_reference_target(
                resource,
                context.index,
                "queue_url",
                expected_resource_types={"aws_sqs_queue"},
                expected_reference_suffixes={".id", ".url"},
            )
            if queue is not None:
                facts.set(AwsResourceMetadata.SQS_QUEUE_URL, resource_reference_value(queue))

        if facts.sqs_redrive_target_arn:
            return
        dead_letter_queue = symbolic_reference_target(
            resource,
            context.index,
            "redrive_policy",
            expected_resource_types={"aws_sqs_queue"},
            expected_reference_suffixes={".arn"},
        )
        if dead_letter_queue is not None:
            facts.set(
                AwsResourceMetadata.SQS_REDRIVE_TARGET_ARN,
                resource_reference_value(dead_letter_queue),
            )

    def _resolve_direct_kms_reference(self, resource: NormalizedResource, context: AwsDecorationContext) -> None:
        direct_fields = {
            "aws_sqs_queue": (
                "kms_master_key_id",
                AwsResourceMetadata.SQS_KMS_MASTER_KEY_ID,
                {".key_id", ".id", ".arn"},
            ),
            "aws_sns_topic": (
                "kms_master_key_id",
                AwsResourceMetadata.SNS_KMS_MASTER_KEY_ID,
                {".key_id", ".id", ".arn"},
            ),
            "aws_dynamodb_table": (
                "kms_key_arn",
                AwsResourceMetadata.DYNAMODB_KMS_KEY_ARN,
                {".arn"},
            ),
        }
        field = direct_fields.get(resource.resource_type)
        if field is None:
            return
        path_name, metadata_field, expected_reference_suffixes = field
        facts = aws_facts(resource)
        if facts.get(metadata_field):
            return
        key = symbolic_reference_target(
            resource,
            context.index,
            path_name,
            expected_resource_types={"aws_kms_key"},
            expected_reference_suffixes=expected_reference_suffixes,
        )
        if key is None and resource.resource_type == "aws_dynamodb_table":
            key_matches = symbolic_reference_target_records(
                resource,
                context.index,
                path_prefix=("server_side_encryption",),
                terminal_segments={"kms_key_arn"},
                expected_resource_types={"aws_kms_key"},
                expected_reference_suffixes={".arn"},
            )
            if len(key_matches) == 1:
                key = key_matches[0][1]
        if key is not None:
            facts.set(metadata_field, resource_reference_value(key))


def _dedupe(values: list[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))
