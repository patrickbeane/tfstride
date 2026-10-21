from __future__ import annotations

import types
import unittest
from typing import Literal, Never, get_args, get_type_hints

from tfstride.providers.aws.messaging_topology_destruction_evidence import (
    AwsEcsMessagingTopologyDestructionPath,
    AwsEcsSnsTopicDeletionPath,
    AwsEcsSqsQueueDeletionPath,
    AwsMessagingTopologyDestructionOutcomeEvidence,
    AwsSnsTopicDeletionPolicyStatementEvidence,
    AwsSqsQueueDeletionPolicyStatementEvidence,
)
from tfstride.providers.azure.messaging_topology_destruction_evidence import (
    AzureAppServiceServiceBusNamespaceDeletionPath,
    AzureAppServiceServiceBusQueueDeletionPath,
    AzureAppServiceServiceBusSubscriptionDeletionPath,
    AzureAppServiceServiceBusTopicDeletionPath,
    AzureAppServiceServiceBusTopologyDestructionPath,
    AzureServiceBusNamespaceDeletionAuthorizationGrant,
    AzureServiceBusQueueDeletionAuthorizationGrant,
    AzureServiceBusSubscriptionDeletionAuthorizationGrant,
    AzureServiceBusTopicDeletionAuthorizationGrant,
    AzureServiceBusTopologyBuiltInRoleEvidence,
    AzureServiceBusTopologyCustomRoleEvidence,
    AzureServiceBusTopologyDestructionLockEvidence,
    AzureServiceBusTopologyDestructionOutcomeEvidence,
)
from tfstride.providers.gcp.messaging_topology_destruction_evidence import (
    GcpCloudRunPubsubProjectSubscriptionDeletionPath,
    GcpCloudRunPubsubProjectTopicDeletionPath,
    GcpCloudRunPubsubSubscriptionDeletionPath,
    GcpCloudRunPubsubTopicDeletionPath,
    GcpCloudRunPubsubTopologyDestructionPath,
    GcpPubsubTopologyBuiltInRoleEvidence,
    GcpPubsubTopologyCustomRoleEvidence,
    GcpPubsubTopologyDestructionOutcomeEvidence,
)


class MessagingTopologyDestructionEvidenceTests(unittest.TestCase):
    def test_aws_contract_discriminates_queue_and_topic_deletion(self) -> None:
        queue_hints = get_type_hints(AwsEcsSqsQueueDeletionPath)
        topic_hints = get_type_hints(AwsEcsSnsTopicDeletionPath)
        queue_statement_hints = get_type_hints(AwsSqsQueueDeletionPolicyStatementEvidence)
        topic_statement_hints = get_type_hints(AwsSnsTopicDeletionPolicyStatementEvidence)
        outcome_hints = get_type_hints(AwsMessagingTopologyDestructionOutcomeEvidence)

        self.assertEqual(
            set(get_args(AwsEcsMessagingTopologyDestructionPath)),
            {AwsEcsSqsQueueDeletionPath, AwsEcsSnsTopicDeletionPath},
        )
        self.assertEqual(queue_hints["operation"], Literal["sqs:DeleteQueue"])
        self.assertEqual(queue_hints["operation_class"], Literal["queue_deletion"])
        self.assertEqual(queue_hints["target_scope"], Literal["exact_sqs_queue"])
        self.assertEqual(queue_hints["same_account"], Literal[True])
        self.assertIs(queue_hints["topic_address"], types.NoneType)
        self.assertEqual(
            queue_hints["authorization_bases"],
            list[Literal["identity_policy", "queue_policy_direct"]],
        )
        self.assertEqual(
            queue_statement_hints["source_kind"],
            Literal["identity_policy", "queue_policy"],
        )

        self.assertEqual(
            queue_statement_hints["resource_scopes"],
            list[Literal["exact_queue", "queue_pattern"]],
        )
        self.assertEqual(
            topic_statement_hints["resource_scopes"],
            list[Literal["exact_topic", "topic_pattern"]],
        )

        self.assertEqual(topic_hints["operation"], Literal["sns:DeleteTopic"])
        self.assertEqual(topic_hints["operation_class"], Literal["topic_deletion"])
        self.assertEqual(topic_hints["target_scope"], Literal["exact_sns_topic"])
        self.assertIs(topic_hints["queue_address"], types.NoneType)
        self.assertEqual(
            topic_hints["authorization_bases"],
            list[Literal["identity_policy", "topic_policy_direct"]],
        )
        self.assertEqual(
            topic_statement_hints["source_kind"],
            Literal["identity_policy", "topic_policy"],
        )
        self.assertEqual(
            outcome_hints["successful_deletion_observed"],
            Literal[False],
        )
        self.assertEqual(
            outcome_hints["recovery_state"],
            Literal["not_established_by_modeled_aws_messaging_topology_evidence"],
        )
        self.assertEqual(
            outcome_hints["descendant_impact_evaluated"],
            Literal[False],
        )

    def test_gcp_contract_discriminates_target_and_iam_scope(self) -> None:
        project_topic_hints = get_type_hints(GcpCloudRunPubsubProjectTopicDeletionPath)
        topic_hints = get_type_hints(GcpCloudRunPubsubTopicDeletionPath)
        project_subscription_hints = get_type_hints(GcpCloudRunPubsubProjectSubscriptionDeletionPath)
        subscription_hints = get_type_hints(GcpCloudRunPubsubSubscriptionDeletionPath)
        built_in_role_hints = get_type_hints(GcpPubsubTopologyBuiltInRoleEvidence)
        custom_role_hints = get_type_hints(GcpPubsubTopologyCustomRoleEvidence)
        outcome_hints = get_type_hints(GcpPubsubTopologyDestructionOutcomeEvidence)

        self.assertEqual(
            set(get_args(GcpCloudRunPubsubTopologyDestructionPath)),
            {
                GcpCloudRunPubsubProjectTopicDeletionPath,
                GcpCloudRunPubsubTopicDeletionPath,
                GcpCloudRunPubsubProjectSubscriptionDeletionPath,
                GcpCloudRunPubsubSubscriptionDeletionPath,
            },
        )
        self.assertEqual(
            project_topic_hints["operation"],
            Literal["pubsub.topics.delete"],
        )
        self.assertEqual(project_topic_hints["scope_type"], Literal["project"])
        self.assertEqual(
            project_topic_hints["grant_basis"],
            Literal["pubsub_project_iam"],
        )
        self.assertIs(
            project_topic_hints["subscription_address"],
            types.NoneType,
        )
        self.assertEqual(topic_hints["scope_type"], Literal["topic"])
        self.assertEqual(
            topic_hints["grant_basis"],
            Literal["pubsub_topic_iam"],
        )

        self.assertEqual(
            project_subscription_hints["operation"],
            Literal["pubsub.subscriptions.delete"],
        )
        self.assertEqual(
            project_subscription_hints["scope_type"],
            Literal["project"],
        )
        self.assertEqual(
            subscription_hints["scope_type"],
            Literal["subscription"],
        )
        self.assertEqual(subscription_hints["topic_address"], str)
        self.assertEqual(subscription_hints["subscription_address"], str)
        self.assertEqual(
            subscription_hints["grant_basis"],
            Literal["pubsub_subscription_iam"],
        )

        self.assertEqual(
            built_in_role_hints["role_kind"],
            Literal["owner", "editor", "admin"],
        )
        self.assertEqual(
            built_in_role_hints["custom_role_permissions"],
            list[Never],
        )
        self.assertIs(
            built_in_role_hints["role_definition_address"],
            types.NoneType,
        )
        self.assertEqual(
            custom_role_hints["custom_role_grant_scope_compatibility_state"],
            Literal["compatible"],
        )
        self.assertEqual(
            outcome_hints["successful_deletion_observed"],
            Literal[False],
        )
        self.assertEqual(
            outcome_hints["recovery_state"],
            Literal["not_established_by_modeled_gcp_messaging_topology_evidence"],
        )

    def test_azure_contract_discriminates_every_topology_target(self) -> None:
        namespace_hints = get_type_hints(AzureAppServiceServiceBusNamespaceDeletionPath)
        queue_hints = get_type_hints(AzureAppServiceServiceBusQueueDeletionPath)
        topic_hints = get_type_hints(AzureAppServiceServiceBusTopicDeletionPath)
        subscription_hints = get_type_hints(AzureAppServiceServiceBusSubscriptionDeletionPath)
        built_in_role_hints = get_type_hints(AzureServiceBusTopologyBuiltInRoleEvidence)
        custom_role_hints = get_type_hints(AzureServiceBusTopologyCustomRoleEvidence)
        lock_hints = get_type_hints(AzureServiceBusTopologyDestructionLockEvidence)
        outcome_hints = get_type_hints(AzureServiceBusTopologyDestructionOutcomeEvidence)

        self.assertEqual(
            set(get_args(AzureAppServiceServiceBusTopologyDestructionPath)),
            {
                AzureAppServiceServiceBusNamespaceDeletionPath,
                AzureAppServiceServiceBusQueueDeletionPath,
                AzureAppServiceServiceBusTopicDeletionPath,
                AzureAppServiceServiceBusSubscriptionDeletionPath,
            },
        )
        cases = (
            (
                namespace_hints,
                Literal["Microsoft.ServiceBus/namespaces/delete"],
                Literal["namespace_deletion"],
                Literal["service_bus_namespace_topology"],
                AzureServiceBusNamespaceDeletionAuthorizationGrant,
            ),
            (
                queue_hints,
                Literal["Microsoft.ServiceBus/namespaces/queues/delete"],
                Literal["queue_deletion"],
                Literal["queue_topology"],
                AzureServiceBusQueueDeletionAuthorizationGrant,
            ),
            (
                topic_hints,
                Literal["Microsoft.ServiceBus/namespaces/topics/delete"],
                Literal["topic_deletion"],
                Literal["topic_topology"],
                AzureServiceBusTopicDeletionAuthorizationGrant,
            ),
            (
                subscription_hints,
                Literal["Microsoft.ServiceBus/namespaces/topics/subscriptions/delete"],
                Literal["subscription_deletion"],
                Literal["subscription_topology"],
                AzureServiceBusSubscriptionDeletionAuthorizationGrant,
            ),
        )
        for (
            hints,
            operation,
            operation_class,
            target_granularity,
            grant_type,
        ) in cases:
            with self.subTest(operation=operation):
                self.assertEqual(hints["operation"], operation)
                self.assertEqual(hints["operation_class"], operation_class)
                self.assertEqual(
                    hints["target_granularity"],
                    target_granularity,
                )
                self.assertEqual(hints["authorization_grant"], grant_type)
                self.assertEqual(
                    hints["lifecycle_compatibility_state"],
                    Literal["compatible"],
                )

        self.assertIs(namespace_hints["queue_address"], types.NoneType)
        self.assertIs(namespace_hints["topic_address"], types.NoneType)
        self.assertEqual(queue_hints["queue_address"], str)
        self.assertIs(queue_hints["topic_address"], types.NoneType)
        self.assertEqual(topic_hints["topic_address"], str)
        self.assertIs(topic_hints["subscription_address"], types.NoneType)
        self.assertEqual(subscription_hints["topic_address"], str)
        self.assertEqual(subscription_hints["subscription_address"], str)

        self.assertEqual(
            built_in_role_hints["role_resolution_state"],
            Literal["modeled_subset"],
        )
        self.assertIs(
            built_in_role_hints["role_definition_address"],
            types.NoneType,
        )
        self.assertEqual(
            custom_role_hints["role_resolution_state"],
            Literal["resolved"],
        )
        self.assertEqual(
            custom_role_hints["role_definition_address"],
            str,
        )
        self.assertEqual(
            lock_hints["modeled_management_lock_state"],
            Literal["not_observed"],
        )
        self.assertEqual(
            lock_hints["applicable_lock_addresses"],
            list[Never],
        )
        self.assertEqual(
            lock_hints["external_management_locks_evaluated"],
            Literal[False],
        )
        self.assertEqual(
            outcome_hints["successful_deletion_observed"],
            Literal[False],
        )
        self.assertEqual(
            outcome_hints["recovery_state"],
            Literal["not_established_by_modeled_azure_messaging_topology_evidence"],
        )


if __name__ == "__main__":
    unittest.main()
