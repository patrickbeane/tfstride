from __future__ import annotations

import unittest

from tfstride.analysis.coverage import build_analysis_coverage
from tfstride.models import (
    IAMPolicyStatement,
    IAMPrincipal,
    NormalizedResource,
    ResourceCategory,
    ResourceInventory,
    SecurityGroupRule,
)
from tfstride.providers.aws.resource_decoration.iam import MergeRolePolicyResourcesStage
from tfstride.providers.aws.resource_decoration.resource_policies import (
    ApplyS3PublicAccessBlocksStage,
)
from tfstride.providers.aws.resource_decoration_stages import default_aws_decoration_stages
from tfstride.providers.aws.resource_decorator import AwsResourceDecorator
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import AwsResourceIndex, AwsResourceIndexBuilder


def _resource(
    *,
    address: str,
    resource_type: str,
    category: ResourceCategory,
    identifier: str | None = None,
    arn: str | None = None,
    metadata: dict | None = None,
    policy_statements: list[IAMPolicyStatement] | None = None,
    network_rules: list[SecurityGroupRule] | None = None,
    public_access_configured: bool = False,
    public_exposure: bool = False,
    vpc_id: str | None = None,
    provider_config_key: str | None = "aws.default",
) -> NormalizedResource:
    return NormalizedResource(
        address=address,
        provider="aws",
        resource_type=resource_type,
        name=address.rsplit(".", 1)[-1],
        category=category,
        identifier=identifier,
        arn=arn,
        metadata=metadata or {},
        policy_statements=policy_statements or [],
        network_rules=network_rules or [],
        public_access_configured=public_access_configured,
        public_exposure=public_exposure,
        vpc_id=vpc_id,
        provider_config_key=provider_config_key,
    )


class AwsResourceIndexBuilderTests(unittest.TestCase):
    def test_indexes_resources_by_provider_specific_references(self) -> None:
        bucket = _resource(
            address="aws_s3_bucket.logs",
            resource_type="aws_s3_bucket",
            category=ResourceCategory.DATA,
            identifier="logs",
            arn="arn:aws:s3:::logs",
        )
        secret = _resource(
            address="aws_secretsmanager_secret.app",
            resource_type="aws_secretsmanager_secret",
            category=ResourceCategory.DATA,
            identifier="app-secret-id",
            arn="arn:aws:secretsmanager:us-east-1:111122223333:secret:app",
            metadata={"name": "app"},
        )
        route_table = _resource(
            address="aws_route_table.public",
            resource_type="aws_route_table",
            category=ResourceCategory.NETWORK,
            identifier="rtb-public",
            vpc_id="vpc-app",
            metadata={
                "routes": [
                    {
                        "destination_cidr_block": "0.0.0.0/0",
                        "gateway_id": "igw-app",
                    }
                ]
            },
        )
        nat_gateway = _resource(
            address="aws_nat_gateway.private",
            resource_type="aws_nat_gateway",
            category=ResourceCategory.NETWORK,
            identifier="nat-private",
        )

        index = AwsResourceIndexBuilder().build([bucket, secret, route_table, nat_gateway])

        self.assertIs(index.buckets.get("logs"), bucket)
        self.assertIs(index.buckets.get("aws_s3_bucket.logs"), bucket)
        self.assertIs(index.buckets.get("arn:aws:s3:::logs"), bucket)
        self.assertIs(index.secrets.get("app"), secret)
        self.assertEqual(index.vpcs_with_public_routes, {("aws.default", "vpc-app")})
        self.assertEqual(index.nat_gateway_ids, {("aws.default", "nat-private")})

    def test_native_alias_collisions_are_deterministic_and_fail_closed(self) -> None:
        first_bucket = _resource(
            address="aws_s3_bucket.first",
            resource_type="aws_s3_bucket",
            category=ResourceCategory.DATA,
            identifier="logs",
            arn="arn:aws:s3:::logs",
            provider_config_key="aws.first",
        )
        second_bucket = _resource(
            address="aws_s3_bucket.second",
            resource_type="aws_s3_bucket",
            category=ResourceCategory.DATA,
            identifier="logs",
            arn="arn:aws:s3:::logs",
            provider_config_key="aws.second",
        )
        unmatched_source = _resource(
            address="aws_s3_bucket_policy.unmatched",
            resource_type="aws_s3_bucket_policy",
            category=ResourceCategory.DATA,
            provider_config_key="aws.unmatched",
        )

        for resources in (
            [first_bucket, second_bucket],
            [second_bucket, first_bucket],
        ):
            with self.subTest(order=[resource.address for resource in resources]):
                index = AwsResourceIndexBuilder().build(resources)
                resolution = index.buckets.resolve("logs")
                strong_resolution = index.buckets.resolve(
                    "arn:aws:s3:::logs",
                    source=unmatched_source,
                )

                self.assertEqual(resolution.state, "ambiguous")
                self.assertEqual(resolution.candidates, (first_bucket, second_bucket))
                self.assertIsNone(resolution.selected_candidate)
                self.assertEqual(strong_resolution.state, "ambiguous")
                self.assertEqual(
                    strong_resolution.candidates,
                    (first_bucket, second_bucket),
                )
                self.assertIsNone(strong_resolution.selected_candidate)
                self.assertIsNone(index.buckets.get("logs"))
                self.assertIs(index.buckets.get("aws_s3_bucket.first"), first_bucket)
                self.assertIs(index.buckets.get("aws_s3_bucket.second"), second_bucket)

    def test_duplicate_strong_identity_remains_ambiguous_in_matching_source_configuration(
        self,
    ) -> None:
        duplicate_arn = "arn:aws:s3:::logs"
        primary_bucket = _resource(
            address="aws_s3_bucket.primary",
            resource_type="aws_s3_bucket",
            category=ResourceCategory.DATA,
            identifier="primary-logs",
            arn=duplicate_arn,
            provider_config_key="aws.primary",
        )
        secondary_bucket = _resource(
            address="aws_s3_bucket.secondary",
            resource_type="aws_s3_bucket",
            category=ResourceCategory.DATA,
            identifier="secondary-logs",
            arn=duplicate_arn,
            provider_config_key="aws.secondary",
        )
        primary_source = _resource(
            address="aws_s3_bucket_public_access_block.logs",
            resource_type="aws_s3_bucket_public_access_block",
            category=ResourceCategory.DATA,
            provider_config_key="aws.primary",
        )

        for resources in (
            [primary_bucket, secondary_bucket],
            [secondary_bucket, primary_bucket],
        ):
            with self.subTest(order=[resource.address for resource in resources]):
                resolution = (
                    AwsResourceIndexBuilder().build(resources).buckets.resolve(duplicate_arn, source=primary_source)
                )

                self.assertEqual(resolution.state, "ambiguous")
                self.assertEqual(
                    resolution.candidates,
                    (primary_bucket, secondary_bucket),
                )
                self.assertIsNone(resolution.selected_candidate)

    def test_exact_address_precedes_a_colliding_native_alias(self) -> None:
        exact_bucket = _resource(
            address="aws_s3_bucket.exact",
            resource_type="aws_s3_bucket",
            category=ResourceCategory.DATA,
            identifier="exact-bucket",
            provider_config_key="aws.primary",
        )
        colliding_bucket = _resource(
            address="aws_s3_bucket.colliding",
            resource_type="aws_s3_bucket",
            category=ResourceCategory.DATA,
            identifier=exact_bucket.address,
            provider_config_key="aws.secondary",
        )
        secondary_policy = _resource(
            address="aws_s3_bucket_policy.secondary",
            resource_type="aws_s3_bucket_policy",
            category=ResourceCategory.DATA,
            provider_config_key="aws.secondary",
        )

        for resources in (
            [exact_bucket, colliding_bucket],
            [colliding_bucket, exact_bucket],
        ):
            with self.subTest(order=[resource.address for resource in resources]):
                resolution = (
                    AwsResourceIndexBuilder()
                    .build(resources)
                    .buckets.resolve(exact_bucket.address, source=secondary_policy)
                )

                self.assertEqual(resolution.state, "resolved")
                self.assertEqual(resolution.candidates, (exact_bucket,))
                self.assertIs(resolution.selected_candidate, exact_bucket)

    def test_resolution_filters_by_type_and_source_provider_configuration(self) -> None:
        primary_bucket = _resource(
            address="aws_s3_bucket.primary",
            resource_type="aws_s3_bucket",
            category=ResourceCategory.DATA,
            identifier="shared",
            provider_config_key="aws.primary",
        )
        secondary_bucket = _resource(
            address="aws_s3_bucket.secondary",
            resource_type="aws_s3_bucket",
            category=ResourceCategory.DATA,
            identifier="shared",
            provider_config_key="aws.secondary",
        )
        unique_secondary_bucket = _resource(
            address="aws_s3_bucket.unique_secondary",
            resource_type="aws_s3_bucket",
            category=ResourceCategory.DATA,
            identifier="unique-secondary",
            arn="arn:aws:s3:::unique-secondary",
            provider_config_key="aws.secondary",
        )
        primary_secret = _resource(
            address="aws_secretsmanager_secret.primary",
            resource_type="aws_secretsmanager_secret",
            category=ResourceCategory.DATA,
            identifier="shared",
            metadata={"name": "shared"},
            provider_config_key="aws.primary",
        )
        primary_policy = _resource(
            address="aws_s3_bucket_policy.primary",
            resource_type="aws_s3_bucket_policy",
            category=ResourceCategory.DATA,
            provider_config_key="aws.primary",
        )
        unmatched_policy = _resource(
            address="aws_s3_bucket_policy.unmatched",
            resource_type="aws_s3_bucket_policy",
            category=ResourceCategory.DATA,
            provider_config_key="aws.unmatched",
        )
        index = AwsResourceIndexBuilder().build(
            [
                secondary_bucket,
                primary_secret,
                unique_secondary_bucket,
                primary_bucket,
                primary_policy,
                unmatched_policy,
            ]
        )

        unscoped = index.buckets.resolve("shared")
        scoped = index.buckets.resolve("shared", source=primary_policy)
        unmatched_scope = index.buckets.resolve("shared", source=unmatched_policy)
        typed = index.secrets.resolve("shared", source=primary_policy)
        weak_cross_config = index.buckets.resolve(
            "unique-secondary",
            source=primary_policy,
        )
        strong_cross_config = index.buckets.resolve(
            "arn:aws:s3:::unique-secondary",
            source=primary_policy,
        )

        self.assertEqual(unscoped.state, "ambiguous")
        self.assertEqual(unscoped.candidates, (primary_bucket, secondary_bucket))
        self.assertEqual(scoped.state, "resolved")
        self.assertIs(scoped.selected_candidate, primary_bucket)
        self.assertEqual(unmatched_scope.state, "unresolved")
        self.assertEqual(unmatched_scope.candidates, ())
        self.assertEqual(typed.state, "resolved")
        self.assertIs(typed.selected_candidate, primary_secret)
        self.assertEqual(weak_cross_config.state, "unresolved")
        self.assertEqual(weak_cross_config.candidates, ())
        self.assertEqual(strong_cross_config.state, "resolved")
        self.assertIs(strong_cross_config.selected_candidate, unique_secondary_bucket)

    def test_weak_reference_scope_contract_fails_closed_on_unknown_candidates(self) -> None:
        local = _resource(
            address="aws_s3_bucket.local",
            resource_type="aws_s3_bucket",
            category=ResourceCategory.DATA,
            identifier="shared",
            provider_config_key="aws.primary",
        )
        foreign = _resource(
            address="aws_s3_bucket.foreign",
            resource_type="aws_s3_bucket",
            category=ResourceCategory.DATA,
            identifier="shared",
            provider_config_key="aws.secondary",
        )
        unknown = _resource(
            address="aws_s3_bucket.unknown",
            resource_type="aws_s3_bucket",
            category=ResourceCategory.DATA,
            identifier="shared",
            provider_config_key=None,
        )
        source = _resource(
            address="aws_s3_bucket_policy.source",
            resource_type="aws_s3_bucket_policy",
            category=ResourceCategory.DATA,
            provider_config_key="aws.primary",
        )
        cases = (
            ("known-local", (local,), "resolved", (local,)),
            ("known-local-and-known-foreign", (local, foreign), "resolved", (local,)),
            ("known-local-and-unknown", (local, unknown), "ambiguous", (local, unknown)),
            (
                "known-local-known-foreign-and-unknown",
                (local, foreign, unknown),
                "ambiguous",
                (local, unknown),
            ),
            ("known-foreign", (foreign,), "unresolved", ()),
            ("unknown", (unknown,), "unresolved", ()),
            ("known-foreign-and-unknown", (foreign, unknown), "unresolved", ()),
        )

        for name, candidates, expected_state, expected_candidates in cases:
            for ordered_candidates in (candidates, tuple(reversed(candidates))):
                with self.subTest(
                    case=name,
                    order=[candidate.address for candidate in ordered_candidates],
                ):
                    resolution = (
                        AwsResourceIndexBuilder()
                        .build(list(ordered_candidates))
                        .buckets.resolve("shared", source=source)
                    )

                    self.assertEqual(resolution.state, expected_state)
                    self.assertEqual(resolution.candidates, expected_candidates)

        exact = AwsResourceIndexBuilder().build([unknown]).buckets.resolve(unknown.address, source=source)
        self.assertEqual(exact.state, "resolved")
        self.assertIs(exact.selected_candidate, unknown)

    def test_weak_reference_with_unknown_source_scope_fails_closed(self) -> None:
        bucket = _resource(
            address="aws_s3_bucket.foreign",
            resource_type="aws_s3_bucket",
            category=ResourceCategory.DATA,
            identifier="shared",
            arn="arn:aws:s3:::shared",
            provider_config_key="aws.foreign",
        )
        source = _resource(
            address="aws_s3_bucket_policy.unknown_scope",
            resource_type="aws_s3_bucket_policy",
            category=ResourceCategory.DATA,
            provider_config_key=None,
        )
        references = AwsResourceIndexBuilder().build([bucket]).buckets

        self.assertIs(references.resolve("shared").selected_candidate, bucket)
        self.assertEqual(references.resolve("shared", source=source).state, "unresolved")
        self.assertIs(references.resolve(bucket.address, source=source).selected_candidate, bucket)
        self.assertIs(references.resolve(bucket.arn, source=source).selected_candidate, bucket)

    def test_strong_reference_precedes_a_same_config_weak_alias(self) -> None:
        foreign_key = _resource(
            address="aws_kms_key.foreign",
            resource_type="aws_kms_key",
            category=ResourceCategory.DATA,
            identifier="foreign-key",
            arn="arn:aws:kms:us-east-1:111122223333:key/foreign",
            provider_config_key="aws.secondary",
        )
        local_arn_collision = _resource(
            address="aws_kms_key.local_arn_collision",
            resource_type="aws_kms_key",
            category=ResourceCategory.DATA,
            identifier=foreign_key.arn,
            provider_config_key="aws.primary",
        )
        local_address_collision = _resource(
            address="aws_kms_key.local_address_collision",
            resource_type="aws_kms_key",
            category=ResourceCategory.DATA,
            identifier=f"{foreign_key.address}.arn",
            provider_config_key="aws.primary",
        )
        primary_source = _resource(
            address="aws_kms_alias.primary",
            resource_type="aws_kms_alias",
            category=ResourceCategory.DATA,
            provider_config_key="aws.primary",
        )

        for resources in (
            [foreign_key, local_arn_collision, local_address_collision],
            [local_address_collision, local_arn_collision, foreign_key],
        ):
            for reference in (
                foreign_key.arn,
                f"{foreign_key.address}.arn",
            ):
                with self.subTest(
                    order=[resource.address for resource in resources],
                    reference=reference,
                ):
                    resolution = (
                        AwsResourceIndexBuilder()
                        .build(resources)
                        .kms_keys.resolve(
                            reference,
                            source=primary_source,
                        )
                    )

                    self.assertEqual(resolution.state, "resolved")
                    self.assertEqual(resolution.candidates, (foreign_key,))
                    self.assertIs(resolution.selected_candidate, foreign_key)

    def test_fully_qualified_service_urls_resolve_across_provider_configurations(
        self,
    ) -> None:
        queue_url = "https://sqs.us-east-1.amazonaws.com/111122223333/jobs"
        repository_url = "111122223333.dkr.ecr.us-east-1.amazonaws.com/orders"
        queue = _resource(
            address="aws_sqs_queue.jobs",
            resource_type="aws_sqs_queue",
            category=ResourceCategory.DATA,
            identifier="jobs",
            metadata={"sqs_queue_url": queue_url},
            provider_config_key="aws.secondary",
        )
        repository = _resource(
            address="aws_ecr_repository.orders",
            resource_type="aws_ecr_repository",
            category=ResourceCategory.DATA,
            identifier="orders",
            metadata={"ecr_repository_url": repository_url},
            provider_config_key="aws.secondary",
        )
        primary_source = _resource(
            address="aws_ecs_task_definition.primary",
            resource_type="aws_ecs_task_definition",
            category=ResourceCategory.COMPUTE,
            provider_config_key="aws.primary",
        )
        index = AwsResourceIndexBuilder().build([queue, repository])

        for view, reference, expected in (
            (index.sqs_queues, queue_url, queue),
            (index.ecr_repositories, repository_url, repository),
        ):
            with self.subTest(reference=reference):
                resolution = view.resolve(reference, source=primary_source)

                self.assertEqual(resolution.state, "resolved")
                self.assertEqual(resolution.candidates, (expected,))
                self.assertIs(resolution.selected_candidate, expected)

    def test_missing_identifiers_are_not_indexed(self) -> None:
        subnet = _resource(
            address="aws_subnet.app",
            resource_type="aws_subnet",
            category=ResourceCategory.NETWORK,
        )
        index = AwsResourceIndexBuilder().build([subnet])

        self.assertEqual(index.subnets.resolve(None).state, "unresolved")
        self.assertIsNone(index.subnets.get(None))
        self.assertIs(index.subnets.get(subnet.address), subnet)


class AwsResourceDecoratorTests(unittest.TestCase):
    def test_decorator_runs_configured_stages_in_order_with_shared_context(self) -> None:
        calls: list[str] = []

        class RecordingStage:
            name = "recording"

            def __init__(self, call_name: str) -> None:
                self._call_name = call_name

            def apply(self, resources: list[NormalizedResource], context) -> None:
                calls.append(f"{self._call_name}:{bool(context.index.subnets.resources)}")

        subnet = _resource(
            address="aws_subnet.app",
            resource_type="aws_subnet",
            category=ResourceCategory.NETWORK,
            identifier="subnet-app",
        )

        AwsResourceDecorator(stages=[RecordingStage("first"), RecordingStage("second")]).decorate([subnet])

        self.assertEqual(calls, ["first:True", "second:True"])

    def test_default_decoration_stages_are_ordered_by_contract(self) -> None:
        self.assertEqual(
            [stage.name for stage in default_aws_decoration_stages()],
            [
                "merge_standalone_security_group_rules",
                "resolve_aws_symbolic_relationships",
                "merge_role_policy_resources",
                "normalize_iam_assignment_posture",
                "decorate_kms_relationships",
                "model_kms_operation_authorization",
                "model_ecs_kms_operation_paths",
                "model_ecs_kms_management_paths",
                "resolve_instance_profile_roles",
                "resolve_oidc_provider_trust",
                "resolve_ecs_service_relationships",
                "model_ecs_secret_access_paths",
                "model_ecs_s3_access_paths",
                "model_ecs_messaging_access_paths",
                "model_ecs_dynamodb_access_paths",
                "model_ecs_dynamodb_item_deletion_paths",
                "model_ecs_dynamodb_table_topology_destruction_paths",
                "model_ecs_cloudtrail_audit_telemetry_disruption_paths",
                "model_workload_ecr_write_paths",
                "resolve_api_gateway_relationships",
                "merge_resource_policy_resources",
                "model_ecs_messaging_topology_destruction_paths",
                "apply_s3_public_access_blocks",
                "apply_s3_posture_resources",
                "model_ecs_s3_bucket_topology_destruction_paths",
                "model_ecs_s3_object_deletion_paths",
                "apply_secrets_manager_posture_resources",
                "model_secrets_manager_operation_authorization",
                "model_ecs_secrets_manager_management_paths",
                "apply_sqs_redrive_policy_resources",
                "model_ecs_sqs_message_removal_paths",
                "resolve_aws_kms_encryption_dependencies",
                "derive_subnet_posture",
                "infer_vpc_ids",
                "derive_public_exposure",
                "mark_ecs_services_fronted_by_internet_facing_load_balancers",
                "project_ecs_kms_operation_paths_onto_services",
                "project_ecs_kms_management_paths_onto_services",
                "project_ecs_secrets_manager_management_paths_onto_services",
                "project_ecs_secret_access_paths_onto_services",
                "project_ecs_s3_access_paths_onto_services",
                "project_ecs_s3_bucket_topology_destruction_paths_onto_services",
                "project_ecs_s3_object_deletion_paths_onto_services",
                "project_ecs_messaging_access_paths_onto_services",
                "project_ecs_sqs_message_removal_paths_onto_services",
                "project_ecs_messaging_topology_destruction_paths_onto_services",
                "project_ecs_dynamodb_access_paths_onto_services",
                "project_ecs_dynamodb_item_deletion_paths_onto_services",
                "project_ecs_dynamodb_table_topology_destruction_paths_onto_services",
                "project_ecs_cloudtrail_audit_telemetry_disruption_paths_onto_services",
                "model_ecs_s3_protected_data_convergence",
            ],
        )

    def test_decorator_uses_configured_index_builder(self) -> None:
        calls: list[str] = []

        class RecordingIndexBuilder(AwsResourceIndexBuilder):
            def build(self, resources: list[NormalizedResource]) -> AwsResourceIndex:
                calls.append(f"builder:{len(resources)}")
                return super().build(resources)

        class RecordingStage:
            name = "recording"

            def apply(self, resources: list[NormalizedResource], context) -> None:
                calls.append(f"stage:{bool(context.index.subnets.resources)}")

        subnet = _resource(
            address="aws_subnet.app",
            resource_type="aws_subnet",
            category=ResourceCategory.NETWORK,
            identifier="subnet-app",
        )

        AwsResourceDecorator(
            index_builder=RecordingIndexBuilder(),
            stages=[RecordingStage()],
        ).decorate([subnet])

        self.assertEqual(calls, ["builder:1", "stage:True"])

    def test_configured_stages_replace_default_pipeline(self) -> None:
        calls: list[str] = []

        class RecordingStage:
            name = "recording"

            def apply(self, resources: list[NormalizedResource], context) -> None:
                calls.append(f"recording:{bool(context.index.security_groups.resources)}")

        security_group = _resource(
            address="aws_security_group.app",
            resource_type="aws_security_group",
            category=ResourceCategory.NETWORK,
            identifier="sg-app",
        )
        rule_resource = _resource(
            address="aws_security_group_rule.app_ingress",
            resource_type="aws_security_group_rule",
            category=ResourceCategory.NETWORK,
            metadata={"security_group_id": "sg-app"},
            network_rules=[
                SecurityGroupRule(
                    direction="ingress",
                    protocol="tcp",
                    from_port=443,
                    to_port=443,
                    cidr_blocks=["0.0.0.0/0"],
                )
            ],
        )

        AwsResourceDecorator(stages=[RecordingStage()]).decorate([security_group, rule_resource])

        self.assertEqual(calls, ["recording:True"])
        self.assertEqual(security_group.network_rules, ())
        self.assertNotIn("standalone_rule_addresses", security_group.metadata)

    def test_standalone_security_group_rules_merge_into_target_groups(self) -> None:
        security_group = _resource(
            address="aws_security_group.app",
            resource_type="aws_security_group",
            category=ResourceCategory.NETWORK,
            identifier="sg-app",
        )
        rule_resource = _resource(
            address="aws_security_group_rule.app_ingress",
            resource_type="aws_security_group_rule",
            category=ResourceCategory.NETWORK,
            metadata={"security_group_id": "sg-app"},
            network_rules=[
                SecurityGroupRule(
                    direction="ingress",
                    protocol="tcp",
                    from_port=443,
                    to_port=443,
                    cidr_blocks=["0.0.0.0/0"],
                )
            ],
        )

        AwsResourceDecorator().decorate([security_group, rule_resource])

        self.assertEqual(len(security_group.network_rules), 1)
        self.assertTrue(security_group.network_rules[0].allows_internet())
        self.assertEqual(
            security_group.metadata["standalone_rule_addresses"],
            ["aws_security_group_rule.app_ingress"],
        )

    def test_role_policy_attachments_merge_customer_managed_policy_statements(self) -> None:
        role = _resource(
            address="aws_iam_role.app",
            resource_type="aws_iam_role",
            category=ResourceCategory.IAM,
            identifier="app-role",
            arn="arn:aws:iam::111122223333:role/app",
        )
        statement = IAMPolicyStatement(
            effect="Allow",
            actions=["secretsmanager:GetSecretValue"],
            resources=["arn:aws:secretsmanager:us-east-1:111122223333:secret:app"],
            principals=["arn:aws:iam::111122223333:role/app"],
            principal_entries=[IAMPrincipal(kind="AWS", value="arn:aws:iam::111122223333:role/app")],
        )
        policy = _resource(
            address="aws_iam_policy.read_secret",
            resource_type="aws_iam_policy",
            category=ResourceCategory.IAM,
            identifier="read-secret",
            arn="arn:aws:iam::111122223333:policy/read-secret",
            policy_statements=[statement],
        )
        attachment = _resource(
            address="aws_iam_role_policy_attachment.app_read_secret",
            resource_type="aws_iam_role_policy_attachment",
            category=ResourceCategory.IAM,
            metadata={
                "role": "app-role",
                "policy_arn": "arn:aws:iam::111122223333:policy/read-secret",
            },
        )

        AwsResourceDecorator().decorate([role, policy, attachment])

        self.assertEqual(len(role.policy_statements), 1)
        self.assertIsNot(role.policy_statements[0], statement)
        self.assertEqual(role.policy_statements[0].actions, ["secretsmanager:GetSecretValue"])
        self.assertEqual(role.policy_statements[0].principals, ["arn:aws:iam::111122223333:role/app"])
        self.assertEqual(role.policy_statements[0].principal_entries[0].kind, "AWS")
        self.assertEqual(
            role.metadata["attached_policy_arns"],
            ["arn:aws:iam::111122223333:policy/read-secret"],
        )
        self.assertEqual(
            role.metadata["attached_policy_addresses"],
            ["aws_iam_policy.read_secret"],
        )

    def test_role_policy_resolution_uses_the_source_provider_configuration(self) -> None:
        for reverse in (False, True):
            primary_role = _resource(
                address="aws_iam_role.primary",
                resource_type="aws_iam_role",
                category=ResourceCategory.IAM,
                identifier="application-role",
                arn="arn:aws:iam::111122223333:role/application",
                provider_config_key="aws.primary",
            )
            secondary_role = _resource(
                address="aws_iam_role.secondary",
                resource_type="aws_iam_role",
                category=ResourceCategory.IAM,
                identifier="application-role",
                arn="arn:aws:iam::444455556666:role/application",
                provider_config_key="aws.secondary",
            )
            inline_policy = _resource(
                address="aws_iam_role_policy.primary",
                resource_type="aws_iam_role_policy",
                category=ResourceCategory.IAM,
                metadata={"role": "application-role", "name": "read-secret"},
                policy_statements=[
                    IAMPolicyStatement(
                        effect="Allow",
                        actions=["secretsmanager:GetSecretValue"],
                        resources=["*"],
                    )
                ],
                provider_config_key="aws.primary",
            )
            resources = [secondary_role, inline_policy, primary_role]
            if reverse:
                resources.reverse()

            with self.subTest(reverse=reverse):
                AwsResourceDecorator(stages=(MergeRolePolicyResourcesStage(),)).decorate(resources)

                self.assertEqual(
                    aws_facts(primary_role).inline_policy_resource_addresses,
                    [inline_policy.address],
                )
                self.assertEqual(
                    primary_role.policy_statements[0].actions,
                    ["secretsmanager:GetSecretValue"],
                )
                self.assertEqual(
                    aws_facts(secondary_role).inline_policy_resource_addresses,
                    [],
                )
                self.assertEqual(secondary_role.policy_statements, ())

    def test_instance_profile_roles_attach_to_ec2_workloads(self) -> None:
        role = _resource(
            address="aws_iam_role.web",
            resource_type="aws_iam_role",
            category=ResourceCategory.IAM,
            identifier="web-role",
            arn="arn:aws:iam::111122223333:role/web",
        )
        instance_profile = _resource(
            address="aws_iam_instance_profile.web",
            resource_type="aws_iam_instance_profile",
            category=ResourceCategory.IAM,
            identifier="web-profile",
            metadata={"role_references": ["web-role"]},
        )
        instance = _resource(
            address="aws_instance.web",
            resource_type="aws_instance",
            category=ResourceCategory.COMPUTE,
            metadata={"iam_instance_profile": "web-profile"},
        )

        AwsResourceDecorator().decorate([role, instance_profile, instance])

        self.assertEqual(aws_facts(instance_profile).resolved_role_references, ["arn:aws:iam::111122223333:role/web"])
        self.assertEqual(instance_profile.metadata["resolved_role_addresses"], ["aws_iam_role.web"])
        self.assertEqual(instance.attached_role_arns, ("arn:aws:iam::111122223333:role/web",))
        self.assertEqual(
            instance.metadata["resolved_instance_profile_addresses"],
            ["aws_iam_instance_profile.web"],
        )

    def test_s3_resource_policies_and_access_blocks_update_bucket_exposure(self) -> None:
        bucket = _resource(
            address="aws_s3_bucket.logs",
            resource_type="aws_s3_bucket",
            category=ResourceCategory.DATA,
            identifier="logs",
            arn="arn:aws:s3:::logs",
            metadata={
                "bucket": "logs",
                "acl": "public-read",
                "policy_document": {},
                "public_access_reasons": ["bucket ACL `public-read` grants public access"],
                "public_exposure_reasons": ["bucket ACL `public-read` grants public access"],
            },
            public_access_configured=True,
            public_exposure=True,
        )
        policy_document = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::logs/*",
                }
            ]
        }
        bucket_policy = _resource(
            address="aws_s3_bucket_policy.logs_public_read",
            resource_type="aws_s3_bucket_policy",
            category=ResourceCategory.DATA,
            metadata={"bucket": "logs", "policy_document": policy_document},
            policy_statements=[
                IAMPolicyStatement(
                    effect="Allow",
                    actions=["s3:GetObject"],
                    resources=["arn:aws:s3:::logs/*"],
                    principals=["*"],
                )
            ],
        )
        access_block = _resource(
            address="aws_s3_bucket_public_access_block.logs",
            resource_type="aws_s3_bucket_public_access_block",
            category=ResourceCategory.DATA,
            metadata={
                "bucket": "logs",
                "block_public_acls": True,
                "block_public_policy": True,
                "ignore_public_acls": True,
                "restrict_public_buckets": True,
            },
        )

        AwsResourceDecorator().decorate([bucket, bucket_policy, access_block])

        self.assertEqual(aws_facts(bucket).resource_policy_source_addresses, ["aws_s3_bucket_policy.logs_public_read"])
        self.assertEqual(len(bucket.policy_statements), 1)
        self.assertEqual(aws_facts(bucket).policy_document, policy_document)
        self.assertFalse(bucket.public_exposure)
        self.assertEqual(bucket.public_exposure_reasons, [])
        self.assertEqual(
            aws_facts(bucket).public_access_block,
            {
                "block_public_acls": True,
                "block_public_policy": True,
                "ignore_public_acls": True,
                "restrict_public_buckets": True,
            },
        )

    def test_ambiguous_bucket_arn_does_not_apply_a_public_access_block(self) -> None:
        duplicate_arn = "arn:aws:s3:::logs"
        primary_bucket = _resource(
            address="aws_s3_bucket.primary",
            resource_type="aws_s3_bucket",
            category=ResourceCategory.DATA,
            identifier="primary-logs",
            arn=duplicate_arn,
            provider_config_key="aws.primary",
        )
        secondary_bucket = _resource(
            address="aws_s3_bucket.secondary",
            resource_type="aws_s3_bucket",
            category=ResourceCategory.DATA,
            identifier="secondary-logs",
            arn=duplicate_arn,
            provider_config_key="aws.secondary",
        )
        access_block = _resource(
            address="aws_s3_bucket_public_access_block.logs",
            resource_type="aws_s3_bucket_public_access_block",
            category=ResourceCategory.DATA,
            metadata={
                "bucket": duplicate_arn,
                "block_public_acls": True,
                "block_public_policy": True,
                "ignore_public_acls": True,
                "restrict_public_buckets": True,
            },
            provider_config_key="aws.primary",
        )

        AwsResourceDecorator(stages=(ApplyS3PublicAccessBlocksStage(),)).decorate(
            [primary_bucket, secondary_bucket, access_block]
        )

        self.assertIsNone(aws_facts(primary_bucket).public_access_block)
        self.assertIsNone(aws_facts(secondary_bucket).public_access_block)

    def test_ecs_services_inherit_task_definition_roles_and_runtime_metadata(self) -> None:
        task_role = _resource(
            address="aws_iam_role.task",
            resource_type="aws_iam_role",
            category=ResourceCategory.IAM,
            arn="arn:aws:iam::111122223333:role/task",
        )
        execution_role = _resource(
            address="aws_iam_role.execution",
            resource_type="aws_iam_role",
            category=ResourceCategory.IAM,
            arn="arn:aws:iam::111122223333:role/execution",
        )
        task_definition = _resource(
            address="aws_ecs_task_definition.app",
            resource_type="aws_ecs_task_definition",
            category=ResourceCategory.COMPUTE,
            identifier="app:12",
            arn="arn:aws:ecs:us-east-1:111122223333:task-definition/app:12",
            metadata={
                "family": "app",
                "revision": 12,
                "network_mode": "awsvpc",
                "requires_compatibilities": ["FARGATE"],
                "task_role_arn": "arn:aws:iam::111122223333:role/task",
                "execution_role_arn": "arn:aws:iam::111122223333:role/execution",
            },
        )
        service = _resource(
            address="aws_ecs_service.app",
            resource_type="aws_ecs_service",
            category=ResourceCategory.COMPUTE,
            metadata={"task_definition": "app:12"},
        )

        AwsResourceDecorator().decorate([task_role, execution_role, task_definition, service])

        self.assertEqual(aws_facts(service).network_mode, "awsvpc")
        self.assertEqual(aws_facts(service).requires_compatibilities, ["FARGATE"])
        self.assertEqual(aws_facts(service).task_role_arn, "arn:aws:iam::111122223333:role/task")
        self.assertEqual(aws_facts(service).execution_role_arn, "arn:aws:iam::111122223333:role/execution")
        self.assertEqual(service.attached_role_arns, ("arn:aws:iam::111122223333:role/task",))
        self.assertEqual(service.metadata["resolved_task_definition_addresses"], ["aws_ecs_task_definition.app"])
        self.assertEqual(service.metadata["resolved_task_role_addresses"], ["aws_iam_role.task"])
        self.assertEqual(service.metadata["resolved_execution_role_addresses"], ["aws_iam_role.execution"])

    def test_unresolved_resource_policy_targets_are_reported_in_coverage(self) -> None:
        bucket_policy = _resource(
            address="aws_s3_bucket_policy.logs",
            resource_type="aws_s3_bucket_policy",
            category=ResourceCategory.DATA,
            metadata={"bucket": "missing-logs"},
        )
        secret_policy = _resource(
            address="aws_secretsmanager_secret_policy.app",
            resource_type="aws_secretsmanager_secret_policy",
            category=ResourceCategory.DATA,
            metadata={"secret_arn": "arn:aws:secretsmanager:us-east-1:111122223333:secret:missing"},
        )
        lambda_permission = _resource(
            address="aws_lambda_permission.invoke",
            resource_type="aws_lambda_permission",
            category=ResourceCategory.COMPUTE,
            metadata={"function_name": "missing-worker"},
        )
        resources = [bucket_policy, secret_policy, lambda_permission]

        AwsResourceDecorator().decorate(resources)
        coverage = build_analysis_coverage(ResourceInventory(provider="aws", resources=resources))
        unresolved_by_resource = {
            reference.resource: reference.references for reference in coverage.references.unresolved_references
        }

        self.assertEqual(bucket_policy.metadata["unresolved_bucket_references"], ["missing-logs"])
        self.assertEqual(
            secret_policy.metadata["unresolved_secret_arns"],
            ["arn:aws:secretsmanager:us-east-1:111122223333:secret:missing"],
        )
        self.assertEqual(lambda_permission.metadata["unresolved_function_references"], ["missing-worker"])
        self.assertEqual(coverage.references.unresolved_reference_count, 3)
        self.assertEqual(
            unresolved_by_resource,
            {
                "aws_s3_bucket_policy.logs": {
                    "unresolved_bucket_references": ["missing-logs"],
                },
                "aws_secretsmanager_secret_policy.app": {
                    "unresolved_secret_arns": ["arn:aws:secretsmanager:us-east-1:111122223333:secret:missing"],
                },
                "aws_lambda_permission.invoke": {
                    "unresolved_function_references": ["missing-worker"],
                },
            },
        )


if __name__ == "__main__":
    unittest.main()
