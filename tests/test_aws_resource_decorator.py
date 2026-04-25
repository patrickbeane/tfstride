from __future__ import annotations

import unittest

from tfstride.models import IAMPolicyStatement, NormalizedResource, ResourceCategory, SecurityGroupRule
from tfstride.providers.aws.resource_decorator import AwsResourceDecorator


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
    )


class AwsResourceDecoratorTests(unittest.TestCase):
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
        self.assertEqual(
            role.metadata["attached_policy_arns"],
            ["arn:aws:iam::111122223333:policy/read-secret"],
        )
        self.assertEqual(
            role.metadata["attached_policy_addresses"],
            ["aws_iam_policy.read_secret"],
        )

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

        self.assertEqual(instance_profile.resolved_role_references, ["arn:aws:iam::111122223333:role/web"])
        self.assertEqual(instance_profile.metadata["resolved_role_addresses"], ["aws_iam_role.web"])
        self.assertEqual(instance.attached_role_arns, ["arn:aws:iam::111122223333:role/web"])
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

        self.assertEqual(bucket.resource_policy_source_addresses, ["aws_s3_bucket_policy.logs_public_read"])
        self.assertEqual(len(bucket.policy_statements), 1)
        self.assertEqual(bucket.policy_document, policy_document)
        self.assertFalse(bucket.public_exposure)
        self.assertEqual(bucket.public_exposure_reasons, [])
        self.assertEqual(
            bucket.public_access_block,
            {
                "block_public_acls": True,
                "block_public_policy": True,
                "ignore_public_acls": True,
                "restrict_public_buckets": True,
            },
        )

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

        self.assertEqual(service.network_mode, "awsvpc")
        self.assertEqual(service.requires_compatibilities, ["FARGATE"])
        self.assertEqual(service.task_role_arn, "arn:aws:iam::111122223333:role/task")
        self.assertEqual(service.execution_role_arn, "arn:aws:iam::111122223333:role/execution")
        self.assertEqual(service.attached_role_arns, ["arn:aws:iam::111122223333:role/task"])
        self.assertEqual(service.metadata["resolved_task_definition_addresses"], ["aws_ecs_task_definition.app"])
        self.assertEqual(service.metadata["resolved_task_role_addresses"], ["aws_iam_role.task"])
        self.assertEqual(service.metadata["resolved_execution_role_addresses"], ["aws_iam_role.execution"])


if __name__ == "__main__":
    unittest.main()