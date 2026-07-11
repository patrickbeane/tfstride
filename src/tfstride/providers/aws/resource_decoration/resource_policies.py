from __future__ import annotations

from typing import Any

from tfstride.models import IAMPolicyStatement, NormalizedResource
from tfstride.providers.aws.coercion import as_list
from tfstride.providers.aws.resource_decoration.policies import clone_policy_statements
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import AwsDecorationContext
from tfstride.providers.aws.resource_mutations import aws_mutations
from tfstride.providers.aws.resource_utils import bucket_public_exposure_reasons
from tfstride.resource_helpers import policy_allows_public_access


class MergeResourcePolicyResourcesStage:
    name = "merge_resource_policy_resources"

    def apply(self, resources: list[NormalizedResource], context: AwsDecorationContext) -> None:
        # Resource-policy resources should flow into the target resource so later analysis can
        # reason over one consolidated policy surface.
        for bucket_policy_resource in resources:
            if bucket_policy_resource.resource_type != "aws_s3_bucket_policy":
                continue
            bucket_name = aws_facts(bucket_policy_resource).bucket_name
            bucket = context.index.buckets.get(bucket_name)
            if bucket is None:
                aws_facts(bucket_policy_resource).add_unresolved_bucket_reference(bucket_name)
                continue
            _merge_resource_policy(
                bucket,
                bucket_policy_resource.policy_statements,
                aws_facts(bucket_policy_resource).policy_document,
                bucket_policy_resource.address,
            )

        for secret_policy_resource in resources:
            if secret_policy_resource.resource_type != "aws_secretsmanager_secret_policy":
                continue
            secret_arn = aws_facts(secret_policy_resource).secret_arn
            secret = context.index.secrets.get(secret_arn)
            if secret is None:
                aws_facts(secret_policy_resource).add_unresolved_secret_arn(secret_arn)
                continue
            _merge_resource_policy(
                secret,
                secret_policy_resource.policy_statements,
                aws_facts(secret_policy_resource).policy_document,
                secret_policy_resource.address,
            )

        for lambda_permission_resource in resources:
            if lambda_permission_resource.resource_type != "aws_lambda_permission":
                continue
            function_name = aws_facts(lambda_permission_resource).function_name
            target_function = context.index.lambda_functions.get(function_name)
            if target_function is None:
                aws_facts(lambda_permission_resource).add_unresolved_function_reference(function_name)
                continue
            _merge_resource_policy(
                target_function,
                lambda_permission_resource.policy_statements,
                {},
                lambda_permission_resource.address,
            )


class ApplyS3PublicAccessBlocksStage:
    name = "apply_s3_public_access_blocks"

    def apply(self, resources: list[NormalizedResource], context: AwsDecorationContext) -> None:
        # Public access blocks can neutralize otherwise-public bucket ACLs or policies, so
        # recompute effective public exposure after the control is applied.
        for access_block_resource in resources:
            if access_block_resource.resource_type != "aws_s3_bucket_public_access_block":
                continue
            bucket_name = aws_facts(access_block_resource).bucket_name
            bucket = context.index.buckets.get(bucket_name)
            if bucket is None:
                continue
            public_access_block = {
                "block_public_acls": aws_facts(access_block_resource).block_public_acls,
                "block_public_policy": aws_facts(access_block_resource).block_public_policy,
                "ignore_public_acls": aws_facts(access_block_resource).ignore_public_acls,
                "restrict_public_buckets": aws_facts(access_block_resource).restrict_public_buckets,
            }
            aws_facts(bucket).set_public_access_block(public_access_block)
            bucket_acl = aws_facts(bucket).bucket_acl
            bucket_policy_document = aws_facts(bucket).policy_document
            public_via_acl = bucket_acl in {"public-read", "public-read-write", "website"}
            public_via_policy = policy_allows_public_access(bucket_policy_document)
            bucket_mutations = aws_mutations(bucket)
            bucket_mutations.set_public_access_reasons(
                bucket_public_exposure_reasons(
                    bucket_acl,
                    public_policy=public_via_policy,
                )
            )
            bucket_mutations.set_public_exposure(
                (
                    public_via_acl
                    and not (public_access_block["block_public_acls"] or public_access_block["ignore_public_acls"])
                )
                or (
                    public_via_policy
                    and not (
                        public_access_block["block_public_policy"] or public_access_block["restrict_public_buckets"]
                    )
                )
            )
            bucket_mutations.set_public_exposure_reasons(
                bucket_public_exposure_reasons(
                    bucket_acl,
                    public_policy=public_via_policy,
                    public_access_block=public_access_block,
                )
            )


class ApplyS3PostureResourcesStage:
    name = "apply_s3_posture_resources"

    def apply(self, resources: list[NormalizedResource], context: AwsDecorationContext) -> None:
        for posture_resource in resources:
            if posture_resource.resource_type == "aws_s3_bucket_versioning":
                self._apply_versioning_resource(posture_resource, context)
            elif posture_resource.resource_type == "aws_s3_bucket_server_side_encryption_configuration":
                self._apply_encryption_resource(posture_resource, context)
            elif posture_resource.resource_type == "aws_s3_bucket_object_lock_configuration":
                self._apply_object_lock_resource(posture_resource, context)
            elif posture_resource.resource_type == "aws_s3_bucket_lifecycle_configuration":
                self._apply_lifecycle_resource(posture_resource, context)

    def _apply_versioning_resource(
        self,
        posture_resource: NormalizedResource,
        context: AwsDecorationContext,
    ) -> None:
        posture_facts = aws_facts(posture_resource)
        bucket = context.index.buckets.get(posture_facts.bucket_name)
        if bucket is None:
            posture_facts.add_unresolved_bucket_reference(posture_facts.bucket_name)
            return
        aws_facts(bucket).set_s3_versioning_posture(
            status=posture_facts.s3_versioning_status,
            configuration=posture_facts.s3_versioning_configuration,
            source_address=posture_resource.address,
        )
        aws_facts(bucket).extend_s3_posture_uncertainties(
            _source_uncertainties(posture_resource, posture_facts.s3_posture_uncertainties)
        )

    def _apply_encryption_resource(
        self,
        posture_resource: NormalizedResource,
        context: AwsDecorationContext,
    ) -> None:
        posture_facts = aws_facts(posture_resource)
        bucket = context.index.buckets.get(posture_facts.bucket_name)
        if bucket is None:
            posture_facts.add_unresolved_bucket_reference(posture_facts.bucket_name)
            return
        aws_facts(bucket).set_s3_encryption_posture(
            algorithm=posture_facts.s3_encryption_algorithm,
            kms_master_key_id=posture_facts.s3_kms_master_key_id,
            bucket_key_enabled_state=posture_facts.s3_bucket_key_enabled_state,
            configuration=posture_facts.s3_server_side_encryption_configuration,
            source_address=posture_resource.address,
        )
        aws_facts(bucket).extend_s3_posture_uncertainties(
            _source_uncertainties(posture_resource, posture_facts.s3_posture_uncertainties)
        )

    def _apply_object_lock_resource(
        self,
        posture_resource: NormalizedResource,
        context: AwsDecorationContext,
    ) -> None:
        posture_facts = aws_facts(posture_resource)
        bucket = context.index.buckets.get(posture_facts.bucket_name)
        if bucket is None:
            posture_facts.add_unresolved_bucket_reference(posture_facts.bucket_name)
            return
        aws_facts(bucket).set_s3_object_lock_posture(
            enabled_state=posture_facts.s3_object_lock_enabled_state,
            default_retention_mode=posture_facts.s3_object_lock_default_retention_mode,
            default_retention_days=posture_facts.s3_object_lock_default_retention_days,
            default_retention_years=posture_facts.s3_object_lock_default_retention_years,
            configuration=posture_facts.s3_object_lock_configuration,
            source_address=posture_resource.address,
        )
        aws_facts(bucket).extend_s3_posture_uncertainties(
            _source_uncertainties(posture_resource, posture_facts.s3_posture_uncertainties)
        )

    def _apply_lifecycle_resource(
        self,
        posture_resource: NormalizedResource,
        context: AwsDecorationContext,
    ) -> None:
        posture_facts = aws_facts(posture_resource)
        bucket = context.index.buckets.get(posture_facts.bucket_name)
        if bucket is None:
            posture_facts.add_unresolved_bucket_reference(posture_facts.bucket_name)
            return
        aws_facts(bucket).set_s3_lifecycle_posture(
            rules=posture_facts.s3_lifecycle_rules,
            rule_count=posture_facts.s3_lifecycle_rule_count,
            source_address=posture_resource.address,
        )
        aws_facts(bucket).extend_s3_posture_uncertainties(
            _source_uncertainties(posture_resource, posture_facts.s3_posture_uncertainties)
        )


class ApplySecretsManagerPostureResourcesStage:
    name = "apply_secrets_manager_posture_resources"

    def apply(self, resources: list[NormalizedResource], context: AwsDecorationContext) -> None:
        for posture_resource in resources:
            if posture_resource.resource_type != "aws_secretsmanager_secret_rotation":
                continue
            posture_facts = aws_facts(posture_resource)
            secret_id = posture_facts.secrets_manager_rotation_secret_id
            secret = context.index.secrets.get(secret_id)
            if secret is None:
                posture_facts.add_unresolved_secret_reference(secret_id)
                continue
            aws_facts(secret).set_secrets_manager_rotation_posture(
                secret_id=secret_id,
                source_address=posture_resource.address,
                rotation_lambda_arn=posture_facts.secrets_manager_rotation_lambda_arn,
                automatically_after_days=posture_facts.secrets_manager_rotation_automatically_after_days,
                duration=posture_facts.secrets_manager_rotation_duration,
                schedule_expression=posture_facts.secrets_manager_rotation_schedule_expression,
                rotation_rules=posture_facts.secrets_manager_rotation_rules,
            )
            aws_facts(secret).extend_secrets_manager_posture_uncertainties(
                _source_uncertainties(posture_resource, posture_facts.secrets_manager_posture_uncertainties)
            )


def _source_uncertainties(resource: NormalizedResource, uncertainties: list[str]) -> list[str]:
    return [f"{resource.address}: {uncertainty}" for uncertainty in uncertainties]


def _merge_resource_policy(
    resource: NormalizedResource,
    policy_statements: list[IAMPolicyStatement],
    policy_document: dict[str, Any],
    source_address: str,
) -> None:
    aws_mutations(resource).merge_policy_statements(clone_policy_statements(policy_statements))
    resource_policy_source_addresses = aws_facts(resource).resource_policy_source_addresses
    if source_address not in resource_policy_source_addresses:
        aws_facts(resource).add_resource_policy_source_address(source_address)
    merged_document = _merge_policy_documents(
        aws_facts(resource).policy_document,
        policy_document,
    )
    if merged_document:
        aws_facts(resource).set_policy_document(merged_document)


def _merge_policy_documents(base_document: Any, extra_document: Any) -> dict[str, Any]:
    base = base_document if isinstance(base_document, dict) else {}
    extra = extra_document if isinstance(extra_document, dict) else {}
    base_statements = as_list(base.get("Statement"))
    extra_statements = as_list(extra.get("Statement"))
    merged_statements = [
        statement for statement in [*base_statements, *extra_statements] if isinstance(statement, dict)
    ]
    if not merged_statements:
        return base or extra
    merged_document = dict(base) if base else dict(extra)
    merged_document["Statement"] = merged_statements
    return merged_document
