from __future__ import annotations

from tfstride.models import NormalizedResource
from tfstride.providers.aws.kms_evidence import AwsKmsAliasRelationship, AwsKmsGrantRelationship
from tfstride.providers.aws.kms_normalizers import serialize_kms_policy_statements
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.resource_decoration.policies import clone_policy_statements
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import AwsDecorationContext
from tfstride.providers.aws.resource_mutations import aws_mutations


class DecorateKmsRelationshipsStage:
    name = "decorate_kms_relationships"

    def apply(self, resources: list[NormalizedResource], context: AwsDecorationContext) -> None:
        self._resolve_aliases(resources, context)
        self._resolve_grants(resources, context)
        self._resolve_key_policies(resources, context)

    def _resolve_aliases(self, resources: list[NormalizedResource], context: AwsDecorationContext) -> None:
        for alias in resources:
            if alias.resource_type != "aws_kms_alias":
                continue
            alias_facts = aws_facts(alias)
            target_reference = alias_facts.kms_alias_target_key_reference
            key = context.index.kms_keys.get(target_reference, source=alias) if target_reference else None
            if key is None or target_reference is None:
                alias_facts.add_unresolved_kms_key_reference(target_reference)
                continue

            alias_facts.set(AwsResourceMetadata.KMS_ALIAS_RESOLVED_KEY_ADDRESS, key.address)
            alias_record: AwsKmsAliasRelationship = {
                "source": alias.address,
                "alias_name": alias_facts.kms_alias_name,
                "alias_name_prefix": alias_facts.kms_alias_name_prefix,
                "alias_arn": alias_facts.kms_alias_arn,
                "target_key_id": alias_facts.kms_alias_target_key_id,
                "target_key_arn": alias_facts.kms_alias_target_key_arn,
                "target_key_reference": target_reference,
                "resolved_key_address": key.address,
            }
            aws_facts(key).add_kms_alias(alias_record)

    def _resolve_grants(self, resources: list[NormalizedResource], context: AwsDecorationContext) -> None:
        for grant in resources:
            if grant.resource_type != "aws_kms_grant":
                continue
            grant_facts = aws_facts(grant)
            key_reference = grant_facts.kms_grant_key_reference
            key = context.index.kms_keys.get(key_reference, source=grant) if key_reference else None
            if key is None or key_reference is None:
                grant_facts.add_unresolved_kms_key_reference(key_reference)
                continue

            grant_facts.set(AwsResourceMetadata.KMS_GRANT_RESOLVED_KEY_ADDRESS, key.address)
            grant_record: AwsKmsGrantRelationship = {
                "source": grant.address,
                "grant_id": grant_facts.kms_grant_id,
                "name": grant_facts.kms_grant_name,
                "key_reference": key_reference,
                "grantee_principal": grant_facts.kms_grant_grantee_principal,
                "operations": grant_facts.kms_grant_operations,
                "retiring_principal": grant_facts.kms_grant_retiring_principal,
                "constraints": grant_facts.kms_grant_constraints,
                "retire_on_delete_state": grant_facts.kms_grant_retire_on_delete_state,
                "resolved_key_address": key.address,
            }
            aws_facts(key).add_kms_grant(grant_record)

    def _resolve_key_policies(self, resources: list[NormalizedResource], context: AwsDecorationContext) -> None:
        policies_by_key: dict[str, list[NormalizedResource]] = {}
        keys_by_address = {
            resource.address: resource for resource in resources if resource.resource_type == "aws_kms_key"
        }

        for policy in resources:
            if policy.resource_type != "aws_kms_key_policy":
                continue
            policy_facts = aws_facts(policy)
            key_reference = policy_facts.kms_key_policy_key_reference
            key = context.index.kms_keys.get(key_reference, source=policy) if key_reference else None
            if key is None:
                policy_facts.add_unresolved_kms_key_reference(key_reference)
                continue

            policy_facts.set(AwsResourceMetadata.KMS_KEY_POLICY_RESOLVED_KEY_ADDRESS, key.address)
            policies_by_key.setdefault(key.address, []).append(policy)
            key_facts = aws_facts(key)
            key_facts.add_kms_policy_source_address(policy.address)
            key_facts.add_kms_key_policy(
                {
                    "source": policy.address,
                    "source_type": "standalone",
                    "configuration_state": policy_facts.kms_policy_configuration_state,
                    "completeness_state": policy_facts.kms_policy_completeness_state,
                    "bypass_lockout_safety_check_state": (
                        policy_facts.kms_key_policy_bypass_lockout_safety_check_state
                    ),
                    "policy_statements": serialize_kms_policy_statements(tuple(policy.policy_statements)),
                    "posture_uncertainties": list(policy_facts.kms_key_policy_posture_uncertainties),
                    "resolved_key_address": key.address,
                }
            )

        for key_address, policies in policies_by_key.items():
            key = keys_by_address.get(key_address)
            if key is None:
                continue
            key_facts = aws_facts(key)
            has_inline_source = key.address in key_facts.kms_policy_source_addresses
            complete_standalone_policies = [
                policy for policy in policies if aws_facts(policy).kms_policy_completeness_state == "complete"
            ]
            if has_inline_source or len(policies) != 1 or len(complete_standalone_policies) != 1:
                key_facts.set(AwsResourceMetadata.KMS_POLICY_CONFIGURATION_STATE, "configured")
                key_facts.set(AwsResourceMetadata.KMS_POLICY_COMPLETENESS_STATE, "unknown")
                key_facts.extend_kms_policy_posture_uncertainties(
                    [f"{key.address}: effective KMS key policy source is ambiguous or unresolved"]
                )
                continue

            policy = complete_standalone_policies[0]
            aws_mutations(key).merge_policy_statements(clone_policy_statements(list(policy.policy_statements)))
            key_facts.add_resource_policy_source_address(policy.address)
            key_facts.set(AwsResourceMetadata.KMS_POLICY_CONFIGURATION_STATE, "configured")
            key_facts.set(AwsResourceMetadata.KMS_POLICY_COMPLETENESS_STATE, "complete")
