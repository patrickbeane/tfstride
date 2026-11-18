from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, replace

from tfstride.models import NormalizedResource
from tfstride.providers.aws.kms_evidence import AwsKmsOperationAuthorization
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.resource_decoration.iam import current_iam_role_policies
from tfstride.providers.aws.resource_decoration.kms_operation_authorization import (
    current_kms_grants_by_key,
    current_kms_operation_authorizations,
)
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import AwsDecorationContext


@dataclass(slots=True)
class AwsKmsAuthorizationContext:
    """Current policy sources and memoized role/key evaluations for one preparation.

    This context owns detached effective policies and reuses the caller's resource
    index. Resource changes require fresh preparation; no cache lives on the engine.
    """

    decoration_context: AwsDecorationContext
    roles: Mapping[str, NormalizedResource]
    keys: Mapping[str, NormalizedResource]
    grants: Mapping[str, tuple[NormalizedResource, ...]]
    _authorizations: dict[tuple[str, str], dict[str, AwsKmsOperationAuthorization]] = field(
        default_factory=dict, init=False, repr=False
    )

    def authorization(self, key_address: str, role_address: str, operation: str) -> AwsKmsOperationAuthorization | None:
        key, role = self.keys.get(key_address), self.roles.get(role_address)
        if key is None or role is None:
            return None
        pair = (key_address, role_address)
        if pair not in self._authorizations:
            records, _ = current_kms_operation_authorizations(
                key, (role,), self.decoration_context, grants=self.grants.get(key_address, ())
            )
            self._authorizations[pair] = {record["operation"]: record for record in records}
        return self._authorizations[pair].get(operation)


def prepare_kms_authorization_context(context: AwsDecorationContext) -> AwsKmsAuthorizationContext:
    keys = _current_key_policies(context)
    return AwsKmsAuthorizationContext(
        decoration_context=context,
        roles=current_iam_role_policies(context) if keys else {},
        keys=keys,
        grants=current_kms_grants_by_key(context) if keys else {},
    )


def _current_key_policies(context: AwsDecorationContext) -> dict[str, NormalizedResource]:
    policies: dict[str, list[NormalizedResource]] = {}
    for source in context.index.resources_by_address.values():
        if source.resource_type != "aws_kms_key_policy" or source.provider != "aws":
            continue
        resolution = context.index.kms_keys.resolve(aws_facts(source).kms_key_policy_key_reference, source=source)
        for key in resolution.candidates:
            policies.setdefault(key.address, []).append(source)

    keys: dict[str, NormalizedResource] = {}
    for key in context.index.kms_keys.resources:
        facts = aws_facts(key)
        sources = policies.get(key.address, [])
        inline = next((record for record in facts.kms_key_policies if record["source"] == key.address), None)
        old_external_sources = [address for address in facts.kms_policy_source_addresses if address != key.address]
        if not sources and not old_external_sources:
            keys[key.address] = key
            continue

        current = replace(key, policy_statements=())
        current_facts = aws_facts(current)
        addresses = ([key.address] if inline is not None else []) + [source.address for source in sources]
        current_facts.set(AwsResourceMetadata.KMS_POLICY_SOURCE_ADDRESSES, addresses)
        if inline is None and len(sources) == 1:
            source = sources[0]
            resolved = context.index.kms_keys.get(aws_facts(source).kms_key_policy_key_reference, source=source)
            complete = resolved is key and aws_facts(source).kms_policy_completeness_state == "complete"
            current.policy_statements = source.policy_statements
            uncertainties = list(aws_facts(source).kms_policy_posture_uncertainties)
        elif inline is not None and not sources:
            # A conflicting standalone source may have been removed. The inline
            # statements remain on the key; decoration never merged a conflict.
            current.policy_statements = key.policy_statements
            complete = inline["completeness_state"] == "complete"
            uncertainties = list(inline["posture_uncertainties"])
        else:
            complete = False
            uncertainties = [f"{key.address}: effective KMS key policy source is ambiguous or unresolved"]
        current_facts.set(AwsResourceMetadata.KMS_POLICY_COMPLETENESS_STATE, "complete" if complete else "unknown")
        current_facts.set(AwsResourceMetadata.KMS_POLICY_POSTURE_UNCERTAINTIES, uncertainties)
        keys[key.address] = current
    return keys
