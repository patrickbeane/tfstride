from __future__ import annotations

from tfstride.analysis.finding_helpers import collect_evidence, evidence_item
from tfstride.analysis.resource_concepts import (
    DATABASE_RESOURCE_TYPES,
    IDENTITY_ROLE_RESOURCE_TYPES,
    OBJECT_STORAGE_PUBLIC_ACCESS_CONTROL_RESOURCE_TYPES,
    OBJECT_STORAGE_RESOURCE_TYPES,
)
from tfstride.models import NormalizedResource, Observation, ResourceInventory
from tfstride.providers.aws.policy_conditions import (
    describe_trust_narrowing_for_principal,
    trust_statement_has_effective_narrowing_for_principal,
    trust_statement_principal_assessments,
)
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.coercion import STATE_ENABLED
from tfstride.resource_helpers import policy_allows_public_access


def observe_aws_controls(inventory: ResourceInventory) -> list[Observation]:
    observations: list[Observation] = []
    observations.extend(_observe_bucket_public_access_blocks(inventory))
    observations.extend(_observe_narrowed_trust(inventory))
    observations.extend(_observe_private_encrypted_databases(inventory))
    observations.extend(_observe_api_gateway_authorization_uncertainties(inventory))
    observations.sort(
        key=lambda observation: ((observation.category or ""), observation.title, observation.observation_id)
    )
    return observations


def _observe_bucket_public_access_blocks(inventory: ResourceInventory) -> list[Observation]:
    observations: list[Observation] = []
    access_block_index: dict[str, NormalizedResource] = {}
    for access_block in inventory.by_type(*OBJECT_STORAGE_PUBLIC_ACCESS_CONTROL_RESOURCE_TYPES):
        bucket_name = aws_facts(access_block).bucket_name
        if bucket_name:
            access_block_index[bucket_name] = access_block
    for bucket in inventory.by_type(*OBJECT_STORAGE_RESOURCE_TYPES):
        bucket_facts = aws_facts(bucket)
        access_block = bucket_facts.public_access_block
        if not access_block or bucket.public_exposure:
            continue
        mitigation_signals: list[str] = []
        acl = bucket_facts.bucket_acl
        if acl in {"public-read", "public-read-write", "website"}:
            mitigation_signals.append(f"bucket ACL `{acl}` would otherwise grant public access")
        if policy_allows_public_access(bucket_facts.policy_document):
            mitigation_signals.append("bucket policy would otherwise allow anonymous access")
        if not mitigation_signals:
            continue
        affected_resources = [bucket.address]
        access_block_resource = access_block_index.get(bucket_facts.bucket_name)
        if access_block_resource is not None:
            affected_resources.append(access_block_resource.address)
        observations.append(
            Observation(
                title="S3 public access is reduced by a public access block",
                observation_id="aws-s3-public-access-block-observed",
                category="data-protection",
                affected_resources=affected_resources,
                rationale=(
                    f"{bucket.display_name} includes public-looking ACL or policy signals, but an attached "
                    "public access block materially reduces that exposure."
                ),
                evidence=collect_evidence(
                    evidence_item("mitigated_public_access", mitigation_signals),
                    evidence_item(
                        "control_posture",
                        [f"{key} is {str(value).lower()}" for key, value in sorted(access_block.items()) if value],
                    ),
                ),
            )
        )
    return observations


def _observe_narrowed_trust(inventory: ResourceInventory) -> list[Observation]:
    observations: list[Observation] = []
    primary_account_id = inventory.primary_account_id
    seen: set[tuple[str, str]] = set()
    for role in inventory.by_type(*IDENTITY_ROLE_RESOURCE_TYPES):
        for trust_statement in aws_facts(role).trust_statements:
            for assessment in trust_statement_principal_assessments(trust_statement, primary_account_id):
                if not trust_statement_has_effective_narrowing_for_principal(trust_statement, assessment):
                    continue
                principal = assessment.principal
                if assessment.is_service:
                    continue
                if assessment.scope_description is None:
                    continue
                observation_key = (role.address, principal)
                if observation_key in seen:
                    continue
                seen.add(observation_key)
                observations.append(
                    Observation(
                        title="Cross-account or broad role trust is narrowed by assume-role conditions",
                        observation_id="aws-role-trust-narrowed",
                        category="iam",
                        affected_resources=[role.address],
                        rationale=(
                            f"{role.display_name} trusts {principal}, but supported assume-role conditions narrow "
                            "when that trust can be exercised."
                        ),
                        evidence=collect_evidence(
                            evidence_item("trust_principals", [principal]),
                            evidence_item("trust_scope", [assessment.scope_description]),
                            evidence_item(
                                "trust_narrowing",
                                describe_trust_narrowing_for_principal(trust_statement, assessment),
                            ),
                        ),
                    )
                )
    return observations


def _observe_private_encrypted_databases(inventory: ResourceInventory) -> list[Observation]:
    if inventory.provider != "aws":
        return []

    observations: list[Observation] = []
    for database in inventory.by_type(*DATABASE_RESOURCE_TYPES):
        if not database.storage_encrypted:
            continue
        if database.publicly_accessible:
            continue
        if database.direct_internet_reachable:
            continue
        if database.internet_ingress_capable:
            continue
        posture_signals = [
            "publicly_accessible is false",
            "storage_encrypted is true",
            "no attached security group allows internet ingress",
        ]
        engine = aws_facts(database).engine
        if engine:
            posture_signals.append(f"engine is {engine}")
        observations.append(
            Observation(
                title="RDS instance is private and storage encrypted",
                observation_id="aws-rds-private-encrypted",
                category="data-protection",
                affected_resources=[database.address],
                rationale=(
                    f"{database.display_name} is kept off direct internet paths and has storage encryption enabled, "
                    "which reduces straightforward data exposure risk."
                ),
                evidence=collect_evidence(
                    evidence_item("database_posture", posture_signals),
                ),
            )
        )
    return observations


_API_GATEWAY_PUBLIC_TYPES = (
    "aws_api_gateway_rest_api",
    "aws_apigatewayv2_api",
)
_AUTHORIZATION_UNKNOWN_SUFFIXES = (
    "authorization is unknown after planning",
    "authorization_type is unknown after planning",
)


def _observe_api_gateway_authorization_uncertainties(inventory: ResourceInventory) -> list[Observation]:
    if inventory.provider != "aws":
        return []

    observations: list[Observation] = []
    for api in inventory.by_type(*_API_GATEWAY_PUBLIC_TYPES):
        facts = aws_facts(api)
        if facts.api_gateway_public_endpoint_state != STATE_ENABLED:
            continue
        uncertainties = [
            uncertainty
            for uncertainty in facts.api_gateway_posture_uncertainties
            if uncertainty.endswith(_AUTHORIZATION_UNKNOWN_SUFFIXES)
        ]
        if not uncertainties:
            continue
        affected_resources = [api.address, *_uncertainty_source_addresses(uncertainties)]
        observations.append(
            Observation(
                title="Public API Gateway authorization contains unresolved plan values",
                observation_id="aws-api-gateway-public-authorization-unknown",
                category="analysis-uncertainty",
                affected_resources=list(dict.fromkeys(affected_resources)),
                rationale=(
                    f"{api.display_name} has public methods or routes whose API Gateway authorization value is "
                    "computed. tfSTRIDE does not infer unauthenticated access from unresolved plan values."
                ),
                evidence=collect_evidence(
                    evidence_item("unknown_authorization_posture", uncertainties),
                    evidence_item(
                        "analysis_effect",
                        ["unauthenticated access findings are emitted only for explicit authorization type NONE"],
                    ),
                ),
            )
        )
    return observations


def _uncertainty_source_addresses(uncertainties: list[str]) -> list[str]:
    addresses: list[str] = []
    for uncertainty in uncertainties:
        address, separator, _ = uncertainty.partition(": ")
        if separator and address:
            addresses.append(address)
    return list(dict.fromkeys(addresses))
