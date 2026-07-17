from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from tfstride.models import NormalizedResource
from tfstride.providers.coercion import dedupe
from tfstride.providers.gcp.resource_decoration.iam import iam_bindings
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_index import GcpDecorationContext
from tfstride.providers.gcp.resource_utils import binding_members, gcp_reference_key

_FEDERATED_SERVICE_ACCOUNT_ROLES = frozenset(
    {
        "roles/iam.serviceAccountTokenCreator",
        "roles/iam.workloadIdentityUser",
    }
)
_PRINCIPAL_PREFIX = "principal://iam.googleapis.com/"
_PRINCIPAL_SET_PREFIX = "principalSet://iam.googleapis.com/"


@dataclass(frozen=True, slots=True)
class _FederatedPrincipal:
    member: str
    member_kind: str
    pool_resource_name: str
    selector: str
    value: str
    required_mapping: str | None


class ModelWorkloadIdentityFederationTrustPathsStage:
    name = "model_workload_identity_federation_trust_paths"

    def apply(self, resources: list[NormalizedResource], context: GcpDecorationContext) -> None:
        pools_by_name = _pools_by_resource_name(context)
        providers_by_pool = _providers_by_pool_resource_name(context)
        paths_by_service_account: dict[str, list[dict[str, Any]]] = defaultdict(list)
        uncertainties_by_service_account: dict[str, list[str]] = defaultdict(list)

        for iam_resource in context.index.service_account_iam_resources:
            service_account = _service_account_target(iam_resource, context)
            if service_account is None:
                continue
            for binding in iam_bindings(iam_resource):
                role = str(binding.get("role") or "").strip()
                if role not in _FEDERATED_SERVICE_ACCOUNT_ROLES:
                    continue
                for member in binding_members(binding):
                    principal, error = _parse_federated_principal(member)
                    if principal is None:
                        if error is not None:
                            uncertainties_by_service_account[service_account.address].append(
                                f"{iam_resource.address}: {error}"
                            )
                        continue

                    pool = pools_by_name.get(principal.pool_resource_name)
                    if pool is None:
                        uncertainties_by_service_account[service_account.address].append(
                            f"{iam_resource.address}: principal member {member} does not resolve to a modeled "
                            "workload identity pool by canonical resource name"
                        )
                        continue

                    providers = providers_by_pool.get(principal.pool_resource_name, ())
                    if not providers:
                        uncertainties_by_service_account[service_account.address].append(
                            f"{iam_resource.address}: pool {principal.pool_resource_name} has no provider with a "
                            "resolved canonical resource name"
                        )
                        continue

                    matched_provider = False
                    for provider, provider_resource_name in providers:
                        if not _provider_supports_principal(provider, principal):
                            continue
                        matched_provider = True
                        paths_by_service_account[service_account.address].append(
                            _trust_path_record(
                                service_account,
                                iam_resource,
                                binding,
                                role,
                                principal,
                                pool,
                                provider,
                                provider_resource_name,
                            )
                        )
                    if not matched_provider:
                        mapping = principal.required_mapping or "pool wildcard"
                        uncertainties_by_service_account[service_account.address].append(
                            f"{iam_resource.address}: no resolved provider in pool "
                            f"{principal.pool_resource_name} supports principal mapping {mapping}"
                        )

        for service_account in context.index.service_accounts:
            paths = _dedupe_paths(paths_by_service_account.get(service_account.address, []))
            uncertainties = dedupe(uncertainties_by_service_account.get(service_account.address, []))
            if not paths and not uncertainties:
                continue
            facts = gcp_facts(service_account)
            facts.set_workload_identity_federation_trust_paths(paths)
            facts.extend_workload_identity_federation_trust_path_uncertainties(uncertainties)


def _pools_by_resource_name(context: GcpDecorationContext) -> dict[str, NormalizedResource]:
    pools: dict[str, NormalizedResource] = {}
    for pool in context.index.workload_identity_pools:
        for candidate in (pool.identifier, gcp_facts(pool).resource_name):
            resource_name = _canonical_pool_resource_name(candidate)
            if resource_name is not None:
                pools.setdefault(resource_name, pool)
    return pools


def _providers_by_pool_resource_name(
    context: GcpDecorationContext,
) -> dict[str, tuple[tuple[NormalizedResource, str], ...]]:
    providers: dict[str, list[tuple[NormalizedResource, str]]] = defaultdict(list)
    for provider in context.index.workload_identity_pool_providers:
        provider_resource_name = _canonical_provider_resource_name(
            provider.identifier
        ) or _canonical_provider_resource_name(gcp_facts(provider).resource_name)
        if provider_resource_name is None:
            continue
        pool_resource_name = provider_resource_name.rsplit("/providers/", 1)[0]
        providers[pool_resource_name].append((provider, provider_resource_name))
    return {
        pool_resource_name: tuple(sorted(values, key=lambda item: item[0].address))
        for pool_resource_name, values in providers.items()
    }


def _service_account_target(
    iam_resource: NormalizedResource,
    context: GcpDecorationContext,
) -> NormalizedResource | None:
    target_reference = gcp_facts(iam_resource).service_account_reference
    if not target_reference:
        return None
    target_key = gcp_reference_key(target_reference)
    matches = [
        service_account
        for service_account in context.index.service_accounts
        if target_key in _exact_service_account_references(service_account)
    ]
    return matches[0] if len(matches) == 1 else None


def _exact_service_account_references(resource: NormalizedResource) -> set[str]:
    facts = gcp_facts(resource)
    references = {
        resource.address,
        f"{resource.address}.id",
        f"{resource.address}.name",
        f"{resource.address}.email",
    }
    for value in (
        resource.identifier,
        facts.service_account_email,
        facts.service_account_member,
        facts.resource_name,
    ):
        if not _is_exact_service_account_identity(value):
            continue
        text = str(value).strip()
        references.add(text)
        if text.startswith("serviceAccount:"):
            references.add(text.removeprefix("serviceAccount:"))
        elif "@" in text:
            references.add(f"serviceAccount:{text}")
    return {gcp_reference_key(reference) for reference in references}


def _is_exact_service_account_identity(value: object) -> bool:
    if value in (None, ""):
        return False
    text = str(value).strip()
    return "@" in text or (text.startswith("projects/") and "/serviceAccounts/" in text)


def _parse_federated_principal(member: str) -> tuple[_FederatedPrincipal | None, str | None]:
    if member.startswith(_PRINCIPAL_PREFIX):
        member_kind = "principal"
        path = member.removeprefix(_PRINCIPAL_PREFIX)
    elif member.startswith(_PRINCIPAL_SET_PREFIX):
        member_kind = "principal_set"
        path = member.removeprefix(_PRINCIPAL_SET_PREFIX)
    elif member.startswith(("principal://", "principalSet://")):
        return None, f"principal member {member} does not use the canonical iam.googleapis.com authority"
    else:
        return None, None

    if not path or "$" + "{" in path or "}" in path or any(character.isspace() for character in path):
        return None, f"principal member {member} is unresolved or malformed"
    segments = path.strip("/").split("/")
    if (
        len(segments) < 7
        or segments[0] != "projects"
        or not segments[1].isdigit()
        or segments[2] != "locations"
        or not segments[3]
        or segments[4] != "workloadIdentityPools"
        or not segments[5]
    ):
        return None, f"principal member {member} is not a canonical workload identity principal URI"

    pool_resource_name = "/".join(segments[:6])
    selector = segments[6]
    if member_kind == "principal":
        if selector != "subject" or len(segments) < 8 or not "/".join(segments[7:]):
            return None, f"principal member {member} does not identify an exact subject"
        value = "/".join(segments[7:])
        required_mapping = "google.subject"
    elif selector == "*" and len(segments) == 7:
        selector = "pool"
        value = "*"
        required_mapping = None
    elif selector == "group" and len(segments) >= 8 and "/".join(segments[7:]):
        value = "/".join(segments[7:])
        required_mapping = "google.groups"
    elif selector.startswith("attribute.") and len(selector) > len("attribute.") and len(segments) >= 8:
        value = "/".join(segments[7:])
        if not value:
            return None, f"principal member {member} does not identify an attribute value"
        required_mapping = selector
    else:
        return None, f"principal member {member} has an unsupported principal-set selector"

    return (
        _FederatedPrincipal(
            member=member,
            member_kind=member_kind,
            pool_resource_name=pool_resource_name,
            selector=selector,
            value=value,
            required_mapping=required_mapping,
        ),
        None,
    )


def _provider_supports_principal(provider: NormalizedResource, principal: _FederatedPrincipal) -> bool:
    if principal.required_mapping is None:
        return True
    return principal.required_mapping in gcp_facts(provider).workload_identity_pool_provider_attribute_mappings


def _canonical_pool_resource_name(value: object) -> str | None:
    if value in (None, ""):
        return None
    text = str(value).strip().strip("/")
    if "$" + "{" in text or "}" in text:
        return None
    segments = text.split("/")
    if (
        len(segments) != 6
        or segments[0] != "projects"
        or not segments[1]
        or segments[2] != "locations"
        or not segments[3]
        or segments[4] != "workloadIdentityPools"
        or not segments[5]
    ):
        return None
    return "/".join(segments)


def _canonical_provider_resource_name(value: object) -> str | None:
    if value in (None, ""):
        return None
    text = str(value).strip().strip("/")
    if "$" + "{" in text or "}" in text:
        return None
    segments = text.split("/")
    if len(segments) != 8 or segments[6] != "providers" or not segments[7]:
        return None
    if _canonical_pool_resource_name("/".join(segments[:6])) is None:
        return None
    return "/".join(segments)


def _trust_path_record(
    service_account: NormalizedResource,
    iam_resource: NormalizedResource,
    binding: Mapping[str, Any],
    role: str,
    principal: _FederatedPrincipal,
    pool: NormalizedResource,
    provider: NormalizedResource,
    provider_resource_name: str,
) -> dict[str, Any]:
    service_account_facts = gcp_facts(service_account)
    pool_facts = gcp_facts(pool)
    provider_facts = gcp_facts(provider)
    condition = binding.get("condition")
    return {
        "service_account_address": service_account.address,
        "service_account_email": service_account_facts.service_account_email,
        "iam_resource_address": iam_resource.address,
        "role": role,
        "member": principal.member,
        "member_kind": principal.member_kind,
        "principal_selector": principal.selector,
        "principal_value": principal.value,
        "pool_address": pool.address,
        "pool_resource_name": principal.pool_resource_name,
        "pool_mode": pool_facts.workload_identity_pool_mode,
        "pool_state": pool_facts.workload_identity_pool_state,
        "provider_address": provider.address,
        "provider_resource_name": provider_resource_name,
        "provider_type": provider_facts.workload_identity_pool_provider_type,
        "provider_state": provider_facts.workload_identity_pool_provider_state,
        "provider_issuer_uri": provider_facts.workload_identity_pool_provider_issuer_uri,
        "provider_allowed_audiences": provider_facts.workload_identity_pool_provider_allowed_audiences,
        "provider_mapping_key": principal.required_mapping,
        "provider_attribute_condition": provider_facts.workload_identity_pool_provider_attribute_condition,
        "iam_condition": dict(condition) if isinstance(condition, Mapping) else None,
        "grant_basis": "service_account_iam",
    }


def _dedupe_paths(values: list[dict[str, Any]]) -> list[dict[str, Any]]:
    paths: list[dict[str, Any]] = []
    for value in sorted(
        values,
        key=lambda item: (
            str(item.get("service_account_address") or ""),
            str(item.get("iam_resource_address") or ""),
            str(item.get("member") or ""),
            str(item.get("provider_address") or ""),
        ),
    ):
        if value not in paths:
            paths.append(value)
    return paths
