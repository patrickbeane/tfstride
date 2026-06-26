from __future__ import annotations

from tfstride.analysis.finding_helpers import collect_evidence, evidence_item
from tfstride.models import Observation, ResourceInventory
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AZURE_COMPUTE_RESOURCE_TYPES, AzureResourceType

_STORAGE_POSTURE_RESOURCE_TYPES = (
    AzureResourceType.STORAGE_ACCOUNT,
    AzureResourceType.STORAGE_CONTAINER,
)


def observe_azure_posture(inventory: ResourceInventory) -> list[Observation]:
    if inventory.provider != "azure":
        return []
    return [
        *_observe_managed_identity_principals(inventory),
        *observe_azure_storage_uncertainty(inventory),
        *_observe_key_vault_network_posture(inventory),
        *_observe_key_vault_authorization_posture(inventory),
        *_observe_key_vault_recovery_posture(inventory),
    ]


def _observe_managed_identity_principals(inventory: ResourceInventory) -> list[Observation]:
    observations: list[Observation] = []
    resource_types = (*AZURE_COMPUTE_RESOURCE_TYPES, AzureResourceType.USER_ASSIGNED_IDENTITY)
    for resource in inventory.by_type(*resource_types):
        facts = azure_facts(resource)
        if facts.identity_type:
            observations.append(
                Observation(
                    title="Azure managed identity principal is modeled",
                    observation_id="azure-managed-identity-principal-observed",
                    category="iam",
                    affected_resources=[resource.address],
                    rationale=(
                        f"{resource.display_name} exposes a `{facts.identity_type}` managed identity principal. "
                        "This models principal identity only and does not imply a role assignment or effective access."
                    ),
                    evidence=collect_evidence(
                        evidence_item("identity_type", [facts.identity_type]),
                        evidence_item("principal_id", [facts.principal_id] if facts.principal_id else []),
                        evidence_item("client_id", [facts.client_id] if facts.client_id else []),
                        evidence_item("tenant_id", [facts.tenant_id] if facts.tenant_id else []),
                        evidence_item("attached_identity_references", facts.attached_identity_references),
                        evidence_item(
                            "analysis_scope",
                            ["managed identity principal is not connected to Azure role assignments"],
                        ),
                    ),
                )
            )
        if facts.managed_identity_uncertainties:
            observations.append(
                Observation(
                    title="Azure managed identity principal contains unresolved plan values",
                    observation_id="azure-managed-identity-principal-unknown",
                    category="analysis-uncertainty",
                    affected_resources=[resource.address],
                    rationale=(
                        f"{resource.display_name} has computed managed identity attributes. tfSTRIDE preserves "
                        "the known principal shape without inferring unresolved identifiers or attachments."
                    ),
                    evidence=collect_evidence(
                        evidence_item("unknown_identity_posture", facts.managed_identity_uncertainties),
                    ),
                )
            )
    return observations


def observe_azure_storage_uncertainty(inventory: ResourceInventory) -> list[Observation]:
    if inventory.provider != "azure":
        return []

    observations: list[Observation] = []
    for resource in inventory.by_type(*_STORAGE_POSTURE_RESOURCE_TYPES):
        uncertainties = azure_facts(resource).storage_posture_uncertainties
        if not uncertainties:
            continue
        observations.append(
            Observation(
                title="Azure Storage exposure posture contains unresolved plan values",
                observation_id="azure-storage-exposure-posture-unknown",
                category="analysis-uncertainty",
                affected_resources=[resource.address],
                rationale=(
                    f"{resource.display_name} has computed storage exposure attributes that are not known in "
                    "this Terraform plan. tfSTRIDE does not infer public access from those unresolved values."
                ),
                evidence=collect_evidence(
                    evidence_item("unknown_storage_posture", uncertainties),
                    evidence_item(
                        "analysis_effect",
                        ["public exposure findings are emitted only for known-positive posture signals"],
                    ),
                ),
            )
        )
    return observations


def _observe_key_vault_network_posture(inventory: ResourceInventory) -> list[Observation]:
    observations: list[Observation] = []
    for vault in inventory.by_type(AzureResourceType.KEY_VAULT):
        facts = azure_facts(vault)
        if facts.key_vault_network_uncertainties:
            observations.append(
                Observation(
                    title="Azure Key Vault network posture contains unresolved plan values",
                    observation_id="azure-key-vault-network-posture-unknown",
                    category="analysis-uncertainty",
                    affected_resources=[vault.address],
                    rationale=(
                        f"{vault.display_name} has computed network exposure attributes. tfSTRIDE does not "
                        "infer public reachability from unresolved public-network or ACL values."
                    ),
                    evidence=collect_evidence(
                        evidence_item("unknown_network_posture", facts.key_vault_network_uncertainties),
                    ),
                )
            )
            continue

        default_action = facts.network_default_action
        if facts.public_network_access_enabled is False:
            posture = ["public_network_access_enabled is false"]
        elif default_action is not None and default_action.strip().lower() == "deny":
            posture = [
                "public_network_access_enabled is true",
                f"effective network_acls.default_action is {default_action}",
                *[f"allowed IP rule is {value}" for value in facts.key_vault_network_ip_rules],
                *[f"allowed subnet is {value}" for value in facts.key_vault_network_subnet_ids],
            ]
        else:
            continue
        observations.append(
            Observation(
                title="Azure Key Vault network access is restricted",
                observation_id="azure-key-vault-network-restricted",
                category="data-protection",
                affected_resources=[vault.address],
                rationale=(
                    f"{vault.display_name} is not broadly reachable through its public endpoint. Network "
                    "controls are evaluated separately from the identities authorized to use the vault."
                ),
                evidence=collect_evidence(evidence_item("network_posture", posture)),
            )
        )
    return observations


def _observe_key_vault_authorization_posture(inventory: ResourceInventory) -> list[Observation]:
    observations: list[Observation] = []
    for vault in inventory.by_type(AzureResourceType.KEY_VAULT):
        facts = azure_facts(vault)
        if facts.key_vault_authorization_uncertainties:
            observations.append(
                Observation(
                    title="Azure Key Vault authorization posture contains unresolved plan values",
                    observation_id="azure-key-vault-authorization-posture-unknown",
                    category="analysis-uncertainty",
                    affected_resources=[vault.address],
                    rationale=(
                        f"{vault.display_name} has computed authorization attributes. tfSTRIDE reports only "
                        "known privileged access policies and role assignments."
                    ),
                    evidence=collect_evidence(
                        evidence_item(
                            "unknown_authorization_posture",
                            facts.key_vault_authorization_uncertainties,
                        ),
                    ),
                )
            )
        policies = facts.key_vault_access_policies
        assignments = facts.key_vault_role_assignments
        if not policies and not assignments:
            continue
        authorization_model = "Azure RBAC" if facts.rbac_authorization_enabled is True else "vault access policies"
        observations.append(
            Observation(
                title="Azure Key Vault identity authorization is modeled separately from network access",
                observation_id="azure-key-vault-authorization-model-observed",
                category="iam",
                affected_resources=[vault.address],
                rationale=(
                    f"{vault.display_name} uses {authorization_model}. Network reachability does not imply "
                    "authorization, and privileged grants are evaluated independently."
                ),
                evidence=collect_evidence(
                    evidence_item("authorization_model", [authorization_model]),
                    evidence_item("access_policy_sources", _record_sources(policies)),
                    evidence_item("role_assignment_sources", _record_sources(assignments)),
                ),
            )
        )
    return observations


def _observe_key_vault_recovery_posture(inventory: ResourceInventory) -> list[Observation]:
    observations: list[Observation] = []
    for vault in inventory.by_type(AzureResourceType.KEY_VAULT):
        uncertainties = azure_facts(vault).key_vault_recovery_uncertainties
        if not uncertainties:
            continue
        observations.append(
            Observation(
                title="Azure Key Vault recovery posture contains unresolved plan values",
                observation_id="azure-key-vault-recovery-posture-unknown",
                category="analysis-uncertainty",
                affected_resources=[vault.address],
                rationale=(
                    f"{vault.display_name} has computed recovery attributes. tfSTRIDE does not infer purge "
                    "protection posture from unresolved values."
                ),
                evidence=collect_evidence(evidence_item("unknown_recovery_posture", uncertainties)),
            )
        )
    return observations


def _record_sources(records: list[dict]) -> list[str]:
    return [str(record["source"]) for record in records if record.get("source")]
