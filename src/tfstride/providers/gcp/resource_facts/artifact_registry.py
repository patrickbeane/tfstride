from __future__ import annotations

from typing import Any

from tfstride.providers.coercion import STATE_DISABLED, STATE_ENABLED
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_facts.base import GcpBaseFacts


class GcpArtifactRegistryFacts(GcpBaseFacts):
    __slots__ = ()

    @property
    def artifact_registry_repository_id(self) -> str | None:
        return self.get(GcpResourceMetadata.ARTIFACT_REGISTRY_REPOSITORY_ID)

    @property
    def artifact_registry_repository_path(self) -> str | None:
        return self.get(GcpResourceMetadata.ARTIFACT_REGISTRY_REPOSITORY_PATH)

    @property
    def artifact_registry_repository_reference(self) -> str | None:
        return self.get(GcpResourceMetadata.ARTIFACT_REGISTRY_REPOSITORY_REFERENCE)

    @property
    def artifact_registry_format(self) -> str | None:
        return self.get(GcpResourceMetadata.ARTIFACT_REGISTRY_FORMAT)

    @property
    def artifact_registry_mode(self) -> str | None:
        return self.get(GcpResourceMetadata.ARTIFACT_REGISTRY_MODE)

    @property
    def artifact_registry_kms_key_name(self) -> str | None:
        return self.get(GcpResourceMetadata.ARTIFACT_REGISTRY_KMS_KEY_NAME)

    @property
    def artifact_registry_encryption_state(self) -> str | None:
        return self.get(GcpResourceMetadata.ARTIFACT_REGISTRY_ENCRYPTION_STATE)

    @property
    def artifact_registry_docker_immutable_tags_state(self) -> str | None:
        return self.get(GcpResourceMetadata.ARTIFACT_REGISTRY_DOCKER_IMMUTABLE_TAGS_STATE)

    @property
    def artifact_registry_docker_immutable_tags(self) -> bool | None:
        return _state_bool(self.artifact_registry_docker_immutable_tags_state)

    @property
    def artifact_registry_docker_config(self) -> dict[str, Any]:
        return self.get(GcpResourceMetadata.ARTIFACT_REGISTRY_DOCKER_CONFIG)

    @property
    def artifact_registry_vulnerability_scanning_enablement_config(self) -> str | None:
        return self.get(GcpResourceMetadata.ARTIFACT_REGISTRY_VULNERABILITY_SCANNING_ENABLEMENT_CONFIG)

    @property
    def artifact_registry_vulnerability_scanning_enablement_state(self) -> str | None:
        return self.get(GcpResourceMetadata.ARTIFACT_REGISTRY_VULNERABILITY_SCANNING_ENABLEMENT_STATE)

    @property
    def artifact_registry_vulnerability_scanning_state(self) -> str | None:
        return self.get(GcpResourceMetadata.ARTIFACT_REGISTRY_VULNERABILITY_SCANNING_STATE)

    @property
    def artifact_registry_vulnerability_scanning_state_reason(self) -> str | None:
        return self.get(GcpResourceMetadata.ARTIFACT_REGISTRY_VULNERABILITY_SCANNING_STATE_REASON)

    @property
    def artifact_registry_vulnerability_scanning_config(self) -> dict[str, Any]:
        return self.get(GcpResourceMetadata.ARTIFACT_REGISTRY_VULNERABILITY_SCANNING_CONFIG)

    @property
    def artifact_registry_cleanup_policies(self) -> list[dict[str, Any]]:
        return self.get(GcpResourceMetadata.ARTIFACT_REGISTRY_CLEANUP_POLICIES)

    @property
    def artifact_registry_cleanup_policy_state(self) -> str | None:
        return self.get(GcpResourceMetadata.ARTIFACT_REGISTRY_CLEANUP_POLICY_STATE)

    @property
    def artifact_registry_cleanup_policy_dry_run_state(self) -> str | None:
        return self.get(GcpResourceMetadata.ARTIFACT_REGISTRY_CLEANUP_POLICY_DRY_RUN_STATE)

    @property
    def artifact_registry_cleanup_policy_dry_run(self) -> bool | None:
        return _state_bool(self.artifact_registry_cleanup_policy_dry_run_state)

    @property
    def artifact_registry_deletion_policy(self) -> str | None:
        return self.get(GcpResourceMetadata.ARTIFACT_REGISTRY_DELETION_POLICY)

    @property
    def artifact_registry_deletion_policy_state(self) -> str | None:
        return self.get(GcpResourceMetadata.ARTIFACT_REGISTRY_DELETION_POLICY_STATE)

    @property
    def artifact_registry_posture_uncertainties(self) -> list[str]:
        return self.get(GcpResourceMetadata.ARTIFACT_REGISTRY_POSTURE_UNCERTAINTIES)

    @property
    def artifact_registry_iam_posture_uncertainties(self) -> list[str]:
        return self.get(GcpResourceMetadata.ARTIFACT_REGISTRY_IAM_POSTURE_UNCERTAINTIES)


def _state_bool(state: str | None) -> bool | None:
    if state == STATE_ENABLED:
        return True
    if state == STATE_DISABLED:
        return False
    return None
