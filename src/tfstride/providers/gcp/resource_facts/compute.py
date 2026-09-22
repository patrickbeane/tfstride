from __future__ import annotations

from typing import Any

from tfstride.providers.gcp.audit_telemetry_disruption_evidence import (
    GcpCloudRunLoggingSinkAuditTelemetryDisruptionPath,
)
from tfstride.providers.gcp.firewall_ingress_evidence import GcpEffectiveFirewallIngress
from tfstride.providers.gcp.kms_evidence import (
    GcpCloudRunKmsManagementPath,
    GcpCloudRunKmsOperationPath,
)
from tfstride.providers.gcp.message_removal_evidence import (
    GcpCloudRunPubsubMessageRemovalPath,
)
from tfstride.providers.gcp.messaging_topology_destruction_evidence import (
    GcpCloudRunPubsubTopologyDestructionPath,
)
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.object_storage_deletion_evidence import (
    GcpCloudRunGcsObjectDeletionPath,
)
from tfstride.providers.gcp.object_storage_topology_destruction_evidence import (
    GcpCloudRunGcsBucketTopologyDestructionPath,
)
from tfstride.providers.gcp.protected_data_evidence import (
    GcpCloudRunGcsAccessPath,
    GcpCloudRunGcsProtectedDataConvergence,
)
from tfstride.providers.gcp.resource_facts.base import GcpBaseFacts
from tfstride.providers.gcp.secret_management_evidence import (
    GcpCloudRunSecretManagementPath,
)
from tfstride.providers.gcp.structured_data_deletion_evidence import (
    GcpCloudRunFirestoreDeletionPath,
)
from tfstride.providers.gcp.structured_data_topology_destruction_evidence import (
    GcpCloudRunFirestoreDatabaseTopologyDestructionPath,
)


class GcpComputeFacts(GcpBaseFacts):
    __slots__ = ()

    @property
    def os_login_enabled(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.OS_LOGIN_ENABLED)

    @property
    def serverless_ingress(self) -> str | None:
        return self.get(GcpResourceMetadata.SERVERLESS_INGRESS)

    @property
    def cloud_run_invoker_iam_disabled(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.CLOUD_RUN_INVOKER_IAM_DISABLED)

    @property
    def network_tags(self) -> list[str]:
        return self.get(GcpResourceMetadata.NETWORK_TAGS)

    @property
    def internet_ingress_firewalls(self) -> list[str]:
        return self.get(GcpResourceMetadata.INTERNET_INGRESS_FIREWALLS)

    @property
    def effective_firewall_ingress(self) -> list[GcpEffectiveFirewallIngress]:
        return self.get(GcpResourceMetadata.EFFECTIVE_FIREWALL_INGRESS)

    @property
    def fronted_by_internet_facing_load_balancer(self) -> bool:
        return self.get(GcpResourceMetadata.FRONTED_BY_INTERNET_FACING_LOAD_BALANCER)

    @property
    def internet_facing_load_balancer_addresses(self) -> list[str]:
        return self.get(GcpResourceMetadata.INTERNET_FACING_LOAD_BALANCER_ADDRESSES)

    @property
    def container_image_references(self) -> list[dict[str, Any]]:
        return self.get(GcpResourceMetadata.CONTAINER_IMAGE_REFERENCES)

    @property
    def container_image_posture_uncertainties(self) -> list[str]:
        return self.get(GcpResourceMetadata.CONTAINER_IMAGE_POSTURE_UNCERTAINTIES)

    @property
    def cloud_run_secret_references(self) -> list[dict[str, Any]]:
        return self.get(GcpResourceMetadata.CLOUD_RUN_SECRET_REFERENCES)

    @property
    def cloud_run_secret_posture_uncertainties(self) -> list[str]:
        return self.get(GcpResourceMetadata.CLOUD_RUN_SECRET_POSTURE_UNCERTAINTIES)

    @property
    def cloud_run_secret_access_paths(self) -> list[dict[str, Any]]:
        return self.get(GcpResourceMetadata.CLOUD_RUN_SECRET_ACCESS_PATHS)

    @property
    def cloud_run_secret_access_path_uncertainties(self) -> list[str]:
        return self.get(GcpResourceMetadata.CLOUD_RUN_SECRET_ACCESS_PATH_UNCERTAINTIES)

    @property
    def cloud_run_secret_management_paths(
        self,
    ) -> list[GcpCloudRunSecretManagementPath]:
        return self.get(GcpResourceMetadata.CLOUD_RUN_SECRET_MANAGEMENT_PATHS)

    @property
    def cloud_run_secret_management_path_uncertainties(self) -> list[str]:
        return self.get(GcpResourceMetadata.CLOUD_RUN_SECRET_MANAGEMENT_PATH_UNCERTAINTIES)

    @property
    def cloud_run_gcs_access_paths(self) -> list[GcpCloudRunGcsAccessPath]:
        return self.get(GcpResourceMetadata.CLOUD_RUN_GCS_ACCESS_PATHS)

    @property
    def cloud_run_gcs_access_path_uncertainties(self) -> list[str]:
        return self.get(GcpResourceMetadata.CLOUD_RUN_GCS_ACCESS_PATH_UNCERTAINTIES)

    @property
    def cloud_run_gcs_object_deletion_paths(
        self,
    ) -> list[GcpCloudRunGcsObjectDeletionPath]:
        return self.get(GcpResourceMetadata.CLOUD_RUN_GCS_OBJECT_DELETION_PATHS)

    @property
    def cloud_run_gcs_object_deletion_path_uncertainties(self) -> list[str]:
        return self.get(GcpResourceMetadata.CLOUD_RUN_GCS_OBJECT_DELETION_PATH_UNCERTAINTIES)

    @property
    def cloud_run_gcs_bucket_topology_destruction_paths(
        self,
    ) -> list[GcpCloudRunGcsBucketTopologyDestructionPath]:
        return self.get(GcpResourceMetadata.CLOUD_RUN_GCS_BUCKET_TOPOLOGY_DESTRUCTION_PATHS)

    @property
    def cloud_run_gcs_bucket_topology_destruction_path_uncertainties(
        self,
    ) -> list[str]:
        return self.get(GcpResourceMetadata.CLOUD_RUN_GCS_BUCKET_TOPOLOGY_DESTRUCTION_PATH_UNCERTAINTIES)

    @property
    def cloud_run_gcs_protected_data_convergences(
        self,
    ) -> list[GcpCloudRunGcsProtectedDataConvergence]:
        return self.get(GcpResourceMetadata.CLOUD_RUN_GCS_PROTECTED_DATA_CONVERGENCES)

    @property
    def cloud_run_gcs_protected_data_convergence_uncertainties(
        self,
    ) -> list[str]:
        return self.get(GcpResourceMetadata.CLOUD_RUN_GCS_PROTECTED_DATA_CONVERGENCE_UNCERTAINTIES)

    @property
    def cloud_run_pubsub_access_paths(self) -> list[dict[str, Any]]:
        return self.get(GcpResourceMetadata.CLOUD_RUN_PUBSUB_ACCESS_PATHS)

    @property
    def cloud_run_pubsub_access_path_uncertainties(self) -> list[str]:
        return self.get(GcpResourceMetadata.CLOUD_RUN_PUBSUB_ACCESS_PATH_UNCERTAINTIES)

    @property
    def cloud_run_pubsub_message_removal_paths(self) -> list[GcpCloudRunPubsubMessageRemovalPath]:
        return self.get(GcpResourceMetadata.CLOUD_RUN_PUBSUB_MESSAGE_REMOVAL_PATHS)

    @property
    def cloud_run_pubsub_message_removal_path_uncertainties(self) -> list[str]:
        return self.get(GcpResourceMetadata.CLOUD_RUN_PUBSUB_MESSAGE_REMOVAL_PATH_UNCERTAINTIES)

    @property
    def cloud_run_pubsub_topology_destruction_paths(
        self,
    ) -> list[GcpCloudRunPubsubTopologyDestructionPath]:
        return self.get(GcpResourceMetadata.CLOUD_RUN_PUBSUB_TOPOLOGY_DESTRUCTION_PATHS)

    @property
    def cloud_run_pubsub_topology_destruction_path_uncertainties(self) -> list[str]:
        return self.get(GcpResourceMetadata.CLOUD_RUN_PUBSUB_TOPOLOGY_DESTRUCTION_PATH_UNCERTAINTIES)

    @property
    def cloud_run_firestore_access_paths(self) -> list[dict[str, Any]]:
        return self.get(GcpResourceMetadata.CLOUD_RUN_FIRESTORE_ACCESS_PATHS)

    @property
    def cloud_run_firestore_access_path_uncertainties(self) -> list[str]:
        return self.get(GcpResourceMetadata.CLOUD_RUN_FIRESTORE_ACCESS_PATH_UNCERTAINTIES)

    @property
    def cloud_run_firestore_entity_deletion_paths(self) -> list[GcpCloudRunFirestoreDeletionPath]:
        return self.get(GcpResourceMetadata.CLOUD_RUN_FIRESTORE_ENTITY_DELETION_PATHS)

    @property
    def cloud_run_firestore_entity_deletion_path_uncertainties(self) -> list[str]:
        return self.get(GcpResourceMetadata.CLOUD_RUN_FIRESTORE_ENTITY_DELETION_PATH_UNCERTAINTIES)

    @property
    def cloud_run_firestore_database_topology_destruction_paths(
        self,
    ) -> list[GcpCloudRunFirestoreDatabaseTopologyDestructionPath]:
        return self.get(GcpResourceMetadata.CLOUD_RUN_FIRESTORE_DATABASE_TOPOLOGY_DESTRUCTION_PATHS)

    @property
    def cloud_run_firestore_database_topology_destruction_path_uncertainties(
        self,
    ) -> list[str]:
        return self.get(GcpResourceMetadata.CLOUD_RUN_FIRESTORE_DATABASE_TOPOLOGY_DESTRUCTION_PATH_UNCERTAINTIES)

    @property
    def cloud_run_logging_sink_audit_telemetry_disruption_paths(
        self,
    ) -> list[GcpCloudRunLoggingSinkAuditTelemetryDisruptionPath]:
        return self.get(GcpResourceMetadata.CLOUD_RUN_LOGGING_SINK_AUDIT_TELEMETRY_DISRUPTION_PATHS)

    @property
    def cloud_run_logging_sink_audit_telemetry_disruption_path_uncertainties(
        self,
    ) -> list[str]:
        return self.get(GcpResourceMetadata.CLOUD_RUN_LOGGING_SINK_AUDIT_TELEMETRY_DISRUPTION_PATH_UNCERTAINTIES)

    @property
    def cloud_run_kms_operation_paths(self) -> list[GcpCloudRunKmsOperationPath]:
        return self.get(GcpResourceMetadata.CLOUD_RUN_KMS_OPERATION_PATHS)

    @property
    def cloud_run_kms_operation_path_uncertainties(self) -> list[str]:
        return self.get(GcpResourceMetadata.CLOUD_RUN_KMS_OPERATION_PATH_UNCERTAINTIES)

    @property
    def cloud_run_kms_management_paths(self) -> list[GcpCloudRunKmsManagementPath]:
        return self.get(GcpResourceMetadata.CLOUD_RUN_KMS_MANAGEMENT_PATHS)

    @property
    def cloud_run_kms_management_path_uncertainties(self) -> list[str]:
        return self.get(GcpResourceMetadata.CLOUD_RUN_KMS_MANAGEMENT_PATH_UNCERTAINTIES)

    @property
    def artifact_registry_write_paths(self) -> list[dict[str, Any]]:
        return self.get(GcpResourceMetadata.ARTIFACT_REGISTRY_WRITE_PATHS)

    @property
    def artifact_registry_write_path_uncertainties(self) -> list[str]:
        return self.get(GcpResourceMetadata.ARTIFACT_REGISTRY_WRITE_PATH_UNCERTAINTIES)

    def set_cloud_run_secret_access_paths(self, values: list[dict[str, Any]]) -> None:
        self.set(GcpResourceMetadata.CLOUD_RUN_SECRET_ACCESS_PATHS, values)

    def extend_cloud_run_secret_access_path_uncertainties(self, values: list[str]) -> None:
        self.extend(GcpResourceMetadata.CLOUD_RUN_SECRET_ACCESS_PATH_UNCERTAINTIES, values)

    def set_cloud_run_secret_management_paths(
        self,
        values: list[GcpCloudRunSecretManagementPath],
    ) -> None:
        self.set(GcpResourceMetadata.CLOUD_RUN_SECRET_MANAGEMENT_PATHS, values)

    def extend_cloud_run_secret_management_path_uncertainties(
        self,
        values: list[str],
    ) -> None:
        self.extend(
            GcpResourceMetadata.CLOUD_RUN_SECRET_MANAGEMENT_PATH_UNCERTAINTIES,
            values,
        )

    def set_cloud_run_gcs_access_paths(self, values: list[GcpCloudRunGcsAccessPath]) -> None:
        self.set(GcpResourceMetadata.CLOUD_RUN_GCS_ACCESS_PATHS, values)

    def extend_cloud_run_gcs_access_path_uncertainties(self, values: list[str]) -> None:
        self.extend(GcpResourceMetadata.CLOUD_RUN_GCS_ACCESS_PATH_UNCERTAINTIES, values)

    def set_cloud_run_gcs_object_deletion_paths(
        self,
        values: list[GcpCloudRunGcsObjectDeletionPath],
    ) -> None:
        self.set(GcpResourceMetadata.CLOUD_RUN_GCS_OBJECT_DELETION_PATHS, values)

    def extend_cloud_run_gcs_object_deletion_path_uncertainties(
        self,
        values: list[str],
    ) -> None:
        self.extend(
            GcpResourceMetadata.CLOUD_RUN_GCS_OBJECT_DELETION_PATH_UNCERTAINTIES,
            values,
        )

    def set_cloud_run_gcs_bucket_topology_destruction_paths(
        self,
        values: list[GcpCloudRunGcsBucketTopologyDestructionPath],
    ) -> None:
        self.set(
            GcpResourceMetadata.CLOUD_RUN_GCS_BUCKET_TOPOLOGY_DESTRUCTION_PATHS,
            values,
        )

    def extend_cloud_run_gcs_bucket_topology_destruction_path_uncertainties(
        self,
        values: list[str],
    ) -> None:
        self.extend(
            GcpResourceMetadata.CLOUD_RUN_GCS_BUCKET_TOPOLOGY_DESTRUCTION_PATH_UNCERTAINTIES,
            values,
        )

    def set_cloud_run_gcs_protected_data_convergences(
        self,
        values: list[GcpCloudRunGcsProtectedDataConvergence],
    ) -> None:
        self.set(
            GcpResourceMetadata.CLOUD_RUN_GCS_PROTECTED_DATA_CONVERGENCES,
            values,
        )

    def extend_cloud_run_gcs_protected_data_convergence_uncertainties(
        self,
        values: list[str],
    ) -> None:
        self.extend(
            GcpResourceMetadata.CLOUD_RUN_GCS_PROTECTED_DATA_CONVERGENCE_UNCERTAINTIES,
            values,
        )

    def set_cloud_run_pubsub_access_paths(self, values: list[dict[str, Any]]) -> None:
        self.set(GcpResourceMetadata.CLOUD_RUN_PUBSUB_ACCESS_PATHS, values)

    def extend_cloud_run_pubsub_access_path_uncertainties(self, values: list[str]) -> None:
        self.extend(GcpResourceMetadata.CLOUD_RUN_PUBSUB_ACCESS_PATH_UNCERTAINTIES, values)

    def set_cloud_run_pubsub_message_removal_paths(
        self,
        values: list[GcpCloudRunPubsubMessageRemovalPath],
    ) -> None:
        self.set(GcpResourceMetadata.CLOUD_RUN_PUBSUB_MESSAGE_REMOVAL_PATHS, values)

    def extend_cloud_run_pubsub_message_removal_path_uncertainties(
        self,
        values: list[str],
    ) -> None:
        self.extend(GcpResourceMetadata.CLOUD_RUN_PUBSUB_MESSAGE_REMOVAL_PATH_UNCERTAINTIES, values)

    def set_cloud_run_pubsub_topology_destruction_paths(
        self,
        values: list[GcpCloudRunPubsubTopologyDestructionPath],
    ) -> None:
        self.set(
            GcpResourceMetadata.CLOUD_RUN_PUBSUB_TOPOLOGY_DESTRUCTION_PATHS,
            values,
        )

    def extend_cloud_run_pubsub_topology_destruction_path_uncertainties(
        self,
        values: list[str],
    ) -> None:
        self.extend(
            GcpResourceMetadata.CLOUD_RUN_PUBSUB_TOPOLOGY_DESTRUCTION_PATH_UNCERTAINTIES,
            values,
        )

    def set_cloud_run_firestore_access_paths(self, values: list[dict[str, Any]]) -> None:
        self.set(GcpResourceMetadata.CLOUD_RUN_FIRESTORE_ACCESS_PATHS, values)

    def extend_cloud_run_firestore_access_path_uncertainties(self, values: list[str]) -> None:
        self.extend(GcpResourceMetadata.CLOUD_RUN_FIRESTORE_ACCESS_PATH_UNCERTAINTIES, values)

    def set_cloud_run_firestore_entity_deletion_paths(
        self,
        values: list[GcpCloudRunFirestoreDeletionPath],
    ) -> None:
        self.set(GcpResourceMetadata.CLOUD_RUN_FIRESTORE_ENTITY_DELETION_PATHS, values)

    def extend_cloud_run_firestore_entity_deletion_path_uncertainties(
        self,
        values: list[str],
    ) -> None:
        self.extend(GcpResourceMetadata.CLOUD_RUN_FIRESTORE_ENTITY_DELETION_PATH_UNCERTAINTIES, values)

    def set_cloud_run_firestore_database_topology_destruction_paths(
        self,
        values: list[GcpCloudRunFirestoreDatabaseTopologyDestructionPath],
    ) -> None:
        self.set(
            GcpResourceMetadata.CLOUD_RUN_FIRESTORE_DATABASE_TOPOLOGY_DESTRUCTION_PATHS,
            values,
        )

    def extend_cloud_run_firestore_database_topology_destruction_path_uncertainties(
        self,
        values: list[str],
    ) -> None:
        self.extend(
            GcpResourceMetadata.CLOUD_RUN_FIRESTORE_DATABASE_TOPOLOGY_DESTRUCTION_PATH_UNCERTAINTIES,
            values,
        )

    def set_cloud_run_logging_sink_audit_telemetry_disruption_paths(
        self,
        values: list[GcpCloudRunLoggingSinkAuditTelemetryDisruptionPath],
    ) -> None:
        self.set(
            GcpResourceMetadata.CLOUD_RUN_LOGGING_SINK_AUDIT_TELEMETRY_DISRUPTION_PATHS,
            values,
        )

    def extend_cloud_run_logging_sink_audit_telemetry_disruption_path_uncertainties(
        self,
        values: list[str],
    ) -> None:
        self.extend(
            GcpResourceMetadata.CLOUD_RUN_LOGGING_SINK_AUDIT_TELEMETRY_DISRUPTION_PATH_UNCERTAINTIES,
            values,
        )

    def set_cloud_run_kms_operation_paths(self, values: list[GcpCloudRunKmsOperationPath]) -> None:
        self.set(GcpResourceMetadata.CLOUD_RUN_KMS_OPERATION_PATHS, values)

    def extend_cloud_run_kms_operation_path_uncertainties(self, values: list[str]) -> None:
        self.extend(GcpResourceMetadata.CLOUD_RUN_KMS_OPERATION_PATH_UNCERTAINTIES, values)

    def set_cloud_run_kms_management_paths(self, values: list[GcpCloudRunKmsManagementPath]) -> None:
        self.set(GcpResourceMetadata.CLOUD_RUN_KMS_MANAGEMENT_PATHS, values)

    def extend_cloud_run_kms_management_path_uncertainties(self, values: list[str]) -> None:
        self.extend(GcpResourceMetadata.CLOUD_RUN_KMS_MANAGEMENT_PATH_UNCERTAINTIES, values)

    def set_artifact_registry_write_paths(self, values: list[dict[str, Any]]) -> None:
        self.set(GcpResourceMetadata.ARTIFACT_REGISTRY_WRITE_PATHS, values)

    def extend_artifact_registry_write_path_uncertainties(self, values: list[str]) -> None:
        self.extend(GcpResourceMetadata.ARTIFACT_REGISTRY_WRITE_PATH_UNCERTAINTIES, values)
