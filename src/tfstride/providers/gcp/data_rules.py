from __future__ import annotations

from tfstride.providers.gcp.artifact_registry_rules import GcpArtifactRegistryRuleDetectors
from tfstride.providers.gcp.cloud_sql_rules import GcpCloudSqlRuleDetectors
from tfstride.providers.gcp.kms_rules import GcpKmsRuleDetectors
from tfstride.providers.gcp.pubsub_bigquery_rules import GcpPubSubBigQueryRuleDetectors
from tfstride.providers.gcp.pubsub_posture_rules import GcpPubSubPostureRuleDetectors
from tfstride.providers.gcp.secret_manager_rules import GcpSecretManagerRuleDetectors
from tfstride.providers.gcp.storage_rules import GcpStorageRuleDetectors


class GcpDataRuleDetectors(
    GcpArtifactRegistryRuleDetectors,
    GcpPubSubBigQueryRuleDetectors,
    GcpPubSubPostureRuleDetectors,
    GcpStorageRuleDetectors,
    GcpSecretManagerRuleDetectors,
    GcpKmsRuleDetectors,
    GcpCloudSqlRuleDetectors,
):
    pass
