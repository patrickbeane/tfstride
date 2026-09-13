from __future__ import annotations

from tfstride.models import NormalizedResource
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_index import GcpDecorationContext
from tfstride.providers.gcp.resource_types import GcpResourceType
from tfstride.providers.gcp.resource_utils import gcp_reference_key


class NormalizeKmsCryptoKeyVersionPostureStage:
    name = "normalize_kms_crypto_key_version_posture"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: GcpDecorationContext,
    ) -> None:
        for version in resources:
            if version.resource_type != GcpResourceType.KMS_CRYPTO_KEY_VERSION:
                continue
            self._decorate_version(version, context)

    def _decorate_version(
        self,
        version: NormalizedResource,
        context: GcpDecorationContext,
    ) -> None:
        version_facts = gcp_facts(version)
        parent_references = tuple(
            reference
            for reference in (
                version_facts.kms_crypto_key_version_crypto_key_reference,
                version_facts.kms_crypto_key_version_crypto_key_path,
            )
            if reference
        )
        parent = next(
            (
                candidate
                for reference in parent_references
                if (
                    candidate := context.index.resources_by_reference.get(
                        gcp_reference_key(reference),
                        source=version,
                        resource_types={GcpResourceType.KMS_CRYPTO_KEY},
                    )
                )
            ),
            None,
        )
        if parent is None:
            reference = ", ".join(parent_references) or "<missing>"
            version_facts.append(
                GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_POSTURE_UNCERTAINTIES,
                f"crypto_key reference {reference} is unresolved",
            )
            return

        parent_facts = gcp_facts(parent)
        version_facts.set(
            GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_RESOLVED_KEY_ADDRESS,
            parent.address,
        )
        if not version_facts.kms_crypto_key_version_crypto_key_path:
            version_facts.set(
                GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_CRYPTO_KEY_PATH,
                parent_facts.kms_crypto_key_reference,
            )
        if not version_facts.project and parent_facts.project:
            version_facts.set(GcpResourceMetadata.PROJECT, parent_facts.project)
        parent_purpose_unknown = any(
            "purpose is unknown after planning" in uncertainty for uncertainty in parent_facts.kms_posture_uncertainties
        )
        version_facts.set(
            GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_PURPOSE,
            None if parent_purpose_unknown else (parent_facts.kms_purpose or "ENCRYPT_DECRYPT"),
        )
        version_facts.set(
            GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_ROTATION_PERIOD,
            parent_facts.kms_rotation_period,
        )
        version_facts.set(
            GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_DESTROY_SCHEDULED_DURATION,
            parent_facts.kms_destroy_scheduled_duration,
        )
        if parent_facts.kms_key_ring and not version_facts.kms_crypto_key_version_key_ring:
            version_facts.set(
                GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_KEY_RING,
                parent_facts.kms_key_ring,
            )
        if parent_facts.kms_posture_uncertainties:
            version_facts.extend(
                GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_POSTURE_UNCERTAINTIES,
                [
                    f"parent crypto key {parent.address}: {uncertainty}"
                    for uncertainty in parent_facts.kms_posture_uncertainties
                ],
            )
