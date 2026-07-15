from __future__ import annotations

from typing import Any

from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.resource_facts.base import AwsBaseFacts, _bool_from_state


class AwsEcrFacts(AwsBaseFacts):
    __slots__ = ()

    @property
    def ecr_encryption_type(self) -> str | None:
        return self.get(AwsResourceMetadata.ECR_ENCRYPTION_TYPE)

    @property
    def ecr_kms_key(self) -> str | None:
        return self.get(AwsResourceMetadata.ECR_KMS_KEY)

    @property
    def ecr_encryption_ownership_state(self) -> str | None:
        return self.get(AwsResourceMetadata.ECR_ENCRYPTION_OWNERSHIP_STATE)

    @property
    def ecr_image_tag_mutability(self) -> str | None:
        return self.get(AwsResourceMetadata.ECR_IMAGE_TAG_MUTABILITY)

    @property
    def ecr_image_tag_mutability_exclusion_filters(self) -> list[dict[str, Any]]:
        return self.get(AwsResourceMetadata.ECR_IMAGE_TAG_MUTABILITY_EXCLUSION_FILTERS)

    @property
    def ecr_repository_scan_on_push_state(self) -> str | None:
        return self.get(AwsResourceMetadata.ECR_REPOSITORY_SCAN_ON_PUSH_STATE)

    @property
    def ecr_repository_scan_on_push(self) -> bool | None:
        return _bool_from_state(self.ecr_repository_scan_on_push_state)

    @property
    def ecr_registry_scan_type(self) -> str | None:
        return self.get(AwsResourceMetadata.ECR_REGISTRY_SCAN_TYPE)

    @property
    def ecr_registry_scanning_coverage_state(self) -> str | None:
        return self.get(AwsResourceMetadata.ECR_REGISTRY_SCANNING_COVERAGE_STATE)

    @property
    def ecr_registry_scanning_rules(self) -> list[dict[str, Any]]:
        return self.get(AwsResourceMetadata.ECR_REGISTRY_SCANNING_RULES)

    @property
    def ecr_posture_uncertainties(self) -> list[str]:
        return self.get(AwsResourceMetadata.ECR_POSTURE_UNCERTAINTIES)
