from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.network_normalizers import AWS_PROVIDER
from tfstride.providers.coercion import (
    STATE_DISABLED,
    STATE_ENABLED,
    STATE_NOT_CONFIGURED,
    STATE_UNKNOWN,
    as_list,
    first_mapping,
    known_block_bool,
    known_block_string,
    known_string,
)


def normalize_ecr_repository(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []
    encryption_configuration = first_mapping(values.get("encryption_configuration"), scan_all=True)
    unknown_encryption_configuration = _first_unknown_block(unknown_values.get("encryption_configuration"))
    image_scanning_configuration = first_mapping(values.get("image_scanning_configuration"), scan_all=True)
    unknown_image_scanning_configuration = _first_unknown_block(unknown_values.get("image_scanning_configuration"))

    if encryption_configuration is None and unknown_values.get("encryption_configuration") is True:
        uncertainties.append("encryption_configuration is unknown after planning")
    if image_scanning_configuration is None and unknown_values.get("image_scanning_configuration") is True:
        uncertainties.append("image_scanning_configuration is unknown after planning")

    encryption_type = known_block_string(
        encryption_configuration,
        unknown_encryption_configuration,
        "encryption_type",
        uncertainties,
        path="encryption_configuration",
    )
    kms_key = known_block_string(
        encryption_configuration,
        unknown_encryption_configuration,
        "kms_key",
        uncertainties,
        path="encryption_configuration",
    )
    scan_on_push = known_block_bool(
        image_scanning_configuration,
        unknown_image_scanning_configuration,
        "scan_on_push",
        uncertainties,
        path="image_scanning_configuration",
    )

    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.DATA,
        identifier=known_string(values, unknown_values, "id", uncertainties) or values.get("name") or resource.address,
        arn=known_string(values, unknown_values, "arn", uncertainties),
        data_sensitivity="sensitive",
        metadata={
            AwsResourceMetadata.NAME: known_string(values, unknown_values, "name", uncertainties) or resource.name,
            AwsResourceMetadata.ECR_ENCRYPTION_TYPE: encryption_type,
            AwsResourceMetadata.ECR_KMS_KEY: kms_key,
            AwsResourceMetadata.ECR_ENCRYPTION_OWNERSHIP_STATE: _encryption_ownership_state(
                encryption_type,
                kms_key,
                encryption_configuration,
                unknown_encryption_configuration,
            ),
            AwsResourceMetadata.ECR_IMAGE_TAG_MUTABILITY: known_string(
                values,
                unknown_values,
                "image_tag_mutability",
                uncertainties,
                require_string=True,
            ),
            AwsResourceMetadata.ECR_IMAGE_TAG_MUTABILITY_EXCLUSION_FILTERS: _exclusion_filters(
                values.get("image_tag_mutability_exclusion_filter"),
                unknown_values.get("image_tag_mutability_exclusion_filter"),
                uncertainties,
            ),
            AwsResourceMetadata.ECR_REPOSITORY_SCAN_ON_PUSH_STATE: _scan_on_push_state(
                image_scanning_configuration,
                unknown_image_scanning_configuration,
                scan_on_push,
            ),
            AwsResourceMetadata.ECR_POSTURE_UNCERTAINTIES: uncertainties,
        },
    )


def normalize_ecr_registry_scanning_configuration(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []
    rules = _registry_scanning_rules(values.get("rule"), unknown_values.get("rule"), uncertainties)

    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.DATA,
        identifier=known_string(values, unknown_values, "id", uncertainties) or resource.address,
        metadata={
            AwsResourceMetadata.ECR_REGISTRY_SCAN_TYPE: known_string(
                values,
                unknown_values,
                "scan_type",
                uncertainties,
                require_string=True,
            ),
            AwsResourceMetadata.ECR_REGISTRY_SCANNING_COVERAGE_STATE: _registry_scanning_coverage_state(
                values.get("rule"),
                unknown_values.get("rule"),
                rules,
            ),
            AwsResourceMetadata.ECR_REGISTRY_SCANNING_RULES: rules,
            AwsResourceMetadata.ECR_POSTURE_UNCERTAINTIES: uncertainties,
        },
    )


def _first_unknown_block(value: Any) -> Any:
    return True if value is True else first_mapping(value, scan_all=True)


def _encryption_ownership_state(
    encryption_type: str | None,
    kms_key: str | None,
    configuration: Mapping[str, Any] | None,
    unknown_configuration: Any,
) -> str:
    if configuration is None:
        return STATE_UNKNOWN if unknown_configuration is True else STATE_NOT_CONFIGURED
    if encryption_type is None:
        return STATE_UNKNOWN
    normalized_type = encryption_type.strip().upper()
    if normalized_type == "KMS":
        return "customer_managed" if kms_key else "service_managed"
    if normalized_type == "AES256":
        return "service_managed"
    return STATE_UNKNOWN


def _scan_on_push_state(
    configuration: Mapping[str, Any] | None,
    unknown_configuration: Any,
    scan_on_push: bool | None,
) -> str:
    if configuration is None:
        return STATE_UNKNOWN if unknown_configuration is True else STATE_NOT_CONFIGURED
    if scan_on_push is True:
        return STATE_ENABLED
    if scan_on_push is False:
        return STATE_DISABLED
    return STATE_UNKNOWN


def _exclusion_filters(value: Any, unknown_value: Any, uncertainties: list[str]) -> list[dict[str, str]]:
    if unknown_value is True:
        uncertainties.append("image_tag_mutability_exclusion_filter is unknown after planning")
        return []

    filters: list[dict[str, str]] = []
    for index, item in enumerate(as_list(value)):
        if not isinstance(item, Mapping):
            uncertainties.append(f"image_tag_mutability_exclusion_filter[{index}] has an unrecognized value shape")
            continue
        unknown_item = _unknown_item(unknown_value, index)
        filter_value = known_block_string(
            item,
            unknown_item,
            "filter",
            uncertainties,
            path=f"image_tag_mutability_exclusion_filter[{index}]",
        )
        filter_type = known_block_string(
            item,
            unknown_item,
            "filter_type",
            uncertainties,
            path=f"image_tag_mutability_exclusion_filter[{index}]",
        )
        record = {
            key: item_value
            for key, item_value in (("filter", filter_value), ("filter_type", filter_type))
            if item_value
        }
        if record:
            filters.append(record)
    return filters


def _registry_scanning_rules(value: Any, unknown_value: Any, uncertainties: list[str]) -> list[dict[str, Any]]:
    if unknown_value is True:
        uncertainties.append("rule is unknown after planning")
        return []

    rules: list[dict[str, Any]] = []
    for index, item in enumerate(as_list(value)):
        if not isinstance(item, Mapping):
            uncertainties.append(f"rule[{index}] has an unrecognized value shape")
            continue
        unknown_item = _unknown_item(unknown_value, index)
        scan_frequency = known_block_string(
            item,
            unknown_item,
            "scan_frequency",
            uncertainties,
            path=f"rule[{index}]",
        )
        filters = _repository_filters(
            item.get("repository_filter"),
            unknown_item.get("repository_filter") if isinstance(unknown_item, Mapping) else None,
            index,
            uncertainties,
        )
        record: dict[str, Any] = {"repository_filters": filters}
        if scan_frequency:
            record["scan_frequency"] = scan_frequency
        rules.append(record)
    return rules


def _repository_filters(
    value: Any, unknown_value: Any, rule_index: int, uncertainties: list[str]
) -> list[dict[str, str]]:
    if unknown_value is True:
        uncertainties.append(f"rule[{rule_index}].repository_filter is unknown after planning")
        return []

    filters: list[dict[str, str]] = []
    for index, item in enumerate(as_list(value)):
        if not isinstance(item, Mapping):
            uncertainties.append(f"rule[{rule_index}].repository_filter[{index}] has an unrecognized value shape")
            continue
        unknown_item = _unknown_item(unknown_value, index)
        filter_value = known_block_string(
            item,
            unknown_item,
            "filter",
            uncertainties,
            path=f"rule[{rule_index}].repository_filter[{index}]",
        )
        filter_type = known_block_string(
            item,
            unknown_item,
            "filter_type",
            uncertainties,
            path=f"rule[{rule_index}].repository_filter[{index}]",
        )
        record = {
            key: item_value
            for key, item_value in (("filter", filter_value), ("filter_type", filter_type))
            if item_value
        }
        if record:
            filters.append(record)
    return filters


def _unknown_item(value: Any, index: int) -> Any:
    if isinstance(value, list) and index < len(value):
        return value[index]
    return None


def _registry_scanning_coverage_state(value: Any, unknown_value: Any, rules: list[dict[str, Any]]) -> str:
    if unknown_value is True:
        return STATE_UNKNOWN
    if not as_list(value):
        return STATE_NOT_CONFIGURED
    if not rules:
        return STATE_UNKNOWN
    if any(not rule.get("scan_frequency") or not rule.get("repository_filters") for rule in rules):
        return STATE_UNKNOWN
    if any(
        repository_filter.get("filter") == "*" and repository_filter.get("filter_type") == "WILDCARD"
        for rule in rules
        for repository_filter in rule["repository_filters"]
    ):
        return "all_repositories"
    return "partial"
