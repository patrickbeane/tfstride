from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from tfstride.models import TerraformResource
from tfstride.providers.coercion import value_is_unknown
from tfstride.providers.gcp.attributes import GcpAttr
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.kubernetes import unknown_block_at_index
from tfstride.providers.secret_settings import SensitiveSettingClassification, classify_sensitive_setting_name


def cloud_run_secret_metadata(
    resource: TerraformResource,
    containers: object,
    unknown_containers: object,
    *,
    path_prefix: str,
) -> dict[Any, object]:
    references, uncertainties = _cloud_run_secret_references(
        containers,
        unknown_containers,
        path_prefix=path_prefix,
    )
    for reference in references:
        reference["source"] = resource.resource_type
    return {
        GcpResourceMetadata.CLOUD_RUN_SECRET_REFERENCES: references,
        GcpResourceMetadata.CLOUD_RUN_SECRET_POSTURE_UNCERTAINTIES: uncertainties,
    }


def _cloud_run_secret_references(
    containers: object,
    unknown_containers: object,
    *,
    path_prefix: str,
) -> tuple[list[dict[str, Any]], list[str]]:
    references: list[dict[str, Any]] = []
    uncertainties: list[str] = []
    if unknown_containers is True:
        reason = f"{path_prefix} is unknown after planning"
        references.append(_gcp_unknown_secret_record(path_prefix, reason))
        uncertainties.append(reason)
        return references, uncertainties

    if containers in (None, "", [], {}):
        if value_is_unknown(unknown_containers):
            reason = f"{path_prefix} is unknown after planning"
            references.append(_gcp_unknown_secret_record(path_prefix, reason))
            uncertainties.append(reason)
        return references, uncertainties

    if isinstance(containers, Mapping):
        container_items: list[object] = [containers]
    elif isinstance(containers, list):
        container_items = containers
    else:
        reason = f"{path_prefix} has an unrecognized value shape"
        references.append(_gcp_unknown_secret_record(path_prefix, reason))
        uncertainties.append(reason)
        return references, uncertainties

    for container_index, container in enumerate(container_items):
        container_path = f"{path_prefix}[{container_index}]"
        if not isinstance(container, Mapping):
            reason = f"{container_path} is not an object"
            references.append(_gcp_unknown_secret_record(container_path, reason))
            uncertainties.append(reason)
            continue

        unknown_container = unknown_block_at_index(
            unknown_containers,
            container_index,
            mapping_applies_to_any_index=True,
        )
        container_name = container.get(GcpAttr.NAME.key) if isinstance(container.get(GcpAttr.NAME.key), str) else None
        env = container.get(GcpAttr.ENV.key)
        env_unknown = _cloud_run_nested_unknown(unknown_container, (GcpAttr.ENV.key,))
        env_path = f"{container_path}.env"

        if env is None and not env_unknown:
            continue
        if env_unknown and env in (None, "", [], {}):
            reason = f"{env_path} is unknown after planning"
            references.append(_gcp_unknown_secret_record(env_path, reason, container_name=container_name))
            uncertainties.append(reason)
            continue

        if isinstance(env, Mapping):
            env_items: list[object] = [env]
        elif isinstance(env, list):
            env_items = env
        else:
            reason = f"{env_path} has an unrecognized value shape"
            references.append(_gcp_unknown_secret_record(env_path, reason, container_name=container_name))
            uncertainties.append(reason)
            continue

        unknown_env = _cloud_run_nested_value(unknown_container, (GcpAttr.ENV.key,))
        for env_index, env_item in enumerate(env_items):
            item_path = f"{env_path}[{env_index}]"
            if not isinstance(env_item, Mapping):
                reason = f"{item_path} is not an object"
                references.append(_gcp_unknown_secret_record(item_path, reason, container_name=container_name))
                uncertainties.append(reason)
                continue

            unknown_item = unknown_block_at_index(
                unknown_env,
                env_index,
                mapping_applies_to_any_index=True,
            )
            name_unknown = _cloud_run_nested_unknown(unknown_item, (GcpAttr.NAME.key,))
            setting_name = env_item.get(GcpAttr.NAME.key) if isinstance(env_item.get(GcpAttr.NAME.key), str) else None
            classification = classify_sensitive_setting_name(setting_name)

            secret_record, secret_reasons = _cloud_run_secret_source(
                env_item,
                unknown_item,
                item_path,
                container_name=container_name,
                setting_name=setting_name,
                classification=classification,
            )
            if secret_record is not None:
                references.append(secret_record)
                uncertainties.extend(secret_reasons)
                continue

            value_unknown = _cloud_run_nested_unknown(unknown_item, (GcpAttr.VALUE.key,))
            value_present = GcpAttr.VALUE.key in env_item
            if classification is None and not name_unknown:
                continue

            if value_unknown or not value_present or env_item.get(GcpAttr.VALUE.key) is None:
                reason = (
                    f"{item_path}.{GcpAttr.VALUE.key} is unknown after planning"
                    if value_unknown
                    else f"{item_path}.{GcpAttr.VALUE.key} is not represented"
                )
                references.append(
                    _gcp_unknown_secret_record(
                        item_path,
                        reason,
                        container_name=container_name,
                        setting_name=setting_name,
                        classification=classification,
                    )
                )
                uncertainties.append(reason)
                continue

            references.append(
                _gcp_secret_record_base(
                    item_path,
                    container_name=container_name,
                    setting_name=setting_name,
                    classification=classification,
                    value_path=f"{item_path}.{GcpAttr.VALUE.key}",
                    state="literal",
                    is_resolved=True,
                )
            )
    return references, uncertainties


def _cloud_run_secret_source(
    item: Mapping[str, Any],
    unknown_item: object,
    item_path: str,
    *,
    container_name: str | None,
    setting_name: str | None,
    classification: SensitiveSettingClassification | None,
) -> tuple[dict[str, Any] | None, list[str]]:
    source_specs = (
        (GcpAttr.VALUE_FROM.key, GcpAttr.NAME.key, GcpAttr.KEY.key),
        (GcpAttr.VALUE_SOURCE.key, GcpAttr.SECRET.key, GcpAttr.VERSION.key),
    )
    for source_key, reference_key, version_key in source_specs:
        source_unknown = _cloud_run_nested_unknown(unknown_item, (source_key,))
        if source_key not in item and not source_unknown:
            continue

        source_path = f"{item_path}.{source_key}"
        if source_unknown and source_key not in item:
            reason = f"{source_path} is unknown after planning"
            return (
                _gcp_unknown_secret_record(
                    item_path,
                    reason,
                    container_name=container_name,
                    setting_name=setting_name,
                    classification=classification,
                ),
                [reason],
            )

        source = _first_mapping(item.get(source_key))
        if source is None:
            reason = f"{source_path} has an unrecognized value shape"
            return (
                _gcp_unknown_secret_record(
                    item_path,
                    reason,
                    container_name=container_name,
                    setting_name=setting_name,
                    classification=classification,
                ),
                [reason],
            )

        secret_key_ref_path = f"{source_path}[0].secret_key_ref"
        secret_key_ref_unknown = _cloud_run_nested_unknown(
            unknown_item,
            (source_key, GcpAttr.SECRET_KEY_REF.key),
        )
        secret_key_ref = _first_mapping(source.get(GcpAttr.SECRET_KEY_REF.key))
        if secret_key_ref is None:
            reason = (
                f"{secret_key_ref_path} is unknown after planning"
                if secret_key_ref_unknown
                else f"{secret_key_ref_path} is not represented"
            )
            return (
                _gcp_unknown_secret_record(
                    item_path,
                    reason,
                    container_name=container_name,
                    setting_name=setting_name,
                    classification=classification,
                ),
                [reason],
            )

        reference_path = f"{secret_key_ref_path}.{reference_key}"
        reference_unknown = _cloud_run_nested_unknown(
            unknown_item,
            (source_key, GcpAttr.SECRET_KEY_REF.key, reference_key),
        )
        raw_reference = secret_key_ref.get(reference_key)
        if reference_unknown or not isinstance(raw_reference, str) or not raw_reference.strip():
            reason = (
                f"{reference_path} is unknown after planning"
                if reference_unknown
                else f"{reference_path} is not represented as a non-empty string"
            )
            return (
                _gcp_unknown_secret_record(
                    item_path,
                    reason,
                    container_name=container_name,
                    setting_name=setting_name,
                    classification=classification,
                ),
                [reason],
            )

        reference = raw_reference.strip()
        version_path = f"{secret_key_ref_path}.{version_key}"
        version_unknown = _cloud_run_nested_unknown(
            unknown_item,
            (source_key, GcpAttr.SECRET_KEY_REF.key, version_key),
        )
        raw_version = secret_key_ref.get(version_key)
        reasons: list[str] = []
        if version_unknown:
            version_state = "unknown"
            version = None
            reasons.append(f"{version_path} is unknown after planning")
        elif not isinstance(raw_version, str) or not raw_version.strip():
            version_state = "unknown"
            version = None
            reasons.append(f"{version_path} is not represented as a non-empty string")
        else:
            version = raw_version.strip()
            if _looks_like_gcp_terraform_reference(version):
                version_state = "unresolved"
                reasons.append(f"{version_path} is an unresolved Terraform reference")
            else:
                version_state = "configured"

        reference_unresolved = _looks_like_gcp_terraform_reference(reference)
        record = _gcp_secret_record_base(
            item_path,
            container_name=container_name,
            setting_name=setting_name,
            classification=classification,
            value_path=f"{item_path}.{source_key}",
            state="reference",
            is_resolved=not reference_unresolved,
        )
        record.update(
            {
                "reference": reference,
                "reference_kind": "terraform" if reference_unresolved else "secret_manager",
                "secret_reference": reference,
                "secret_name": reference,
                "secret_version": version,
                "version": version,
                "secret_version_state": version_state,
                "version_path": version_path,
                "secret_reference_path": reference_path,
                "target_resolution": "unresolved" if reference_unresolved else "resolved",
            }
        )
        if reference_unresolved:
            record["unresolved_reference"] = reference
            record["unresolved_reason"] = "Terraform Secret Manager reference is unresolved during normalization"
            reasons.insert(0, f"{reference_path} is an unresolved Terraform reference")
        if version_state == "unresolved":
            record["unresolved_version"] = version
        return record, reasons

    return None, []


def _gcp_secret_record_base(
    path: str,
    *,
    container_name: str | None,
    setting_name: str | None,
    classification: SensitiveSettingClassification | None,
    value_path: str,
    state: str,
    is_resolved: bool,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "source": "cloud_run_environment",
        "path": path,
        "value_path": value_path,
        "container_name": container_name,
        "setting_name": setting_name,
        "state": state,
        "is_resolved": is_resolved,
    }
    if classification is not None:
        record["normalized_setting_name"] = classification.normalized_name
        record["sensitive_category"] = classification.category.value
    return record


def _gcp_unknown_secret_record(
    path: str,
    reason: str,
    *,
    container_name: str | None = None,
    setting_name: str | None = None,
    classification: SensitiveSettingClassification | None = None,
) -> dict[str, Any]:
    return _gcp_secret_record_base(
        path,
        container_name=container_name,
        setting_name=setting_name,
        classification=classification,
        value_path=f"{path}.{GcpAttr.VALUE.key}",
        state="unknown",
        is_resolved=False,
    ) | {"unresolved_reason": reason}


def _first_mapping(value: object) -> Mapping[str, Any] | None:
    if isinstance(value, Mapping):
        return value
    if isinstance(value, list):
        for item in value:
            if isinstance(item, Mapping):
                return item
    return None


def _cloud_run_nested_value(value: object, keys: tuple[str, ...]) -> object:
    current = value
    for key in keys:
        while isinstance(current, list):
            current = current[0] if current and isinstance(current[0], Mapping) else None
        if current is True:
            return True
        if isinstance(current, Mapping):
            current = current.get(key)
        else:
            return None
    return current


def _cloud_run_nested_unknown(value: object, keys: tuple[str, ...]) -> bool:
    return value_is_unknown(_cloud_run_nested_value(value, keys))


def _looks_like_gcp_terraform_reference(value: str) -> bool:
    markers = (
        "$" + "{",
        "google_secret_manager_secret.",
        "google_secret_manager_secret_version.",
    )
    return any(marker in value for marker in markers)
