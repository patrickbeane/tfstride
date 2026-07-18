from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from tfstride.models import TerraformResource
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.resource_utils import attribute_unknown, known_string, value_is_unknown
from tfstride.providers.coercion import STATE_CONFIGURED, STATE_NOT_CONFIGURED
from tfstride.providers.secret_settings import SensitiveSettingClassification, classify_sensitive_setting_name

_KEY_VAULT_REFERENCE_PATTERN = re.compile(
    r"@Microsoft\.KeyVault\(\s*SecretUri\s*=\s*(?P<uri>[^)]+?)\s*\)",
    re.IGNORECASE,
)
_KEY_VAULT_DNS_SUFFIXES = (
    ".vault.azure.net",
    ".vault.azure.cn",
    ".vault.usgovcloudapi.net",
    ".vault.microsoftazure.de",
)
_KEY_VAULT_PATH_SEGMENT_PATTERN = re.compile(r"[A-Za-z0-9-]+")
_UNRESOLVED_MARKERS = ("${", "<known after apply>", "(known after apply)", "known after apply")


@dataclass(frozen=True, slots=True)
class _KeyVaultSecretReference:
    reference: str
    vault_uri: str
    secret_uri: str
    versionless_secret_uri: str
    secret_name: str
    secret_version: str | None


def app_service_secret_delivery_metadata(resource: TerraformResource) -> dict[Any, object]:
    references, uncertainties = _app_setting_secret_references(resource)
    identity_uncertainties: list[str] = []
    key_vault_reference_identity_id = known_string(
        resource.values,
        resource.unknown_values,
        "key_vault_reference_identity_id",
        identity_uncertainties,
        require_string=True,
    )
    uncertainties.extend(identity_uncertainties)

    metadata: dict[Any, object] = {
        AzureResourceMetadata.APP_SERVICE_SECRET_REFERENCES: references,
        AzureResourceMetadata.APP_SERVICE_SECRET_POSTURE_UNCERTAINTIES: uncertainties,
    }
    if key_vault_reference_identity_id is not None:
        metadata[AzureResourceMetadata.APP_SERVICE_KEY_VAULT_REFERENCE_IDENTITY_ID] = key_vault_reference_identity_id
    return metadata


def _app_setting_secret_references(
    resource: TerraformResource,
) -> tuple[list[dict[str, Any]], list[str]]:
    values = resource.values
    unknown_values = resource.unknown_values
    app_settings = values.get("app_settings")
    unknown_app_settings = unknown_values.get("app_settings")
    references: list[dict[str, Any]] = []
    uncertainties: list[str] = []

    if attribute_unknown(unknown_values, "app_settings") and not isinstance(app_settings, Mapping):
        reason = "app_settings is unknown after planning"
        references.append(_unknown_secret_record("app_settings", reason, source=resource.resource_type))
        uncertainties.append(reason)
        return references, uncertainties
    if app_settings in (None, "", {}):
        return references, uncertainties
    if not isinstance(app_settings, Mapping):
        reason = "app_settings has an unrecognized value shape"
        references.append(_unknown_secret_record("app_settings", reason, source=resource.resource_type))
        uncertainties.append(reason)
        return references, uncertainties

    for raw_name in sorted(app_settings, key=str):
        setting_name = str(raw_name)
        path = f"app_settings[{setting_name!r}]"
        classification = classify_sensitive_setting_name(setting_name)
        raw_value = app_settings[raw_name]
        value_unknown = _app_setting_value_unknown(unknown_app_settings, raw_name)

        if value_unknown or _looks_unresolved(raw_value):
            if classification is None and not _looks_like_key_vault_reference(raw_value):
                continue
            reason = f"{path} is unknown after planning"
            references.append(
                _unknown_secret_record(
                    path,
                    reason,
                    source=resource.resource_type,
                    setting_name=setting_name,
                    classification=classification,
                )
            )
            uncertainties.append(reason)
            continue

        parsed_reference = _parse_key_vault_secret_reference(raw_value)
        if parsed_reference is not None:
            references.append(
                _key_vault_secret_record(
                    path,
                    source=resource.resource_type,
                    setting_name=setting_name,
                    classification=classification,
                    parsed=parsed_reference,
                )
            )
            continue

        if _looks_like_key_vault_reference(raw_value):
            reason = f"{path} contains an unsupported Key Vault reference"
            references.append(
                _unresolved_key_vault_record(
                    path,
                    reason,
                    source=resource.resource_type,
                    setting_name=setting_name,
                    classification=classification,
                )
            )
            uncertainties.append(reason)
            continue

        if classification is not None:
            references.append(
                _secret_record_base(
                    path,
                    source=resource.resource_type,
                    setting_name=setting_name,
                    classification=classification,
                    state="literal",
                    is_resolved=True,
                )
            )

    return references, uncertainties


def _parse_key_vault_secret_reference(value: object) -> _KeyVaultSecretReference | None:
    if not isinstance(value, str):
        return None
    reference = value.strip()
    match = _KEY_VAULT_REFERENCE_PATTERN.fullmatch(reference)
    if match is None:
        return None
    raw_uri = match.group("uri").strip()
    try:
        parsed = urlsplit(raw_uri)
        port = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        return None

    host = parsed.hostname.lower().rstrip(".")
    if not _is_key_vault_host(host):
        return None
    segments = parsed.path.split("/")
    if len(segments) not in (3, 4) or segments[0] or segments[1].lower() != "secrets":
        return None
    secret_name = segments[2]
    secret_version = segments[3] if len(segments) == 4 else None
    if not _valid_key_vault_path_segment(secret_name) or (
        secret_version is not None and not _valid_key_vault_path_segment(secret_version)
    ):
        return None

    vault_uri = f"https://{host}"
    versionless_secret_uri = f"{vault_uri}/secrets/{secret_name}"
    secret_uri = f"{versionless_secret_uri}/{secret_version}" if secret_version else versionless_secret_uri
    return _KeyVaultSecretReference(
        reference=reference,
        vault_uri=vault_uri,
        secret_uri=secret_uri,
        versionless_secret_uri=versionless_secret_uri,
        secret_name=secret_name,
        secret_version=secret_version,
    )


def _key_vault_secret_record(
    path: str,
    *,
    source: str,
    setting_name: str,
    classification: SensitiveSettingClassification | None,
    parsed: _KeyVaultSecretReference,
) -> dict[str, Any]:
    record = _secret_record_base(
        path,
        source=source,
        setting_name=setting_name,
        classification=classification,
        state="reference",
        is_resolved=True,
    )
    record.update(
        {
            "reference": parsed.reference,
            "reference_kind": "key_vault_secret_uri",
            "target_resolution": "resolved",
            "key_vault_uri": parsed.vault_uri,
            "key_vault_secret_uri": parsed.secret_uri,
            "key_vault_secret_versionless_uri": parsed.versionless_secret_uri,
            "key_vault_secret_name": parsed.secret_name,
            "key_vault_secret_version": parsed.secret_version,
            "secret_version_state": (STATE_CONFIGURED if parsed.secret_version is not None else STATE_NOT_CONFIGURED),
        }
    )
    return record


def _unresolved_key_vault_record(
    path: str,
    reason: str,
    *,
    source: str,
    setting_name: str,
    classification: SensitiveSettingClassification | None,
) -> dict[str, Any]:
    record = _secret_record_base(
        path,
        source=source,
        setting_name=setting_name,
        classification=classification,
        state="reference",
        is_resolved=False,
    )
    record.update(
        {
            "reference_kind": "key_vault",
            "target_resolution": "unresolved",
            "unresolved_reason": reason,
        }
    )
    return record


def _unknown_secret_record(
    path: str,
    reason: str,
    *,
    source: str,
    setting_name: str | None = None,
    classification: SensitiveSettingClassification | None = None,
) -> dict[str, Any]:
    return _secret_record_base(
        path,
        source=source,
        setting_name=setting_name,
        classification=classification,
        state="unknown",
        is_resolved=False,
    ) | {"unresolved_reason": reason}


def _secret_record_base(
    path: str,
    *,
    source: str,
    setting_name: str | None,
    classification: SensitiveSettingClassification | None,
    state: str,
    is_resolved: bool,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "source": source,
        "path": path,
        "setting_name": setting_name,
        "state": state,
        "is_resolved": is_resolved,
    }
    if classification is not None:
        record["normalized_setting_name"] = classification.normalized_name
        record["sensitive_category"] = classification.category.value
    return record


def _is_key_vault_host(host: str) -> bool:
    for suffix in _KEY_VAULT_DNS_SUFFIXES:
        if not host.endswith(suffix):
            continue
        vault_name = host[: -len(suffix)]
        return bool(vault_name) and "." not in vault_name
    return False


def _valid_key_vault_path_segment(value: str) -> bool:
    return _KEY_VAULT_PATH_SEGMENT_PATTERN.fullmatch(value) is not None


def _looks_like_key_vault_reference(value: object) -> bool:
    return isinstance(value, str) and value.strip().lower().startswith("@microsoft.keyvault(")


def _looks_unresolved(value: object) -> bool:
    return isinstance(value, str) and any(marker in value.lower() for marker in _UNRESOLVED_MARKERS)


def _app_setting_value_unknown(unknown_app_settings: object, key: object) -> bool:
    if unknown_app_settings is True:
        return True
    if not isinstance(unknown_app_settings, Mapping):
        return False
    return value_is_unknown(unknown_app_settings.get(key))
