from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast

from tfstride.models import TerraformResource
from tfstride.providers.azure.container_registry_references import normalize_container_registry_login_server
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.azure.resource_utils import (
    block_attribute_unknown,
    first_mapping,
    known_block_string,
    unknown_block_at,
)
from tfstride.providers.container_images import parse_container_image_reference

_WEB_APP_TYPES = frozenset({AzureResourceType.LINUX_WEB_APP, AzureResourceType.WINDOWS_WEB_APP})


def app_service_container_image_metadata(
    resource: TerraformResource,
    site_config: Mapping[str, Any] | None,
) -> dict[Any, object]:
    if resource.resource_type in _WEB_APP_TYPES:
        references, uncertainties = _web_app_images(resource, site_config)
    elif resource.resource_type == AzureResourceType.LINUX_FUNCTION_APP:
        references, uncertainties = _linux_function_app_images(resource, site_config)
    elif resource.resource_type == AzureResourceType.FUNCTION_APP:
        references, uncertainties = _legacy_function_app_images(resource, site_config)
    else:
        references, uncertainties = [], []
    return {
        AzureResourceMetadata.CONTAINER_IMAGE_REFERENCES: references,
        AzureResourceMetadata.CONTAINER_IMAGE_POSTURE_UNCERTAINTIES: uncertainties,
    }


def _web_app_images(
    resource: TerraformResource,
    site_config: Mapping[str, Any] | None,
) -> tuple[list[dict[str, Any]], list[str]]:
    uncertainties: list[str] = []
    unknown_site_config = unknown_block_at(resource.unknown_values.get("site_config"), 0)
    application_stack, unknown_stack = _nested_block(
        site_config,
        unknown_site_config,
        "application_stack",
        path="site_config.application_stack",
        uncertainties=uncertainties,
    )
    if application_stack is None:
        return [], uncertainties

    path = "site_config.application_stack[0]"
    image_name = known_block_string(
        application_stack,
        unknown_stack,
        "docker_image_name",
        uncertainties,
        path=path,
    )
    registry_url = known_block_string(
        application_stack,
        unknown_stack,
        "docker_registry_url",
        uncertainties,
        path=path,
    )
    if image_name is None and not block_attribute_unknown(unknown_stack, "docker_image_name"):
        return [], uncertainties

    unresolved_reason = _first_unresolved_reason(
        ("docker image name is unknown after planning", block_attribute_unknown(unknown_stack, "docker_image_name")),
        (
            "container registry URL is unknown after planning",
            block_attribute_unknown(unknown_stack, "docker_registry_url"),
        ),
    )
    return [
        _image_record(
            resource,
            path=f"{path}.docker_image_name",
            image_name=image_name,
            configured_fields={
                "docker_image_name": image_name,
                "docker_registry_url": registry_url,
            },
            uncertainties=uncertainties,
            registry_url=registry_url,
            unresolved_reason=unresolved_reason,
        )
    ], uncertainties


def _linux_function_app_images(
    resource: TerraformResource,
    site_config: Mapping[str, Any] | None,
) -> tuple[list[dict[str, Any]], list[str]]:
    uncertainties: list[str] = []
    unknown_site_config = unknown_block_at(resource.unknown_values.get("site_config"), 0)
    application_stack, unknown_stack = _nested_block(
        site_config,
        unknown_site_config,
        "application_stack",
        path="site_config.application_stack",
        uncertainties=uncertainties,
    )
    if application_stack is None:
        return [], uncertainties
    docker, unknown_docker = _nested_block(
        application_stack,
        unknown_stack,
        "docker",
        path="site_config.application_stack[0].docker",
        uncertainties=uncertainties,
    )
    if docker is None:
        return [], uncertainties

    path = "site_config.application_stack[0].docker[0]"
    image_name = known_block_string(docker, unknown_docker, "image_name", uncertainties, path=path)
    image_tag = known_block_string(docker, unknown_docker, "image_tag", uncertainties, path=path)
    registry_url = known_block_string(docker, unknown_docker, "registry_url", uncertainties, path=path)
    if image_name is None and not block_attribute_unknown(unknown_docker, "image_name"):
        return [], uncertainties

    unresolved_reason = _first_unresolved_reason(
        ("docker image name is unknown after planning", block_attribute_unknown(unknown_docker, "image_name")),
        ("docker image tag is unknown after planning", block_attribute_unknown(unknown_docker, "image_tag")),
        ("container registry URL is unknown after planning", block_attribute_unknown(unknown_docker, "registry_url")),
    )
    return [
        _image_record(
            resource,
            path=f"{path}.image_name",
            image_name=image_name,
            configured_fields={
                "image_name": image_name,
                "image_tag": image_tag,
                "registry_url": registry_url,
            },
            uncertainties=uncertainties,
            registry_url=registry_url,
            image_tag=image_tag,
            unresolved_reason=unresolved_reason,
        )
    ], uncertainties


def _legacy_function_app_images(
    resource: TerraformResource,
    site_config: Mapping[str, Any] | None,
) -> tuple[list[dict[str, Any]], list[str]]:
    uncertainties: list[str] = []
    unknown_site_config = unknown_block_at(resource.unknown_values.get("site_config"), 0)
    path = "site_config[0]"
    linux_fx_version = known_block_string(
        site_config,
        unknown_site_config,
        "linux_fx_version",
        uncertainties,
        path=path,
    )
    if linux_fx_version is None:
        return [], uncertainties
    prefix, separator, image_name = linux_fx_version.partition("|")
    if not separator or prefix.strip().upper() != "DOCKER":
        return [], uncertainties
    return [
        _image_record(
            resource,
            path=f"{path}.linux_fx_version",
            image_name=image_name,
            configured_fields={"linux_fx_version": linux_fx_version},
            uncertainties=uncertainties,
        )
    ], uncertainties


def _nested_block(
    parent: Mapping[str, Any] | None,
    unknown_parent: Any,
    key: str,
    *,
    path: str,
    uncertainties: list[str],
) -> tuple[Mapping[str, Any] | None, Any]:
    if unknown_parent is True:
        uncertainties.append(f"{path} is unknown after planning")
        return None, True
    unknown_mapping = cast(Mapping[str, Any], unknown_parent) if isinstance(unknown_parent, Mapping) else None
    raw_unknown = unknown_mapping.get(key) if unknown_mapping is not None else None
    unknown_block = unknown_block_at(raw_unknown, 0)
    raw = parent.get(key) if parent is not None else None
    if raw in (None, [], {}):
        if raw_unknown is True or unknown_block is True:
            uncertainties.append(f"{path} is unknown after planning")
            return None, True
        return None, unknown_block
    block = first_mapping(raw)
    if block is None:
        uncertainties.append(f"{path} has an unrecognized value shape")
    return block, unknown_block


def _image_record(
    resource: TerraformResource,
    *,
    path: str,
    image_name: str | None,
    configured_fields: Mapping[str, str | None],
    uncertainties: list[str],
    registry_url: str | None = None,
    image_tag: str | None = None,
    unresolved_reason: str | None = None,
) -> dict[str, Any]:
    explicit_unresolved_reason = unresolved_reason
    login_server = normalize_container_registry_login_server(registry_url)
    if registry_url and login_server is None and unresolved_reason is None:
        unresolved_reason = "container registry URL is unresolved"
        uncertainties.append(f"{path}: {unresolved_reason}")

    raw_reference = _compose_reference(image_name, image_tag, login_server)
    reference = parse_container_image_reference(raw_reference)
    if (
        login_server
        and reference.registry_host
        and reference.registry_host.lower() != login_server
        and unresolved_reason is None
    ):
        unresolved_reason = "image registry host does not match configured registry URL"
        uncertainties.append(f"{path}: {unresolved_reason}")
    if unresolved_reason is None:
        unresolved_reason = reference.unresolved_reason
    if (
        reference.unresolved_reason
        and explicit_unresolved_reason is None
        and not any(reference.unresolved_reason in item for item in uncertainties)
    ):
        uncertainties.append(f"{path}: {reference.unresolved_reason}")

    record: dict[str, Any] = {
        "source": resource.resource_type,
        "path": path,
        "raw": reference.raw,
        "registry_host": reference.registry_host,
        "repository": reference.repository,
        "tag": reference.tag,
        "digest": reference.digest,
        "digest_pinned": reference.digest_pinned,
        "is_resolved": reference.is_resolved and unresolved_reason is None,
    }
    for key, value in configured_fields.items():
        if value is not None:
            record[key] = value
    resolved_login_server = normalize_container_registry_login_server(reference.registry_host)
    if unresolved_reason is None and resolved_login_server:
        record["container_registry_login_server"] = resolved_login_server
    if unresolved_reason:
        record["unresolved_reason"] = unresolved_reason
    if reference.unresolved_value is not None:
        record["unresolved_value"] = reference.unresolved_value
    return record


def _compose_reference(
    image_name: str | None,
    image_tag: str | None,
    login_server: str | None,
) -> str | None:
    if image_name is None:
        return None
    image = image_name.strip()
    if image_tag:
        image = f"{image}:{image_tag.strip()}"
    parsed = parse_container_image_reference(image)
    if login_server and parsed.registry_host is None:
        return f"{login_server}/{image}"
    return image


def _first_unresolved_reason(*conditions: tuple[str, bool]) -> str | None:
    for reason, active in conditions:
        if active:
            return reason
    return None
