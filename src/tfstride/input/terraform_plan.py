from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from tfstride.models import TerraformPlan, TerraformResource


class TerraformPlanLoadError(ValueError):
    """Raised when an input file is not a usable Terraform plan JSON document."""


def load_terraform_plan(path: str | Path) -> TerraformPlan:
    plan_path = Path(path)
    try:
        payload = json.loads(plan_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise TerraformPlanLoadError(f"Terraform plan file not found: {plan_path}") from exc
    except json.JSONDecodeError as exc:
        raise TerraformPlanLoadError(f"Failed to parse Terraform plan JSON in {plan_path}: {exc.msg}") from exc

    if not isinstance(payload, dict):
        raise TerraformPlanLoadError(f"Terraform plan input must be a JSON object: {plan_path}")

    terraform_version = payload.get("terraform_version")
    if not isinstance(terraform_version, str) or not terraform_version:
        raise TerraformPlanLoadError(
            f"Input is not a Terraform plan JSON document: missing `terraform_version` in {plan_path}"
        )

    planned_values = payload.get("planned_values")
    if not isinstance(planned_values, dict):
        raise TerraformPlanLoadError(
            f"Input is not a Terraform plan JSON document: missing `planned_values` object in {plan_path}"
        )

    root_module = planned_values.get("root_module")
    if not isinstance(root_module, dict):
        raise TerraformPlanLoadError(
            f"Input is not a Terraform plan JSON document: missing `planned_values.root_module` in {plan_path}"
        )

    resources = _collect_module_resources(
        root_module,
        plan_path=plan_path,
        module_path="planned_values.root_module",
    )
    return TerraformPlan(
        source_path=str(plan_path),
        terraform_version=terraform_version,
        resources=resources,
    )


def _collect_module_resources(
    module: dict[str, Any],
    *,
    plan_path: Path,
    module_path: str,
) -> list[TerraformResource]:
    resources: list[TerraformResource] = []
    raw_resources = module.get("resources", [])
    if raw_resources is None:
        raw_resources = []
    if not isinstance(raw_resources, list):
        raise TerraformPlanLoadError(f"`{module_path}.resources` must be an array in {plan_path}")

    for index, resource in enumerate(raw_resources):
        resource_path = f"{module_path}.resources[{index}]"
        if not isinstance(resource, dict):
            raise TerraformPlanLoadError(f"`{resource_path}` must be an object in {plan_path}")
        address = _required_string(resource, "address", resource_path, plan_path)
        resource_type = _required_string(resource, "type", resource_path, plan_path)
        name = _required_string(resource, "name", resource_path, plan_path)
        mode = _optional_string(resource, "mode", resource_path, plan_path, default="managed")
        provider_name = _optional_string(resource, "provider_name", resource_path, plan_path, default="")
        values = resource.get("values", {})
        if values is None:
            values = {}
        if not isinstance(values, dict):
            raise TerraformPlanLoadError(f"`{resource_path}.values` must be an object in {plan_path}")
        resources.append(
            TerraformResource(
                address=address,
                mode=mode,
                resource_type=resource_type,
                name=name,
                provider_name=provider_name,
                values=values,
            )
        )
    # Terraform nests resources under child modules recursively; flatten them here so
    # the rest of the engine can analyze one uniform resource list.
    raw_child_modules = module.get("child_modules", [])
    if raw_child_modules is None:
        raw_child_modules = []
    if not isinstance(raw_child_modules, list):
        raise TerraformPlanLoadError(f"`{module_path}.child_modules` must be an array in {plan_path}")

    for index, child_module in enumerate(raw_child_modules):
        child_module_path = f"{module_path}.child_modules[{index}]"
        if not isinstance(child_module, dict):
            raise TerraformPlanLoadError(f"`{child_module_path}` must be an object in {plan_path}")
        resources.extend(
            _collect_module_resources(
                child_module,
                plan_path=plan_path,
                module_path=child_module_path,
            )
        )
    return resources


def _required_string(
    payload: dict[str, Any],
    key: str,
    resource_path: str,
    plan_path: Path,
) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise TerraformPlanLoadError(f"`{resource_path}.{key}` must be a non-empty string in {plan_path}")
    return value

	
def _optional_string(
    payload: dict[str, Any],
    key: str,
    resource_path: str,
    plan_path: Path,
    *,
    default: str,
) -> str:
    value = payload.get(key, default)
    if value is None:
        return default
    if not isinstance(value, str):
        raise TerraformPlanLoadError(f"`{resource_path}.{key}` must be a string in {plan_path}")
    return value 
