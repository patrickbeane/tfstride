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

    resources = _collect_module_resources(root_module)
    return TerraformPlan(
        source_path=str(plan_path),
        terraform_version=terraform_version,
        resources=resources,
    )


def _collect_module_resources(module: dict[str, Any]) -> list[TerraformResource]:
    resources: list[TerraformResource] = []
    for resource in module.get("resources", []):
        resources.append(
            TerraformResource(
                address=resource["address"],
                mode=resource.get("mode", "managed"),
                resource_type=resource["type"],
                name=resource["name"],
                provider_name=resource.get("provider_name", ""),
                values=resource.get("values", {}),
            )
        )
    # Terraform nests resources under child modules recursively; flatten them here so
    # the rest of the engine can analyze one uniform resource list.
    for child_module in module.get("child_modules", []):
        resources.extend(_collect_module_resources(child_module))
    return resources
