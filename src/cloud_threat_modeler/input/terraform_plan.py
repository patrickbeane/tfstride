from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cloud_threat_modeler.models import TerraformPlan, TerraformResource


def load_terraform_plan(path: str | Path) -> TerraformPlan:
    plan_path = Path(path)
    payload = json.loads(plan_path.read_text(encoding="utf-8"))
    root_module = payload.get("planned_values", {}).get("root_module", {})
    resources = _collect_module_resources(root_module)
    return TerraformPlan(
        source_path=str(plan_path),
        terraform_version=payload.get("terraform_version"),
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
