"""Plan ingestion and constructor measurements shared by GCS tests and benchmarks."""

from __future__ import annotations

import json
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from unittest.mock import patch

from tfstride.app import TfStride
from tfstride.models import AnalysisResult, TerraformResource
from tfstride.providers.gcp.gcs_grant_evaluation import GcsGrantConstraintContext
from tfstride.providers.gcp.resource_index import GcpResourceIndexBuilder


def plan_payload(resources: Sequence[TerraformResource]) -> dict[str, Any]:
    return {
        "format_version": "1.2",
        "terraform_version": "1.9.0",
        "planned_values": {
            "root_module": {
                "resources": [
                    {
                        "address": resource.address,
                        "type": resource.resource_type,
                        "name": resource.name,
                        "mode": resource.mode,
                        "provider_name": resource.provider_name,
                        "values": resource.values,
                    }
                    for resource in resources
                ]
            }
        },
        "resource_changes": [
            {"address": resource.address, "change": {"after_unknown": resource.unknown_values}}
            for resource in resources
            if resource.unknown_values
        ],
    }


@contextmanager
def plan_file(resources: Sequence[TerraformResource]) -> Iterator[Path]:
    with TemporaryDirectory(prefix="tfstride-gcs-characterization-") as directory:
        path = Path(directory) / "gcs-contexts.tfplan.json"
        path.write_text(json.dumps(plan_payload(resources)), encoding="utf-8")
        yield path


def analyze_with_counts(path: Path, engine: TfStride) -> tuple[AnalysisResult, dict[str, int]]:
    """Measure one complete analysis, including normalization, rules, and gap collection.

    Wrappers call the real constructors. Benchmarks time a separate unpatched run.
    """
    with (
        patch.object(GcsGrantConstraintContext, "build", wraps=GcsGrantConstraintContext.build) as contexts,
        patch.object(
            GcpResourceIndexBuilder,
            "build",
            autospec=True,
            side_effect=GcpResourceIndexBuilder.build,
        ) as indexes,
    ):
        result = engine.analyze_plan(path)
    return result, {"gcs_context_builds": contexts.call_count, "gcp_resource_index_builds": indexes.call_count}
