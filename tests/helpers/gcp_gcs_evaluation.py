"""Plan ingestion and constructor measurements shared by GCS tests and benchmarks."""

from __future__ import annotations

import json
from collections.abc import Iterator, Sequence
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from unittest.mock import patch

from tfstride.app import TfStride
from tfstride.models import AnalysisResult, NormalizedResource, TerraformResource
from tfstride.providers.gcp.gcs_grant_evaluation import GcsGrantConstraintContext
from tfstride.providers.gcp.gcs_project_grants import BucketIamManager, bucket_iam_managers
from tfstride.providers.gcp.resource_index import GcpResourceIndex, GcpResourceIndexBuilder


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


@dataclass(slots=True)
class _GrantQueryStats:
    queries: int = 0
    source_scans: int = 0
    # Hold contexts so object ids stay unique for the whole measured analysis.
    contexts: dict[int, GcsGrantConstraintContext] = field(default_factory=dict)
    distinct: set[tuple[int, str, str]] = field(default_factory=set)


@contextmanager
def _count_grant_queries(stats: _GrantQueryStats) -> Iterator[None]:
    """Count grant queries and the IAM-source scanning done to select each bucket's managers."""
    original_bindings = GcsGrantConstraintContext.bindings

    def counting_bindings(
        self: GcsGrantConstraintContext, principal: str, bucket: NormalizedResource
    ) -> tuple[list[dict[str, object]], list[str]]:
        stats.queries += 1
        stats.contexts[id(self)] = self
        stats.distinct.add((id(self), principal, bucket.address))
        return original_bindings(self, principal, bucket)

    def counting_managers(
        bucket: NormalizedResource,
        sources: Sequence[NormalizedResource],
        index: GcpResourceIndex,
    ) -> tuple[BucketIamManager, ...]:
        stats.source_scans += len(sources)
        return bucket_iam_managers(bucket, sources, index)

    with (
        patch.object(GcsGrantConstraintContext, "bindings", counting_bindings),
        patch("tfstride.providers.gcp.gcs_grant_evaluation.bucket_iam_managers", counting_managers),
    ):
        yield


def analyze_with_counts(
    path: Path, engine: TfStride, *, grant_queries: bool = False
) -> tuple[AnalysisResult, dict[str, int]]:
    """Measure one complete analysis, including normalization, rules, and gap collection.

    Wrappers call the real constructors. Benchmarks time a separate unpatched run.
    With `grant_queries`, also report how often grants are queried and how many IAM
    sources those queries scan; the extra counts are omitted otherwise so recorded
    constructor baselines keep their shape.
    """
    stats = _GrantQueryStats()
    with ExitStack() as stack:
        contexts = stack.enter_context(
            patch.object(GcsGrantConstraintContext, "build", wraps=GcsGrantConstraintContext.build)
        )
        indexes = stack.enter_context(
            patch.object(
                GcpResourceIndexBuilder,
                "build",
                autospec=True,
                side_effect=GcpResourceIndexBuilder.build,
            )
        )
        if grant_queries:
            stack.enter_context(_count_grant_queries(stats))
        result = engine.analyze_plan(path)
    counts = {"gcs_context_builds": contexts.call_count, "gcp_resource_index_builds": indexes.call_count}
    if grant_queries:
        counts |= {
            "grant_binding_queries": stats.queries,
            "distinct_grant_binding_queries": len(stats.distinct),
            "grant_source_scans": stats.source_scans,
        }
    return result, counts
