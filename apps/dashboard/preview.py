from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import cast

from fastapi import FastAPI

from apps.dashboard.scenarios import (
    DEMO_SCENARIO_DEFINITIONS,
    FIXTURES_DIR,
    PROVIDER_DISPLAY_NAMES,
    DemoScenarioDefinition,
)
from tfstride.app import TfStride
from tfstride.input.terraform_plan import TerraformPlanLoadError
from tfstride.reporting.json_report import build_json_report_payload
from tfstride.reporting.report_contract import (
    FindingPayload,
    ObservationPayload,
    ReportSummaryPayload,
    TrustBoundaryPayload,
)


@dataclass(frozen=True, slots=True)
class DemoPreview:
    scenario: DemoScenarioDefinition
    provider_display_name: str
    summary: ReportSummaryPayload
    findings: tuple[FindingPayload, ...]
    boundary: TrustBoundaryPayload | None
    observations: tuple[ObservationPayload, ...]
    observed_controls: int
    operation_gaps: int
    unresolved_references: int


def build_demo_preview(engine: TfStride, *, fixtures_dir: Path = FIXTURES_DIR) -> DemoPreview | None:
    """Select a small report excerpt without maintaining a second report fixture."""
    scenario = next(item for item in DEMO_SCENARIO_DEFINITIONS if item.scenario_id == "ecs-fargate")
    plan_path = fixtures_dir / scenario.fixture_name
    if not plan_path.is_file():
        return None
    try:
        result = engine.analyze_plan(plan_path, title=scenario.report_title)
    except TerraformPlanLoadError:
        return None

    payload = build_json_report_payload(result)
    boundaries = payload["trust_boundaries"]
    return DemoPreview(
        scenario=scenario,
        provider_display_name=PROVIDER_DISPLAY_NAMES[scenario.fixture_name.split("/", 1)[0]],
        summary=payload["summary"],
        findings=tuple(payload["findings"][:2]),
        boundary=next((boundary for boundary in boundaries if boundary["source"] == "internet"), None),
        observations=tuple(payload["observations"][:1]),
        observed_controls=len(payload["observations"]),
        operation_gaps=len(payload["operation_gaps"]["records"]),
        unresolved_references=payload["analysis_coverage"]["references"]["unresolved_reference_count"],
    )


def get_demo_preview(app: FastAPI, engine: TfStride) -> DemoPreview | None:
    """Called through the app's execution gate; only built-in demo data is cached."""
    if not hasattr(app.state, "demo_preview"):
        app.state.demo_preview = build_demo_preview(engine)
    return cast(DemoPreview | None, app.state.demo_preview)
