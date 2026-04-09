from __future__ import annotations

import inspect
import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi import FastAPI, File, Form, HTTPException, Path as FastApiPath, Request, UploadFile
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from apps.dashboard.api_models import (
    CloudThreatModelReportModel,
    DashboardApiErrorModel,
    HealthResponseModel,
    ValidationErrorResponseModel,
)
from cloud_threat_modeler.app import CloudThreatModeler
from cloud_threat_modeler.input.terraform_plan import TerraformPlanLoadError


APP_ROOT = Path(__file__).resolve().parent
REPO_ROOT = APP_ROOT.parents[1]
FIXTURES_DIR = REPO_ROOT / "fixtures"
TEMPLATES = Jinja2Templates(directory=str(APP_ROOT / "templates"))
TEMPLATE_RESPONSE_ACCEPTS_REQUEST = "request" in inspect.signature(TEMPLATES.TemplateResponse).parameters
MAX_UPLOAD_BYTES = 10 * 1024 * 1024
DEFAULT_REPORT_TITLE = "Cloud Threat Model Report"
DOCS_CHROME_HIDE_STYLE = """
<style>
  .swagger-ui .topbar {
    display: none !important;
  }

  .swagger-ui section.models {
    display: none !important;
  }

  a[href$="/openapi.json"],
  a[href="openapi.json"],
  .swagger-ui a[href$="/openapi.json"],
  .swagger-ui a[href="openapi.json"] {
    display: none !important;
  }
</style>
"""
DOCS_LINK_CLEANUP_SCRIPT = """
<script>
  const hideOpenApiChrome = () => {
    for (const link of document.querySelectorAll('a[href$="/openapi.json"], a[href="openapi.json"]')) {
      const container = link.closest("div, span, p, section, article, li") || link;
      container.style.display = "none";
    }
  };

  window.addEventListener("load", () => {
    hideOpenApiChrome();
    window.setTimeout(hideOpenApiChrome, 250);
    window.setTimeout(hideOpenApiChrome, 1000);
  });
</script>
"""
HTML_LANDING_EXAMPLE = "<!doctype html><html><body><main>Cloud Threat Modeler dashboard landing page</main></body></html>"
HTML_REPORT_EXAMPLE = "<!doctype html><html><body><main>Cloud Threat Modeler report page</main></body></html>"
API_ERROR_EXAMPLE = {
    "kind": "cloud-threat-model-error",
    "message": "Upload a non-empty Terraform plan JSON file.",
}
UPLOAD_VALIDATION_ERROR_EXAMPLE = {
    "detail": [
        {
            "loc": ["body", "plan"],
            "msg": "Field required",
            "type": "missing",
            "input": None,
            "ctx": None,
        }
    ]
}


class DashboardInputError(ValueError):
    """Raised when an uploaded plan cannot be analyzed by the dashboard."""


@dataclass(slots=True)
class DashboardAnalysis:
    payload: dict[str, object]
    markdown_report: str


@dataclass(frozen=True, slots=True)
class DemoScenarioDefinition:
    scenario_id: str
    title: str
    report_title: str
    fixture_name: str
    description: str
    emphasis: str
    theme: str


@dataclass(frozen=True, slots=True)
class DemoScenario:
    scenario_id: str
    title: str
    report_title: str
    fixture_name: str
    fixture_path: str
    description: str
    emphasis: str
    theme: str
    normalized_resources: int
    trust_boundaries: int
    active_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int


DEMO_SCENARIO_DEFINITIONS = (
    DemoScenarioDefinition(
        scenario_id="safe",
        title="Safe Plan",
        report_title="Safe Plan Demo",
        fixture_name="sample_aws_safe_plan.json",
        description="Private-by-default AWS infrastructure with guarded storage, private database access, and no active findings.",
        emphasis="Quiet reference architecture",
        theme="safe",
    ),
    DemoScenarioDefinition(
        scenario_id="baseline",
        title="Baseline Plan",
        report_title="Baseline Plan Demo",
        fixture_name="sample_aws_baseline_plan.json",
        description="Mostly segmented AWS infrastructure with a small IAM hygiene issue and a non-obvious private-data path.",
        emphasis="Calibrated baseline",
        theme="balanced",
    ),
    DemoScenarioDefinition(
        scenario_id="mixed",
        title="Mixed AWS Plan",
        report_title="Mixed AWS Plan Demo",
        fixture_name="sample_aws_plan.json",
        description="Public exposure, permissive database access, risky IAM, and broad trust in one reviewable plan.",
        emphasis="Representative mixed case",
        theme="mixed",
    ),
    DemoScenarioDefinition(
        scenario_id="nightmare",
        title="Nightmare Plan",
        report_title="Nightmare Plan Demo",
        fixture_name="sample_aws_nightmare_plan.json",
        description="Stacked public access, wildcard IAM, exposed storage, and high blast radius across the stack.",
        emphasis="Stress-case fixture",
        theme="nightmare",
    ),
    DemoScenarioDefinition(
        scenario_id="alb-ec2-rds",
        title="ALB, EC2, and RDS",
        report_title="ALB / EC2 / RDS Demo",
        fixture_name="sample_aws_alb_ec2_rds_plan.json",
        description="A common web architecture where an internet-facing load balancer still composes into a private RDS access path.",
        emphasis="Common architecture",
        theme="balanced",
    ),
    DemoScenarioDefinition(
        scenario_id="lambda-deploy-role",
        title="Lambda Deploy Role",
        report_title="Lambda Deploy Role Demo",
        fixture_name="sample_aws_lambda_deploy_role_plan.json",
        description="Private Lambda deployment path with scoped S3 access and deliberate trust-chain review points.",
        emphasis="Control-plane focus",
        theme="balanced",
    ),
    DemoScenarioDefinition(
        scenario_id="trust-unconstrained",
        title="Cross-Account Trust",
        report_title="Cross-Account Trust Demo",
        fixture_name="sample_aws_cross_account_trust_unconstrained_plan.json",
        description="Minimal assume-role trust without narrowing conditions to exercise the IAM trust path directly.",
        emphasis="Trust expansion",
        theme="trust",
    ),
    DemoScenarioDefinition(
        scenario_id="trust-constrained",
        title="Constrained Trust",
        report_title="Constrained Trust Demo",
        fixture_name="sample_aws_cross_account_trust_constrained_plan.json",
        description="The same trust edge narrowed by ExternalId, SourceArn, and SourceAccount conditions.",
        emphasis="Narrowed trust",
        theme="safe",
    ),
)


def create_app() -> FastAPI:
    app = FastAPI(
        title="Cloud Threat Modeler Dashboard",
        docs_url=None,
        openapi_url="/openapi.json",
        redoc_url=None,
    )
    app.mount("/static", StaticFiles(directory=str(APP_ROOT / "static")), name="static")
    engine = CloudThreatModeler()
    demo_scenarios = _build_demo_scenarios(engine)
    demo_scenarios_by_id = {scenario.scenario_id: scenario for scenario in demo_scenarios}
    known_demo_scenarios = ", ".join(scenario.scenario_id for scenario in demo_scenarios)
    api_report_example = _build_api_report_example(engine)

    @app.get("/api/docs", include_in_schema=False)
    async def api_docs() -> HTMLResponse:
        swagger_ui = get_swagger_ui_html(
            openapi_url=app.openapi_url or "/openapi.json",
            title=f"{app.title} - API Docs",
            swagger_ui_parameters={
                "defaultModelsExpandDepth": -1,
            },
        )
        content = swagger_ui.body.decode("utf-8").replace(
            "</head>",
            f"{DOCS_CHROME_HIDE_STYLE}{DOCS_LINK_CLEANUP_SCRIPT}</head>",
        )
        return HTMLResponse(content=content, status_code=swagger_ui.status_code)

    @app.get(
        "/",
        response_class=HTMLResponse,
        tags=["dashboard"],
        summary="Render dashboard landing page",
        description="Server-rendered landing page with the plan upload form and the built-in demo scenario gallery.",
        responses={
            200: {
                "description": "HTML dashboard landing page.",
                "content": {"text/html": {"example": HTML_LANDING_EXAMPLE}},
            }
        },
    )
    async def index(request: Request) -> HTMLResponse:
        return _template_response(request, "index.html", _base_context(request, demo_scenarios=demo_scenarios))

    @app.get(
        "/healthz",
        tags=["api"],
        summary="Health check",
        description="Simple liveness check for service monitoring and reverse-proxy health probes.",
        response_model=HealthResponseModel,
        response_description="Health status response.",
        responses={
            200: {
                "description": "Healthy dashboard service.",
                "content": {"application/json": {"example": {"status": "ok"}}},
            }
        },
    )
    async def healthz() -> HealthResponseModel:
        return {"status": "ok"}

    @app.get(
        "/demo/{scenario_id}",
        response_class=HTMLResponse,
        tags=["dashboard"],
        summary="Render a built-in demo report",
        description="Run one of the checked-in fixture scenarios and render its HTML report page.",
        responses={
            200: {
                "description": "HTML demo report page.",
                "content": {"text/html": {"example": HTML_REPORT_EXAMPLE}},
            },
            404: {
                "description": "Requested built-in scenario was not found.",
                "content": {"application/json": {"example": {"detail": "Demo scenario not found."}}},
            },
        },
    )
    async def demo_view(
        request: Request,
        scenario_id: str = FastApiPath(
            ...,
            description=(
                "Built-in fixture scenario to render. "
                f"Known scenario IDs: {known_demo_scenarios or 'safe, mixed, nightmare'}."
            ),
            examples=["safe"],
        ),
    ) -> HTMLResponse:
        scenario = demo_scenarios_by_id.get(scenario_id)
        if scenario is None:
            raise HTTPException(status_code=404, detail="Demo scenario not found.")

        analysis = _analyze_plan_path(
            Path(scenario.fixture_path),
            title=scenario.report_title,
            engine=engine,
        )
        return _template_response(request, "report.html", _report_context(request, analysis, scenario=scenario))

    @app.post(
        "/analyze",
        response_class=HTMLResponse,
        tags=["dashboard"],
        summary="Render an HTML report from an uploaded plan",
        description=(
            "Browser-oriented multipart upload endpoint. Accepts a Terraform plan JSON file generated by "
            "`terraform show -json tfplan` and returns the rendered HTML report page."
        ),
        responses={
            200: {
                "description": "HTML report page rendered from the uploaded plan.",
                "content": {"text/html": {"example": HTML_REPORT_EXAMPLE}},
            },
            400: {
                "description": "HTML page with an upload or parsing error message.",
                "content": {"text/html": {"example": HTML_LANDING_EXAMPLE}},
            },
            422: {
                "model": ValidationErrorResponseModel,
                "description": "Request validation error, such as a missing uploaded plan file.",
                "content": {"application/json": {"example": UPLOAD_VALIDATION_ERROR_EXAMPLE}},
            },
        },
    )
    async def analyze_view(
        request: Request,
        plan: UploadFile = File(
            ...,
            description="Terraform plan JSON file generated by `terraform show -json tfplan`.",
        ),
        title: str = Form(
            DEFAULT_REPORT_TITLE,
            description="Optional report title shown in the rendered dashboard report.",
        ),
    ) -> HTMLResponse:
        try:
            analysis = await _analyze_upload(plan, title=title, engine=engine)
        except (DashboardInputError, TerraformPlanLoadError) as exc:
            context = _base_context(
                request,
                error=str(exc),
                form_title=title or DEFAULT_REPORT_TITLE,
                demo_scenarios=demo_scenarios,
            )
            return _template_response(request, "index.html", context, status_code=400)

        return _template_response(request, "report.html", _report_context(request, analysis))

    @app.post(
        "/api/analyze",
        tags=["api"],
        summary="Analyze Terraform plan JSON",
        description=(
            "Upload a Terraform plan JSON file generated by `terraform show -json tfplan` and receive "
            "the versioned machine-readable cloud threat model report."
        ),
        response_model=CloudThreatModelReportModel,
        response_description="Versioned machine-readable cloud threat model report.",
        responses={
            200: {
                "description": "JSON report produced from the uploaded Terraform plan.",
                "content": {"application/json": {"example": api_report_example}},
            },
            400: {
                "model": DashboardApiErrorModel,
                "description": "Input validation or parsing error for the uploaded plan.",
                "content": {"application/json": {"example": API_ERROR_EXAMPLE}},
            },
            422: {
                "model": ValidationErrorResponseModel,
                "description": "Request validation error, such as a missing uploaded plan file.",
                "content": {"application/json": {"example": UPLOAD_VALIDATION_ERROR_EXAMPLE}},
            },
        },
    )
    async def analyze_api(
        plan: UploadFile = File(
            ...,
            description="Terraform plan JSON file generated by `terraform show -json tfplan`.",
        ),
        title: str = Form(
            DEFAULT_REPORT_TITLE,
            description="Optional report title embedded in the JSON report output.",
        ),
    ) -> JSONResponse:
        try:
            analysis = await _analyze_upload(plan, title=title, engine=engine)
        except (DashboardInputError, TerraformPlanLoadError) as exc:
            return JSONResponse(
                status_code=400,
                content={
                    "kind": "cloud-threat-model-error",
                    "message": str(exc),
                },
            )
        return JSONResponse(content=analysis.payload)

    return app

async def _analyze_upload(
    upload: UploadFile,
    *,
    title: str,
    engine: CloudThreatModeler,
) -> DashboardAnalysis:
    filename = Path(upload.filename or "uploaded-plan.json").name or "uploaded-plan.json"
    file_bytes = await upload.read()
    await upload.close()

    if not file_bytes:
        raise DashboardInputError("Upload a non-empty Terraform plan JSON file.")
    if len(file_bytes) > MAX_UPLOAD_BYTES:
        raise DashboardInputError(
            f"Uploaded plan exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MiB dashboard limit."
        )

    with TemporaryDirectory(prefix="ctm-dashboard-") as tmp_dir:
        plan_path = Path(tmp_dir) / filename
        plan_path.write_bytes(file_bytes)
        return _analyze_plan_path(plan_path, title=title or DEFAULT_REPORT_TITLE, engine=engine)


def _analyze_plan_path(
    plan_path: Path,
    *,
    title: str,
    engine: CloudThreatModeler,
) -> DashboardAnalysis:
    result = engine.analyze_plan(plan_path, title=title)
    payload = json.loads(engine.json_renderer.render(result))
    markdown_report = engine.report_renderer.render(result)
    return DashboardAnalysis(payload=payload, markdown_report=markdown_report)


def _build_demo_scenarios(engine: CloudThreatModeler) -> tuple[DemoScenario, ...]:
    scenarios: list[DemoScenario] = []
    for definition in DEMO_SCENARIO_DEFINITIONS:
        fixture_path = FIXTURES_DIR / definition.fixture_name
        if not fixture_path.is_file():
            continue
        try:
            result = engine.analyze_plan(fixture_path, title=definition.report_title)
        except TerraformPlanLoadError:
            continue
        severity_counts = Counter(finding.severity.value for finding in result.findings)
        scenarios.append(
            DemoScenario(
                scenario_id=definition.scenario_id,
                title=definition.title,
                report_title=definition.report_title,
                fixture_name=definition.fixture_name,
                fixture_path=str(fixture_path),
                description=definition.description,
                emphasis=definition.emphasis,
                theme=definition.theme,
                normalized_resources=len(result.inventory.resources),
                trust_boundaries=len(result.trust_boundaries),
                active_findings=len(result.findings),
                high_findings=severity_counts["high"],
                medium_findings=severity_counts["medium"],
                low_findings=severity_counts["low"],
            )
        )
    return tuple(scenarios)


def _build_api_report_example(engine: CloudThreatModeler) -> dict[str, object]:
    sample_fixture_path = FIXTURES_DIR / "sample_aws_plan.json"
    if sample_fixture_path.is_file():
        try:
            payload = _analyze_plan_path(sample_fixture_path, title="Mixed AWS Plan Demo", engine=engine).payload
            return _prune_api_report_example(payload)
        except TerraformPlanLoadError:
            pass
    safe_fixture_path = FIXTURES_DIR / "sample_aws_safe_plan.json"
    if safe_fixture_path.is_file():
        try:
            payload = _analyze_plan_path(safe_fixture_path, title="Safe Plan Demo", engine=engine).payload
            return _prune_api_report_example(payload)
        except TerraformPlanLoadError:
            pass
    return {
        "kind": "cloud-threat-model-report",
        "version": "1.1",
        "tool": {"name": "cloud-threat-modeler", "version": "0.1.0"},
        "title": "Cloud Threat Model Report",
        "analyzed_file": "tfplan.json",
        "analyzed_path": "tfplan.json",
        "summary": {
            "normalized_resources": 0,
            "unsupported_resources": 0,
            "trust_boundaries": 0,
            "active_findings": 0,
            "total_findings": 0,
            "suppressed_findings": 0,
            "baselined_findings": 0,
            "severity_counts": {"high": 0, "medium": 0, "low": 0},
        },
        "filtering": {
            "total_findings": 0,
            "active_findings": 0,
            "suppressed_findings": 0,
            "baselined_findings": 0,
            "suppressions_path": None,
            "baseline_path": None,
        },
        "inventory": {"provider": "aws", "unsupported_resources": [], "metadata": {}, "resources": []},
        "trust_boundaries": [],
        "findings": [],
        "suppressed_findings": [],
        "baselined_findings": [],
        "observations": [],
        "limitations": [],
    }


def _prune_api_report_example(payload: dict[str, object]) -> dict[str, object]:
    inventory = dict(payload.get("inventory", {}))
    inventory_resources = list(inventory.get("resources", []))
    trust_boundaries = list(payload.get("trust_boundaries", []))
    findings = list(payload.get("findings", []))
    observations = list(payload.get("observations", []))
    limitations = list(payload.get("limitations", []))

    pruned_resources = inventory_resources[:2]
    pruned_boundaries = trust_boundaries[:2]
    pruned_findings = findings[:2]
    pruned_observations = observations[:1]
    pruned_limitations = limitations[:2]

    summary = dict(payload.get("summary", {}))
    summary["normalized_resources"] = len(pruned_resources)
    summary["trust_boundaries"] = len(pruned_boundaries)
    summary["active_findings"] = len(pruned_findings)
    summary["total_findings"] = len(pruned_findings)
    summary["suppressed_findings"] = 0
    summary["baselined_findings"] = 0
    summary["severity_counts"] = {
        "high": sum(1 for finding in pruned_findings if finding.get("severity") == "high"),
        "medium": sum(1 for finding in pruned_findings if finding.get("severity") == "medium"),
        "low": sum(1 for finding in pruned_findings if finding.get("severity") == "low"),
    }

    filtering = dict(payload.get("filtering", {}))
    filtering["total_findings"] = len(pruned_findings)
    filtering["active_findings"] = len(pruned_findings)
    filtering["suppressed_findings"] = 0
    filtering["baselined_findings"] = 0
    filtering["suppressions_path"] = None
    filtering["baseline_path"] = None

    inventory["resources"] = pruned_resources

    return {
        **payload,
        "summary": summary,
        "filtering": filtering,
        "inventory": inventory,
        "trust_boundaries": pruned_boundaries,
        "findings": pruned_findings,
        "suppressed_findings": [],
        "baselined_findings": [],
        "observations": pruned_observations,
        "limitations": pruned_limitations,
    }


def _base_context(
    request: Request,
    *,
    error: str | None = None,
    form_title: str = DEFAULT_REPORT_TITLE,
    demo_scenarios: tuple[DemoScenario, ...] = (),
) -> dict[str, object]:
    return {
        "request": request,
        "page_title": "Cloud Threat Modeler Dashboard",
        "error": error,
        "form_title": form_title,
        "max_upload_mebibytes": MAX_UPLOAD_BYTES // (1024 * 1024),
        "demo_scenarios": demo_scenarios,
    }


def _template_response(
    request: Request,
    template_name: str,
    context: dict[str, object],
    *,
    status_code: int = 200,
) -> HTMLResponse:
    if TEMPLATE_RESPONSE_ACCEPTS_REQUEST:
        return TEMPLATES.TemplateResponse(
            request=request,
            name=template_name,
            context=context,
            status_code=status_code,
        )
    return TEMPLATES.TemplateResponse(template_name, context, status_code=status_code)


def _report_context(
    request: Request,
    analysis: DashboardAnalysis,
    *,
    scenario: DemoScenario | None = None,
) -> dict[str, object]:
    payload = analysis.payload
    findings = payload["findings"]
    summary = payload["summary"]
    severity_counts = summary["severity_counts"]
    findings_by_severity = {
        severity: [finding for finding in findings if finding["severity"] == severity]
        for severity in ("high", "medium", "low")
    }
    summary_cards = [
        {"label": "Active findings", "value": summary["active_findings"]},
        {"label": "Trust boundaries", "value": summary["trust_boundaries"]},
        {"label": "Resources", "value": summary["normalized_resources"]},
        {"label": "Observations", "value": len(payload["observations"])},
    ]
    top_risks = [
        {"label": "High", "value": severity_counts["high"]},
        {"label": "Medium", "value": severity_counts["medium"]},
        {"label": "Low", "value": severity_counts["low"]},
    ]

    return {
        "request": request,
        "page_title": payload["title"],
        "payload": payload,
        "summary_cards": summary_cards,
        "top_risks": top_risks,
        "findings_by_severity": findings_by_severity,
        "unsupported_resources": payload["inventory"]["unsupported_resources"],
        "raw_json": json.dumps(payload, indent=2),
        "raw_markdown": analysis.markdown_report,
        "finding_counter": Counter(finding["severity"] for finding in findings),
        "scenario": scenario,
    }


app = create_app()
