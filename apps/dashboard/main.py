from __future__ import annotations

import inspect
import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

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
</style>
"""


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
        description="Mostly segmented AWS infrastructure with one deliberate IAM hygiene issue.",
        emphasis="Calibrated baseline",
        theme="safe",
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
        description="A common web architecture with an internet-facing load balancer, private app tier, and private RDS.",
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
        openapi_url="/api/openapi.json",
        redoc_url=None,
    )
    app.mount("/static", StaticFiles(directory=str(APP_ROOT / "static")), name="static")
    engine = CloudThreatModeler()
    demo_scenarios = _build_demo_scenarios(engine)
    demo_scenarios_by_id = {scenario.scenario_id: scenario for scenario in demo_scenarios}

    @app.get("/api/docs", include_in_schema=False)
    async def api_docs() -> HTMLResponse:
        swagger_ui = get_swagger_ui_html(
            openapi_url=app.openapi_url or "/api/openapi.json",
            title=f"{app.title} - API Docs",
            swagger_ui_parameters={
                "defaultModelsExpandDepth": -1,
            },
        )
        content = swagger_ui.body.decode("utf-8").replace("</head>", f"{DOCS_CHROME_HIDE_STYLE}</head>")
        return HTMLResponse(content=content, status_code=swagger_ui.status_code)

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request) -> HTMLResponse:
        return _template_response(request, "index.html", _base_context(request, demo_scenarios=demo_scenarios))

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/demo/{scenario_id}", response_class=HTMLResponse)
    async def demo_view(request: Request, scenario_id: str) -> HTMLResponse:
        scenario = demo_scenarios_by_id.get(scenario_id)
        if scenario is None:
            raise HTTPException(status_code=404, detail="Demo scenario not found.")

        analysis = _analyze_plan_path(
            Path(scenario.fixture_path),
            title=scenario.report_title,
            engine=engine,
        )
        return _template_response(request, "report.html", _report_context(request, analysis, scenario=scenario))

    @app.post("/analyze", response_class=HTMLResponse)
    async def analyze_view(
        request: Request,
        plan: UploadFile = File(...),
        title: str = Form(DEFAULT_REPORT_TITLE),
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

    @app.post("/api/analyze")
    async def analyze_api(
        plan: UploadFile = File(...),
        title: str = Form(DEFAULT_REPORT_TITLE),
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
