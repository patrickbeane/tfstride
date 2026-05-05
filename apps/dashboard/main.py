from __future__ import annotations

import inspect
import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, cast

from fastapi import FastAPI, File, Form, HTTPException, Path as FastApiPath, Request, UploadFile
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from apps.dashboard.api_models import (
    DashboardApiErrorModel,
    HealthResponseModel,
    ValidationErrorResponseModel,
)
from tfstride.app import TfStride
from tfstride.input.terraform_plan import TerraformPlanLoadError
from tfstride.reporting.report_contract import TFSReportPayload


APP_ROOT = Path(__file__).resolve().parent
REPO_ROOT = APP_ROOT.parents[1]
FIXTURES_DIR = REPO_ROOT / "fixtures"
TEMPLATES = Jinja2Templates(directory=str(APP_ROOT / "templates"))
TEMPLATE_RESPONSE_ACCEPTS_REQUEST = "request" in inspect.signature(TEMPLATES.TemplateResponse).parameters
MAX_UPLOAD_BYTES = 10 * 1024 * 1024
MAX_MULTIPART_ENVELOPE_BYTES = 1024 * 1024
MAX_MULTIPART_REQUEST_BYTES = MAX_UPLOAD_BYTES + MAX_MULTIPART_ENVELOPE_BYTES
UPLOAD_READ_CHUNK_BYTES = 1024 * 1024
UPLOAD_ENDPOINT_PATHS = frozenset({"/analyze", "/api/analyze"})
DEFAULT_REPORT_TITLE = "tfSTRIDE Report"
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
HTML_LANDING_EXAMPLE = "<!doctype html><html><body><main>tfSTRIDE dashboard landing page</main></body></html>"
HTML_REPORT_EXAMPLE = "<!doctype html><html><body><main>tfSTRIDE report page</main></body></html>"
API_REPORT_EXAMPLE: TFSReportPayload = {
    "kind": "tfstride-report",
    "version": "1.0",
    "tool": {"name": "tfstride", "version": "0.2.3"},
    "title": "tfSTRIDE Report",
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
    "analysis_coverage": {
        "resources": {
            "total_resources": 0,
            "provider_resources": 0,
            "normalized_resources": 0,
            "unsupported_resources": 0,
            "unsupported_resource_types": {},
        },
        "rules": {
            "registered_rule_count": 0,
            "enabled_rules": [],
            "disabled_rules": [],
            "severity_overrides": {},
            "finding_counts_by_rule": {},
        },
        "references": {
            "unresolved_reference_count": 0,
            "unresolved_references": [],
        },
    },
    "inventory": {"provider": "aws", "unsupported_resources": [], "metadata": {}, "resources": []},
    "trust_boundaries": [],
    "findings": [],
    "suppressed_findings": [],
    "baselined_findings": [],
    "observations": [],
    "limitations": [],
}
API_ERROR_EXAMPLE = {
    "kind": "tfstride-error",
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


class _UploadTooLarge(ValueError):
    """Raised when a dashboard upload exceeds the request body size limit."""


@dataclass(slots=True)
class DashboardAnalysis:
    payload: TFSReportPayload
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


class UploadSizeLimitMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (
            scope["type"] != "http"
            or scope.get("method") != "POST"
            or scope.get("path") not in UPLOAD_ENDPOINT_PATHS
        ):
            await self.app(scope, receive, send)
            return

        bytes_seen = 0

        # Enforce a hard ceiling on the multipart body before Starlette finishes
        # parsing the upload into an UploadFile object.
        async def limited_receive() -> Message:
            nonlocal bytes_seen
            message = await receive()
            if message["type"] != "http.request":
                return message

            body = message.get("body", b"")
            bytes_seen += len(body)
            if bytes_seen > MAX_MULTIPART_REQUEST_BYTES:
                raise _UploadTooLarge(_upload_too_large_message())
            return message

        try:
            await self.app(scope, limited_receive, send)
        except _UploadTooLarge as exc:
            response = _upload_limit_response(scope, receive, str(exc))
            await response(scope, receive, send)


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
        scenario_id="ecs-fargate",
        title="ECS / Fargate",
        report_title="ECS / Fargate Demo",
        fixture_name="sample_aws_ecs_fargate_plan.json",
        description="Internet-facing ALB, private ECS tasks, RDS security-group trust, and Secrets Manager access through the task role.",
        emphasis="Container workload",
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
KNOWN_DEMO_SCENARIO_IDS = ", ".join(definition.scenario_id for definition in DEMO_SCENARIO_DEFINITIONS)


def create_app() -> FastAPI:
    app = FastAPI(
        title="tfSTRIDE Dashboard",
        docs_url=None,
        openapi_url="/openapi.json",
        redoc_url=None,
    )
    app.add_middleware(UploadSizeLimitMiddleware)
    app.mount("/static", StaticFiles(directory=str(APP_ROOT / "static")), name="static")
    app.state.engine = TfStride()

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
        description="Server-rendered landing page with the plan upload form.",
        responses={
            200: {
                "description": "HTML dashboard landing page.",
                "content": {"text/html": {"example": HTML_LANDING_EXAMPLE}},
            }
        },
    )
    async def index(request: Request) -> HTMLResponse:
        return _template_response(request, "index.html", _base_context(request))

    @app.get("/scenarios", response_class=HTMLResponse, include_in_schema=False)
    async def scenarios_page(request: Request) -> HTMLResponse:
        demo_scenarios = _get_demo_scenarios(request.app)
        return _template_response(
            request,
            "scenarios.html",
            _base_context(
                request,
                page_title="tfSTRIDE Scenarios",
                demo_scenarios=demo_scenarios,
            ),
        )

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
                f"Known scenario IDs: {KNOWN_DEMO_SCENARIO_IDS or 'safe, mixed, nightmare'}."
            ),
            examples=["safe"],
        ),
    ) -> HTMLResponse:
        scenario = _get_demo_scenarios_by_id(request.app).get(scenario_id)
        if scenario is None:
            raise HTTPException(status_code=404, detail="Demo scenario not found.")

        analysis = _analyze_plan_path(
            Path(scenario.fixture_path),
            title=scenario.report_title,
            engine=_engine(request.app),
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
            analysis = await _analyze_upload(plan, title=title, engine=_engine(request.app))
        except (DashboardInputError, TerraformPlanLoadError) as exc:
            context = _base_context(
                request,
                error=str(exc),
                form_title=title or DEFAULT_REPORT_TITLE,
                demo_scenarios=_get_demo_scenarios(request.app),
            )
            return _template_response(request, "index.html", context, status_code=400)

        return _template_response(request, "report.html", _report_context(request, analysis))

    @app.post(
        "/api/analyze",
        tags=["api"],
        summary="Analyze Terraform plan JSON",
        description=(
            "Upload a Terraform plan JSON file generated by `terraform show -json tfplan` and receive "
            "the versioned machine-readable tfSTRIDE report."
        ),
        response_model=TFSReportPayload,
        response_description="Versioned machine-readable tfSTRIDE report.",
        responses={
            200: {
                "description": "JSON report produced from the uploaded Terraform plan.",
                "content": {"application/json": {"example": API_REPORT_EXAMPLE}},
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
    ) -> TFSReportPayload | JSONResponse:
        try:
            analysis = await _analyze_upload(plan, title=title, engine=_engine(app))
        except (DashboardInputError, TerraformPlanLoadError) as exc:
            return JSONResponse(
                status_code=400,
                content={
                    "kind": "tfstride-error",
                    "message": str(exc),
                },
            )
        return analysis.payload

    return app

async def _analyze_upload(
    upload: UploadFile,
    *,
    title: str,
    engine: TfStride,
) -> DashboardAnalysis:
    filename = Path(upload.filename or "uploaded-plan.json").name or "uploaded-plan.json"
    bytes_written = 0

    with TemporaryDirectory(prefix="tfstride-dashboard-") as tmp_dir:
        plan_path = Path(tmp_dir) / filename
        try:
            with plan_path.open("wb") as plan_file:
                while True:
                    chunk = await upload.read(UPLOAD_READ_CHUNK_BYTES)
                    if not chunk:
                        break
                    if bytes_written + len(chunk) > MAX_UPLOAD_BYTES:
                        raise DashboardInputError(_upload_too_large_message())
                    plan_file.write(chunk)
                    bytes_written += len(chunk)
        finally:
            await upload.close()

        if bytes_written == 0:
            raise DashboardInputError("Upload a non-empty Terraform plan JSON file.")

        return _analyze_plan_path(plan_path, title=title or DEFAULT_REPORT_TITLE, engine=engine)


def _analyze_plan_path(
    plan_path: Path,
    *,
    title: str,
    engine: TfStride,
) -> DashboardAnalysis:
    result = engine.analyze_plan(plan_path, title=title)
    payload = _sanitize_dashboard_payload(engine.build_json_report_payload(result))
    markdown_report = engine.render_markdown(result)
    return DashboardAnalysis(payload=payload, markdown_report=markdown_report)


def _build_demo_scenarios(engine: TfStride) -> tuple[DemoScenario, ...]:
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


def _engine(app: FastAPI) -> TfStride:
    return cast(TfStride, app.state.engine)


def _get_demo_scenarios(app: FastAPI) -> tuple[DemoScenario, ...]:
    cached = getattr(app.state, "demo_scenarios", None)
    if cached is None:
        cached = _build_demo_scenarios(_engine(app))
        app.state.demo_scenarios = cached
    return cast(tuple[DemoScenario, ...], cached)


def _get_demo_scenarios_by_id(app: FastAPI) -> dict[str, DemoScenario]:
    cached = getattr(app.state, "demo_scenarios_by_id", None)
    if cached is None:
        cached = {scenario.scenario_id: scenario for scenario in _get_demo_scenarios(app)}
        app.state.demo_scenarios_by_id = cached
    return cast(dict[str, DemoScenario], cached)


def _sanitize_dashboard_payload(payload: TFSReportPayload) -> TFSReportPayload:
    sanitized_payload = dict(payload)
    analyzed_file = sanitized_payload.get("analyzed_file")
    if isinstance(analyzed_file, str) and analyzed_file:
        sanitized_payload["analyzed_path"] = analyzed_file
    return sanitized_payload


def _base_context(
    request: Request,
    *,
    page_title: str = "tfSTRIDE Dashboard",
    error: str | None = None,
    form_title: str = DEFAULT_REPORT_TITLE,
    demo_scenarios: tuple[DemoScenario, ...] = (),
) -> dict[str, object]:
    return {
        "request": request,
        "page_title": page_title,
        "error": error,
        "form_title": form_title,
        "max_upload_mebibytes": MAX_UPLOAD_BYTES // (1024 * 1024),
        "demo_scenarios": demo_scenarios,
    }


def _upload_too_large_message() -> str:
    return f"Uploaded plan exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MiB dashboard limit."


def _upload_limit_response(scope: Scope, receive: Receive, message: str) -> HTMLResponse | JSONResponse:
    if scope.get("path") == "/api/analyze":
        return JSONResponse(
            status_code=413,
            content={
                "kind": "tfstride-error",
                "message": message,
            },
        )

    request = Request(scope, receive)
    return _template_response(
        request,
        "index.html",
        _base_context(request, error=message),
        status_code=413,
    )


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
        **_coverage_context(payload),
        "raw_json": json.dumps(payload, indent=2),
        "raw_markdown": analysis.markdown_report,
        "scenario": scenario,
    }


def _coverage_context(payload: TFSReportPayload) -> dict[str, object]:
    analysis_coverage = _analysis_coverage_payload(payload)
    disabled_rules = list(analysis_coverage["rules"]["disabled_rules"])
    severity_overrides = [
        {"rule_id": rule_id, "severity": severity}
        for rule_id, severity in analysis_coverage["rules"]["severity_overrides"].items()
    ]
    unresolved_references = [
        {
            "resource": reference["resource"],
            "details": [
                {
                    "key": key,
                    "value_text": ", ".join(values),
                }
                for key, values in sorted(reference["references"].items())
            ],
        }
        for reference in analysis_coverage["references"]["unresolved_references"]
    ]
    return {
        "coverage_cards": [
            {"label": "Terraform resources", "value": analysis_coverage["resources"]["total_resources"]},
            {"label": "Unsupported", "value": analysis_coverage["resources"]["unsupported_resources"]},
            {"label": "Enabled rules", "value": len(analysis_coverage["rules"]["enabled_rules"])},
            {"label": "Unresolved refs", "value": analysis_coverage["references"]["unresolved_reference_count"]},
        ],
        "coverage_resource_stats": [
            {"label": "Provider resources considered", "value": analysis_coverage["resources"]["provider_resources"]},
            {"label": "Normalized resources", "value": analysis_coverage["resources"]["normalized_resources"]},
        ],
        "coverage_rule_stats": [
            {"label": "Registered rules", "value": analysis_coverage["rules"]["registered_rule_count"]},
            {"label": "Disabled rules", "value": len(disabled_rules)},
        ],
        "unsupported_resource_types": [
            {"resource_type": resource_type, "count": count}
            for resource_type, count in sorted(analysis_coverage["resources"]["unsupported_resource_types"].items())
        ],
        "finding_counts_by_rule": [
            {"rule_id": rule_id, "count": count}
            for rule_id, count in analysis_coverage["rules"]["finding_counts_by_rule"].items()
            if count
        ],
        "disabled_rule_ids": disabled_rules,
        "severity_overrides": severity_overrides,
        "unresolved_references": unresolved_references,
    }


def _analysis_coverage_payload(payload: TFSReportPayload) -> dict[str, Any]:
    coverage = payload.get("analysis_coverage")
    if isinstance(coverage, dict):
        return coverage

    summary = payload["summary"]
    return {
        "resources": {
            "total_resources": summary["normalized_resources"] + summary["unsupported_resources"],
            "provider_resources": summary["normalized_resources"] + summary["unsupported_resources"],
            "normalized_resources": summary["normalized_resources"],
            "unsupported_resources": summary["unsupported_resources"],
            "unsupported_resource_types": {},
        },
        "rules": {
            "registered_rule_count": 0,
            "enabled_rules": [],
            "disabled_rules": [],
            "severity_overrides": {},
            "finding_counts_by_rule": {},
        },
        "references": {
            "unresolved_reference_count": 0,
            "unresolved_references": [],
        },
    }


app = create_app()
