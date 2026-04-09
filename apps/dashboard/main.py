from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from cloud_threat_modeler.app import CloudThreatModeler
from cloud_threat_modeler.input.terraform_plan import TerraformPlanLoadError


APP_ROOT = Path(__file__).resolve().parent
TEMPLATES = Jinja2Templates(directory=str(APP_ROOT / "templates"))
MAX_UPLOAD_BYTES = 10 * 1024 * 1024
DEFAULT_REPORT_TITLE = "Cloud Threat Model Report"


class DashboardInputError(ValueError):
    """Raised when an uploaded plan cannot be analyzed by the dashboard."""


@dataclass(slots=True)
class DashboardAnalysis:
    payload: dict[str, object]
    markdown_report: str


def create_app() -> FastAPI:
    app = FastAPI(
        title="Cloud Threat Modeler Dashboard",
        docs_url="/api/docs",
        redoc_url=None,
    )
    app.mount("/static", StaticFiles(directory=str(APP_ROOT / "static")), name="static")
    engine = CloudThreatModeler()

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request) -> HTMLResponse:
        return TEMPLATES.TemplateResponse(
            "index.html",
            _base_context(request),
        )

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

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
            )
            return TEMPLATES.TemplateResponse("index.html", context, status_code=400)

        return TEMPLATES.TemplateResponse(
            "report.html",
            _report_context(request, analysis),
        )

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


app = create_app()


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
        result = engine.analyze_plan(plan_path, title=title or DEFAULT_REPORT_TITLE)
        payload = json.loads(engine.json_renderer.render(result))
        markdown_report = engine.report_renderer.render(result)

    return DashboardAnalysis(payload=payload, markdown_report=markdown_report)


def _base_context(
    request: Request,
    *,
    error: str | None = None,
    form_title: str = DEFAULT_REPORT_TITLE,
) -> dict[str, object]:
    return {
        "request": request,
        "page_title": "Cloud Threat Modeler Dashboard",
        "error": error,
        "form_title": form_title,
        "max_upload_mebibytes": MAX_UPLOAD_BYTES // (1024 * 1024),
    }


def _report_context(request: Request, analysis: DashboardAnalysis) -> dict[str, object]:
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
    }
