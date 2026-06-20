from __future__ import annotations

import inspect
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from apps.dashboard.routes import register_routes
from apps.dashboard.uploads import UploadSizeLimitMiddleware
from tfstride.app import TfStride

APP_ROOT = Path(__file__).resolve().parent
TEMPLATES = Jinja2Templates(directory=str(APP_ROOT / "templates"))
TEMPLATE_RESPONSE_ACCEPTS_REQUEST = "request" in inspect.signature(TEMPLATES.TemplateResponse).parameters


def create_app() -> FastAPI:
    app = FastAPI(
        title="tfSTRIDE Dashboard",
        docs_url=None,
        openapi_url="/openapi.json",
        redoc_url=None,
    )
    app.add_middleware(UploadSizeLimitMiddleware, template_response=_template_response)
    app.mount("/static", StaticFiles(directory=str(APP_ROOT / "static")), name="static")
    app.state.engine = TfStride()
    register_routes(app, template_response=_template_response)
    return app


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


app = create_app()
