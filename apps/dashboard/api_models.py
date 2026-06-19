from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class DashboardApiErrorModel(BaseModel):
    kind: str = Field(description="Stable error kind for dashboard API failures.")
    message: str = Field(description="Human-readable error message.")


class ValidationDetailModel(BaseModel):
    loc: list[str | int] = Field(description="Location of the invalid or missing input.")
    msg: str = Field(description="Human-readable validation message.")
    type: str = Field(description="FastAPI or Pydantic validation error type.")
    input: Any | None = Field(default=None, description="Rejected input value when available.")
    ctx: dict[str, Any] | None = Field(default=None, description="Optional validation context.")


class ValidationErrorResponseModel(BaseModel):
    detail: list[ValidationDetailModel] = Field(description="One or more request validation issues.")


class HealthResponseModel(BaseModel):
    status: str = Field(description="Liveness status for the dashboard service.")
