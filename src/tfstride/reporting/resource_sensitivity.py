"""Report the basis for sensitivity labels without claiming knowledge of contents."""

from __future__ import annotations

from tfstride.reporting.report_contract import ResourceSensitivityPayload

RESOURCE_SENSITIVITY_EXPLANATION = (
    "Sensitive resource labels are assumptions based on resource class. "
    "tfSTRIDE does not assess stored data contents from the plan."
)


def serialize_resource_sensitivity() -> ResourceSensitivityPayload:
    return {
        "basis": "resource_class_assumption",
        "data_contents_state": "not_assessed",
        "explanation": RESOURCE_SENSITIVITY_EXPLANATION,
    }
