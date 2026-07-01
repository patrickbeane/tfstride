from __future__ import annotations

from tfstride.analysis.gcp.compute_exposure_rules import GcpComputeExposureRuleDetectors
from tfstride.analysis.gcp.gke_rules import GcpGkeRuleDetectors
from tfstride.analysis.gcp.serverless_rules import GcpServerlessRuleDetectors


class GcpComputeRuleDetectors(
    GcpComputeExposureRuleDetectors,
    GcpGkeRuleDetectors,
    GcpServerlessRuleDetectors,
):
    pass
