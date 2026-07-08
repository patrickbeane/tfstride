from __future__ import annotations

from tfstride.providers.gcp.compute_exposure_rules import GcpComputeExposureRuleDetectors
from tfstride.providers.gcp.gke_rules import GcpGkeRuleDetectors
from tfstride.providers.gcp.serverless_rules import GcpServerlessRuleDetectors


class GcpComputeRuleDetectors(
    GcpComputeExposureRuleDetectors,
    GcpGkeRuleDetectors,
    GcpServerlessRuleDetectors,
):
    pass
