from __future__ import annotations

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.gcp_compute_rule_detectors import GcpComputeRuleDetectors
from tfstride.analysis.gcp_data_rule_detectors import GcpDataRuleDetectors
from tfstride.analysis.gcp_iam_rule_detectors import GcpIamRuleDetectors


class GcpRuleDetectors(GcpComputeRuleDetectors, GcpIamRuleDetectors, GcpDataRuleDetectors):
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory