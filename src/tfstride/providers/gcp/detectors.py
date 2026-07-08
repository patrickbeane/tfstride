from __future__ import annotations

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.providers.gcp.compute_rules import GcpComputeRuleDetectors
from tfstride.providers.gcp.data_rules import GcpDataRuleDetectors
from tfstride.providers.gcp.iam_rules import GcpIamRuleDetectors


class GcpRuleDetectors(GcpComputeRuleDetectors, GcpIamRuleDetectors, GcpDataRuleDetectors):
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory
