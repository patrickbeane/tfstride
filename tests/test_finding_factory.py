from __future__ import annotations

import unittest

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.rule_registry import RuleMetadata, RuleRegistry
from tfstride.models import EvidenceItem, Severity, StrideCategory


class FindingFactoryTests(unittest.TestCase):
    def test_build_uses_registry_metadata_for_finding_contract(self) -> None:
        registry = RuleRegistry(
            [
                RuleMetadata(
                    rule_id="test-rule",
                    title="Registry-backed title",
                    category=StrideCategory.TAMPERING,
                    recommended_mitigation="Registry-backed mitigation.",
                )
            ]
        )
        evidence = [EvidenceItem(key="signal", values=["value"])]

        finding = FindingFactory(registry).build(
            rule_id="test-rule",
            severity=Severity.HIGH,
            affected_resources=["aws_instance.web"],
            trust_boundary_id="boundary-1",
            rationale="Detected from test evidence.",
            evidence=evidence,
        )

        self.assertEqual(finding.rule_id, "test-rule")
        self.assertEqual(finding.title, "Registry-backed title")
        self.assertEqual(finding.category, StrideCategory.TAMPERING)
        self.assertEqual(finding.recommended_mitigation, "Registry-backed mitigation.")
        self.assertEqual(finding.severity, Severity.HIGH)
        self.assertEqual(finding.affected_resources, ["aws_instance.web"])
        self.assertEqual(finding.trust_boundary_id, "boundary-1")
        self.assertEqual(finding.rationale, "Detected from test evidence.")
        self.assertEqual(finding.evidence, evidence)


if __name__ == "__main__":
    unittest.main()