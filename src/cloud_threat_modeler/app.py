from __future__ import annotations

from pathlib import Path

from cloud_threat_modeler.analysis.stride_rules import StrideRuleEngine
from cloud_threat_modeler.filtering import apply_finding_filters
from cloud_threat_modeler.analysis.trust_boundaries import TrustBoundaryDetector
from cloud_threat_modeler.input.terraform_plan import load_terraform_plan
from cloud_threat_modeler.models import AnalysisResult
from cloud_threat_modeler.providers.aws.normalizer import AwsNormalizer
from cloud_threat_modeler.reporting.json_report import JsonReportRenderer
from cloud_threat_modeler.reporting.markdown import MarkdownReportRenderer
from cloud_threat_modeler.reporting.sarif import SarifReportRenderer


DEFAULT_LIMITATIONS = [
    "AWS support is intentionally limited to a curated v1 resource set rather than the full Terraform AWS provider.",
    "Subnet public/private classification prefers explicit route table associations and NAT or internet routes when present, but it does not model main-route-table inheritance or every routing edge case.",
    "IAM analysis resolves inline role policies, customer-managed role-policy attachments, and EC2 instance profiles present in the plan, but it does not expand AWS-managed policy documents that are not materialized in Terraform state.",
    "Resource-policy analysis focuses on explicit policy documents and Lambda permission resources present in the plan; it does not model every service-specific condition key or every downstream runtime authorization path.",
    "The engine reasons over Terraform planned values only and does not validate runtime drift, CloudTrail evidence, or post-deploy control-plane activity.",
]


class CloudThreatModeler:
    def __init__(self) -> None:
        self.aws_normalizer = AwsNormalizer()
        self.boundary_detector = TrustBoundaryDetector()
        self.rule_engine = StrideRuleEngine()
        self.json_renderer = JsonReportRenderer()
        self.report_renderer = MarkdownReportRenderer()
        self.sarif_renderer = SarifReportRenderer()

    def analyze_plan(self, plan_path: str | Path, title: str = "Cloud Threat Model Report") -> AnalysisResult:
        terraform_plan = load_terraform_plan(plan_path)
        inventory = self.aws_normalizer.normalize(terraform_plan.resources)
        trust_boundaries = self.boundary_detector.detect(inventory)
        findings = self.rule_engine.evaluate(inventory, trust_boundaries)
        observations = self.rule_engine.observe_controls(inventory)
        return AnalysisResult(
            title=title,
            analyzed_file=Path(terraform_plan.source_path).name,
            analyzed_path=str(terraform_plan.source_path),
            inventory=inventory,
            trust_boundaries=trust_boundaries,
            findings=findings,
            observations=observations,
            limitations=list(DEFAULT_LIMITATIONS),
        )

    def filter_findings(
        self,
        result: AnalysisResult,
        *,
        suppressions_path: str | Path | None = None,
        baseline_path: str | Path | None = None,
    ) -> AnalysisResult:
        return apply_finding_filters(
            result,
            suppressions_path=suppressions_path,
            baseline_path=baseline_path,
        )

    def render_markdown_report(self, plan_path: str | Path, title: str = "Cloud Threat Model Report") -> str:
        result = self.analyze_plan(plan_path, title=title)
        return self.report_renderer.render(result)

    def render_json_report(self, plan_path: str | Path, title: str = "Cloud Threat Model Report") -> str:
        result = self.analyze_plan(plan_path, title=title)
        return self.json_renderer.render(result)

    def render_sarif_report(self, plan_path: str | Path, title: str = "Cloud Threat Model Report") -> str:
        result = self.analyze_plan(plan_path, title=title)
        return self.sarif_renderer.render(result)
