from __future__ import annotations

from pathlib import Path

from tfstride.analysis.coverage import build_analysis_coverage
from tfstride.analysis.indexes import build_analysis_indexes
from tfstride.analysis.rule_registry import RulePolicy, apply_severity_overrides
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.input.terraform_plan import load_terraform_plan
from tfstride.models import AnalysisResult
from tfstride.providers.catalog import DEFAULT_PROVIDER, default_provider_registry
from tfstride.providers.registry import ProviderRegistry


DEFAULT_LIMITATIONS = [
    "AWS support is intentionally limited to a curated v1 resource set rather than the full Terraform AWS provider.",
    "Subnet public/private classification prefers explicit route table associations and NAT or internet routes when present, but it does not model main-route-table inheritance or every routing edge case.",
    "IAM analysis resolves inline role policies, customer-managed role-policy attachments, and EC2 instance profiles present in the plan, but it does not expand AWS-managed policy documents that are not materialized in Terraform state.",
    "Resource-policy analysis focuses on explicit policy documents and Lambda permission resources present in the plan; it does not model every service-specific condition key or every downstream runtime authorization path.",
    "The engine reasons over Terraform planned values only and does not validate runtime drift, CloudTrail evidence, or post-deploy control-plane activity.",
]


class TfStride:
    def __init__(
        self,
        *,
        rule_policy: RulePolicy | None = None,
        provider_registry: ProviderRegistry | None = None,
    ) -> None:
        self._provider_registry = provider_registry or default_provider_registry()
        self._rule_engine = StrideRuleEngine()
        self._rule_policy = rule_policy

    @property
    def provider_registry(self) -> ProviderRegistry:
        return self._provider_registry

    @property
    def rule_policy(self) -> RulePolicy | None:
        return self._rule_policy

    def analyze_plan(self, plan_path: str | Path, title: str = "tfSTRIDE Threat Model Report") -> AnalysisResult:
        terraform_plan = load_terraform_plan(plan_path)
        inventory = self._provider_registry.normalize(DEFAULT_PROVIDER, terraform_plan.resources)
        analysis_indexes = build_analysis_indexes(inventory)
        trust_boundaries = detect_trust_boundaries(inventory, indexes=analysis_indexes)
        findings = apply_severity_overrides(
            self._rule_engine.evaluate(
                inventory,
                trust_boundaries,
                analysis_indexes=analysis_indexes,
                rule_policy=self._rule_policy,
            ),
            self._rule_policy,
        )
        observations = self._rule_engine.observe_controls(inventory)
        return AnalysisResult(
            title=title,
            analyzed_file=Path(terraform_plan.source_path).name,
            analyzed_path=str(terraform_plan.source_path),
            inventory=inventory,
            trust_boundaries=trust_boundaries,
            findings=findings,
            observations=observations,
            analysis_coverage=build_analysis_coverage(
                inventory,
                rule_policy=self._rule_policy,
            ),
            limitations=list(DEFAULT_LIMITATIONS),
        )