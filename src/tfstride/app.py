from __future__ import annotations

from collections.abc import Iterable, Mapping
from pathlib import Path

from tfstride.analysis.boundaries import detect_trust_boundaries
from tfstride.analysis.coverage import build_analysis_coverage
from tfstride.analysis.indexes import build_analysis_indexes
from tfstride.analysis.rule_registry import RulePolicy, apply_severity_overrides
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.input.terraform_plan import load_terraform_plan
from tfstride.models import AnalysisResult, ResourceInventory, TerraformResource
from tfstride.providers.catalog import (
    DEFAULT_PROVIDER,
    default_provider_limitations,
    default_provider_registry,
)
from tfstride.providers.registry import ProviderRegistry

AUTO_PROVIDER = "auto"
SHARED_LIMITATIONS = (
    "The engine reasons over Terraform planned values only and does not validate runtime drift, CloudTrail evidence, or post-deploy control-plane activity.",
)
DEFAULT_LIMITATIONS = [
    *default_provider_limitations().get(DEFAULT_PROVIDER, ()),
    *SHARED_LIMITATIONS,
]


class TfStride:
    def __init__(
        self,
        *,
        rule_policy: RulePolicy | None = None,
        provider_registry: ProviderRegistry | None = None,
        provider: str | None = None,
        provider_limitations: Mapping[str, Iterable[str]] | None = None,
    ) -> None:
        self._provider_registry = provider_registry or default_provider_registry()
        self._provider = _normalize_requested_provider(provider)
        self._provider_limitations = _normalize_provider_limitations(
            provider_limitations if provider_limitations is not None else default_provider_limitations()
        )
        self._rule_engine = StrideRuleEngine()
        self._rule_policy = rule_policy

    @property
    def provider_registry(self) -> ProviderRegistry:
        return self._provider_registry

    @property
    def provider(self) -> str:
        return self._provider or AUTO_PROVIDER

    @property
    def rule_policy(self) -> RulePolicy | None:
        return self._rule_policy

    def analyze_plan(self, plan_path: str | Path, title: str = "tfSTRIDE Threat Model Report") -> AnalysisResult:
        terraform_plan = load_terraform_plan(plan_path)
        inventory = self._normalize_resources(terraform_plan.resources)
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
            limitations=_limitations_for_provider(inventory.provider, self._provider_limitations),
        )

    def _normalize_resources(self, resources: list[TerraformResource]) -> ResourceInventory:
        if self._provider is not None:
            return self._provider_registry.normalize(self._provider, resources)
        return self._provider_registry.normalize_detected(resources, default_provider=DEFAULT_PROVIDER)


def _normalize_requested_provider(provider: str | None) -> str | None:
    if provider is None:
        return None
    normalized = str(provider).strip().lower()
    if not normalized or normalized == AUTO_PROVIDER:
        return None
    return normalized


def _normalize_provider_limitations(
    provider_limitations: Mapping[str, Iterable[str]],
) -> dict[str, tuple[str, ...]]:
    normalized: dict[str, tuple[str, ...]] = {}
    for provider, limitations in provider_limitations.items():
        provider_name = str(provider).strip().lower()
        if not provider_name:
            continue
        normalized[provider_name] = tuple(
            limitation for limitation in (str(item).strip() for item in limitations) if limitation
        )
    return normalized


def _limitations_for_provider(
    provider: str,
    provider_limitations: Mapping[str, tuple[str, ...]],
) -> list[str]:
    return [
        *provider_limitations.get(str(provider).strip().lower(), ()),
        *SHARED_LIMITATIONS,
    ]
