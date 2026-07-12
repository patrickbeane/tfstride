"""Shared test helpers for tfSTRIDE tests."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tfstride.analysis.stride_rules import StrideRuleEngine


def engine_configured_rule_ids(engine: StrideRuleEngine) -> set[str]:
    """Extract configured rule IDs from a StrideRuleEngine instance."""
    return {rule.metadata.rule_id for rule_group in engine._rule_groups() for rule in rule_group}
