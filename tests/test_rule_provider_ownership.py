from __future__ import annotations

import ast
import unittest
from collections import Counter
from pathlib import Path

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.rule_registry import DEFAULT_RULE_REGISTRY
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.providers.aws.rules import AWS_RULE_GROUP_IDS
from tfstride.providers.catalog import default_provider_plugins, default_provider_rule_metadata
from tfstride.providers.gcp.rules import GCP_RULE_GROUP_IDS

REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = REPO_ROOT / "src" / "tfstride"
TESTS_ROOT = REPO_ROOT / "tests"
STRIDE_RULES_PATH = REPO_ROOT / "src" / "tfstride" / "analysis" / "stride_rules.py"
SHARED_PROVIDER_NEUTRAL_PATHS = (
    SOURCE_ROOT / "analysis" / "rule_registry.py",
    SOURCE_ROOT / "analysis" / "trust_boundaries.py",
    SOURCE_ROOT / "analysis" / "boundaries" / "__init__.py",
    SOURCE_ROOT / "analysis" / "boundaries" / "core.py",
    SOURCE_ROOT / "analysis" / "boundaries" / "shared.py",
    SOURCE_ROOT / "analysis" / "boundaries" / "types.py",
)


def _flatten(rule_groups: tuple[tuple[str, ...], ...]) -> tuple[str, ...]:
    return tuple(rule_id for rule_group in rule_groups for rule_id in rule_group)


def _python_files() -> tuple[Path, ...]:
    return tuple(sorted(SOURCE_ROOT.rglob("*.py"))) + tuple(sorted(TESTS_ROOT.rglob("*.py")))


def _string_literals(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(), filename=str(path))
    return {node.value for node in ast.walk(tree) if isinstance(node, ast.Constant) and isinstance(node.value, str)}


def _rule_id_occurrences(rule_ids: set[str]) -> list[tuple[Path, str]]:
    occurrences: list[tuple[Path, str]] = []
    for path in _python_files():
        literals = _string_literals(path)
        occurrences.extend((path, rule_id) for rule_id in sorted(rule_ids.intersection(literals)))
    return occurrences


def _is_allowed_rule_id_location(path: Path, provider: str) -> bool:
    if path.is_relative_to(TESTS_ROOT):
        return True
    return path.is_relative_to(REPO_ROOT / "src" / "tfstride" / "providers" / provider)


def _imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(), filename=str(path))
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            modules.add(node.module)
    return modules


def _provider_source_markers() -> tuple[str, ...]:
    return tuple(
        marker
        for plugin in default_provider_plugins()
        for marker in (
            f"{plugin.provider}-",
            f"tfstride.analysis.{plugin.provider}",
            f"tfstride.providers.{plugin.provider}",
        )
    )


class ProviderRuleOwnershipTests(unittest.TestCase):
    def test_aws_rule_ids_only_appear_in_aws_provider_shared_metadata_or_tests(self) -> None:
        aws_rule_ids = set(_flatten(AWS_RULE_GROUP_IDS))

        violations = [
            (str(path.relative_to(REPO_ROOT)), rule_id)
            for path, rule_id in _rule_id_occurrences(aws_rule_ids)
            if not _is_allowed_rule_id_location(path, "aws")
        ]

        self.assertEqual(violations, [])

    def test_gcp_rule_ids_only_appear_in_gcp_provider_shared_metadata_or_tests(self) -> None:
        gcp_rule_ids = set(_flatten(GCP_RULE_GROUP_IDS))

        violations = [
            (str(path.relative_to(REPO_ROOT)), rule_id)
            for path, rule_id in _rule_id_occurrences(gcp_rule_ids)
            if not _is_allowed_rule_id_location(path, "gcp")
        ]

        self.assertEqual(violations, [])

    def test_stride_rule_engine_does_not_import_gcp_rule_detectors(self) -> None:
        self.assertNotIn("tfstride.analysis.gcp.rules", _imported_modules(STRIDE_RULES_PATH))

    def test_plugin_contributed_rules_are_unique_and_have_metadata(self) -> None:
        contributed_rule_ids: list[str] = []

        for plugin in default_provider_plugins():
            contribution = plugin.create_rule_contribution(FindingFactory(DEFAULT_RULE_REGISTRY))
            self.assertIsNotNone(contribution, f"Provider `{plugin.provider}` must contribute rules.")
            for rule_group in contribution.rule_groups:
                for rule in rule_group:
                    contributed_rule_ids.append(rule.metadata.rule_id)
                    self.assertEqual(rule.metadata, DEFAULT_RULE_REGISTRY.get(rule.metadata.rule_id))

        duplicate_rule_ids = sorted(rule_id for rule_id, count in Counter(contributed_rule_ids).items() if count > 1)
        self.assertEqual(duplicate_rule_ids, [])
        self.assertEqual(set(contributed_rule_ids), StrideRuleEngine().configured_rule_ids())

    def test_provider_rule_metadata_ids_match_contributed_rule_ids(self) -> None:
        for plugin in default_provider_plugins():
            metadata_ids = {metadata.rule_id for metadata in plugin.create_rule_metadata()}
            contribution = plugin.create_rule_contribution(FindingFactory(DEFAULT_RULE_REGISTRY))

            self.assertIsNotNone(contribution, f"Provider `{plugin.provider}` must contribute rules.")
            contribution_ids = {rule.metadata.rule_id for rule_group in contribution.rule_groups for rule in rule_group}

            self.assertEqual(metadata_ids, contribution_ids)

    def test_provider_rule_metadata_ids_use_provider_prefix(self) -> None:
        for plugin in default_provider_plugins():
            expected_prefix = f"{plugin.provider}-"
            violations = [
                metadata.rule_id
                for metadata in plugin.create_rule_metadata()
                if not metadata.rule_id.startswith(expected_prefix)
            ]

            self.assertEqual(violations, [])

    def test_default_provider_rule_metadata_order_follows_plugin_order(self) -> None:
        expected_rule_ids = tuple(
            metadata.rule_id for plugin in default_provider_plugins() for metadata in plugin.create_rule_metadata()
        )
        actual_rule_ids = tuple(metadata.rule_id for metadata in default_provider_rule_metadata())

        self.assertEqual(actual_rule_ids, expected_rule_ids)

    def test_shared_rule_registry_and_boundary_core_do_not_contain_provider_ids(self) -> None:
        provider_rule_ids = {metadata.rule_id for metadata in default_provider_rule_metadata()}
        provider_source_markers = _provider_source_markers()
        violations: list[tuple[str, str]] = []

        for path in SHARED_PROVIDER_NEUTRAL_PATHS:
            source = path.read_text()
            rule_id_markers = sorted(rule_id for rule_id in provider_rule_ids if rule_id in source)
            source_markers = sorted(marker for marker in provider_source_markers if marker in source)
            violations.extend(
                (str(path.relative_to(REPO_ROOT)), marker) for marker in (*rule_id_markers, *source_markers)
            )

        self.assertEqual(violations, [])


if __name__ == "__main__":
    unittest.main()
