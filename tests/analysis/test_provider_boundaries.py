from __future__ import annotations

import ast
import unittest
from pathlib import Path

from tests.helpers.paths import SOURCE_ROOT


def _python_sources(root: Path) -> tuple[Path, ...]:
    return tuple(sorted(path for path in root.rglob("*.py") if path.is_file()))


def _imports_from(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)
            for alias in node.names:
                imports.add(f"{node.module}.{alias.name}")
        elif isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
    return imports


def _relative(path: Path) -> str:
    return path.relative_to(SOURCE_ROOT.parent).as_posix()


class AnalysisProviderBoundaryTests(unittest.TestCase):
    def test_gcp_analysis_does_not_import_gcp_provider_modules(self) -> None:
        offenders: dict[str, list[str]] = {}
        analysis_gcp_root = SOURCE_ROOT / "analysis" / "gcp"

        for path in _python_sources(analysis_gcp_root):
            forbidden = sorted(module for module in _imports_from(path) if module.startswith("tfstride.providers.gcp"))
            if forbidden:
                offenders[_relative(path)] = forbidden

        self.assertEqual(offenders, {})

    def test_shared_analysis_does_not_import_gcp_concrete_metadata_or_constants(self) -> None:
        forbidden_prefixes = (
            "tfstride.providers.gcp.metadata",
            "tfstride.providers.gcp.constants",
            "tfstride.providers.gcp.resource_types",
        )
        forbidden_provider_members = {"metadata", "constants", "resource_types"}
        offenders: dict[str, list[str]] = {}
        analysis_root = SOURCE_ROOT / "analysis"
        analysis_gcp_root = analysis_root / "gcp"

        for path in _python_sources(analysis_root):
            if path.is_relative_to(analysis_gcp_root):
                continue

            imports = _imports_from(path)
            forbidden = sorted(
                module
                for module in imports
                if module.startswith(forbidden_prefixes)
                or module.removeprefix("tfstride.providers.gcp.") in forbidden_provider_members
            )
            if forbidden:
                offenders[_relative(path)] = forbidden

        self.assertEqual(offenders, {})


if __name__ == "__main__":
    unittest.main()
