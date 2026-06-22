from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TESTS_ROOT = REPO_ROOT / "tests"
SRC_ROOT = REPO_ROOT / "src"
SOURCE_ROOT = SRC_ROOT / "tfstride"
FIXTURES_DIR = REPO_ROOT / "fixtures"
EXAMPLES_DIR = REPO_ROOT / "examples"
GOLDEN_DIR = TESTS_ROOT / "golden"
