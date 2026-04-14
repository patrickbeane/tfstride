from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tfstride.analysis.rule_registry import DEFAULT_RULE_REGISTRY, RulePolicy
from tfstride.models import Severity


CONFIG_FILENAME = "tfstride.toml"
CONFIG_FORMAT_VERSION = "1.0"


class ProjectConfigLoadError(ValueError):
    """Raised when the project configuration cannot be parsed."""


@dataclass(frozen=True, slots=True)
class ProjectConfig:
    path: str | None = None
    title: str | None = None
    fail_on: Severity | None = None
    suppressions_path: str | None = None
    baseline_path: str | None = None
    rule_policy: RulePolicy = field(default_factory=RulePolicy)


def load_project_config(
    *,
    path: str | Path | None = None,
    plan_path: str | Path | None = None,
) -> ProjectConfig:
    config_path = Path(path).expanduser().resolve() if path else discover_project_config(plan_path=plan_path)
    if config_path is None:
        return ProjectConfig()
    if not config_path.is_file():
        raise ProjectConfigLoadError(f"Config file not found: {config_path}")

    try:
        payload = tomllib.loads(config_path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise ProjectConfigLoadError(f"Failed to parse config TOML in {config_path}: {exc}") from exc

    if not isinstance(payload, dict):
        raise ProjectConfigLoadError(f"Config file must contain a TOML table: {config_path}")

    _ensure_known_keys(
        payload,
        allowed={"version", "title", "fail_on", "baseline", "suppressions", "rules"},
        label="config",
        path=config_path,
    )
    version = payload.get("version")
    if version is not None and version != CONFIG_FORMAT_VERSION:
        raise ProjectConfigLoadError(
            f"Unsupported config version `{version}` in {config_path}; expected `{CONFIG_FORMAT_VERSION}`."
        )

    title = _optional_string(payload.get("title"), key="title", path=config_path)
    fail_on = _optional_severity(payload.get("fail_on"), key="fail_on", path=config_path)
    baseline_path = _optional_path(payload.get("baseline"), key="baseline", base_path=config_path)
    suppressions_path = _optional_path(payload.get("suppressions"), key="suppressions", base_path=config_path)
    rule_policy = _load_rule_policy(payload.get("rules"), config_path)

    return ProjectConfig(
        path=str(config_path),
        title=title,
        fail_on=fail_on,
        suppressions_path=suppressions_path,
        baseline_path=baseline_path,
        rule_policy=rule_policy,
    )


def discover_project_config(*, plan_path: str | Path | None = None) -> Path | None:
    search_roots: list[Path] = [Path.cwd().resolve()]
    if plan_path is not None:
        search_roots.append(Path(plan_path).expanduser().resolve().parent)

    seen: set[Path] = set()
    for root in search_roots:
        current = root
        while True:
            candidate = current / CONFIG_FILENAME
            if candidate not in seen:
                seen.add(candidate)
                if candidate.is_file():
                    return candidate
            if current.parent == current:
                break
            current = current.parent
    return None


def _load_rule_policy(payload: Any, config_path: Path) -> RulePolicy:
    if payload is None:
        return RulePolicy()
    if not isinstance(payload, dict):
        raise ProjectConfigLoadError(f"`rules` must be a TOML table in {config_path}")

    _ensure_known_keys(
        payload,
        allowed={"enable", "disable", "severity_overrides"},
        label="rules",
        path=config_path,
    )

    enabled = _optional_string_list(payload, "enable", config_path)
    disabled = _optional_string_list(payload, "disable", config_path) or []
    severity_overrides = _severity_override_map(payload.get("severity_overrides"), config_path)
    known_rule_ids = DEFAULT_RULE_REGISTRY.known_rule_ids()

    enabled_ids = set(enabled) if enabled is not None else None
    disabled_ids = set(disabled)
    unknown_rule_ids = sorted((enabled_ids or set()).union(disabled_ids, severity_overrides) - known_rule_ids)
    if unknown_rule_ids:
        raise ProjectConfigLoadError(
            f"Config references unknown rule IDs in {config_path}: {', '.join(unknown_rule_ids)}"
        )
    if enabled_ids is not None and enabled_ids.intersection(disabled_ids):
        overlap = ", ".join(sorted(enabled_ids.intersection(disabled_ids)))
        raise ProjectConfigLoadError(f"`rules.enable` and `rules.disable` overlap in {config_path}: {overlap}")

    active_rule_ids = DEFAULT_RULE_REGISTRY.default_enabled_rule_ids() if enabled_ids is None else enabled_ids
    active_rule_ids.difference_update(disabled_ids)
    return RulePolicy(
        enabled_rule_ids=frozenset(active_rule_ids),
        severity_overrides=severity_overrides,
    )


def _optional_string(value: Any, *, key: str, path: Path) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ProjectConfigLoadError(f"`{key}` must be a non-empty string in {path}")
    return value.strip()


def _optional_severity(value: Any, *, key: str, path: Path) -> Severity | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ProjectConfigLoadError(f"`{key}` must be a severity string in {path}")
    try:
        return Severity(value.strip())
    except ValueError as exc:
        raise ProjectConfigLoadError(f"`{key}` must be one of low, medium, or high in {path}") from exc


def _optional_path(value: Any, *, key: str, base_path: Path) -> str | None:
    text = _optional_string(value, key=key, path=base_path)
    if text is None:
        return None
    return str((base_path.parent / text).resolve())


def _optional_string_list(payload: dict[str, Any], key: str, path: Path) -> list[str] | None:
    if key not in payload:
        return None
    value = payload.get(key)
    if not isinstance(value, list):
        raise ProjectConfigLoadError(f"`rules.{key}` must be an array of rule IDs in {path}")
    parsed_values: list[str] = []
    for index, entry in enumerate(value):
        if not isinstance(entry, str) or not entry.strip():
            raise ProjectConfigLoadError(f"`rules.{key}[{index}]` must be a non-empty string in {path}")
        parsed_values.append(entry.strip())
    return parsed_values


def _severity_override_map(value: Any, path: Path) -> dict[str, Severity]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ProjectConfigLoadError(f"`rules.severity_overrides` must be a TOML table in {path}")

    overrides: dict[str, Severity] = {}
    for rule_id, severity in value.items():
        if not isinstance(rule_id, str) or not rule_id.strip():
            raise ProjectConfigLoadError(f"`rules.severity_overrides` contains an invalid rule ID in {path}")
        if not isinstance(severity, str):
            raise ProjectConfigLoadError(
                f"`rules.severity_overrides.{rule_id}` must be one of low, medium, or high in {path}"
            )
        try:
            overrides[rule_id.strip()] = Severity(severity.strip())
        except ValueError as exc:
            raise ProjectConfigLoadError(
                f"`rules.severity_overrides.{rule_id}` must be one of low, medium, or high in {path}"
            ) from exc
    return overrides


def _ensure_known_keys(payload: dict[str, Any], *, allowed: set[str], label: str, path: Path) -> None:
    unknown_keys = sorted(set(payload) - allowed)
    if unknown_keys:
        raise ProjectConfigLoadError(
            f"Unknown {label} key(s) in {path}: {', '.join(unknown_keys)}"
        )
