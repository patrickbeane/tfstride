"""Characterize KMS findings and reevaluation with retained decoration evidence.

Regenerate the valid-output golden only for reviewed behavior changes:
    .venv/bin/python -m tests.providers.gcp.test_gcp_kms_authorization_reevaluation --write

The strict expected failures track the missing current-authorization validation.
Remove those markers when the next implementation slice fixes these cases.
"""

from __future__ import annotations

import json
import sys
from copy import deepcopy
from dataclasses import asdict, dataclass, replace
from itertools import product
from typing import Literal

import pytest

from tests.helpers.paths import GOLDEN_DIR
from tests.providers.gcp.test_gcp_cloud_run_kms_operation_paths import (
    _OTHER_MEMBER,
    _custom_role,
    _key,
    _key_member,
    _project_member,
    _ring_member,
    _version,
)
from tests.providers.gcp.test_gcp_public_cloud_run_firestore_mutation_rules import _public_cloud_run, _public_invoker
from tfstride.analysis.preparation import PreparedAnalysis, prepare_analysis
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import Finding, NormalizedResource, ResourceInventory, TerraformResource
from tfstride.providers.catalog import default_provider_boundary_contributor_factories_by_provider
from tfstride.providers.gcp.analysis_indexes import build_gcp_analysis_indexes
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_decoration.iam import iam_bindings
from tfstride.providers.gcp.resource_facts import gcp_facts

_SNAPSHOT_PATH = GOLDEN_DIR / "gcp_kms_authorization_findings.json"
_WORKLOAD_ADDRESS = "google_cloud_run_v2_service.orders"
_SCOPES = ("project", "key_ring", "crypto_key")
_CHANGES = ("role", "member", "condition", "unknown_condition", "custom_role_permissions")
_Scope = Literal["project", "key_ring", "crypto_key"]


@dataclass(frozen=True)
class _KmsCase:
    name: str
    rule_id: str
    purpose: str
    algorithm: str
    role: str
    permission: str


_CASES = (
    _KmsCase(
        "decrypt",
        "gcp-public-cloud-run-kms-decrypt-access",
        "ENCRYPT_DECRYPT",
        "GOOGLE_SYMMETRIC_ENCRYPTION",
        "roles/cloudkms.cryptoKeyDecrypter",
        "cloudkms.cryptoKeyVersions.useToDecrypt",
    ),
    _KmsCase(
        "sign",
        "gcp-public-cloud-run-kms-signing-access",
        "ASYMMETRIC_SIGN",
        "EC_SIGN_P256_SHA256",
        "roles/cloudkms.signer",
        "cloudkms.cryptoKeyVersions.useToSign",
    ),
    _KmsCase(
        "mac",
        "gcp-public-cloud-run-kms-signing-access",
        "MAC",
        "HMAC_SHA256",
        "roles/cloudkms.signer",
        "cloudkms.cryptoKeyVersions.useToSign",
    ),
    _KmsCase(
        "disruption",
        "gcp-public-cloud-run-kms-key-disruption",
        "ENCRYPT_DECRYPT",
        "GOOGLE_SYMMETRIC_ENCRYPTION",
        "roles/cloudkms.admin",
        "cloudkms.cryptoKeyVersions.destroy",
    ),
    _KmsCase(
        "delegation",
        "gcp-public-cloud-run-kms-authorization-delegation",
        "ENCRYPT_DECRYPT",
        "GOOGLE_SYMMETRIC_ENCRYPTION",
        "roles/cloudkms.admin",
        "cloudkms.cryptoKeys.setIamPolicy",
    ),
)
_RULE_IDS = tuple(dict.fromkeys(case.rule_id for case in _CASES))


def _resources(case: _KmsCase, scope: _Scope, *, custom: bool = False) -> list[TerraformResource]:
    role_definition = _custom_role(f"runtime_{case.name}", [case.permission, "cloudkms.cryptoKeys.get"])
    role = str(role_definition.values["name"]) if custom else case.role
    name = f"runtime_{case.name}"
    if scope == "project":
        grant = _project_member(name, role)
    elif scope == "key_ring":
        grant = _ring_member(name, role)
    else:
        grant = _key_member(name, case.name, role)
    return [
        _public_cloud_run(),
        _public_invoker(),
        _key(case.name, case.purpose),
        _version(case.name, case.algorithm),
        *([role_definition] if custom else []),
        grant,
    ]


def _resource(inventory: ResourceInventory, address: str) -> NormalizedResource:
    resource = inventory.get_by_address(address)
    assert resource is not None, address
    return resource


def _replace_source(original: ResourceInventory, source: NormalizedResource) -> ResourceInventory:
    return replace(
        original,
        resources=tuple(source if resource.address == source.address else resource for resource in original.resources),
    )


def _evaluate(
    engine: StrideRuleEngine, inventory: ResourceInventory, rule_ids: tuple[str, ...]
) -> tuple[list[Finding], PreparedAnalysis]:
    prepared = prepare_analysis(
        inventory,
        rule_set=engine.rule_set_for("gcp"),
        provider_extension_factory=build_gcp_analysis_indexes,
        provider_boundary_contributor_factories=default_provider_boundary_contributor_factories_by_provider()["gcp"],
    )
    findings = engine.evaluate(
        prepared.inventory,
        prepared.boundaries,
        analysis_indexes=prepared.indexes,
        rule_set=prepared.rule_set,
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids)),
    )
    return findings, prepared


def _finding_payloads(findings: list[Finding]) -> list[dict[str, object]]:
    # Preserve complete findings, including ordered evidence values and severity.
    return [asdict(finding) for finding in findings]


def _valid_snapshots() -> dict[str, list[dict[str, object]]]:
    engine = StrideRuleEngine()
    snapshots = {}
    for case, scope in product(_CASES, _SCOPES):
        inventory = GcpNormalizer().normalize(_resources(case, scope))
        findings, _ = _evaluate(engine, inventory, (case.rule_id,))
        snapshots[f"{case.name}/{scope}"] = _finding_payloads(findings)
    mixed = {resource.address: resource for case in _CASES for resource in _resources(case, "crypto_key")}
    findings, _ = _evaluate(engine, GcpNormalizer().normalize(list(mixed.values())), _RULE_IDS)
    snapshots["mixed"] = _finding_payloads(findings)
    return snapshots


@pytest.fixture(params=_CASES, ids=lambda case: case.name)
def case(request: pytest.FixtureRequest) -> _KmsCase:
    return request.param


@pytest.fixture(params=_SCOPES)
def scope(request: pytest.FixtureRequest) -> _Scope:
    return request.param


@dataclass
class _Reevaluation:
    original: ResourceInventory
    retained: ResourceInventory
    fresh: ResourceInventory
    changed_address: str
    baseline_findings: list[Finding]
    retained_findings: list[Finding]
    fresh_findings: list[Finding]
    preparations: tuple[PreparedAnalysis, ...]
    retained_metadata: dict[str, dict[str, object]]


@pytest.fixture(params=_CHANGES)
def reevaluation(request: pytest.FixtureRequest, case: _KmsCase, scope: _Scope) -> _Reevaluation:
    change = request.param
    inputs = _resources(case, scope, custom=change == "custom_role_permissions")
    changed_inputs = deepcopy(inputs)
    grant = changed_inputs[-1]
    changed_address = grant.address
    if change == "role":
        grant.values["role"] = "roles/viewer"
    elif change == "member":
        grant.values["member"] = _OTHER_MEMBER
    elif change == "condition":
        grant.values["condition"] = [{"title": "restricted", "expression": "false"}]
    elif change == "unknown_condition":
        grant.unknown_values["condition"] = True
    else:
        role = changed_inputs[-2]
        role.values["permissions"] = ["cloudkms.cryptoKeys.get"]
        changed_address = role.address

    original = GcpNormalizer().normalize(inputs)
    fresh = GcpNormalizer().normalize(changed_inputs)
    # Replace the entire normalized input, including IAM_BINDINGS and unknown
    # markers. Retain the old workload/key evidence to exercise revalidation.
    retained = _replace_source(original, _resource(fresh, changed_address))
    retained_metadata = {resource.address: resource.metadata_snapshot() for resource in retained.resources}
    engine = StrideRuleEngine()
    baseline_findings, before = _evaluate(engine, original, (case.rule_id,))
    retained_findings, after = _evaluate(engine, retained, (case.rule_id,))
    fresh_findings, normalized = _evaluate(engine, fresh, (case.rule_id,))
    return _Reevaluation(
        original,
        retained,
        fresh,
        changed_address,
        baseline_findings,
        retained_findings,
        fresh_findings,
        (before, after, normalized),
        retained_metadata,
    )


def test_valid_findings_preserve_evidence_severity_and_ordering() -> None:
    expected = json.loads(_SNAPSHOT_PATH.read_text(encoding="utf-8"))
    actual = _valid_snapshots()
    assert actual == expected
    for case, scope in product(_CASES, _SCOPES):
        assert [finding["rule_id"] for finding in actual[f"{case.name}/{scope}"]] == [case.rule_id]
    assert [finding["rule_id"] for finding in actual["mixed"]] == list(_RULE_IDS)


@pytest.mark.parametrize("custom", (False, True), ids=("builtin", "custom"))
def test_equivalent_replacement_preserves_valid_findings(case: _KmsCase, scope: _Scope, custom: bool) -> None:
    inputs = _resources(case, scope, custom=custom)
    original = GcpNormalizer().normalize(inputs)
    fresh = GcpNormalizer().normalize(deepcopy(inputs))
    grant_address = inputs[-1].address
    retained = _replace_source(original, _resource(fresh, grant_address))
    engine = StrideRuleEngine()
    before, _ = _evaluate(engine, original, (case.rule_id,))
    after, _ = _evaluate(engine, retained, (case.rule_id,))
    assert len(before) == 1
    assert _resource(retained, grant_address) is not _resource(original, grant_address)
    assert after == before


def test_unrelated_custom_role_permission_change_preserves_authority(case: _KmsCase, scope: _Scope) -> None:
    inputs = _resources(case, scope, custom=True)
    changed_inputs = deepcopy(inputs)
    role = changed_inputs[-2]
    role.values["permissions"] = [case.permission]
    original = GcpNormalizer().normalize(inputs)
    fresh = GcpNormalizer().normalize(changed_inputs)
    retained = _replace_source(original, _resource(fresh, role.address))
    engine = StrideRuleEngine()
    before, _ = _evaluate(engine, original, (case.rule_id,))
    after, _ = _evaluate(engine, retained, (case.rule_id,))
    normalized, _ = _evaluate(engine, fresh, (case.rule_id,))
    assert len(before) == 1
    assert len(after) == len(normalized) == 1
    assert gcp_facts(_resource(retained, role.address)).custom_role_permissions == [case.permission]
    # Management evidence includes the full effective-permission list, so a
    # fresh proof may describe the changed role differently while preserving
    # the same authority, finding identity, targets, and severity.
    assert replace(after[0], evidence=[]) == replace(before[0], evidence=[]) == replace(normalized[0], evidence=[])
    path_key = "kms_management_paths" if case.name in {"disruption", "delegation"} else "kms_operation_paths"
    for findings in (after, normalized):
        paths = next(item.values for item in findings[0].evidence if item.key == path_key)
        assert paths
        assert all(f"operation={case.permission};" in path and "authorization_state=granted" in path for path in paths)


def test_replacements_are_coherent_and_withdraw_authority_when_normalized_fresh(
    case: _KmsCase, reevaluation: _Reevaluation
) -> None:
    observed = reevaluation
    assert [finding.rule_id for finding in observed.baseline_findings] == [case.rule_id]
    assert observed.fresh_findings == []
    replacement = _resource(observed.retained, observed.changed_address)
    assert replacement is _resource(observed.fresh, observed.changed_address)
    assert replacement is not _resource(observed.original, observed.changed_address)
    assert replacement.metadata_snapshot() != _resource(observed.original, observed.changed_address).metadata_snapshot()
    if "custom_role" in replacement.resource_type:
        assert case.permission not in gcp_facts(replacement).custom_role_permissions
    else:
        assert iam_bindings(replacement) != iam_bindings(_resource(observed.original, observed.changed_address))
    assert _resource(observed.retained, _WORKLOAD_ADDRESS) is _resource(observed.original, _WORKLOAD_ADDRESS)
    assert _resource(observed.retained, f"google_kms_crypto_key.{case.name}") is _resource(
        observed.original, f"google_kms_crypto_key.{case.name}"
    )
    before, after, normalized = observed.preparations
    assert before.indexes is not after.indexes
    assert after.indexes is not normalized.indexes
    assert before.boundaries is not after.boundaries
    assert before.indexes.provider_extension is not after.indexes.provider_extension
    assert {resource.address: resource.metadata_snapshot() for resource in observed.retained.resources} == (
        observed.retained_metadata
    )


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="KMS path validation trusts retained authorization evidence; next slice must recheck current IAM inputs",
)
def test_retained_kms_paths_recheck_current_authorization(reevaluation: _Reevaluation) -> None:
    assert reevaluation.retained_findings == reevaluation.fresh_findings


def test_removing_grant_invalidates_paths_and_restoring_it_preserves_output(case: _KmsCase, scope: _Scope) -> None:
    inputs = _resources(case, scope)
    original = GcpNormalizer().normalize(inputs)
    grant_address = inputs[-1].address
    removed = replace(original, resources=tuple(r for r in original.resources if r.address != grant_address))
    engine = StrideRuleEngine()
    baseline, _ = _evaluate(engine, original, (case.rule_id,))
    without_grant, _ = _evaluate(engine, removed, (case.rule_id,))
    restored, _ = _evaluate(engine, original, (case.rule_id,))
    assert len(baseline) == 1
    assert without_grant == []
    assert restored == baseline


if __name__ == "__main__":
    if sys.argv[1:] != ["--write"]:
        raise SystemExit("Use --write to regenerate the reviewed valid-output golden.")
    _SNAPSHOT_PATH.write_text(json.dumps(_valid_snapshots(), indent=2) + "\n", encoding="utf-8")
