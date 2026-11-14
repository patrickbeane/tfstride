"""Characterize KMS findings and reevaluation with retained decoration evidence.

Regenerate the valid-output golden only for reviewed behavior changes:
    .venv/bin/python -m tests.providers.gcp.test_gcp_kms_authorization_reevaluation --write

"""

from __future__ import annotations

import json
import sys
from collections.abc import Sequence
from copy import deepcopy
from dataclasses import asdict, dataclass, replace
from itertools import product
from pathlib import Path
from typing import Literal
from unittest.mock import patch

import pytest

from tests.helpers.gcp_gcs_evaluation import plan_payload
from tests.helpers.paths import GOLDEN_DIR
from tests.providers.gcp.normalizer_support import _terraform_resource
from tests.providers.gcp.test_gcp_cloud_run_kms_management_paths import _key_ring
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
from tests.providers.gcp.test_gcp_public_cloud_run_kms_management_rules import _inventory_with_version_dependency
from tests.providers.test_protected_data_key_authority_convergence import GCP_BUCKET_ADDRESS, _gcp_resources
from tfstride.analysis.preparation import PreparedAnalysis, prepare_analysis
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.app import TfStride
from tfstride.models import Finding, NormalizedResource, ResourceInventory, TerraformResource
from tfstride.providers.catalog import default_provider_boundary_contributor_factories_by_provider
from tfstride.providers.gcp.analysis_indexes import GcpAnalysisIndexes, build_gcp_analysis_indexes
from tfstride.providers.gcp.kms_authorization import GcpKmsAuthorizationContext
from tfstride.providers.gcp.metadata import GcpResourceMetadata
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


def test_retained_kms_paths_recheck_current_authorization(reevaluation: _Reevaluation) -> None:
    assert reevaluation.retained_findings == reevaluation.fresh_findings


def test_same_engine_automatically_prepares_fresh_authorization(case: _KmsCase, reevaluation: _Reevaluation) -> None:
    engine = StrideRuleEngine()
    contexts: list[GcpKmsAuthorizationContext] = []
    build = GcpKmsAuthorizationContext.build

    def record_build(resources: Sequence[NormalizedResource]) -> GcpKmsAuthorizationContext:
        context = build(resources)
        contexts.append(context)
        return context

    before, after, _ = reevaluation.preparations
    policy = RulePolicy(enabled_rule_ids=frozenset({case.rule_id}))
    # Reuse the engine's rule set while alternating inventories with identical
    # resource addresses. Include both repeated negative results and recovery.
    with patch.object(GcpKmsAuthorizationContext, "build", side_effect=record_build):
        for prepared, expected in (
            (before, reevaluation.baseline_findings),
            (after, []),
            (after, []),
            (before, reevaluation.baseline_findings),
        ):
            assert engine.evaluate(prepared.inventory, prepared.boundaries, rule_policy=policy) == expected
    assert len(contexts) == 4
    assert len({id(context) for context in contexts}) == 4
    assert {resource.address: resource.metadata_snapshot() for resource in reevaluation.retained.resources} == (
        reevaluation.retained_metadata
    )


def test_same_inventory_permission_edits_require_fresh_preparation(case: _KmsCase) -> None:
    inputs = _resources(case, "crypto_key", custom=True)
    inventory = GcpNormalizer().normalize(inputs)
    definition = _resource(inventory, inputs[-2].address)
    original_permissions = gcp_facts(definition).custom_role_permissions
    workload = _resource(inventory, _WORKLOAD_ADDRESS)
    original_workload_metadata = workload.metadata_snapshot()
    engine = StrideRuleEngine()
    baseline, _ = _evaluate(engine, inventory, (case.rule_id,))
    assert len(baseline) == 1
    preparations: list[PreparedAnalysis] = []
    for permissions, expected in (
        (["cloudkms.cryptoKeys.get"], []),
        (original_permissions, baseline),
        (["cloudkms.cryptoKeys.get"], []),
        (original_permissions, baseline),
    ):
        gcp_facts(definition).set(GcpResourceMetadata.CUSTOM_ROLE_PERMISSIONS, permissions)
        findings, prepared = _evaluate(engine, inventory, (case.rule_id,))
        preparations.append(prepared)
        assert prepared.inventory is inventory
        assert findings == expected
    contexts = [
        prepared.indexes.require_provider_extension(GcpAnalysisIndexes).kms_authorization_context
        for prepared in preparations
    ]
    assert all(context is not None for context in contexts)
    assert len({id(context) for context in contexts}) == len(preparations)
    assert workload.metadata_snapshot() == original_workload_metadata


@pytest.mark.parametrize("custom", (False, True), ids=("builtin", "custom"))
def test_reused_application_observes_plan_changes_at_the_same_path(tmp_path: Path, custom: bool) -> None:
    inputs = _resources(_CASES[0], "crypto_key", custom=custom)
    changed = deepcopy(inputs)
    if custom:
        changed[-2].values["permissions"] = ["cloudkms.cryptoKeys.get"]
    else:
        changed[-1].values["member"] = _OTHER_MEMBER
    empty = [_public_cloud_run(), _public_invoker()]
    policy = RulePolicy(enabled_rule_ids=frozenset({_CASES[0].rule_id}))
    engine = TfStride(rule_policy=policy)
    path = tmp_path / "kms.tfplan.json"
    baseline: list[Finding] | None = None
    for resources, authorized, expected_builds in (
        (inputs, True, 1),
        (changed, False, 1),
        (empty, False, 0),
        (inputs, True, 1),
    ):
        path.write_text(json.dumps(plan_payload(resources)), encoding="utf-8")
        with patch.object(GcpKmsAuthorizationContext, "build", wraps=GcpKmsAuthorizationContext.build) as builds:
            result = engine.analyze_plan(path)
        assert builds.call_count == expected_builds
        assert result.findings == TfStride(rule_policy=policy).analyze_plan(path).findings
        if authorized:
            assert len(result.findings) == 1
            if baseline is None:
                baseline = result.findings
            assert result.findings == baseline
        else:
            assert result.findings == []


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


@pytest.mark.parametrize("unknown", (False, True), ids=("different", "unknown"))
def test_current_scope_must_still_cover_the_target(case: _KmsCase, scope: _Scope, unknown: bool) -> None:
    inputs = _resources(case, scope)
    changed_inputs = deepcopy(inputs)
    grant = changed_inputs[-1]
    field = {"project": "project", "key_ring": "key_ring_id", "crypto_key": "crypto_key_id"}[scope]
    if unknown:
        grant.unknown_values[field] = True
    else:
        grant.values[field] = {
            "project": "other-project",
            "key_ring": "projects/other-project/locations/global/keyRings/other",
            "crypto_key": "google_kms_crypto_key.other.id",
        }[scope]
    original = GcpNormalizer().normalize(inputs)
    fresh = GcpNormalizer().normalize(changed_inputs)
    retained = _replace_source(original, _resource(fresh, grant.address))
    engine = StrideRuleEngine()
    assert len(_evaluate(engine, original, (case.rule_id,))[0]) == 1
    assert _evaluate(engine, retained, (case.rule_id,))[0] == _evaluate(engine, fresh, (case.rule_id,))[0] == []


def _authoritative_source(grant: TerraformResource, mode: str) -> TerraformResource:
    values = dict(grant.values)
    binding = {"role": values.pop("role"), "members": [values.pop("member")]}
    if mode == "binding":
        values.update(binding)
    else:
        values["policy_data"] = json.dumps({"bindings": [binding]})
    return _terraform_resource(
        grant.address.replace("_iam_member.", f"_iam_{mode}."),
        grant.resource_type.replace("_iam_member", f"_iam_{mode}"),
        values,
    )


@pytest.mark.parametrize("mode", ("binding", "policy"))
def test_new_conflicting_iam_manager_invalidates_retained_paths(case: _KmsCase, scope: _Scope, mode: str) -> None:
    inputs = _resources(case, scope)
    conflicting_grant = deepcopy(inputs[-1])
    conflicting_grant.values["member"] = _OTHER_MEMBER
    if mode == "policy":
        # A policy conflicts even when its bindings do not grant KMS authority.
        conflicting_grant.values["role"] = "roles/viewer"
    conflict = _authoritative_source(conflicting_grant, mode)
    original = GcpNormalizer().normalize(inputs)
    fresh = GcpNormalizer().normalize([*inputs, conflict])
    retained = replace(original, resources=(*original.resources, _resource(fresh, conflict.address)))
    engine = StrideRuleEngine()
    assert len(_evaluate(engine, original, (case.rule_id,))[0]) == 1
    assert _evaluate(engine, retained, (case.rule_id,))[0] == _evaluate(engine, fresh, (case.rule_id,))[0] == []


@pytest.mark.parametrize("mode", ("binding", "policy"))
@pytest.mark.parametrize("unknown", (False, True), ids=("removed_member", "unknown"))
def test_authoritative_sources_recheck_current_bindings(
    case: _KmsCase, scope: _Scope, mode: str, unknown: bool
) -> None:
    inputs = _resources(case, scope)
    inputs[-1] = _authoritative_source(inputs[-1], mode)
    changed_inputs = deepcopy(inputs)
    grant = changed_inputs[-1]
    if unknown:
        grant.unknown_values["members" if mode == "binding" else "policy_data"] = True
    elif mode == "binding":
        grant.values["members"] = [_OTHER_MEMBER]
    else:
        grant.values["policy_data"] = json.dumps({"bindings": [{"role": case.role, "members": [_OTHER_MEMBER]}]})
    original = GcpNormalizer().normalize(inputs)
    fresh = GcpNormalizer().normalize(changed_inputs)
    retained = _replace_source(original, _resource(fresh, grant.address))
    engine = StrideRuleEngine()
    assert len(_evaluate(engine, original, (case.rule_id,))[0]) == 1
    assert _evaluate(engine, retained, (case.rule_id,))[0] == _evaluate(engine, fresh, (case.rule_id,))[0] == []


@pytest.mark.parametrize("ring_scope", ("project", "key_ring"))
@pytest.mark.parametrize("custom", (False, True), ids=("builtin", "custom"))
def test_explicit_ring_without_keys_rechecks_current_authority(ring_scope: str, custom: bool) -> None:
    permission = "cloudkms.keyRings.setIamPolicy"
    definition = _custom_role("ring_admin", [permission])
    role = str(definition.values["name"]) if custom else "roles/cloudkms.admin"
    grant = _project_member("ring_admin", role) if ring_scope == "project" else _ring_member("ring_admin", role)
    inputs = [_public_cloud_run(), _public_invoker(), _key_ring(), *([definition] if custom else []), grant]
    changed_inputs = deepcopy(inputs)
    changed = changed_inputs[-2] if custom else changed_inputs[-1]
    changed.values["permissions" if custom else "role"] = ["cloudkms.keyRings.get"] if custom else "roles/viewer"
    original = GcpNormalizer().normalize(inputs)
    fresh = GcpNormalizer().normalize(changed_inputs)
    retained = _replace_source(original, _resource(fresh, changed.address))
    engine = StrideRuleEngine()
    rule_ids = ("gcp-public-cloud-run-kms-authorization-delegation",)
    before, _ = _evaluate(engine, original, rule_ids)
    assert len(before) == 1
    assert "google_kms_key_ring.application" in before[0].affected_resources
    assert _evaluate(engine, retained, rule_ids)[0] == _evaluate(engine, fresh, rule_ids)[0] == []


def test_revoked_decrypt_path_cannot_contribute_protected_data_convergence() -> None:
    inputs = [
        *_gcp_resources(),
        _key("other", "ENCRYPT_DECRYPT"),
        _key_member("other_decrypter", "other", "roles/cloudkms.cryptoKeyDecrypter"),
    ]
    changed_inputs = deepcopy(inputs)
    grant_address = "google_kms_crypto_key_iam_member.runtime_decrypter"
    next(resource for resource in changed_inputs if resource.address == grant_address).values["role"] = (
        "roles/cloudkms.viewer"
    )
    original = GcpNormalizer().normalize(inputs)
    fresh = GcpNormalizer().normalize(changed_inputs)
    retained = _replace_source(original, _resource(fresh, grant_address))
    engine = StrideRuleEngine()
    rule_ids = ("gcp-public-cloud-run-kms-decrypt-access",)
    before, _ = _evaluate(engine, original, rule_ids)
    after, _ = _evaluate(engine, retained, rule_ids)
    assert len(before) == len(after) == 1
    assert GCP_BUCKET_ADDRESS in before[0].affected_resources
    assert GCP_BUCKET_ADDRESS not in after[0].affected_resources
    assert after == _evaluate(engine, fresh, rule_ids)[0]
    assert gcp_facts(_resource(retained, _WORKLOAD_ADDRESS)).cloud_run_gcs_protected_data_convergences


def test_revoked_destroy_permission_cannot_contribute_downstream_dependencies() -> None:
    baseline = _inventory_with_version_dependency(
        coherent=True,
        custom_role_permissions=["cloudkms.cryptoKeyVersions.update", "cloudkms.cryptoKeyVersions.destroy"],
    )
    # Retain update authority so the finding survives, but its destruction
    # targets and dependent-resource impact must disappear.
    definition = _custom_role("runtime_admin", ["cloudkms.cryptoKeyVersions.update"])
    replacement = _resource(GcpNormalizer().normalize([definition]), definition.address)
    retained = _replace_source(baseline, replacement)
    engine = StrideRuleEngine()
    rule_ids = ("gcp-public-cloud-run-kms-key-disruption",)
    before, _ = _evaluate(engine, baseline, rule_ids)
    after, _ = _evaluate(engine, retained, rule_ids)
    assert len(before) == len(after) == 1
    assert "google_pubsub_topic.orders" in before[0].affected_resources
    assert "google_pubsub_topic.orders" not in after[0].affected_resources
    paths = next(item.values for item in after[0].evidence if item.key == "kms_management_paths")
    assert paths and all("operation=cloudkms.cryptoKeyVersions.update;" in path for path in paths)
    dependencies = next(item.values for item in after[0].evidence if item.key == "downstream_dependencies")
    assert dependencies == [
        "unique_dependency_count=0; unique_dependent_resource_count=0; "
        "unique_version_target_count=0; blast_radius_basis=no_resolved_downstream_dependents"
    ]


if __name__ == "__main__":
    if sys.argv[1:] != ["--write"]:
        raise SystemExit("Use --write to regenerate the reviewed valid-output golden.")
    _SNAPSHOT_PATH.write_text(json.dumps(_valid_snapshots(), indent=2) + "\n", encoding="utf-8")
