"""Gate KMS preparation cost with real constructor/evaluator calls, not timings.

Normalization is outside the measured region: its decoration dependencies have
a different lifetime. Prepared rules share one authorization context and cache
grant evaluation per target, independent of workload and candidate-path counts.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import asdict, replace
from unittest.mock import Mock, patch

import pytest

from tests.providers.gcp.test_gcp_cloud_run_gcs_access_paths import _bucket_iam_member
from tests.providers.gcp.test_gcp_cloud_run_kms_management_paths import _key_ring
from tests.providers.gcp.test_gcp_cloud_run_kms_operation_paths import (
    _RING,
    _custom_role,
    _key,
    _project_member,
    _version,
)
from tests.providers.gcp.test_gcp_kms_authorization_reevaluation import _CASES, _RULE_IDS, _replace_source, _resource
from tests.providers.gcp.test_gcp_public_cloud_run_firestore_mutation_rules import _public_cloud_run
from tests.providers.test_protected_data_key_authority_convergence import GCP_BUCKET_ADDRESS, _gcp_bucket
from tfstride.analysis.indexes import build_analysis_indexes
from tfstride.analysis.preparation import PreparedAnalysis, prepare_analysis
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import Finding, ResourceInventory, TerraformResource
from tfstride.providers.gcp import kms_authorization
from tfstride.providers.gcp.analysis_indexes import GcpAnalysisIndexes, build_gcp_analysis_indexes
from tfstride.providers.gcp.boundaries import GcpBoundaryContributor
from tfstride.providers.gcp.kms_authorization import GcpKmsAuthorizationContext
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_index import GcpResourceIndexBuilder
from tfstride.providers.gcp.resource_types import GcpResourceType

_POLICY = RulePolicy(enabled_rule_ids=frozenset(_RULE_IDS))
_PERMISSIONS = [
    "cloudkms.cryptoKeyVersions.useToDecrypt",
    "cloudkms.cryptoKeyVersions.useToSign",
    "cloudkms.cryptoKeyVersions.update",
    "cloudkms.cryptoKeyVersions.destroy",
    "cloudkms.cryptoKeys.setIamPolicy",
    "cloudkms.keyRings.setIamPolicy",
]


def _scaled_inventory(
    workloads: int = 1, grants: int = 1, keys_per_purpose: int = 1, *, protected_data: bool = False
) -> ResourceInventory:
    definition = _custom_role("runtime", _PERMISSIONS)
    resources = [_key_ring(), definition]
    for case in _CASES[:3]:  # Decrypt, asymmetric signing and MAC keys.
        for index in range(keys_per_purpose):
            name = f"{case.name}{index}"
            resources.extend([_key(name, case.purpose), _version(name, case.algorithm)])
    for index in range(workloads):
        name = f"w{index}"
        workload = _public_cloud_run(invoker_iam_disabled=True)
        workload.values["name"] = name
        resources.append(replace(workload, address=f"google_cloud_run_v2_service.{name}", name=name))
    resources.extend(_project_member(f"proof{index}", str(definition.values["name"])) for index in range(grants))
    if protected_data:
        bucket_grant = _bucket_iam_member()
        assert isinstance(bucket_grant, TerraformResource)
        resources.extend([_gcp_bucket(key_reference=f"{_RING}/cryptoKeys/decrypt0"), bucket_grant])
    return GcpNormalizer().normalize(resources)


def _prepare(engine: StrideRuleEngine, inventory: ResourceInventory) -> PreparedAnalysis:
    return prepare_analysis(
        inventory,
        rule_set=engine.rule_set_for("gcp"),
        provider_extension_factory=build_gcp_analysis_indexes,
        provider_boundary_contributor_factories=(GcpBoundaryContributor,),
    )


def _evaluate(engine: StrideRuleEngine, prepared: PreparedAnalysis) -> list[Finding]:
    return engine.evaluate(
        prepared.inventory,
        prepared.boundaries,
        analysis_indexes=prepared.indexes,
        rule_set=prepared.rule_set,
        rule_policy=_POLICY,
    )


@contextmanager
def _measure_kms_work() -> Iterator[dict[str, Mock]]:
    with ExitStack() as stack:
        measured = {
            "contexts": stack.enter_context(
                patch.object(GcpKmsAuthorizationContext, "build", wraps=GcpKmsAuthorizationContext.build)
            ),
            "references": stack.enter_context(
                patch.object(GcpResourceIndexBuilder, "build", autospec=True, side_effect=GcpResourceIndexBuilder.build)
            ),
        }
        for name in ("build_gcp_custom_role_index", "evaluate_kms_key_grants", "evaluate_kms_key_ring_grants"):
            measured[name] = stack.enter_context(
                patch.object(kms_authorization, name, wraps=getattr(kms_authorization, name))
            )
        yield measured


@pytest.mark.parametrize("case", ("empty", "iam_only", "removed_targets"))
def test_no_kms_targets_build_no_authorization_dependencies(case: str) -> None:
    if case == "empty":
        inventory = ResourceInventory(provider="gcp", resources=())
    elif case == "iam_only":
        inventory = GcpNormalizer().normalize(
            [_public_cloud_run(invoker_iam_disabled=True), _project_member("admin", "roles/cloudkms.admin")]
        )
    else:
        inventory = _scaled_inventory()
        assert any(gcp_facts(r).cloud_run_kms_operation_paths for r in inventory.resources)
        inventory = replace(
            inventory,
            resources=tuple(
                resource
                for resource in inventory.resources
                if resource.resource_type
                not in {
                    GcpResourceType.KMS_CRYPTO_KEY,
                    GcpResourceType.KMS_KEY_RING,
                    GcpResourceType.KMS_CRYPTO_KEY_VERSION,
                }
            ),
        )
    engine = StrideRuleEngine()
    with _measure_kms_work() as work:
        prepared = _prepare(engine, inventory)
        assert prepared.indexes.require_provider_extension(GcpAnalysisIndexes).kms_authorization_context is None
        assert _evaluate(engine, prepared) == []
        assert engine.evaluate(inventory, prepared.boundaries, rule_policy=_POLICY) == []
    assert {name: calls.call_count for name, calls in work.items()} == dict.fromkeys(work, 0)


@pytest.mark.parametrize(
    ("workloads", "grants", "keys_per_purpose"),
    [(1, 1, 1), (8, 1, 1), (1, 6, 1), (8, 6, 1), (4, 3, 3), (8, 6, 0)],
    ids=("baseline", "more_workloads", "more_proofs", "workloads_and_proofs", "more_targets", "ring_only"),
)
def test_prepared_dependency_work_is_bounded_by_targets(workloads: int, grants: int, keys_per_purpose: int) -> None:
    inventory = _scaled_inventory(workloads, grants, keys_per_purpose)
    engine = StrideRuleEngine()
    metadata_before = {r.address: r.metadata_snapshot() for r in inventory.resources}
    with _measure_kms_work() as work:
        prepared = _prepare(engine, inventory)
        assert (
            work["contexts"].call_count
            == work["references"].call_count
            == work["build_gcp_custom_role_index"].call_count
            == 1
        )
        assert work["evaluate_kms_key_grants"].call_count == work["evaluate_kms_key_ring_grants"].call_count == 0
        findings = _evaluate(engine, prepared)
        first_payload = [asdict(finding) for finding in findings]
        counts_after_first = {name: calls.call_count for name, calls in work.items()}
        assert [asdict(finding) for finding in _evaluate(engine, prepared)] == first_payload
        assert {name: calls.call_count for name, calls in work.items()} == counts_after_first

    assert counts_after_first == {
        "contexts": 1,
        "references": 1,
        "build_gcp_custom_role_index": 1,
        "evaluate_kms_key_grants": 3 * keys_per_purpose,
        "evaluate_kms_key_ring_grants": 1,
    }
    for function, resource_type in (
        ("evaluate_kms_key_grants", GcpResourceType.KMS_CRYPTO_KEY),
        ("evaluate_kms_key_ring_grants", GcpResourceType.KMS_KEY_RING),
    ):
        assert Counter(call.args[0].address for call in work[function].call_args_list) == Counter(
            resource.address for resource in inventory.by_type(resource_type)
        )
    expected_rules = _RULE_IDS if keys_per_purpose else (_CASES[-1].rule_id,)
    assert Counter(finding.rule_id for finding in findings) == dict.fromkeys(expected_rules, workloads)
    candidate_count = sum(
        len(gcp_facts(workload).cloud_run_kms_operation_paths) + len(gcp_facts(workload).cloud_run_kms_management_paths)
        for workload in inventory.by_type(GcpResourceType.CLOUD_RUN_V2_SERVICE)
    )
    # Make sure larger cases really exercise every candidate, not just empty or
    # filtered workloads that happen to have a small constructor count.
    assert candidate_count == workloads * grants * (12 * keys_per_purpose + 1)
    assert (
        sum(
            len(evidence.values)
            for finding in findings
            for evidence in finding.evidence
            if evidence.key in {"kms_operation_paths", "kms_management_paths"}
        )
        == candidate_count
    )
    assert {r.address: r.metadata_snapshot() for r in inventory.resources} == metadata_before


@pytest.mark.parametrize("keys_per_purpose", (0, 1), ids=("ring_only", "keys_and_ring"))
def test_empty_grant_results_are_cached_across_workloads_and_rules(keys_per_purpose: int) -> None:
    original = _scaled_inventory(workloads=8, grants=6, keys_per_purpose=keys_per_purpose)
    # Leave the sources and retained paths in place, but remove every KMS
    # permission so the current evaluators return empty grant lists.
    definition = _custom_role("runtime", ["resourcemanager.projects.get"])
    replacement = _resource(GcpNormalizer().normalize([definition]), definition.address)
    inventory = _replace_source(original, replacement)
    engine = StrideRuleEngine()
    with _measure_kms_work() as work:
        prepared = _prepare(engine, inventory)
        assert _evaluate(engine, prepared) == []
        assert _evaluate(engine, prepared) == []
    assert {name: calls.call_count for name, calls in work.items()} == {
        "contexts": 1,
        "references": 1,
        "build_gcp_custom_role_index": 1,
        "evaluate_kms_key_grants": 3 * keys_per_purpose,
        "evaluate_kms_key_ring_grants": 1,
    }


def test_dependent_convergence_reuses_prepared_kms_authorization() -> None:
    inventory = _scaled_inventory(workloads=4, grants=3, protected_data=True)
    engine = StrideRuleEngine()
    prepared = _prepare(engine, inventory)
    with _measure_kms_work() as work:
        findings = _evaluate(engine, prepared)
    assert (
        work["contexts"].call_count
        == work["references"].call_count
        == work["build_gcp_custom_role_index"].call_count
        == 0
    )
    assert work["evaluate_kms_key_grants"].call_count == 3
    assert work["evaluate_kms_key_ring_grants"].call_count == 1
    decrypt_findings = [finding for finding in findings if finding.rule_id == _CASES[0].rule_id]
    assert len(decrypt_findings) == 4
    assert all(GCP_BUCKET_ADDRESS in finding.affected_resources for finding in decrypt_findings)
    for workload in inventory.by_type(GcpResourceType.CLOUD_RUN_V2_SERVICE):
        assert len(gcp_facts(workload).cloud_run_gcs_protected_data_convergences) == 3


@pytest.mark.parametrize("workloads", (1, 8))
def test_omitted_provider_extension_constructs_fresh_dependencies_per_detector(workloads: int) -> None:
    original = _scaled_inventory(workloads=workloads, grants=3)
    definition = _custom_role("runtime", ["cloudkms.cryptoKeys.get"])
    replacement = _resource(GcpNormalizer().normalize([definition]), definition.address)
    revoked = _replace_source(original, replacement)
    engine = StrideRuleEngine()
    baseline = _evaluate(engine, _prepare(engine, original))
    for inventory, expected in ((original, baseline), (revoked, []), (original, baseline)):
        indexes = build_analysis_indexes(inventory, provider_extension_factory=lambda _inventory: None)
        # Workloads and their public-exposure boundaries are unchanged.
        boundaries = _prepare(engine, inventory).boundaries
        with _measure_kms_work() as work:
            findings = engine.evaluate(inventory, boundaries, analysis_indexes=indexes, rule_policy=_POLICY)
        assert findings == expected
        assert (
            work["contexts"].call_count
            == work["references"].call_count
            == work["build_gcp_custom_role_index"].call_count
            == len(_RULE_IDS)
        )
        assert work["evaluate_kms_key_grants"].call_count <= 3 * len(_RULE_IDS)
        assert work["evaluate_kms_key_ring_grants"].call_count <= len(_RULE_IDS)
