"""Gate reevaluation cost with real preparation/evaluator calls, not timings.

Normalization is outside the measured region. Rule preparation owns one source
view and caches authorization per role/key pair, including negative results.
Workload and grant counts must not multiply that work.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from copy import deepcopy
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from tests.helpers.gcp_gcs_evaluation import plan_payload
from tests.providers.aws.test_aws_kms_authorization_reevaluation import (
    _CASES,
    _EXECUTION_ROLE_ARN,
    _ROLE_ADDRESS,
    _ROOT_ARN,
    _RULE_IDS,
    _SCENARIOS,
    _WORKLOAD_ADDRESS,
    _Basis,
    _change_authorization,
    _document_resources,
    _grant,
    _input,
    _key,
    _KmsCase,
    _policy,
    _protected_data_resources,
    _public_edge,
    _replace_source,
    _resource,
    _resources,
    _role,
    _service,
    _statement,
    _task_definition,
    _with_lifecycle,
)
from tfstride.analysis.preparation import PreparedAnalysis, prepare_analysis
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.app import TfStride
from tfstride.models import Finding, ResourceInventory, TerraformResource
from tfstride.providers.aws import analysis_indexes, kms_authorization_context
from tfstride.providers.aws.analysis_indexes import AwsAnalysisIndexes, build_aws_analysis_indexes
from tfstride.providers.aws.boundaries import AwsBoundaryContributor
from tfstride.providers.aws.kms_authorization_context import AwsKmsAuthorizationContext
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import AwsDecorationContext, AwsResourceIndexBuilder

_POLICY = RulePolicy(enabled_rule_ids=frozenset(_RULE_IDS))


def _scaled_resources(
    workloads: int = 1, grants: int = 1, keys_per_usage: int = 1, roles: int = 1
) -> list[TerraformResource]:
    resources = [
        *_public_edge(),
        _role("orders_execution", _EXECUTION_ROLE_ARN, [_statement("Allow", "kms:DescribeKey", "*")]),
    ]
    role_arns = [f"arn:aws:iam::111122223333:role/runtime{index}" for index in range(roles)]
    for index, arn in enumerate(role_arns):
        resources.append(_role(f"runtime{index}", arn, [_statement("Allow", [case.operation for case in _CASES], "*")]))
        task = _task_definition()
        task.values.update(family=f"runtime{index}", task_role_arn=arn)
        resources.append(replace(task, address=f"aws_ecs_task_definition.runtime{index}", name=f"runtime{index}"))
    for index in range(workloads):
        service = _service(f"aws_ecs_task_definition.runtime{index % roles}")
        service.values["name"] = f"w{index}"
        resources.append(replace(service, address=f"aws_ecs_service.w{index}", name=f"w{index}"))
    for purpose, case in enumerate(_CASES[:3]):
        operations = [item.operation for item in _CASES if item.key_name == case.key_name]
        for index in range(keys_per_usage):
            name = f"{case.key_name}{index}"
            key_id = f"{purpose + 1:08x}-0000-0000-0000-{index + 1:012x}"
            key = _with_lifecycle(
                _key(
                    case.key_name,
                    case.usage,
                    _policy(_statement("Allow", operations, "*", principal={"AWS": _ROOT_ARN})),
                ),
                origin="EXTERNAL" if case.key_name == "data" else "AWS_KMS",
            )
            key.values.update(id=key_id, key_id=key_id, arn=f"arn:aws:kms:us-east-1:111122223333:key/{key_id}")
            resources.append(replace(key, address=f"aws_kms_key.{name}", name=name))
            grant_operations = [case.operation.removeprefix("kms:")]
            if case.key_name == "data":
                grant_operations.append("CreateGrant")
            for role_index, arn in enumerate(role_arns):
                resources.extend(
                    _grant(f"{name}_r{role_index}_g{number}", name, grant_operations, grantee_principal=arn)
                    for number in range(grants)
                )
    return resources


def _prepare(engine: StrideRuleEngine, inventory: ResourceInventory) -> PreparedAnalysis:
    return prepare_analysis(
        inventory,
        rule_set=engine.rule_set_for("aws"),
        provider_extension_factory=build_aws_analysis_indexes,
        provider_boundary_contributor_factories=(AwsBoundaryContributor,),
    )


def _evaluate(engine: StrideRuleEngine, prepared: PreparedAnalysis) -> list[Finding]:
    return engine.evaluate(
        prepared.inventory,
        prepared.boundaries,
        analysis_indexes=prepared.indexes,
        rule_set=prepared.rule_set,
        rule_policy=_POLICY,
    )


@dataclass
class _KmsWork:
    calls: dict[str, Mock]
    contexts: list[AwsKmsAuthorizationContext]

    def counts(self) -> dict[str, int]:
        return {name: calls.call_count for name, calls in self.calls.items()}


@contextmanager
def _measure_kms_work() -> Iterator[_KmsWork]:
    contexts: list[AwsKmsAuthorizationContext] = []
    prepare = analysis_indexes.prepare_kms_authorization_context

    def record_prepare(context: AwsDecorationContext) -> AwsKmsAuthorizationContext:
        prepared = prepare(context)
        contexts.append(prepared)
        return prepared

    with ExitStack() as stack:
        calls = {
            "contexts": stack.enter_context(
                patch.object(analysis_indexes, "prepare_kms_authorization_context", side_effect=record_prepare)
            ),
            "references": stack.enter_context(
                patch.object(AwsResourceIndexBuilder, "build", autospec=True, side_effect=AwsResourceIndexBuilder.build)
            ),
        }
        for name, function in (
            ("role_sources", "current_iam_role_policies"),
            ("key_sources", "_current_key_policies"),
            ("grants", "current_kms_grants_by_key"),
            ("authorizations", "current_kms_operation_authorizations"),
        ):
            calls[name] = stack.enter_context(
                patch.object(kms_authorization_context, function, wraps=getattr(kms_authorization_context, function))
            )
        yield _KmsWork(calls, contexts)


def _expected_work(evaluations: int, *, preparations: int = 1) -> dict[str, int]:
    return {
        "contexts": preparations,
        "references": preparations,
        "role_sources": preparations,
        "key_sources": preparations,
        "grants": preparations,
        "authorizations": evaluations,
    }


@pytest.mark.parametrize("case", ("empty", "iam_only", "removed_keys"))
def test_no_keys_build_no_kms_dependencies(case: str) -> None:
    if case == "empty":
        inventory = ResourceInventory(provider="aws", resources=())
    elif case == "iam_only":
        inventory = AwsNormalizer().normalize(_scaled_resources(keys_per_usage=0))
    else:
        original = AwsNormalizer().normalize(_scaled_resources())
        assert any(aws_facts(resource).ecs_kms_operation_paths for resource in original.resources)
        inventory = replace(
            original,
            resources=tuple(resource for resource in original.resources if resource.resource_type != "aws_kms_key"),
        )
    engine = StrideRuleEngine()
    with _measure_kms_work() as work:
        prepared = _prepare(engine, inventory)
        assert prepared.indexes.require_provider_extension(AwsAnalysisIndexes).kms_authorization is None
        assert _evaluate(engine, prepared) == []
        assert engine.evaluate(inventory, prepared.boundaries, rule_policy=_POLICY) == []
    # AWS still prepares its shared network/relationship index for each call.
    assert work.counts() == {**dict.fromkeys(work.calls, 0), "references": 2}


@pytest.mark.parametrize(
    ("workloads", "grants", "keys_per_usage", "roles"),
    [(1, 1, 1, 1), (8, 1, 1, 1), (1, 6, 1, 1), (8, 6, 1, 1), (8, 3, 3, 1), (8, 3, 2, 2)],
    ids=("baseline", "more_workloads", "more_grants", "workloads_and_grants", "more_keys", "more_roles"),
)
def test_prepared_work_is_bounded_by_role_key_pairs(
    workloads: int, grants: int, keys_per_usage: int, roles: int
) -> None:
    inventory = AwsNormalizer().normalize(_scaled_resources(workloads, grants, keys_per_usage, roles))
    before = asdict(inventory)
    engine = StrideRuleEngine()
    with _measure_kms_work() as work:
        prepared = _prepare(engine, inventory)
        assert work.counts() == _expected_work(0)
        findings = _evaluate(engine, prepared)
        expected_counts = _expected_work(3 * keys_per_usage * roles)
        assert work.counts() == expected_counts
        assert _evaluate(engine, prepared) == findings
        assert work.counts() == expected_counts
    assert Counter(
        (call.args[0].address, call.args[1][0].address) for call in work.calls["authorizations"].call_args_list
    ) == Counter(
        (key.address, f"aws_iam_role.runtime{role}")
        for key in inventory.by_type("aws_kms_key")
        for role in range(roles)
    )
    assert Counter(finding.rule_id for finding in findings) == dict.fromkeys(_RULE_IDS, workloads)
    candidates = sum(
        len(aws_facts(service).ecs_kms_operation_paths) + len(aws_facts(service).ecs_kms_management_paths)
        for service in inventory.by_type("aws_ecs_service")
    )
    assert candidates == workloads * keys_per_usage * len(_CASES)
    assert (
        sum(
            len(item.values)
            for finding in findings
            for item in finding.evidence
            if item.key in {"kms_operation_paths", "kms_management_paths"}
        )
        == candidates
    )
    assert len(inventory.by_type("aws_kms_grant")) == 3 * keys_per_usage * roles * grants
    assert all(
        len(path["kms_grants"]) == grants
        for service in inventory.by_type("aws_ecs_service")
        for path in aws_facts(service).ecs_kms_operation_paths
    )
    assert asdict(inventory) == before


@pytest.mark.parametrize(("workloads", "roles"), ((1, 1), (8, 2)))
def test_automatic_preparation_is_bounded_and_fresh_for_scaled_inputs(workloads: int, roles: int) -> None:
    inventory = AwsNormalizer().normalize(_scaled_resources(workloads, grants=6, keys_per_usage=2, roles=roles))
    engine = StrideRuleEngine()
    prepared = _prepare(engine, inventory)
    expected = _evaluate(engine, prepared)
    assert len(expected) == workloads * len(_RULE_IDS)
    with _measure_kms_work() as work:
        assert engine.evaluate(inventory, prepared.boundaries, rule_policy=_POLICY) == expected
        assert work.counts() == _expected_work(6 * roles)
        assert engine.evaluate(inventory, prepared.boundaries, rule_policy=_POLICY) == expected
        assert work.counts() == _expected_work(12 * roles, preparations=2)
    assert work.contexts[0] is not work.contexts[1]


@pytest.mark.parametrize("state", ("empty", "denied", "unknown"))
@pytest.mark.parametrize("workloads", (1, 8))
def test_negative_results_are_cached_across_workloads_and_rules(state: str, workloads: int) -> None:
    original = AwsNormalizer().normalize(_scaled_resources(workloads=workloads, grants=0))
    inputs = _role(
        "runtime0",
        "arn:aws:iam::111122223333:role/runtime0",
        [
            _statement(
                "Deny" if state == "denied" else "Allow", "kms:*" if state == "denied" else "kms:DescribeKey", "*"
            )
        ],
    )
    if state == "unknown":
        inputs.unknown_values["inline_policy"] = [{"policy": True}]
    source = _resource(AwsNormalizer().normalize([inputs]), inputs.address)
    inventory = _replace_source(original, source)
    engine = StrideRuleEngine()
    assert len(_evaluate(engine, _prepare(engine, original))) == workloads * len(_RULE_IDS)
    with _measure_kms_work() as work:
        prepared = _prepare(engine, inventory)
        assert _evaluate(engine, prepared) == _evaluate(engine, prepared) == []
        context = prepared.indexes.require_provider_extension(AwsAnalysisIndexes).kms_authorization
        assert context is not None
        for case in _CASES[:3]:
            record = context.authorization(f"aws_kms_key.{case.key_name}0", inputs.address, case.operation)
            if state == "empty":
                assert record is None
            else:
                assert record is not None and record["authorization_state"] == state
    assert work.counts() == _expected_work(3)


@pytest.mark.parametrize("workloads", (1, 8))
def test_protected_data_convergence_reuses_prepared_dependencies(workloads: int) -> None:
    inputs = _protected_data_resources()
    service = _input(inputs, _WORKLOAD_ADDRESS)
    inputs.remove(service)
    for index in range(workloads):
        clone = deepcopy(service)
        clone.values["name"] = f"w{index}"
        inputs.append(replace(clone, address=f"aws_ecs_service.w{index}", name=f"w{index}"))
    inventory = AwsNormalizer().normalize(inputs)
    engine = StrideRuleEngine()
    prepared = _prepare(engine, inventory)
    with _measure_kms_work() as work:
        findings = _evaluate(engine, prepared)
        assert _evaluate(engine, prepared) == findings
    assert work.counts() == _expected_work(1, preparations=0)
    assert len(findings) == workloads
    assert all(
        finding.rule_id == _CASES[0].rule_id and "aws_s3_bucket.orders" in finding.affected_resources
        for finding in findings
    )


@pytest.mark.parametrize(("case", "basis"), _SCENARIOS, ids=[f"{case.name}/{basis}" for case, basis in _SCENARIOS])
@pytest.mark.parametrize("automatic", (False, True), ids=("prepared", "engine_defaults"))
def test_reused_engine_observes_revocation_uncertainty_and_restoration(
    case: _KmsCase, basis: _Basis, automatic: bool
) -> None:
    inputs = _resources(case, basis)
    original = AwsNormalizer().normalize(inputs)
    changed_inventories: list[ResourceInventory] = []
    for change in ("authority_removed", "unknown_key_policy", "key_deny"):
        changed = deepcopy(inputs)
        address = _change_authorization(changed, case, basis, change)
        fresh = AwsNormalizer().normalize(changed)
        changed_inventories.append(_replace_source(original, _resource(fresh, address)))
    engine = StrideRuleEngine()
    prepared = _prepare(engine, original)
    baseline = _evaluate(engine, prepared)
    assert len(baseline) == 1 and baseline[0].rule_id == case.rule_id
    sequence = [
        (original, baseline),
        *((inventory, []) for inventory in changed_inventories),
        (changed_inventories[-1], []),
        (original, baseline),
    ]
    with _measure_kms_work() as work:
        for inventory, expected in sequence:
            before = asdict(inventory)
            # These replacements leave internet-ingress inputs unchanged.
            findings = (
                engine.evaluate(inventory, prepared.boundaries, rule_policy=_POLICY)
                if automatic
                else _evaluate(engine, _prepare(engine, inventory))
            )
            assert findings == expected
            assert asdict(inventory) == before
    assert work.counts() == _expected_work(len(sequence), preparations=len(sequence))
    assert len({id(context) for context in work.contexts}) == len(sequence)
    assert len({id(context.decoration_context.index) for context in work.contexts}) == len(sequence)


def _source_inputs(kind: str) -> tuple[list[TerraformResource], str]:
    if kind in {"direct_key_policy", "iam_via_account_principal", "kms_grant"}:
        inputs = _resources(_CASES[0], kind)
        return inputs, {
            "direct_key_policy": "aws_kms_key.data",
            "iam_via_account_principal": _ROLE_ADDRESS,
            "kms_grant": "aws_kms_grant.runtime",
        }[kind]
    return _document_resources(kind)


_SOURCE_KINDS = (
    "direct_key_policy",
    "iam_via_account_principal",
    "kms_grant",
    "inline_policy_resource",
    "managed_policy",
    "key_policy_resource",
)


@pytest.mark.parametrize("kind", _SOURCE_KINDS)
@pytest.mark.parametrize("automatic", (False, True), ids=("prepared", "engine_defaults"))
def test_same_inventory_source_edits_require_fresh_preparation(kind: str, automatic: bool) -> None:
    inputs, address = _source_inputs(kind)
    inventory = AwsNormalizer().normalize(inputs)
    source = _resource(inventory, address)
    workload = _resource(inventory, _WORKLOAD_ADDRESS)
    original_workload = asdict(workload)
    original_statements = source.policy_statements
    original_operations = aws_facts(source).kms_grant_operations
    engine = StrideRuleEngine()
    prepared = _prepare(engine, inventory)
    baseline = _evaluate(engine, prepared)
    assert len(baseline) == 1
    with _measure_kms_work() as work:
        for authorized in (False, False, True, False, True):
            if kind == "kms_grant":
                aws_facts(source).set(
                    AwsResourceMetadata.KMS_GRANT_OPERATIONS, original_operations if authorized else ["Encrypt"]
                )
            else:
                source.policy_statements = original_statements if authorized else ()
            findings = (
                engine.evaluate(inventory, prepared.boundaries, rule_policy=_POLICY)
                if automatic
                else _evaluate(engine, _prepare(engine, inventory))
            )
            assert findings == (baseline if authorized else [])
    assert work.counts() == _expected_work(5, preparations=5)
    assert len({id(context) for context in work.contexts}) == 5
    assert asdict(workload) == original_workload


@pytest.mark.parametrize("kind", (*_SOURCE_KINDS, "managed_attachment"))
def test_reused_application_observes_changed_plan_at_same_path(tmp_path: Path, kind: str) -> None:
    inputs, address = _source_inputs(kind)
    changed = deepcopy(inputs)
    source = _input(changed, address)
    if kind == "kms_grant":
        source.values["operations"] = ["Encrypt"]
    elif kind == "managed_attachment":
        source.values["policy_arn"] = "arn:aws:iam::111122223333:policy/unmodeled"
    elif kind == "iam_via_account_principal":
        source.values["inline_policy"] = [
            {"name": "unrelated", "policy": _policy(_statement("Allow", "kms:DescribeKey", "*"))}
        ]
    else:
        source.values["policy"] = _policy(
            _statement(
                "Deny",
                "kms:*",
                "*",
                principal={"AWS": _ROOT_ARN} if kind in {"direct_key_policy", "key_policy_resource"} else None,
            )
        )
    empty = [
        resource
        for resource in inputs
        if resource.resource_type not in {"aws_kms_key", "aws_kms_grant", "aws_kms_key_policy"}
    ]
    app = TfStride(rule_policy=_POLICY)
    path = tmp_path / "kms.tfplan.json"
    baseline: list[Finding] | None = None
    for resources, authorized, expected_builds in (
        (inputs, True, 1),
        (changed, False, 1),
        (empty, False, 0),
        (inputs, True, 1),
    ):
        path.write_text(json.dumps(plan_payload(resources)), encoding="utf-8")
        with patch.object(
            analysis_indexes,
            "prepare_kms_authorization_context",
            wraps=analysis_indexes.prepare_kms_authorization_context,
        ) as builds:
            result = app.analyze_plan(path)
        assert builds.call_count == expected_builds
        fresh = TfStride(rule_policy=_POLICY).analyze_plan(path)
        assert result.findings == fresh.findings
        assert result.observations == fresh.observations
        assert result.operation_gaps == fresh.operation_gaps
        if authorized:
            assert len(result.findings) == 1
            if baseline is None:
                baseline = result.findings
            assert result.findings == baseline
        else:
            assert result.findings == []
