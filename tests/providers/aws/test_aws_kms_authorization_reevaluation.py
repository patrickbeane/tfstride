"""Require current AWS KMS authorization while preserving valid finding output.

Controls establish coherent source replacements and unchanged valid evidence.
Regenerate the golden only for reviewed behavior changes:
    .venv/bin/python -m tests.providers.aws.test_aws_kms_authorization_reevaluation --write
"""

from __future__ import annotations

import json
import sys
from copy import deepcopy
from dataclasses import asdict, dataclass, replace
from typing import Literal

import pytest

from tests.helpers.paths import GOLDEN_DIR
from tests.providers.aws.test_aws_ecs_kms_management_paths import _with_lifecycle
from tests.providers.aws.test_aws_ecs_kms_operation_paths import (
    _EXECUTION_ROLE_ARN,
    _KEY_ARNS,
    _ROOT_ARN,
    _TASK_ROLE_ARN,
    _grant,
    _key,
    _role,
    _task_definition,
)
from tests.providers.aws.test_aws_ecs_kms_operation_paths import (
    _resource as _terraform_resource,
)
from tests.providers.aws.test_aws_kms_operation_authorization import _ADMIN_ROLE_ARN, _policy, _statement
from tests.providers.aws.test_aws_public_ecs_dynamodb_mutation_rules import _public_edge, _service
from tests.providers.aws.test_aws_public_ecs_kms_management_rules import _public_management_resources
from tests.providers.test_protected_data_key_authority_convergence import _aws_resources as _protected_data_resources
from tfstride.analysis.preparation import PreparedAnalysis, prepare_analysis
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import (
    Finding,
    NormalizedResource,
    ResourceInventory,
    TerraformReferenceProvenance,
    TerraformReferenceResolution,
    TerraformReferenceResolutionState,
    TerraformReferenceTarget,
    TerraformResource,
)
from tfstride.providers.aws.analysis_indexes import build_aws_analysis_indexes
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.catalog import default_provider_boundary_contributor_factories_by_provider

_SNAPSHOT_PATH = GOLDEN_DIR / "aws_kms_authorization_findings.json"
_WORKLOAD_ADDRESS = "aws_ecs_service.orders"
_TASK_ADDRESS = "aws_ecs_task_definition.orders"
_ROLE_ADDRESS = "aws_iam_role.orders_task"
_GRANT_ADDRESS = "aws_kms_grant.runtime"
_Basis = Literal["direct_key_policy", "iam_via_account_principal", "kms_grant"]
_BASES: tuple[_Basis, ...] = ("direct_key_policy", "iam_via_account_principal", "kms_grant")
_CONDITION = {"StringEquals": {"kms:EncryptionContext:tenant": "orders"}}


@dataclass(frozen=True)
class _KmsCase:
    name: str
    rule_id: str
    key_name: str
    usage: str
    operation: str
    origin: str = "AWS_KMS"
    supports_grant: bool = False


_CASES = (
    _KmsCase(
        "decrypt", "aws-public-ecs-kms-decrypt-access", "data", "ENCRYPT_DECRYPT", "kms:Decrypt", supports_grant=True
    ),
    _KmsCase("sign", "aws-public-ecs-kms-signing-access", "signing", "SIGN_VERIFY", "kms:Sign", supports_grant=True),
    _KmsCase(
        "mac", "aws-public-ecs-kms-signing-access", "mac", "GENERATE_VERIFY_MAC", "kms:GenerateMac", supports_grant=True
    ),
    _KmsCase("disable", "aws-public-ecs-kms-key-disruption", "data", "ENCRYPT_DECRYPT", "kms:DisableKey"),
    _KmsCase(
        "schedule_deletion", "aws-public-ecs-kms-key-disruption", "data", "ENCRYPT_DECRYPT", "kms:ScheduleKeyDeletion"
    ),
    _KmsCase(
        "delete_material",
        "aws-public-ecs-kms-key-disruption",
        "data",
        "ENCRYPT_DECRYPT",
        "kms:DeleteImportedKeyMaterial",
        origin="EXTERNAL",
    ),
    _KmsCase(
        "create_grant",
        "aws-public-ecs-kms-authorization-delegation",
        "data",
        "ENCRYPT_DECRYPT",
        "kms:CreateGrant",
        supports_grant=True,
    ),
    _KmsCase(
        "put_policy", "aws-public-ecs-kms-authorization-delegation", "data", "ENCRYPT_DECRYPT", "kms:PutKeyPolicy"
    ),
)
_SCENARIOS = tuple((case, basis) for case in _CASES for basis in _BASES if basis != "kms_grant" or case.supports_grant)
_RULE_IDS = tuple(dict.fromkeys(case.rule_id for case in _CASES))
_CHANGES = (
    "authority_removed",
    "conditional_authority",
    "identity_deny",
    "key_deny",
    "unknown_identity_policy",
    "unknown_key_policy",
    "task_role_changed",
)


def _resources(case: _KmsCase, basis: _Basis) -> list[TerraformResource]:
    key_statements = [_statement("Allow", "kms:*", "*", principal={"AWS": _ADMIN_ROLE_ARN})]
    # A valid unrelated policy keeps completeness explicit without supplying
    # the operation under test through an additional authorization basis.
    identity_statements = [_statement("Allow", "kms:DescribeKey", "*")]
    if basis != "kms_grant":
        principal = _TASK_ROLE_ARN if basis == "direct_key_policy" else _ROOT_ARN
        key_statements.append(_statement("Allow", case.operation, "*", principal={"AWS": principal}))
    if basis == "iam_via_account_principal":
        identity_statements.append(_statement("Allow", case.operation, _KEY_ARNS[case.key_name]))
    return [
        *_public_edge(),
        _with_lifecycle(_key(case.key_name, case.usage, _policy(*key_statements)), origin=case.origin),
        _role("orders_task", _TASK_ROLE_ARN, identity_statements),
        _role("orders_execution", _EXECUTION_ROLE_ARN, [_statement("Allow", "kms:DescribeKey", "*")]),
        *([_grant("runtime", case.key_name, [case.operation.removeprefix("kms:")])] if basis == "kms_grant" else []),
        _task_definition(),
        _service(),
    ]


def _resource(inventory: ResourceInventory, address: str) -> NormalizedResource:
    resource = inventory.get_by_address(address)
    assert resource is not None, address
    return resource


def _input(resources: list[TerraformResource], address: str) -> TerraformResource:
    return next(resource for resource in resources if resource.address == address)


def _replace_source(inventory: ResourceInventory, source: NormalizedResource) -> ResourceInventory:
    return replace(
        inventory, resources=tuple(source if r.address == source.address else r for r in inventory.resources)
    )


def _evaluate(
    engine: StrideRuleEngine, inventory: ResourceInventory, rule_ids: tuple[str, ...]
) -> tuple[list[Finding], PreparedAnalysis]:
    prepared = prepare_analysis(
        inventory,
        rule_set=engine.rule_set_for("aws"),
        provider_extension_factory=build_aws_analysis_indexes,
        provider_boundary_contributor_factories=default_provider_boundary_contributor_factories_by_provider()["aws"],
    )
    return engine.evaluate(
        inventory,
        prepared.boundaries,
        analysis_indexes=prepared.indexes,
        rule_set=prepared.rule_set,
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids)),
    ), prepared


def _change_authorization(inputs: list[TerraformResource], case: _KmsCase, basis: _Basis, change: str) -> str:
    key = _input(inputs, f"aws_kms_key.{case.key_name}")
    role = _input(inputs, _ROLE_ADDRESS)
    if change == "task_role_changed":
        task = _input(inputs, _TASK_ADDRESS)
        task.values["task_role_arn"] = _EXECUTION_ROLE_ARN
        return task.address
    if change == "unknown_identity_policy":
        role.unknown_values["inline_policy"] = [{"policy": True}]
        return role.address
    if change == "unknown_key_policy":
        key.unknown_values["policy"] = True
        return key.address
    if change == "identity_deny":
        role.values["inline_policy"] = [{"name": "kms-use", "policy": _policy(_statement("Deny", case.operation, "*"))}]
        return role.address
    if change == "key_deny":
        policy = json.loads(str(key.values["policy"]))
        policy["Statement"].append(_statement("Deny", case.operation, "*", principal={"AWS": _TASK_ROLE_ARN}))
        key.values["policy"] = json.dumps(policy)
        return key.address
    if basis == "kms_grant":
        grant = _input(inputs, _GRANT_ADDRESS)
        if change == "authority_removed":
            grant.values["operations"] = ["Encrypt"]
        else:
            grant.values["constraints"] = [{"source_arn": "arn:aws:ecs:us-east-1:111122223333:service/orders/api"}]
        return grant.address
    source = key if basis == "direct_key_policy" else role
    policy = json.loads(str(key.values["policy"] if source is key else role.values["inline_policy"][0]["policy"]))
    statement = policy["Statement"][-1]
    if change == "authority_removed":
        statement["Action"] = "kms:DescribeKey"
    else:
        statement["Condition"] = deepcopy(_CONDITION)
    if source is key:
        key.values["policy"] = json.dumps(policy)
    else:
        role.values["inline_policy"][0]["policy"] = json.dumps(policy)
    return source.address


@dataclass
class _Reevaluation:
    original: ResourceInventory
    retained: ResourceInventory
    fresh: ResourceInventory
    changed_address: str
    before: list[Finding]
    after: list[Finding]
    normalized: list[Finding]
    preparations: tuple[PreparedAnalysis, ...]
    retained_metadata: dict[str, dict[str, object]]


def _reevaluate(
    inputs: list[TerraformResource], changed: list[TerraformResource], address: str, rule_id: str
) -> _Reevaluation:
    original = AwsNormalizer().normalize(inputs)
    fresh = AwsNormalizer().normalize(changed)
    retained = _replace_source(original, _resource(fresh, address))
    metadata = {resource.address: resource.metadata_snapshot() for resource in retained.resources}
    engine = StrideRuleEngine()
    before, original_preparation = _evaluate(engine, original, (rule_id,))
    after, retained_preparation = _evaluate(engine, retained, (rule_id,))
    normalized, fresh_preparation = _evaluate(engine, fresh, (rule_id,))
    return _Reevaluation(
        original,
        retained,
        fresh,
        address,
        before,
        after,
        normalized,
        (original_preparation, retained_preparation, fresh_preparation),
        metadata,
    )


@pytest.fixture(params=_SCENARIOS, ids=[f"{case.name}/{basis}" for case, basis in _SCENARIOS])
def scenario(request: pytest.FixtureRequest) -> tuple[_KmsCase, _Basis]:
    return request.param


@pytest.fixture(params=_CHANGES)
def reevaluation(request: pytest.FixtureRequest, scenario: tuple[_KmsCase, _Basis]) -> _Reevaluation:
    case, basis = scenario
    inputs = _resources(case, basis)
    changed = deepcopy(inputs)
    address = _change_authorization(changed, case, basis, request.param)
    return _reevaluate(inputs, changed, address, case.rule_id)


def _assert_coherent_replacement(observed: _Reevaluation) -> None:
    assert len(observed.before) == 1
    assert observed.normalized == []
    source = _resource(observed.retained, observed.changed_address)
    original_source = _resource(observed.original, observed.changed_address)
    assert source is _resource(observed.fresh, observed.changed_address)
    assert source is not original_source
    assert (
        source.metadata_snapshot() != original_source.metadata_snapshot()
        or source.policy_statements != original_source.policy_statements
    )
    assert _resource(observed.retained, _WORKLOAD_ADDRESS) is _resource(observed.original, _WORKLOAD_ADDRESS)
    for previous, current in zip(observed.preparations[:-1], observed.preparations[1:], strict=True):
        assert previous.indexes is not current.indexes
        assert previous.indexes.provider_extension is not current.indexes.provider_extension
        assert previous.boundaries is not current.boundaries
    assert {
        resource.address: resource.metadata_snapshot() for resource in observed.retained.resources
    } == observed.retained_metadata


def test_source_replacements_are_coherent_and_fresh_normalization_withdraws_authority(
    reevaluation: _Reevaluation,
) -> None:
    _assert_coherent_replacement(reevaluation)


def test_retained_paths_recheck_current_authorization(reevaluation: _Reevaluation) -> None:
    assert reevaluation.after == reevaluation.normalized


@pytest.fixture(params=[case for case in _CASES if case.supports_grant], ids=lambda case: case.name)
def grant_case(request: pytest.FixtureRequest) -> _KmsCase:
    return request.param


@pytest.fixture(params=("grantee_changed", "target_changed", "unknown_operations"))
def grant_reevaluation(request: pytest.FixtureRequest, grant_case: _KmsCase) -> _Reevaluation:
    inputs = _resources(grant_case, "kms_grant")
    changed = deepcopy(inputs)
    grant = _input(changed, _GRANT_ADDRESS)
    if request.param == "grantee_changed":
        grant.values["grantee_principal"] = _EXECUTION_ROLE_ARN
    elif request.param == "target_changed":
        grant.values["key_id"] = "arn:aws:kms:us-east-1:111122223333:key/unrelated"
    else:
        grant.unknown_values["operations"] = True
    return _reevaluate(inputs, changed, grant.address, grant_case.rule_id)


def test_grant_replacements_withdraw_authority_after_fresh_normalization(grant_reevaluation: _Reevaluation) -> None:
    _assert_coherent_replacement(grant_reevaluation)


def test_retained_paths_recheck_current_grant_relationships(grant_reevaluation: _Reevaluation) -> None:
    assert grant_reevaluation.after == grant_reevaluation.normalized


def test_equivalent_source_replacements_preserve_complete_findings(scenario: tuple[_KmsCase, _Basis]) -> None:
    case, basis = scenario
    inputs = _resources(case, basis)
    original = AwsNormalizer().normalize(inputs)
    fresh = AwsNormalizer().normalize(deepcopy(inputs))
    engine = StrideRuleEngine()
    expected, _ = _evaluate(engine, original, (case.rule_id,))
    assert len(expected) == 1
    finding = expected[0]
    assert finding.rule_id == case.rule_id
    assert finding.severity.value == "high"
    paths = next(
        item.values for item in finding.evidence if item.key in {"kms_operation_paths", "kms_management_paths"}
    )
    assert len(paths) == 1
    fields = set(paths[0].split("; "))
    expected_basis = {
        "direct_key_policy": "key_policy_direct",
        "iam_via_account_principal": "iam_via_key_policy",
        "kms_grant": "grant",
    }[basis]
    assert f"operation={case.operation}" in fields
    assert f"key_usage={case.usage}" in fields
    assert f"authorization_bases={expected_basis}" in fields
    for address in (
        _ROLE_ADDRESS,
        _TASK_ADDRESS,
        f"aws_kms_key.{case.key_name}",
        *([_GRANT_ADDRESS] if basis == "kms_grant" else []),
    ):
        retained = _replace_source(original, _resource(fresh, address))
        assert _evaluate(engine, retained, (case.rule_id,))[0] == expected


def test_unrelated_identity_permission_changes_preserve_valid_authority(scenario: tuple[_KmsCase, _Basis]) -> None:
    case, basis = scenario
    inputs = _resources(case, basis)
    changed = deepcopy(inputs)
    role = _input(changed, _ROLE_ADDRESS)
    policy = json.loads(str(role.values["inline_policy"][0]["policy"]))
    policy["Statement"][0]["Action"] = "kms:ListAliases"
    role.values["inline_policy"][0]["policy"] = json.dumps(policy)
    observed = _reevaluate(inputs, changed, role.address, case.rule_id)
    assert len(observed.before) == 1
    assert observed.after == observed.normalized == observed.before


def test_removing_key_invalidates_paths_and_restoration_preserves_output(scenario: tuple[_KmsCase, _Basis]) -> None:
    case, basis = scenario
    original = AwsNormalizer().normalize(_resources(case, basis))
    removed = replace(
        original, resources=tuple(r for r in original.resources if r.address != f"aws_kms_key.{case.key_name}")
    )
    engine = StrideRuleEngine()
    baseline, _ = _evaluate(engine, original, (case.rule_id,))
    assert len(baseline) == 1
    assert _evaluate(engine, removed, (case.rule_id,))[0] == []
    assert _evaluate(engine, original, (case.rule_id,))[0] == baseline


def _document_resources(kind: str) -> tuple[list[TerraformResource], str]:
    # A source-only replacement must not be justified by the old merged policy
    # statements still stored on the role or key.
    case = _CASES[0]
    inputs = _resources(case, "iam_via_account_principal")
    role = _input(inputs, _ROLE_ADDRESS)
    if kind == "key_policy_resource":
        key = _input(inputs, f"aws_kms_key.{case.key_name}")
        source = _terraform_resource(
            "aws_kms_key_policy", "runtime", {"key_id": _KEY_ARNS[case.key_name], "policy": key.values.pop("policy")}
        )
    else:
        policy = role.values["inline_policy"][0]["policy"]
        role.values["inline_policy"] = []
        if kind == "inline_policy_resource":
            source = _terraform_resource("aws_iam_role_policy", "runtime", {"role": _TASK_ROLE_ARN, "policy": policy})
        else:
            policy_arn = "arn:aws:iam::111122223333:policy/runtime-kms"
            source = _terraform_resource("aws_iam_policy", "runtime", {"arn": policy_arn, "policy": policy})
            inputs.append(
                _terraform_resource(
                    "aws_iam_role_policy_attachment", "runtime", {"role": _TASK_ROLE_ARN, "policy_arn": policy_arn}
                )
            )
    inputs.append(source)
    address = "aws_iam_role_policy_attachment.runtime" if kind == "managed_attachment" else source.address
    return inputs, address


@pytest.fixture(params=("inline_policy_resource", "managed_policy", "managed_attachment", "key_policy_resource"))
def document_reevaluation(request: pytest.FixtureRequest) -> _Reevaluation:
    kind = request.param
    case = _CASES[0]
    inputs, address = _document_resources(kind)
    changed = deepcopy(inputs)
    source = _input(changed, address)
    if kind == "managed_attachment":
        source.values["policy_arn"] = "arn:aws:iam::111122223333:policy/unmodeled"
    else:
        statement = _statement(
            "Deny",
            case.operation,
            "*",
            principal={"AWS": _TASK_ROLE_ARN} if kind == "key_policy_resource" else None,
        )
        _input(changed, source.address).values["policy"] = _policy(statement)
    return _reevaluate(inputs, changed, source.address, case.rule_id)


def test_document_replacement_preserves_stale_merged_evidence_only_in_retained_inventory(
    document_reevaluation: _Reevaluation,
) -> None:
    _assert_coherent_replacement(document_reevaluation)
    for address in (_ROLE_ADDRESS, "aws_kms_key.data"):
        assert _resource(document_reevaluation.retained, address) is _resource(document_reevaluation.original, address)


def test_replaced_policy_documents_invalidate_retained_findings(document_reevaluation: _Reevaluation) -> None:
    assert document_reevaluation.after == document_reevaluation.normalized


@pytest.mark.parametrize(
    "kind", ("inline_policy_resource", "managed_policy", "managed_attachment", "key_policy_resource")
)
@pytest.mark.parametrize("change", ("removed", "retargeted", "permission_removed", "equivalent"))
def test_current_policy_sources_replace_merged_authority(kind: str, change: str) -> None:
    inputs, address = _document_resources(kind)
    changed = deepcopy(inputs)
    source = _input(changed, address)
    if change == "removed":
        changed.remove(source)
    elif change == "retargeted":
        field, value = {
            "inline_policy_resource": ("role", _EXECUTION_ROLE_ARN),
            "managed_policy": ("arn", "arn:aws:iam::111122223333:policy/other"),
            "managed_attachment": ("role", _EXECUTION_ROLE_ARN),
            "key_policy_resource": ("key_id", "arn:aws:kms:us-east-1:111122223333:key/other"),
        }[kind]
        source.values[field] = value
    elif change == "permission_removed":
        if kind == "managed_attachment":
            source.values["policy_arn"] = "arn:aws:iam::111122223333:policy/other"
        else:
            policy = json.loads(str(source.values["policy"]))
            for statement in policy["Statement"]:
                statement["Action"] = "kms:DescribeKey"
            source.values["policy"] = json.dumps(policy)
    original = AwsNormalizer().normalize(inputs)
    fresh = AwsNormalizer().normalize(changed)
    retained = (
        replace(original, resources=tuple(resource for resource in original.resources if resource.address != address))
        if change == "removed"
        else _replace_source(original, _resource(fresh, address))
    )
    engine = StrideRuleEngine()
    rule_ids = (_CASES[0].rule_id,)
    before, _ = _evaluate(engine, original, rule_ids)
    expected, _ = _evaluate(engine, fresh, rule_ids)
    assert len(before) == 1
    assert expected == (before if change == "equivalent" else [])
    assert _evaluate(engine, retained, rule_ids)[0] == expected


@pytest.mark.parametrize("case", _CASES, ids=lambda case: case.name)
@pytest.mark.parametrize("revoked_basis", ("direct_key_policy", "iam_via_account_principal"))
def test_surviving_authority_refreshes_reported_basis(case: _KmsCase, revoked_basis: _Basis) -> None:
    inputs = _resources(case, "iam_via_account_principal")
    key = _input(inputs, f"aws_kms_key.{case.key_name}")
    policy = json.loads(str(key.values["policy"]))
    policy["Statement"].append(_statement("Allow", case.operation, "*", principal={"AWS": _TASK_ROLE_ARN}))
    key.values["policy"] = json.dumps(policy)
    changed = deepcopy(inputs)
    address = _change_authorization(changed, case, revoked_basis, "authority_removed")
    observed = _reevaluate(inputs, changed, address, case.rule_id)
    assert len(observed.before) == len(observed.normalized) == 1
    assert observed.before != observed.normalized
    assert observed.after == observed.normalized
    basis = "iam_via_key_policy" if revoked_basis == "direct_key_policy" else "key_policy_direct"
    paths = next(
        item.values
        for item in observed.after[0].evidence
        if item.key in {"kms_operation_paths", "kms_management_paths"}
    )
    assert all(f"authorization_bases={basis}" in path.split("; ") for path in paths)


def test_changed_grant_target_cannot_reuse_its_decorated_relationship(grant_case: _KmsCase) -> None:
    original = AwsNormalizer().normalize(_resources(grant_case, "kms_grant"))
    grant = replace(_resource(original, _GRANT_ADDRESS))
    aws_facts(grant).set(AwsResourceMetadata.KMS_GRANT_KEY_REFERENCE, "arn:aws:kms:us-east-1:111122223333:key/other")
    assert aws_facts(grant).kms_grant_resolved_key_address == f"aws_kms_key.{grant_case.key_name}"
    retained = _replace_source(original, grant)
    engine = StrideRuleEngine()
    assert len(_evaluate(engine, original, (grant_case.rule_id,))[0]) == 1
    assert _evaluate(engine, retained, (grant_case.rule_id,))[0] == []


@pytest.mark.parametrize("case", (_CASES[0], _CASES[3]), ids=lambda case: case.name)
@pytest.mark.parametrize(
    "change",
    (
        "missing_task",
        "missing_role",
        "ambiguous_role",
        "ambiguous_key",
        "unproven_role_reference",
        "symbolic_role_reference",
    ),
)
def test_current_task_role_and_key_relationships_must_remain_exact(case: _KmsCase, change: str) -> None:
    original = AwsNormalizer().normalize(_resources(case, "direct_key_policy"))
    if change in {"missing_task", "missing_role"}:
        address = _TASK_ADDRESS if change == "missing_task" else _ROLE_ADDRESS
        retained = replace(
            original, resources=tuple(resource for resource in original.resources if resource.address != address)
        )
    elif change in {"ambiguous_role", "ambiguous_key"}:
        address = _ROLE_ADDRESS if change == "ambiguous_role" else f"aws_kms_key.{case.key_name}"
        source = _resource(original, address)
        duplicate = replace(source, address=f"{source.resource_type}.duplicate", name="duplicate")
        retained = replace(original, resources=(*original.resources, duplicate))
    else:
        task = replace(_resource(original, _TASK_ADDRESS))
        aws_facts(task).set(AwsResourceMetadata.TASK_ROLE_ARN, _ROLE_ADDRESS)
        if change == "symbolic_role_reference":
            task = replace(
                task,
                reference_resolutions=(
                    TerraformReferenceResolution(
                        path=("task_role_arn",),
                        state=TerraformReferenceResolutionState.SYMBOLIC,
                        provenance=TerraformReferenceProvenance.CONFIGURATION_REFERENCE,
                        references=(f"{_ROLE_ADDRESS}.arn",),
                        targets=(TerraformReferenceTarget(address=_ROLE_ADDRESS, reference=f"{_ROLE_ADDRESS}.arn"),),
                    ),
                ),
            )
        retained = _replace_source(original, task)
    engine = StrideRuleEngine()
    before, _ = _evaluate(engine, original, (case.rule_id,))
    assert len(before) == 1
    assert _evaluate(engine, retained, (case.rule_id,))[0] == (before if change == "symbolic_role_reference" else [])


def test_inconsistent_merged_policy_provenance_cannot_authorize() -> None:
    inputs, _ = _document_resources("managed_policy")
    original = AwsNormalizer().normalize(inputs)
    role = _resource(original, _ROLE_ADDRESS)
    # Alter the aggregate without replacing its source. Preparation must not
    # guess which statements are inline and accidentally preserve authority.
    changed = replace(role, policy_statements=(*role.policy_statements, role.policy_statements[-1]))
    retained = _replace_source(original, changed)
    engine = StrideRuleEngine()
    assert len(_evaluate(engine, original, (_CASES[0].rule_id,))[0]) == 1
    assert _evaluate(engine, retained, (_CASES[0].rule_id,))[0] == []


def test_changed_s3_policy_source_removes_convergence_while_decrypt_authority_survives() -> None:
    inputs = _protected_data_resources()
    role = _input(inputs, _ROLE_ADDRESS)
    policy = json.loads(str(role.values["inline_policy"][0]["policy"]))
    s3_statement = policy["Statement"].pop()
    assert s3_statement["Action"] == "s3:GetObject"
    role.values["inline_policy"][0]["policy"] = json.dumps(policy)
    source = _terraform_resource("aws_iam_role_policy", "s3", {"role": _TASK_ROLE_ARN, "policy": _policy(s3_statement)})
    inputs.append(source)
    changed = deepcopy(inputs)
    _input(changed, source.address).values["policy"] = _policy(
        _statement("Allow", "s3:ListBucket", "arn:aws:s3:::orders")
    )
    observed = _reevaluate(inputs, changed, source.address, _CASES[0].rule_id)
    assert len(observed.before) == len(observed.normalized) == 1
    assert "aws_s3_bucket.orders" in observed.before[0].affected_resources
    assert "aws_s3_bucket.orders" not in observed.normalized[0].affected_resources
    assert observed.after == observed.normalized


def _downstream_resources() -> list[TerraformResource]:
    return [
        *_public_management_resources(),
        _terraform_resource(
            "aws_sqs_queue",
            "orders",
            {
                "name": "orders",
                "arn": "arn:aws:sqs:us-east-1:111122223333:orders",
                "kms_master_key_id": _KEY_ARNS["data"],
                "sqs_managed_sse_enabled": False,
            },
        ),
    ]


@pytest.fixture(params=("protected_data", "downstream_disruption"))
def dependency_reevaluation(request: pytest.FixtureRequest) -> tuple[_Reevaluation, str]:
    protected_data = request.param == "protected_data"
    inputs = _protected_data_resources() if protected_data else _downstream_resources()
    operation = "kms:Decrypt" if protected_data else "kms:DisableKey"
    rule_id = "aws-public-ecs-kms-decrypt-access" if protected_data else "aws-public-ecs-kms-key-disruption"
    dependent = "aws_s3_bucket.orders" if protected_data else "aws_sqs_queue.orders"
    # A second key keeps the finding alive after the first key loses authority.
    # Its surviving path must not inherit the revoked key's dependent evidence.
    inputs.append(
        _with_lifecycle(
            _key(
                "signing",
                "ENCRYPT_DECRYPT",
                _policy(_statement("Allow", operation, "*", principal={"AWS": _TASK_ROLE_ARN})),
            ),
            origin="AWS_KMS",
        )
    )
    changed = deepcopy(inputs)
    key = _input(changed, "aws_kms_key.data")
    key.values["policy"] = _policy(_statement("Deny", "kms:*", "*", principal={"AWS": _TASK_ROLE_ARN}))
    return _reevaluate(inputs, changed, key.address, rule_id), dependent


def test_revoking_one_key_preserves_other_authority_without_dependent_evidence_after_normalization(
    dependency_reevaluation: tuple[_Reevaluation, str],
) -> None:
    observed, dependent = dependency_reevaluation
    assert len(observed.before) == len(observed.normalized) == 1
    assert dependent in observed.before[0].affected_resources
    assert dependent not in observed.normalized[0].affected_resources
    assert "aws_kms_key.signing" in observed.normalized[0].affected_resources
    assert "aws_kms_key.data" not in observed.normalized[0].affected_resources
    assert _resource(observed.retained, observed.changed_address) is _resource(observed.fresh, observed.changed_address)
    assert _resource(observed.retained, _WORKLOAD_ADDRESS) is _resource(observed.original, _WORKLOAD_ADDRESS)


def test_revoked_key_paths_cannot_contribute_dependent_evidence(
    dependency_reevaluation: tuple[_Reevaluation, str],
) -> None:
    observed, _ = dependency_reevaluation
    assert observed.after == observed.normalized


def _mixed_resources() -> list[TerraformResource]:
    operations = tuple(case.operation for case in _CASES if case.key_name == "data")
    resources = _public_management_resources(operations=operations)
    _input(resources, "aws_kms_key.data").values["origin"] = "EXTERNAL"
    for case in _CASES[1:3]:
        resources.append(
            _key(
                case.key_name,
                case.usage,
                _policy(_statement("Allow", case.operation, "*", principal={"AWS": _TASK_ROLE_ARN})),
            )
        )
    return resources


def _valid_snapshots() -> dict[str, list[dict[str, object]]]:
    engine = StrideRuleEngine()
    # Pin complete output for distinct evidence structures. The parameterized
    # tests cover the full operation/basis matrix without duplicating reports.
    cases = {
        f"{case.name}/{basis}": _resources(case, basis)
        for case, basis in _SCENARIOS
        if basis == "kms_grant" and case.name in {"decrypt", "create_grant"}
    }
    cases["mixed"] = _mixed_resources()
    cases["protected_data"] = _protected_data_resources()
    cases["downstream_disruption"] = _downstream_resources()
    return {
        name: [asdict(finding) for finding in _evaluate(engine, AwsNormalizer().normalize(resources), _RULE_IDS)[0]]
        for name, resources in cases.items()
    }


def test_valid_findings_preserve_evidence_severity_dependencies_and_ordering() -> None:
    expected = json.loads(_SNAPSHOT_PATH.read_text(encoding="utf-8"))
    actual = _valid_snapshots()
    assert actual == expected
    assert [finding["rule_id"] for finding in actual["mixed"]] == list(_RULE_IDS)
    assert "aws_s3_bucket.orders" in actual["protected_data"][0]["affected_resources"]
    disruption = next(
        finding
        for finding in actual["downstream_disruption"]
        if finding["rule_id"] == "aws-public-ecs-kms-key-disruption"
    )
    assert "aws_sqs_queue.orders" in disruption["affected_resources"]


if __name__ == "__main__":
    if sys.argv[1:] != ["--write"]:
        raise SystemExit("Use --write to regenerate the reviewed valid-output golden.")
    _SNAPSHOT_PATH.write_text(json.dumps(_valid_snapshots(), indent=2) + "\n", encoding="utf-8")
