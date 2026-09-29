from __future__ import annotations

import json
import unittest
from dataclasses import replace
from itertools import permutations
from pathlib import Path
from tempfile import TemporaryDirectory

from tests.providers.gcp.normalizer_support import _terraform_resource
from tests.providers.gcp.test_gcp_cloud_run_gcs_access_paths import (
    _BUCKET_ADDRESS,
    _PROJECT,
    _SERVICE_ACCOUNT_EMAIL,
    _SERVICE_ACCOUNT_MEMBER,
    _bucket,
    _bucket_iam_member,
    _custom_role,
    _normalize,
    _workload_facts,
)
from tests.providers.gcp.test_gcp_public_cloud_run_gcs_mutation_rules import (
    _DISCLOSURE_RULE_ID,
    _RULE_ID,
    _cloud_run,
    _evaluate,
    _public_invoker,
)
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.input.terraform_plan import load_terraform_plan
from tfstride.models import TerraformResource
from tfstride.providers.gcp.custom_role_index import build_gcp_custom_role_index
from tfstride.providers.gcp.gcs_grant_evaluation import evaluate_gcs_bucket_grants
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_types import GcpResourceType


def _project_grant(
    *,
    project: str = _PROJECT,
    role: str = "roles/storage.objectCreator",
    kind: str = GcpResourceType.PROJECT_IAM_MEMBER,
    name: str = "grant",
    condition: dict[str, str] | None = None,
    unknown: dict[str, object] | None = None,
) -> TerraformResource:
    values: dict[str, object] = {"project": project, "role": role}
    if kind == GcpResourceType.PROJECT_IAM_MEMBER:
        values["member"] = _SERVICE_ACCOUNT_MEMBER
    elif kind == GcpResourceType.PROJECT_IAM_BINDING:
        values["members"] = [_SERVICE_ACCOUNT_MEMBER]
    else:
        binding: dict[str, object] = {"role": role, "members": [_SERVICE_ACCOUNT_MEMBER]}
        if condition:
            binding["condition"] = condition
        values = {"project": project, "policy_data": json.dumps({"bindings": [binding]})}
    if condition and kind != GcpResourceType.PROJECT_IAM_POLICY:
        values["condition"] = [condition]
    return _terraform_resource(f"{kind}.{name}", kind, values, unknown_values=unknown)


def _deny(
    *,
    project: str = _PROJECT,
    permission: str = "storage.googleapis.com/objects.create",
    principal: str = "principalSet://goog/public:all",
    extra: dict[str, object] | None = None,
    unknown: dict[str, object] | None = None,
    parent: str | None = None,
) -> TerraformResource:
    rule = {"denied_permissions": [permission], "denied_principals": [principal], **(extra or {})}
    return _terraform_resource(
        "google_iam_deny_policy.deny",
        GcpResourceType.IAM_DENY_POLICY,
        {
            "parent": parent or f"cloudresourcemanager.googleapis.com/projects/{project}",
            "rules": [{"deny_rule": [rule]}],
        },
        unknown_values=unknown,
    )


def _grants(resources):
    inventory = _normalize(resources)
    return evaluate_gcs_bucket_grants(
        _SERVICE_ACCOUNT_MEMBER,
        inventory.resources,
        build_gcp_custom_role_index(inventory.resources),
        resources=inventory.resources,
    )


class GcpProjectGcsGrantTests(unittest.TestCase):
    def test_exact_project_reference_resolves_but_collisions_do_not(self) -> None:
        project = _terraform_resource(
            "google_project.owner",
            GcpResourceType.PROJECT,
            {"project_id": _PROJECT, "org_id": "123"},
        )
        grants, problems = _grants(
            [
                _bucket(),
                project,
                _project_grant(project="google_project.owner.project_id"),
            ]
        )
        self.assertEqual(len(grants), 1)
        self.assertEqual(problems, [])
        collision = replace(project, address="google_project.collision", name="collision")
        grants, problems = _grants([_bucket(), project, collision, _project_grant()])
        self.assertEqual(grants, [])
        self.assertTrue(problems)

    def test_known_organization_deny_and_unrelated_organization(self) -> None:
        project = _terraform_resource(
            "google_project.owner",
            GcpResourceType.PROJECT,
            {"project_id": _PROJECT, "org_id": "123"},
        )
        for organization, expected_count in (("123", 0), ("456", 1)):
            with self.subTest(organization=organization):
                grants, problems = _grants(
                    [
                        _bucket(),
                        project,
                        _project_grant(),
                        _deny(parent=f"cloudresourcemanager.googleapis.com/organizations/{organization}"),
                    ]
                )
                self.assertEqual(len(grants), expected_count)
                self.assertEqual(problems, [])

    def test_different_authoritative_conditions_remain_distinct_alternatives(self) -> None:
        first = _project_grant(
            kind=GcpResourceType.PROJECT_IAM_BINDING,
            name="first",
            condition={"title": "first", "expression": "resource.name == 'first'"},
        )
        second = _project_grant(
            kind=GcpResourceType.PROJECT_IAM_BINDING,
            name="second",
            condition={"title": "second", "expression": "resource.name == 'second'"},
        )
        expected = None
        for ordered in permutations([_bucket(), first, second]):
            grants, problems = _grants(list(ordered))
            self.assertEqual(problems, [])
            self.assertEqual(len(grants), 2)
            self.assertTrue(all(grant["access_state"] == "conditional" for grant in grants))
            if expected is None:
                expected = grants
            self.assertEqual(grants, expected)

    def test_malformed_grant_conditions_and_unknown_policy_stay_unresolved(self) -> None:
        for kind in (GcpResourceType.PROJECT_IAM_MEMBER, GcpResourceType.PROJECT_IAM_POLICY):
            grant = _project_grant(kind=kind)
            values = dict(grant.values)
            if kind == GcpResourceType.PROJECT_IAM_MEMBER:
                values["condition"] = "unrepresentable"
            else:
                values["policy_data"] = json.dumps(
                    {
                        "bindings": [
                            {
                                "role": "roles/storage.objectCreator",
                                "members": [_SERVICE_ACCOUNT_MEMBER],
                                "condition": "unrepresentable",
                            }
                        ]
                    }
                )
            grants, problems = _grants([_bucket(), replace(grant, values=values)])
            self.assertEqual(grants, [])
            self.assertTrue(problems)
        grants, problems = _grants(
            [
                _bucket(),
                _project_grant(kind=GcpResourceType.PROJECT_IAM_POLICY, unknown={"policy_data": True}),
            ]
        )
        self.assertEqual(grants, [])
        self.assertTrue(problems)

    def test_payload_read_deny_cannot_fall_back_to_a_topology_boundary(self) -> None:
        resources = [
            _cloud_run(),
            _public_invoker(),
            _bucket(),
            _project_grant(role="roles/storage.objectViewer"),
        ]
        _, _, positive = _evaluate(resources, _DISCLOSURE_RULE_ID)
        self.assertEqual(len(positive), 1)
        for deny in (
            _deny(permission="storage.googleapis.com/objects.get"),
            _deny(permission="storage.googleapis.com/objects.*"),
            _deny(permission="storage.googleapis.com/objects.get", unknown={"rules": True}),
        ):
            with self.subTest(deny=deny.values):
                _, boundaries, findings = _evaluate([*resources, deny], _DISCLOSURE_RULE_ID)
                self.assertTrue(any(boundary.target == _BUCKET_ADDRESS for boundary in boundaries))
                self.assertEqual(findings, [])

    def test_project_grants_and_unknown_denies_survive_plan_ingestion(self) -> None:
        for include_deny in (False, True):
            resources = [_cloud_run(), _public_invoker(), _bucket(), _project_grant()]
            if include_deny:
                resources.append(_deny(unknown={"rules": True}))
            plan = {
                "terraform_version": "1.9.0",
                "planned_values": {
                    "root_module": {
                        "resources": [
                            {
                                "address": resource.address,
                                "type": resource.resource_type,
                                "name": resource.name,
                                "mode": resource.mode,
                                "provider_name": resource.provider_name,
                                "values": resource.values,
                            }
                            for resource in resources
                        ]
                    }
                },
                "resource_changes": [
                    {"address": resource.address, "change": {"after_unknown": resource.unknown_values}}
                    for resource in resources
                ],
            }
            with TemporaryDirectory() as directory:
                path = Path(directory) / "plan.json"
                path.write_text(json.dumps(plan), encoding="utf-8")
                inventory, _, findings = _evaluate(load_terraform_plan(path).resources)
            self.assertEqual(len(findings), 0 if include_deny else 1)
            if include_deny:
                self.assertTrue(_workload_facts(inventory).cloud_run_gcs_access_path_uncertainties)

    def test_project_member_binding_and_policy_enable_existing_mutation_finding(self) -> None:
        for kind in (
            GcpResourceType.PROJECT_IAM_MEMBER,
            GcpResourceType.PROJECT_IAM_BINDING,
            GcpResourceType.PROJECT_IAM_POLICY,
        ):
            with self.subTest(kind=kind):
                inventory, _, findings = _evaluate(
                    [_cloud_run(), _public_invoker(), _bucket(), _project_grant(kind=kind)]
                )
                self.assertEqual(len(findings), 1)
                path = _workload_facts(inventory).cloud_run_gcs_access_paths[0]
                self.assertEqual(path["bucket_address"], _BUCKET_ADDRESS)
                self.assertEqual(path["grant_basis"], "storage_project_iam")
                self.assertEqual(path["grant_project"], _PROJECT)
                self.assertEqual(path["access_classes"], ["write"])
                self.assertEqual(path["matched_permissions"], ["storage.objects.create"])
                self.assertIn(f"grant_project={_PROJECT}", str(findings[0].evidence))

    def test_known_deny_blocks_project_and_bucket_grants(self) -> None:
        for grant in (_project_grant(), _bucket_iam_member(role="roles/storage.objectCreator")):
            for permission in ("storage.googleapis.com/objects.create", "storage.googleapis.com/objects.*"):
                with self.subTest(grant=grant.address, permission=permission):
                    resources = [_cloud_run(), _public_invoker(), _bucket(), grant, _deny(permission=permission)]
                    inventory, _, findings = _evaluate(resources)
                    self.assertEqual(findings, [])
                    self.assertEqual(_workload_facts(inventory).cloud_run_gcs_access_paths, [])

    def test_deny_removes_only_matching_operations(self) -> None:
        grants, problems = _grants(
            [
                _bucket(),
                _project_grant(role="roles/storage.objectUser"),
                _deny(permission="storage.googleapis.com/objects.delete"),
            ]
        )
        self.assertEqual(problems, [])
        self.assertEqual(grants[0]["access_classes"], ["read", "write"])
        self.assertNotIn("storage.objects.delete", grants[0]["matched_permissions"])
        self.assertEqual(grants[0]["permission_constraints"][0]["state"], "denied")
        _, _, findings = _evaluate(
            [
                _cloud_run(),
                _public_invoker(),
                _bucket(),
                _project_grant(role="roles/storage.objectUser"),
                _deny(permission="storage.googleapis.com/objects.delete"),
            ]
        )
        self.assertEqual(len(findings), 1)
        self.assertIn("google_iam_deny_policy.deny:storage.objects.delete:denied", str(findings[0].evidence))

    def test_wildcard_custom_bucket_grant_cannot_bypass_a_specific_deny(self) -> None:
        grants, problems = _grants(
            [
                _bucket(),
                _custom_role(permissions=["storage.objects.*"]),
                _bucket_iam_member(role=f"projects/{_PROJECT}/roles/cloudRunStorage"),
                _deny(permission="storage.googleapis.com/objects.delete"),
            ]
        )
        self.assertEqual(problems, [])
        self.assertEqual(len(grants), 1)
        self.assertNotIn("delete", grants[0]["access_classes"])
        self.assertNotIn("storage.objects.delete", grants[0]["matched_permissions"])
        self.assertIn("write", grants[0]["access_classes"])

    def test_unrelated_denies_and_established_exceptions_preserve_grants(self) -> None:
        principal = f"principal://iam.googleapis.com/projects/-/serviceAccounts/{_SERVICE_ACCOUNT_EMAIL}"
        cases = [
            _deny(project="unrelated-project"),
            _deny(permission="storage.googleapis.com/objects.delete"),
            _deny(principal="principal://iam.googleapis.com/projects/-/serviceAccounts/other@example.com"),
            _deny(extra={"exception_principals": [principal]}),
            _deny(extra={"exception_permissions": ["storage.googleapis.com/objects.create"]}),
        ]
        for deny in cases:
            with self.subTest(deny=deny.values):
                grants, problems = _grants([_bucket(), _project_grant(), deny])
                self.assertEqual(len(grants), 1)
                self.assertEqual(problems, [])

    def test_uncertain_deny_never_becomes_unconditional_authority(self) -> None:
        cases = [
            _deny(extra={"denial_condition": [{"expression": "resource.matchTag('123/env', 'prod')"}]}),
            _deny(unknown={"rules": True}),
            _deny(unknown={"parent": True}),
            _deny(permission="storage.googleapis.com/*"),
            _deny(principal="principalSet://cloudresourcemanager.googleapis.com/projects/123/type/ServiceAccount"),
            _deny(extra={"exception_principals": ["unsupported-membership"]}),
            _deny(parent="cloudresourcemanager.googleapis.com/folders/123"),
            _deny(project="123456789"),
        ]
        for deny in cases:
            with self.subTest(deny=deny.values, unknown=deny.unknown_values):
                grants, problems = _grants([_bucket(), _project_grant(), deny])
                self.assertEqual(grants, [])
                self.assertTrue(problems)
                self.assertIn(_BUCKET_ADDRESS, str(problems))

    def test_unknown_rule_fields_do_not_poison_unrelated_permissions(self) -> None:
        deny = _deny(
            permission="storage.googleapis.com/objects.delete",
            unknown={"rules": [{"deny_rule": [{"denied_principals": True}]}]},
        )
        grants, problems = _grants([_bucket(), _project_grant(), deny])
        self.assertEqual(len(grants), 1)
        self.assertEqual(problems, [])

    def test_unknown_grant_constraints_and_custom_roles_stay_unresolved(self) -> None:
        for field in ("condition", "member", "role", "project"):
            with self.subTest(field=field):
                grants, problems = _grants([_bucket(), _project_grant(unknown={field: True})])
                self.assertEqual(grants, [])
                self.assertTrue(problems)
        grants, problems = _grants(
            [
                _bucket(),
                _custom_role(),
                _project_grant(role=f"projects/{_PROJECT}/roles/cloudRunStorage"),
            ]
        )
        self.assertEqual(grants, [])
        self.assertIn("not representable", str(problems))

    def test_condition_is_retained_without_a_definite_finding(self) -> None:
        condition = {
            "title": "prefix",
            "expression": 'resource.name.startsWith("projects/_/buckets/a/objects/private/")',
        }
        inventory, _, findings = _evaluate(
            [
                _cloud_run(),
                _public_invoker(),
                _bucket(),
                _project_grant(condition=condition),
            ]
        )
        self.assertEqual(findings, [])
        path = _workload_facts(inventory).cloud_run_gcs_access_paths[0]
        self.assertEqual(path["condition"], condition)
        self.assertEqual(path["access_state"], "conditional")

    def test_project_scope_does_not_follow_provider_alias_or_resource_order(self) -> None:
        other = _terraform_resource(
            "google_storage_bucket.other",
            GcpResourceType.STORAGE_BUCKET,
            {"name": "other-data", "project": "other-project"},
        )
        bucket = replace(_bucket(), provider_config_key="google.storage")
        grant = replace(_project_grant(), provider_config_key="google.iam")
        for ordered in permutations([bucket, grant, other]):
            grants, problems = _grants(list(ordered))
            self.assertEqual(problems, [])
            self.assertEqual([grant["bucket_address"] for grant in grants], [_BUCKET_ADDRESS])
        unknown_bucket = replace(bucket, unknown_values={"project": True})
        grants, problems = _grants([unknown_bucket, grant])
        self.assertEqual(grants, [])
        self.assertTrue(problems)

    def test_authoritative_manager_conflicts_and_incomplete_policy_block_grants(self) -> None:
        conflicts = [
            _project_grant(kind=GcpResourceType.PROJECT_IAM_POLICY, name="policy"),
            _project_grant(kind=GcpResourceType.PROJECT_IAM_BINDING, name="binding"),
            _project_grant(kind=GcpResourceType.PROJECT_IAM_POLICY, unknown={"policy_data": True}),
            _project_grant(kind=GcpResourceType.PROJECT_IAM_BINDING, unknown={"role": True}),
        ]
        for conflict in conflicts:
            with self.subTest(conflict=conflict.address):
                grants, problems = _grants([_bucket(), _project_grant(), conflict])
                self.assertEqual(grants, [])
                self.assertTrue(problems)

    def test_denies_are_rechecked_after_cached_path_was_created(self) -> None:
        inventory, boundaries, findings = _evaluate(
            [
                _cloud_run(),
                _public_invoker(),
                _bucket(),
                _project_grant(),
                _deny(permission="storage.googleapis.com/objects.delete"),
            ]
        )
        self.assertEqual(len(findings), 1)
        deny = inventory.get_by_address("google_iam_deny_policy.deny")
        assert deny is not None
        facts = gcp_facts(deny)
        rules = facts.iam_deny_policy_rules
        rules[0]["denied_permissions"] = ["storage.googleapis.com/objects.create"]
        facts.set(GcpResourceMetadata.IAM_DENY_POLICY_RULES, rules)
        self.assertTrue(_workload_facts(inventory).cloud_run_gcs_access_paths)
        findings = StrideRuleEngine().evaluate(inventory, boundaries)
        self.assertFalse(any(finding.rule_id == _RULE_ID for finding in findings))
