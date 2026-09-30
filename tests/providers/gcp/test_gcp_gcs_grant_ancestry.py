from __future__ import annotations

import json
import unittest
from dataclasses import replace
from itertools import permutations

from tests.providers.gcp.normalizer_support import _terraform_resource
from tests.providers.gcp.test_gcp_cloud_run_gcs_access_paths import (
    _PROJECT,
    _SERVICE_ACCOUNT_MEMBER,
    _bucket,
)
from tests.providers.gcp.test_gcp_project_gcs_grants import _deny, _grants, _project_grant
from tests.providers.gcp.test_gcp_public_cloud_run_gcs_mutation_rules import _cloud_run, _evaluate, _public_invoker
from tests.providers.gcp.test_gcp_scoped_gcs_consumers import _findings
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_types import GcpResourceType

_MUTATE = "gcp-public-cloud-run-gcs-mutation-access"
_READ = "gcp-public-workload-sensitive-data-access"


def _hierarchy():
    return [
        _terraform_resource(
            "google_project.owner", GcpResourceType.PROJECT, {"project_id": _PROJECT, "folder_id": "200"}
        ),
        _terraform_resource(
            "google_folder.child", GcpResourceType.FOLDER, {"name": "folders/200", "parent": "folders/100"}
        ),
        _terraform_resource(
            "google_folder.parent", GcpResourceType.FOLDER, {"name": "folders/100", "parent": "organizations/10"}
        ),
    ]


def _grant(
    *,
    scope="folders/100",
    role="roles/storage.objectCreator",
    condition=None,
    name="grant",
    mode="member",
    unknown=None,
):
    kind = (
        "google_folder_iam"
        if scope.startswith("folders/") or scope.startswith("google_folder.")
        else "google_organization_iam"
    )
    field = "folder" if kind == "google_folder_iam" else "org_id"
    binding = {"role": role, "members": [_SERVICE_ACCOUNT_MEMBER]}
    if condition:
        binding["condition"] = condition
    if mode == "policy":
        values = {field: scope, "policy_data": json.dumps({"bindings": [binding]})}
    else:
        values = {field: scope, "role": role}
        values["member" if mode == "member" else "members"] = (
            _SERVICE_ACCOUNT_MEMBER if mode == "member" else [_SERVICE_ACCOUNT_MEMBER]
        )
        if condition:
            values["condition"] = [condition]
    return _terraform_resource(f"{kind}_{mode}.{name}", f"{kind}_{mode}", values, unknown_values=unknown)


class GcpGcsGrantAncestryTests(unittest.TestCase):
    def test_nested_ancestor_grants_reach_downstream_mutation_findings(self):
        for scope in ("folders/200", "folders/100", "organizations/10", "google_folder.parent.name"):
            for mode in ("member", "binding", "policy"):
                with self.subTest(scope=scope, mode=mode):
                    grant = _grant(scope=scope, mode=mode)
                    inventory, _, findings = _evaluate(
                        [_cloud_run(), _public_invoker(), _bucket(), *_hierarchy(), grant], _MUTATE
                    )
                    self.assertEqual(len(findings), 1)
                    self.assertIn(grant.address, str(findings[0].evidence))
                    self.assertIn("grant_ancestry=google_project.owner", str(findings[0].evidence))
                    workload = inventory.get_by_address(_cloud_run().address)
                    paths = gcp_facts(workload).cloud_run_gcs_access_paths
                    self.assertEqual(len(paths), 1)
                    self.assertEqual(paths[0]["matched_permissions"], ["storage.objects.create"])
                    self.assertNotIn("read", paths[0]["access_classes"])

    def test_missing_links_remain_uncertain_but_proven_immediate_parent_survives(self):
        project, child, _ = _hierarchy()
        for resources, scope, expected in (
            ([], "folders/100", False),
            ([project], "folders/100", False),
            ([project], "folders/200", True),
            ([project, child], "organizations/10", False),
            ([project, child], "folders/100", True),
        ):
            with self.subTest(scope=scope, resources=len(resources)):
                grants, problems = _grants([_bucket(), *resources, _grant(scope=scope)])
                self.assertEqual(bool(grants), expected)
                self.assertEqual(bool(problems), not expected)

    def test_unrelated_scopes_are_excluded_only_with_complete_ancestry(self):
        for scope in ("folders/999", "organizations/99"):
            grants, problems = _grants([_bucket(), *_hierarchy(), _grant(scope=scope)])
            self.assertEqual((grants, problems), ([], []))

    def test_unknown_conflicting_cyclic_and_ambiguous_ancestry(self):
        project, child, parent = _hierarchy()
        variants = [
            [replace(project, unknown_values={"folder_id": True}), child, parent],
            [replace(project, values={**project.values, "org_id": "10"}), child, parent],
            [project, replace(child, unknown_values={"parent": True}), parent],
            [project, child, replace(parent, values={**parent.values, "parent": "folders/200"})],
            [project, child, parent, replace(child, address="google_folder.collision", name="collision")],
            [project, child, parent, replace(project, address="google_project.collision", name="collision")],
        ]
        for hierarchy in variants:
            with self.subTest(hierarchy=hierarchy):
                grants, problems = _grants([_bucket(), *hierarchy, _grant(scope="organizations/10")])
                self.assertEqual(grants, [])
                self.assertTrue(problems)

    def test_names_and_provider_aliases_are_not_project_ownership(self):
        project, child, parent = _hierarchy()
        for value in (None, "another-project", "owner"):
            for provider in ("google", "google.shared"):
                bucket = replace(_bucket(), provider_config_key=provider, values={**_bucket().values, "project": value})
                resources = [bucket, replace(project, provider_config_key=provider), child, parent, _grant()]
                grants, problems = _grants(resources)
                self.assertEqual(grants, [])
                self.assertTrue(problems)
        # Exact references remain usable across provider configurations.
        bucket = replace(
            _bucket(),
            provider_config_key="google.other",
            values={**_bucket().values, "project": "google_project.owner.project_id"},
        )
        grants, problems = _grants([bucket, project, child, parent, _grant()])
        self.assertEqual(len(grants), 1)
        self.assertEqual(problems, [])

    def test_unknown_ancestor_iam_fields_do_not_become_authority(self):
        for field in ("folder", "role", "member", "condition"):
            with self.subTest(field=field):
                grants, problems = _grants([_bucket(), *_hierarchy(), _grant(unknown={field: True})])
                self.assertEqual(grants, [])
                self.assertTrue(problems)

    def test_conditions_and_scopes_remain_separate_alternatives(self):
        condition = {"title": "limited", "expression": 'resource.name.startsWith("projects/_/buckets/other")'}
        conditional = _grant(condition=condition, mode="binding")
        unconditional = _grant(scope="organizations/10", mode="policy")
        grants, problems = _grants([_bucket(), *_hierarchy(), conditional, unconditional])
        self.assertEqual(problems, [])
        self.assertEqual({grant["access_state"] for grant in grants}, {"conditional", "granted"})
        self.assertEqual(
            next(grant for grant in grants if grant["access_state"] == "conditional")["condition"], condition
        )
        for extra, count in (([], 0), ([unconditional], 1)):
            _, _, findings = _evaluate(
                [_cloud_run(), _public_invoker(), _bucket(), *_hierarchy(), conditional, *extra], _MUTATE
            )
            self.assertEqual(len(findings), count)
            if findings:
                self.assertIn(unconditional.address, str(findings[0].evidence))
                self.assertNotIn(conditional.address, str(findings[0].evidence))

    def test_inherited_denies_constrain_both_parent_and_project_grants(self):
        for grant in (_grant(), _project_grant()):
            for parent, expected in (("folders/100", 0), ("organizations/10", 0), ("folders/999", 1)):
                with self.subTest(grant=grant.address, deny=parent):
                    _, _, findings = _evaluate(
                        [_cloud_run(), _public_invoker(), _bucket(), *_hierarchy(), grant, _deny(parent=parent)],
                        _MUTATE,
                    )
                    self.assertEqual(len(findings), expected)
        _, _, findings = _evaluate(
            [
                _cloud_run(),
                _public_invoker(),
                _bucket(),
                _hierarchy()[0],
                _grant(scope="folders/200"),
                _deny(parent="organizations/10"),
            ],
            _MUTATE,
        )
        self.assertEqual(findings, [])

    def test_conditions_on_applicable_denies_preserve_uncertainty(self):
        deny = _deny(
            parent="folders/100", extra={"denial_condition": [{"expression": "resource.matchTag('tag', 'value')"}]}
        )
        grants, problems = _grants([_bucket(), *_hierarchy(), _grant(), deny])
        self.assertEqual(grants, [])
        self.assertTrue(problems)

    def test_revalidation_observes_changed_parent_and_preserves_cached_evidence_only_as_history(self):
        inventory, _, before = _evaluate([_cloud_run(), _public_invoker(), _bucket(), *_hierarchy(), _grant()], _MUTATE)
        self.assertEqual(len(before), 1)
        parent = inventory.get_by_address("google_folder.child")
        gcp_facts(parent).set(GcpResourceMetadata.HIERARCHY_PARENT, "organizations/99")
        self.assertEqual(_findings(inventory, {_MUTATE}), [])

    def test_resource_permutations_preserve_grants_and_findings(self):
        hierarchy = _hierarchy()
        baseline = None
        for ordered in permutations([*hierarchy, _grant()]):
            grants, problems = _grants([_bucket(), *ordered])
            _, _, findings = _evaluate([_cloud_run(), _public_invoker(), _bucket(), *ordered], _MUTATE)
            result = (grants, problems, findings)
            if baseline is None:
                baseline = result
            self.assertEqual(result, baseline)

    def test_operation_consumers_use_ancestor_scope_without_widening_permissions(self):
        delete = "gcp-public-cloud-run-gcs-object-disruption"
        bucket_delete = "gcp-public-cloud-run-gcs-bucket-topology-disruption"
        rules = {_READ, _MUTATE, delete, bucket_delete}
        for scope in ("folders/100", "organizations/10"):
            for role, expected in (
                ("roles/storage.objectCreator", {_MUTATE}),
                ("roles/storage.objectViewer", {_READ}),
                ("roles/storage.objectAdmin", {_READ, _MUTATE, delete}),
                ("roles/storage.admin", rules),
            ):
                with self.subTest(scope=scope, role=role):
                    _, _, findings = _evaluate(
                        [_cloud_run(), _public_invoker(), _bucket(), *_hierarchy(), _grant(scope=scope, role=role)],
                        *rules,
                    )
                    self.assertEqual({finding.rule_id for finding in findings}, expected)
        for permission, removed in (
            ("objects.get", _READ),
            ("objects.delete", delete),
            ("buckets.delete", bucket_delete),
        ):
            with self.subTest(permission=permission):
                _, _, findings = _evaluate(
                    [
                        _cloud_run(),
                        _public_invoker(),
                        _bucket(),
                        *_hierarchy(),
                        _grant(role="roles/storage.admin"),
                        _deny(parent="organizations/10", permission=f"storage.googleapis.com/{permission}"),
                    ],
                    *rules,
                )
                self.assertEqual({finding.rule_id for finding in findings}, rules - {removed})

    def test_distinct_conditional_and_unconditional_managers_at_one_scope(self):
        rules = {
            _MUTATE,
            "gcp-public-cloud-run-gcs-object-disruption",
            "gcp-public-cloud-run-gcs-bucket-topology-disruption",
        }
        for scope in ("folders/100", "organizations/10"):
            for ordering in permutations(
                [
                    _grant(
                        scope=scope,
                        role="roles/storage.admin",
                        mode="binding",
                        name="limited",
                        condition={"title": "limited", "expression": "false"},
                    ),
                    _grant(scope=scope, role="roles/storage.admin", mode="binding", name="open"),
                ]
            ):
                with self.subTest(scope=scope, ordering=ordering):
                    _, _, findings = _evaluate(
                        [_cloud_run(), _public_invoker(), _bucket(), *_hierarchy(), *ordering], *rules
                    )
                    self.assertEqual({finding.rule_id for finding in findings}, rules)
                    self.assertTrue(all(".limited" not in str(finding.evidence) for finding in findings))

    def test_parent_change_revalidates_all_operation_consumers(self):
        rules = {
            _READ,
            _MUTATE,
            "gcp-public-cloud-run-gcs-object-disruption",
            "gcp-public-cloud-run-gcs-bucket-topology-disruption",
        }
        inventory, _, findings = _evaluate(
            [_cloud_run(), _public_invoker(), _bucket(), *_hierarchy(), _grant(role="roles/storage.admin")], *rules
        )
        self.assertEqual({finding.rule_id for finding in findings}, rules)
        parent = inventory.get_by_address("google_folder.child")
        gcp_facts(parent).set(GcpResourceMetadata.HIERARCHY_PARENT, "organizations/99")
        self.assertEqual(_findings(inventory, rules), [])

    def test_overlapping_unconditional_managers_still_block_all_consumers(self):
        rules = {
            _READ,
            _MUTATE,
            "gcp-public-cloud-run-gcs-object-disruption",
            "gcp-public-cloud-run-gcs-bucket-topology-disruption",
        }
        for second in (
            _grant(role="roles/storage.admin", mode="binding", name="second"),
            _grant(role="roles/storage.admin", mode="policy", name="second"),
            _grant(role="roles/storage.admin", mode="policy", name="second", unknown={"policy_data": True}),
        ):
            _, _, findings = _evaluate(
                [
                    _cloud_run(),
                    _public_invoker(),
                    _bucket(),
                    *_hierarchy(),
                    _grant(role="roles/storage.admin", mode="binding"),
                    second,
                ],
                *rules,
            )
            self.assertEqual(findings, [])

    def test_read_authority_retains_key_convergence_without_changing_key_authority(self):
        from tests.providers.test_protected_data_key_authority_convergence import _gcp_resources
        from tfstride.providers.gcp.normalizer import GcpNormalizer
        from tfstride.providers.gcp.resource_types import GCP_STORAGE_BUCKET_IAM_RESOURCE_TYPES

        resources = [
            resource
            for resource in _gcp_resources()
            if resource.resource_type not in GCP_STORAGE_BUCKET_IAM_RESOURCE_TYPES
        ]
        resources.extend([*_hierarchy(), _grant(role="roles/storage.objectViewer")])
        kms_rule = "gcp-public-cloud-run-kms-decrypt-access"
        for deny in ([], [_deny(parent="folders/100", permission="storage.googleapis.com/objects.get")]):
            inventory = GcpNormalizer().normalize([*resources, *deny])
            workload = inventory.get_by_address(_cloud_run().address)
            self.assertEqual(bool(gcp_facts(workload).cloud_run_gcs_protected_data_convergences), not deny)
            findings = _findings(inventory, {kms_rule})
            self.assertEqual(len(findings), 1)
            self.assertEqual(_bucket().address in findings[0].affected_resources, not deny)

    def test_plan_ingestion_preserves_unknown_parent_and_grant_conditions(self):
        from pathlib import Path
        from tempfile import TemporaryDirectory

        from tfstride.input.terraform_plan import load_terraform_plan

        for unknown_parent, conditional, expected in ((False, False, 1), (True, False, 0), (False, True, 0)):
            hierarchy = _hierarchy()
            if unknown_parent:
                hierarchy[1] = replace(hierarchy[1], unknown_values={"parent": True})
            resources = [
                _cloud_run(),
                _public_invoker(),
                _bucket(),
                *hierarchy,
                _grant(condition={"title": "limited", "expression": "false"} if conditional else None),
            ]
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
                                "values": resource.values,
                            }
                            for resource in resources
                        ]
                    }
                },
                "resource_changes": [
                    {
                        "address": resource.address,
                        "type": resource.resource_type,
                        "name": resource.name,
                        "mode": resource.mode,
                        "change": {
                            "actions": ["create"],
                            "after": resource.values,
                            "after_unknown": resource.unknown_values,
                        },
                    }
                    for resource in resources
                ],
            }
            with TemporaryDirectory() as directory:
                path = Path(directory) / "plan.json"
                path.write_text(json.dumps(plan), encoding="utf-8")
                _, _, findings = _evaluate(load_terraform_plan(path).resources, _MUTATE)
            self.assertEqual(len(findings), expected)

    def test_unsupported_roles_remain_uncertain_at_ancestor_scopes(self):
        for role in ("roles/owner", "organizations/10/roles/custom", "projects/tfstride-demo/roles/custom"):
            grants, problems = _grants([_bucket(), *_hierarchy(), _grant(role=role)])
            self.assertEqual(grants, [])
            self.assertTrue(problems)

    def test_unknown_project_is_not_replaced_by_another_resource_identity(self):
        bucket = replace(_bucket(), unknown_values={"project": True})
        grants, problems = _grants([bucket, *_hierarchy(), _grant()])
        self.assertEqual(grants, [])
        self.assertTrue(problems)
