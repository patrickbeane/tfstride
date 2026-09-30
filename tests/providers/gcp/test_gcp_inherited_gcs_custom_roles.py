from __future__ import annotations

import unittest
from dataclasses import replace
from itertools import permutations

from tests.providers.gcp.normalizer_support import _terraform_resource
from tests.providers.gcp.test_gcp_cloud_run_gcs_access_paths import _PROJECT, _bucket
from tests.providers.gcp.test_gcp_gcs_grant_ancestry import _grant, _hierarchy
from tests.providers.gcp.test_gcp_project_gcs_grants import _deny, _grants, _project_grant
from tests.providers.gcp.test_gcp_public_cloud_run_gcs_mutation_rules import _cloud_run, _evaluate, _public_invoker
from tests.providers.gcp.test_gcp_scoped_gcs_consumers import _findings
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_facts import gcp_facts

_READ = "gcp-public-workload-sensitive-data-access"
_MUTATE = "gcp-public-cloud-run-gcs-mutation-access"
_DELETE = "gcp-public-cloud-run-gcs-object-disruption"
_BUCKET_DELETE = "gcp-public-cloud-run-gcs-bucket-topology-disruption"
_RULES = {_READ, _MUTATE, _DELETE, _BUCKET_DELETE}
_PERMISSIONS = ["storage.objects.get", "storage.objects.create", "storage.objects.delete", "storage.buckets.delete"]


def _role(*, scope="organizations/10", permissions=None, unknown=None, **values):
    project = scope.startswith("projects/")
    kind = "google_project_iam_custom_role" if project else "google_organization_iam_custom_role"
    return _terraform_resource(
        f"{kind}.data",
        kind,
        {
            "project" if project else "org_id": scope.split("/", 1)[1],
            "role_id": "data",
            "name": f"{scope}/roles/data",
            "permissions": permissions or _PERMISSIONS,
            **values,
        },
        unknown_values=unknown,
    )


class GcpInheritedGcsCustomRoleTests(unittest.TestCase):
    def test_compatible_scopes_enable_all_existing_operation_consumers(self):
        for role_scope, grant_scope in (
            (f"projects/{_PROJECT}", "project"),
            ("organizations/10", "project"),
            ("organizations/10", "folders/200"),
            ("organizations/10", "folders/100"),
            ("organizations/10", "organizations/10"),
        ):
            with self.subTest(role_scope=role_scope, grant_scope=grant_scope):
                role = _role(scope=role_scope)
                grant = (
                    _project_grant(role=role.values["name"])
                    if grant_scope == "project"
                    else _grant(scope=grant_scope, role=role.values["name"])
                )
                inventory, _, findings = _evaluate(
                    [_cloud_run(), _public_invoker(), _bucket(), *_hierarchy(), role, grant], *_RULES
                )
                self.assertEqual({finding.rule_id for finding in findings}, _RULES)
                paths = gcp_facts(inventory.get_by_address(_cloud_run().address)).cloud_run_gcs_access_paths
                self.assertEqual(paths[0]["custom_role_evidence"]["role_definition_address"], role.address)
                self.assertEqual(paths[0]["custom_role_evidence"]["role_scope"], role_scope)
                self.assertEqual(paths[0]["custom_role_evidence"]["grant_scope_compatibility"], "compatible")

    def test_project_roles_cannot_be_granted_above_the_project_even_for_its_own_bucket(self):
        for scope in ("folders/200", "organizations/10"):
            role = _role(scope=f"projects/{_PROJECT}")
            _, _, findings = _evaluate(
                [
                    _cloud_run(),
                    _public_invoker(),
                    _bucket(),
                    *_hierarchy(),
                    role,
                    _grant(scope=scope, role=role.values["name"]),
                ],
                *_RULES,
            )
            self.assertEqual(findings, [])

    def test_foreign_role_ownership_does_not_follow_provider_aliases(self):
        for scope in ("organizations/99", "projects/foreign-project"):
            role = replace(_role(scope=scope), provider_config_key="google.shared")
            bucket = replace(_bucket(), provider_config_key="google.shared")
            resources = [bucket, *_hierarchy(), role, _project_grant(role=role.values["name"])]
            grants, problems = _grants(resources)
            self.assertEqual(grants, [])
            self.assertTrue(problems)
            _, _, findings = _evaluate([_cloud_run(), _public_invoker(), *resources], *_RULES)
            self.assertEqual(findings, [])

    def test_unknown_ownership_hierarchy_and_lifecycle_never_establish_custom_authority(self):
        role = _role()
        grant = _project_grant(role=role.values["name"])
        for field in ("org_id", "permissions", "stage", "deleted"):
            with self.subTest(field=field):
                resources = [_bucket(), *_hierarchy(), replace(role, unknown_values={field: True}), grant]
                grants, problems = _grants(resources)
                self.assertEqual(grants, [])
                self.assertTrue(problems)
                _, _, findings = _evaluate([_cloud_run(), _public_invoker(), *resources], *_RULES)
                self.assertEqual(findings, [])
        for hierarchy in ([], _hierarchy()[:1], _hierarchy()[:2]):
            grants, problems = _grants([_bucket(), *hierarchy, role, grant])
            self.assertEqual(grants, [])
            self.assertTrue(problems)

    def test_disabled_deleted_and_unsupported_permissions_do_not_grant_access(self):
        for role in (
            _role(deleted=True),
            _role(stage="DISABLED"),
            _role(stage="UNRECOGNIZED"),
            _role(permissions=["storage.*"]),
            _role(permissions=["storage.objects.get", "bad"]),
            _role(unknown={"permissions": [False, True]}),
        ):
            resources = [_bucket(), *_hierarchy(), role, _grant(role=role.values["name"])]
            _, _, findings = _evaluate([_cloud_run(), _public_invoker(), *resources], *_RULES)
            self.assertEqual(findings, [])

    def test_exact_permissions_do_not_become_other_operations(self):
        for permission, expected in zip(_PERMISSIONS, (_READ, _MUTATE, _DELETE, _BUCKET_DELETE), strict=True):
            with self.subTest(permission=permission):
                role = _role(permissions=[permission])
                _, _, findings = _evaluate(
                    [_cloud_run(), _public_invoker(), _bucket(), *_hierarchy(), role, _grant(role=role.values["name"])],
                    *_RULES,
                )
                self.assertEqual({finding.rule_id for finding in findings}, {expected})

    def test_conditions_and_inherited_denies_constrain_custom_permissions(self):
        role = _role()
        conditional = _grant(role=role.values["name"], condition={"title": "limited", "expression": "false"})
        grants, problems = _grants([_bucket(), *_hierarchy(), role, conditional])
        self.assertEqual(problems, [])
        self.assertEqual(grants[0]["access_state"], "conditional")
        self.assertEqual(grants[0]["condition"], conditional.values["condition"][0])
        _, _, findings = _evaluate(
            [_cloud_run(), _public_invoker(), _bucket(), *_hierarchy(), role, conditional], *_RULES
        )
        self.assertEqual(findings, [])
        for permission, removed in zip(_PERMISSIONS, (_READ, _MUTATE, _DELETE, _BUCKET_DELETE), strict=True):
            deny = _deny(
                parent="organizations/10", permission=permission.replace("storage.", "storage.googleapis.com/", 1)
            )
            _, _, findings = _evaluate(
                [
                    _cloud_run(),
                    _public_invoker(),
                    _bucket(),
                    *_hierarchy(),
                    role,
                    _grant(role=role.values["name"]),
                    deny,
                ],
                *_RULES,
            )
            self.assertEqual({finding.rule_id for finding in findings}, _RULES - {removed})

    def test_scoped_and_symbolic_role_references_are_distinct_from_weak_names(self):
        role = _role()
        collision = replace(
            _role(scope="organizations/99"), address="google_organization_iam_custom_role.other", name="other"
        )
        for reference, expected in (
            (role.values["name"], _RULES),
            (f"{role.address}.name", _RULES),
            ("data", set()),
            (f"{role.address}.role_id", set()),
        ):
            _, _, findings = _evaluate(
                [_cloud_run(), _public_invoker(), _bucket(), *_hierarchy(), role, collision, _grant(role=reference)],
                *_RULES,
            )
            self.assertEqual({finding.rule_id for finding in findings}, expected)
        duplicate = replace(role, address="google_organization_iam_custom_role.duplicate", name="duplicate")
        grants, problems = _grants([_bucket(), *_hierarchy(), role, duplicate, _grant(role=role.values["name"])])
        self.assertEqual(grants, [])
        self.assertTrue(problems)

    def test_conflicting_role_name_and_ownership_stay_unknown(self):
        for values in ({"org_id": "99"}, {"role_id": "other"}, {"id": "organizations/99/roles/data"}):
            role = _role(**values)
            grants, problems = _grants([_bucket(), *_hierarchy(), role, _grant(role="organizations/10/roles/data")])
            self.assertEqual(grants, [])
            self.assertTrue(problems)

    def test_revalidation_rechecks_current_custom_role_ownership_permissions_and_lifecycle(self):
        for field, value, expected in (
            (GcpResourceMetadata.ORGANIZATION_ID, "99", set()),
            (GcpResourceMetadata.CUSTOM_ROLE_DELETED, True, set()),
            (GcpResourceMetadata.CUSTOM_ROLE_STAGE, "DISABLED", set()),
            (GcpResourceMetadata.CUSTOM_ROLE_PERMISSIONS, ["storage.objects.get"], {_READ}),
        ):
            with self.subTest(field=field):
                role = _role()
                inventory, _, findings = _evaluate(
                    [_cloud_run(), _public_invoker(), _bucket(), *_hierarchy(), role, _grant(role=role.values["name"])],
                    *_RULES,
                )
                self.assertEqual({finding.rule_id for finding in findings}, _RULES)
                definition = inventory.get_by_address(role.address)
                gcp_facts(definition).set(field, value)
                self.assertEqual({finding.rule_id for finding in _findings(inventory)}, expected)

    def test_resource_order_and_unrelated_roles_preserve_results(self):
        role = _role()
        other = replace(
            _role(scope="organizations/99"), address="google_organization_iam_custom_role.other", name="other"
        )
        grant = _grant(role=role.values["name"])
        expected = None
        for ordered in permutations([role, other, grant]):
            _, _, findings = _evaluate([_cloud_run(), _public_invoker(), _bucket(), *_hierarchy(), *ordered], *_RULES)
            if expected is None:
                expected = findings
            self.assertEqual(findings, expected)

    def test_role_definition_and_scope_are_explained_in_public_findings(self):
        role = _role()
        _, _, findings = _evaluate(
            [_cloud_run(), _public_invoker(), _bucket(), *_hierarchy(), role, _grant(role=role.values["name"])], *_RULES
        )
        for finding in findings:
            self.assertIn(role.address, str(finding.evidence))
            if finding.rule_id != _DELETE:
                self.assertIn(role.address, finding.affected_resources)
        mutation = next(finding for finding in findings if finding.rule_id == _MUTATE)
        self.assertIn("role_scope=organizations/10", str(mutation.evidence))
        self.assertIn("role_scope_compatibility=compatible", str(mutation.evidence))

    def test_unknown_custom_role_name_can_use_exact_reference_without_inventing_ownership(self):
        role = _role(unknown={"name": True, "id": True})
        grant = _grant(role=f"{role.address}.name")
        for unknown_owner, count in ((False, 4), (True, 0)):
            current = replace(
                role, unknown_values={**role.unknown_values, **({"org_id": True} if unknown_owner else {})}
            )
            _, _, findings = _evaluate(
                [_cloud_run(), _public_invoker(), _bucket(), *_hierarchy(), current, grant], *_RULES
            )
            self.assertEqual(len(findings), count)

    def test_inherited_custom_read_supports_kms_convergence_and_retains_separate_key_authority(self):
        from tests.providers.test_protected_data_key_authority_convergence import _gcp_resources
        from tfstride.providers.gcp.normalizer import GcpNormalizer
        from tfstride.providers.gcp.resource_types import GCP_STORAGE_BUCKET_IAM_RESOURCE_TYPES

        role = _role(permissions=["storage.objects.get"])
        resources = [
            resource
            for resource in _gcp_resources()
            if resource.resource_type not in GCP_STORAGE_BUCKET_IAM_RESOURCE_TYPES
        ]
        resources.extend([*_hierarchy(), role, _grant(role=role.values["name"])])
        inventory = GcpNormalizer().normalize(resources)
        workload = inventory.get_by_address(_cloud_run().address)
        self.assertTrue(gcp_facts(workload).cloud_run_gcs_protected_data_convergences)
        kms_rule = "gcp-public-cloud-run-kms-decrypt-access"
        self.assertIn(_bucket().address, _findings(inventory, {kms_rule})[0].affected_resources)
        gcp_facts(inventory.get_by_address(role.address)).set(GcpResourceMetadata.CUSTOM_ROLE_DELETED, True)
        findings = _findings(inventory, {kms_rule})
        self.assertEqual(len(findings), 1)
        self.assertNotIn(_bucket().address, findings[0].affected_resources)

    def test_unknown_role_scope_survives_plan_ingestion(self):
        import json
        from pathlib import Path
        from tempfile import TemporaryDirectory

        from tfstride.input.terraform_plan import load_terraform_plan

        for unknown_owner in (False, True):
            role = _role(unknown={"org_id": True} if unknown_owner else None)
            resources = [
                _cloud_run(),
                _public_invoker(),
                _bucket(),
                *_hierarchy(),
                role,
                _grant(role=role.values["name"]),
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
                _, _, findings = _evaluate(load_terraform_plan(path).resources, *_RULES)
            self.assertEqual({finding.rule_id for finding in findings}, set() if unknown_owner else _RULES)

    def test_authoritative_managers_cannot_evade_conflicts_with_custom_role_aliases(self):
        role = _role()
        for scope in ("project", "folders/100", "organizations/10"):
            for different_condition in (False, True):
                condition = {"title": "limited", "expression": "false"} if different_condition else None
                if scope == "project":
                    first = _project_grant(role=role.values["name"], kind="google_project_iam_binding", name="first")
                    second = _project_grant(
                        role=f"{role.address}.name",
                        kind="google_project_iam_binding",
                        name="second",
                        condition=condition,
                    )
                else:
                    first = _grant(scope=scope, role=role.values["name"], mode="binding", name="first")
                    second = _grant(
                        scope=scope, role=f"{role.address}.name", mode="binding", name="second", condition=condition
                    )
                with self.subTest(scope=scope, separate_alternative=different_condition):
                    _, _, findings = _evaluate(
                        [_cloud_run(), _public_invoker(), _bucket(), *_hierarchy(), role, first, second], *_RULES
                    )
                    self.assertEqual(
                        {finding.rule_id for finding in findings}, _RULES if different_condition else set()
                    )

    def test_unmodeled_but_distinct_scoped_role_manager_does_not_override_known_role(self):
        role = _role()
        for unrelated in (
            "organizations/10/roles/unrelated",
            "organizations/99/roles/data",
            "projects/other-project/roles/data",
        ):
            resources = [
                _cloud_run(),
                _public_invoker(),
                _bucket(),
                *_hierarchy(),
                role,
                _grant(role=role.values["name"], mode="binding", name="known"),
                _grant(role=unrelated, mode="binding", name="other"),
            ]
            _, _, findings = _evaluate(resources, *_RULES)
            self.assertEqual({finding.rule_id for finding in findings}, _RULES)
