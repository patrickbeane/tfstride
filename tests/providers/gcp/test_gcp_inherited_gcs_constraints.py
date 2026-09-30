from __future__ import annotations

import json
import unittest
from dataclasses import replace
from itertools import permutations
from pathlib import Path
from tempfile import TemporaryDirectory

from tests.providers.gcp.test_gcp_cloud_run_gcs_access_paths import _SERVICE_ACCOUNT_EMAIL, _bucket
from tests.providers.gcp.test_gcp_gcs_grant_ancestry import _grant, _hierarchy
from tests.providers.gcp.test_gcp_project_gcs_grants import _deny, _grants
from tests.providers.gcp.test_gcp_public_cloud_run_gcs_mutation_rules import _cloud_run, _evaluate, _public_invoker
from tests.providers.gcp.test_gcp_scoped_gcs_consumers import _findings, _set_deny_permission
from tfstride.input.terraform_plan import load_terraform_plan
from tfstride.providers.gcp.gcs_grant_evaluation import gcs_path_permissions
from tfstride.providers.gcp.resource_facts import gcp_facts

_MUTATE = "gcp-public-cloud-run-gcs-mutation-access"
_READ = "gcp-public-workload-sensitive-data-access"
_DELETE = "gcp-public-cloud-run-gcs-object-disruption"
_BUCKET_DELETE = "gcp-public-cloud-run-gcs-bucket-topology-disruption"
_RULES = {_READ, _MUTATE, _DELETE, _BUCKET_DELETE}


class GcpInheritedGcsConstraintTests(unittest.TestCase):
    def test_additional_unknown_deny_rules_cannot_be_lost_beside_known_field_uncertainty(self):
        field_unknown = {"denied_principals": True}
        shapes = (
            {"rules": [{"deny_rule": [field_unknown]}, True]},
            {"rules": [{"deny_rule": [field_unknown, True]}]},
        )
        for scope in ("folders/100", "organizations/10"):
            for unknown in shapes:
                with self.subTest(scope=scope, unknown=unknown):
                    deny = _deny(parent=scope, permission="storage.googleapis.com/objects.delete", unknown=unknown)
                    resources = [_bucket(), *_hierarchy(), _grant(scope=scope, role="roles/storage.admin"), deny]
                    grants, problems = _grants(resources)
                    self.assertEqual(grants, [])
                    self.assertTrue(problems)
                    _, _, findings = _evaluate([_cloud_run(), _public_invoker(), *resources], *_RULES)
                    self.assertEqual(findings, [])

    def test_unknown_parent_and_rule_membership_do_not_affect_disjoint_operations(self):
        deny = _deny(
            parent="folders/100",
            permission="storage.googleapis.com/objects.delete",
            unknown={"parent": True, "rules": [{"deny_rule": [{"denied_principals": True}]}]},
        )
        resources = [_bucket(), *_hierarchy(), _grant(role="roles/storage.admin"), deny]
        grants, problems = _grants(resources)
        self.assertEqual(len(grants), 1)
        self.assertNotIn("storage.objects.delete", gcs_path_permissions(grants[0]))
        self.assertIn("storage.objects.create", gcs_path_permissions(grants[0]))
        self.assertTrue(problems)
        _, _, findings = _evaluate([_cloud_run(), _public_invoker(), *resources], *_RULES)
        self.assertEqual({finding.rule_id for finding in findings}, _RULES - {_DELETE})

    def test_known_exceptions_are_local_to_their_policy_and_operation(self):
        principal = f"principal://iam.googleapis.com/projects/-/serviceAccounts/{_SERVICE_ACCOUNT_EMAIL}"
        exception_policy = _deny(
            parent="organizations/10",
            permission="storage.googleapis.com/objects.*",
            extra={"exception_permissions": ["storage.googleapis.com/objects.create"]},
        )
        # An exception in one policy does not override a different deny policy.
        blocking_policy = replace(_deny(parent="folders/100"), address="google_iam_deny_policy.block")
        for ordered in permutations([exception_policy, blocking_policy]):
            _, _, findings = _evaluate(
                [
                    _cloud_run(),
                    _public_invoker(),
                    _bucket(),
                    *_hierarchy(),
                    _grant(role="roles/storage.admin"),
                    *ordered,
                ],
                *_RULES,
            )
            self.assertEqual({finding.rule_id for finding in findings}, {_BUCKET_DELETE})
        exempt = _deny(
            parent="folders/100",
            permission="storage.googleapis.com/objects.*",
            extra={"exception_principals": [principal]},
        )
        _, _, findings = _evaluate(
            [_cloud_run(), _public_invoker(), _bucket(), *_hierarchy(), _grant(role="roles/storage.admin"), exempt],
            *_RULES,
        )
        self.assertEqual({finding.rule_id for finding in findings}, _RULES)

    def test_unknown_exception_only_constrains_the_permissions_it_could_exempt(self):
        deny = _deny(
            parent="organizations/10",
            permission="storage.googleapis.com/objects.delete",
            unknown={"rules": [{"deny_rule": [{"exception_principals": True}]}]},
        )
        _, _, findings = _evaluate(
            [_cloud_run(), _public_invoker(), _bucket(), *_hierarchy(), _grant(role="roles/storage.admin"), deny],
            *_RULES,
        )
        self.assertEqual({finding.rule_id for finding in findings}, _RULES - {_DELETE})

    def test_inherited_denies_are_revalidated_for_each_operation(self):
        inventory, _, before = _evaluate(
            [
                _cloud_run(),
                _public_invoker(),
                _bucket(),
                *_hierarchy(),
                _grant(role="roles/storage.admin"),
                _deny(parent="organizations/10", permission="logging.googleapis.com/sinks.delete"),
            ],
            *_RULES,
        )
        self.assertEqual({finding.rule_id for finding in before}, _RULES)
        workload = inventory.get_by_address(_cloud_run().address)
        self.assertTrue(gcp_facts(workload).cloud_run_gcs_access_paths)
        for permission, removed in (
            ("objects.get", _READ),
            ("objects.delete", _DELETE),
            ("buckets.delete", _BUCKET_DELETE),
        ):
            _set_deny_permission(inventory, f"storage.googleapis.com/{permission}")
            self.assertEqual({finding.rule_id for finding in _findings(inventory)}, _RULES - {removed})

    def test_unknown_extra_deny_blocks_survive_plan_ingestion(self):
        for extra in (True, {}, {"deny_rule": [{"denied_permissions": True}]}):
            deny = _deny(
                parent="organizations/10",
                permission="storage.googleapis.com/objects.delete",
                unknown={"rules": [{"deny_rule": [{"denied_principals": True}]}, extra]},
            )
            resources = [_cloud_run(), _public_invoker(), _bucket(), *_hierarchy(), _grant(), deny]
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
                inventory, _, findings = _evaluate(load_terraform_plan(path).resources, _MUTATE)
            # Empty after_unknown entries cannot introduce hypothetical rules.
            self.assertEqual(len(findings), 1 if extra == {} else 0)
            workload = inventory.get_by_address(_cloud_run().address)
            if extra != {}:
                self.assertTrue(gcp_facts(workload).cloud_run_gcs_access_path_uncertainties)
