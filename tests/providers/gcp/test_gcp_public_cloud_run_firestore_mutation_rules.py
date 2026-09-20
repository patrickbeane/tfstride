from __future__ import annotations

import unittest

from tests.providers.gcp.normalizer_support import _terraform_resource
from tests.providers.gcp.test_gcp_cloud_run_firestore_access_paths import (
    _DATABASE_ADDRESS,
    _DATABASE_RESOURCE_NAME,
    _IAM_ADDRESS,
    _PROJECT,
    _SERVICE_ACCOUNT_MEMBER,
    _WORKLOAD_ADDRESS,
    _cloud_run,
    _custom_role,
    _database,
    _project_iam_member,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import StrideCategory, TerraformResource
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_types import GcpResourceType
from tfstride.providers.gcp.rules import GCP_RULE_GROUP_IDS

_RULE_ID = "gcp-public-cloud-run-firestore-mutation-access"
_PUBLIC_INVOKER_ADDRESS = "google_cloud_run_v2_service_iam_member.public_invoker"


def _public_cloud_run(
    *,
    public_ingress: bool = True,
    invoker_iam_disabled: bool | None = None,
) -> TerraformResource:
    workload = _cloud_run()
    assert isinstance(workload, TerraformResource)
    workload.values["ingress"] = "INGRESS_TRAFFIC_ALL" if public_ingress else "INGRESS_TRAFFIC_INTERNAL_ONLY"
    if invoker_iam_disabled is not None:
        workload.values["invoker_iam_disabled"] = invoker_iam_disabled
    return workload


def _public_invoker(
    *,
    member: str = "allUsers",
    role: str = "roles/run.invoker",
    condition: dict[str, str] | None = None,
) -> TerraformResource:
    values: dict[str, object] = {
        "name": "orders",
        "project": "tfstride-demo",
        "location": "us-central1",
        "role": role,
        "member": member,
    }
    if condition is not None:
        values["condition"] = [condition]
    return _terraform_resource(
        _PUBLIC_INVOKER_ADDRESS,
        GcpResourceType.CLOUD_RUN_V2_SERVICE_IAM_MEMBER,
        values,
    )


def _as_resource(value: object) -> TerraformResource:
    assert isinstance(value, TerraformResource)
    return value


def _evaluate(resources: list[TerraformResource]):
    inventory = GcpNormalizer().normalize(resources)
    boundaries = detect_trust_boundaries(inventory)
    return StrideRuleEngine().evaluate(
        inventory,
        boundaries,
        rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
    )


def _evidence(finding):
    return {item.key: item.values for item in finding.evidence}


class GcpPublicCloudRunFirestoreMutationRuleTests(unittest.TestCase):
    def test_rule_is_registered(self) -> None:
        registered = {rule_id for group in GCP_RULE_GROUP_IDS for rule_id in group}

        self.assertIn(_RULE_ID, registered)

    def test_project_applicable_entity_mutation_grant_is_reported(self) -> None:
        findings = _evaluate(
            [
                _public_cloud_run(),
                _public_invoker(),
                _as_resource(_database()),
                _as_resource(_project_iam_member()),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        self.assertEqual(finding.category, StrideCategory.TAMPERING)
        self.assertEqual(
            finding.affected_resources,
            [
                _WORKLOAD_ADDRESS,
                _PUBLIC_INVOKER_ADDRESS,
                _DATABASE_ADDRESS,
                _IAM_ADDRESS,
            ],
        )
        self.assertEqual(
            finding.trust_boundary_id,
            f"internet-to-service:internet->{_WORKLOAD_ADDRESS}",
        )
        self.assertIsNotNone(finding.severity_reasoning)
        assert finding.severity_reasoning is not None
        self.assertEqual(finding.severity_reasoning.blast_radius, 2)
        self.assertEqual(finding.severity_reasoning.privilege_breadth, 1)
        self.assertIn(
            "Firestore entity create, update operations",
            finding.rationale,
        )
        self.assertIn("grant is project-applicable", finding.rationale)
        self.assertIn(
            "Firestore Security Rules are not evaluated for server/API access",
            finding.rationale,
        )
        evidence = _evidence(finding)
        self.assertEqual(
            evidence["public_invoker_bindings"],
            [f"source={_PUBLIC_INVOKER_ADDRESS}; role=roles/run.invoker; member=allUsers; condition=none"],
        )
        self.assertIn(
            f"member={_SERVICE_ACCOUNT_MEMBER}",
            evidence["runtime_identity"][0],
        )
        path_evidence = evidence["firestore_mutation_paths"][0]
        self.assertIn(f"database_address={_DATABASE_ADDRESS}", path_evidence)
        self.assertIn(
            "entity_mutation_operations=create,update",
            path_evidence,
        )
        self.assertIn("database_administration_classes=none", path_evidence)
        self.assertIn("scope_type=project", path_evidence)
        self.assertIn("resource_scope=firestore_project", path_evidence)
        self.assertEqual(
            evidence["scope_breadth"],
            [
                "project_applicable_grants=1; exact_database_grants=0; "
                "modeled_databases=1; blast_radius_basis=project_applicable_grant"
            ],
        )
        self.assertIn(
            "firestore_security_rules=not evaluated for server/API access",
            evidence["authorization_scope"][1],
        )

    def test_exact_database_grant_has_narrower_blast_radius(self) -> None:
        condition = {
            "title": "orders-only",
            "expression": f'resource.name == "{_DATABASE_RESOURCE_NAME}"',
        }
        findings = _evaluate(
            [
                _public_cloud_run(),
                _public_invoker(),
                _as_resource(_database()),
                _as_resource(_project_iam_member(condition=condition)),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        self.assertIsNotNone(finding.severity_reasoning)
        assert finding.severity_reasoning is not None
        self.assertEqual(finding.severity_reasoning.blast_radius, 1)
        self.assertIn(
            "limited by exact Firestore database-name conditions",
            finding.rationale,
        )
        evidence = _evidence(finding)
        self.assertIn(
            "scope_type=database",
            evidence["firestore_mutation_paths"][0],
        )
        self.assertIn(
            "condition_evaluation=exact_database_scope_match",
            evidence["firestore_mutation_paths"][0],
        )
        self.assertEqual(
            evidence["scope_breadth"],
            [
                "project_applicable_grants=0; exact_database_grants=1; "
                "modeled_databases=1; blast_radius_basis=exact_database_scoped_grant"
            ],
        )

    def test_known_project_and_name_resolve_without_computed_database_id(self) -> None:
        condition = {
            "title": "orders-only",
            "expression": f'resource.name == "{_DATABASE_RESOURCE_NAME}"',
        }
        database = _terraform_resource(
            _DATABASE_ADDRESS,
            GcpResourceType.FIRESTORE_DATABASE,
            {
                "name": "orders",
                "project": _PROJECT,
                "location_id": "nam5",
                "type": "FIRESTORE_NATIVE",
            },
        )

        findings = _evaluate(
            [
                _public_cloud_run(),
                _public_invoker(),
                database,
                _as_resource(_project_iam_member(condition=condition)),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        path_evidence = _evidence(findings[0])["firestore_mutation_paths"][0]
        self.assertIn(
            f"database_resource_name={_DATABASE_RESOURCE_NAME}",
            path_evidence,
        )
        self.assertIn("scope_type=database", path_evidence)

    def test_exact_and_wildcard_entity_permissions_trigger_expected_operations(self) -> None:
        cases = {
            "create": (["datastore.entities.create"], "create"),
            "update": (["datastore.entities.update"], "update"),
            "delete": (["datastore.entities.delete"], None),
            "entity wildcard": (
                ["datastore.entities.*"],
                "create,update",
            ),
        }

        for case, (permissions, operations) in cases.items():
            with self.subTest(case=case):
                role = f"projects/{_PROJECT}/roles/cloudRunFirestore"
                findings = _evaluate(
                    [
                        _public_cloud_run(),
                        _public_invoker(),
                        _as_resource(_database()),
                        _as_resource(_custom_role(permissions=permissions)),
                        _as_resource(_project_iam_member(role=role)),
                    ]
                )

                if operations is None:
                    self.assertEqual(findings, [])
                    continue

                self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
                path_evidence = _evidence(findings[0])["firestore_mutation_paths"][0]
                self.assertIn(
                    f"entity_mutation_operations={operations}",
                    path_evidence,
                )

    def test_mixed_mutation_and_deletion_permissions_render_only_mutation_evidence(
        self,
    ) -> None:
        role = f"projects/{_PROJECT}/roles/cloudRunFirestore"
        findings = _evaluate(
            [
                _public_cloud_run(),
                _public_invoker(),
                _as_resource(_database()),
                _as_resource(
                    _custom_role(
                        permissions=[
                            "datastore.entities.create",
                            "datastore.entities.delete",
                            "datastore.databases.bulkDelete",
                        ]
                    )
                ),
                _as_resource(_project_iam_member(role=role)),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        path_evidence = _evidence(findings[0])["firestore_mutation_paths"][0]
        self.assertIn("entity_mutation_operations=create", path_evidence)
        self.assertIn(
            "matched_permissions=datastore.entities.create",
            path_evidence,
        )
        self.assertNotIn("datastore.entities.delete", path_evidence)
        self.assertNotIn("datastore.databases.bulkDelete", path_evidence)
        self.assertIn("database_administration_classes=none", path_evidence)
        finding = findings[0]
        assert finding.severity_reasoning is not None
        self.assertEqual(finding.severity_reasoning.privilege_breadth, 1)
        self.assertEqual(finding.severity_reasoning.final_score, 8)
        self.assertNotIn("destructive_administration", finding.rationale)

    def test_database_administration_remains_separate_from_entity_mutation(self) -> None:
        findings = _evaluate(
            [
                _public_cloud_run(),
                _public_invoker(),
                _as_resource(_database()),
                _as_resource(_project_iam_member(role="roles/datastore.owner")),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        self.assertIsNotNone(finding.severity_reasoning)
        assert finding.severity_reasoning is not None
        self.assertEqual(finding.severity_reasoning.privilege_breadth, 2)
        self.assertIn(
            "configuration_administration database capabilities",
            finding.rationale,
        )
        path_evidence = _evidence(finding)["firestore_mutation_paths"][0]
        self.assertIn(
            "entity_mutation_operations=create,update",
            path_evidence,
        )
        self.assertIn(
            "database_administration_classes=configuration_administration",
            path_evidence,
        )
        self.assertNotIn("destructive_administration", finding.rationale)
        self.assertNotIn("destructive_administration", path_evidence)

    def test_supported_public_invocation_mechanisms_are_detected(self) -> None:
        cases = {
            "services invoker": (
                [
                    _public_cloud_run(),
                    _public_invoker(role="roles/run.servicesInvoker"),
                    _as_resource(_database()),
                    _as_resource(_project_iam_member()),
                ],
                "public_invoker_bindings",
                "role=roles/run.servicesInvoker",
            ),
            "invoker IAM check disabled": (
                [
                    _public_cloud_run(invoker_iam_disabled=True),
                    _as_resource(_database()),
                    _as_resource(_project_iam_member()),
                ],
                "public_exposure_configuration",
                "invoker_iam_check=disabled; ingress=INGRESS_TRAFFIC_ALL",
            ),
        }

        for case, (resources, evidence_key, expected) in cases.items():
            with self.subTest(case=case):
                findings = _evaluate(resources)
                self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
                self.assertIn(expected, _evidence(findings[0])[evidence_key][0])

    def test_non_entity_mutation_and_uncertain_paths_remain_quiet(self) -> None:
        runtime_condition = {
            "title": "temporary",
            "expression": "request.time < timestamp('2030-01-01T00:00:00Z')",
        }
        unknown_public_invoker = _public_invoker()
        unknown_public_invoker.unknown_values["condition"] = True
        cases = {
            "read only": [
                _public_cloud_run(),
                _public_invoker(),
                _as_resource(_database()),
                _as_resource(_project_iam_member(role="roles/datastore.viewer")),
            ],
            "database administration only": [
                _public_cloud_run(),
                _public_invoker(),
                _as_resource(_database()),
                _as_resource(_project_iam_member(role="roles/iam.databasesAdmin")),
            ],
            "runtime IAM condition": [
                _public_cloud_run(),
                _public_invoker(),
                _as_resource(_database()),
                _as_resource(_project_iam_member(condition=runtime_condition)),
            ],
            "private ingress": [
                _public_cloud_run(public_ingress=False),
                _public_invoker(),
                _as_resource(_database()),
                _as_resource(_project_iam_member()),
            ],
            "non-public invoker": [
                _public_cloud_run(),
                _public_invoker(member=("serviceAccount:caller@tfstride-demo.iam.gserviceaccount.com")),
                _as_resource(_database()),
                _as_resource(_project_iam_member()),
            ],
            "unknown public invoker condition": [
                _public_cloud_run(),
                unknown_public_invoker,
                _as_resource(_database()),
                _as_resource(_project_iam_member()),
            ],
            "unresolved custom role": [
                _public_cloud_run(),
                _public_invoker(),
                _as_resource(_database()),
                _as_resource(_project_iam_member(role=f"projects/{_PROJECT}/roles/externalFirestore")),
            ],
        }

        for case, resources in cases.items():
            with self.subTest(case=case):
                self.assertEqual(_evaluate(resources), [])


if __name__ == "__main__":
    unittest.main()
