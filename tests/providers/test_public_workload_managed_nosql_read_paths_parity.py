from __future__ import annotations

import unittest
from typing import Any

from tests.providers.aws.test_aws_ecs_dynamodb_access_paths import (
    _INDEX_ARN as AWS_INDEX_ARN,
)
from tests.providers.aws.test_aws_ecs_dynamodb_access_paths import (
    _TABLE_ARN as AWS_TABLE_ARN,
)
from tests.providers.aws.test_aws_ecs_dynamodb_access_paths import (
    _TASK_ROLE_ARN as AWS_TASK_ROLE_ARN,
)
from tests.providers.aws.test_aws_ecs_dynamodb_access_paths import (
    _role as aws_role,
)
from tests.providers.aws.test_aws_ecs_dynamodb_access_paths import (
    _role_policy_attachment as aws_role_policy_attachment,
)
from tests.providers.aws.test_aws_ecs_dynamodb_access_paths import (
    _statement as aws_statement,
)
from tests.providers.aws.test_aws_ecs_dynamodb_access_paths import (
    _table as aws_table,
)
from tests.providers.aws.test_aws_ecs_dynamodb_access_paths import (
    _task_definition as aws_task_definition,
)
from tests.providers.aws.test_aws_public_ecs_dynamodb_mutation_rules import (
    _public_edge as aws_public_edge,
)
from tests.providers.aws.test_aws_public_ecs_dynamodb_mutation_rules import (
    _service as aws_service,
)
from tests.providers.azure.test_azure_app_service_cosmosdb_access_paths import (
    _CONTRIBUTOR_ROLE_ID as AZURE_CONTRIBUTOR_ROLE_ID,
)
from tests.providers.azure.test_azure_app_service_cosmosdb_access_paths import (
    _CUSTOM_ROLE_ID as AZURE_CUSTOM_ROLE_ID,
)
from tests.providers.azure.test_azure_app_service_cosmosdb_access_paths import (
    _READER_ROLE_ID as AZURE_READER_ROLE_ID,
)
from tests.providers.azure.test_azure_app_service_cosmosdb_access_paths import (
    _account as azure_account,
)
from tests.providers.azure.test_azure_app_service_cosmosdb_access_paths import (
    _container as azure_container,
)
from tests.providers.azure.test_azure_app_service_cosmosdb_access_paths import (
    _custom_role as azure_custom_role,
)
from tests.providers.azure.test_azure_app_service_cosmosdb_access_paths import (
    _database as azure_database,
)
from tests.providers.azure.test_azure_app_service_cosmosdb_access_paths import (
    _native_assignment as azure_native_assignment,
)
from tests.providers.azure.test_azure_app_service_cosmosdb_access_paths import (
    _web_app as azure_web_app,
)
from tests.providers.gcp.test_gcp_cloud_run_firestore_access_paths import (
    _DATABASE_RESOURCE_NAME as GCP_DATABASE_RESOURCE_NAME,
)
from tests.providers.gcp.test_gcp_cloud_run_firestore_access_paths import (
    _PROJECT as GCP_PROJECT,
)
from tests.providers.gcp.test_gcp_cloud_run_firestore_access_paths import (
    _SERVICE_ACCOUNT_MEMBER as GCP_SERVICE_ACCOUNT_MEMBER,
)
from tests.providers.gcp.test_gcp_cloud_run_firestore_access_paths import (
    _custom_role as gcp_custom_role,
)
from tests.providers.gcp.test_gcp_cloud_run_firestore_access_paths import (
    _database as gcp_database,
)
from tests.providers.gcp.test_gcp_cloud_run_firestore_access_paths import (
    _project_iam_member as gcp_project_iam_member,
)
from tests.providers.gcp.test_gcp_public_cloud_run_firestore_mutation_rules import (
    _as_resource as gcp_resource,
)
from tests.providers.gcp.test_gcp_public_cloud_run_firestore_mutation_rules import (
    _public_cloud_run as gcp_public_cloud_run,
)
from tests.providers.gcp.test_gcp_public_cloud_run_firestore_mutation_rules import (
    _public_invoker as gcp_public_invoker,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import Finding, StrideCategory, TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.rules import AWS_RULE_GROUP_IDS
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.rules import AZURE_RULE_GROUP_IDS
from tfstride.providers.base import ProviderNormalizer
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.rules import GCP_RULE_GROUP_IDS

AWS_READ_RULE = "aws-public-ecs-dynamodb-read-access"
GCP_READ_RULE = "gcp-public-cloud-run-firestore-read-access"
AZURE_READ_RULE = "azure-public-app-service-cosmosdb-read-access"

AWS_MUTATION_RULE = "aws-public-ecs-dynamodb-mutation-access"
GCP_MUTATION_RULE = "gcp-public-cloud-run-firestore-mutation-access"
AZURE_MUTATION_RULE = "azure-public-app-service-cosmosdb-mutation-access"

READ_RULE_IDS = frozenset({AWS_READ_RULE, GCP_READ_RULE, AZURE_READ_RULE})
MUTATION_RULE_IDS = frozenset(
    {
        AWS_MUTATION_RULE,
        GCP_MUTATION_RULE,
        AZURE_MUTATION_RULE,
    }
)
NOSQL_PATH_RULE_IDS = READ_RULE_IDS | MUTATION_RULE_IDS

_AWS_EXTERNAL_POLICY_ARN = "arn:aws:iam::aws:policy/ExternalDynamoDbRead"
_AWS_EXTERNAL_TABLE_ARN = "arn:aws:dynamodb:us-west-2:999900001111:table/external"
_GCP_CUSTOM_ROLE = f"projects/{GCP_PROJECT}/roles/cloudRunFirestore"
_AZURE_ITEM_CREATE = "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/create"
_AZURE_READ_METADATA = "Microsoft.DocumentDB/databaseAccounts/readMetadata"
_AZURE_EXTERNAL_SCOPE = (
    "/subscriptions/sub-0001/resourceGroups/data/providers/Microsoft.DocumentDB/databaseAccounts/external"
)
_AWS_READ_CONTEXT_EVIDENCE = (
    (
        "network_path",
        ("aws_lb_listener.https forwards through aws_lb_target_group.orders to aws_ecs_service.orders",),
    ),
    (
        "task_roles",
        (
            "address=aws_iam_role.orders_task",
            "credential_context=workload_runtime",
        ),
    ),
)
_GCP_READ_CONTEXT_EVIDENCE = (
    (
        "public_invoker_bindings",
        (
            "role=roles/run.invoker",
            "member=allUsers",
        ),
    ),
    (
        "runtime_identity",
        (
            f"member={GCP_SERVICE_ACCOUNT_MEMBER}",
            "credential_context=workload_runtime",
        ),
    ),
)
_AZURE_READ_CONTEXT_EVIDENCE = (
    (
        "public_endpoint",
        ("address=azurerm_linux_web_app.orders",),
    ),
    (
        "public_endpoint",
        ("public_network_access_enabled=true",),
    ),
    (
        "runtime_identity",
        (
            "identity_address=azurerm_linux_web_app.orders",
            "principal_id=app-system-principal-id",
            "credential_context=workload_runtime",
        ),
    ),
)


def _flatten(rule_groups: tuple[tuple[str, ...], ...]) -> frozenset[str]:
    return frozenset(rule_id for group in rule_groups for rule_id in group)


def _evaluate(
    normalizer: ProviderNormalizer,
    resources: list[Any],
) -> list[Finding]:
    inventory = normalizer.normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        detect_trust_boundaries(inventory),
        rule_policy=RulePolicy(enabled_rule_ids=NOSQL_PATH_RULE_IDS),
    )


def _evidence(finding: Finding) -> dict[str, list[str]]:
    return {item.key: item.values for item in finding.evidence}


def _assert_evidence_fragments(
    test_case: unittest.TestCase,
    evidence: dict[str, list[str]],
    expectations: tuple[tuple[str, tuple[str, ...]], ...],
) -> None:
    for evidence_key, fragments in expectations:
        test_case.assertTrue(
            any(all(fragment in value for fragment in fragments) for value in evidence[evidence_key]),
            (evidence_key, fragments, evidence[evidence_key]),
        )


def _aws_resources(
    *,
    actions: str | list[str] = "dynamodb:GetItem",
    target: str = AWS_TABLE_ARN,
    index_names: tuple[str, ...] = (),
    internal: bool = False,
    condition: dict[str, object] | None = None,
    deny: bool = False,
    incomplete_policy: bool = False,
) -> list[TerraformResource]:
    statements = [
        aws_statement(
            "Allow",
            actions,
            target,
            condition=condition,
        )
    ]
    if deny:
        statements.append(aws_statement("Deny", actions, target))
    resources = [
        *aws_public_edge(internal=internal),
        aws_table(index_names=index_names),
        aws_role("orders_task", AWS_TASK_ROLE_ARN, statements),
    ]
    if incomplete_policy:
        resources.append(
            aws_role_policy_attachment(
                AWS_TASK_ROLE_ARN,
                _AWS_EXTERNAL_POLICY_ARN,
            )
        )
    resources.extend(
        [
            aws_task_definition(execution_role_arn=None),
            aws_service(),
        ]
    )
    return resources


def _gcp_resources(
    *,
    role: str = "roles/datastore.viewer",
    public: bool = True,
    condition: dict[str, str] | None = None,
    member: str = GCP_SERVICE_ACCOUNT_MEMBER,
    custom_permissions: list[str] | None = None,
) -> list[TerraformResource]:
    resources = [
        gcp_public_cloud_run(public_ingress=public),
        gcp_public_invoker(),
        gcp_resource(gcp_database()),
    ]
    if custom_permissions is not None:
        resources.append(gcp_resource(gcp_custom_role(permissions=custom_permissions)))
    resources.append(
        gcp_resource(
            gcp_project_iam_member(
                role=role,
                member=member,
                condition=condition,
            )
        )
    )
    return resources


def _azure_resources(
    *,
    target_kind: str = "account",
    public: bool = True,
    role_definition_id: str = AZURE_READER_ROLE_ID,
    custom_actions: list[str] | None = None,
    unknown_custom_permissions: bool = False,
    scope_override: str | None = None,
) -> list[TerraformResource]:
    resources = [azure_account()]
    if target_kind in {"database", "container"}:
        resources.append(azure_database())
    if target_kind == "container":
        resources.append(azure_container())

    workload = azure_web_app()
    workload.values["public_network_access_enabled"] = public
    resources.append(workload)

    if custom_actions is not None or unknown_custom_permissions:
        resources.append(
            azure_custom_role(
                data_actions=custom_actions or [],
                unknown_permissions=unknown_custom_permissions,
            )
        )
        role_definition_id = AZURE_CUSTOM_ROLE_ID

    scope = (
        scope_override
        or {
            "account": "/",
            "database": "/dbs/app",
            "container": "/dbs/app/colls/events",
        }[target_kind]
    )
    resources.append(
        azure_native_assignment(
            role_definition_id=role_definition_id,
            scope=scope,
        )
    )
    return resources


class PublicWorkloadManagedNosqlReadPathParityTests(unittest.TestCase):
    """Pins coverage parity while retaining provider-native authority shapes."""

    def test_provider_local_read_rules_are_registered(self) -> None:
        self.assertIn(AWS_READ_RULE, _flatten(AWS_RULE_GROUP_IDS))
        self.assertIn(GCP_READ_RULE, _flatten(GCP_RULE_GROUP_IDS))
        self.assertIn(AZURE_READ_RULE, _flatten(AZURE_RULE_GROUP_IDS))

    def test_public_exact_read_authority_preserves_native_scope(self) -> None:
        exact_database_condition = {
            "title": "orders-only",
            "expression": (f'resource.name == "{GCP_DATABASE_RESOURCE_NAME}"'),
        }
        cases = (
            (
                "aws-table",
                "aws",
                AwsNormalizer(),
                _aws_resources(),
                AWS_READ_RULE,
                "aws_dynamodb_table.orders",
                (
                    *_AWS_READ_CONTEXT_EVIDENCE,
                    (
                        "dynamodb_read_paths",
                        (
                            "target_kind=table",
                            "target_scope=exact_table",
                            "actions=dynamodb:GetItem",
                        ),
                    ),
                ),
            ),
            (
                "aws-index",
                "aws",
                AwsNormalizer(),
                _aws_resources(
                    actions="dynamodb:Query",
                    target=AWS_INDEX_ARN,
                    index_names=("by-status",),
                ),
                AWS_READ_RULE,
                "aws_dynamodb_table.orders",
                (
                    *_AWS_READ_CONTEXT_EVIDENCE,
                    (
                        "dynamodb_read_paths",
                        (
                            "target_kind=index",
                            "target_scope=exact_index",
                            "index_name=by-status",
                            "actions=dynamodb:Query",
                        ),
                    ),
                ),
            ),
            (
                "gcp-project",
                "gcp",
                GcpNormalizer(),
                _gcp_resources(),
                GCP_READ_RULE,
                "google_firestore_database.orders",
                (
                    *_GCP_READ_CONTEXT_EVIDENCE,
                    (
                        "firestore_read_paths",
                        (
                            "scope_type=project",
                            "resource_scope=firestore_project",
                        ),
                    ),
                ),
            ),
            (
                "gcp-database",
                "gcp",
                GcpNormalizer(),
                _gcp_resources(condition=exact_database_condition),
                GCP_READ_RULE,
                "google_firestore_database.orders",
                (
                    *_GCP_READ_CONTEXT_EVIDENCE,
                    (
                        "firestore_read_paths",
                        (
                            "scope_type=database",
                            "resource_scope=exact_firestore_database",
                            "condition_evaluation=exact_database_scope_match",
                        ),
                    ),
                ),
            ),
            (
                "azure-account",
                "azure",
                AzureNormalizer(),
                _azure_resources(target_kind="account"),
                AZURE_READ_RULE,
                "azurerm_cosmosdb_account.orders",
                (
                    *_AZURE_READ_CONTEXT_EVIDENCE,
                    (
                        "cosmosdb_read_paths",
                        (
                            "scope_type=account",
                            "resource_scope=exact_cosmosdb_for_nosql_account",
                        ),
                    ),
                ),
            ),
            (
                "azure-database",
                "azure",
                AzureNormalizer(),
                _azure_resources(target_kind="database"),
                AZURE_READ_RULE,
                "azurerm_cosmosdb_sql_database.app",
                (
                    *_AZURE_READ_CONTEXT_EVIDENCE,
                    (
                        "cosmosdb_read_paths",
                        (
                            "scope_type=database",
                            "resource_scope=exact_cosmosdb_for_nosql_database",
                        ),
                    ),
                ),
            ),
            (
                "azure-container",
                "azure",
                AzureNormalizer(),
                _azure_resources(target_kind="container"),
                AZURE_READ_RULE,
                "azurerm_cosmosdb_sql_container.events",
                (
                    *_AZURE_READ_CONTEXT_EVIDENCE,
                    (
                        "cosmosdb_read_paths",
                        (
                            "scope_type=container",
                            "resource_scope=exact_cosmosdb_for_nosql_container",
                        ),
                    ),
                ),
            ),
        )

        for (
            case,
            provider,
            normalizer,
            resources,
            expected_rule,
            target_address,
            evidence_expectations,
        ) in cases:
            with self.subTest(case=case):
                findings = _evaluate(normalizer, resources)

                self.assertEqual(
                    [finding.rule_id for finding in findings],
                    [expected_rule],
                )
                finding = findings[0]
                self.assertEqual(
                    finding.category,
                    StrideCategory.INFORMATION_DISCLOSURE,
                )
                self.assertIn(target_address, finding.affected_resources)
                self.assertTrue(all(item.rule_id.startswith(f"{provider}-") for item in findings))
                _assert_evidence_fragments(
                    self,
                    _evidence(finding),
                    evidence_expectations,
                )

    def test_private_workloads_stay_quiet(self) -> None:
        cases = (
            ("aws", AwsNormalizer(), _aws_resources(internal=True)),
            ("gcp", GcpNormalizer(), _gcp_resources(public=False)),
            (
                "azure",
                AzureNormalizer(),
                _azure_resources(public=False),
            ),
        )

        for provider, normalizer, resources in cases:
            with self.subTest(provider=provider):
                self.assertEqual(_evaluate(normalizer, resources), [])

    def test_write_only_grants_emit_mutation_without_read(self) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_resources(actions="dynamodb:BatchWriteItem"),
                AWS_MUTATION_RULE,
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_resources(
                    role=_GCP_CUSTOM_ROLE,
                    custom_permissions=["datastore.entities.create"],
                ),
                GCP_MUTATION_RULE,
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_resources(custom_actions=[_AZURE_ITEM_CREATE]),
                AZURE_MUTATION_RULE,
            ),
        )

        for provider, normalizer, resources, expected_mutation_rule in cases:
            with self.subTest(provider=provider):
                findings = _evaluate(normalizer, resources)

                self.assertEqual(
                    [finding.rule_id for finding in findings],
                    [expected_mutation_rule],
                )
                provider_read_rule = next(rule_id for rule_id in READ_RULE_IDS if rule_id.startswith(f"{provider}-"))
                self.assertNotIn(
                    provider_read_rule,
                    {finding.rule_id for finding in findings},
                )

    def test_azure_metadata_only_access_stays_quiet(self) -> None:
        self.assertEqual(
            _evaluate(
                AzureNormalizer(),
                _azure_resources(custom_actions=[_AZURE_READ_METADATA]),
            ),
            [],
        )

    def test_non_deterministic_external_or_unresolved_paths_stay_quiet(
        self,
    ) -> None:
        runtime_condition = {
            "title": "temporary",
            "expression": ("request.time < timestamp('2030-01-01T00:00:00Z')"),
        }
        aws_condition: dict[str, object] = {
            "ForAllValues:StringEquals": {
                "dynamodb:LeadingKeys": ["tenant-123"],
            }
        }
        cases = (
            (
                "aws-denied",
                AwsNormalizer(),
                _aws_resources(deny=True),
            ),
            (
                "aws-conditional",
                AwsNormalizer(),
                _aws_resources(condition=aws_condition),
            ),
            (
                "aws-external",
                AwsNormalizer(),
                _aws_resources(target=_AWS_EXTERNAL_TABLE_ARN),
            ),
            (
                "aws-incomplete",
                AwsNormalizer(),
                _aws_resources(incomplete_policy=True),
            ),
            (
                "gcp-conditional",
                GcpNormalizer(),
                _gcp_resources(condition=runtime_condition),
            ),
            (
                "gcp-external",
                GcpNormalizer(),
                _gcp_resources(member=("serviceAccount:external@other-project.iam.gserviceaccount.com")),
            ),
            (
                "gcp-unresolved",
                GcpNormalizer(),
                _gcp_resources(role=f"projects/{GCP_PROJECT}/roles/externalFirestore"),
            ),
            (
                "azure-external",
                AzureNormalizer(),
                _azure_resources(scope_override=_AZURE_EXTERNAL_SCOPE),
            ),
            (
                "azure-unresolved",
                AzureNormalizer(),
                _azure_resources(unknown_custom_permissions=True),
            ),
        )

        for case, normalizer, resources in cases:
            with self.subTest(case=case):
                self.assertEqual(_evaluate(normalizer, resources), [])

    def test_read_and_mutation_findings_remain_distinct_and_provider_local(
        self,
    ) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_resources(actions="dynamodb:PutItem"),
                AWS_READ_RULE,
                AWS_MUTATION_RULE,
                "dynamodb_read_paths",
                "dynamodb_mutation_paths",
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_resources(role="roles/datastore.user"),
                GCP_READ_RULE,
                GCP_MUTATION_RULE,
                "firestore_read_paths",
                "firestore_mutation_paths",
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_resources(
                    role_definition_id=AZURE_CONTRIBUTOR_ROLE_ID,
                ),
                AZURE_READ_RULE,
                AZURE_MUTATION_RULE,
                "cosmosdb_read_paths",
                "cosmosdb_mutation_paths",
            ),
        )

        for (
            provider,
            normalizer,
            resources,
            read_rule,
            mutation_rule,
            read_evidence_key,
            mutation_evidence_key,
        ) in cases:
            with self.subTest(provider=provider):
                findings = _evaluate(normalizer, resources)
                findings_by_rule = {finding.rule_id: finding for finding in findings}

                self.assertEqual(
                    set(findings_by_rule),
                    {read_rule, mutation_rule},
                )
                self.assertEqual(
                    findings_by_rule[read_rule].category,
                    StrideCategory.INFORMATION_DISCLOSURE,
                )
                self.assertEqual(
                    findings_by_rule[mutation_rule].category,
                    StrideCategory.TAMPERING,
                )
                self.assertIn(
                    read_evidence_key,
                    _evidence(findings_by_rule[read_rule]),
                )
                self.assertNotIn(
                    mutation_evidence_key,
                    _evidence(findings_by_rule[read_rule]),
                )
                self.assertIn(
                    mutation_evidence_key,
                    _evidence(findings_by_rule[mutation_rule]),
                )
                self.assertNotIn(
                    read_evidence_key,
                    _evidence(findings_by_rule[mutation_rule]),
                )
                self.assertTrue(all(finding.rule_id.startswith(f"{provider}-") for finding in findings))


if __name__ == "__main__":
    unittest.main()
