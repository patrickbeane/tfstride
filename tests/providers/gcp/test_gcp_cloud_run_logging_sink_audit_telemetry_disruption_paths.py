from __future__ import annotations

import json
import unittest

from tests.providers.gcp.normalizer_support import _terraform_resource
from tfstride.models import TerraformResource
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_decoration.cloud_run_logging_sink_audit_telemetry_disruption_paths import (
    current_cloud_run_logging_sink_audit_telemetry_disruption_paths,
)
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_index import (
    GcpDecorationContext,
    GcpResourceIndexBuilder,
)
from tfstride.providers.gcp.resource_types import GcpResourceType

_PROJECT = "tfstride-demo"
_OTHER_PROJECT = "tfstride-foreign"
_ORGANIZATION = "1234567890"
_OTHER_ORGANIZATION = "9876543210"
_SERVICE_ACCOUNT_EMAIL = "orders@tfstride-demo.iam.gserviceaccount.com"
_SERVICE_ACCOUNT_MEMBER = f"serviceAccount:{_SERVICE_ACCOUNT_EMAIL}"
_WORKLOAD_ADDRESS = "google_cloud_run_v2_service.orders"
_SINK_ADDRESS = "google_logging_project_sink.audit"
_SINK_NAME = "audit"
_SINK_RESOURCE_NAME = f"projects/{_PROJECT}/sinks/{_SINK_NAME}"
_DESTINATION = "storage.googleapis.com/tfstride-audit-archive"
_AUDIT_FILTER = 'logName:"cloudaudit.googleapis.com"'
_DELETE_SINK = "logging.sinks.delete"
_DENY_DELETE_SINK = "logging.googleapis.com/sinks.delete"
_RUNTIME_DENY_PRINCIPAL = f"principal://iam.googleapis.com/projects/-/serviceAccounts/{_SERVICE_ACCOUNT_EMAIL}"
_CUSTOM_ROLE_ID = "loggingSinkDisruptor"
_CUSTOM_ROLE_NAME = f"projects/{_PROJECT}/roles/{_CUSTOM_ROLE_ID}"
_CUSTOM_ROLE_ADDRESS = "google_project_iam_custom_role.logging_sink"
_IAM_ADDRESS = "google_project_iam_member.logging_sink"


def _tf(value: object) -> TerraformResource:
    assert isinstance(value, TerraformResource)
    return value


def _cloud_run(
    *,
    service_account: str | None = _SERVICE_ACCOUNT_EMAIL,
) -> TerraformResource:
    template: dict[str, object] = {}
    if service_account is not None:
        template["service_account"] = service_account
    return _terraform_resource(
        _WORKLOAD_ADDRESS,
        GcpResourceType.CLOUD_RUN_V2_SERVICE,
        {
            "name": "orders",
            "project": _PROJECT,
            "location": "us-central1",
            "template": [template],
        },
    )


def _sink(
    *,
    address: str = _SINK_ADDRESS,
    name: str = _SINK_NAME,
    project: str = _PROJECT,
    destination: str | None = _DESTINATION,
    filter_text: str | None = _AUDIT_FILTER,
    disabled: bool | None = False,
    identifier: str | None = None,
    unknown_name: bool = False,
    unknown_project: bool = False,
    unknown_destination: bool = False,
    unknown_filter: bool = False,
    unknown_disabled: bool = False,
    exclusions: list[dict[str, object]] | None = None,
    unknown_exclusions: object | None = None,
) -> TerraformResource:
    values: dict[str, object] = {
        "id": identifier or f"projects/{project}/sinks/{name}",
        "name": name,
        "project": project,
        "writer_identity": (f"serviceAccount:logging-{project}@gcp-sa-logging.iam.gserviceaccount.com"),
        "unique_writer_identity": True,
    }
    if destination is not None:
        values["destination"] = destination
    if filter_text is not None:
        values["filter"] = filter_text
    if disabled is not None:
        values["disabled"] = disabled
    if exclusions is not None:
        values["exclusions"] = exclusions
    unknown_values: dict[str, object] = {}
    if unknown_name:
        unknown_values["name"] = True
    if unknown_project:
        unknown_values["project"] = True
    if unknown_destination:
        unknown_values["destination"] = True
    if unknown_filter:
        unknown_values["filter"] = True
    if unknown_disabled:
        unknown_values["disabled"] = True
    if unknown_exclusions is not None:
        unknown_values["exclusions"] = unknown_exclusions
    return _terraform_resource(
        address,
        GcpResourceType.LOGGING_PROJECT_SINK,
        values,
        unknown_values=unknown_values,
    )


def _organization_sink() -> TerraformResource:
    return _terraform_resource(
        "google_logging_organization_sink.audit",
        GcpResourceType.LOGGING_ORGANIZATION_SINK,
        {
            "name": "organization-audit",
            "org_id": _ORGANIZATION,
            "destination": _DESTINATION,
            "filter": _AUDIT_FILTER,
        },
    )


def _project_member(
    *,
    role: str | None = _CUSTOM_ROLE_NAME,
    member: str = _SERVICE_ACCOUNT_MEMBER,
    name: str = "logging_sink",
    project: str = _PROJECT,
    condition: dict[str, str] | None = None,
    unknown_role: bool = False,
    unknown_member: bool = False,
    unknown_project: bool = False,
    unknown_condition: bool = False,
) -> TerraformResource:
    values: dict[str, object] = {
        "project": project,
        "member": member,
    }
    if role is not None:
        values["role"] = role
    if condition is not None:
        values["condition"] = [condition]
    unknown_values: dict[str, object] = {}
    if unknown_role:
        unknown_values["role"] = True
    if unknown_member:
        unknown_values["member"] = True
    if unknown_project:
        unknown_values["project"] = True
    if unknown_condition:
        unknown_values["condition"] = True
    return _terraform_resource(
        f"google_project_iam_member.{name}",
        GcpResourceType.PROJECT_IAM_MEMBER,
        values,
        unknown_values=unknown_values,
    )


def _project_binding(
    *,
    role: str | None,
    members: list[str],
    name: str = "logging_sink",
    project: str = _PROJECT,
    unknown_role: bool = False,
    unknown_project: bool = False,
) -> TerraformResource:
    values: dict[str, object] = {
        "project": project,
        "members": members,
    }
    if role is not None:
        values["role"] = role
    unknown_values: dict[str, object] = {}
    if unknown_role:
        unknown_values["role"] = True
    if unknown_project:
        unknown_values["project"] = True
    return _terraform_resource(
        f"google_project_iam_binding.{name}",
        GcpResourceType.PROJECT_IAM_BINDING,
        values,
        unknown_values=unknown_values,
    )


def _project_policy(
    *,
    bindings: list[dict[str, object]],
    unknown_policy: bool = False,
) -> TerraformResource:
    return _terraform_resource(
        "google_project_iam_policy.logging_sink",
        GcpResourceType.PROJECT_IAM_POLICY,
        {
            "project": _PROJECT,
            "policy_data": json.dumps({"bindings": bindings}),
        },
        unknown_values={"policy_data": True} if unknown_policy else None,
    )


def _custom_role(
    *,
    address: str = _CUSTOM_ROLE_ADDRESS,
    project: str = _PROJECT,
    role_id: str | None = _CUSTOM_ROLE_ID,
    permissions: list[str] | None = None,
    stage: str | None = "GA",
    deleted: bool | None = False,
    unknown_role_id: bool = False,
    unknown_name: bool = False,
    unknown_stage: bool = False,
    unknown_deleted: bool = False,
    unknown_permissions: bool = False,
) -> TerraformResource:
    values: dict[str, object] = {
        "project": project,
        "permissions": permissions or [_DELETE_SINK],
    }
    if role_id is not None:
        values["role_id"] = role_id
        values["name"] = f"projects/{project}/roles/{role_id}"
    if stage is not None:
        values["stage"] = stage
    if deleted is not None:
        values["deleted"] = deleted
    unknown_values: dict[str, object] = {}
    if unknown_role_id:
        unknown_values["role_id"] = True
    if unknown_name:
        unknown_values["name"] = True
    if unknown_stage:
        unknown_values["stage"] = True
    if unknown_deleted:
        unknown_values["deleted"] = True
    if unknown_permissions:
        unknown_values["permissions"] = True
    return _terraform_resource(
        address,
        GcpResourceType.PROJECT_IAM_CUSTOM_ROLE,
        values,
        unknown_values=unknown_values,
    )


def _organization_custom_role(
    *,
    organization: str = _ORGANIZATION,
) -> TerraformResource:
    return _terraform_resource(
        "google_organization_iam_custom_role.logging_sink",
        GcpResourceType.ORGANIZATION_IAM_CUSTOM_ROLE,
        {
            "org_id": organization,
            "role_id": _CUSTOM_ROLE_ID,
            "name": f"organizations/{organization}/roles/{_CUSTOM_ROLE_ID}",
            "permissions": [_DELETE_SINK],
            "stage": "GA",
            "deleted": False,
        },
    )


def _project_resource(
    *,
    organization: str = _ORGANIZATION,
) -> TerraformResource:
    return _terraform_resource(
        "google_project.main",
        GcpResourceType.PROJECT,
        {
            "project_id": _PROJECT,
            "org_id": organization,
        },
    )


def _deny_policy(
    *,
    parent: str = "cloudresourcemanager.googleapis.com%2Fprojects%2Ftfstride-demo",
    denied_principals: list[str] | None = None,
    denied_permissions: list[str] | None = None,
    exception_principals: list[str] | None = None,
    exception_permissions: list[str] | None = None,
    condition: dict[str, str] | None = None,
    unknown_parent: bool = False,
    unknown_denied_permissions: bool = False,
) -> TerraformResource:
    deny_rule: dict[str, object] = {
        "denied_principals": denied_principals or [_RUNTIME_DENY_PRINCIPAL],
        "denied_permissions": denied_permissions or [_DENY_DELETE_SINK],
        "exception_principals": exception_principals or [],
        "exception_permissions": exception_permissions or [],
    }
    if condition is not None:
        deny_rule["denial_condition"] = [condition]
    unknown_values: dict[str, object] = {}
    if unknown_parent:
        unknown_values["parent"] = True
    if unknown_denied_permissions:
        unknown_values["rules"] = [{"deny_rule": [{"denied_permissions": True}]}]
    return _terraform_resource(
        "google_iam_deny_policy.logging_sink",
        GcpResourceType.IAM_DENY_POLICY,
        {
            "parent": parent,
            "name": "deny-logging-sink-delete",
            "rules": [{"deny_rule": [deny_rule]}],
        },
        unknown_values=unknown_values,
    )


def _principal_access_boundary_policy() -> TerraformResource:
    return _terraform_resource(
        "google_iam_principal_access_boundary_policy.runtime",
        "google_iam_principal_access_boundary_policy",
        {
            "parent": "organizations/1234567890/locations/global",
            "name": "runtime-boundary",
            "details": [
                {
                    "rules": [
                        {
                            "resources": ["//cloudresourcemanager.googleapis.com/projects/other"],
                        }
                    ]
                }
            ],
        },
    )


def _normalize(*resources: object):
    inventory = GcpNormalizer().normalize([_tf(resource) for resource in resources])
    workload = inventory.get_by_address(_WORKLOAD_ADDRESS)
    sink = inventory.get_by_address(_SINK_ADDRESS)
    assert workload is not None
    assert sink is not None
    return inventory, workload, sink, gcp_facts(workload)


class GcpCloudRunLoggingSinkAuditTelemetryDisruptionPathTests(unittest.TestCase):
    def test_exact_custom_role_preserves_authority_sink_and_nonclaim_evidence(
        self,
    ) -> None:
        inventory, workload, _sink_target, facts = _normalize(
            _cloud_run(),
            _sink(),
            _custom_role(
                permissions=[
                    "logging.sinks.get",
                    _DELETE_SINK,
                    _DELETE_SINK,
                ]
            ),
            _project_member(),
        )

        self.assertFalse(workload.public_exposure)
        self.assertEqual(
            len(facts.cloud_run_logging_sink_audit_telemetry_disruption_paths),
            1,
        )
        path = facts.cloud_run_logging_sink_audit_telemetry_disruption_paths[0]
        self.assertEqual(path["workload_address"], _WORKLOAD_ADDRESS)
        self.assertEqual(path["service_account_email"], _SERVICE_ACCOUNT_EMAIL)
        self.assertEqual(path["service_account_member"], _SERVICE_ACCOUNT_MEMBER)
        self.assertEqual(path["identity_kind"], "cloud_run_service_account")
        self.assertEqual(path["credential_context"], "workload_runtime")
        self.assertEqual(path["logging_sink_address"], _SINK_ADDRESS)
        self.assertEqual(
            path["logging_sink_resource_type"],
            GcpResourceType.LOGGING_PROJECT_SINK,
        )
        self.assertEqual(path["logging_sink_name"], _SINK_NAME)
        self.assertEqual(path["logging_sink_resource_name"], _SINK_RESOURCE_NAME)
        self.assertEqual(path["logging_sink_project"], _PROJECT)
        self.assertEqual(path["logging_sink_destination"], _DESTINATION)
        self.assertTrue(path["logging_sink_unique_writer_identity"])
        self.assertEqual(path["operation"], _DELETE_SINK)
        self.assertEqual(path["matched_permissions"], [_DELETE_SINK])
        self.assertEqual(path["operation_class"], "project_sink_deletion")
        self.assertEqual(path["internal_operation"], "delete_project_logging_sink")
        self.assertEqual(path["management_effect"], "audit_telemetry_disruption")
        self.assertEqual(path["target_granularity"], "project_logging_sink")
        self.assertEqual(path["target_scope"], "exact_project_logging_sink")
        self.assertEqual(path["target_model_evidence_addresses"], [_SINK_ADDRESS])
        self.assertEqual(path["scope_type"], "project")
        self.assertEqual(path["scope"], _PROJECT)
        self.assertEqual(path["resource_scope"], "logging_project")
        self.assertEqual(path["grant_basis"], "logging_project_iam")
        self.assertEqual(path["authorization_state"], "granted")
        self.assertTrue(path["policy_complete"])
        self.assertEqual(path["iam_manager_ambiguity_state"], "not_detected")
        self.assertIsNone(path["condition"])
        self.assertEqual(path["condition_state"], "not_configured")
        self.assertEqual(path["condition_evaluation"], "not_configured")

        role = path["role_evidence"]
        self.assertEqual(role["role_kind"], "custom")
        self.assertEqual(role["role_definition_address"], _CUSTOM_ROLE_ADDRESS)
        self.assertEqual(
            role["custom_role_permissions"],
            [_DELETE_SINK, "logging.sinks.get"],
        )
        self.assertEqual(role["custom_role_stage"], "GA")
        self.assertFalse(role["custom_role_deleted"])
        self.assertFalse(role["custom_role_wildcard_permissions_present"])
        self.assertEqual(
            role["custom_role_grant_scope_compatibility_state"],
            "compatible",
        )
        self.assertEqual(
            path["iam_source_addresses"],
            [_IAM_ADDRESS, _CUSTOM_ROLE_ADDRESS],
        )
        self.assertIsNotNone(inventory.get_by_address(path["iam_resource_address"]))

        lifecycle = path["lifecycle_evidence"]
        self.assertEqual(lifecycle["disabled_configuration_state"], "configured")
        self.assertFalse(lifecycle["sink_disabled"])
        self.assertFalse(lifecycle["provider_default_applied"])
        self.assertEqual(lifecycle["sink_lifecycle_state"], "active")
        constraint = path["deletion_constraint_evidence"]
        self.assertEqual(constraint["sink_kind"], "user_managed")
        self.assertTrue(constraint["api_deletion_supported"])
        relevance = path["audit_telemetry_relevance_evidence"]
        self.assertEqual(relevance["filter_state"], "configured")
        self.assertEqual(relevance["relevance_basis"], "audit_security_filter")
        self.assertIn(
            "cloudaudit.googleapis.com",
            relevance["matched_audit_security_filter_signals"],
        )

        outcome = path["outcome_evidence"]
        self.assertFalse(outcome["successful_operation_observed"])
        self.assertFalse(outcome["historical_log_entry_deletion_authorized_by_operation"])
        self.assertFalse(outcome["historical_log_entry_deletion_observed"])
        self.assertFalse(outcome["destination_resource_deletion_authorized_by_operation"])
        self.assertFalse(outcome["destination_resource_deletion_observed"])
        self.assertFalse(outcome["unique_writer_identity_side_effect_evaluated"])
        self.assertFalse(outcome["all_project_audit_sinks_evaluated"])
        self.assertFalse(outcome["out_of_plan_sinks_evaluated"])
        self.assertEqual(
            outcome["telemetry_recovery_state"],
            "not_established_by_modeled_gcp_logging_sink_evidence",
        )
        self.assertFalse(outcome["restoration_observed"])
        self.assertEqual(path["posture_uncertainties"], [])
        self.assertEqual(
            facts.cloud_run_logging_sink_audit_telemetry_disruption_path_uncertainties,
            [],
        )

    def test_relevance_requires_positive_filter_and_effective_export(
        self,
    ) -> None:
        _inventory, _workload, _sink_target, positive = _normalize(
            _cloud_run(),
            _sink(),
            _project_member(role="roles/logging.admin"),
        )
        self.assertEqual(
            positive.cloud_run_logging_sink_audit_telemetry_disruption_paths[0]["audit_telemetry_relevance_evidence"][
                "audit_telemetry_relevance_state"
            ],
            "established",
        )

        _inventory, _workload, _sink_target, excluded = _normalize(
            _cloud_run(),
            _sink(
                exclusions=[
                    {
                        "name": "drop-audit",
                        "filter": _AUDIT_FILTER,
                    }
                ]
            ),
            _project_member(role="roles/logging.admin"),
        )
        self.assertEqual(
            excluded.cloud_run_logging_sink_audit_telemetry_disruption_paths,
            [],
        )
        self.assertTrue(excluded.cloud_run_logging_sink_audit_telemetry_disruption_path_uncertainties)

        for active_exclusion_filter in ("logName:*", "severity=DEBUG"):
            with self.subTest(active_exclusion=active_exclusion_filter):
                _inventory, _workload, _sink_target, active_exclusion = _normalize(
                    _cloud_run(),
                    _sink(
                        exclusions=[
                            {
                                "name": "active-exclusion",
                                "filter": active_exclusion_filter,
                            }
                        ]
                    ),
                    _project_member(role="roles/logging.admin"),
                )
                self.assertEqual(
                    active_exclusion.cloud_run_logging_sink_audit_telemetry_disruption_paths,
                    [],
                )
                self.assertTrue(active_exclusion.cloud_run_logging_sink_audit_telemetry_disruption_path_uncertainties)

        _inventory, _workload, _sink_target, unresolved = _normalize(
            _cloud_run(),
            _sink(
                exclusions=[
                    {
                        "name": "drop-audit",
                        "filter": _AUDIT_FILTER,
                    }
                ],
                unknown_exclusions=[{"disabled": True}],
            ),
            _project_member(role="roles/logging.admin"),
        )
        self.assertEqual(
            unresolved.cloud_run_logging_sink_audit_telemetry_disruption_paths,
            [],
        )
        self.assertTrue(unresolved.cloud_run_logging_sink_audit_telemetry_disruption_path_uncertainties)

        _inventory, _workload, _sink_target, disabled_irrelevant = _normalize(
            _cloud_run(),
            _sink(
                exclusions=[
                    {
                        "name": "drop-debug",
                        "filter": "severity=DEBUG",
                        "disabled": True,
                    }
                ]
            ),
            _project_member(role="roles/logging.admin"),
        )
        self.assertEqual(
            len(disabled_irrelevant.cloud_run_logging_sink_audit_telemetry_disruption_paths),
            1,
        )

        explicit_audit_type_filter = 'protoPayload.@type="type.googleapis.com/google.cloud.audit.AuditLog"'
        _inventory, _workload, _sink_target, explicit_audit_type = _normalize(
            _cloud_run(),
            _sink(filter_text=explicit_audit_type_filter),
            _project_member(role="roles/logging.admin"),
        )
        explicit_paths = explicit_audit_type.cloud_run_logging_sink_audit_telemetry_disruption_paths
        self.assertEqual(len(explicit_paths), 1)
        self.assertEqual(
            explicit_paths[0]["audit_telemetry_relevance_evidence"]["matched_audit_security_filter_signals"],
            ["google.cloud.audit.auditlog"],
        )

        for non_audit_filter in (
            'protoPayload.@type="type.googleapis.com/google.cloud.storage.SomeEvent"',
            'protoPayload.serviceName="example.googleapis.com"',
            'jsonPayload.message="cloudaudit.googleapis.com"',
            'jsonPayload.logName="cloudaudit.googleapis.com"',
            ('logName:"cloudaudit.googleapis.com" AND logName="projects/example/logs/custom"'),
            ('logName:"cloudaudit.googleapis.com"\nlogName="projects/example/logs/custom"'),
        ):
            with self.subTest(filter=non_audit_filter):
                _inventory, _workload, _sink_target, non_audit = _normalize(
                    _cloud_run(),
                    _sink(filter_text=non_audit_filter),
                    _project_member(role="roles/logging.admin"),
                )
                self.assertEqual(
                    non_audit.cloud_run_logging_sink_audit_telemetry_disruption_paths,
                    [],
                )

        for operator_filter in (
            'NOT logName:"cloudaudit.googleapis.com"',
            '-logName:"cloudaudit.googleapis.com"',
            'logName!="cloudaudit.googleapis.com"',
            'logName!~"cloudaudit.googleapis.com"',
        ):
            with self.subTest(filter=operator_filter):
                _inventory, _workload, _sink_target, negative = _normalize(
                    _cloud_run(),
                    _sink(filter_text=operator_filter),
                    _project_member(role="roles/logging.admin"),
                )
                self.assertEqual(
                    negative.cloud_run_logging_sink_audit_telemetry_disruption_paths,
                    [],
                )

    def test_predefined_roles_and_provider_defaults_are_modeled_exactly(self) -> None:
        roles = {
            "roles/owner": "owner",
            "roles/logging.admin": "logging_admin",
            "roles/logging.configWriter": "logging_config_writer",
            "roles/iam.devOps": "iam_devops",
            "roles/iam.infrastructureAdmin": "iam_infrastructure_admin",
            "roles/iam.networkAdmin": "iam_network_admin",
        }
        for role, role_kind in roles.items():
            with self.subTest(role=role):
                _inventory, _workload, _sink_target, facts = _normalize(
                    _cloud_run(),
                    _sink(filter_text=None, disabled=None),
                    _project_member(role=role),
                )
                path = facts.cloud_run_logging_sink_audit_telemetry_disruption_paths[0]
                self.assertEqual(path["role_evidence"]["role_kind"], role_kind)
                self.assertEqual(
                    path["lifecycle_evidence"]["disabled_configuration_state"],
                    "not_configured",
                )
                self.assertTrue(path["lifecycle_evidence"]["provider_default_applied"])
                self.assertEqual(
                    path["audit_telemetry_relevance_evidence"]["relevance_basis"],
                    "all_logs",
                )

        _inventory, _workload, _sink_target, non_delete = _normalize(
            _cloud_run(),
            _sink(),
            _project_member(role="roles/logging.viewer"),
        )
        self.assertEqual(
            non_delete.cloud_run_logging_sink_audit_telemetry_disruption_paths,
            [],
        )

    def test_in_plan_iam_deny_policy_controls_effective_sink_authority(self) -> None:
        _inventory, _workload, _sink_target, denied = _normalize(
            _cloud_run(),
            _sink(),
            _project_member(role="roles/logging.admin"),
            _deny_policy(),
        )
        self.assertEqual(
            denied.cloud_run_logging_sink_audit_telemetry_disruption_paths,
            [],
        )
        self.assertEqual(
            denied.cloud_run_logging_sink_audit_telemetry_disruption_path_uncertainties,
            [],
        )

        _inventory, _workload, _sink_target, public_denied = _normalize(
            _cloud_run(),
            _sink(),
            _project_member(role="roles/logging.admin"),
            _deny_policy(denied_principals=["principalSet://goog/public:all"]),
        )
        self.assertEqual(
            public_denied.cloud_run_logging_sink_audit_telemetry_disruption_paths,
            [],
        )

        _inventory, _workload, _sink_target, organization_denied = _normalize(
            _cloud_run(),
            _sink(),
            _project_member(role="roles/logging.admin"),
            _project_resource(),
            _deny_policy(parent=(f"cloudresourcemanager.googleapis.com%2Forganizations%2F{_ORGANIZATION}")),
        )
        self.assertEqual(
            organization_denied.cloud_run_logging_sink_audit_telemetry_disruption_paths,
            [],
        )

        compatible_policies = {
            "other permission": _deny_policy(denied_permissions=["logging.googleapis.com/logMetrics.delete"]),
            "unsupported wildcard": _deny_policy(denied_permissions=["logging.googleapis.com/sinks.de*"]),
            "other principal": _deny_policy(
                denied_principals=[
                    "principal://iam.googleapis.com/projects/-/serviceAccounts/other@example.iam.gserviceaccount.com"
                ]
            ),
            "other project": _deny_policy(parent=("cloudresourcemanager.googleapis.com%2Fprojects%2Ftfstride-foreign")),
            "permission exception": _deny_policy(exception_permissions=[_DENY_DELETE_SINK]),
            "principal exception": _deny_policy(exception_principals=[_RUNTIME_DENY_PRINCIPAL]),
        }
        for case, policy in compatible_policies.items():
            with self.subTest(case=case):
                _inventory, _workload, _sink_target, compatible = _normalize(
                    _cloud_run(),
                    _sink(),
                    _project_member(role="roles/logging.admin"),
                    policy,
                )
                self.assertEqual(
                    len(compatible.cloud_run_logging_sink_audit_telemetry_disruption_paths),
                    1,
                )

    def test_unresolved_applicable_iam_deny_policy_fails_closed(self) -> None:
        policies = {
            "conditional": _deny_policy(condition={"expression": "resource.matchTag('123/environment', 'prod')"}),
            "unknown permission": _deny_policy(unknown_denied_permissions=True),
            "unknown parent": _deny_policy(unknown_parent=True),
            "unresolved folder inheritance": _deny_policy(
                parent="cloudresourcemanager.googleapis.com%2Ffolders%2F123456"
            ),
        }
        for case, policy in policies.items():
            with self.subTest(case=case):
                _inventory, _workload, _sink_target, facts = _normalize(
                    _cloud_run(),
                    _sink(),
                    _project_member(role="roles/logging.admin"),
                    policy,
                )
                self.assertEqual(
                    facts.cloud_run_logging_sink_audit_telemetry_disruption_paths,
                    [],
                )
                self.assertTrue(facts.cloud_run_logging_sink_audit_telemetry_disruption_path_uncertainties)

    def test_principal_access_boundary_does_not_suppress_sink_delete(self) -> None:
        _inventory, _workload, _sink_target, facts = _normalize(
            _cloud_run(),
            _sink(),
            _project_member(role="roles/logging.admin"),
            _principal_access_boundary_policy(),
        )

        self.assertEqual(
            len(facts.cloud_run_logging_sink_audit_telemetry_disruption_paths),
            1,
        )

    def test_project_grant_correlates_only_exact_same_project_sinks(self) -> None:
        archive_address = "google_logging_project_sink.archive"
        foreign_address = "google_logging_project_sink.foreign"
        inventory = GcpNormalizer().normalize(
            [
                _cloud_run(),
                _sink(),
                _sink(
                    address=archive_address,
                    name="archive",
                    filter_text=None,
                ),
                _sink(
                    address=foreign_address,
                    name="foreign",
                    project=_OTHER_PROJECT,
                ),
                _organization_sink(),
                _project_member(role="roles/logging.admin"),
            ]
        )
        workload = inventory.get_by_address(_WORKLOAD_ADDRESS)
        assert workload is not None
        paths = gcp_facts(workload).cloud_run_logging_sink_audit_telemetry_disruption_paths

        self.assertEqual(
            {path["logging_sink_address"] for path in paths},
            {_SINK_ADDRESS, archive_address},
        )
        self.assertEqual(
            {path["logging_sink_project"] for path in paths},
            {_PROJECT},
        )
        self.assertEqual(
            {path["logging_sink_resource_name"] for path in paths},
            {
                _SINK_RESOURCE_NAME,
                f"projects/{_PROJECT}/sinks/archive",
            },
        )
        self.assertNotIn(
            foreign_address,
            {path["logging_sink_address"] for path in paths},
        )
        self.assertNotIn(
            "google_logging_organization_sink.audit",
            {path["logging_sink_address"] for path in paths},
        )

    def test_sink_identity_lifecycle_relevance_and_system_constraints_fail_closed(
        self,
    ) -> None:
        cases = {
            "disabled": (_sink(disabled=True), False),
            "unknown disabled": (
                _sink(disabled=None, unknown_disabled=True),
                True,
            ),
            "irrelevant filter": (
                _sink(filter_text="resource.type=gce_instance"),
                False,
            ),
            "unknown filter": (
                _sink(filter_text=None, unknown_filter=True),
                True,
            ),
            "missing destination": (_sink(destination=None), True),
            "unknown destination": (
                _sink(destination=None, unknown_destination=True),
                True,
            ),
            "system default": (_sink(name="_Default"), False),
            "system required": (_sink(name="_Required"), False),
            "unknown name": (_sink(unknown_name=True), True),
            "unknown project": (_sink(unknown_project=True), True),
            "mismatched canonical id": (
                _sink(identifier=f"projects/{_OTHER_PROJECT}/sinks/{_SINK_NAME}"),
                True,
            ),
        }
        for case, (sink, has_uncertainty) in cases.items():
            with self.subTest(case=case):
                _inventory, _workload, _sink_target, facts = _normalize(
                    _cloud_run(),
                    sink,
                    _project_member(role="roles/logging.admin"),
                )
                self.assertEqual(
                    facts.cloud_run_logging_sink_audit_telemetry_disruption_paths,
                    [],
                )
                self.assertEqual(
                    bool(facts.cloud_run_logging_sink_audit_telemetry_disruption_path_uncertainties),
                    has_uncertainty,
                )

        for service_account in (None, "unknown-service-account"):
            with self.subTest(service_account=service_account):
                _inventory, _workload, _sink_target, facts = _normalize(
                    _cloud_run(service_account=service_account),
                    _sink(),
                    _project_member(role="roles/logging.admin"),
                )
                self.assertEqual(
                    facts.cloud_run_logging_sink_audit_telemetry_disruption_paths,
                    [],
                )
                self.assertTrue(facts.cloud_run_logging_sink_audit_telemetry_disruption_path_uncertainties)

    def test_custom_role_lifecycle_permissions_and_grant_scope_fail_closed(
        self,
    ) -> None:
        cases = {
            "disabled": (
                _custom_role(stage="DISABLED"),
                _CUSTOM_ROLE_NAME,
                False,
            ),
            "deleted": (
                _custom_role(deleted=True),
                _CUSTOM_ROLE_NAME,
                False,
            ),
            "unknown stage": (
                _custom_role(stage=None, unknown_stage=True),
                _CUSTOM_ROLE_NAME,
                True,
            ),
            "unknown deleted": (
                _custom_role(deleted=None, unknown_deleted=True),
                _CUSTOM_ROLE_NAME,
                True,
            ),
            "unknown permissions": (
                _custom_role(unknown_permissions=True),
                _CUSTOM_ROLE_NAME,
                True,
            ),
            "wildcard permissions": (
                _custom_role(permissions=["logging.sinks.*"]),
                _CUSTOM_ROLE_NAME,
                True,
            ),
            "other permission": (
                _custom_role(permissions=["logging.sinks.get"]),
                _CUSTOM_ROLE_NAME,
                False,
            ),
            "unsupported stage": (
                _custom_role(stage="UNKNOWN"),
                _CUSTOM_ROLE_NAME,
                True,
            ),
            "incompatible project": (
                _custom_role(project=_OTHER_PROJECT),
                f"projects/{_OTHER_PROJECT}/roles/{_CUSTOM_ROLE_ID}",
                True,
            ),
        }
        for case, (role, role_name, has_uncertainty) in cases.items():
            with self.subTest(case=case):
                _inventory, _workload, _sink_target, facts = _normalize(
                    _cloud_run(),
                    _sink(),
                    role,
                    _project_member(role=role_name),
                )
                self.assertEqual(
                    facts.cloud_run_logging_sink_audit_telemetry_disruption_paths,
                    [],
                )
                self.assertEqual(
                    bool(facts.cloud_run_logging_sink_audit_telemetry_disruption_path_uncertainties),
                    has_uncertainty,
                )

        organization_role_name = f"organizations/{_ORGANIZATION}/roles/{_CUSTOM_ROLE_ID}"
        _inventory, _workload, _sink_target, compatible = _normalize(
            _cloud_run(),
            _sink(),
            _project_resource(),
            _organization_custom_role(),
            _project_member(role=organization_role_name),
        )
        self.assertEqual(
            len(compatible.cloud_run_logging_sink_audit_telemetry_disruption_paths),
            1,
        )

        _inventory, _workload, _sink_target, incompatible = _normalize(
            _cloud_run(),
            _sink(),
            _project_resource(organization=_OTHER_ORGANIZATION),
            _organization_custom_role(),
            _project_member(role=organization_role_name),
        )
        self.assertEqual(
            incompatible.cloud_run_logging_sink_audit_telemetry_disruption_paths,
            [],
        )
        self.assertTrue(incompatible.cloud_run_logging_sink_audit_telemetry_disruption_path_uncertainties)

    def test_custom_role_identity_is_exact_and_collision_free(self) -> None:
        unknown_role = _custom_role(
            role_id=None,
            unknown_role_id=True,
            unknown_name=True,
        )
        inventory, _workload, _sink_target, unknown = _normalize(
            _cloud_run(),
            _sink(),
            unknown_role,
            _project_member(role="google_project_iam_custom_role.logging_sink.name"),
        )
        normalized_unknown_role = inventory.get_by_address(_CUSTOM_ROLE_ADDRESS)
        assert normalized_unknown_role is not None
        self.assertIsNone(gcp_facts(normalized_unknown_role).custom_role_id)
        self.assertEqual(
            len(unknown.cloud_run_logging_sink_audit_telemetry_disruption_paths),
            1,
        )
        self.assertEqual(
            unknown.cloud_run_logging_sink_audit_telemetry_disruption_paths[0]["role_evidence"][
                "role_definition_address"
            ],
            _CUSTOM_ROLE_ADDRESS,
        )
        self.assertEqual(
            unknown.cloud_run_logging_sink_audit_telemetry_disruption_path_uncertainties,
            [],
        )

        colliding_roles = (
            _custom_role(),
            _custom_role(
                address="google_project_iam_custom_role.logging_sink_duplicate",
                permissions=["logging.sinks.get"],
            ),
        )
        for role_definitions in (colliding_roles, tuple(reversed(colliding_roles))):
            with self.subTest(role_order=tuple(role.address for role in role_definitions)):
                _inventory, _workload, _sink_target, collision = _normalize(
                    _cloud_run(),
                    _sink(),
                    *role_definitions,
                    _project_member(),
                )
                self.assertEqual(
                    collision.cloud_run_logging_sink_audit_telemetry_disruption_paths,
                    [],
                )
                self.assertTrue(
                    any(
                        "collides across multiple role definitions" in uncertainty
                        for uncertainty in (
                            collision.cloud_run_logging_sink_audit_telemetry_disruption_path_uncertainties
                        )
                    )
                )

    def test_unknown_conditional_and_incomplete_iam_evidence_fails_closed(
        self,
    ) -> None:
        condition = {
            "title": "temporary",
            "expression": "request.time < timestamp('2030-01-01T00:00:00Z')",
        }
        cases = {
            "condition": _project_member(
                role="roles/logging.admin",
                condition=condition,
            ),
            "unknown condition": _project_member(
                role="roles/logging.admin",
                unknown_condition=True,
            ),
            "unknown role": _project_member(
                role=None,
                unknown_role=True,
            ),
            "unknown member": _project_member(
                role="roles/logging.admin",
                unknown_member=True,
            ),
            "unknown project": _project_member(
                role="roles/logging.admin",
                unknown_project=True,
            ),
            "unknown policy": _project_policy(
                bindings=[
                    {
                        "role": "roles/logging.admin",
                        "members": [_SERVICE_ACCOUNT_MEMBER],
                    }
                ],
                unknown_policy=True,
            ),
        }
        for case, iam_resource in cases.items():
            with self.subTest(case=case):
                _inventory, _workload, _sink_target, facts = _normalize(
                    _cloud_run(),
                    _sink(),
                    iam_resource,
                )
                self.assertEqual(
                    facts.cloud_run_logging_sink_audit_telemetry_disruption_paths,
                    [],
                )
                self.assertTrue(facts.cloud_run_logging_sink_audit_telemetry_disruption_path_uncertainties)

        _inventory, _workload, _sink_target, policy = _normalize(
            _cloud_run(),
            _sink(),
            _project_policy(
                bindings=[
                    {
                        "role": "roles/logging.admin",
                        "members": [_SERVICE_ACCOUNT_MEMBER],
                    }
                ]
            ),
        )
        self.assertEqual(
            len(policy.cloud_run_logging_sink_audit_telemetry_disruption_paths),
            1,
        )
        path = policy.cloud_run_logging_sink_audit_telemetry_disruption_paths[0]
        self.assertEqual(
            path["iam_resource_type"],
            GcpResourceType.PROJECT_IAM_POLICY,
        )
        self.assertTrue(path["policy_complete"])

    def test_iam_manager_reconciliation_handles_aliases_and_overlap(self) -> None:
        _inventory, _workload, _sink_target, ambiguous = _normalize(
            _cloud_run(),
            _sink(),
            _custom_role(),
            _project_member(role="google_project_iam_custom_role.logging_sink.name"),
            _project_binding(
                role=_CUSTOM_ROLE_NAME,
                members=["serviceAccount:other@tfstride-demo.iam.gserviceaccount.com"],
            ),
        )
        self.assertEqual(
            ambiguous.cloud_run_logging_sink_audit_telemetry_disruption_paths,
            [],
        )
        self.assertTrue(
            any(
                "ambiguous" in uncertainty
                for uncertainty in (ambiguous.cloud_run_logging_sink_audit_telemetry_disruption_path_uncertainties)
            )
        )

        _inventory, _workload, _sink_target, compatible = _normalize(
            _cloud_run(),
            _sink(),
            _custom_role(),
            _project_member(role="google_project_iam_custom_role.logging_sink.name"),
            _project_binding(
                role="roles/logging.viewer",
                members=["serviceAccount:other@tfstride-demo.iam.gserviceaccount.com"],
            ),
        )
        self.assertEqual(
            len(compatible.cloud_run_logging_sink_audit_telemetry_disruption_paths),
            1,
        )

        for case, manager in {
            "unknown role": _project_binding(
                role=None,
                members=["serviceAccount:other@tfstride-demo.iam.gserviceaccount.com"],
                unknown_role=True,
            ),
            "unknown project": _project_binding(
                role=_CUSTOM_ROLE_NAME,
                members=["serviceAccount:other@tfstride-demo.iam.gserviceaccount.com"],
                unknown_project=True,
            ),
        }.items():
            with self.subTest(case=case):
                _inventory, _workload, _sink_target, unresolved = _normalize(
                    _cloud_run(),
                    _sink(),
                    _custom_role(),
                    _project_member(),
                    manager,
                )
                self.assertEqual(
                    unresolved.cloud_run_logging_sink_audit_telemetry_disruption_paths,
                    [],
                )
                self.assertTrue(unresolved.cloud_run_logging_sink_audit_telemetry_disruption_path_uncertainties)

    def test_exact_proofs_are_deduplicated_and_current_state_is_revalidated(
        self,
    ) -> None:
        duplicate_binding = {
            "role": "roles/logging.admin",
            "members": [_SERVICE_ACCOUNT_MEMBER],
        }
        inventory, workload, sink, facts = _normalize(
            _cloud_run(),
            _sink(),
            _project_policy(
                bindings=[duplicate_binding, duplicate_binding],
            ),
        )
        paths = facts.cloud_run_logging_sink_audit_telemetry_disruption_paths
        self.assertEqual(len(paths), 1)

        resources = list(inventory.resources)
        context = GcpDecorationContext(GcpResourceIndexBuilder().build(resources))
        self.assertEqual(
            current_cloud_run_logging_sink_audit_telemetry_disruption_paths(
                workload,
                sink,
                resources,
                context,
            ),
            paths,
        )

        revoked = [resource for resource in resources if resource.resource_type != GcpResourceType.PROJECT_IAM_POLICY]
        revoked_context = GcpDecorationContext(GcpResourceIndexBuilder().build(revoked))
        self.assertEqual(
            current_cloud_run_logging_sink_audit_telemetry_disruption_paths(
                workload,
                sink,
                revoked,
                revoked_context,
            ),
            [],
        )

        disabled_inventory, disabled_workload, disabled_sink, _disabled_facts = _normalize(
            _cloud_run(),
            _sink(disabled=True),
            _project_member(role="roles/logging.admin"),
        )
        disabled_resources = list(disabled_inventory.resources)
        disabled_context = GcpDecorationContext(GcpResourceIndexBuilder().build(disabled_resources))
        self.assertEqual(
            current_cloud_run_logging_sink_audit_telemetry_disruption_paths(
                disabled_workload,
                disabled_sink,
                disabled_resources,
                disabled_context,
            ),
            [],
        )


if __name__ == "__main__":
    unittest.main()
