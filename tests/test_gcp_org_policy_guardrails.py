from __future__ import annotations

import unittest

from tfstride.analysis.gcp.org_policy_guardrails import (
    GCP_ORG_POLICY_SCOPE_FOLDER,
    GCP_ORG_POLICY_SCOPE_ORGANIZATION,
    GCP_ORG_POLICY_SCOPE_PROJECT,
    ORG_POLICY_STORAGE_PUBLIC_ACCESS_PREVENTION,
    GcpOrgPolicyScopeKey,
)
from tfstride.analysis.gcp.org_policy_evidence import organization_guardrail_evidence
from tfstride.analysis.gcp.org_policy_severity import guardrail_adjusted_severity_reasoning
from tfstride.analysis.indexes import build_analysis_indexes
from tfstride.models import NormalizedResource, ResourceCategory, ResourceInventory
from tfstride.providers.gcp.metadata import GcpResourceMetadata


def _gcp_resource(
    address: str,
    resource_type: str,
    category: ResourceCategory,
    *,
    identifier: str | None = None,
    metadata: dict[str, object] | None = None,
) -> NormalizedResource:
    return NormalizedResource(
        address=address,
        provider="gcp",
        resource_type=resource_type,
        name=address.rsplit(".", 1)[-1],
        category=category,
        identifier=identifier,
        metadata=metadata,
    )


def _org_policy(
    address: str,
    *,
    constraint: str,
    scope_type: str,
    scope: str,
    enforced: bool | None = None,
    inherit_from_parent: bool | None = None,
    restore_default: bool | None = None,
    allowed_values: list[str] | None = None,
    denied_values: list[str] | None = None,
    rules: list[dict[str, object]] | None = None,
    resource_type: str = "google_org_policy_policy",
) -> NormalizedResource:
    metadata: dict[str, object] = {
        GcpResourceMetadata.ORG_POLICY_CONSTRAINT.key: constraint,
        GcpResourceMetadata.ORG_POLICY_SCOPE_TYPE.key: scope_type,
        GcpResourceMetadata.ORG_POLICY_SCOPE.key: scope,
        GcpResourceMetadata.ORG_POLICY_RULES.key: rules or [],
        GcpResourceMetadata.ORG_POLICY_ALLOWED_VALUES.key: allowed_values or [],
        GcpResourceMetadata.ORG_POLICY_DENIED_VALUES.key: denied_values or [],
    }
    if scope_type == GCP_ORG_POLICY_SCOPE_PROJECT:
        metadata[GcpResourceMetadata.PROJECT.key] = scope
    elif scope_type == GCP_ORG_POLICY_SCOPE_FOLDER:
        metadata[GcpResourceMetadata.FOLDER_ID.key] = scope
    elif scope_type == GCP_ORG_POLICY_SCOPE_ORGANIZATION:
        metadata[GcpResourceMetadata.ORGANIZATION_ID.key] = scope
    if enforced is not None:
        metadata[GcpResourceMetadata.ORG_POLICY_ENFORCED.key] = enforced
    if inherit_from_parent is not None:
        metadata[GcpResourceMetadata.ORG_POLICY_INHERIT_FROM_PARENT.key] = inherit_from_parent
    if restore_default is not None:
        metadata[GcpResourceMetadata.ORG_POLICY_RESTORE_DEFAULT.key] = restore_default
    return _gcp_resource(
        address,
        resource_type,
        ResourceCategory.IAM,
        metadata=metadata,
    )


def _guardrail_index(resources: list[NormalizedResource]):
    return build_analysis_indexes(ResourceInventory(provider="gcp", resources=resources)).gcp_org_policy_guardrails


class GcpOrgPolicyGuardrailIndexTests(unittest.TestCase):
    def test_indexes_direct_guardrails_by_scope_and_constraint(self) -> None:
        guardrail = _org_policy(
            "google_org_policy_policy.storage_pap",
            constraint="constraints/storage.publicAccessPrevention",
            scope_type=GCP_ORG_POLICY_SCOPE_PROJECT,
            scope="projects/tfstride-demo",
            enforced=True,
            rules=[{"enforced": True}],
        )

        index = _guardrail_index([guardrail])
        scope = GcpOrgPolicyScopeKey(GCP_ORG_POLICY_SCOPE_PROJECT, "tfstride-demo")
        indexed = index.direct_guardrails_for_constraint(
            scope,
            "constraints/storage.publicAccessPrevention",
        )

        self.assertEqual(indexed, index.direct_guardrails_for_scope(scope))
        self.assertEqual(indexed[0].resource, guardrail)
        self.assertEqual(indexed[0].constraint, "constraints/storage.publicAccessPrevention")
        self.assertTrue(indexed[0].enforced)
        self.assertEqual(indexed[0].rules, ({"enforced": True},))

    def test_effective_guardrails_walk_org_folder_project_chain(self) -> None:
        organization_guardrail = _org_policy(
            "google_org_policy_policy.allowed_domains",
            constraint="constraints/iam.allowedPolicyMemberDomains",
            scope_type=GCP_ORG_POLICY_SCOPE_ORGANIZATION,
            scope="organizations/123",
            allowed_values=["C01abcd"],
        )
        folder_guardrail = _org_policy(
            "google_org_policy_policy.disable_keys",
            constraint="constraints/iam.disableServiceAccountKeyCreation",
            scope_type=GCP_ORG_POLICY_SCOPE_FOLDER,
            scope="folders/456",
            enforced=True,
        )
        project_guardrail = _org_policy(
            "google_org_policy_policy.public_ip",
            constraint="constraints/compute.vmExternalIpAccess",
            scope_type=GCP_ORG_POLICY_SCOPE_PROJECT,
            scope="projects/tfstride-demo",
            denied_values=["*"],
        )
        instance = _gcp_resource(
            "google_compute_instance.app",
            "google_compute_instance",
            ResourceCategory.COMPUTE,
            metadata={
                GcpResourceMetadata.PROJECT.key: "tfstride-demo",
                GcpResourceMetadata.FOLDER_ID.key: "folders/456",
                GcpResourceMetadata.ORGANIZATION_ID.key: "organizations/123",
            },
        )

        index = _guardrail_index([organization_guardrail, folder_guardrail, project_guardrail, instance])
        effective = index.effective_guardrails_for_resource(instance)

        self.assertEqual(
            [guardrail.resource.address for guardrail in effective],
            [
                "google_org_policy_policy.allowed_domains",
                "google_org_policy_policy.disable_keys",
                "google_org_policy_policy.public_ip",
            ],
        )
        self.assertEqual(
            index.effective_guardrails_for_resource(
                instance,
                constraint="constraints/iam.disableServiceAccountKeyCreation",
            ),
            (effective[1],),
        )


    def test_guardrail_adjusted_severity_reduces_active_enforced_guardrails(self) -> None:
        guardrail = _org_policy(
            "google_org_policy_policy.storage_pap",
            constraint=ORG_POLICY_STORAGE_PUBLIC_ACCESS_PREVENTION,
            scope_type=GCP_ORG_POLICY_SCOPE_PROJECT,
            scope="projects/tfstride-demo",
            enforced=True,
        )
        bucket = _gcp_resource(
            "google_storage_bucket.logs",
            "google_storage_bucket",
            ResourceCategory.DATA,
            metadata={GcpResourceMetadata.PROJECT.key: "tfstride-demo"},
        )

        reasoning = guardrail_adjusted_severity_reasoning(
            _guardrail_index([guardrail, bucket]),
            bucket,
            constraints=(ORG_POLICY_STORAGE_PUBLIC_ACCESS_PREVENTION,),
            internet_exposure=True,
            privilege_breadth=0,
            data_sensitivity=2,
            lateral_movement=0,
            blast_radius=1,
        )

        self.assertEqual(reasoning.internet_exposure, 0)
        self.assertEqual(reasoning.blast_radius, 0)
        self.assertEqual(reasoning.final_score, 2)
        self.assertEqual(reasoning.severity.value, "low")

    def test_guardrail_adjusted_severity_ignores_restore_default_guardrails(self) -> None:
        guardrail = _org_policy(
            "google_org_policy_policy.storage_pap",
            constraint=ORG_POLICY_STORAGE_PUBLIC_ACCESS_PREVENTION,
            scope_type=GCP_ORG_POLICY_SCOPE_PROJECT,
            scope="projects/tfstride-demo",
            restore_default=True,
        )
        bucket = _gcp_resource(
            "google_storage_bucket.logs",
            "google_storage_bucket",
            ResourceCategory.DATA,
            metadata={GcpResourceMetadata.PROJECT.key: "tfstride-demo"},
        )

        reasoning = guardrail_adjusted_severity_reasoning(
            _guardrail_index([guardrail, bucket]),
            bucket,
            constraints=(ORG_POLICY_STORAGE_PUBLIC_ACCESS_PREVENTION,),
            internet_exposure=True,
            privilege_breadth=0,
            data_sensitivity=2,
            lateral_movement=0,
            blast_radius=1,
        )

        self.assertEqual(reasoning.internet_exposure, 2)
        self.assertEqual(reasoning.blast_radius, 1)
        self.assertEqual(reasoning.final_score, 5)
        self.assertEqual(reasoning.severity.value, "medium")

    def test_organization_guardrail_evidence_formats_effective_guardrails(self) -> None:
        guardrail = _org_policy(
            "google_org_policy_policy.allowed_domains",
            constraint="constraints/iam.allowedPolicyMemberDomains",
            scope_type=GCP_ORG_POLICY_SCOPE_PROJECT,
            scope="projects/tfstride-demo",
            allowed_values=["C01abcd"],
        )
        binding = _gcp_resource(
            "google_project_iam_member.public",
            "google_project_iam_member",
            ResourceCategory.IAM,
            metadata={GcpResourceMetadata.PROJECT.key: "tfstride-demo"},
        )

        evidence = organization_guardrail_evidence(
            _guardrail_index([guardrail, binding]),
            binding,
            "constraints/iam.allowedPolicyMemberDomains",
        )

        self.assertIsNotNone(evidence)
        assert evidence is not None
        self.assertEqual(evidence.key, "organization_guardrails")
        self.assertEqual(
            evidence.values,
            [
                "constraint=constraints/iam.allowedPolicyMemberDomains; "
                "scope=project:tfstride-demo; "
                "source=google_org_policy_policy.allowed_domains; "
                "allowed_values=C01abcd"
            ],
        )

    def test_child_policy_replaces_parent_when_inheritance_disabled(self) -> None:
        parent_guardrail = _org_policy(
            "google_org_policy_policy.org_domains",
            constraint="constraints/iam.allowedPolicyMemberDomains",
            scope_type=GCP_ORG_POLICY_SCOPE_ORGANIZATION,
            scope="organizations/123",
            allowed_values=["C01abcd"],
        )
        child_guardrail = _org_policy(
            "google_org_policy_policy.project_domains",
            constraint="constraints/iam.allowedPolicyMemberDomains",
            scope_type=GCP_ORG_POLICY_SCOPE_PROJECT,
            scope="projects/tfstride-demo",
            inherit_from_parent=False,
            allowed_values=["C02wxyz"],
        )
        bucket = _gcp_resource(
            "google_storage_bucket.logs",
            "google_storage_bucket",
            ResourceCategory.DATA,
            metadata={
                GcpResourceMetadata.PROJECT.key: "projects/tfstride-demo",
                GcpResourceMetadata.ORGANIZATION_ID.key: "123",
            },
        )

        index = _guardrail_index([parent_guardrail, child_guardrail, bucket])

        self.assertEqual(
            index.effective_guardrails_for_resource(
                bucket,
                constraint="constraints/iam.allowedPolicyMemberDomains",
            ),
            (
                index.direct_guardrails_for_scope(
                    GcpOrgPolicyScopeKey(GCP_ORG_POLICY_SCOPE_PROJECT, "tfstride-demo")
                )[0],
            ),
        )

    def test_restore_default_policy_resets_parent_guardrail_chain(self) -> None:
        parent_guardrail = _org_policy(
            "google_org_policy_policy.org_os_login",
            constraint="constraints/compute.requireOsLogin",
            scope_type=GCP_ORG_POLICY_SCOPE_ORGANIZATION,
            scope="organizations/123",
            enforced=True,
        )
        restore_guardrail = _org_policy(
            "google_org_policy_policy.project_os_login",
            constraint="constraints/compute.requireOsLogin",
            scope_type=GCP_ORG_POLICY_SCOPE_PROJECT,
            scope="projects/tfstride-demo",
            restore_default=True,
        )
        instance = _gcp_resource(
            "google_compute_instance.app",
            "google_compute_instance",
            ResourceCategory.COMPUTE,
            metadata={
                GcpResourceMetadata.PROJECT.key: "tfstride-demo",
                GcpResourceMetadata.ORGANIZATION_ID.key: "organizations/123",
            },
        )

        index = _guardrail_index([parent_guardrail, restore_guardrail, instance])
        effective = index.effective_guardrails_for_resource(
            instance,
            constraint="constraints/compute.requireOsLogin",
        )

        self.assertEqual([guardrail.resource.address for guardrail in effective], [restore_guardrail.address])
        self.assertTrue(effective[0].restore_default)

    def test_legacy_organization_policy_resource_types_are_indexed(self) -> None:
        project_policy = _org_policy(
            "google_project_organization_policy.public_ip",
            constraint="constraints/compute.vmExternalIpAccess",
            scope_type=GCP_ORG_POLICY_SCOPE_PROJECT,
            scope="tfstride-demo",
            denied_values=["*"],
            resource_type="google_project_organization_policy",
        )

        index = _guardrail_index([project_policy])

        self.assertEqual(
            index.direct_guardrails_for_scope(
                GcpOrgPolicyScopeKey(GCP_ORG_POLICY_SCOPE_PROJECT, "tfstride-demo")
            )[0].resource,
            project_policy,
        )

    def test_unresolved_policy_resources_track_missing_constraint_or_scope(self) -> None:
        missing_constraint = _gcp_resource(
            "google_org_policy_policy.missing_constraint",
            "google_org_policy_policy",
            ResourceCategory.IAM,
            metadata={
                GcpResourceMetadata.ORG_POLICY_SCOPE_TYPE.key: GCP_ORG_POLICY_SCOPE_PROJECT,
                GcpResourceMetadata.ORG_POLICY_SCOPE.key: "projects/tfstride-demo",
            },
        )
        missing_scope = _gcp_resource(
            "google_org_policy_policy.missing_scope",
            "google_org_policy_policy",
            ResourceCategory.IAM,
            metadata={
                GcpResourceMetadata.ORG_POLICY_CONSTRAINT.key: "constraints/storage.publicAccessPrevention",
            },
        )

        index = _guardrail_index([missing_constraint, missing_scope])

        self.assertEqual(index.unresolved_policy_resources, (missing_constraint, missing_scope))

    def test_non_gcp_inventory_uses_empty_guardrail_index(self) -> None:
        aws_resource = NormalizedResource(
            address="aws_instance.web",
            provider="aws",
            resource_type="aws_instance",
            name="web",
            category=ResourceCategory.COMPUTE,
        )

        index = build_analysis_indexes(
            ResourceInventory(provider="aws", resources=[aws_resource])
        ).gcp_org_policy_guardrails

        self.assertEqual(index.guardrails_by_scope, {})
        self.assertEqual(index.unresolved_policy_resources, ())


if __name__ == "__main__":
    unittest.main()