from __future__ import annotations

import unittest

from tests.providers.gcp.normalizer_support import _terraform_resource
from tfstride.models import ResourceCategory
from tfstride.providers.gcp.audit_normalizers import (
    normalize_logging_organization_exclusion,
    normalize_logging_organization_sink,
    normalize_logging_project_exclusion,
    normalize_logging_project_sink,
    normalize_scc_organization_settings,
)
from tfstride.providers.gcp.normalizer import SUPPORTED_GCP_TYPES, GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_types import GcpResourceType


class GcpAuditNormalizerTests(unittest.TestCase):
    def test_logging_project_sink_preserves_audit_export_evidence(self) -> None:
        normalized = normalize_logging_project_sink(
            _terraform_resource(
                "google_logging_project_sink.processor",
                GcpResourceType.LOGGING_PROJECT_SINK,
                {
                    "id": "projects/tfstride-demo/sinks/processor-logs",
                    "name": "processor-logs",
                    "project": "tfstride-demo",
                    "destination": "storage.googleapis.com/tfstride-logs",
                    "filter": "severity>=ERROR",
                    "writer_identity": "serviceAccount:cloud-logs@example.iam.gserviceaccount.com",
                    "include_children": False,
                    "unique_writer_identity": True,
                },
            )
        )

        facts = gcp_facts(normalized)

        self.assertEqual(normalized.category, ResourceCategory.IAM)
        self.assertEqual(normalized.identifier, "projects/tfstride-demo/sinks/processor-logs")
        self.assertEqual(facts.logging_sink_name, "processor-logs")
        self.assertEqual(facts.logging_sink_destination, "storage.googleapis.com/tfstride-logs")
        self.assertEqual(facts.logging_sink_filter, "severity>=ERROR")
        self.assertEqual(
            facts.logging_sink_writer_identity, "serviceAccount:cloud-logs@example.iam.gserviceaccount.com"
        )
        self.assertEqual(facts.logging_sink_scope_type, "project")
        self.assertEqual(facts.logging_sink_scope, "tfstride-demo")
        self.assertFalse(facts.logging_sink_include_children)
        self.assertTrue(facts.logging_sink_unique_writer_identity)
        self.assertEqual(facts.audit_security_posture_uncertainties, [])

    def test_logging_organization_sink_preserves_scope_evidence(self) -> None:
        normalized = normalize_logging_organization_sink(
            _terraform_resource(
                "google_logging_organization_sink.audit",
                GcpResourceType.LOGGING_ORGANIZATION_SINK,
                {
                    "name": "org-audit",
                    "org_id": "1234567890",
                    "destination": "pubsub.googleapis.com/projects/audit/topics/org-logs",
                    "include_children": True,
                },
            )
        )

        facts = gcp_facts(normalized)

        self.assertEqual(facts.organization_id, "1234567890")
        self.assertEqual(facts.logging_sink_scope_type, "organization")
        self.assertEqual(facts.logging_sink_scope, "1234567890")
        self.assertTrue(facts.logging_sink_include_children)
        self.assertIsNone(facts.logging_sink_unique_writer_identity)

    def test_logging_exclusions_preserve_filter_and_disabled_state(self) -> None:
        project_exclusion = normalize_logging_project_exclusion(
            _terraform_resource(
                "google_logging_project_exclusion.debug",
                GcpResourceType.LOGGING_PROJECT_EXCLUSION,
                {
                    "name": "drop-debug",
                    "project": "tfstride-demo",
                    "description": "Drop debug logs",
                    "filter": "severity=DEBUG",
                    "disabled": True,
                },
            )
        )
        organization_exclusion = normalize_logging_organization_exclusion(
            _terraform_resource(
                "google_logging_organization_exclusion.noisy",
                GcpResourceType.LOGGING_ORGANIZATION_EXCLUSION,
                {
                    "name": "drop-noisy",
                    "org_id": "1234567890",
                    "filter": "resource.type=gce_instance",
                    "disabled": False,
                },
            )
        )

        project_facts = gcp_facts(project_exclusion)
        organization_facts = gcp_facts(organization_exclusion)

        self.assertEqual(project_facts.logging_exclusion_name, "drop-debug")
        self.assertEqual(project_facts.logging_exclusion_description, "Drop debug logs")
        self.assertEqual(project_facts.logging_exclusion_filter, "severity=DEBUG")
        self.assertEqual(project_facts.logging_exclusion_scope_type, "project")
        self.assertEqual(project_facts.logging_exclusion_scope, "tfstride-demo")
        self.assertTrue(project_facts.logging_exclusion_disabled)
        self.assertEqual(organization_facts.logging_exclusion_scope_type, "organization")
        self.assertEqual(organization_facts.logging_exclusion_scope, "1234567890")
        self.assertFalse(organization_facts.logging_exclusion_disabled)

    def test_scc_organization_settings_preserve_asset_discovery_posture(self) -> None:
        normalized = normalize_scc_organization_settings(
            _terraform_resource(
                "google_scc_organization_settings.main",
                GcpResourceType.SCC_ORGANIZATION_SETTINGS,
                {
                    "organization": "1234567890",
                    "enable_asset_discovery": True,
                    "asset_discovery_config": [
                        {
                            "inclusion_mode": "INCLUDE_ONLY",
                            "project_ids": ["tfstride-prod"],
                            "folder_ids": ["folders/123"],
                        }
                    ],
                },
            )
        )

        facts = gcp_facts(normalized)

        self.assertEqual(normalized.category, ResourceCategory.IAM)
        self.assertEqual(facts.scc_organization, "1234567890")
        self.assertTrue(facts.scc_enable_asset_discovery)
        self.assertEqual(facts.scc_asset_discovery_state, "enabled")
        self.assertEqual(facts.scc_asset_discovery_inclusion_mode, "INCLUDE_ONLY")
        self.assertEqual(facts.scc_asset_discovery_project_ids, ["tfstride-prod"])
        self.assertEqual(facts.scc_asset_discovery_folder_ids, ["folders/123"])
        self.assertEqual(
            facts.scc_asset_discovery_config,
            {
                "inclusion_mode": "INCLUDE_ONLY",
                "project_ids": ["tfstride-prod"],
                "folder_ids": ["folders/123"],
            },
        )
        self.assertEqual(facts.audit_security_posture_uncertainties, [])

    def test_unknown_audit_and_scc_fields_are_preserved_as_uncertainty(self) -> None:
        sink = normalize_logging_project_sink(
            _terraform_resource(
                "google_logging_project_sink.processor",
                GcpResourceType.LOGGING_PROJECT_SINK,
                {"name": "processor-logs", "project": "tfstride-demo"},
                unknown_values={
                    "destination": True,
                    "writer_identity": True,
                    "include_children": True,
                },
            )
        )
        scc = normalize_scc_organization_settings(
            _terraform_resource(
                "google_scc_organization_settings.main",
                GcpResourceType.SCC_ORGANIZATION_SETTINGS,
                {"organization": "1234567890", "asset_discovery_config": [{}]},
                unknown_values={
                    "enable_asset_discovery": True,
                    "asset_discovery_config": [{"inclusion_mode": True, "project_ids": True}],
                },
            )
        )

        self.assertEqual(
            gcp_facts(sink).audit_security_posture_uncertainties,
            [
                "destination is unknown after planning",
                "writer_identity is unknown after planning",
                "include_children is unknown after planning",
            ],
        )
        self.assertEqual(gcp_facts(scc).scc_asset_discovery_state, "unknown")
        self.assertEqual(
            gcp_facts(scc).audit_security_posture_uncertainties,
            [
                "enable_asset_discovery is unknown after planning",
                "asset_discovery_config.inclusion_mode is unknown after planning",
                "asset_discovery_config.project_ids is unknown after planning",
            ],
        )

    def test_audit_security_resource_types_are_supported_by_gcp_normalizer(self) -> None:
        resource_types = {
            GcpResourceType.LOGGING_ORGANIZATION_EXCLUSION,
            GcpResourceType.LOGGING_ORGANIZATION_SINK,
            GcpResourceType.LOGGING_PROJECT_EXCLUSION,
            GcpResourceType.LOGGING_PROJECT_SINK,
            GcpResourceType.SCC_ORGANIZATION_SETTINGS,
        }
        resources = [
            _terraform_resource(f"{resource_type}.sample", resource_type, {"name": "sample"})
            for resource_type in sorted(resource_types)
        ]

        inventory = GcpNormalizer().normalize(resources)

        self.assertLessEqual(resource_types, SUPPORTED_GCP_TYPES)
        self.assertEqual(inventory.unsupported_resources, [])
        self.assertEqual({resource.resource_type for resource in inventory.resources}, resource_types)


if __name__ == "__main__":
    unittest.main()
