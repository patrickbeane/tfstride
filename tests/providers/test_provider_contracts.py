from __future__ import annotations

import re
import unittest
from dataclasses import fields
from pathlib import Path

from tests.helpers.paths import SOURCE_ROOT
from tfstride.models import NormalizedResource
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.contracts import (
    DEFAULT_PROVIDER_ENCAPSULATION_CONTRACT,
    DEFAULT_RESOURCE_METADATA_OWNERSHIP_CONTRACT,
)
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.resource_metadata import MetadataField, ResourceMetadata

_NORMALIZED_RESOURCE_WRITE_PATTERNS = (
    re.compile(r"\.\s*(?:set_metadata_field|append_metadata_field|extend_metadata_field)\("),
    re.compile(r"\.\s*(?:extend_network_rules|extend_policy_statements|add_attached_role_arn)\("),
    re.compile(
        r"\.\s*(?:"
        r"vpc_id|"
        r"direct_internet_reachable|"
        r"internet_ingress_capable|"
        r"internet_ingress_reasons|"
        r"in_public_subnet|"
        r"is_public_subnet|"
        r"has_public_route|"
        r"has_nat_gateway_egress|"
        r"public_access_configured|"
        r"public_access_reasons|"
        r"public_exposure|"
        r"public_exposure_reasons"
        r")\s*(?<![=!<>])=(?!=)"
    ),
)
_NORMALIZED_RESOURCE_WRITE_FACADES = frozenset(
    {
        "providers/aws/resource_facts.py",
        "providers/aws/resource_mutations.py",
        "providers/gcp/resource_facts.py",
        "providers/gcp/resource_mutations.py",
    }
)
_NORMALIZED_RESOURCE_DIRECT_WRITE_EXCEPTIONS = frozenset()

_PROVIDER_NORMALIZER_RAW_SHARED_POSTURE_KEYS = frozenset(
    {
        "direct_internet_reachable",
        "internet_ingress_capable",
        "publicly_accessible",
        "storage_encrypted",
        "public_access_reasons",
        "public_exposure_reasons",
    }
)
_GCP_NETWORK_NORMALIZER_RAW_POSTURE_KEYS = frozenset(
    {
        "direction",
        "disabled",
        "enable_logging",
        "priority",
    }
)
_GCP_DATA_NORMALIZER_RAW_POSTURE_KEYS = frozenset({"customer_managed_encryption"})
_PROVIDER_STORAGE_SQL_METADATA_FIELDS = (
    AwsResourceMetadata.BUCKET_NAME,
    AwsResourceMetadata.BUCKET_ACL,
    AwsResourceMetadata.ENGINE,
    AwsResourceMetadata.PUBLIC_ACCESS_BLOCK,
    GcpResourceMetadata.BUCKET_NAME,
    GcpResourceMetadata.DATABASE_VERSION,
)
_PROVIDER_IAM_POLICY_METADATA_FIELDS = (
    AwsResourceMetadata.POLICY_DOCUMENT,
    AwsResourceMetadata.TRUST_STATEMENTS,
    AwsResourceMetadata.RESOURCE_POLICY_SOURCE_ADDRESSES,
    GcpResourceMetadata.POLICY_DOCUMENT,
    GcpResourceMetadata.RESOURCE_POLICY_SOURCE_ADDRESSES,
)
_GCP_PROMOTED_RULE_FACING_METADATA_FIELDS = (
    GcpResourceMetadata.PUBLIC_ACCESS_PREVENTION,
    GcpResourceMetadata.UNIFORM_BUCKET_LEVEL_ACCESS,
    GcpResourceMetadata.GCS_VERSIONING_ENABLED,
    GcpResourceMetadata.GCS_DEFAULT_KMS_KEY_NAME,
    GcpResourceMetadata.CUSTOMER_MANAGED_ENCRYPTION,
    GcpResourceMetadata.CLOUD_SQL_IPV4_ENABLED,
    GcpResourceMetadata.CLOUD_SQL_BACKUP_ENABLED,
    GcpResourceMetadata.CLOUD_SQL_POINT_IN_TIME_RECOVERY_ENABLED,
    GcpResourceMetadata.CLOUD_SQL_REQUIRE_SSL,
    GcpResourceMetadata.CLOUD_SQL_SSL_MODE,
    GcpResourceMetadata.CLOUD_SQL_AUTHORIZED_NETWORKS,
    GcpResourceMetadata.OS_LOGIN_ENABLED,
    GcpResourceMetadata.SERVERLESS_INGRESS,
    GcpResourceMetadata.ROUTE_PRIORITY,
    GcpResourceMetadata.FIREWALL_DIRECTION,
    GcpResourceMetadata.FIREWALL_PRIORITY,
    GcpResourceMetadata.FIREWALL_DISABLED,
    GcpResourceMetadata.FIREWALL_POLICY_DIRECTION,
    GcpResourceMetadata.FIREWALL_POLICY_PRIORITY,
    GcpResourceMetadata.FIREWALL_POLICY_DISABLED,
    GcpResourceMetadata.FIREWALL_POLICY_ENABLE_LOGGING,
    GcpResourceMetadata.INTERNET_INGRESS_FIREWALLS,
    GcpResourceMetadata.GKE_ENDPOINT,
    GcpResourceMetadata.GKE_PRIVATE_ENDPOINT_ENABLED,
    GcpResourceMetadata.GKE_PRIVATE_NODES_ENABLED,
    GcpResourceMetadata.GKE_MASTER_AUTHORIZED_NETWORKS,
    GcpResourceMetadata.GKE_WORKLOAD_IDENTITY_ENABLED,
    GcpResourceMetadata.GKE_NODE_SERVICE_ACCOUNT,
    GcpResourceMetadata.GKE_NODE_OAUTH_SCOPES,
    GcpResourceMetadata.GKE_NODE_METADATA_MODE,
    GcpResourceMetadata.GKE_LEGACY_METADATA_ENDPOINTS_ENABLED,
    GcpResourceMetadata.FRONTED_BY_INTERNET_FACING_LOAD_BALANCER,
    GcpResourceMetadata.INTERNET_FACING_LOAD_BALANCER_ADDRESSES,
    GcpResourceMetadata.LOAD_BALANCER_FRONTENDS,
    GcpResourceMetadata.LOAD_BALANCER_REACHABLE_BACKENDS,
)
_RULE_FACING_METADATA_RAW_KEYS = (
    _PROVIDER_NORMALIZER_RAW_SHARED_POSTURE_KEYS
    | _GCP_NETWORK_NORMALIZER_RAW_POSTURE_KEYS
    | _GCP_DATA_NORMALIZER_RAW_POSTURE_KEYS
    | frozenset(field.key for field in _PROVIDER_STORAGE_SQL_METADATA_FIELDS)
    | frozenset(field.key for field in _PROVIDER_IAM_POLICY_METADATA_FIELDS)
    | frozenset(field.key for field in _GCP_PROMOTED_RULE_FACING_METADATA_FIELDS)
)
_RULE_FACING_METADATA_RAW_STRING_EXCLUDED_FILES = frozenset(
    {
        "providers/contracts.py",
        "providers/aws/metadata.py",
        "providers/gcp/metadata.py",
    }
)
_RULE_FACING_METADATA_RAW_KEY_PATTERN = "|".join(
    re.escape(key) for key in sorted(_RULE_FACING_METADATA_RAW_KEYS, key=len, reverse=True)
)
_RULE_FACING_METADATA_RAW_READ_PATTERNS = (
    re.compile(
        rf'(?:^|\W)(?:\w+\.)?metadata(?:_snapshot\(\))?\.get\(\s*["\']'
        rf'(?:{_RULE_FACING_METADATA_RAW_KEY_PATTERN})["\']'
    ),
    re.compile(
        rf'(?:^|\W)(?:\w+\.)?metadata(?:_snapshot\(\))?\s*\[\s*["\']'
        rf'(?:{_RULE_FACING_METADATA_RAW_KEY_PATTERN})["\']'
    ),
    re.compile(
        rf'\.(?:get|set|append|extend)_metadata_field\(\s*["\']'
        rf'(?:{_RULE_FACING_METADATA_RAW_KEY_PATTERN})["\']'
    ),
)
_RULE_FACING_METADATA_RAW_WRITE_PATTERN = re.compile(rf'["\'](?:{_RULE_FACING_METADATA_RAW_KEY_PATTERN})["\']\s*:')


def _metadata_field_names(namespace: type) -> set[str]:
    return {name for name, value in vars(namespace).items() if isinstance(value, MetadataField)}


def _resource_metadata_field_names() -> set[str]:
    return _metadata_field_names(ResourceMetadata)


def _uses_rule_facing_metadata_key_as_raw_string(path: Path, line: str) -> bool:
    return _reads_rule_facing_metadata_key_as_raw_string(line) or _writes_rule_facing_metadata_key_as_raw_string(
        path,
        line,
    )


def _reads_rule_facing_metadata_key_as_raw_string(line: str) -> bool:
    return any(pattern.search(line) for pattern in _RULE_FACING_METADATA_RAW_READ_PATTERNS)


def _writes_rule_facing_metadata_key_as_raw_string(path: Path, line: str) -> bool:
    if not path.relative_to(SOURCE_ROOT).as_posix().startswith("providers/"):
        return False
    return bool(_RULE_FACING_METADATA_RAW_WRITE_PATTERN.search(line))


class ProviderEncapsulationContractTests(unittest.TestCase):
    def test_normalized_resource_fields_match_provider_contract(self) -> None:
        actual_fields = {field.name for field in fields(NormalizedResource) if not field.name.startswith("_")}

        self.assertEqual(
            actual_fields,
            DEFAULT_PROVIDER_ENCAPSULATION_CONTRACT.provider_neutral_resource_fields,
        )

    def test_normalized_resource_accessors_are_classified_by_provider_contract(self) -> None:
        actual_accessors = {name for name, value in vars(NormalizedResource).items() if isinstance(value, property)}
        provider_neutral = DEFAULT_PROVIDER_ENCAPSULATION_CONTRACT.provider_neutral_resource_accessors
        legacy_provider_owned = DEFAULT_PROVIDER_ENCAPSULATION_CONTRACT.legacy_provider_metadata_accessors
        classified_accessors = provider_neutral | legacy_provider_owned

        self.assertFalse(provider_neutral & legacy_provider_owned)
        self.assertEqual(legacy_provider_owned, frozenset())
        self.assertEqual(actual_accessors - classified_accessors, set())
        self.assertEqual(provider_neutral - actual_accessors, set())
        self.assertEqual(legacy_provider_owned - actual_accessors, set())

    def test_resource_metadata_fields_are_limited_to_shared_core_fields(self) -> None:
        contract = DEFAULT_RESOURCE_METADATA_OWNERSHIP_CONTRACT
        provider_owned = frozenset().union(*contract.provider_owned_fields.values())
        actual_fields = _resource_metadata_field_names()

        self.assertEqual(actual_fields, contract.shared_core_fields)
        self.assertFalse(actual_fields & provider_owned)
        self.assertFalse(contract.shared_core_fields & provider_owned)

    def test_provider_metadata_namespaces_match_ownership_contract(self) -> None:
        contract = DEFAULT_RESOURCE_METADATA_OWNERSHIP_CONTRACT
        shared_core = contract.shared_core_fields
        provider_namespaces = {
            "aws": AwsResourceMetadata,
            "gcp": GcpResourceMetadata,
            "azure": AzureResourceMetadata,
        }

        for provider, namespace in provider_namespaces.items():
            with self.subTest(provider=provider):
                metadata_fields = _metadata_field_names(namespace)
                provider_owned = contract.provider_owned_fields[provider]

                self.assertEqual(metadata_fields - shared_core, provider_owned)
                self.assertFalse(provider_owned & shared_core)
                self.assertEqual(provider_owned - metadata_fields, set())

    def test_resource_metadata_ownership_contract_marks_known_boundaries(self) -> None:
        contract = DEFAULT_RESOURCE_METADATA_OWNERSHIP_CONTRACT
        aws_owned = contract.provider_owned_fields["aws"]
        gcp_owned = contract.provider_owned_fields["gcp"]
        azure_owned = contract.provider_owned_fields["azure"]

        self.assertEqual(azure_owned, frozenset())
        self.assertIn("DIRECT_INTERNET_REACHABLE", contract.shared_core_fields)
        self.assertIn("SECURITY_GROUP_ID", aws_owned)
        self.assertIn("TASK_ROLE_ARN", aws_owned)
        self.assertIn("SERVICE_ACCOUNT_EMAIL", gcp_owned)
        self.assertIn("KMS_CRYPTO_KEY_REFERENCE", gcp_owned)
        self.assertIn("GKE_NODE_OAUTH_SCOPES", gcp_owned)
        self.assertIn("FIREWALL_DIRECTION", gcp_owned)
        self.assertIn("FIREWALL_POLICY_ENABLE_LOGGING", gcp_owned)
        self.assertIn("CUSTOMER_MANAGED_ENCRYPTION", gcp_owned)
        self.assertIn("BUCKET_NAME", aws_owned)
        self.assertIn("BUCKET_ACL", aws_owned)
        self.assertIn("ENGINE", aws_owned)
        self.assertIn("PUBLIC_ACCESS_BLOCK", aws_owned)
        self.assertIn("POLICY_DOCUMENT", aws_owned)
        self.assertIn("TRUST_STATEMENTS", aws_owned)
        self.assertIn("RESOURCE_POLICY_SOURCE_ADDRESSES", aws_owned)
        self.assertIn("BUCKET_NAME", gcp_owned)
        self.assertIn("POLICY_DOCUMENT", gcp_owned)
        self.assertIn("RESOURCE_POLICY_SOURCE_ADDRESSES", gcp_owned)
        self.assertNotIn("SECURITY_GROUP_ID", contract.shared_core_fields)
        self.assertNotIn("SERVICE_ACCOUNT_EMAIL", contract.shared_core_fields)

    def test_resource_metadata_ownership_contract_documents_migration_rules(self) -> None:
        guidelines = DEFAULT_RESOURCE_METADATA_OWNERSHIP_CONTRACT.guidelines

        self.assertTrue(any("Provider-owned metadata" in item for item in guidelines))
        self.assertTrue(any("provider facts" in item for item in guidelines))

    def test_shared_boundary_core_does_not_import_provider_packages(self) -> None:
        forbidden_imports = (
            "tfstride.analysis.gcp",
            "tfstride.providers.aws",
            "tfstride.providers.gcp",
            "tfstride.providers.azure",
            "tfstride.providers.catalog",
        )
        scanned_paths = (
            SOURCE_ROOT / "analysis" / "boundaries" / "core.py",
            SOURCE_ROOT / "analysis" / "boundaries" / "shared.py",
            SOURCE_ROOT / "analysis" / "boundaries" / "types.py",
        )

        violations = {
            path.relative_to(SOURCE_ROOT).as_posix(): forbidden
            for path in scanned_paths
            for forbidden in forbidden_imports
            if forbidden in path.read_text(encoding="utf-8")
        }

        self.assertEqual(violations, {})

    def test_provider_boundary_contributors_are_plugin_owned(self) -> None:
        aws_plugin = (SOURCE_ROOT / "providers" / "aws" / "plugin.py").read_text(encoding="utf-8")
        gcp_plugin = (SOURCE_ROOT / "providers" / "gcp" / "plugin.py").read_text(encoding="utf-8")
        azure_plugin = (SOURCE_ROOT / "providers" / "azure" / "plugin.py").read_text(encoding="utf-8")

        self.assertIn("boundary_contributor_factory=", aws_plugin)
        self.assertIn("boundary_contributor_factory=", gcp_plugin)
        self.assertNotIn("boundary_contributor_factory=", azure_plugin)
        self.assertTrue((SOURCE_ROOT / "providers" / "aws" / "boundaries.py").exists())
        self.assertTrue((SOURCE_ROOT / "providers" / "gcp" / "boundaries.py").exists())

    def test_provider_contract_documents_encapsulation_rules(self) -> None:
        guidelines = DEFAULT_PROVIDER_ENCAPSULATION_CONTRACT.guidelines

        self.assertTrue(any("boundary contributors" in item for item in guidelines))
        self.assertTrue(any("provider plugin contract" in item for item in guidelines))
        self.assertTrue(any("Do not add new provider-specific convenience accessors" in item for item in guidelines))

    def test_provider_normalizers_do_not_write_shared_posture_metadata_as_raw_keys(self) -> None:
        raw_writes: set[tuple[str, str]] = set()

        for provider_root in sorted((SOURCE_ROOT / "providers").iterdir()):
            if not provider_root.is_dir():
                continue
            for path in sorted(provider_root.glob("*_normalizers.py")):
                relative_path = path.relative_to(SOURCE_ROOT).as_posix()
                for line in path.read_text(encoding="utf-8").splitlines():
                    stripped = line.strip()
                    for key in _PROVIDER_NORMALIZER_RAW_SHARED_POSTURE_KEYS:
                        if f'"{key}":' in stripped:
                            raw_writes.add((relative_path, stripped))

        self.assertEqual(raw_writes, set())

    def test_gcp_network_normalizers_do_not_write_network_posture_as_raw_keys(self) -> None:
        raw_writes: set[tuple[str, str]] = set()
        path = SOURCE_ROOT / "providers" / "gcp" / "network_normalizers.py"
        relative_path = path.relative_to(SOURCE_ROOT).as_posix()

        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            for key in _GCP_NETWORK_NORMALIZER_RAW_POSTURE_KEYS:
                if f'"{key}":' in stripped:
                    raw_writes.add((relative_path, stripped))

        self.assertEqual(raw_writes, set())

    def test_gcp_data_normalizers_do_not_write_encryption_posture_as_raw_keys(self) -> None:
        raw_writes: set[tuple[str, str]] = set()
        path = SOURCE_ROOT / "providers" / "gcp" / "data_normalizers.py"
        relative_path = path.relative_to(SOURCE_ROOT).as_posix()

        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            for key in _GCP_DATA_NORMALIZER_RAW_POSTURE_KEYS:
                if f'"{key}":' in stripped:
                    raw_writes.add((relative_path, stripped))

        self.assertEqual(raw_writes, set())

    def test_rule_facing_metadata_keys_are_not_used_as_raw_metadata_strings(self) -> None:
        raw_uses: set[tuple[str, int, str]] = set()
        scanned_roots = (
            SOURCE_ROOT / "analysis",
            SOURCE_ROOT / "providers",
        )

        for root in scanned_roots:
            for path in sorted(root.rglob("*.py")):
                relative_path = path.relative_to(SOURCE_ROOT).as_posix()
                if relative_path in _RULE_FACING_METADATA_RAW_STRING_EXCLUDED_FILES:
                    continue
                for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                    stripped = line.strip()
                    if _uses_rule_facing_metadata_key_as_raw_string(path, stripped):
                        raw_uses.add((relative_path, line_number, stripped))

        self.assertEqual(raw_uses, set())

    def test_normalized_resource_write_paths_are_centralized(self) -> None:
        direct_writes: set[tuple[str, str]] = set()
        scanned_roots = (
            SOURCE_ROOT / "analysis",
            SOURCE_ROOT / "providers",
        )

        for root in scanned_roots:
            for path in sorted(root.rglob("*.py")):
                relative_path = path.relative_to(SOURCE_ROOT).as_posix()
                if relative_path in _NORMALIZED_RESOURCE_WRITE_FACADES:
                    continue
                for line in path.read_text(encoding="utf-8").splitlines():
                    stripped = line.strip()
                    if any(pattern.search(stripped) for pattern in _NORMALIZED_RESOURCE_WRITE_PATTERNS):
                        direct_writes.add((relative_path, stripped))

        self.assertEqual(direct_writes, _NORMALIZED_RESOURCE_DIRECT_WRITE_EXCEPTIONS)


if __name__ == "__main__":
    unittest.main()
