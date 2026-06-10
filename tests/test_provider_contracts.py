from __future__ import annotations

import re
import unittest
from dataclasses import fields
from pathlib import Path

from tfstride.models import NormalizedResource
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.contracts import (
    DEFAULT_PROVIDER_ENCAPSULATION_CONTRACT,
    DEFAULT_RESOURCE_METADATA_OWNERSHIP_CONTRACT,
)
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.resource_metadata import MetadataField, ResourceMetadata


_SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src" / "tfstride"
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


def _metadata_field_names(namespace: type) -> set[str]:
    return {
        name
        for name, value in vars(namespace).items()
        if isinstance(value, MetadataField)
    }


def _resource_metadata_field_names() -> set[str]:
    return _metadata_field_names(ResourceMetadata)


class ProviderEncapsulationContractTests(unittest.TestCase):
    def test_normalized_resource_fields_match_provider_contract(self) -> None:
        actual_fields = {
            field.name
            for field in fields(NormalizedResource)
            if not field.name.startswith("_")
        }

        self.assertEqual(
            actual_fields,
            DEFAULT_PROVIDER_ENCAPSULATION_CONTRACT.provider_neutral_resource_fields,
        )

    def test_normalized_resource_accessors_are_classified_by_provider_contract(self) -> None:
        actual_accessors = {
            name
            for name, value in vars(NormalizedResource).items()
            if isinstance(value, property)
        }
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
        self.assertFalse(actual_fields & contract.transitional_fields)
        self.assertFalse(contract.shared_core_fields & provider_owned)
        self.assertFalse(contract.shared_core_fields & contract.transitional_fields)
        self.assertFalse(provider_owned & contract.transitional_fields)

    def test_provider_metadata_namespaces_match_ownership_contract(self) -> None:
        contract = DEFAULT_RESOURCE_METADATA_OWNERSHIP_CONTRACT
        shared_or_transitional = contract.shared_core_fields | contract.transitional_fields
        provider_namespaces = {
            "aws": AwsResourceMetadata,
            "gcp": GcpResourceMetadata,
        }

        for provider, namespace in provider_namespaces.items():
            with self.subTest(provider=provider):
                metadata_fields = _metadata_field_names(namespace)
                provider_owned = contract.provider_owned_fields[provider]

                self.assertEqual(metadata_fields - shared_or_transitional, provider_owned)
                self.assertFalse(provider_owned & shared_or_transitional)
                self.assertEqual(provider_owned - metadata_fields, set())

    def test_resource_metadata_ownership_contract_marks_known_boundaries(self) -> None:
        contract = DEFAULT_RESOURCE_METADATA_OWNERSHIP_CONTRACT
        aws_owned = contract.provider_owned_fields["aws"]
        gcp_owned = contract.provider_owned_fields["gcp"]

        self.assertIn("DIRECT_INTERNET_REACHABLE", contract.shared_core_fields)
        self.assertIn("SECURITY_GROUP_ID", aws_owned)
        self.assertIn("TASK_ROLE_ARN", aws_owned)
        self.assertIn("SERVICE_ACCOUNT_EMAIL", gcp_owned)
        self.assertIn("KMS_CRYPTO_KEY_REFERENCE", gcp_owned)
        self.assertIn("GKE_NODE_OAUTH_SCOPES", gcp_owned)
        self.assertIn("BUCKET_NAME", contract.transitional_fields)
        self.assertIn("POLICY_DOCUMENT", contract.transitional_fields)
        self.assertIn("RESOURCE_POLICY_SOURCE_ADDRESSES", contract.transitional_fields)
        self.assertNotIn("SECURITY_GROUP_ID", contract.shared_core_fields)
        self.assertNotIn("SERVICE_ACCOUNT_EMAIL", contract.shared_core_fields)

    def test_resource_metadata_ownership_contract_documents_migration_rules(self) -> None:
        guidelines = DEFAULT_RESOURCE_METADATA_OWNERSHIP_CONTRACT.guidelines

        self.assertTrue(any("Provider-owned metadata" in item for item in guidelines))
        self.assertTrue(any("Transitional metadata" in item for item in guidelines))

    def test_provider_contract_documents_encapsulation_rules(self) -> None:
        guidelines = DEFAULT_PROVIDER_ENCAPSULATION_CONTRACT.guidelines

        self.assertTrue(any("Provider packages own provider-specific facts" in item for item in guidelines))
        self.assertTrue(any("Do not add new provider-specific convenience accessors" in item for item in guidelines))


    def test_provider_normalizers_do_not_write_shared_posture_metadata_as_raw_keys(self) -> None:
        raw_writes: set[tuple[str, str]] = set()

        for provider_root in sorted((_SOURCE_ROOT / "providers").iterdir()):
            if not provider_root.is_dir():
                continue
            for path in sorted(provider_root.glob("*_normalizers.py")):
                relative_path = path.relative_to(_SOURCE_ROOT).as_posix()
                for line in path.read_text(encoding="utf-8").splitlines():
                    stripped = line.strip()
                    for key in _PROVIDER_NORMALIZER_RAW_SHARED_POSTURE_KEYS:
                        if f'"{key}":' in stripped:
                            raw_writes.add((relative_path, stripped))

        self.assertEqual(raw_writes, set())

    def test_normalized_resource_write_paths_are_centralized(self) -> None:
        direct_writes: set[tuple[str, str]] = set()
        scanned_roots = (
            _SOURCE_ROOT / "analysis",
            _SOURCE_ROOT / "providers",
        )

        for root in scanned_roots:
            for path in sorted(root.rglob("*.py")):
                relative_path = path.relative_to(_SOURCE_ROOT).as_posix()
                if relative_path in _NORMALIZED_RESOURCE_WRITE_FACADES:
                    continue
                for line in path.read_text(encoding="utf-8").splitlines():
                    stripped = line.strip()
                    if any(pattern.search(stripped) for pattern in _NORMALIZED_RESOURCE_WRITE_PATTERNS):
                        direct_writes.add((relative_path, stripped))

        self.assertEqual(direct_writes, _NORMALIZED_RESOURCE_DIRECT_WRITE_EXCEPTIONS)


if __name__ == "__main__":
    unittest.main()