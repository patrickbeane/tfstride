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
    }
)
_TEMPORARY_GCP_DIRECT_WRITE_EXCEPTIONS = frozenset(
    {
        ("providers/gcp/container_normalizers.py", "normalized.direct_internet_reachable = public_exposure"),
        ("providers/gcp/container_normalizers.py", "normalized.internet_ingress_capable = public_endpoint"),
        ("providers/gcp/container_normalizers.py", "normalized.internet_ingress_reasons = public_exposure_reasons"),
        ("providers/gcp/data_normalizers.py", "normalized.direct_internet_reachable = public_exposure"),
        ("providers/gcp/data_normalizers.py", "normalized.internet_ingress_capable = public_exposure"),
        ("providers/gcp/data_normalizers.py", "normalized.internet_ingress_reasons = public_exposure_reasons"),
        ("providers/gcp/resource_decorator.py", "forwarding_rule.set_metadata_field("),
        (
            "providers/gcp/resource_decorator.py",
            "resource.set_metadata_field(GcpResourceMetadata.LOAD_BALANCER_FRONTENDS, _dedupe_dicts(frontends))",
        ),
        (
            "providers/gcp/resource_decorator.py",
            "resource.set_metadata_field(GcpResourceMetadata.FRONTED_BY_INTERNET_FACING_LOAD_BALANCER, True)",
        ),
        ("providers/gcp/resource_decorator.py", "resource.append_metadata_field("),
        ("providers/gcp/resource_decorator.py", "subnetwork.has_public_route = has_public_route"),
        ("providers/gcp/resource_decorator.py", "subnetwork.is_public_subnet = has_public_route"),
        ("providers/gcp/resource_decorator.py", "subnetwork.has_nat_gateway_egress = has_nat_egress"),
        (
            "providers/gcp/resource_decorator.py",
            "resource.in_public_subnet = any(subnetwork.is_public_subnet for subnetwork in subnetworks)",
        ),
        (
            "providers/gcp/resource_decorator.py",
            "resource.has_nat_gateway_egress = any(subnetwork.has_nat_gateway_egress for subnetwork in subnetworks)",
        ),
        ("providers/gcp/resource_decorator.py", "resource.has_public_route = resource.in_public_subnet or any("),
        ("providers/gcp/resource_decorator.py", "resource.vpc_id = subnet_network_reference"),
        ("providers/gcp/resource_decorator.py", "resource.vpc_id = network_reference"),
        ("providers/gcp/resource_decorator.py", "resource.internet_ingress_capable = internet_ingress"),
        ("providers/gcp/resource_decorator.py", "resource.internet_ingress_reasons = internet_ingress_reasons"),
        ("providers/gcp/resource_decorator.py", "resource.set_metadata_field("),
        ("providers/gcp/resource_decorator.py", "resource.public_exposure = public_exposure"),
        ("providers/gcp/resource_decorator.py", "resource.direct_internet_reachable = public_exposure"),
        ("providers/gcp/resource_decorator.py", "resource.public_exposure_reasons = ["),
        ("providers/gcp/resource_decorator.py", "bucket.public_access_configured = bool(public_access_reasons)"),
        ("providers/gcp/resource_decorator.py", "bucket.public_access_reasons = public_access_reasons"),
        ("providers/gcp/resource_decorator.py", "bucket.public_exposure = public_exposure"),
        ("providers/gcp/resource_decorator.py", "bucket.direct_internet_reachable = public_exposure"),
        ("providers/gcp/resource_decorator.py", "bucket.public_exposure_reasons = public_access_reasons"),
        ("providers/gcp/resource_decorator.py", "resource.public_access_reasons = public_access_reasons"),
        ("providers/gcp/resource_decorator.py", "resource.public_exposure_reasons = public_access_reasons"),
        ("providers/gcp/resource_decorator.py", "resource.set_metadata_field(GcpResourceMetadata.IAM_BINDINGS, bindings)"),
        (
            "providers/gcp/resource_decorator.py",
            "resource.extend_metadata_field(GcpResourceMetadata.RESOURCE_POLICY_SOURCE_ADDRESSES, source_addresses)",
        ),
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

        self.assertEqual(direct_writes, _TEMPORARY_GCP_DIRECT_WRITE_EXCEPTIONS)


if __name__ == "__main__":
    unittest.main()