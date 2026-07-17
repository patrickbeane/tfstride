from __future__ import annotations

import unittest
from typing import Any

from tfstride.models import ResourceCategory, TerraformResource
from tfstride.providers.aws.iam_normalizers import normalize_iam_openid_connect_provider
from tfstride.providers.aws.normalizer import SUPPORTED_AWS_TYPES, AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts


def _oidc_provider(
    values: dict[str, Any],
    *,
    unknown_values: dict[str, Any] | None = None,
    name: str = "github",
) -> TerraformResource:
    return TerraformResource(
        address=f"aws_iam_openid_connect_provider.{name}",
        mode="managed",
        resource_type="aws_iam_openid_connect_provider",
        name=name,
        provider_name="registry.terraform.io/hashicorp/aws",
        values=values,
        unknown_values=unknown_values or {},
    )


class AwsOidcProviderNormalizerTests(unittest.TestCase):
    def test_normalizes_oidc_provider_identity_and_trust_evidence(self) -> None:
        arn = "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"
        normalized = normalize_iam_openid_connect_provider(
            _oidc_provider(
                {
                    "url": "https://token.actions.githubusercontent.com",
                    "arn": arn,
                    "client_id_list": ["sts.amazonaws.com", "example-client"],
                    "thumbprint_list": ["6938fd4d98bab03faadb97b34396831e3780aea1"],
                }
            )
        )
        facts = aws_facts(normalized)

        self.assertEqual(normalized.category, ResourceCategory.IAM)
        self.assertEqual(normalized.identifier, arn)
        self.assertEqual(normalized.arn, arn)
        self.assertEqual(facts.oidc_provider_url, "https://token.actions.githubusercontent.com")
        self.assertEqual(facts.oidc_provider_arn, arn)
        self.assertEqual(facts.oidc_provider_client_ids, ["sts.amazonaws.com", "example-client"])
        self.assertEqual(facts.oidc_provider_thumbprints, ["6938fd4d98bab03faadb97b34396831e3780aea1"])
        self.assertEqual(facts.oidc_provider_posture_uncertainties, [])

    def test_preserves_absent_optional_lists_without_claiming_uncertainty(self) -> None:
        facts = aws_facts(
            normalize_iam_openid_connect_provider(_oidc_provider({"url": "https://issuer.example.com"}, name="minimal"))
        )

        self.assertEqual(facts.oidc_provider_url, "https://issuer.example.com")
        self.assertIsNone(facts.oidc_provider_arn)
        self.assertEqual(facts.oidc_provider_client_ids, [])
        self.assertEqual(facts.oidc_provider_thumbprints, [])
        self.assertEqual(facts.oidc_provider_posture_uncertainties, [])

    def test_preserves_computed_oidc_fields_as_uncertainties(self) -> None:
        normalized = normalize_iam_openid_connect_provider(
            _oidc_provider(
                {},
                name="computed",
                unknown_values={
                    "url": True,
                    "arn": True,
                    "client_id_list": True,
                    "thumbprint_list": [True],
                },
            )
        )
        facts = aws_facts(normalized)

        self.assertEqual(normalized.identifier, "aws_iam_openid_connect_provider.computed")
        self.assertIsNone(normalized.arn)
        self.assertIsNone(facts.oidc_provider_url)
        self.assertIsNone(facts.oidc_provider_arn)
        self.assertEqual(facts.oidc_provider_client_ids, [])
        self.assertEqual(facts.oidc_provider_thumbprints, [])
        self.assertEqual(
            facts.oidc_provider_posture_uncertainties,
            [
                "url is unknown after planning",
                "arn is unknown after planning",
                "client_id_list is unknown after planning",
                "thumbprint_list is unknown after planning",
            ],
        )

    def test_oidc_provider_is_registered_as_supported(self) -> None:
        resource = _oidc_provider(
            {
                "url": "https://issuer.example.com",
                "client_id_list": ["sts.amazonaws.com"],
            }
        )

        inventory = AwsNormalizer().normalize([resource])

        self.assertIn("aws_iam_openid_connect_provider", SUPPORTED_AWS_TYPES)
        self.assertEqual(inventory.unsupported_resources, [])
        self.assertEqual([item.address for item in inventory.resources], [resource.address])


if __name__ == "__main__":
    unittest.main()
