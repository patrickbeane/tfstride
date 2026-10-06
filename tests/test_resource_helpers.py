from __future__ import annotations

import unittest

from tfstride.resource_helpers import parse_aws_account_id, policy_allows_public_access


class AwsAccountIdParsingTests(unittest.TestCase):
    def test_parse_aws_account_id_extracts_account_from_arn(self) -> None:
        self.assertEqual(
            parse_aws_account_id("arn:aws:iam::111122223333:role/app"),
            "111122223333",
        )
        self.assertEqual(
            parse_aws_account_id("arn:aws:s3:::bucket-without-account"),
            None,
        )

    def test_parse_aws_account_id_only_accepts_bare_ids_when_enabled(self) -> None:
        self.assertIsNone(parse_aws_account_id("111122223333"))
        self.assertEqual(
            parse_aws_account_id("111122223333", allow_bare=True),
            "111122223333",
        )

    def test_parse_aws_account_id_rejects_empty_or_non_arn_values(self) -> None:
        self.assertIsNone(parse_aws_account_id(None))
        self.assertIsNone(parse_aws_account_id(""))
        self.assertIsNone(parse_aws_account_id("lambda.amazonaws.com"))
        self.assertIsNone(parse_aws_account_id("arn:aws"))
        self.assertIsNone(parse_aws_account_id("arn:aws:iam::not-an-account:role/app"))
        self.assertIsNone(parse_aws_account_id("arn:aws:iam::1234:role/app"))


class PolicyPublicAccessTests(unittest.TestCase):
    def test_missing_effect_does_not_grant_public_access(self) -> None:
        self.assertFalse(
            policy_allows_public_access(
                {"Statement": [{"Principal": "*", "Action": "s3:GetObject"}]},
            )
        )

    def test_explicit_allow_with_wildcard_principal_grants_public_access(self) -> None:
        self.assertTrue(
            policy_allows_public_access(
                {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}]},
            )
        )

    def test_explicit_deny_with_wildcard_principal_denies_public_access(self) -> None:
        self.assertFalse(
            policy_allows_public_access(
                {"Statement": [{"Effect": "Deny", "Principal": "*", "Action": "s3:GetObject"}]},
            )
        )


if __name__ == "__main__":
    unittest.main()
