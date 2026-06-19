from __future__ import annotations

import unittest

from tfstride.resource_helpers import parse_aws_account_id


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


if __name__ == "__main__":
    unittest.main()
