from __future__ import annotations

import unittest

from tfstride.providers.aws.coercion import as_bool, as_list, as_optional_int, compact, first_item
from tfstride.providers.aws.policy_documents import (
    compact_condition_entries,
    condition_entry,
    extract_principals,
    extract_trust_statements,
    lambda_permission_principal_entries,
    load_json_document,
    parse_policy_statements,
)


class AwsCoercionTests(unittest.TestCase):
    def test_coerces_terraform_value_shapes(self) -> None:
        self.assertEqual(as_list(None), [])
        self.assertEqual(as_list("sg-123"), ["sg-123"])
        self.assertEqual(compact([None, "", [], "sg-123", 443]), ["sg-123", "443"])
        self.assertTrue(as_bool("enabled"))
        self.assertTrue(as_bool("yes"))
        self.assertFalse(as_bool("disabled"))
        self.assertFalse(as_bool("false"))
        self.assertEqual(first_item([{"assign_public_ip": "true"}]), {"assign_public_ip": "true"})
        self.assertIsNone(first_item(["not-a-dict"]))
        self.assertEqual(as_optional_int("12"), 12)
        self.assertIsNone(as_optional_int("not-an-int"))


class AwsPolicyDocumentTests(unittest.TestCase):
    def test_load_json_document_accepts_dict_json_object_and_invalid_input(self) -> None:
        self.assertEqual(load_json_document({"Statement": []}), {"Statement": []})
        self.assertEqual(load_json_document('{"Statement": []}'), {"Statement": []})
        self.assertEqual(load_json_document("[1, 2, 3]"), {})
        self.assertEqual(load_json_document("{not json"), {})

    def test_parse_policy_statements_extracts_principals_and_conditions(self) -> None:
        policy = {
            "Statement": {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": ["arn:aws:s3:::logs/*"],
                "Principal": {
                    "AWS": ["arn:aws:iam::111122223333:role/app"],
                    "Service": "lambda.amazonaws.com",
                },
                "Condition": {
                    "StringEquals": {
                        "aws:SourceAccount": "111122223333",
                        "aws:SourceArn": ["arn:aws:lambda:us-east-1:111122223333:function:app"],
                    }
                },
            }
        }

        statements = parse_policy_statements(policy)

        self.assertEqual(len(statements), 1)
        statement = statements[0]
        self.assertEqual(statement.effect, "Allow")
        self.assertEqual(statement.actions, ["s3:GetObject"])
        self.assertEqual(statement.resources, ["arn:aws:s3:::logs/*"])
        self.assertEqual(
            [(entry.kind, entry.value) for entry in statement.principal_entries],
            [
                ("AWS", "arn:aws:iam::111122223333:role/app"),
                ("Service", "lambda.amazonaws.com"),
            ],
        )
        self.assertEqual(
            [(condition.operator, condition.key, condition.values) for condition in statement.conditions],
            [
                ("StringEquals", "aws:SourceAccount", ["111122223333"]),
                ("StringEquals", "aws:SourceArn", ["arn:aws:lambda:us-east-1:111122223333:function:app"]),
            ],
        )
        self.assertEqual(
            extract_principals(policy),
            ["arn:aws:iam::111122223333:role/app", "lambda.amazonaws.com"],
        )

    def test_extract_trust_statements_keeps_supported_narrowing_conditions(self) -> None:
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Federated": "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"},
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {
                        "StringEquals": {
                            "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                            "token.actions.githubusercontent.com:sub": "repo:example/app:ref:refs/heads/main",
                            "unsupported:key": "ignored",
                        }
                    },
                },
                {
                    "Effect": "Deny",
                    "Principal": {"AWS": "*"},
                    "Action": "sts:AssumeRole",
                },
            ]
        }

        trust_statements = extract_trust_statements(policy)

        self.assertEqual(len(trust_statements), 1)
        self.assertEqual(
            trust_statements[0]["principals"],
            ["arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"],
        )
        self.assertTrue(trust_statements[0]["has_narrowing_conditions"])
        self.assertEqual(
            trust_statements[0]["narrowing_condition_keys"],
            [
                "token.actions.githubusercontent.com:aud",
                "token.actions.githubusercontent.com:sub",
            ],
        )

    def test_builds_lambda_permission_principals_and_compacts_conditions(self) -> None:
        service_principal = lambda_permission_principal_entries("events.amazonaws.com")
        aws_principal = lambda_permission_principal_entries("arn:aws:iam::111122223333:role/app")

        self.assertEqual([(entry.kind, entry.value) for entry in service_principal], [("Service", "events.amazonaws.com")])
        self.assertEqual([(entry.kind, entry.value) for entry in aws_principal], [("AWS", "arn:aws:iam::111122223333:role/app")])
        self.assertEqual(
            compact_condition_entries(
                [
                    condition_entry(operator="ArnLike", key="aws:SourceArn", values=["arn:aws:events:::rule/app"]),
                    condition_entry(operator="", key="aws:SourceAccount", values=["111122223333"]),
                ]
            ),
            [condition_entry(operator="ArnLike", key="aws:SourceArn", values=["arn:aws:events:::rule/app"])],
        )


if __name__ == "__main__":
    unittest.main()
