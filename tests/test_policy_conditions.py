from __future__ import annotations

import unittest

from cloud_threat_modeler.analysis.policy_conditions import (
    assess_principal,
    describe_trust_narrowing,
    trust_statement_has_supported_narrowing,
    trust_statement_narrowing_conditions,
    trust_statement_narrowing_keys,
)
from cloud_threat_modeler.models import IAMPolicyCondition


class PolicyConditionsTests(unittest.TestCase):
    def test_assess_principal_classifies_foreign_root_and_same_account_role(self) -> None:
        foreign_root = assess_principal("arn:aws:iam::444455556666:root", "111122223333")
        same_account_role = assess_principal("arn:aws:iam::111122223333:role/deployer", "111122223333")

        self.assertTrue(foreign_root.is_foreign_account)
        self.assertTrue(foreign_root.is_root_like)
        self.assertEqual(foreign_root.scope_description, "principal is foreign account root 444455556666")
        self.assertEqual(foreign_root.trust_path_description, "trust principal belongs to foreign account 444455556666")

        self.assertFalse(same_account_role.is_foreign_account)
        self.assertFalse(same_account_role.is_root_like)
        self.assertIsNone(same_account_role.scope_description)
        self.assertEqual(same_account_role.trust_path_description, "trust principal belongs to account 111122223333")

    def test_trust_statement_helpers_use_structured_conditions(self) -> None:
        trust_statement = {
            "principals": ["arn:aws:iam::444455556666:role/deployer"],
            "narrowing_condition_keys": ["aws:SourceAccount", "aws:SourceArn", "sts:ExternalId"],
            "narrowing_conditions": [
                {
                    "operator": "ArnLike",
                    "key": "aws:SourceArn",
                    "values": ["arn:aws:codebuild:us-east-1:444455556666:project/release-*"],
                },
                {
                    "operator": "StringEquals",
                    "key": "aws:SourceAccount",
                    "values": ["444455556666"],
                },
                {
                    "operator": "StringEquals",
                    "key": "sts:ExternalId",
                    "values": ["release-pipeline"],
                },
            ],
            "has_narrowing_conditions": True,
        }

        self.assertTrue(trust_statement_has_supported_narrowing(trust_statement))
        self.assertEqual(
            trust_statement_narrowing_keys(trust_statement),
            ["aws:SourceAccount", "aws:SourceArn", "sts:ExternalId"],
        )
        self.assertEqual(
            trust_statement_narrowing_conditions(trust_statement),
            [
                IAMPolicyCondition(
                    operator="ArnLike",
                    key="aws:SourceArn",
                    values=["arn:aws:codebuild:us-east-1:444455556666:project/release-*"],
                ),
                IAMPolicyCondition(
                    operator="StringEquals",
                    key="aws:SourceAccount",
                    values=["444455556666"],
                ),
                IAMPolicyCondition(
                    operator="StringEquals",
                    key="sts:ExternalId",
                    values=["release-pipeline"],
                ),
            ],
        )
        self.assertEqual(
            describe_trust_narrowing(trust_statement),
            [
                "supported narrowing conditions present: true",
                "supported narrowing condition keys: aws:SourceAccount, aws:SourceArn, sts:ExternalId",
            ],
        )

    def test_trust_statement_helpers_fall_back_to_key_only_metadata(self) -> None:
        trust_statement = {
            "principals": ["*"],
            "narrowing_condition_keys": ["aws:SourceArn"],
        }

        self.assertTrue(trust_statement_has_supported_narrowing(trust_statement))
        self.assertEqual(
            trust_statement_narrowing_conditions(trust_statement),
            [IAMPolicyCondition(operator="", key="aws:SourceArn", values=[])],
        )


if __name__ == "__main__":
    unittest.main()
