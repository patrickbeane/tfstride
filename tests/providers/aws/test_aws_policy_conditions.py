from __future__ import annotations

import unittest

from tfstride.models import IAMPolicyCondition, IAMPolicyStatement, IAMPrincipal
from tfstride.providers.aws.policy_conditions import (
    assess_principal,
    describe_trust_narrowing,
    describe_trust_narrowing_for_principal,
    federated_provider_description,
    policy_statement_principal_assessments,
    resource_policy_statement_has_effective_narrowing,
    trust_statement_has_effective_narrowing,
    trust_statement_has_effective_narrowing_for_principal,
    trust_statement_has_supported_narrowing,
    trust_statement_has_supported_narrowing_for_principal,
    trust_statement_narrowing_conditions,
    trust_statement_narrowing_keys,
    trust_statement_principal_assessments,
)


class PolicyConditionsTests(unittest.TestCase):
    def test_federated_provider_description_labels_known_provider_types(self) -> None:
        self.assertEqual(federated_provider_description("saml"), "SAML identity provider")
        self.assertEqual(federated_provider_description("oidc"), "OIDC identity provider")
        self.assertEqual(federated_provider_description("cognito"), "Cognito identity provider")
        self.assertEqual(federated_provider_description("unknown"), "federated identity provider")
        self.assertEqual(federated_provider_description(None), "federated identity provider")

    def test_assess_principal_classifies_foreign_root_and_same_account_role(self) -> None:
        foreign_root = assess_principal("arn:aws:iam::444455556666:root", "111122223333")
        same_account_root = assess_principal("arn:aws:iam::111122223333:root", "111122223333")
        same_account_role = assess_principal("arn:aws:iam::111122223333:role/deployer", "111122223333")

        self.assertTrue(foreign_root.is_foreign_account)
        self.assertTrue(foreign_root.is_root_like)
        self.assertEqual(foreign_root.scope_description, "principal is foreign account root 444455556666")
        self.assertEqual(foreign_root.trust_path_description, "trust principal belongs to foreign account 444455556666")

        self.assertFalse(same_account_root.is_foreign_account)
        self.assertTrue(same_account_root.is_root_like)
        self.assertEqual(same_account_root.scope_description, "principal is account root 111122223333")

        self.assertFalse(same_account_role.is_foreign_account)
        self.assertFalse(same_account_role.is_root_like)
        self.assertIsNone(same_account_role.scope_description)
        self.assertEqual(same_account_role.trust_path_description, "trust principal belongs to account 111122223333")

    def test_assess_principal_classifies_federated_identity_provider_arns(self) -> None:
        same_account_saml = assess_principal(
            "arn:aws:iam::111122223333:saml-provider/CorpSSO",
            "111122223333",
        )
        foreign_oidc = assess_principal(
            "arn:aws:iam::444455556666:oidc-provider/token.actions.githubusercontent.com",
            "111122223333",
        )

        self.assertEqual(same_account_saml.principal_kind, "Federated")
        self.assertTrue(same_account_saml.is_federated)
        self.assertFalse(same_account_saml.is_service)
        self.assertEqual(same_account_saml.federated_provider_type, "saml")
        self.assertEqual(
            same_account_saml.scope_description,
            "SAML identity provider belongs to account 111122223333",
        )
        self.assertEqual(
            same_account_saml.trust_path_description,
            "trust principal is SAML identity provider in account 111122223333",
        )

        self.assertEqual(foreign_oidc.principal_kind, "Federated")
        self.assertTrue(foreign_oidc.is_federated)
        self.assertFalse(foreign_oidc.is_service)
        self.assertEqual(foreign_oidc.federated_provider_type, "oidc")
        self.assertEqual(
            foreign_oidc.scope_description,
            "OIDC identity provider belongs to foreign account 444455556666",
        )
        self.assertEqual(
            foreign_oidc.trust_path_description,
            "trust principal is OIDC identity provider in foreign account 444455556666",
        )

    def test_explicit_federated_kind_takes_precedence_over_service_suffix(self) -> None:
        assessment = assess_principal(
            "cognito-identity.amazonaws.com",
            "111122223333",
            principal_kind="Federated",
        )

        self.assertEqual(assessment.principal_kind, "Federated")
        self.assertTrue(assessment.is_federated)
        self.assertFalse(assessment.is_service)
        self.assertEqual(assessment.federated_provider_type, "cognito")
        self.assertEqual(assessment.trust_path_description, "trust principal is Cognito identity provider")

    def test_principal_assessment_helpers_preserve_structured_principal_kinds(self) -> None:
        trust_statement = {
            "principals": ["cognito-identity.amazonaws.com"],
            "principal_entries": [
                {"kind": "Federated", "value": "cognito-identity.amazonaws.com"},
                {"kind": "Service", "value": "lambda.amazonaws.com"},
            ],
        }
        policy_statement = IAMPolicyStatement(
            effect="Allow",
            principals=["arn:aws:iam::111122223333:saml-provider/CorpSSO"],
            principal_entries=[
                IAMPrincipal(
                    kind="Federated",
                    value="arn:aws:iam::111122223333:saml-provider/CorpSSO",
                )
            ],
        )

        trust_assessments = trust_statement_principal_assessments(trust_statement, "111122223333")
        policy_assessments = policy_statement_principal_assessments(policy_statement, "111122223333")

        self.assertEqual(
            [(assessment.principal_kind, assessment.principal) for assessment in trust_assessments],
            [
                ("Federated", "cognito-identity.amazonaws.com"),
                ("Service", "lambda.amazonaws.com"),
            ],
        )
        self.assertTrue(trust_assessments[0].is_federated)
        self.assertFalse(trust_assessments[0].is_service)
        self.assertEqual(
            [(assessment.principal_kind, assessment.principal) for assessment in policy_assessments],
            [("Federated", "arn:aws:iam::111122223333:saml-provider/CorpSSO")],
        )

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
        self.assertTrue(trust_statement_has_effective_narrowing(trust_statement))

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

    def test_source_account_alone_is_not_effective_narrowing(self) -> None:
        trust_statement = {
            "principals": ["arn:aws:iam::444455556666:role/deployer"],
            "narrowing_condition_keys": ["aws:SourceAccount"],
            "narrowing_conditions": [
                {
                    "operator": "StringEquals",
                    "key": "aws:SourceAccount",
                    "values": ["444455556666"],
                }
            ],
            "has_narrowing_conditions": True,
        }
        resource_statement = IAMPolicyStatement(
            effect="Allow",
            principals=["*"],
            conditions=[
                IAMPolicyCondition(
                    operator="StringEquals",
                    key="aws:SourceAccount",
                    values=["111122223333"],
                )
            ],
        )

        self.assertFalse(trust_statement_has_effective_narrowing(trust_statement))
        self.assertFalse(resource_policy_statement_has_effective_narrowing(resource_statement))

    def test_saml_audience_is_effective_for_saml_federated_principal(self) -> None:
        assessment = assess_principal(
            "arn:aws:iam::111122223333:saml-provider/CorpSSO",
            "111122223333",
        )
        trust_statement = {
            "principals": ["arn:aws:iam::111122223333:saml-provider/CorpSSO"],
            "principal_entries": [
                {
                    "kind": "Federated",
                    "value": "arn:aws:iam::111122223333:saml-provider/CorpSSO",
                }
            ],
            "narrowing_condition_keys": ["SAML:aud"],
            "narrowing_conditions": [
                {
                    "operator": "StringEquals",
                    "key": "SAML:aud",
                    "values": ["https://signin.aws.amazon.com/saml"],
                }
            ],
            "has_narrowing_conditions": True,
        }

        self.assertTrue(trust_statement_has_supported_narrowing_for_principal(trust_statement, assessment))
        self.assertTrue(trust_statement_has_effective_narrowing_for_principal(trust_statement, assessment))
        self.assertEqual(
            describe_trust_narrowing_for_principal(trust_statement, assessment),
            [
                "supported narrowing conditions present: true",
                "supported narrowing condition keys: SAML:aud",
            ],
        )

    def test_oidc_principal_requires_matching_audience_and_subject_narrowing(self) -> None:
        assessment = assess_principal(
            "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com",
            "111122223333",
        )
        audience_only_statement = {
            "principals": ["arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"],
            "principal_entries": [
                {
                    "kind": "Federated",
                    "value": "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com",
                }
            ],
            "narrowing_condition_keys": ["token.actions.githubusercontent.com:aud"],
            "narrowing_conditions": [
                {
                    "operator": "StringEquals",
                    "key": "token.actions.githubusercontent.com:aud",
                    "values": ["sts.amazonaws.com"],
                }
            ],
            "has_narrowing_conditions": True,
        }
        complete_statement = {
            **audience_only_statement,
            "narrowing_condition_keys": [
                "token.actions.githubusercontent.com:aud",
                "token.actions.githubusercontent.com:sub",
            ],
            "narrowing_conditions": [
                *audience_only_statement["narrowing_conditions"],
                {
                    "operator": "StringLike",
                    "key": "token.actions.githubusercontent.com:sub",
                    "values": ["repo:example/app:*"],
                },
            ],
        }
        mismatched_statement = {
            **complete_statement,
            "narrowing_condition_keys": [
                "accounts.google.com:aud",
                "accounts.google.com:sub",
            ],
            "narrowing_conditions": [
                {
                    "operator": "StringEquals",
                    "key": "accounts.google.com:aud",
                    "values": ["sts.amazonaws.com"],
                },
                {
                    "operator": "StringLike",
                    "key": "accounts.google.com:sub",
                    "values": ["repo:example/app:*"],
                },
            ],
        }

        self.assertTrue(trust_statement_has_supported_narrowing_for_principal(audience_only_statement, assessment))
        self.assertFalse(trust_statement_has_effective_narrowing_for_principal(audience_only_statement, assessment))
        self.assertTrue(trust_statement_has_effective_narrowing_for_principal(complete_statement, assessment))
        self.assertFalse(trust_statement_has_supported_narrowing_for_principal(mismatched_statement, assessment))
        self.assertFalse(trust_statement_has_effective_narrowing_for_principal(mismatched_statement, assessment))

    def test_source_arn_is_effective_resource_policy_narrowing(self) -> None:
        statement = IAMPolicyStatement(
            effect="Allow",
            principals=["*"],
            conditions=[
                IAMPolicyCondition(
                    operator="ArnEquals",
                    key="aws:SourceArn",
                    values=["arn:aws:sns:us-east-1:111122223333:events"],
                ),
                IAMPolicyCondition(
                    operator="StringEquals",
                    key="aws:SourceAccount",
                    values=["111122223333"],
                ),
            ],
        )

        self.assertTrue(resource_policy_statement_has_effective_narrowing(statement))


if __name__ == "__main__":
    unittest.main()
