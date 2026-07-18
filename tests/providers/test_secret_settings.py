from __future__ import annotations

import unittest

from tfstride.providers.secret_settings import (
    SensitiveSettingCategory,
    classify_sensitive_setting_name,
    redacted_sensitive_setting_evidence,
)


class SensitiveSettingClassificationTests(unittest.TestCase):
    def test_classifies_strict_sensitive_suffixes(self) -> None:
        cases = {
            "DB_PASSWORD": SensitiveSettingCategory.PASSWORD,
            "cache_passwd": SensitiveSettingCategory.PASSWORD,
            "OAUTH_CLIENT_SECRET": SensitiveSettingCategory.CLIENT_SECRET,
            "STRIPE_API_KEY": SensitiveSettingCategory.API_KEY,
            "SERVICE_ACCESS_TOKEN": SensitiveSettingCategory.TOKEN,
            "OAUTH_REFRESH_TOKEN": SensitiveSettingCategory.TOKEN,
            "INTERNAL_AUTH_TOKEN": SensitiveSettingCategory.TOKEN,
            "TLS_PRIVATE_KEY": SensitiveSettingCategory.PRIVATE_KEY,
            "DATABASE_CONNECTION_STRING": SensitiveSettingCategory.CONNECTION_STRING,
            "AWS_SECRET_ACCESS_KEY": SensitiveSettingCategory.SECRET_ACCESS_KEY,
        }

        for name, expected_category in cases.items():
            with self.subTest(name=name):
                classification = classify_sensitive_setting_name(name)
                self.assertIsNotNone(classification)
                assert classification is not None
                self.assertEqual(classification.category, expected_category)

    def test_normalizes_camel_case_and_structural_separators(self) -> None:
        camel_case = classify_sensitive_setting_name("databasePassword")
        acronym = classify_sensitive_setting_name("DBPassword")
        dotted = classify_sensitive_setting_name("database.connection-string")

        self.assertEqual(camel_case.normalized_name if camel_case else None, "database_password")
        self.assertEqual(acronym.normalized_name if acronym else None, "db_password")
        self.assertEqual(dotted.normalized_name if dotted else None, "database_connection_string")

    def test_reference_and_public_identifiers_are_not_classified_as_secret_material(self) -> None:
        names = (
            "TOKEN_ENDPOINT",
            "SECRET_NAME",
            "SECRET_ARN",
            "SECRET_ID",
            "KMS_KEY_ID",
            "PUBLIC_KEY",
            "CLIENT_ID",
            "DATABASE_URL",
            "PAGINATION_TOKEN",
        )

        for name in names:
            with self.subTest(name=name):
                self.assertIsNone(classify_sensitive_setting_name(name))

    def test_missing_dynamic_and_non_string_names_are_not_classified(self) -> None:
        values = (
            None,
            "",
            "   ",
            "${var.setting_name}",
            "<known after apply>",
            ["DB_PASSWORD"],
        )

        for value in values:
            with self.subTest(value=value):
                self.assertIsNone(classify_sensitive_setting_name(value))

    def test_evidence_contains_only_canonical_name_category_and_redaction(self) -> None:
        classification = classify_sensitive_setting_name("DbPassword")
        assert classification is not None

        evidence = redacted_sensitive_setting_evidence(
            classification,
            path="container_definitions[0].environment[2]",
        )

        self.assertEqual(
            evidence,
            "path=container_definitions[0].environment[2]; setting=db_password; category=password; value=<redacted>",
        )

    def test_classification_and_evidence_have_no_literal_value_surface(self) -> None:
        literal_value = "do-not-leak-this-value"
        classification = classify_sensitive_setting_name("API_KEY")
        assert classification is not None

        evidence = redacted_sensitive_setting_evidence(classification)

        self.assertFalse(hasattr(classification, "value"))
        self.assertNotIn(literal_value, repr(classification))
        self.assertNotIn(literal_value, evidence)
        self.assertEqual(evidence, "setting=api_key; category=api-key; value=<redacted>")


if __name__ == "__main__":
    unittest.main()
