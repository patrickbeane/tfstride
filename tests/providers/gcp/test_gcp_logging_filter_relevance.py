from __future__ import annotations

import unittest

from tfstride.providers.gcp.logging_filter_relevance import (
    LoggingFilterAuditRelevanceState,
    classify_logging_filter_audit_relevance,
)

_AUDIT = 'logName:"cloudaudit.googleapis.com"'
_ACTIVITY = 'logName="projects/p/logs/cloudaudit.googleapis.com%2Factivity"'
_DATA_ACCESS = 'logName="projects/p/logs/cloudaudit.googleapis.com%2Fdata_access"'
_AUDIT_SIGNAL = ("cloudaudit.googleapis.com",)


class LoggingFilterAuditRelevanceTests(unittest.TestCase):
    def assert_state(self, filter_text: str | None, state: LoggingFilterAuditRelevanceState) -> None:
        with self.subTest(filter_text=filter_text):
            self.assertEqual(classify_logging_filter_audit_relevance(filter_text).state, state)

    def test_absent_filter_exports_all_logs(self) -> None:
        for filter_text in (None, "", "   "):
            self.assert_state(filter_text, "all_logs")
        self.assertTrue(classify_logging_filter_audit_relevance(None).established)

    def test_single_positive_terms_include_the_audit_stream(self) -> None:
        for filter_text in (
            _AUDIT,
            _ACTIVITY,
            f"({_AUDIT})",
            f"(({_AUDIT}))",
            "logName:'cloudaudit.googleapis.com'",
            'protoPayload.@type="type.googleapis.com/google.cloud.audit.AuditLog"',
            'resource.type="gce_firewall_rule"',
            'LOGNAME:"cloudaudit.googleapis.com"',
        ):
            self.assert_state(filter_text, "includes_audit")

    def test_or_includes_audit_when_any_branch_does(self) -> None:
        self.assert_state(f"{_ACTIVITY} OR {_DATA_ACCESS}", "includes_audit")
        self.assert_state(f'{_AUDIT} OR resource.type="gce_instance"', "includes_audit")
        self.assert_state(f'resource.type="gce_instance" OR {_AUDIT}', "includes_audit")
        self.assert_state(f"({_ACTIVITY} OR {_DATA_ACCESS}) AND {_AUDIT}", "includes_audit")

    def test_and_with_other_terms_narrows_the_audit_stream(self) -> None:
        for filter_text in (
            f"{_AUDIT} AND severity>=ERROR",
            f"{_AUDIT} severity >= ERROR",
            f"{_AUDIT} AND NOT severity=DEBUG",
            f'{_AUDIT} AND resource.type="gce_instance"',
            f"{_AUDIT} AND (severity=ERROR OR severity=WARNING)",
        ):
            self.assert_state(filter_text, "narrowed_audit")
        self.assertTrue(classify_logging_filter_audit_relevance(f"{_AUDIT} AND severity>=ERROR").established)

    def test_and_of_audit_terms_still_includes_audit(self) -> None:
        self.assert_state(f"{_AUDIT} AND {_ACTIVITY}", "includes_audit")

    def test_narrowed_branch_of_or_does_not_beat_a_full_branch(self) -> None:
        self.assert_state(f"({_AUDIT} AND severity>=ERROR) OR {_ACTIVITY}", "includes_audit")
        self.assert_state(f'({_AUDIT} AND severity>=ERROR) OR resource.type="gce_instance"', "narrowed_audit")

    def test_terms_without_an_audit_signal_are_not_established(self) -> None:
        for filter_text in (
            'resource.type="gce_instance"',
            'resource.type="gce_instance" AND severity>=ERROR',
            'resource.type="gce_instance" OR severity>=ERROR',
            'NOT resource.type="gce_instance"',
            'textPayload:"cloudaudit.googleapis.com"',
        ):
            self.assert_state(filter_text, "no_audit_signal")
        self.assertFalse(classify_logging_filter_audit_relevance('resource.type="gce_instance"').established)

    def test_negated_audit_terms_exclude_the_stream(self) -> None:
        for filter_text in (
            f"NOT {_AUDIT}",
            f"-{_AUDIT}",
            f"NOT ({_AUDIT})",
            'logName!="cloudaudit.googleapis.com"',
            'logName!~"cloudaudit.googleapis.com"',
            f"{_AUDIT} AND NOT {_AUDIT}",
            f"{_AUDIT} AND -{_ACTIVITY}",
        ):
            self.assert_state(filter_text, "excludes_audit")
        self.assertFalse(classify_logging_filter_audit_relevance(f"NOT {_AUDIT}").established)

    def test_or_with_an_excluded_branch_is_not_established(self) -> None:
        self.assert_state(f'NOT {_AUDIT} OR resource.type="gce_instance"', "excludes_audit")

    def test_unsupported_negation_shapes_are_unknown(self) -> None:
        for filter_text in (
            f"NOT NOT {_AUDIT}",
            f"NOT ({_AUDIT} AND severity>=ERROR)",
        ):
            self.assert_state(filter_text, "unknown")

    def test_quoted_values_may_contain_operators_and_parentheses(self) -> None:
        self.assert_state(f'textPayload:"a ) OR (b AND not c" AND {_AUDIT}', "narrowed_audit")
        self.assert_state('textPayload:"logName:\\"cloudaudit.googleapis.com\\""', "no_audit_signal")

    def test_signals_are_reported_without_duplicates(self) -> None:
        relevance = classify_logging_filter_audit_relevance(
            f'{_ACTIVITY} OR {_DATA_ACCESS} OR resource.type="gce_firewall_rule"'
        )
        self.assertEqual(relevance.signals, (*_AUDIT_SIGNAL, 'resource.type="gce_firewall_rule"'))

    def test_unparseable_filters_are_unknown_with_a_reason(self) -> None:
        for filter_text in (
            f"{_AUDIT} AND (",
            f"({_AUDIT}",
            f"{_AUDIT})",
            f"{_AUDIT} AND",
            f"AND {_AUDIT}",
            "()",
            'SEARCH("audit")',
            "error",
            f"{_AUDIT} OR SEARCH(x)",
        ):
            with self.subTest(filter_text=filter_text):
                relevance = classify_logging_filter_audit_relevance(filter_text)
                self.assertEqual(relevance.state, "unknown")
                self.assertTrue(relevance.reasons)
                self.assertFalse(relevance.established)

    def test_mixed_and_or_without_parentheses_is_ambiguous(self) -> None:
        for filter_text in (
            f"{_AUDIT} AND severity>=ERROR OR {_ACTIVITY}",
            f"{_AUDIT} severity>=ERROR OR {_ACTIVITY}",
        ):
            relevance = classify_logging_filter_audit_relevance(filter_text)
            self.assertEqual(relevance.state, "unknown")
            self.assertIn("mixes AND and OR", relevance.reasons[0])
        self.assert_state(f"({_AUDIT} AND severity>=ERROR) OR {_ACTIVITY}", "includes_audit")


if __name__ == "__main__":
    unittest.main()
