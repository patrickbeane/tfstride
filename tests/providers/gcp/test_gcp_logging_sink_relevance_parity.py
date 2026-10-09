"""Characterize how sink-filter audit relevance is judged in two places.

The posture rule (`gcp-logging-sink-audit-export-incomplete`) and the public
Cloud Run sink-disruption path each decide whether a sink filter exports audit
or security logs, using different matchers. This table pins the current answer
of each for a set of representative filters so later changes to a shared
classifier move the baseline deliberately.
"""

from __future__ import annotations

import unittest
from dataclasses import dataclass

from tests.providers.gcp.test_gcp_audit_rules import _LOGGING_SINK_RULE, _evaluate
from tests.providers.gcp.test_gcp_cloud_run_logging_sink_audit_telemetry_disruption_paths import (
    _cloud_run,
    _normalize,
    _project_member,
    _sink,
)

_ACTIVITY = 'logName="projects/tfstride-demo/logs/cloudaudit.googleapis.com%2Factivity"'
_DATA_ACCESS = 'logName="projects/tfstride-demo/logs/cloudaudit.googleapis.com%2Fdata_access"'


@dataclass(frozen=True)
class _Case:
    name: str
    filter_text: str | None
    # The posture rule stays quiet: it treats the filter as exporting audit logs.
    posture_accepts: bool
    # The disruption path is established: the filter is proven audit-relevant.
    disruption_established: bool


_CASES = (
    _Case("single term", 'logName:"cloudaudit.googleapis.com"', True, True),
    _Case("exact log name", _ACTIVITY, True, True),
    _Case(
        "audit auditlog payload type",
        'protoPayload.@type="type.googleapis.com/google.cloud.audit.AuditLog"',
        True,
        True,
    ),
    _Case("no filter exports everything", None, True, True),
    _Case("non-audit filter", 'resource.type="gce_instance"', False, False),
    # Rows below are the disagreements this baseline exists to expose. For the
    # OR / AND / parenthesized / unparseable rows the disruption matcher is too
    # strict; for the NOT and dash-negated rows the posture matcher is too
    # lenient, because it counts a negated audit term as an audit signal.
    _Case("OR of audit terms", f"{_ACTIVITY} OR {_DATA_ACCESS}", True, False),
    _Case("audit AND severity", 'logName:"cloudaudit.googleapis.com" AND severity>=ERROR', True, False),
    _Case(
        "audit OR unrelated term", 'logName:"cloudaudit.googleapis.com" OR resource.type="gce_instance"', True, False
    ),
    _Case("parenthesized single term", '(logName:"cloudaudit.googleapis.com")', True, False),
    _Case("NOT audit", 'NOT logName:"cloudaudit.googleapis.com"', True, False),
    _Case("dash-negated audit", '-logName:"cloudaudit.googleapis.com"', True, False),
    _Case("unparseable", 'logName:"cloudaudit.googleapis.com" AND (', True, False),
)


def _posture_accepts(filter_text: str | None) -> bool:
    findings = _evaluate([_sink(filter_text=filter_text)], _LOGGING_SINK_RULE)
    return not findings


def _disruption_established(filter_text: str | None) -> bool:
    _inventory, _workload, _sink_target, facts = _normalize(
        _cloud_run(),
        _sink(filter_text=filter_text),
        _project_member(role="roles/logging.admin"),
    )
    return bool(facts.cloud_run_logging_sink_audit_telemetry_disruption_paths)


class GcpLoggingSinkRelevanceParityBaselineTests(unittest.TestCase):
    def test_filter_relevance_baseline(self) -> None:
        for case in _CASES:
            with self.subTest(case=case.name):
                self.assertEqual(_posture_accepts(case.filter_text), case.posture_accepts)
                self.assertEqual(_disruption_established(case.filter_text), case.disruption_established)

    def test_baseline_disagreements_are_the_known_ones(self) -> None:
        disagreements = sorted(case.name for case in _CASES if case.posture_accepts != case.disruption_established)
        self.assertEqual(
            disagreements,
            [
                "NOT audit",
                "OR of audit terms",
                "audit AND severity",
                "audit OR unrelated term",
                "dash-negated audit",
                "parenthesized single term",
                "unparseable",
            ],
        )
