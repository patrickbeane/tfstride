from __future__ import annotations

import unittest

from tests.providers.aws.test_aws_network_telemetry_rules import (
    _ALL_RULE_IDS as AWS_NETWORK_TELEMETRY_RULE_IDS,
)
from tests.providers.aws.test_aws_network_telemetry_rules import (
    _INCOMPLETE_TRAFFIC_RULE as AWS_INCOMPLETE_TRAFFIC_RULE,
)
from tests.providers.aws.test_aws_network_telemetry_rules import (
    _MISSING as AWS_MISSING,
)
from tests.providers.aws.test_aws_network_telemetry_rules import (
    _MISSING_DESTINATION_RULE as AWS_MISSING_DESTINATION_RULE,
)
from tests.providers.aws.test_aws_network_telemetry_rules import (
    _MISSING_VPC_FLOW_LOG_RULE as AWS_MISSING_VPC_FLOW_LOG_RULE,
)
from tests.providers.aws.test_aws_network_telemetry_rules import (
    _findings as _aws_findings,
)
from tests.providers.aws.test_aws_network_telemetry_rules import (
    _flow_log as _aws_flow_log,
)
from tests.providers.aws.test_aws_network_telemetry_rules import (
    _vpc as _aws_vpc,
)
from tests.providers.azure.test_azure_network_telemetry_rules import (
    _ALL_RULE_IDS as AZURE_NETWORK_TELEMETRY_RULE_IDS,
)
from tests.providers.azure.test_azure_network_telemetry_rules import (
    _DISABLED_FLOW_LOG_RULE as AZURE_DISABLED_FLOW_LOG_RULE,
)
from tests.providers.azure.test_azure_network_telemetry_rules import (
    _INSUFFICIENT_RETENTION_RULE as AZURE_INSUFFICIENT_RETENTION_RULE,
)
from tests.providers.azure.test_azure_network_telemetry_rules import (
    _MISSING as AZURE_MISSING,
)
from tests.providers.azure.test_azure_network_telemetry_rules import (
    _MISSING_DESTINATION_RULE as AZURE_MISSING_DESTINATION_RULE,
)
from tests.providers.azure.test_azure_network_telemetry_rules import (
    _MISSING_FLOW_LOG_RULE as AZURE_MISSING_FLOW_LOG_RULE,
)
from tests.providers.azure.test_azure_network_telemetry_rules import (
    _findings as _azure_findings,
)
from tests.providers.azure.test_azure_network_telemetry_rules import (
    _flow_log as _azure_flow_log,
)
from tests.providers.azure.test_azure_network_telemetry_rules import (
    _network_security_group as _azure_network_security_group,
)
from tests.providers.gcp.test_gcp_network_telemetry_rules import (
    _ALL_RULE_IDS as GCP_NETWORK_TELEMETRY_RULE_IDS,
)
from tests.providers.gcp.test_gcp_network_telemetry_rules import (
    _INCOMPLETE_CAPTURE_RULE as GCP_INCOMPLETE_CAPTURE_RULE,
)
from tests.providers.gcp.test_gcp_network_telemetry_rules import (
    _MISSING_FLOW_LOG_RULE as GCP_MISSING_FLOW_LOG_RULE,
)
from tests.providers.gcp.test_gcp_network_telemetry_rules import (
    _findings as _gcp_findings,
)
from tests.providers.gcp.test_gcp_network_telemetry_rules import (
    _flow_log_config as _gcp_flow_log_config,
)
from tests.providers.gcp.test_gcp_network_telemetry_rules import (
    _subnetwork as _gcp_subnetwork,
)
from tfstride.providers.aws.rules import AWS_RULE_GROUP_IDS
from tfstride.providers.azure.rules import AZURE_RULE_GROUP_IDS
from tfstride.providers.gcp.rules import GCP_RULE_GROUP_IDS

NETWORK_TELEMETRY_RULE_IDS_BY_PROVIDER = {
    "aws": frozenset(AWS_NETWORK_TELEMETRY_RULE_IDS),
    "gcp": frozenset(GCP_NETWORK_TELEMETRY_RULE_IDS),
    "azure": frozenset(AZURE_NETWORK_TELEMETRY_RULE_IDS),
}


def _flatten(rule_groups: tuple[tuple[str, ...], ...]) -> frozenset[str]:
    return frozenset(rule_id for rule_group in rule_groups for rule_id in rule_group)


def _rule_ids(findings) -> frozenset[str]:
    return frozenset(finding.rule_id for finding in findings)


class NetworkTelemetryPostureParityTests(unittest.TestCase):
    def test_network_telemetry_rule_families_are_registered(self) -> None:
        self.assertLessEqual(NETWORK_TELEMETRY_RULE_IDS_BY_PROVIDER["aws"], _flatten(AWS_RULE_GROUP_IDS))
        self.assertLessEqual(NETWORK_TELEMETRY_RULE_IDS_BY_PROVIDER["gcp"], _flatten(GCP_RULE_GROUP_IDS))
        self.assertLessEqual(NETWORK_TELEMETRY_RULE_IDS_BY_PROVIDER["azure"], _flatten(AZURE_RULE_GROUP_IDS))

    def test_missing_network_telemetry_findings_are_pinned_by_provider(self) -> None:
        aws_findings = _aws_findings([_aws_vpc()], AWS_MISSING_VPC_FLOW_LOG_RULE)
        gcp_findings = _gcp_findings([_gcp_subnetwork()], GCP_MISSING_FLOW_LOG_RULE)
        azure_findings = _azure_findings([_azure_network_security_group()], AZURE_MISSING_FLOW_LOG_RULE)

        self.assertEqual(_rule_ids(aws_findings), frozenset({AWS_MISSING_VPC_FLOW_LOG_RULE}))
        self.assertEqual(_rule_ids(gcp_findings), frozenset({GCP_MISSING_FLOW_LOG_RULE}))
        self.assertEqual(_rule_ids(azure_findings), frozenset({AZURE_MISSING_FLOW_LOG_RULE}))

    def test_incomplete_network_telemetry_control_findings_are_pinned_by_provider(self) -> None:
        aws_findings = _aws_findings(
            [
                _aws_vpc(),
                _aws_flow_log(
                    traffic_type="REJECT",
                    destination_type="s3",
                    destination=AWS_MISSING,
                    log_group_name=AWS_MISSING,
                ),
            ],
            AWS_INCOMPLETE_TRAFFIC_RULE,
            AWS_MISSING_DESTINATION_RULE,
        )
        gcp_findings = _gcp_findings(
            [_gcp_subnetwork(_gcp_flow_log_config(flow_sampling=0.5))],
            GCP_INCOMPLETE_CAPTURE_RULE,
        )
        azure_findings = _azure_findings(
            [
                _azure_network_security_group(),
                _azure_flow_log(
                    enabled=False,
                    storage_account_id=AZURE_MISSING,
                    retention_policy=[{"enabled": True, "days": 3}],
                ),
            ],
            AZURE_DISABLED_FLOW_LOG_RULE,
            AZURE_MISSING_DESTINATION_RULE,
            AZURE_INSUFFICIENT_RETENTION_RULE,
        )

        self.assertEqual(
            _rule_ids(aws_findings),
            frozenset({AWS_INCOMPLETE_TRAFFIC_RULE, AWS_MISSING_DESTINATION_RULE}),
        )
        self.assertEqual(_rule_ids(gcp_findings), frozenset({GCP_INCOMPLETE_CAPTURE_RULE}))
        self.assertEqual(
            _rule_ids(azure_findings),
            frozenset(
                {
                    AZURE_DISABLED_FLOW_LOG_RULE,
                    AZURE_MISSING_DESTINATION_RULE,
                    AZURE_INSUFFICIENT_RETENTION_RULE,
                }
            ),
        )

    def test_complete_network_telemetry_posture_is_quiet_across_providers(self) -> None:
        aws_findings = _aws_findings([_aws_vpc(), _aws_flow_log()], *AWS_NETWORK_TELEMETRY_RULE_IDS)
        gcp_findings = _gcp_findings(
            [_gcp_subnetwork(_gcp_flow_log_config())],
            *GCP_NETWORK_TELEMETRY_RULE_IDS,
        )
        azure_findings = _azure_findings(
            [_azure_network_security_group(), _azure_flow_log()],
            *AZURE_NETWORK_TELEMETRY_RULE_IDS,
        )

        self.assertEqual(aws_findings, [])
        self.assertEqual(gcp_findings, [])
        self.assertEqual(azure_findings, [])

    def test_provider_specific_network_telemetry_semantics_are_preserved(self) -> None:
        aws_findings = _aws_findings(
            [_aws_vpc(), _aws_flow_log(vpc_id=AWS_MISSING, subnet_id="subnet-private")],
            AWS_MISSING_VPC_FLOW_LOG_RULE,
        )
        gcp_findings = _gcp_findings(
            [_gcp_subnetwork(_gcp_flow_log_config(metadata="EXCLUDE_ALL_METADATA"))],
            GCP_INCOMPLETE_CAPTURE_RULE,
        )
        azure_findings = _azure_findings(
            [
                _azure_network_security_group(),
                _azure_flow_log(target_id=AZURE_MISSING, unknown_values={"network_security_group_id": True}),
            ],
            AZURE_MISSING_FLOW_LOG_RULE,
        )

        self.assertEqual(_rule_ids(aws_findings), frozenset({AWS_MISSING_VPC_FLOW_LOG_RULE}))
        self.assertIn("subnet-private", aws_findings[0].evidence[1].values[-1])
        self.assertEqual(_rule_ids(gcp_findings), frozenset({GCP_INCOMPLETE_CAPTURE_RULE}))
        self.assertEqual(azure_findings, [])


if __name__ == "__main__":
    unittest.main()
