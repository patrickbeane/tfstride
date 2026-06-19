from __future__ import annotations

from tfstride.analysis.gcp.iam_inherited import GcpInheritedIamDetectors
from tfstride.analysis.gcp.iam_scoped import GcpScopedIamDetectors
from tfstride.analysis.gcp.iam_sensitive_resources import GcpSensitiveResourceIamDetectors
from tfstride.analysis.gcp.iam_service_account_keys import GcpServiceAccountKeyDetectors
from tfstride.analysis.gcp.iam_service_accounts import GcpServiceAccountIamDetectors


class GcpIamRuleDetectors(
    GcpSensitiveResourceIamDetectors,
    GcpServiceAccountIamDetectors,
    GcpServiceAccountKeyDetectors,
    GcpScopedIamDetectors,
    GcpInheritedIamDetectors,
):
    pass
