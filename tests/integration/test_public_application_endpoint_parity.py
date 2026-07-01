from __future__ import annotations

import unittest
from typing import Any

from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.gcp.normalizer import GcpNormalizer

_AWS_PUBLIC_APP_RULE_IDS = frozenset({"aws-lambda-public-invocation"})
_GCP_PUBLIC_APP_RULE_IDS = frozenset({"gcp-cloud-run-public-invoker", "gcp-cloud-functions-public-invoker"})
_AZURE_PUBLIC_APP_RULE_IDS = frozenset(
    {
        "azure-app-service-public-network-access-not-disabled",
        "azure-app-service-access-restrictions-not-default-deny",
        "azure-app-service-broad-access-restriction-allow",
        "azure-app-service-scm-access-unrestricted",
    }
)


def _aws_resource(
    address: str,
    resource_type: str,
    values: dict[str, Any],
    *,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address=address,
        mode="managed",
        resource_type=resource_type,
        name=address.rsplit(".", 1)[-1],
        provider_name="registry.terraform.io/hashicorp/aws",
        values=values,
        unknown_values=unknown_values or {},
    )


def _lambda_function_url(authorization_type: str) -> TerraformResource:
    return _aws_resource(
        "aws_lambda_function_url.worker",
        "aws_lambda_function_url",
        {
            "function_name": "worker",
            "function_url": "https://abc.lambda-url.us-east-1.on.aws/",
            "url_id": "abc",
            "authorization_type": authorization_type,
        },
    )


def _gcp_resource(
    address: str,
    resource_type: str,
    values: dict[str, object],
) -> TerraformResource:
    return TerraformResource(
        address=address,
        mode="managed",
        resource_type=resource_type,
        name=address.rsplit(".", 1)[-1],
        provider_name="registry.terraform.io/hashicorp/google",
        values=values,
    )


def _cloud_run_service(*, public_ingress: bool) -> TerraformResource:
    return _gcp_resource(
        "google_cloud_run_v2_service.api",
        "google_cloud_run_v2_service",
        {
            "name": "tfstride-api",
            "project": "tfstride-demo",
            "location": "us-central1",
            "ingress": "INGRESS_TRAFFIC_ALL" if public_ingress else "INGRESS_TRAFFIC_INTERNAL_ONLY",
            "template": [{"service_account": "tfstride-run@tfstride-demo.iam.gserviceaccount.com"}],
        },
    )


def _cloud_run_service_iam_member(member: str = "allUsers") -> TerraformResource:
    return _gcp_resource(
        "google_cloud_run_v2_service_iam_member.public_invoker",
        "google_cloud_run_v2_service_iam_member",
        {
            "name": "tfstride-api",
            "location": "us-central1",
            "role": "roles/run.invoker",
            "member": member,
        },
    )


def _cloud_function(*, public: bool) -> TerraformResource:
    return _gcp_resource(
        "google_cloudfunctions_function.fn",
        "google_cloudfunctions_function",
        {
            "name": "tfstride-fn",
            "project": "tfstride-demo",
            "region": "us-central1",
            "runtime": "python312",
            "trigger_http": public,
            "service_account_email": "tfstride-fn@tfstride-demo.iam.gserviceaccount.com",
        },
    )


def _cloud_function_iam_member(member: str = "allUsers") -> TerraformResource:
    return _gcp_resource(
        "google_cloudfunctions_function_iam_member.public_invoker",
        "google_cloudfunctions_function_iam_member",
        {
            "cloud_function": "tfstride-fn",
            "region": "us-central1",
            "role": "roles/cloudfunctions.invoker",
            "member": member,
        },
    )


def _azure_app(
    *,
    public_network: bool,
    site_config_overrides: dict[str, object] | None = None,
) -> TerraformResource:
    site_config: dict[str, object] = {"minimum_tls_version": "1.2"}
    if site_config_overrides:
        site_config.update(site_config_overrides)
    return TerraformResource(
        address="azurerm_linux_web_app.app",
        mode="managed",
        resource_type=AzureResourceType.LINUX_WEB_APP,
        name="app",
        provider_name="registry.terraform.io/hashicorp/azurerm",
        values={
            "id": "/subscriptions/example/resourceGroups/app/providers/Microsoft.Web/sites/app",
            "name": "app",
            "location": "eastus",
            "service_plan_id": "azurerm_service_plan.apps.id",
            "public_network_access_enabled": public_network,
            "site_config": [site_config],
            "identity": [
                {
                    "type": "SystemAssigned",
                    "principal_id": "principal-id",
                    "tenant_id": "tenant-id",
                    "identity_ids": [],
                }
            ],
        },
    )


def _aws_findings(resources: list[TerraformResource]):
    inventory = AwsNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        detect_trust_boundaries(inventory),
        rule_policy=RulePolicy(enabled_rule_ids=_AWS_PUBLIC_APP_RULE_IDS),
    )


def _gcp_findings(resources: list[TerraformResource]):
    inventory = GcpNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        detect_trust_boundaries(inventory),
        rule_policy=RulePolicy(enabled_rule_ids=_GCP_PUBLIC_APP_RULE_IDS),
    )


def _azure_findings(resources: list[TerraformResource]):
    inventory = AzureNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        detect_trust_boundaries(inventory),
        rule_policy=RulePolicy(enabled_rule_ids=_AZURE_PUBLIC_APP_RULE_IDS),
    )


def _rule_ids(findings) -> set[str]:
    return {finding.rule_id for finding in findings}


class PublicApplicationEndpointParityTests(unittest.TestCase):
    def test_public_application_endpoint_findings_are_pinned(self) -> None:
        self.assertEqual(
            _rule_ids(_aws_findings([_lambda_function_url("NONE")])),
            {"aws-lambda-public-invocation"},
        )
        self.assertEqual(
            _rule_ids(_gcp_findings([_cloud_run_service(public_ingress=True), _cloud_run_service_iam_member()])),
            {"gcp-cloud-run-public-invoker"},
        )
        self.assertEqual(
            _rule_ids(_gcp_findings([_cloud_function(public=True), _cloud_function_iam_member()])),
            {"gcp-cloud-functions-public-invoker"},
        )
        self.assertEqual(
            _rule_ids(_azure_findings([_azure_app(public_network=True)])),
            {
                "azure-app-service-public-network-access-not-disabled",
                "azure-app-service-access-restrictions-not-default-deny",
            },
        )

    def test_public_application_endpoint_safe_posture_is_quiet(self) -> None:
        self.assertEqual(_aws_findings([_lambda_function_url("AWS_IAM")]), [])
        self.assertEqual(
            _gcp_findings([_cloud_run_service(public_ingress=False), _cloud_run_service_iam_member()]),
            [],
        )
        self.assertEqual(
            _gcp_findings(
                [
                    _cloud_function(public=True),
                    _cloud_function_iam_member(member="serviceAccount:caller@example.iam.gserviceaccount.com"),
                ]
            ),
            [],
        )
        self.assertEqual(_azure_findings([_azure_app(public_network=False)]), [])

    def test_provider_specific_public_endpoint_controls_are_preserved(self) -> None:
        azure_findings = _azure_findings(
            [
                _azure_app(
                    public_network=True,
                    site_config_overrides={
                        "ip_restriction_default_action": "Deny",
                        "ip_restriction": [
                            {
                                "name": "internet",
                                "priority": 100,
                                "action": "Allow",
                                "ip_address": "0.0.0.0/0",
                            }
                        ],
                        "scm_use_main_ip_restriction": True,
                    },
                )
            ]
        )

        self.assertEqual(
            _rule_ids(azure_findings),
            {
                "azure-app-service-public-network-access-not-disabled",
                "azure-app-service-broad-access-restriction-allow",
                "azure-app-service-scm-access-unrestricted",
            },
        )


if __name__ == "__main__":
    unittest.main()
