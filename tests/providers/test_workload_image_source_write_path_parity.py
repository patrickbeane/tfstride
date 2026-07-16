from __future__ import annotations

import unittest
from collections import Counter

from tests.providers.aws.test_aws_ecr_self_modification_rules import _repository as _aws_repository
from tests.providers.aws.test_aws_ecr_write_paths import (
    _REPOSITORY_ARN,
    _REPOSITORY_URL,
    _TASK_ROLE_ARN,
)
from tests.providers.aws.test_aws_ecr_write_paths import (
    _allow as _aws_allow,
)
from tests.providers.aws.test_aws_ecr_write_paths import (
    _role as _aws_role,
)
from tests.providers.aws.test_aws_ecr_write_paths import (
    _role_policy_attachment as _aws_role_policy_attachment,
)
from tests.providers.aws.test_aws_ecr_write_paths import (
    _task_definition as _aws_task_definition,
)
from tests.providers.azure.test_azure_acr_write_paths import (
    _registry as _azure_registry,
)
from tests.providers.azure.test_azure_acr_write_paths import (
    _role_assignment as _azure_role_assignment,
)
from tests.providers.azure.test_azure_acr_write_paths import (
    _web_app as _azure_web_app,
)
from tests.providers.gcp.normalizer_support import _terraform_resource
from tests.providers.gcp.test_gcp_artifact_registry_self_modification_rules import (
    _IMAGE as _GCP_IMAGE,
)
from tests.providers.gcp.test_gcp_artifact_registry_self_modification_rules import (
    _cloud_run as _gcp_cloud_run,
)
from tests.providers.gcp.test_gcp_artifact_registry_self_modification_rules import (
    _repository as _gcp_repository,
)
from tests.providers.gcp.test_gcp_artifact_registry_self_modification_rules import (
    _repository_iam_member as _gcp_repository_iam_member,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import Finding, TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.rules import AWS_RULE_GROUP_IDS
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.rules import AZURE_RULE_GROUP_IDS
from tfstride.providers.base import ProviderNormalizer
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_types import GcpResourceType
from tfstride.providers.gcp.rules import GCP_RULE_GROUP_IDS

AWS_WRITE_PATH_RULE = "aws-workload-can-modify-image-repository"
GCP_WRITE_PATH_RULE = "gcp-cloud-run-can-modify-image-repository"
AZURE_WRITE_PATH_RULE = "azure-app-service-can-modify-image-repository"

AWS_WRITE_PATH_RULE_IDS = frozenset({AWS_WRITE_PATH_RULE})
GCP_WRITE_PATH_RULE_IDS = frozenset({GCP_WRITE_PATH_RULE})
AZURE_WRITE_PATH_RULE_IDS = frozenset({AZURE_WRITE_PATH_RULE})
ALL_WRITE_PATH_RULE_IDS = AWS_WRITE_PATH_RULE_IDS | GCP_WRITE_PATH_RULE_IDS | AZURE_WRITE_PATH_RULE_IDS

_DIGEST = "sha256:" + "a" * 64


def _flatten(rule_groups: tuple[tuple[str, ...], ...]) -> frozenset[str]:
    return frozenset(rule_id for rule_group in rule_groups for rule_id in rule_group)


def _evaluate(
    normalizer: ProviderNormalizer,
    resources: list[TerraformResource],
) -> list[Finding]:
    inventory = normalizer.normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=ALL_WRITE_PATH_RULE_IDS),
    )


def _aws_unsafe_resources(*, image: str | None = None) -> list[TerraformResource]:
    return [
        _aws_repository(),
        _aws_role(
            "task",
            _TASK_ROLE_ARN,
            [_aws_allow("ecr:PutImage", _REPOSITORY_ARN)],
        ),
        _aws_task_definition(
            image=image or f"{_REPOSITORY_URL}:stable",
            execution_role_arn=None,
        ),
    ]


def _gcp_unsafe_resources(*, image: str | None = None) -> list[TerraformResource]:
    return [
        _gcp_repository(),
        _gcp_cloud_run(image=image or _GCP_IMAGE),
        _gcp_repository_iam_member(),
    ]


def _azure_unsafe_resources(*, image: str | None = None) -> list[TerraformResource]:
    return [
        _azure_registry(),
        _azure_web_app(image=image or "team/api:stable"),
        _azure_role_assignment(),
    ]


def _gcp_cloud_run_with_unresolved_identity() -> TerraformResource:
    return _terraform_resource(
        "google_cloud_run_v2_service.api",
        GcpResourceType.CLOUD_RUN_V2_SERVICE,
        {
            "name": "api",
            "location": "us-central1",
            "template": [
                {
                    "containers": [{"image": _GCP_IMAGE}],
                    "service_account": None,
                }
            ],
        },
        unknown_values={
            "template": [
                {
                    "service_account": True,
                }
            ]
        },
    )


class WorkloadImageSourceWritePathParityTests(unittest.TestCase):
    def test_workload_image_source_write_path_rule_families_are_registered(self) -> None:
        self.assertLessEqual(AWS_WRITE_PATH_RULE_IDS, _flatten(AWS_RULE_GROUP_IDS))
        self.assertLessEqual(GCP_WRITE_PATH_RULE_IDS, _flatten(GCP_RULE_GROUP_IDS))
        self.assertLessEqual(AZURE_WRITE_PATH_RULE_IDS, _flatten(AZURE_RULE_GROUP_IDS))

    def test_unpinned_image_with_write_capable_runtime_identity_is_detected(self) -> None:
        self.assertEqual(
            Counter(
                finding.rule_id
                for finding in _evaluate(
                    AwsNormalizer(),
                    _aws_unsafe_resources(),
                )
            ),
            Counter({AWS_WRITE_PATH_RULE: 1}),
        )
        self.assertEqual(
            Counter(
                finding.rule_id
                for finding in _evaluate(
                    GcpNormalizer(),
                    _gcp_unsafe_resources(),
                )
            ),
            Counter({GCP_WRITE_PATH_RULE: 1}),
        )
        self.assertEqual(
            Counter(
                finding.rule_id
                for finding in _evaluate(
                    AzureNormalizer(),
                    _azure_unsafe_resources(),
                )
            ),
            Counter({AZURE_WRITE_PATH_RULE: 1}),
        )

    def test_digest_pinned_images_are_quiet_across_providers(self) -> None:
        self.assertEqual(
            _evaluate(
                AwsNormalizer(),
                _aws_unsafe_resources(image=f"{_REPOSITORY_URL}@{_DIGEST}"),
            ),
            [],
        )
        self.assertEqual(
            _evaluate(
                GcpNormalizer(),
                _gcp_unsafe_resources(
                    image="us-central1-docker.pkg.dev/tfstride-demo/images/api@" + _DIGEST,
                ),
            ),
            [],
        )
        self.assertEqual(
            _evaluate(
                AzureNormalizer(),
                _azure_unsafe_resources(image=f"team/api@{_DIGEST}"),
            ),
            [],
        )

    def test_read_only_pull_identities_are_quiet_across_providers(self) -> None:
        aws_findings = _evaluate(
            AwsNormalizer(),
            [
                _aws_repository(),
                _aws_role(
                    "task",
                    _TASK_ROLE_ARN,
                    [_aws_allow("ecr:BatchGetImage", _REPOSITORY_ARN)],
                ),
                _aws_task_definition(execution_role_arn=None),
            ],
        )
        gcp_findings = _evaluate(
            GcpNormalizer(),
            [
                _gcp_repository(),
                _gcp_cloud_run(),
                _gcp_repository_iam_member(role="roles/artifactregistry.reader"),
            ],
        )
        azure_findings = _evaluate(
            AzureNormalizer(),
            [
                _azure_registry(),
                _azure_web_app(),
                _azure_role_assignment(role_name="AcrPull"),
            ],
        )

        self.assertEqual(aws_findings, [])
        self.assertEqual(gcp_findings, [])
        self.assertEqual(azure_findings, [])

    def test_unresolved_relationship_data_does_not_become_an_access_claim(self) -> None:
        incomplete_aws_policy = _evaluate(
            AwsNormalizer(),
            [
                _aws_repository(),
                _aws_role(
                    "task",
                    _TASK_ROLE_ARN,
                    [_aws_allow("ecr:PutImage", _REPOSITORY_ARN)],
                ),
                _aws_role_policy_attachment(
                    _TASK_ROLE_ARN,
                    "arn:aws:iam::aws:policy/ExternalEcrPolicy",
                ),
                _aws_task_definition(execution_role_arn=None),
            ],
        )
        unmodeled_gcp_repository = _evaluate(
            GcpNormalizer(),
            [
                _gcp_cloud_run(),
                _gcp_repository_iam_member(),
            ],
        )
        unresolved_gcp_identity = _evaluate(
            GcpNormalizer(),
            [
                _gcp_repository(),
                _gcp_cloud_run_with_unresolved_identity(),
                _gcp_repository_iam_member(),
            ],
        )
        unresolved_azure_assignment = _evaluate(
            AzureNormalizer(),
            [
                _azure_registry(),
                _azure_web_app(),
                _azure_role_assignment(
                    role_name=None,
                    unknown_values={"role_definition_name": True},
                ),
            ],
        )

        self.assertEqual(incomplete_aws_policy, [])
        self.assertEqual(unmodeled_gcp_repository, [])
        self.assertEqual(unresolved_gcp_identity, [])
        self.assertEqual(unresolved_azure_assignment, [])

    def test_provider_findings_do_not_leak_across_inventories(self) -> None:
        findings_by_provider = {
            "aws": _evaluate(AwsNormalizer(), _aws_unsafe_resources()),
            "gcp": _evaluate(GcpNormalizer(), _gcp_unsafe_resources()),
            "azure": _evaluate(AzureNormalizer(), _azure_unsafe_resources()),
        }
        expected_rule_by_provider = {
            "aws": AWS_WRITE_PATH_RULE,
            "gcp": GCP_WRITE_PATH_RULE,
            "azure": AZURE_WRITE_PATH_RULE,
        }

        for provider, findings in findings_by_provider.items():
            with self.subTest(provider=provider):
                self.assertEqual(
                    [finding.rule_id for finding in findings],
                    [expected_rule_by_provider[provider]],
                )
                self.assertTrue(all(finding.rule_id.startswith(f"{provider}-") for finding in findings))


if __name__ == "__main__":
    unittest.main()
