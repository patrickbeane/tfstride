from __future__ import annotations

import unittest
from typing import Any

from tests.providers.gcp.normalizer_support import _terraform_resource
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.rules import GCP_RULE_GROUP_IDS

_MUTABLE_TAGS_RULE = "gcp-artifact-registry-docker-tags-mutable"
_ENCRYPTION_RULE = "gcp-artifact-registry-customer-managed-encryption-missing"
_SCANNING_RULE = "gcp-artifact-registry-vulnerability-scanning-disabled"
_ARTIFACT_REGISTRY_RULE_IDS = (_MUTABLE_TAGS_RULE, _ENCRYPTION_RULE, _SCANNING_RULE)
_MISSING = object()


def _repository(
    *,
    name: str = "images",
    format: object = _MISSING,
    kms_key_name: object = _MISSING,
    docker_config: object = _MISSING,
    vulnerability_scanning_config: object = _MISSING,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    values: dict[str, Any] = {
        "name": name,
        "project": "tfstride-demo",
        "location": "us-central1",
        "repository_id": name,
    }
    if format is not _MISSING:
        values["format"] = format
    if kms_key_name is not _MISSING:
        values["kms_key_name"] = kms_key_name
    if docker_config is not _MISSING:
        values["docker_config"] = docker_config
    if vulnerability_scanning_config is not _MISSING:
        values["vulnerability_scanning_config"] = vulnerability_scanning_config
    return _terraform_resource(
        f"google_artifact_registry_repository.{name}",
        "google_artifact_registry_repository",
        values,
        unknown_values=unknown_values,
    )


def _evaluate(resources: list[TerraformResource], *rule_ids: str):
    inventory = GcpNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids or _ARTIFACT_REGISTRY_RULE_IDS)),
    )


def _evidence(finding):
    return {item.key: item.values for item in finding.evidence}


class GcpArtifactRegistryRuleTests(unittest.TestCase):
    def test_artifact_registry_rules_are_registered(self) -> None:
        registered = {rule_id for group in GCP_RULE_GROUP_IDS for rule_id in group}
        self.assertTrue(set(_ARTIFACT_REGISTRY_RULE_IDS).issubset(registered))

    def test_mutable_docker_tags_are_detected(self) -> None:
        findings = _evaluate(
            [
                _repository(
                    format="DOCKER",
                    kms_key_name="projects/tfstride-demo/locations/us-central1/keyRings/app/cryptoKeys/images",
                    docker_config=[{"immutable_tags": False}],
                )
            ],
            _MUTABLE_TAGS_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_MUTABLE_TAGS_RULE])
        self.assertEqual(findings[0].severity.value, "medium")
        evidence = _evidence(findings[0])
        self.assertEqual(
            evidence["tag_mutability"],
            [
                "format=DOCKER",
                "docker_immutable_tags_state=disabled",
                "docker_immutable_tags=false",
                "docker_config.immutable_tags=False",
            ],
        )
        self.assertIn("mutable Artifact Registry Docker image tags", findings[0].rationale)

    def test_immutable_or_non_docker_tags_are_quiet(self) -> None:
        self.assertEqual(
            _evaluate(
                [_repository(format="DOCKER", docker_config=[{"immutable_tags": True}])],
                _MUTABLE_TAGS_RULE,
            ),
            [],
        )
        self.assertEqual(
            _evaluate(
                [_repository(format="MAVEN", docker_config=[{"immutable_tags": False}])],
                _MUTABLE_TAGS_RULE,
            ),
            [],
        )

    def test_unknown_docker_tag_posture_is_not_overclaimed(self) -> None:
        findings = _evaluate(
            [
                _repository(
                    format="DOCKER",
                    docker_config=[{"immutable_tags": False}],
                    unknown_values={"docker_config": True},
                )
            ],
            _MUTABLE_TAGS_RULE,
        )

        self.assertEqual(findings, [])

    def test_missing_customer_managed_encryption_is_detected_as_ownership_posture(self) -> None:
        findings = _evaluate(
            [_repository(format="DOCKER")],
            _ENCRYPTION_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_ENCRYPTION_RULE])
        self.assertEqual(findings[0].severity.value, "medium")
        self.assertIn("does not claim", findings[0].rationale)
        self.assertEqual(
            _evidence(findings[0])["encryption_ownership"],
            [
                "encryption_ownership_state=not_configured",
                "kms_key_name=unset",
                "finding_scope=customer-managed key ownership and control posture",
            ],
        )

    def test_customer_managed_encryption_is_quiet(self) -> None:
        findings = _evaluate(
            [_repository(kms_key_name="projects/tfstride-demo/locations/us-central1/keyRings/app/cryptoKeys/images")],
            _ENCRYPTION_RULE,
        )

        self.assertEqual(findings, [])

    def test_unknown_customer_managed_encryption_is_not_overclaimed(self) -> None:
        findings = _evaluate(
            [
                _repository(
                    kms_key_name="projects/tfstride-demo/locations/us-central1/keyRings/app/cryptoKeys/images",
                    unknown_values={"kms_key_name": True},
                )
            ],
            _ENCRYPTION_RULE,
        )

        self.assertEqual(findings, [])

    def test_explicitly_disabled_vulnerability_scanning_is_detected(self) -> None:
        findings = _evaluate(
            [
                _repository(
                    vulnerability_scanning_config=[
                        {
                            "enablement_config": "DISABLED",
                            "enablement_state": "SCANNING_DISABLED",
                            "enablement_state_reason": "Disabled by repository configuration",
                        }
                    ]
                )
            ],
            _SCANNING_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_SCANNING_RULE])
        self.assertEqual(findings[0].severity.value, "medium")
        evidence = _evidence(findings[0])
        self.assertEqual(
            evidence["vulnerability_scanning"],
            [
                "vulnerability_scanning_state=disabled",
                "vulnerability_scanning_config.enablement_config=DISABLED",
                "vulnerability_scanning_config.enablement_state=SCANNING_DISABLED",
                "vulnerability_scanning_config.enablement_state_reason=Disabled by repository configuration",
                "scanning_scope=repository vulnerability scanning configuration",
                "registry_level_scanning_absence=not_inferred",
            ],
        )
        self.assertIn("explicitly disables Artifact Registry vulnerability scanning", findings[0].rationale)

    def test_enabled_missing_or_unknown_scanning_is_quiet(self) -> None:
        self.assertEqual(
            _evaluate(
                [
                    _repository(
                        vulnerability_scanning_config=[
                            {"enablement_config": "INHERITED", "enablement_state": "SCANNING"}
                        ]
                    )
                ],
                _SCANNING_RULE,
            ),
            [],
        )
        self.assertEqual(_evaluate([_repository()], _SCANNING_RULE), [])
        self.assertEqual(
            _evaluate(
                [
                    _repository(
                        vulnerability_scanning_config=[{"enablement_config": "DISABLED"}],
                        unknown_values={"vulnerability_scanning_config": True},
                    )
                ],
                _SCANNING_RULE,
            ),
            [],
        )

    def test_explicitly_unsafe_postures_produce_only_their_provider_local_findings(self) -> None:
        findings = _evaluate(
            [
                _repository(
                    format="DOCKER",
                    docker_config=[{"immutable_tags": False}],
                    vulnerability_scanning_config=[{"enablement_config": "DISABLED"}],
                )
            ],
            *_ARTIFACT_REGISTRY_RULE_IDS,
        )

        self.assertEqual(
            {finding.rule_id for finding in findings},
            set(_ARTIFACT_REGISTRY_RULE_IDS),
        )
        self.assertTrue(
            all(finding.affected_resources == ["google_artifact_registry_repository.images"] for finding in findings)
        )


if __name__ == "__main__":
    unittest.main()
