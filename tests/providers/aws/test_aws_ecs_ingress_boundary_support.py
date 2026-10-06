from __future__ import annotations

import unittest
from copy import deepcopy
from dataclasses import replace
from types import MappingProxyType
from unittest.mock import patch

from tests.helpers.inventory import inventory_with_resources
from tests.helpers.paths import FIXTURES_DIR
from tests.providers.aws.test_aws_ecs_forwarding_associations import _rule as _listener_rule
from tests.providers.aws.test_aws_ecs_public_ingress import _get, _plan_resources, _resources, _rule
from tfstride.analysis.boundaries.core import collect_boundary_contributions, default_boundary_contributors
from tfstride.analysis.preparation import PreparedAnalysis, prepare_analysis
from tfstride.analysis.relationships import RelationshipOutcome
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.app import TfStride
from tfstride.models import BoundaryType, ResourceInventory, TerraformResource
from tfstride.providers.aws.analysis_indexes import aws_analysis_indexes, build_aws_analysis_indexes
from tfstride.providers.aws.boundaries import AwsBoundaryContributor
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.reporting.json_report import build_json_report_payload

EDGE = (BoundaryType.INTERNET_TO_SERVICE, "internet", "aws_lb.public")


def _prepare_inventory(inventory: ResourceInventory) -> PreparedAnalysis:
    return prepare_analysis(
        inventory,
        rule_set=StrideRuleEngine().rule_set_for("aws"),
        provider_extension_factory=build_aws_analysis_indexes,
        provider_boundary_contributor_factories=(AwsBoundaryContributor,),
    )


def _prepare(resources: list[TerraformResource]) -> PreparedAnalysis:
    return _prepare_inventory(AwsNormalizer().normalize(deepcopy(resources)))


def _assessed_support(prepared: PreparedAnalysis):
    return tuple(support for support in prepared.boundary_supports[EDGE] if support.assessment is not None)


def _second_listener(resources: list[TerraformResource]) -> TerraformResource:
    listener = deepcopy(_get(resources, "aws_lb_listener.https"))
    listener.address = "aws_lb_listener.alternate"
    listener.name = "alternate"
    listener.values["port"] = 8443
    _get(resources, "aws_security_group.alb").values["ingress"].append(_rule(8443, cidr="0.0.0.0/0"))
    resources.append(listener)
    return listener


class AwsEcsIngressBoundarySupportTests(unittest.TestCase):
    def test_crossing_preserves_full_assessment_and_standalone_presentation(self) -> None:
        prepared = _prepare(_resources())
        (support,) = _assessed_support(prepared)
        original = (
            aws_analysis_indexes(prepared.indexes, prepared.inventory)
            .ecs_public_ingress["aws_ecs_service.app"][0]
            .relationship
        )

        self.assertIs(support.assessment, original)
        self.assertEqual(support.assessment_scope, "path_crossing")
        self.assertEqual(original.target_address, "aws_ecs_service.app")
        boundary = next(item for item in prepared.boundaries if item.target == EDGE[2])
        self.assertEqual(boundary.identifier, "internet-to-service:internet->aws_lb.public")
        (legacy_support,) = [item for item in prepared.boundary_supports[EDGE] if item.assessment is None]
        self.assertEqual(
            (support.description, support.rationale), (legacy_support.description, legacy_support.rationale)
        )
        with self.assertRaises(TypeError):
            prepared.boundary_supports[EDGE] = ()

    def test_multiple_listeners_retain_separate_traffic_and_evidence(self) -> None:
        resources = _resources()
        _second_listener(resources)
        prepared = _prepare(resources)
        assessments = [item.assessment for item in _assessed_support(prepared)]
        self.assertEqual(len(assessments), 2)
        self.assertEqual({item.traffic_scope[0].from_port for item in assessments}, {443, 8443})
        self.assertEqual(
            {
                evidence.address
                for item in assessments
                for evidence in item.evidence_sources
                if evidence.evidence_type == "load_balancer_listener"
            },
            {"aws_lb_listener.https", "aws_lb_listener.alternate"},
        )
        for ordering in (list(reversed(resources)), resources[3:] + resources[:3]):
            self.assertEqual(_prepare(ordering).boundary_supports, prepared.boundary_supports)

    def test_services_sharing_an_alb_keep_their_own_support(self) -> None:
        resources = _resources()
        other_group = deepcopy(_get(resources, "aws_lb_target_group.app"))
        other_group.address = "aws_lb_target_group.other"
        other_group.name = "other"
        other_service = deepcopy(_get(resources, "aws_ecs_service.app"))
        other_service.address = "aws_ecs_service.other"
        other_service.name = "other"
        other_service.values["load_balancer"][0]["target_group_arn"] = other_group.address
        resources.extend([other_group, other_service])
        _second_listener(resources).values["default_action"][0]["target_group_arn"] = other_group.address
        prepared = _prepare(resources)
        assessments = [item.assessment for item in _assessed_support(prepared)]
        self.assertEqual(len(assessments), 2)
        self.assertEqual(
            {item.target_address for item in assessments}, {"aws_ecs_service.app", "aws_ecs_service.other"}
        )
        for item in assessments:
            group = "aws_lb_target_group.other" if item.target_address.endswith(".other") else "aws_lb_target_group.app"
            self.assertIn(group, item.resource_scope.resource_addresses)
        self.assertEqual(_prepare(list(reversed(resources))).boundary_supports, prepared.boundary_supports)

    def test_conditional_forwarding_alternatives_are_not_merged(self) -> None:
        resources = _resources()
        _get(resources, "aws_lb_listener.https").values["default_action"] = [{"type": "fixed-response"}]
        resources.extend([_listener_rule("app", 10, "/app/*"), _listener_rule("other", 20, "/other/*")])
        prepared = _prepare(resources)
        assessments = [item.assessment for item in _assessed_support(prepared)]
        self.assertEqual(len(assessments), 2)
        self.assertEqual(len({item.remaining_conditions for item in assessments}), 2)
        self.assertTrue(all(len(item.remaining_conditions) == 1 for item in assessments))
        self.assertEqual(_prepare(list(reversed(resources))).boundary_supports, prepared.boundary_supports)

    def test_blocked_unknown_and_missing_forwarding_leave_standalone_boundary(self) -> None:
        for state in ("blocked", "unknown", "missing_listener", "standalone"):
            with self.subTest(state=state):
                resources = _resources()
                if state == "blocked":
                    _get(resources, "aws_security_group.tasks").values["ingress"] = [
                        _rule(9090, peer="aws_security_group.alb")
                    ]
                elif state == "unknown":
                    _get(resources, "aws_ecs_service.app").unknown_values = {
                        "network_configuration": [{"security_groups": True}]
                    }
                elif state == "missing_listener":
                    resources = [item for item in resources if item.resource_type != "aws_lb_listener"]
                else:
                    resources = [item for item in resources if item.resource_type in {"aws_lb", "aws_security_group"}]
                prepared = _prepare(resources)
                self.assertEqual(_assessed_support(prepared), ())
                self.assertTrue(
                    any(
                        item.identifier == "internet-to-service:internet->aws_lb.public" for item in prepared.boundaries
                    )
                )

    def test_repreparation_discards_stale_ingress_support(self) -> None:
        prepared = _prepare(_resources())
        inventory = prepared.inventory
        refreshed_inventory = inventory_with_resources(
            inventory,
            (item for item in inventory.resources if item.resource_type != "aws_lb_listener"),
        )
        refreshed = _prepare_inventory(refreshed_inventory)
        self.assertEqual(len(_assessed_support(prepared)), 1)
        self.assertEqual(_assessed_support(refreshed), ())

    def test_unrelated_alb_gets_no_ecs_path_support(self) -> None:
        resources = _resources()
        other = deepcopy(_get(resources, "aws_lb.public"))
        other.address = "aws_lb.unrelated"
        other.name = "unrelated"
        resources.append(other)
        prepared = _prepare(resources)
        self.assertEqual(len(_assessed_support(prepared)), 1)
        other_support = prepared.boundary_supports[(EDGE[0], "internet", other.address)]
        self.assertTrue(all(item.assessment is None for item in other_support))

    def test_non_established_assessments_are_not_promoted_if_present_in_index(self) -> None:
        prepared = _prepare(_resources())
        original_indexes = aws_analysis_indexes(prepared.indexes, prepared.inventory)
        (ingress,) = original_indexes.ecs_public_ingress["aws_ecs_service.app"]
        for outcome in (RelationshipOutcome.UNKNOWN, RelationshipOutcome.NOT_ESTABLISHED):
            with self.subTest(outcome=outcome):
                altered = replace(ingress, relationship=replace(ingress.relationship, outcome=outcome))
                indexes = replace(
                    original_indexes, ecs_public_ingress=MappingProxyType({"aws_ecs_service.app": (altered,)})
                )
                with patch("tfstride.providers.aws.boundaries.aws_analysis_indexes", return_value=indexes):
                    contributions = collect_boundary_contributions(
                        prepared.inventory,
                        prepared.indexes,
                        contributors=default_boundary_contributors((AwsBoundaryContributor(),)),
                    )
                self.assertTrue(all(item.assessment is None for item in contributions.supports(*EDGE)))

    def test_plan_ingestion_retains_support_and_report_output_parity(self) -> None:
        prepared = _prepare(_plan_resources(_resources(), {}))
        self.assertEqual(len(_assessed_support(prepared)), 1)
        path = FIXTURES_DIR / "aws" / "sample_aws_ecs_fargate_plan.json"
        with patch("tfstride.providers.aws.boundaries._contribute_ecs_ingress_support"):
            before = build_json_report_payload(TfStride().analyze_plan(path))
        after = build_json_report_payload(TfStride().analyze_plan(path))
        self.assertEqual(after["trust_boundaries"], before["trust_boundaries"])
        self.assertEqual(after["findings"], before["findings"])


if __name__ == "__main__":
    unittest.main()
