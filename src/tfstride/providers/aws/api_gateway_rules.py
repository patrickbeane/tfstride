from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    dedupe_addresses,
    evidence_item,
)
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding, NormalizedResource
from tfstride.providers.aws.resource_facts import AwsResourceFacts, aws_facts
from tfstride.providers.coercion import STATE_ENABLED

_AWS_API_GATEWAY_REST_API = "aws_api_gateway_rest_api"
_AWS_APIGATEWAYV2_API = "aws_apigatewayv2_api"
_AWS_WAFV2_WEB_ACL_ASSOCIATION = "aws_wafv2_web_acl_association"
_PUBLIC_API_GATEWAY_TYPES = (_AWS_API_GATEWAY_REST_API, _AWS_APIGATEWAYV2_API)
_PROTOCOL_TYPE_WEBSOCKET = "websocket"
_CORS_WILDCARD_ORIGIN = "*"


class AwsApiGatewayRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_cors_permissive(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for api in context.inventory.by_type(_AWS_APIGATEWAYV2_API):
            facts = aws_facts(api)
            if facts.api_gateway_public_endpoint_state != STATE_ENABLED:
                continue
            if _normalized_protocol_type(facts) == _PROTOCOL_TYPE_WEBSOCKET:
                continue
            if not _cors_allows_all_origins(facts.api_gateway_cors_configuration):
                continue
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=0,
                data_sensitivity=0,
                lateral_movement=1,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=dedupe_addresses([api.address]),
                    trust_boundary_id=None,
                    rationale=(
                        f"{api.display_name} is a public API Gateway HTTP API whose CORS "
                        "configuration allows all origins. Public APIs should reflect only "
                        "reviewed origins so untrusted browsers cannot call the endpoint."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_endpoint", _endpoint_evidence(api, facts)),
                        evidence_item("cors_configuration", _cors_evidence(facts)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_waf_missing(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        associations = list(context.inventory.by_type(_AWS_WAFV2_WEB_ACL_ASSOCIATION))
        if _has_unresolved_association_target(associations):
            return []

        associated_api_ids = _associated_api_ids(associations)
        findings: list[Finding] = []
        for api in context.inventory.by_type(*_PUBLIC_API_GATEWAY_TYPES):
            facts = aws_facts(api)
            if facts.api_gateway_public_endpoint_state != STATE_ENABLED:
                continue
            api_id = facts.api_gateway_api_id
            if not api_id or api_id in associated_api_ids:
                continue
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=0,
                data_sensitivity=0,
                lateral_movement=1,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=dedupe_addresses([api.address]),
                    trust_boundary_id=None,
                    rationale=(
                        f"{api.display_name} is a public API Gateway endpoint, but the "
                        "Terraform plan does not show a deterministic AWS WAFv2 Web ACL "
                        "association targeting it. Public edge traffic can reach the endpoint "
                        "without a modeled WAF policy."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_endpoint", _endpoint_evidence(api, facts)),
                        evidence_item(
                            "waf_association_coverage",
                            _waf_association_coverage_evidence(api, facts, associations),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_public_route_authorization_none(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for api in context.inventory.by_type(*_PUBLIC_API_GATEWAY_TYPES):
            facts = aws_facts(api)
            if facts.api_gateway_public_endpoint_state != STATE_ENABLED:
                continue
            if _rest_api_has_unresolved_openapi_body_only(api, facts):
                continue
            for resource_kind, route in _api_authorization_records(facts):
                if _normalized_authorization_type(route) != _AUTHORIZATION_NONE:
                    continue
                route_address = _record_string(route, "address")
                severity_reasoning = build_severity_reasoning(
                    internet_exposure=True,
                    privilege_breadth=2,
                    data_sensitivity=0,
                    lateral_movement=1,
                    blast_radius=1,
                )
                findings.append(
                    self._finding_factory.build(
                        rule_id=rule_id,
                        severity=severity_reasoning.severity,
                        affected_resources=dedupe_addresses([api.address, route_address or ""]),
                        trust_boundary_id=None,
                        rationale=(
                            f"{api.display_name} is publicly reachable and its modeled {resource_kind} uses "
                            "authorization type NONE. Requests to that method or route do not require an "
                            "API Gateway authorizer or IAM authorization."
                        ),
                        evidence=collect_evidence(
                            evidence_item("target_endpoint", _endpoint_evidence(api, facts)),
                            evidence_item(
                                "unauthenticated_method_or_route", _authorization_evidence(resource_kind, route)
                            ),
                        ),
                        severity_reasoning=severity_reasoning,
                    )
                )
        return findings

    def detect_stage_access_logs_missing(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for api in context.inventory.by_type(*_PUBLIC_API_GATEWAY_TYPES):
            facts = aws_facts(api)
            if facts.api_gateway_public_endpoint_state != STATE_ENABLED:
                continue
            for stage in facts.api_gateway_stages:
                if _record_string(stage, "access_log_destination_arn"):
                    continue
                if _stage_access_log_destination_is_unknown(stage, facts):
                    continue
                stage_address = _record_string(stage, "address")
                severity_reasoning = build_severity_reasoning(
                    internet_exposure=True,
                    privilege_breadth=0,
                    data_sensitivity=0,
                    lateral_movement=1,
                    blast_radius=1,
                )
                findings.append(
                    self._finding_factory.build(
                        rule_id=rule_id,
                        severity=severity_reasoning.severity,
                        affected_resources=dedupe_addresses([api.address, stage_address or ""]),
                        trust_boundary_id=None,
                        rationale=(
                            f"{api.display_name} is publicly reachable, but its modeled API Gateway stage does "
                            "not configure a resolved access-log destination. Requests may not have durable "
                            "stage-level request telemetry."
                        ),
                        evidence=collect_evidence(
                            evidence_item("target_endpoint", _endpoint_evidence(api, facts)),
                            evidence_item("stage_telemetry", _stage_telemetry_evidence(stage)),
                        ),
                        severity_reasoning=severity_reasoning,
                    )
                )
        return findings


_AUTHORIZATION_NONE = "none"
_ACCESS_LOG_UNKNOWN_SUFFIX = "access_log_settings"


def _rest_api_has_unresolved_openapi_body_only(api: NormalizedResource, facts: AwsResourceFacts) -> bool:
    return (
        api.resource_type == _AWS_API_GATEWAY_REST_API
        and facts.api_gateway_openapi_body_state == "unknown"
        and not facts.api_gateway_methods
    )


def _api_authorization_records(facts: AwsResourceFacts) -> tuple[tuple[str, Mapping[str, Any]], ...]:
    methods = (("REST method", method) for method in facts.api_gateway_methods)
    routes = (("v2 route", route) for route in facts.api_gateway_routes)
    return tuple((*methods, *routes))


def _normalized_authorization_type(record: Mapping[str, Any]) -> str | None:
    value = _record_string(record, "authorization_type")
    return value.lower() if value else None


def _record_string(record: Mapping[str, Any], key: str) -> str | None:
    value = record.get(key)
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value or None


def _authorization_evidence(resource_kind: str, route: Mapping[str, Any]) -> list[str]:
    values = [f"resource_kind={resource_kind}", "authorization_type=NONE"]
    if address := _record_string(route, "address"):
        values.append(f"address={address}")
    if resource_id := _record_string(route, "resource_id"):
        values.append(f"resource_id={resource_id}")
    if http_method := _record_string(route, "http_method"):
        values.append(f"http_method={http_method}")
    if route_key := _record_string(route, "route_key"):
        values.append(f"route_key={route_key}")
    return values


def _stage_access_log_destination_is_unknown(stage: Mapping[str, Any], facts: AwsResourceFacts) -> bool:
    stage_address = _record_string(stage, "address")
    if not stage_address:
        return True
    prefix = f"{stage_address}: "
    return any(
        uncertainty.startswith(prefix + _ACCESS_LOG_UNKNOWN_SUFFIX)
        for uncertainty in facts.api_gateway_posture_uncertainties
    )


def _stage_telemetry_evidence(stage: Mapping[str, Any]) -> list[str]:
    values = ["access_log_destination_arn is not configured"]
    if address := _record_string(stage, "address"):
        values.append(f"address={address}")
    if resource_type := _record_string(stage, "resource_type"):
        values.append(f"resource_type={resource_type}")
    if stage_name := _record_string(stage, "stage_name"):
        values.append(f"stage_name={stage_name}")
    if log_format := _record_string(stage, "access_log_format"):
        values.append(f"access_log_format={log_format}")
    return values


def _normalized_protocol_type(facts: AwsResourceFacts) -> str | None:
    value = facts.api_gateway_protocol_type
    return value.strip().lower() if value else None


def _cors_allows_all_origins(cors: Mapping[str, Any] | None) -> bool:
    if not isinstance(cors, Mapping):
        return False
    origins = cors.get("allow_origins")
    return isinstance(origins, (list, tuple)) and any(
        isinstance(origin, str) and origin.strip() == _CORS_WILDCARD_ORIGIN for origin in origins
    )


def _cors_evidence(facts: AwsResourceFacts) -> list[str]:
    cors = facts.api_gateway_cors_configuration
    values: list[str] = []
    if isinstance(cors, Mapping):
        origins = cors.get("allow_origins")
        if isinstance(origins, (list, tuple)) and origins:
            values.append("allow_origins=" + ", ".join(str(origin) for origin in origins))
        else:
            values.append("allow_origins is unset")
        allow_methods = cors.get("allow_methods")
        if isinstance(allow_methods, (list, tuple)) and allow_methods:
            values.append("allow_methods=" + ", ".join(str(method) for method in allow_methods))
        allow_headers = cors.get("allow_headers")
        if isinstance(allow_headers, (list, tuple)) and allow_headers:
            values.append("allow_headers=" + ", ".join(str(header) for header in allow_headers))
        allow_credentials = cors.get("allow_credentials")
        if allow_credentials is not None:
            values.append(f"allow_credentials={str(allow_credentials).lower()}")
        expose_headers = cors.get("expose_headers")
        if isinstance(expose_headers, (list, tuple)) and expose_headers:
            values.append("expose_headers=" + ", ".join(str(header) for header in expose_headers))
        max_age = cors.get("max_age")
        if max_age is not None:
            values.append(f"max_age={max_age}")
    values.append("CORS allow_origins reflects every origin for a public API")
    return values


def _endpoint_evidence(api: NormalizedResource, facts: AwsResourceFacts) -> list[str]:
    values = [f"address={api.address}", f"type={api.resource_type}"]
    if facts.api_gateway_api_id:
        values.append(f"api_id={facts.api_gateway_api_id}")
    if api.identifier:
        values.append(f"identifier={api.identifier}")
    if api.arn:
        values.append(f"arn={api.arn}")
    if facts.api_gateway_protocol_type:
        values.append(f"protocol_type={facts.api_gateway_protocol_type}")
    if facts.api_gateway_endpoint_types:
        values.append("endpoint_types=" + ",".join(facts.api_gateway_endpoint_types))
    if facts.api_gateway_api_endpoint:
        values.append(f"api_endpoint={facts.api_gateway_api_endpoint}")
    values.append(f"public_endpoint_state={facts.api_gateway_public_endpoint_state or 'unknown'}")
    values.append("public_exposure=true")
    values.extend(api.public_exposure_reasons)
    return values


def _associated_api_ids(associations: list[NormalizedResource]) -> frozenset[str]:
    api_ids: set[str] = set()
    for association in associations:
        resource_arn = aws_facts(association).web_acl_association_resource_arn
        api_id = _api_id_from_resource_arn(resource_arn)
        if api_id:
            api_ids.add(api_id)
    return frozenset(api_ids)


def _api_id_from_resource_arn(resource_arn: str | None) -> str | None:
    if not isinstance(resource_arn, str) or not resource_arn.strip():
        return None
    arn = resource_arn.strip()
    # arn:aws:execute-api:{region}:{account}:{api_id}
    if ":execute-api:" in arn:
        return _last_arn_segment(arn)
    # arn:aws:apigateway:{region}:{account}::/restapis/{api_id}/stages/{stage}
    if "/restapis/" in arn:
        return _segment_after(arn, "/restapis/")
    # arn:aws:apigateway:{region}:{account}::/apis/{api_id}/stages/{stage}
    if "/apis/" in arn:
        return _segment_after(arn, "/apis/")
    return None


def _last_arn_segment(arn: str) -> str | None:
    segment = arn.rsplit(":", 1)[-1].strip()
    return segment or None


def _segment_after(arn: str, marker: str) -> str | None:
    api_id = arn.split(marker, 1)[1].split("/", 1)[0].strip()
    return api_id or None


def _has_unresolved_association_target(associations: list[NormalizedResource]) -> bool:
    return any(
        aws_facts(association).web_acl_association_resource_arn is None
        and any(
            "resource_arn" in uncertainty
            for uncertainty in aws_facts(association).edge_protection_posture_uncertainties
        )
        for association in associations
    )


def _waf_association_coverage_evidence(
    api: NormalizedResource,
    facts: AwsResourceFacts,
    associations: list[NormalizedResource],
) -> list[str]:
    values = [f"target_api_id={facts.api_gateway_api_id}", "resolved_web_acl_association_count=0"]
    if associations:
        values.append(f"modeled_web_acl_association_count={len(associations)}")
        nonmatching_targets = sorted(
            resource_arn
            for association in associations
            if (resource_arn := aws_facts(association).web_acl_association_resource_arn)
            and _api_id_from_resource_arn(resource_arn) != facts.api_gateway_api_id
        )
        values.extend(f"nonmatching_association_target={arn}" for arn in nonmatching_targets)
    else:
        values.append("modeled_web_acl_association_count=0")
    return values
