from __future__ import annotations

from typing import Any

from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.resource_facts.base import AwsBaseFacts, _bool_from_state


class AwsEdgeFacts(AwsBaseFacts):
    __slots__ = ()

    @property
    def load_balancer_type(self) -> str | None:
        return self.get(AwsResourceMetadata.LOAD_BALANCER_TYPE)

    @property
    def load_balancer_arn(self) -> str | None:
        return self.get(AwsResourceMetadata.LOAD_BALANCER_ARN)

    @property
    def load_balancer_target_group_arns(self) -> list[str]:
        return self.get(AwsResourceMetadata.LOAD_BALANCER_TARGET_GROUP_ARNS)

    @property
    def listener_arn(self) -> str | None:
        return self.get(AwsResourceMetadata.LISTENER_ARN)

    @property
    def load_balancer_listener_protocol(self) -> str | None:
        return self.get(AwsResourceMetadata.LOAD_BALANCER_LISTENER_PROTOCOL)

    @property
    def load_balancer_listener_certificate_arn(self) -> str | None:
        return self.get(AwsResourceMetadata.LOAD_BALANCER_LISTENER_CERTIFICATE_ARN)

    @property
    def load_balancer_listener_ssl_policy(self) -> str | None:
        return self.get(AwsResourceMetadata.LOAD_BALANCER_LISTENER_SSL_POLICY)

    @property
    def load_balancer_listener_tls_uncertainties(self) -> list[str]:
        return self.get(AwsResourceMetadata.LOAD_BALANCER_LISTENER_TLS_UNCERTAINTIES)

    @property
    def cloudfront_distribution_id(self) -> str | None:
        return self.get(AwsResourceMetadata.CLOUDFRONT_DISTRIBUTION_ID)

    @property
    def cloudfront_distribution_arn(self) -> str | None:
        return self.get(AwsResourceMetadata.CLOUDFRONT_DISTRIBUTION_ARN)

    @property
    def cloudfront_domain_name(self) -> str | None:
        return self.get(AwsResourceMetadata.CLOUDFRONT_DOMAIN_NAME)

    @property
    def cloudfront_enabled_state(self) -> str | None:
        return self.get(AwsResourceMetadata.CLOUDFRONT_ENABLED_STATE)

    @property
    def cloudfront_enabled(self) -> bool | None:
        return _bool_from_state(self.cloudfront_enabled_state)

    @property
    def cloudfront_ipv6_enabled_state(self) -> str | None:
        return self.get(AwsResourceMetadata.CLOUDFRONT_IPV6_ENABLED_STATE)

    @property
    def cloudfront_ipv6_enabled(self) -> bool | None:
        return _bool_from_state(self.cloudfront_ipv6_enabled_state)

    @property
    def cloudfront_http_version(self) -> str | None:
        return self.get(AwsResourceMetadata.CLOUDFRONT_HTTP_VERSION)

    @property
    def cloudfront_default_root_object(self) -> str | None:
        return self.get(AwsResourceMetadata.CLOUDFRONT_DEFAULT_ROOT_OBJECT)

    @property
    def cloudfront_aliases(self) -> list[str]:
        return self.get(AwsResourceMetadata.CLOUDFRONT_ALIASES)

    @property
    def cloudfront_web_acl_id(self) -> str | None:
        return self.get(AwsResourceMetadata.CLOUDFRONT_WEB_ACL_ID)

    @property
    def cloudfront_default_cache_behavior(self) -> dict[str, Any]:
        return self.get(AwsResourceMetadata.CLOUDFRONT_DEFAULT_CACHE_BEHAVIOR)

    @property
    def cloudfront_default_viewer_protocol_policy(self) -> str | None:
        return self.get(AwsResourceMetadata.CLOUDFRONT_DEFAULT_VIEWER_PROTOCOL_POLICY)

    @property
    def cloudfront_default_allowed_methods(self) -> list[str]:
        return self.get(AwsResourceMetadata.CLOUDFRONT_DEFAULT_ALLOWED_METHODS)

    @property
    def cloudfront_default_cached_methods(self) -> list[str]:
        return self.get(AwsResourceMetadata.CLOUDFRONT_DEFAULT_CACHED_METHODS)

    @property
    def cloudfront_ordered_cache_behaviors(self) -> list[dict[str, Any]]:
        return self.get(AwsResourceMetadata.CLOUDFRONT_ORDERED_CACHE_BEHAVIORS)

    @property
    def cloudfront_ordered_viewer_protocol_policies(self) -> list[str]:
        return self.get(AwsResourceMetadata.CLOUDFRONT_ORDERED_VIEWER_PROTOCOL_POLICIES)

    @property
    def cloudfront_origins(self) -> list[dict[str, Any]]:
        return self.get(AwsResourceMetadata.CLOUDFRONT_ORIGINS)

    @property
    def cloudfront_origin_ids(self) -> list[str]:
        return self.get(AwsResourceMetadata.CLOUDFRONT_ORIGIN_IDS)

    @property
    def cloudfront_origin_domain_names(self) -> list[str]:
        return self.get(AwsResourceMetadata.CLOUDFRONT_ORIGIN_DOMAIN_NAMES)

    @property
    def cloudfront_viewer_certificate(self) -> dict[str, Any]:
        return self.get(AwsResourceMetadata.CLOUDFRONT_VIEWER_CERTIFICATE)

    @property
    def cloudfront_viewer_certificate_source(self) -> str | None:
        return self.get(AwsResourceMetadata.CLOUDFRONT_VIEWER_CERTIFICATE_SOURCE)

    @property
    def cloudfront_default_certificate_state(self) -> str | None:
        return self.get(AwsResourceMetadata.CLOUDFRONT_DEFAULT_CERTIFICATE_STATE)

    @property
    def cloudfront_default_certificate(self) -> bool | None:
        return _bool_from_state(self.cloudfront_default_certificate_state)

    @property
    def cloudfront_minimum_protocol_version(self) -> str | None:
        return self.get(AwsResourceMetadata.CLOUDFRONT_MINIMUM_PROTOCOL_VERSION)

    @property
    def cloudfront_ssl_support_method(self) -> str | None:
        return self.get(AwsResourceMetadata.CLOUDFRONT_SSL_SUPPORT_METHOD)

    @property
    def cloudfront_acm_certificate_arn(self) -> str | None:
        return self.get(AwsResourceMetadata.CLOUDFRONT_ACM_CERTIFICATE_ARN)

    @property
    def cloudfront_iam_certificate_id(self) -> str | None:
        return self.get(AwsResourceMetadata.CLOUDFRONT_IAM_CERTIFICATE_ID)

    @property
    def cloudfront_logging_state(self) -> str | None:
        return self.get(AwsResourceMetadata.CLOUDFRONT_LOGGING_STATE)

    @property
    def cloudfront_logging_config(self) -> dict[str, Any]:
        return self.get(AwsResourceMetadata.CLOUDFRONT_LOGGING_CONFIG)

    @property
    def cloudfront_logging_bucket(self) -> str | None:
        return self.get(AwsResourceMetadata.CLOUDFRONT_LOGGING_BUCKET)

    @property
    def cloudfront_logging_prefix(self) -> str | None:
        return self.get(AwsResourceMetadata.CLOUDFRONT_LOGGING_PREFIX)

    @property
    def cloudfront_posture_uncertainties(self) -> list[str]:
        return self.get(AwsResourceMetadata.CLOUDFRONT_POSTURE_UNCERTAINTIES)

    @property
    def web_acl_id(self) -> str | None:
        return self.get(AwsResourceMetadata.WEB_ACL_ID)

    @property
    def web_acl_name(self) -> str | None:
        return self.get(AwsResourceMetadata.WEB_ACL_NAME)

    @property
    def web_acl_arn(self) -> str | None:
        return self.get(AwsResourceMetadata.WEB_ACL_ARN)

    @property
    def web_acl_scope(self) -> str | None:
        return self.get(AwsResourceMetadata.WEB_ACL_SCOPE)

    @property
    def web_acl_default_action(self) -> str | None:
        return self.get(AwsResourceMetadata.WEB_ACL_DEFAULT_ACTION)

    @property
    def web_acl_default_action_evidence(self) -> dict[str, Any]:
        return self.get(AwsResourceMetadata.WEB_ACL_DEFAULT_ACTION_EVIDENCE)

    @property
    def web_acl_rules(self) -> list[dict[str, Any]]:
        return self.get(AwsResourceMetadata.WEB_ACL_RULES)

    @property
    def web_acl_rule_names(self) -> list[str]:
        return self.get(AwsResourceMetadata.WEB_ACL_RULE_NAMES)

    @property
    def web_acl_association_resource_arn(self) -> str | None:
        return self.get(AwsResourceMetadata.WEB_ACL_ASSOCIATION_RESOURCE_ARN)

    @property
    def web_acl_association_web_acl_arn(self) -> str | None:
        return self.get(AwsResourceMetadata.WEB_ACL_ASSOCIATION_WEB_ACL_ARN)

    @property
    def edge_protection_posture_uncertainties(self) -> list[str]:
        return self.get(AwsResourceMetadata.EDGE_PROTECTION_POSTURE_UNCERTAINTIES)
