from __future__ import annotations

from typing import Any

from tfstride.providers.gcp.metadata import GcpResourceMetadata


class GcpEdgeFacts:
    __slots__ = ()

    @property
    def load_balancer_frontends(self) -> list[dict[str, Any]]:
        return self.get(GcpResourceMetadata.LOAD_BALANCER_FRONTENDS)

    @property
    def load_balancer_reachable_backends(self) -> list[dict[str, Any]]:
        return self.get(GcpResourceMetadata.LOAD_BALANCER_REACHABLE_BACKENDS)

    @property
    def load_balancer_backend_service_protocol(self) -> str | None:
        return self.get(GcpResourceMetadata.LOAD_BALANCER_BACKEND_SERVICE_PROTOCOL)

    @property
    def load_balancer_backend_service_load_balancing_scheme(self) -> str | None:
        return self.get(GcpResourceMetadata.LOAD_BALANCER_BACKEND_SERVICE_LOAD_BALANCING_SCHEME)

    @property
    def load_balancer_backend_service_security_policy(self) -> str | None:
        return self.get(GcpResourceMetadata.LOAD_BALANCER_BACKEND_SERVICE_SECURITY_POLICY)

    @property
    def load_balancer_backend_service_edge_security_policy(self) -> str | None:
        return self.get(GcpResourceMetadata.LOAD_BALANCER_BACKEND_SERVICE_EDGE_SECURITY_POLICY)

    @property
    def edge_protection_posture_uncertainties(self) -> list[str]:
        return self.get(GcpResourceMetadata.EDGE_PROTECTION_POSTURE_UNCERTAINTIES)

    @property
    def forwarding_rule_target(self) -> str | None:
        return self.get(GcpResourceMetadata.FORWARDING_RULE_TARGET)

    @property
    def forwarding_rule_load_balancing_scheme(self) -> str | None:
        return self.get(GcpResourceMetadata.FORWARDING_RULE_LOAD_BALANCING_SCHEME)

    @property
    def forwarding_rule_ip_address(self) -> str | None:
        return self.get(GcpResourceMetadata.FORWARDING_RULE_IP_ADDRESS)

    @property
    def forwarding_rule_ports(self) -> list[str]:
        return self.get(GcpResourceMetadata.FORWARDING_RULE_PORTS)

    @property
    def load_balancer_ssl_certificates(self) -> list[str]:
        return self.get(GcpResourceMetadata.LOAD_BALANCER_SSL_CERTIFICATES)

    @property
    def load_balancer_ssl_policy(self) -> str | None:
        return self.get(GcpResourceMetadata.LOAD_BALANCER_SSL_POLICY)

    @property
    def load_balancer_certificate_map(self) -> str | None:
        return self.get(GcpResourceMetadata.LOAD_BALANCER_CERTIFICATE_MAP)

    @property
    def ssl_policy_min_tls_version(self) -> str | None:
        return self.get(GcpResourceMetadata.SSL_POLICY_MIN_TLS_VERSION)

    @property
    def ssl_policy_profile(self) -> str | None:
        return self.get(GcpResourceMetadata.SSL_POLICY_PROFILE)

    @property
    def ssl_policy_custom_features(self) -> list[str]:
        return self.get(GcpResourceMetadata.SSL_POLICY_CUSTOM_FEATURES)

    @property
    def ssl_policy_enabled_features(self) -> list[str]:
        return self.get(GcpResourceMetadata.SSL_POLICY_ENABLED_FEATURES)

    @property
    def security_policy_name(self) -> str | None:
        return self.get(GcpResourceMetadata.SECURITY_POLICY_NAME)

    @property
    def security_policy_type(self) -> str | None:
        return self.get(GcpResourceMetadata.SECURITY_POLICY_TYPE)

    @property
    def security_policy_default_action(self) -> str | None:
        return self.get(GcpResourceMetadata.SECURITY_POLICY_DEFAULT_ACTION)

    @property
    def security_policy_rules(self) -> list[dict[str, Any]]:
        return self.get(GcpResourceMetadata.SECURITY_POLICY_RULES)

    @property
    def security_policy_rule_actions(self) -> list[str]:
        return self.get(GcpResourceMetadata.SECURITY_POLICY_RULE_ACTIONS)

    @property
    def managed_ssl_certificate_domains(self) -> list[str]:
        return self.get(GcpResourceMetadata.MANAGED_SSL_CERTIFICATE_DOMAINS)

    @property
    def managed_ssl_certificate_status(self) -> str | None:
        return self.get(GcpResourceMetadata.MANAGED_SSL_CERTIFICATE_STATUS)
