from __future__ import annotations

from tfstride.models import SecurityGroupRule


def parse_firewall_port_range(value: object) -> tuple[int | None, int | None]:
    text = str(value).strip()
    if not text:
        return (None, None)
    if "-" not in text:
        port = _optional_int(text)
        return (port, port)
    start, end = text.split("-", 1)
    return (_optional_int(start.strip()), _optional_int(end.strip()))


def _optional_int(value: str) -> int | None:
    try:
        return int(value)
    except ValueError:
        return None


def priority_value(value: object, *, default: int = 1000) -> int:
    if value is None:
        return default
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip())
    except ValueError:
        return default


def firewall_rules_overlap(left: SecurityGroupRule, right: SecurityGroupRule) -> bool:
    if not _firewall_protocols_overlap(left.protocol, right.protocol):
        return False
    left_ports = _firewall_port_range(left)
    right_ports = _firewall_port_range(right)
    if left_ports is None or right_ports is None:
        return True
    left_start, left_end = left_ports
    right_start, right_end = right_ports
    return left_start <= right_end and right_start <= left_end


def _firewall_protocols_overlap(left: str, right: str) -> bool:
    left_protocol = left.lower()
    right_protocol = right.lower()
    return left_protocol == "-1" or right_protocol == "-1" or left_protocol == right_protocol


def _firewall_port_range(rule: SecurityGroupRule) -> tuple[int, int] | None:
    if rule.protocol == "-1" or rule.from_port is None or rule.to_port is None:
        return None
    return (rule.from_port, rule.to_port)
