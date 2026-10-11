"""Audit/security relevance matching for Cloud Logging filters.

``classify_logging_filter_audit_relevance`` parses a filter's boolean structure
and reports how it relates to the audit/security streams. Posture rules and
public-workload disruption paths share it so both judge a filter identically.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

_AUDIT_SECURITY_SIGNAL_DESCRIPTIONS = {
    "cloudaudit.googleapis.com": "matches Cloud Audit Logs",
    "google.cloud.audit.auditlog": "matches AuditLog proto payloads",
    "securitycenter.googleapis.com": "matches Security Command Center logs",
    "security_command_center": "matches Security Command Center logs",
    "securitycenter": "matches security center logs",
    'resource.type="gce_firewall_rule"': "matches firewall rule logs",
}

_AUDIT_SECURITY_FILTER_PATTERNS = (
    (
        "cloudaudit.googleapis.com",
        re.compile(
            r'logname\s*(?::|=|=~)\s*(?:"(?:projects/[^"/\s]+/logs/)?cloudaudit\.googleapis\.com(?:%2f[^"]+)?"|(?:projects/[^\s()/]+/logs/)?cloudaudit\.googleapis\.com(?:%2f[^\s()]+)?)'
        ),
    ),
    (
        "google.cloud.audit.auditlog",
        re.compile(
            r'protopayload\.@type\s*(?::|=|=~)\s*(?:"(?:type\.googleapis\.com/)?google\.cloud\.audit\.auditlog"|(?:type\.googleapis\.com/)?google\.cloud\.audit\.auditlog)(?=$|[\s)])'
        ),
    ),
    (
        "securitycenter.googleapis.com",
        re.compile(
            r'logname\s*(?::|=|=~)\s*(?:"(?:projects/[^"/\s]+/logs/)?securitycenter\.googleapis\.com(?:%2f[^"]+)?"|(?:projects/[^\s()/]+/logs/)?securitycenter\.googleapis\.com(?:%2f[^\s()]+)?)'
        ),
    ),
    (
        "security_command_center",
        re.compile(r'resource\.type\s*(?::|=|=~)\s*(?:"security_command_center"|security_command_center)(?=$|[\s)])'),
    ),
    (
        "securitycenter",
        re.compile(r'resource\.type\s*(?::|=|=~)\s*(?:"securitycenter"|securitycenter)(?=$|[\s)])'),
    ),
    (
        'resource.type="gce_firewall_rule"',
        re.compile(r'resource\.type\s*(?::|=|=~)\s*(?:"gce_firewall_rule"|gce_firewall_rule)(?=$|[\s)])'),
    ),
)


def normalize_logging_filter(filter_text: str) -> str:
    return " ".join(filter_text.lower().replace(chr(39), chr(34)).split())


def describe_audit_security_signal(signal: str) -> str:
    return _AUDIT_SECURITY_SIGNAL_DESCRIPTIONS.get(signal, f"matches {signal}")


LoggingFilterAuditRelevanceState = Literal[
    "all_logs",
    "includes_audit",
    "narrowed_audit",
    "no_audit_signal",
    "excludes_audit",
    "unknown",
]


@dataclass(frozen=True, slots=True)
class LoggingFilterAuditRelevance:
    """How a sink filter relates to the audit/security log streams.

    ``all_logs`` is an absent filter. ``includes_audit`` means a positive
    audit/security term exports the whole stream, and ``narrowed_audit`` means
    such a term is further restricted by other terms, so only part of the stream
    is exported. ``no_audit_signal`` and ``excludes_audit`` do not establish
    audit export, and ``unknown`` covers filters this classifier cannot parse
    or whose boolean precedence would be ambiguous.
    """

    state: LoggingFilterAuditRelevanceState
    signals: tuple[str, ...] = ()
    reasons: tuple[str, ...] = ()

    @property
    def established(self) -> bool:
        return self.state in {"all_logs", "includes_audit", "narrowed_audit"}


_COMPARISON_PATTERN = re.compile(
    r"""(?P<field>[a-z0-9_.@\[\]*]+)\s*(?P<op>=~|!~|!=|>=|<=|:|=|>|<)\s*"""
    r"""(?P<value>"(?:[^"\\]|\\.)*"|[^\s()]+)"""
)
_KEYWORD_PATTERN = re.compile(r"(and|or|not)(?=[\s()]|$)")

_Token = tuple[str, str]  # (kind, text) where kind is lp, rp, and, or, not, or cmp


class _FilterParseError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class _Node:
    state: Literal["includes", "narrowed", "none", "excludes", "unknown"]
    signals: tuple[str, ...] = ()
    reasons: tuple[str, ...] = ()
    fields: frozenset[str] = frozenset()
    audit_fields: frozenset[str] = frozenset()


def classify_logging_filter_audit_relevance(filter_text: str | None) -> LoggingFilterAuditRelevance:
    if filter_text is None or not filter_text.strip():
        return LoggingFilterAuditRelevance("all_logs")
    try:
        tokens = _tokenize(normalize_logging_filter(filter_text))
        parser = _Parser(tokens)
        node = parser.parse()
    except _FilterParseError as error:
        return LoggingFilterAuditRelevance("unknown", reasons=(str(error),))
    return _relevance_from_node(node)


def _relevance_from_node(node: _Node) -> LoggingFilterAuditRelevance:
    if node.state == "includes":
        return LoggingFilterAuditRelevance("includes_audit", node.signals)
    if node.state == "narrowed":
        return LoggingFilterAuditRelevance("narrowed_audit", node.signals)
    if node.state == "excludes":
        return LoggingFilterAuditRelevance("excludes_audit", node.signals)
    if node.state == "none":
        return LoggingFilterAuditRelevance("no_audit_signal")
    return LoggingFilterAuditRelevance("unknown", reasons=node.reasons)


def _tokenize(text: str) -> list[_Token]:
    tokens: list[_Token] = []
    position = 0
    while position < len(text):
        character = text[position]
        if character.isspace():
            position += 1
            continue
        if character == "(":
            tokens.append(("lp", character))
            position += 1
            continue
        if character == ")":
            tokens.append(("rp", character))
            position += 1
            continue
        if character == "-" and position + 1 < len(text) and not text[position + 1].isspace():
            tokens.append(("not", character))
            position += 1
            continue
        keyword = _KEYWORD_PATTERN.match(text, position)
        if keyword is not None:
            tokens.append((keyword.group(1), keyword.group(1)))
            position = keyword.end()
            continue
        comparison = _COMPARISON_PATTERN.match(text, position)
        if comparison is None:
            raise _FilterParseError(f"logging filter term at offset {position} is not a supported comparison")
        tokens.append(("cmp", comparison.group(0)))
        position = comparison.end()
    return tokens


class _Parser:
    def __init__(self, tokens: list[_Token]) -> None:
        self._tokens = tokens
        self._position = 0

    def parse(self) -> _Node:
        if not self._tokens:
            raise _FilterParseError("logging filter has no terms")
        node = self._expression()
        if self._position != len(self._tokens):
            raise _FilterParseError("logging filter has unbalanced parentheses or a dangling operator")
        return node

    def _peek(self) -> str | None:
        return self._tokens[self._position][0] if self._position < len(self._tokens) else None

    def _expression(self) -> _Node:
        operands = [self._term()]
        operators: set[str] = set()
        while True:
            kind = self._peek()
            if kind in {"and", "or"}:
                assert kind is not None
                operators.add(kind)
                self._position += 1
            elif kind in {"lp", "not", "cmp"}:
                operators.add("and")
            else:
                break
            operands.append(self._term())
        if len(operators) > 1:
            return _Node("unknown", reasons=("logging filter mixes AND and OR without parentheses",))
        if not operators:
            return operands[0]
        return _combine_or(operands) if operators == {"or"} else _combine_and(operands)

    def _term(self) -> _Node:
        kind = self._peek()
        if kind == "not":
            self._position += 1
            return _negate(self._term())
        if kind == "lp":
            self._position += 1
            node = self._expression()
            if self._peek() != "rp":
                raise _FilterParseError("logging filter has unbalanced parentheses")
            self._position += 1
            return node
        if kind == "cmp":
            text = self._tokens[self._position][1]
            self._position += 1
            return _comparison_node(text)
        raise _FilterParseError("logging filter has a dangling operator or empty group")


def _comparison_node(text: str) -> _Node:
    match = _COMPARISON_PATTERN.fullmatch(text)
    fields = frozenset({match.group("field")}) if match is not None else frozenset()
    signals = tuple(signal for signal, pattern in _AUDIT_SECURITY_FILTER_PATTERNS if pattern.fullmatch(text))
    if signals:
        return _Node("includes", signals, fields=fields, audit_fields=fields)
    positive = text.replace("!=", "=", 1).replace("!~", "=~", 1)
    if positive != text:
        negated = tuple(signal for signal, pattern in _AUDIT_SECURITY_FILTER_PATTERNS if pattern.fullmatch(positive))
        if negated:
            return _Node("excludes", negated, fields=fields, audit_fields=fields)
    return _Node("none", fields=fields)


def _negate(node: _Node) -> _Node:
    if node.state == "includes":
        return _Node("excludes", node.signals, fields=node.fields, audit_fields=node.audit_fields)
    if node.state == "narrowed":
        return _Node(
            "unknown",
            reasons=("logging filter negates a narrowed audit/security term",),
            fields=node.fields,
            audit_fields=node.audit_fields,
        )
    if node.state == "none":
        return node
    if node.state == "excludes":
        return _Node(
            "unknown",
            reasons=("logging filter double-negates an audit/security term",),
            fields=node.fields,
            audit_fields=node.audit_fields,
        )
    return node


def _merge_signals(nodes: list[_Node]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(signal for node in nodes for signal in node.signals))


def _merged(
    state: Literal["includes", "narrowed", "none", "excludes", "unknown"], nodes: list[_Node], picked: list[_Node]
) -> _Node:
    return _Node(
        state,
        _merge_signals(picked),
        fields=frozenset().union(*(node.fields for node in nodes)),
        audit_fields=frozenset().union(*(node.audit_fields for node in nodes)),
    )


def _first_unknown(nodes: list[_Node]) -> _Node | None:
    return next((node for node in nodes if node.state == "unknown"), None)


def _combine_or(nodes: list[_Node]) -> _Node:
    if any(node.state == "includes" for node in nodes):
        return _merged("includes", nodes, [node for node in nodes if node.state == "includes"])
    if any(node.state == "narrowed" for node in nodes):
        return _merged("narrowed", nodes, [node for node in nodes if node.state == "narrowed"])
    unknown = _first_unknown(nodes)
    if unknown is not None:
        return _unknown_node(nodes, unknown.reasons)
    if any(node.state == "excludes" for node in nodes):
        return _merged("excludes", nodes, [node for node in nodes if node.state == "excludes"])
    return _merged("none", nodes, [])


def _combine_and(nodes: list[_Node]) -> _Node:
    excluding = [node for node in nodes if node.state == "excludes"]
    if excluding:
        return _merged("excludes", nodes, excluding)
    unknown = _first_unknown(nodes)
    if unknown is not None:
        return _unknown_node(nodes, unknown.reasons)
    audit = [node for node in nodes if node.state in {"includes", "narrowed"}]
    if not audit:
        return _merged("none", nodes, [])
    others = [node for node in nodes if node.state == "none"]
    if any(node.audit_fields & other.fields for node in audit for other in others):
        return _unknown_node(
            nodes,
            ("logging filter constrains the same field as an audit/security term, so the intersection is unproven",),
        )
    if not others and all(node.state == "includes" for node in audit):
        return _merged("includes", nodes, audit)
    return _merged("narrowed", nodes, audit)


def _unknown_node(nodes: list[_Node], reasons: tuple[str, ...]) -> _Node:
    return _Node(
        "unknown",
        reasons=reasons,
        fields=frozenset().union(*(node.fields for node in nodes)),
        audit_fields=frozenset().union(*(node.audit_fields for node in nodes)),
    )
