from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional


@dataclass
class PatternRule:
    name: str
    regex: str
    severity: str
    _compiled: re.Pattern


@dataclass
class RuleMatch:
    rule_name: str
    severity: str
    value_redacted: str


def redact(text: str) -> str:
    value = text.strip()
    if not value:
        return value
    if len(value) <= 6:
        return "*" * len(value)
    return f"{value[:4]}...{value[-2:]}"


def load_pattern_rules(data: Dict) -> List[PatternRule]:
    rules: List[PatternRule] = []
    for item in data.get("patterns", []):
        try:
            name = str(item["name"])
            regex = str(item["regex"])
            severity = str(item.get("severity", "low"))
            rules.append(PatternRule(name=name, regex=regex, severity=severity, _compiled=re.compile(regex)))
        except Exception:
            continue
    return rules


def collect_exceptions(data: Dict) -> Dict[str, List[str]]:
    exceptions = data.get("exceptions", {})
    return {
        "hosts": [str(x) for x in exceptions.get("hosts", [])],
        "regexes": [str(x) for x in exceptions.get("regexes", [])],
    }


def match_patterns(payload_text: str, rules: Iterable[PatternRule]) -> List[RuleMatch]:
    matches: List[RuleMatch] = []
    for rule in rules:
        for m in rule._compiled.finditer(payload_text):
            if m.groups():
                raw = m.group(1)
            else:
                raw = m.group(0)
            matches.append(RuleMatch(rule_name=rule.name, severity=rule.severity, value_redacted=redact(raw)))
    return matches


def ignored_by_exception(src_ip: str, dst_ip: str, payload: str, exceptions: Dict[str, List[str]]) -> bool:
    if src_ip in exceptions.get("hosts", []) or dst_ip in exceptions.get("hosts", []):
        return True
    for expr in exceptions.get("regexes", []):
        try:
            if re.search(expr, payload):
                return True
        except re.error:
            continue
    return False


def min_severity(matches: List[RuleMatch]) -> Optional[str]:
    if not matches:
        return None
    order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    return max(matches, key=lambda x: order.get(x.severity, 1)).severity
