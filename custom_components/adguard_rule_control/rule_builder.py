"""Rule generation and managed block helpers."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable

from .const import (
    MANAGED_END,
    MANAGED_START,
    TARGET_CLIENT_NAME,
    TARGET_IPV4,
    TARGET_IPV6,
    TARGET_MAC,
)
from .models import ClientTarget, RuleControl


class RuleBuilderError(ValueError):
    """Raised when rule generation would be unsafe."""


_MAC_RE = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")
_CLIENT_RE = re.compile(r"^[A-Za-z0-9_. @:+-]{1,128}$")
_UNSAFE_CLIENT_CHARS_RE = re.compile(r"[\n\r',=$]")


def validate_comment_label(value: str, field_name: str = "Label") -> str:
    """Validate text used in managed-block comments."""
    value = value.strip()
    if not value:
        raise RuleBuilderError(f"{field_name} is required")
    if "\n" in value or "\r" in value or MANAGED_START in value or MANAGED_END in value:
        raise RuleBuilderError(f"{field_name} contains unsafe text")
    return value


def normalize_mac(value: str) -> str:
    """Normalize common MAC address formats to colon-separated lower case."""
    cleaned = value.strip().lower().replace("-", ":")
    if "." in cleaned and ":" not in cleaned:
        compact = cleaned.replace(".", "")
    else:
        compact = cleaned.replace(":", "")
    if len(compact) == 12 and all(char in "0123456789abcdef" for char in compact):
        cleaned = ":".join(compact[index : index + 2] for index in range(0, 12, 2))
    if not _MAC_RE.fullmatch(cleaned):
        raise RuleBuilderError("Invalid MAC address")
    return cleaned


def validate_client_identifier(identifier_type: str, value: str) -> str:
    """Validate and normalize a client identifier."""
    value = value.strip()
    if not value:
        raise RuleBuilderError("Client identifier is required")
    if MANAGED_START in value or MANAGED_END in value or "\n" in value or "\r" in value:
        raise RuleBuilderError("Client identifier contains unsafe text")

    if identifier_type == TARGET_IPV4:
        try:
            ip = ipaddress.ip_address(value)
        except ValueError as err:
            raise RuleBuilderError("Invalid IP address") from err
        if ip.version != 4:
            raise RuleBuilderError("Expected an IPv4 address")
        return str(ip)
    if identifier_type == TARGET_IPV6:
        try:
            ip = ipaddress.ip_address(value)
        except ValueError as err:
            raise RuleBuilderError("Invalid IP address") from err
        if ip.version != 6:
            raise RuleBuilderError("Expected an IPv6 address")
        return str(ip)
    if identifier_type == TARGET_MAC:
        return normalize_mac(value)
    if identifier_type == TARGET_CLIENT_NAME:
        if _UNSAFE_CLIENT_CHARS_RE.search(value) or not _CLIENT_RE.fullmatch(value):
            raise RuleBuilderError("Invalid AdGuard client name")
        return value
    raise RuleBuilderError("Unsupported client identifier type")


def validate_rule(rule: str) -> str:
    """Validate a single AdGuard rule."""
    rule = rule.strip()
    if not rule:
        raise RuleBuilderError("Rule cannot be empty")
    if "\n" in rule or "\r" in rule:
        raise RuleBuilderError("Rule cannot contain newlines")
    if MANAGED_START in rule or MANAGED_END in rule:
        raise RuleBuilderError("Rule cannot contain managed block markers")
    if "$client=" in rule or ",client=" in rule or "$client='" in rule or ",client='" in rule:
        raise RuleBuilderError("Rules cannot include a client modifier directly")
    return rule


def add_client_modifier(rule: str, target: ClientTarget) -> str:
    """Return rule with a safe AdGuard $client modifier."""
    rule = validate_rule(rule)
    client = validate_client_identifier(target.identifier_type, target.identifier_value)
    modifier = f"client='{client}'"
    if "$" in rule:
        base, modifiers = rule.split("$", 1)
        if not base or not modifiers:
            raise RuleBuilderError("Invalid rule modifier syntax")
        return f"{base}${modifiers},{modifier}"
    return f"{rule}${modifier}"


def generate_rules_for_control(control: RuleControl) -> list[str]:
    """Generate AdGuard rules for one configured control."""
    generated: list[str] = []
    for rule in control.rules:
        generated.append(add_client_modifier(rule, control.target) if control.target else validate_rule(rule))
    return _deduplicate(generated)


def build_managed_block(active_controls: Iterable[RuleControl]) -> list[str]:
    """Build the full managed rule block."""
    lines: list[str] = []
    seen_rules: set[str] = set()
    for control in active_controls:
        rules = generate_rules_for_control(control)
        if not rules:
            continue
        lines.append(f"! Rule Control: {validate_comment_label(control.display_name, 'Display name')}")
        if control.target:
            lines.append(f"! Target: {validate_comment_label(control.target.display_name, 'Target display name')}")
        for rule in rules:
            if rule in seen_rules:
                continue
            seen_rules.add(rule)
            lines.append(rule)
    if not lines:
        return []
    return [MANAGED_START, *lines, MANAGED_END]


def replace_managed_block(existing_rules: list[str], managed_rules: list[str]) -> list[str]:
    """Replace this integration's managed block while preserving all other rules."""
    start_indexes = [index for index, rule in enumerate(existing_rules) if rule.strip() == MANAGED_START]
    end_indexes = [index for index, rule in enumerate(existing_rules) if rule.strip() == MANAGED_END]
    if len(start_indexes) != len(end_indexes):
        raise RuleBuilderError("Malformed managed rule block markers")
    if len(start_indexes) > 1 or len(end_indexes) > 1:
        raise RuleBuilderError("Duplicate managed rule block markers")
    if start_indexes and end_indexes:
        start = start_indexes[0]
        end = end_indexes[0]
        if end <= start:
            raise RuleBuilderError("Malformed managed rule block marker order")
        preserved = [*existing_rules[:start], *existing_rules[end + 1 :]]
    else:
        preserved = list(existing_rules)

    preserved = _trim_outer_blank_lines(preserved)
    if not managed_rules:
        return preserved
    if preserved:
        return [*preserved, *managed_rules]
    return list(managed_rules)


def extract_managed_block(existing_rules: list[str]) -> list[str]:
    """Return this integration's managed block contents without markers."""
    start_indexes = [index for index, rule in enumerate(existing_rules) if rule.strip() == MANAGED_START]
    end_indexes = [index for index, rule in enumerate(existing_rules) if rule.strip() == MANAGED_END]
    if len(start_indexes) != len(end_indexes):
        raise RuleBuilderError("Malformed managed rule block markers")
    if len(start_indexes) > 1 or len(end_indexes) > 1:
        raise RuleBuilderError("Duplicate managed rule block markers")
    if not start_indexes:
        return []
    start = start_indexes[0]
    end = end_indexes[0]
    if end <= start:
        raise RuleBuilderError("Malformed managed rule block marker order")
    return existing_rules[start + 1 : end]


def infer_active_control_ids(existing_rules: list[str], controls: Iterable[RuleControl]) -> set[str]:
    """Infer active controls by matching generated rules in the current managed block."""
    block_rules = {
        rule.strip()
        for rule in extract_managed_block(existing_rules)
        if rule.strip() and not rule.strip().startswith("!")
    }
    active: set[str] = set()
    for control in controls:
        generated = set(generate_rules_for_control(control))
        if generated and generated.issubset(block_rules):
            active.add(control.control_id)
    return active


def preview_control(control: RuleControl) -> list[str]:
    """Return the generated managed-block preview for one control."""
    return build_managed_block([control])


def _deduplicate(lines: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for line in lines:
        if line not in seen:
            seen.add(line)
            result.append(line)
    return result


def _trim_outer_blank_lines(lines: list[str]) -> list[str]:
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return lines
