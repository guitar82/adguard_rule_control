"""Tests for rule generation."""

from __future__ import annotations

import pytest

from custom_components.adguard_rule_control.const import TARGET_CLIENT_NAME, TARGET_IPV4, TARGET_IPV6, TARGET_MAC
from custom_components.adguard_rule_control.models import ClientTarget, RuleControl
from custom_components.adguard_rule_control.rule_builder import (
    RuleBuilderError,
    add_client_modifier,
    generate_rules_for_control,
    normalize_mac,
    preview_control,
    validate_comment_label,
)


def test_global_rule() -> None:
    control = RuleControl("id", "Block", ("||example.com^",))
    assert generate_rules_for_control(control) == ["||example.com^"]


def test_ipv4_client() -> None:
    target = ClientTarget("TV", TARGET_IPV4, "192.168.1.25")
    assert add_client_modifier("||youtube.com^", target) == "||youtube.com^$client='192.168.1.25'"


def test_ipv6_client() -> None:
    target = ClientTarget("Laptop", TARGET_IPV6, "2001:db8::1")
    assert add_client_modifier("||example.com^", target) == "||example.com^$client='2001:db8::1'"


def test_mac_address() -> None:
    target = ClientTarget("Console", TARGET_MAC, "AA-BB-CC-DD-EE-FF")
    assert add_client_modifier("||games.example^", target) == "||games.example^$client='aa:bb:cc:dd:ee:ff'"
    assert normalize_mac("aabb.ccdd.eeff") == "aa:bb:cc:dd:ee:ff"


def test_client_name() -> None:
    target = ClientTarget("Kid Laptop", TARGET_CLIENT_NAME, "Kid Laptop")
    assert add_client_modifier("||social.example^", target) == "||social.example^$client='Kid Laptop'"


def test_existing_rule_modifiers() -> None:
    target = ClientTarget("TV", TARGET_IPV4, "192.168.1.25")
    assert add_client_modifier("||youtube.com^$important", target) == "||youtube.com^$important,client='192.168.1.25'"


def test_allow_rule() -> None:
    target = ClientTarget("TV", TARGET_IPV4, "192.168.1.25")
    assert add_client_modifier("@@||allowed.example.com^", target) == "@@||allowed.example.com^$client='192.168.1.25'"


def test_invalid_newline() -> None:
    with pytest.raises(RuleBuilderError):
        generate_rules_for_control(RuleControl("id", "Bad", ("||a^\n||b^",)))


def test_invalid_marker_injection() -> None:
    with pytest.raises(RuleBuilderError):
        generate_rules_for_control(RuleControl("id", "Bad", ("! ADGUARD RULE CONTROL START",)))


def test_invalid_client_modifier_injection() -> None:
    with pytest.raises(RuleBuilderError):
        generate_rules_for_control(RuleControl("id", "Bad", ("||a^$client='1.2.3.4'",)))


def test_deduplication() -> None:
    control = RuleControl("id", "Block", ("||example.com^", "||example.com^"))
    assert generate_rules_for_control(control) == ["||example.com^"]


def test_preview_control() -> None:
    assert preview_control(RuleControl("id", "Block", ("||example.com^",))) == [
        "! ADGUARD RULE CONTROL START",
        "! Rule Control: Block",
        "||example.com^",
        "! ADGUARD RULE CONTROL END",
    ]


def test_invalid_comment_label() -> None:
    with pytest.raises(RuleBuilderError):
        validate_comment_label("Bad\nName", "Display name")
