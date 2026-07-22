"""Tests for managed block replacement and sync behavior."""

from __future__ import annotations

import pytest

from custom_components.adguard_rule_control.const import MANAGED_END, MANAGED_START
from custom_components.adguard_rule_control.models import RuleControl
from custom_components.adguard_rule_control.rule_builder import (
    RuleBuilderError,
    build_managed_block,
    extract_managed_block,
    infer_active_control_ids,
    replace_managed_block,
)


def test_add_block_when_absent() -> None:
    block = build_managed_block([RuleControl("id", "Block", ("||example.com^",))])
    assert replace_managed_block(["||keep.com^"], block) == [
        "||keep.com^",
        MANAGED_START,
        "! Rule Control: Block",
        "||example.com^",
        MANAGED_END,
    ]


def test_replace_existing_block() -> None:
    current = ["||keep.com^", MANAGED_START, "||old.com^", MANAGED_END]
    block = build_managed_block([RuleControl("id", "New", ("||new.com^",))])
    assert replace_managed_block(current, block) == [
        "||keep.com^",
        MANAGED_START,
        "! Rule Control: New",
        "||new.com^",
        MANAGED_END,
    ]


def test_remove_block_when_no_controls_active() -> None:
    assert replace_managed_block(["||keep.com^", MANAGED_START, "||old.com^", MANAGED_END], []) == ["||keep.com^"]


def test_preserve_unrelated_rules() -> None:
    current = ["||a.com^", "! OTHER START", "||b.com^", "! OTHER END"]
    block = build_managed_block([RuleControl("id", "C", ("||c.com^",))])
    assert replace_managed_block(current, block)[:4] == current


def test_preserve_blocks_from_other_integrations() -> None:
    current = ["! OTHER INTEGRATION START", "||other.com^", "! OTHER INTEGRATION END"]
    assert replace_managed_block(current, []) == current


def test_reject_missing_end_marker() -> None:
    with pytest.raises(RuleBuilderError):
        replace_managed_block([MANAGED_START, "||old.com^"], [])


def test_reject_duplicate_markers() -> None:
    with pytest.raises(RuleBuilderError):
        replace_managed_block([MANAGED_START, "a", MANAGED_END, MANAGED_START, "b", MANAGED_END], [])


def test_extract_managed_block() -> None:
    assert extract_managed_block(["||keep.com^", MANAGED_START, "! Rule Control: A", "||a.com^", MANAGED_END]) == [
        "! Rule Control: A",
        "||a.com^",
    ]


def test_infer_active_control_ids() -> None:
    controls = [
        RuleControl("one", "One", ("||one.com^",)),
        RuleControl("two", "Two", ("||two.com^",)),
    ]
    rules = [MANAGED_START, "! Rule Control: One", "||one.com^", MANAGED_END]
    assert infer_active_control_ids(rules, controls) == {"one"}
