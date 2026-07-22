"""Tests for options-flow validation helpers."""

from __future__ import annotations

import pytest

from custom_components.adguard_rule_control.const import TARGET_IPV4, TARGET_MAC
from custom_components.adguard_rule_control.config_flow import _find_control_index
from custom_components.adguard_rule_control.presets import PRESET_CUSTOM, get_preset, preset_choices
from custom_components.adguard_rule_control.rule_builder import RuleBuilderError, validate_client_identifier, validate_rule


def test_add_client_target_ipv4_validation() -> None:
    assert validate_client_identifier(TARGET_IPV4, "192.168.1.25") == "192.168.1.25"


def test_invalid_ip_validation() -> None:
    with pytest.raises(RuleBuilderError):
        validate_client_identifier(TARGET_IPV4, "not-an-ip")


def test_invalid_mac_validation() -> None:
    with pytest.raises(RuleBuilderError):
        validate_client_identifier(TARGET_MAC, "not-a-mac")


def test_add_control_rule_validation() -> None:
    assert validate_rule("||example.com^") == "||example.com^"


def test_delete_control_options_shape() -> None:
    controls = [{"control_id": "one"}, {"control_id": "two"}]
    assert [control for control in controls if control["control_id"] != "one"] == [{"control_id": "two"}]


def test_find_control_index() -> None:
    controls = [{"control_id": "one"}, {"control_id": "two"}]
    assert _find_control_index(controls, "two") == 1


def test_move_control_options_shape() -> None:
    controls = [{"control_id": "one"}, {"control_id": "two"}]
    controls[0], controls[1] = controls[1], controls[0]
    assert [control["control_id"] for control in controls] == ["two", "one"]


def test_duplicate_control_options_shape() -> None:
    control = {"control_id": "one", "display_name": "Original"}
    duplicated = dict(control)
    duplicated["control_id"] = "two"
    duplicated["display_name"] = f"Copy of {duplicated['display_name']}"
    assert duplicated == {"control_id": "two", "display_name": "Copy of Original"}


def test_preset_choices_include_custom_and_youtube() -> None:
    choices = preset_choices()
    assert choices[PRESET_CUSTOM] == "Custom rules"
    assert choices["youtube"] == "Block YouTube"


def test_youtube_preset_prefills_rules() -> None:
    preset = get_preset("youtube")
    assert preset is not None
    assert preset.name == "Block YouTube"
    assert "||youtube.com^" in preset.rules
    assert preset.icon == "mdi:youtube"
