"""Tests for config helpers."""

from __future__ import annotations

import pytest

from custom_components.adguard_rule_control.config_flow import normalize_base_url


def test_normalize_host() -> None:
    assert normalize_base_url("192.168.1.10", 3000, False) == "http://192.168.1.10:3000"


def test_normalize_host_with_port() -> None:
    assert normalize_base_url("192.168.1.10:3000", None, False) == "http://192.168.1.10:3000"


def test_normalize_url() -> None:
    assert normalize_base_url("https://adguard.example.com", None, True) == "https://adguard.example.com"


def test_remove_control_suffix() -> None:
    assert normalize_base_url("http://adguard.local:3000/control", None, False) == "http://adguard.local:3000"


def test_invalid_url() -> None:
    with pytest.raises(ValueError):
        normalize_base_url("", None, False)


def test_reject_credentials_embedded_in_url() -> None:
    with pytest.raises(ValueError):
        normalize_base_url("http://admin:secret@adguard.local:3000", None, False)


def test_normalize_ipv6_url() -> None:
    assert normalize_base_url("http://[fd00::10]:3000", None, False) == "http://[fd00::10]:3000"
