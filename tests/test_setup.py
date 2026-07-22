"""Tests for integration reload behavior."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest

from custom_components.adguard_rule_control import (
    _async_remove_stale_entities,
    _async_update_listener,
)
from custom_components.adguard_rule_control.const import DOMAIN


@pytest.mark.asyncio
async def test_options_update_syncs_before_reload() -> None:
    manager = SimpleNamespace(async_sync=AsyncMock())
    config_entries = SimpleNamespace(async_reload=AsyncMock())
    hass = SimpleNamespace(data={DOMAIN: {"entry": manager}}, config_entries=config_entries)
    entry = SimpleNamespace(entry_id="entry")

    await _async_update_listener(hass, entry)

    manager.async_sync.assert_awaited_once()
    config_entries.async_reload.assert_awaited_once_with("entry")


def test_stale_control_entities_are_removed() -> None:
    hass = SimpleNamespace()
    entry = SimpleNamespace(entry_id="entry")
    controls = [SimpleNamespace(control_id="active", entity_enabled=True)]
    registry = SimpleNamespace(async_remove=MagicMock())
    entries = [
        SimpleNamespace(
            entity_id="switch.active",
            domain="switch",
            platform=DOMAIN,
            unique_id="entry_active",
        ),
        SimpleNamespace(
            entity_id="button.active_timer",
            domain="button",
            platform=DOMAIN,
            unique_id="entry_active_quick_block",
        ),
        SimpleNamespace(
            entity_id="switch.deleted",
            domain="switch",
            platform=DOMAIN,
            unique_id="entry_deleted",
        ),
        SimpleNamespace(
            entity_id="button.deleted_timer",
            domain="button",
            platform=DOMAIN,
            unique_id="entry_deleted_quick_block",
        ),
        SimpleNamespace(
            entity_id="sensor.foreign",
            domain="sensor",
            platform="another_integration",
            unique_id="entry_foreign",
        ),
    ]

    with (
        patch("custom_components.adguard_rule_control.er.async_get", return_value=registry),
        patch(
            "custom_components.adguard_rule_control.er.async_entries_for_config_entry",
            return_value=entries,
        ),
    ):
        _async_remove_stale_entities(hass, entry, controls)

    assert registry.async_remove.call_args_list == [
        call("switch.deleted"),
        call("button.deleted_timer"),
    ]


def test_disabled_control_entities_are_removed() -> None:
    hass = SimpleNamespace()
    entry = SimpleNamespace(entry_id="entry")
    controls = [SimpleNamespace(control_id="disabled", entity_enabled=False)]
    registry = SimpleNamespace(async_remove=MagicMock())
    entries = [
        SimpleNamespace(
            entity_id="switch.disabled",
            domain="switch",
            platform=DOMAIN,
            unique_id="entry_disabled",
        ),
    ]

    with (
        patch("custom_components.adguard_rule_control.er.async_get", return_value=registry),
        patch(
            "custom_components.adguard_rule_control.er.async_entries_for_config_entry",
            return_value=entries,
        ),
    ):
        _async_remove_stale_entities(hass, entry, controls)

    registry.async_remove.assert_called_once_with("switch.disabled")
