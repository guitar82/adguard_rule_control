"""Tests for integration reload behavior."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from custom_components.adguard_rule_control import _async_update_listener
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
