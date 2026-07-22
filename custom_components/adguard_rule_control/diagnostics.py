"""Diagnostics for AdGuard Rule Control."""

from __future__ import annotations

from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import CONF_PASSWORD, DOMAIN
from .coordinator import get_manager


async def async_get_config_entry_diagnostics(hass: HomeAssistant, entry: ConfigEntry) -> dict[str, Any]:
    """Return sanitized diagnostics."""
    manager = get_manager(hass, entry)
    data = dict(entry.data)
    data.pop(CONF_PASSWORD, None)
    return {
        "entry": data,
        "control_count": len(manager.controls),
        "connected": manager.connected,
        "last_error": manager.last_error,
        "last_sync": manager.last_sync,
        "managed_rule_count": manager.managed_rule_count,
    }
