"""Diagnostics for AdGuard Rule Control."""

from __future__ import annotations

from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import CONF_PASSWORD
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
        "controls": [
            {
                "control_id": control.control_id,
                "display_name": control.display_name,
                "kind": control.kind,
                "enabled": manager.state_for(control.control_id),
                "temporary_until": manager.temporary_until_for(control.control_id),
                "generated_rule_count": len(control.rules),
                "blocked_service_count": len(control.blocked_service_ids),
            }
            for control in manager.controls
        ],
    }
