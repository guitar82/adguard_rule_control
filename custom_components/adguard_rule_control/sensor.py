"""Sensor platform for AdGuard Rule Control."""

from __future__ import annotations

from homeassistant.components.sensor import SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .coordinator import AdGuardRuleControlManager, get_manager


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback) -> None:
    """Set up diagnostic sensors."""
    manager = get_manager(hass, entry)
    async_add_entities(
        [
            AdGuardRuleControlManagedRuleCountSensor(manager, entry),
            AdGuardRuleControlLastSyncSensor(manager, entry),
        ]
    )


class _BaseAdGuardRuleControlSensor(SensorEntity):
    _attr_has_entity_name = True

    def __init__(self, manager: AdGuardRuleControlManager, entry: ConfigEntry, suffix: str) -> None:
        self._manager = manager
        self._attr_unique_id = f"{entry.entry_id}_{suffix}"
        self._attr_device_info = {
            "identifiers": {(DOMAIN, entry.entry_id)},
            "name": "AdGuard Rule Control",
            "manufacturer": "AdGuard Rule Control",
        }

    @property
    def available(self) -> bool:
        return self._manager.available

    async def async_added_to_hass(self) -> None:
        self.async_on_remove(self._manager.async_add_listener(self._handle_manager_update))

    @callback
    def _handle_manager_update(self) -> None:
        self.async_write_ha_state()


class AdGuardRuleControlManagedRuleCountSensor(_BaseAdGuardRuleControlSensor):
    """Managed rule count sensor."""

    _attr_name = "Managed Rule Count"

    def __init__(self, manager: AdGuardRuleControlManager, entry: ConfigEntry) -> None:
        super().__init__(manager, entry, "managed_rule_count")

    @property
    def native_value(self) -> int:
        return self._manager.managed_rule_count


class AdGuardRuleControlLastSyncSensor(_BaseAdGuardRuleControlSensor):
    """Last successful sync sensor."""

    _attr_name = "Last Sync"

    def __init__(self, manager: AdGuardRuleControlManager, entry: ConfigEntry) -> None:
        super().__init__(manager, entry, "last_sync")

    @property
    def native_value(self) -> str | None:
        return self._manager.last_sync
