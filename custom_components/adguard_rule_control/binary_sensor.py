"""Binary sensor platform for AdGuard Rule Control."""

from __future__ import annotations

from homeassistant.components.binary_sensor import BinarySensorDeviceClass, BinarySensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .coordinator import AdGuardRuleControlManager, get_manager


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback) -> None:
    """Set up diagnostic binary sensor."""
    async_add_entities([AdGuardRuleControlConnectedSensor(get_manager(hass, entry), entry)])


class AdGuardRuleControlConnectedSensor(BinarySensorEntity):
    """Reports whether AdGuard is reachable."""

    _attr_has_entity_name = True
    _attr_name = "Connected"
    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY

    def __init__(self, manager: AdGuardRuleControlManager, entry: ConfigEntry) -> None:
        self._manager = manager
        self._attr_unique_id = f"{entry.entry_id}_connected"
        self._attr_device_info = {
            "identifiers": {(DOMAIN, entry.entry_id)},
            "name": "AdGuard Rule Control",
            "manufacturer": "AdGuard Rule Control",
        }

    @property
    def is_on(self) -> bool:
        """Return connectivity."""
        return self._manager.connected

    @property
    def extra_state_attributes(self) -> dict[str, str | None]:
        """Return sanitized diagnostics."""
        return {"last_error": self._manager.last_error}

    async def async_added_to_hass(self) -> None:
        self.async_on_remove(self._manager.async_add_listener(self._handle_manager_update))

    @callback
    def _handle_manager_update(self) -> None:
        self.async_write_ha_state()
