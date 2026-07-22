"""Binary sensor platform for AdGuard Rule Control."""

from __future__ import annotations

from homeassistant.components.binary_sensor import BinarySensorDeviceClass, BinarySensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .coordinator import AdGuardRuleControlManager, get_manager
from .device import main_device_info


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback) -> None:
    """Set up diagnostic binary sensor."""
    manager = get_manager(hass, entry)
    async_add_entities(
        [
            AdGuardRuleControlAnyBlockActiveSensor(manager, entry),
            AdGuardRuleControlConnectedSensor(manager, entry),
        ]
    )


class AdGuardRuleControlConnectedSensor(BinarySensorEntity):
    """Reports whether AdGuard is reachable."""

    _attr_has_entity_name = True
    _attr_name = "Connected"
    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, manager: AdGuardRuleControlManager, entry: ConfigEntry) -> None:
        self._manager = manager
        self._attr_unique_id = f"{entry.entry_id}_connected"
        self._attr_device_info = main_device_info(entry)

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


class AdGuardRuleControlAnyBlockActiveSensor(BinarySensorEntity):
    """Report whether any managed block is active."""

    _attr_has_entity_name = True
    _attr_name = "Any Block Active"
    _attr_icon = "mdi:shield-lock-outline"

    def __init__(self, manager: AdGuardRuleControlManager, entry: ConfigEntry) -> None:
        self._manager = manager
        self._attr_unique_id = f"{entry.entry_id}_any_block_active"
        self._attr_device_info = main_device_info(entry)

    @property
    def is_on(self) -> bool:
        """Return whether one or more controls are active."""
        return bool(self._manager.active_control_names)

    @property
    def available(self) -> bool:
        return self._manager.available

    @property
    def extra_state_attributes(self) -> dict[str, list[str]]:
        return {"active_controls": self._manager.active_control_names}

    async def async_added_to_hass(self) -> None:
        self.async_on_remove(self._manager.async_add_listener(self._handle_manager_update))

    @callback
    def _handle_manager_update(self) -> None:
        self.async_write_ha_state()
