"""Button platform for AdGuard Rule Control."""

from __future__ import annotations

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .coordinator import AdGuardRuleControlManager, get_manager
from .models import RuleControl


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback) -> None:
    """Set up sync button."""
    manager = get_manager(hass, entry)
    async_add_entities(
        [AdGuardRuleControlSyncButton(manager, entry)]
        + [
            AdGuardRuleControlQuickBlockButton(manager, entry, control)
            for control in manager.controls
            if control.entity_enabled
        ]
    )


class AdGuardRuleControlSyncButton(ButtonEntity):
    """Force a managed rules sync."""

    _attr_has_entity_name = True
    _attr_name = "Sync"

    def __init__(self, manager: AdGuardRuleControlManager, entry: ConfigEntry) -> None:
        self._manager = manager
        self._attr_unique_id = f"{entry.entry_id}_sync"
        self._attr_device_info = {
            "identifiers": {(DOMAIN, entry.entry_id)},
            "name": "AdGuard Rule Control",
            "manufacturer": "AdGuard Rule Control",
        }

    @property
    def available(self) -> bool:
        return self._manager.available

    async def async_press(self) -> None:
        """Force a sync."""
        await self._manager.async_sync()

    async def async_added_to_hass(self) -> None:
        self.async_on_remove(self._manager.async_add_listener(self._handle_manager_update))

    @callback
    def _handle_manager_update(self) -> None:
        self.async_write_ha_state()


class AdGuardRuleControlQuickBlockButton(ButtonEntity):
    """Start a configured temporary block from a dashboard."""

    _attr_has_entity_name = True

    def __init__(self, manager: AdGuardRuleControlManager, entry: ConfigEntry, control: RuleControl) -> None:
        self._manager = manager
        self._control = control
        self._attr_name = f"{control.display_name} for {control.quick_block_minutes} minutes"
        self._attr_unique_id = f"{entry.entry_id}_{control.control_id}_quick_block"
        self._attr_icon = "mdi:timer-lock"
        self._attr_device_info = {
            "identifiers": {(DOMAIN, entry.entry_id)},
            "name": "AdGuard Rule Control",
            "manufacturer": "AdGuard Rule Control",
        }

    @property
    def available(self) -> bool:
        return self._manager.available

    async def async_press(self) -> None:
        """Enable the control for its configured quick duration."""
        await self._manager.async_enable_control_for(
            self._control.control_id,
            self._control.quick_block_minutes,
        )

    async def async_added_to_hass(self) -> None:
        self.async_on_remove(self._manager.async_add_listener(self._handle_manager_update))

    @callback
    def _handle_manager_update(self) -> None:
        self.async_write_ha_state()
