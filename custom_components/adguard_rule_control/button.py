"""Button platform for AdGuard Rule Control."""

from __future__ import annotations

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .coordinator import AdGuardRuleControlManager, get_manager
from .device import control_device_info, main_device_info
from .models import RuleControl


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback) -> None:
    """Set up sync button."""
    manager = get_manager(hass, entry)
    async_add_entities(
        [
            AdGuardRuleControlSyncButton(manager, entry),
            AdGuardRuleControlAllowAllButton(manager, entry),
        ]
        + [
            AdGuardRuleControlQuickBlockButton(manager, entry, control)
            for control in manager.controls
            if control.entity_enabled
        ]
        + [
            AdGuardRuleControlQuickAllowButton(manager, entry, control)
            for control in manager.controls
            if control.entity_enabled
        ]
    )


class AdGuardRuleControlSyncButton(ButtonEntity):
    """Force a managed rules sync."""

    _attr_has_entity_name = True
    _attr_name = "Sync"
    _attr_entity_category = EntityCategory.CONFIG

    def __init__(self, manager: AdGuardRuleControlManager, entry: ConfigEntry) -> None:
        self._manager = manager
        self._attr_unique_id = f"{entry.entry_id}_sync"
        self._attr_device_info = main_device_info(entry)

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


class AdGuardRuleControlAllowAllButton(ButtonEntity):
    """Immediately disable every managed control."""

    _attr_has_entity_name = True
    _attr_name = "Allow Everything"
    _attr_icon = "mdi:shield-off-outline"

    def __init__(self, manager: AdGuardRuleControlManager, entry: ConfigEntry) -> None:
        self._manager = manager
        self._attr_unique_id = f"{entry.entry_id}_allow_all"
        self._attr_device_info = main_device_info(entry)

    @property
    def available(self) -> bool:
        return self._manager.available

    async def async_press(self) -> None:
        """Disable all managed controls."""
        await self._manager.async_disable_all_controls()

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
        self._attr_device_info = control_device_info(entry, control.target)

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


class AdGuardRuleControlQuickAllowButton(ButtonEntity):
    """Temporarily allow one configured control target."""

    _attr_has_entity_name = True

    def __init__(self, manager: AdGuardRuleControlManager, entry: ConfigEntry, control: RuleControl) -> None:
        self._manager = manager
        self._control = control
        self._attr_name = f"Allow {control.display_name} for {control.quick_block_minutes} minutes"
        self._attr_unique_id = f"{entry.entry_id}_{control.control_id}_quick_allow"
        self._attr_icon = "mdi:timer-check-outline"
        self._attr_device_info = control_device_info(entry, control.target)

    @property
    def available(self) -> bool:
        return self._manager.available and self._manager.state_for(self._control.control_id)

    async def async_press(self) -> None:
        """Disable the control for its configured quick duration."""
        await self._manager.async_disable_control_for(
            self._control.control_id,
            self._control.quick_block_minutes,
        )

    async def async_added_to_hass(self) -> None:
        self.async_on_remove(self._manager.async_add_listener(self._handle_manager_update))

    @callback
    def _handle_manager_update(self) -> None:
        self.async_write_ha_state()
