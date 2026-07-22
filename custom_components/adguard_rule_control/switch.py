"""Switch platform for AdGuard Rule Control."""

from __future__ import annotations

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .coordinator import AdGuardRuleControlManager, get_manager
from .device import control_device_info, main_device_info
from .models import ControlProfile, RuleControl


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback) -> None:
    """Set up rule control switches."""
    manager = get_manager(hass, entry)
    async_add_entities(
        [
            AdGuardRuleControlSwitch(manager, entry, control)
            for control in manager.controls
            if control.entity_enabled
        ]
        + [
            AdGuardRuleControlProfileSwitch(manager, entry, profile)
            for profile in manager.profiles
        ]
    )


class AdGuardRuleControlSwitch(SwitchEntity):
    """Switch for a configured AdGuard rule control."""

    _attr_has_entity_name = True

    def __init__(self, manager: AdGuardRuleControlManager, entry: ConfigEntry, control: RuleControl) -> None:
        self._manager = manager
        self._entry = entry
        self._control = control
        self._attr_name = control.display_name
        self._attr_unique_id = f"{entry.entry_id}_{control.control_id}"
        self._attr_icon = control.icon
        self._attr_device_info = control_device_info(entry, control.target)

    @property
    def is_on(self) -> bool:
        """Return switch state."""
        return self._manager.state_for(self._control.control_id)

    @property
    def available(self) -> bool:
        """Return entity availability."""
        return self._manager.available

    @property
    def extra_state_attributes(self) -> dict[str, str | int | None]:
        """Return useful attributes."""
        status = self._manager.status_for(self._control.control_id)
        return {
            "control_id": self._control.control_id,
            "kind": status.get("kind"),
            "last_error": self._manager.last_error,
            "generated_rule_count": status.get("generated_rule_count"),
            "blocked_service_count": status.get("blocked_service_count"),
            "last_generated_checksum": status.get("last_generated_checksum"),
            "last_successful_sync": status.get("last_successful_sync"),
            "temporary_until": self._manager.temporary_until_for(self._control.control_id),
            "temporary_mode": (
                "allow"
                if self._manager.temporary_restore_state_for(self._control.control_id) is True
                else "block"
                if self._manager.temporary_restore_state_for(self._control.control_id) is False
                else None
            ),
            "target": self._control.target.display_name if self._control.target else "everyone",
        }

    async def async_turn_on(self, **kwargs) -> None:
        """Enable this control."""
        await self._manager.async_set_control_state(self._control.control_id, True)

    async def async_turn_off(self, **kwargs) -> None:
        """Disable this control."""
        await self._manager.async_set_control_state(self._control.control_id, False)

    async def async_added_to_hass(self) -> None:
        """Subscribe to manager updates."""
        self.async_on_remove(self._manager.async_add_listener(self._handle_manager_update))

    @callback
    def _handle_manager_update(self) -> None:
        self.async_write_ha_state()


class AdGuardRuleControlProfileSwitch(SwitchEntity):
    """Switch a named group of rule controls together."""

    _attr_has_entity_name = True

    def __init__(
        self,
        manager: AdGuardRuleControlManager,
        entry: ConfigEntry,
        profile: ControlProfile,
    ) -> None:
        self._manager = manager
        self._profile = profile
        self._attr_name = profile.display_name
        self._attr_unique_id = f"{entry.entry_id}_profile_{profile.profile_id}"
        self._attr_icon = profile.icon or "mdi:account-group"
        self._attr_device_info = main_device_info(entry)

    @property
    def is_on(self) -> bool:
        """Return whether all profile members are enabled."""
        return self._manager.profile_state_for(self._profile.profile_id)

    @property
    def available(self) -> bool:
        """Return profile availability."""
        return self._manager.available

    @property
    def extra_state_attributes(self) -> dict[str, list[str] | int]:
        """Return profile membership information."""
        names_by_id = {control.control_id: control.display_name for control in self._manager.controls}
        return {
            "member_count": len(self._profile.control_ids),
            "members": [
                names_by_id[control_id]
                for control_id in self._profile.control_ids
                if control_id in names_by_id
            ],
        }

    async def async_turn_on(self, **kwargs) -> None:
        """Enable all profile controls."""
        await self._manager.async_set_profile_state(self._profile.profile_id, True)

    async def async_turn_off(self, **kwargs) -> None:
        """Disable all profile controls."""
        await self._manager.async_set_profile_state(self._profile.profile_id, False)

    async def async_added_to_hass(self) -> None:
        """Subscribe to manager updates."""
        self.async_on_remove(self._manager.async_add_listener(self._handle_manager_update))

    @callback
    def _handle_manager_update(self) -> None:
        self.async_write_ha_state()
