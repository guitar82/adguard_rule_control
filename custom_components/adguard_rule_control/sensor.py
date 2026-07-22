"""Sensor platform for AdGuard Rule Control."""

from __future__ import annotations

from homeassistant.components.sensor import SensorDeviceClass, SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.util import dt as dt_util

from .coordinator import AdGuardRuleControlManager, get_manager
from .device import main_device_info


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback) -> None:
    """Set up diagnostic sensors."""
    manager = get_manager(hass, entry)
    entities = [
        AdGuardRuleControlActiveControlCountSensor(manager, entry),
        AdGuardRuleControlNextAutomaticChangeSensor(manager, entry),
        AdGuardRuleControlManagedRuleCountSensor(manager, entry),
        AdGuardRuleControlLastSyncSensor(manager, entry),
    ]
    if manager.activity_enabled:
        entities.extend(
            [
                AdGuardRuleControlBlockedActivitySensor(manager, entry),
                AdGuardRuleControlLastBlockedSensor(manager, entry),
            ]
        )
    async_add_entities(entities)


class _BaseAdGuardRuleControlSensor(SensorEntity):
    _attr_has_entity_name = True

    def __init__(self, manager: AdGuardRuleControlManager, entry: ConfigEntry, suffix: str) -> None:
        self._manager = manager
        self._attr_unique_id = f"{entry.entry_id}_{suffix}"
        self._attr_device_info = main_device_info(entry)

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
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, manager: AdGuardRuleControlManager, entry: ConfigEntry) -> None:
        super().__init__(manager, entry, "managed_rule_count")

    @property
    def native_value(self) -> int:
        return self._manager.managed_rule_count


class AdGuardRuleControlLastSyncSensor(_BaseAdGuardRuleControlSensor):
    """Last successful sync sensor."""

    _attr_name = "Last Sync"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, manager: AdGuardRuleControlManager, entry: ConfigEntry) -> None:
        super().__init__(manager, entry, "last_sync")

    @property
    def native_value(self) -> str | None:
        return self._manager.last_sync


class AdGuardRuleControlActiveControlCountSensor(_BaseAdGuardRuleControlSensor):
    """Count currently active controls for dashboards and automations."""

    _attr_name = "Active Blocks"
    _attr_icon = "mdi:shield-lock-outline"

    def __init__(self, manager: AdGuardRuleControlManager, entry: ConfigEntry) -> None:
        super().__init__(manager, entry, "active_blocks")

    @property
    def native_value(self) -> int:
        return len(self._manager.active_control_names)

    @property
    def extra_state_attributes(self) -> dict[str, list[str]]:
        return {"active_controls": self._manager.active_control_names}


class AdGuardRuleControlNextAutomaticChangeSensor(_BaseAdGuardRuleControlSensor):
    """Show the next temporary block or allow restoration time."""

    _attr_name = "Next Automatic Change"
    _attr_icon = "mdi:timer-outline"
    _attr_device_class = SensorDeviceClass.TIMESTAMP

    def __init__(self, manager: AdGuardRuleControlManager, entry: ConfigEntry) -> None:
        super().__init__(manager, entry, "next_automatic_change")

    @property
    def native_value(self):
        return self._manager.next_temporary_deadline


class AdGuardRuleControlBlockedActivitySensor(_BaseAdGuardRuleControlSensor):
    """Expose opt-in blocked activity aggregates without domains or raw rows."""

    _attr_name = "Blocked Requests Last 24 Hours"
    _attr_icon = "mdi:shield-search"

    def __init__(self, manager: AdGuardRuleControlManager, entry: ConfigEntry) -> None:
        super().__init__(manager, entry, "blocked_requests_24h")

    @property
    def native_value(self) -> int | None:
        value = self._manager.activity_summary.get("blocked_last_24_hours")
        return int(value) if value is not None else None

    @property
    def extra_state_attributes(self) -> dict:
        summary = self._manager.activity_summary
        return {
            "sample_limit": summary.get("sample_limit"),
            "sample_truncated": summary.get("sample_truncated"),
            "top_services": summary.get("top_services", {}),
            "top_clients": summary.get("top_clients", {}),
            "activity_error": self._manager.activity_error,
            "privacy": "Domains and raw query-log rows are not retained",
        }


class AdGuardRuleControlLastBlockedSensor(_BaseAdGuardRuleControlSensor):
    """Show when the most recent sampled blocked request occurred."""

    _attr_name = "Last Blocked Request"
    _attr_icon = "mdi:clock-alert-outline"
    _attr_device_class = SensorDeviceClass.TIMESTAMP

    def __init__(self, manager: AdGuardRuleControlManager, entry: ConfigEntry) -> None:
        super().__init__(manager, entry, "last_blocked_request")

    @property
    def native_value(self):
        value = self._manager.activity_summary.get("last_blocked")
        return dt_util.parse_datetime(value) if isinstance(value, str) else None
