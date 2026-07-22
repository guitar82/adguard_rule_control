"""Home Assistant device grouping helpers."""

from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.device_registry import DeviceEntryType, DeviceInfo

from .const import CONF_BASE_URL, DOMAIN
from .models import ClientTarget


def main_device_info(entry: ConfigEntry) -> DeviceInfo:
    """Return device info for the AdGuard service connection."""
    return DeviceInfo(
        identifiers={(DOMAIN, entry.entry_id)},
        name="AdGuard Rule Control",
        manufacturer="AdGuard Home",
        model="Rule Control",
        configuration_url=entry.data.get(CONF_BASE_URL),
        entry_type=DeviceEntryType.SERVICE,
    )


def target_device_identifier(entry: ConfigEntry, target: ClientTarget) -> tuple[str, str]:
    """Return a stable device identifier for one client target."""
    return (
        DOMAIN,
        f"{entry.entry_id}:target:{target.identifier_type}:{target.identifier_value}",
    )


def target_device_info(entry: ConfigEntry, target: ClientTarget) -> DeviceInfo:
    """Return device info grouping controls for one AdGuard client."""
    return DeviceInfo(
        identifiers={target_device_identifier(entry, target)},
        name=f"{target.display_name} Internet Controls",
        manufacturer="AdGuard Home",
        model="Client Internet Controls",
        via_device=(DOMAIN, entry.entry_id),
    )


def control_device_info(entry: ConfigEntry, target: ClientTarget | None) -> DeviceInfo:
    """Return the correct parent device for a rule control."""
    return target_device_info(entry, target) if target else main_device_info(entry)
