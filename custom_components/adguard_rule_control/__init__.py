"""AdGuard Rule Control integration."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from homeassistant.helpers import config_validation as cv

if TYPE_CHECKING:
    from homeassistant.config_entries import ConfigEntry
    from homeassistant.core import HomeAssistant, ServiceCall

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    """Set up integration-level service actions."""
    _async_register_services(hass)
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up AdGuard Rule Control from a config entry."""
    from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
    from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady
    from homeassistant.helpers.aiohttp_client import async_get_clientsession

    from .api import (
        AdGuardAuthenticationError,
        AdGuardConnectionError,
        AdGuardInvalidResponseError,
        AdGuardRuleControlClient,
    )
    from .const import CONF_BASE_URL, CONF_VERIFY_SSL, PLATFORMS
    from .coordinator import AdGuardRuleControlManager

    hass.data.setdefault(DOMAIN, {})
    client = AdGuardRuleControlClient(
        async_get_clientsession(hass),
        entry.data[CONF_BASE_URL],
        entry.data.get(CONF_USERNAME),
        entry.data.get(CONF_PASSWORD),
        entry.data.get(CONF_VERIFY_SSL, True),
    )
    manager = AdGuardRuleControlManager(hass, entry, client)
    try:
        await manager.async_load()
    except AdGuardAuthenticationError as err:
        raise ConfigEntryAuthFailed(str(err)) from err
    except (AdGuardConnectionError, AdGuardInvalidResponseError) as err:
        raise ConfigEntryNotReady(str(err)) from err
    hass.data[DOMAIN][entry.entry_id] = manager
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    _async_register_services(hass)
    from homeassistant import config_entries

    if not hasattr(config_entries, "OptionsFlowWithReload"):
        entry.async_on_unload(entry.add_update_listener(_async_update_listener))
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    from .const import PLATFORMS

    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    manager = hass.data[DOMAIN].get(entry.entry_id)
    if manager:
        await manager.async_unload()
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id, None)
    return unload_ok


async def _async_update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Reload entry when options change."""
    manager = hass.data.get(DOMAIN, {}).get(entry.entry_id)
    if manager is not None:
        try:
            await manager.async_sync()
        except Exception as err:  # noqa: BLE001 - reload still preserves the saved options
            _LOGGER.warning("Unable to apply updated AdGuard controls before reload: %s", err)
    await hass.config_entries.async_reload(entry.entry_id)


def _async_register_services(hass: HomeAssistant) -> None:
    """Register integration services once."""
    import voluptuous as vol
    from homeassistant.exceptions import HomeAssistantError

    from .api import AdGuardRuleControlError
    from .const import CONF_CONTROL_ID, CONF_ENTRY_ID
    from .coordinator import AdGuardRuleControlManager

    if hass.services.has_service(DOMAIN, "sync"):
        return

    async def _get_manager_for_call(call, control_id: str | None = None) -> AdGuardRuleControlManager:
        managers_by_id = hass.data.get(DOMAIN, {})
        managers = list(managers_by_id.values())
        if not managers:
            raise HomeAssistantError("AdGuard Rule Control is not configured")
        entry_id = call.data.get(CONF_ENTRY_ID)
        if entry_id:
            manager = managers_by_id.get(entry_id)
            if manager is None:
                raise HomeAssistantError("No AdGuard Rule Control instance found for entry_id")
            return manager
        if control_id:
            matches = [
                manager
                for manager in managers
                if control_id in {control.control_id for control in manager.controls}
            ]
            if len(matches) == 1:
                return matches[0]
            if len(matches) > 1:
                raise HomeAssistantError(
                    "control_id exists in multiple AdGuard Rule Control instances; provide entry_id"
                )
        if len(managers) == 1:
            return managers[0]
        raise HomeAssistantError("Multiple AdGuard Rule Control instances are configured; provide entry_id")

    async def async_sync(call: ServiceCall) -> None:
        manager = await _get_manager_for_call(call)
        try:
            await manager.async_sync()
        except AdGuardRuleControlError as err:
            raise HomeAssistantError(str(err)) from err

    async def async_enable(call: ServiceCall) -> None:
        control_id = call.data[CONF_CONTROL_ID]
        manager = await _get_manager_for_call(call, control_id)
        try:
            await manager.async_set_control_state(control_id, True)
        except (AdGuardRuleControlError, ValueError) as err:
            raise HomeAssistantError(str(err)) from err

    async def async_disable(call: ServiceCall) -> None:
        control_id = call.data[CONF_CONTROL_ID]
        manager = await _get_manager_for_call(call, control_id)
        try:
            await manager.async_set_control_state(control_id, False)
        except (AdGuardRuleControlError, ValueError) as err:
            raise HomeAssistantError(str(err)) from err

    async def async_set_state(call: ServiceCall) -> None:
        control_id = call.data[CONF_CONTROL_ID]
        manager = await _get_manager_for_call(call, control_id)
        try:
            await manager.async_set_control_state(control_id, call.data["enabled"])
        except (AdGuardRuleControlError, ValueError) as err:
            raise HomeAssistantError(str(err)) from err

    async def async_enable_for(call: ServiceCall) -> None:
        control_id = call.data[CONF_CONTROL_ID]
        manager = await _get_manager_for_call(call, control_id)
        try:
            await manager.async_enable_control_for(control_id, call.data["minutes"])
        except (AdGuardRuleControlError, ValueError) as err:
            raise HomeAssistantError(str(err)) from err

    control_schema = vol.Schema({vol.Required(CONF_CONTROL_ID): str, vol.Optional(CONF_ENTRY_ID): str})
    hass.services.async_register(DOMAIN, "sync", async_sync, schema=vol.Schema({vol.Optional(CONF_ENTRY_ID): str}))
    hass.services.async_register(DOMAIN, "enable", async_enable, schema=control_schema)
    hass.services.async_register(DOMAIN, "disable", async_disable, schema=control_schema)
    hass.services.async_register(
        DOMAIN,
        "enable_for",
        async_enable_for,
        schema=vol.Schema(
            {
                vol.Required(CONF_CONTROL_ID): str,
                vol.Required("minutes"): vol.All(vol.Coerce(int), vol.Range(min=1, max=10080)),
                vol.Optional(CONF_ENTRY_ID): str,
            }
        ),
    )
    hass.services.async_register(
        DOMAIN,
        "set_state",
        async_set_state,
        schema=vol.Schema(
            {
                vol.Required(CONF_CONTROL_ID): str,
                vol.Required("enabled"): bool,
                vol.Optional(CONF_ENTRY_ID): str,
            }
        ),
    )
