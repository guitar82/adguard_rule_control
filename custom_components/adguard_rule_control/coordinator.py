"""Runtime manager for AdGuard Rule Control."""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Callable
from datetime import timedelta
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.helpers.storage import Store
from homeassistant.util import dt as dt_util

from .api import (
    AdGuardAuthenticationError,
    AdGuardConnectionError,
    AdGuardRuleControlClient,
)
from .const import (
    CONF_CONTROLS,
    CONNECTION_CHECK_INTERVAL_SECONDS,
    CONTROL_KIND_BLOCKED_SERVICES,
    CONTROL_KIND_RULES,
    DOMAIN,
    STORAGE_KEY_PREFIX,
    STORAGE_VERSION,
    WRITE_DEBOUNCE_SECONDS,
)
from .models import RuleControl
from .rule_builder import build_managed_block, generate_rules_for_control, infer_active_control_ids


class AdGuardRuleControlManager:
    """Manage rule state and AdGuard synchronization."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry, client: AdGuardRuleControlClient) -> None:
        self.hass = hass
        self.entry = entry
        self.client = client
        self._store: Store[dict[str, Any]] = Store(hass, STORAGE_VERSION, f"{STORAGE_KEY_PREFIX}.{entry.entry_id}")
        self._lock = asyncio.Lock()
        self._listeners: list[Callable[[], None]] = []
        self._unsub_interval: Callable[[], None] | None = None
        self.states: dict[str, bool] = {}
        self.connected = False
        self.last_error: str | None = None
        self.last_sync: str | None = None
        self.last_checksum: str | None = None
        self.managed_rule_count = 0
        self.control_status: dict[str, dict[str, Any]] = {}
        self.last_managed_blocked_service_ids: set[str] = set()

    @property
    def controls(self) -> list[RuleControl]:
        """Return configured controls."""
        return [RuleControl.from_dict(control) for control in self.entry.options.get(CONF_CONTROLS, [])]

    @property
    def available(self) -> bool:
        """Return whether entities should be available."""
        return self.connected

    async def async_load(self) -> None:
        """Load persisted runtime state and start health checks."""
        data = await self._store.async_load() or {}
        self.states = {str(key): bool(value) for key, value in data.get("states", {}).items()}
        self.last_sync = data.get("last_sync")
        self.last_checksum = data.get("last_checksum")
        self.control_status = data.get("control_status", {})
        self.last_managed_blocked_service_ids = set(data.get("last_managed_blocked_service_ids", []))
        for control in self.controls:
            self.states.setdefault(control.control_id, False)
            self.control_status.setdefault(control.control_id, self._status_for_control(control, False))
        await self.async_check_connection()
        self._unsub_interval = async_track_time_interval(
            self.hass,
            lambda _now: self.hass.async_create_task(self.async_check_connection()),
            timedelta(seconds=CONNECTION_CHECK_INTERVAL_SECONDS),
        )

    async def async_unload(self) -> None:
        """Unload the manager."""
        if self._unsub_interval:
            self._unsub_interval()
            self._unsub_interval = None

    @callback
    def async_add_listener(self, listener: Callable[[], None]) -> Callable[[], None]:
        """Register an entity update listener."""
        self._listeners.append(listener)

        @callback
        def remove_listener() -> None:
            if listener in self._listeners:
                self._listeners.remove(listener)

        return remove_listener

    @callback
    def _notify_listeners(self) -> None:
        for listener in list(self._listeners):
            listener()

    async def async_check_connection(self) -> None:
        """Run a lightweight AdGuard connection check."""
        try:
            await self.client.async_test_connection()
        except (AdGuardAuthenticationError, AdGuardConnectionError) as err:
            self.connected = False
            self.last_error = str(err)
        except Exception as err:  # noqa: BLE001 - keep integrations available without leaking internals
            self.connected = False
            self.last_error = str(err)
        else:
            self.connected = True
            self.last_error = None
        self._notify_listeners()

    def state_for(self, control_id: str) -> bool:
        """Return enabled state for a control."""
        return self.states.get(control_id, False)

    async def async_set_control_state(self, control_id: str, enabled: bool) -> None:
        """Set a control state and synchronize AdGuard rules."""
        if control_id not in {control.control_id for control in self.controls}:
            raise ValueError("Unknown rule control")
        previous = self.states.get(control_id, False)
        self.states[control_id] = enabled
        self._notify_listeners()
        await asyncio.sleep(WRITE_DEBOUNCE_SECONDS)
        try:
            await self.async_sync()
        except Exception:
            self.states[control_id] = previous
            self._notify_listeners()
            raise

    async def async_import_states_from_adguard(self) -> set[str]:
        """Import enabled states by reading the current managed block from AdGuard."""
        async with self._lock:
            existing_rules = await self.client.async_get_user_rules()
            blocked_config = await self.client.async_get_blocked_services_config()
            blocked_ids = set(blocked_config["ids"])
            controls = self.controls
            active_ids = infer_active_control_ids(
                existing_rules,
                [control for control in controls if control.kind == CONTROL_KIND_RULES],
            )
            for control in controls:
                if control.kind == CONTROL_KIND_BLOCKED_SERVICES:
                    is_active = bool(control.blocked_service_ids) and set(control.blocked_service_ids).issubset(blocked_ids)
                    self.states[control.control_id] = is_active
                    if is_active:
                        active_ids.add(control.control_id)
                else:
                    self.states[control.control_id] = control.control_id in active_ids
                self.control_status[control.control_id] = self._status_for_control(
                    control,
                    self.states[control.control_id],
                )
            self.connected = True
            self.last_error = None
            await self._async_save_state()
            self._notify_listeners()
            return active_ids

    async def async_sync(self) -> None:
        """Rebuild and apply the managed rule block."""
        async with self._lock:
            controls = self.controls
            rule_controls = [control for control in controls if control.kind == CONTROL_KIND_RULES]
            service_controls = [control for control in controls if control.kind == CONTROL_KIND_BLOCKED_SERVICES]
            active_controls = [control for control in rule_controls if self.states.get(control.control_id, False)]
            managed_rules = build_managed_block(active_controls)
            await self.client.async_replace_managed_rules(managed_rules)
            if service_controls or self.last_managed_blocked_service_ids:
                await self._async_sync_blocked_services(service_controls)
            self.connected = True
            self.last_error = None
            self.last_sync = dt_util.utcnow().isoformat()
            self.last_checksum = hashlib.sha256(json.dumps(managed_rules, sort_keys=True).encode()).hexdigest()
            self.managed_rule_count = max(0, len([rule for rule in managed_rules if rule and not rule.startswith("!")]))
            self.control_status = {
                control.control_id: self._status_for_control(control, self.states.get(control.control_id, False))
                for control in controls
            }
            await self._async_save_state()
            self._notify_listeners()

    def status_for(self, control_id: str) -> dict[str, Any]:
        """Return lightweight per-control sync metadata."""
        return self.control_status.get(control_id, {})

    def _status_for_control(self, control: RuleControl, active: bool) -> dict[str, Any]:
        """Build per-control status metadata."""
        generated_rules = generate_rules_for_control(control) if control.kind == CONTROL_KIND_RULES else []
        managed_items = list(generated_rules or control.blocked_service_ids)
        checksum = hashlib.sha256(json.dumps(managed_items, sort_keys=True).encode()).hexdigest()
        return {
            "active": active,
            "kind": control.kind,
            "generated_rule_count": len(generated_rules),
            "blocked_service_count": len(control.blocked_service_ids),
            "last_generated_checksum": checksum,
            "last_successful_sync": self.last_sync if active else None,
        }

    async def _async_sync_blocked_services(self, service_controls: list[RuleControl]) -> None:
        """Synchronize global AdGuard blocked services while preserving unrelated services."""
        config = await self.client.async_get_blocked_services_config()
        current_ids = set(config["ids"])
        active_ids = {
            service_id
            for control in service_controls
            if self.states.get(control.control_id, False)
            for service_id in control.blocked_service_ids
        }
        next_ids = sorted((current_ids - self.last_managed_blocked_service_ids) | active_ids)
        if set(config["ids"]) != set(next_ids):
            await self.client.async_update_blocked_services_config(next_ids, config["schedule"])
        self.last_managed_blocked_service_ids = set(active_ids)

    async def _async_save_state(self) -> None:
        """Persist runtime state."""
        await self._store.async_save(
            {
                "states": self.states,
                "last_sync": self.last_sync,
                "last_checksum": self.last_checksum,
                "control_status": self.control_status,
                "last_managed_blocked_service_ids": sorted(self.last_managed_blocked_service_ids),
            }
        )


def get_manager(hass: HomeAssistant, entry: ConfigEntry) -> AdGuardRuleControlManager:
    """Return the manager for an entry."""
    return hass.data[DOMAIN][entry.entry_id]
