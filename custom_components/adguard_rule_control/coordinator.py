"""Runtime manager for AdGuard Rule Control."""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.event import async_call_later, async_track_time_interval
from homeassistant.helpers.storage import Store
from homeassistant.util import dt as dt_util

from .api import (
    AdGuardAuthenticationError,
    AdGuardConnectionError,
    AdGuardInvalidResponseError,
    AdGuardRuleControlClient,
)
from .const import (
    ACTIVITY_REFRESH_INTERVAL_SECONDS,
    CONF_ACTIVITY_ENABLED,
    CONF_ACTIVITY_LIMIT,
    CONF_CONTROLS,
    CONF_PROFILES,
    CONTROL_KIND_BLOCKED_SERVICES,
    CONTROL_KIND_RULES,
    DEFAULT_ACTIVITY_LIMIT,
    DOMAIN,
    MAX_TEMPORARY_BLOCK_MINUTES,
    STATE_REFRESH_INTERVAL_SECONDS,
    STORAGE_KEY_PREFIX,
    STORAGE_VERSION,
    WRITE_DEBOUNCE_SECONDS,
)
from .models import ControlProfile, RuleControl
from .rule_builder import (
    RuleBuilderError,
    build_managed_block,
    generate_rules_for_control,
    infer_active_control_ids,
)


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
        self._temporary_unsubs: dict[str, Callable[[], None]] = {}
        self.states: dict[str, bool] = {}
        self.temporary_until: dict[str, str] = {}
        self.temporary_restore_states: dict[str, bool] = {}
        self.connected = False
        self.last_error: str | None = None
        self.last_sync: str | None = None
        self.last_checksum: str | None = None
        self.managed_rule_count = 0
        self.control_status: dict[str, dict[str, Any]] = {}
        self.last_managed_blocked_service_ids: set[str] = set()
        self.managed_client_blocked_services: dict[str, dict[str, Any]] = {}
        self.activity_summary: dict[str, Any] = {}
        self.activity_last_refresh: datetime | None = None
        self.activity_error: str | None = None

    @property
    def controls(self) -> list[RuleControl]:
        """Return configured controls."""
        return [RuleControl.from_dict(control) for control in self.entry.options.get(CONF_CONTROLS, [])]

    @property
    def profiles(self) -> list[ControlProfile]:
        """Return configured control profiles."""
        valid_ids = {control.control_id for control in self.controls}
        profiles: list[ControlProfile] = []
        for raw_profile in self.entry.options.get(CONF_PROFILES, []):
            profile = ControlProfile.from_dict(raw_profile)
            control_ids = tuple(control_id for control_id in profile.control_ids if control_id in valid_ids)
            if control_ids:
                profiles.append(
                    ControlProfile(
                        profile_id=profile.profile_id,
                        display_name=profile.display_name,
                        control_ids=control_ids,
                        icon=profile.icon,
                    )
                )
        return profiles

    @property
    def activity_enabled(self) -> bool:
        """Return whether aggregate query-log activity is enabled."""
        return bool(self.entry.options.get(CONF_ACTIVITY_ENABLED, False))

    @property
    def available(self) -> bool:
        """Return whether entities should be available."""
        return self.connected

    async def async_load(self) -> None:
        """Load persisted runtime state and start refresh checks."""
        data = await self._store.async_load() or {}
        self.states = {str(key): bool(value) for key, value in data.get("states", {}).items()}
        self.last_sync = data.get("last_sync")
        self.last_checksum = data.get("last_checksum")
        self.control_status = data.get("control_status", {})
        self.last_managed_blocked_service_ids = set(data.get("last_managed_blocked_service_ids", []))
        self.managed_client_blocked_services = data.get("managed_client_blocked_services", {})
        self.temporary_until = {
            str(key): str(value)
            for key, value in data.get("temporary_until", {}).items()
            if isinstance(value, str)
        }
        self.temporary_restore_states = {
            str(key): bool(value)
            for key, value in data.get("temporary_restore_states", {}).items()
        }
        for control in self.controls:
            self.states.setdefault(control.control_id, False)
            self.control_status.setdefault(control.control_id, self._status_for_control(control, False))
        self._discard_expired_temporary_states()
        try:
            await self.client.async_test_connection()
            self.connected = True
            await self.async_sync()
        except (AdGuardConnectionError, AdGuardInvalidResponseError, RuleBuilderError) as err:
            self._create_issue("managed_state_unavailable", str(err))
            raise
        self._restore_temporary_timers()
        self._unsub_interval = async_track_time_interval(
            self.hass,
            lambda _now: self.hass.async_create_task(self.async_refresh_state()),
            timedelta(seconds=STATE_REFRESH_INTERVAL_SECONDS),
        )

    async def async_unload(self) -> None:
        """Unload the manager."""
        if self._unsub_interval:
            self._unsub_interval()
            self._unsub_interval = None
        for unsub in self._temporary_unsubs.values():
            unsub()
        self._temporary_unsubs.clear()

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
        """Refresh AdGuard connectivity and managed state."""
        await self.async_refresh_state()

    async def async_refresh_state(self, *, raise_errors: bool = False) -> None:
        """Read actual AdGuard state and reconcile entity states."""
        try:
            async with self._lock:
                existing_rules = await self.client.async_get_user_rules()
                controls = self.controls
                active_rule_ids = infer_active_control_ids(
                    existing_rules,
                    [control for control in controls if control.kind == CONTROL_KIND_RULES],
                )
                service_controls = [control for control in controls if control.kind == CONTROL_KIND_BLOCKED_SERVICES]
                global_blocked_ids: set[str] = set()
                client_configs: dict[str, dict[str, Any]] = {}
                if any(control.target is None for control in service_controls):
                    blocked_config = await self.client.async_get_blocked_services_config()
                    global_blocked_ids = set(blocked_config["ids"])
                if any(control.target is not None for control in service_controls):
                    client_configs = {
                        str(client["name"]): client
                        for client in await self.client.async_get_client_configs()
                    }

                for control in controls:
                    if control.kind == CONTROL_KIND_RULES:
                        enabled = control.control_id in active_rule_ids
                    elif control.target is None:
                        enabled = bool(control.blocked_service_ids) and set(control.blocked_service_ids).issubset(
                            global_blocked_ids
                        )
                    else:
                        client = client_configs.get(control.target.identifier_value)
                        enabled = bool(
                            client
                            and not client.get("use_global_blocked_services", True)
                            and set(control.blocked_service_ids).issubset(set(client.get("blocked_services", [])))
                        )
                    self.states[control.control_id] = enabled
                    if (
                        control.control_id in self.temporary_until
                        and enabled == self.temporary_restore_states.get(control.control_id, False)
                    ):
                        self._clear_temporary_timer(control.control_id)

                self.connected = True
                self.last_error = None
                self.managed_rule_count = sum(
                    len(generate_rules_for_control(control))
                    for control in controls
                    if control.kind == CONTROL_KIND_RULES and self.states.get(control.control_id, False)
                )
                self.control_status = {
                    control.control_id: self._status_for_control(control, self.states.get(control.control_id, False))
                    for control in controls
                }
                await self._async_refresh_activity()
                await self._async_save_state()
                ir.async_delete_issue(self.hass, DOMAIN, "managed_state_unavailable")
        except AdGuardAuthenticationError as err:
            self.connected = False
            self.last_error = str(err)
            self.entry.async_start_reauth(self.hass)
            if raise_errors:
                raise
        except (AdGuardConnectionError, AdGuardInvalidResponseError, RuleBuilderError) as err:
            self.connected = False
            self.last_error = str(err)
            self._create_issue("managed_state_unavailable", str(err))
            if raise_errors:
                raise
        except Exception as err:  # noqa: BLE001 - keep entities unavailable for unexpected API errors
            self.connected = False
            self.last_error = str(err)
            if raise_errors:
                raise
        finally:
            self._notify_listeners()

    def state_for(self, control_id: str) -> bool:
        """Return enabled state for a control."""
        return self.states.get(control_id, False)

    def temporary_until_for(self, control_id: str) -> str | None:
        """Return an active temporary-state deadline."""
        return self.temporary_until.get(control_id)

    def temporary_restore_state_for(self, control_id: str) -> bool | None:
        """Return the state that will be restored at the temporary deadline."""
        if control_id not in self.temporary_until:
            return None
        return self.temporary_restore_states.get(control_id, False)

    def profile_state_for(self, profile_id: str) -> bool:
        """Return whether every member of a profile is enabled."""
        profile = next((item for item in self.profiles if item.profile_id == profile_id), None)
        return bool(profile and all(self.states.get(control_id, False) for control_id in profile.control_ids))

    @property
    def active_control_names(self) -> list[str]:
        """Return friendly names for active controls."""
        return [control.display_name for control in self.controls if self.states.get(control.control_id, False)]

    @property
    def next_temporary_deadline(self) -> datetime | None:
        """Return the next valid automatic state restoration deadline."""
        deadlines = [
            dt_util.as_utc(deadline)
            for value in self.temporary_until.values()
            if (deadline := dt_util.parse_datetime(value)) is not None
        ]
        return min(deadlines, default=None)

    async def async_set_control_state(self, control_id: str, enabled: bool) -> None:
        """Set a control state and synchronize AdGuard rules."""
        await self._async_apply_state_changes({control_id: enabled})

    async def async_enable_control_for(self, control_id: str, minutes: int) -> None:
        """Enable a control temporarily and restore its previous state."""
        await self._async_set_control_for(control_id, True, minutes)

    async def async_disable_control_for(self, control_id: str, minutes: int) -> None:
        """Disable a control temporarily and restore its previous state."""
        await self._async_set_control_for(control_id, False, minutes)

    async def async_set_profile_state(self, profile_id: str, enabled: bool) -> None:
        """Set every control in a profile with one synchronized write."""
        profile = next((item for item in self.profiles if item.profile_id == profile_id), None)
        if profile is None:
            raise ValueError("Unknown control profile")
        await self._async_apply_state_changes(
            {control_id: enabled for control_id in profile.control_ids}
        )

    async def async_disable_all_controls(self) -> None:
        """Disable every configured control with one synchronized write."""
        await self._async_apply_state_changes(
            {control.control_id: False for control in self.controls}
        )

    async def _async_apply_state_changes(self, updates: dict[str, bool]) -> None:
        """Apply a group of control state changes and roll back atomically."""
        valid_ids = {control.control_id for control in self.controls}
        if unknown := set(updates) - valid_ids:
            raise ValueError(f"Unknown rule control: {sorted(unknown)[0]}")
        previous_states = {control_id: self.states.get(control_id, False) for control_id in updates}
        previous_timers = {
            control_id: (
                self.temporary_until.get(control_id),
                self.temporary_restore_states.get(control_id, False),
            )
            for control_id in updates
        }
        for control_id, enabled in updates.items():
            self._clear_temporary_timer(control_id)
            self.states[control_id] = enabled
        self._notify_listeners()
        await asyncio.sleep(WRITE_DEBOUNCE_SECONDS)
        try:
            await self.async_sync()
        except Exception:
            self.states.update(previous_states)
            for control_id, (deadline, restore_state) in previous_timers.items():
                if deadline:
                    self._set_temporary_timer(control_id, deadline, restore_state)
            self._notify_listeners()
            raise

    async def _async_set_control_for(self, control_id: str, enabled: bool, minutes: int) -> None:
        """Temporarily set one control and restore its previous state."""
        if minutes < 1 or minutes > MAX_TEMPORARY_BLOCK_MINUTES:
            raise ValueError(
                f"Duration must be between 1 and {MAX_TEMPORARY_BLOCK_MINUTES} minutes"
            )
        if control_id not in {control.control_id for control in self.controls}:
            raise ValueError("Unknown rule control")
        previous = self.states.get(control_id, False)
        previous_deadline = self.temporary_until.get(control_id)
        previous_restore_state = self.temporary_restore_states.get(control_id, False)
        restore_state = previous_restore_state if previous_deadline and previous == enabled else previous
        if previous == enabled and not previous_deadline:
            return
        deadline = dt_util.utcnow() + timedelta(minutes=minutes)
        self.states[control_id] = enabled
        self._set_temporary_timer(control_id, deadline.isoformat(), restore_state)
        self._notify_listeners()
        await asyncio.sleep(WRITE_DEBOUNCE_SECONDS)
        try:
            await self.async_sync()
        except Exception:
            self.states[control_id] = previous
            self._clear_temporary_timer(control_id)
            if previous_deadline:
                self._set_temporary_timer(control_id, previous_deadline, previous_restore_state)
            self._notify_listeners()
            raise

    async def async_import_states_from_adguard(self) -> set[str]:
        """Import enabled states from AdGuard without writing changes."""
        await self.async_refresh_state(raise_errors=True)
        return {control_id for control_id, enabled in self.states.items() if enabled}

    async def async_sync(self) -> None:
        """Rebuild and apply all managed rule and blocked-service state."""
        async with self._lock:
            controls = self.controls
            rule_controls = [control for control in controls if control.kind == CONTROL_KIND_RULES]
            service_controls = [control for control in controls if control.kind == CONTROL_KIND_BLOCKED_SERVICES]
            active_controls = [control for control in rule_controls if self.states.get(control.control_id, False)]
            managed_rules = build_managed_block(active_controls)
            await self.client.async_replace_managed_rules(managed_rules)
            if service_controls or self.last_managed_blocked_service_ids or self.managed_client_blocked_services:
                await self._async_sync_blocked_services(service_controls)
            self.connected = True
            self.last_error = None
            self.last_sync = dt_util.utcnow().isoformat()
            self.last_checksum = hashlib.sha256(json.dumps(managed_rules, sort_keys=True).encode()).hexdigest()
            self.managed_rule_count = sum(
                1 for rule in managed_rules if rule and not rule.startswith("!")
            )
            self.control_status = {
                control.control_id: self._status_for_control(control, self.states.get(control.control_id, False))
                for control in controls
            }
            await self._async_save_state()
            ir.async_delete_issue(self.hass, DOMAIN, "managed_state_unavailable")
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
            "temporary_until": self.temporary_until.get(control.control_id),
        }

    async def _async_sync_blocked_services(self, service_controls: list[RuleControl]) -> None:
        """Synchronize global and per-client services while preserving unrelated settings."""
        global_controls = [control for control in service_controls if control.target is None]
        client_controls = [control for control in service_controls if control.target is not None]
        global_config: dict[str, Any] | None = None
        if (
            global_controls
            or client_controls
            or self.last_managed_blocked_service_ids
            or self.managed_client_blocked_services
        ):
            global_config = await self.client.async_get_blocked_services_config()

        if global_controls or self.last_managed_blocked_service_ids:
            config = global_config or {"ids": [], "schedule": {}}
            current_ids = set(config["ids"])
            active_ids = {
                service_id
                for control in global_controls
                if self.states.get(control.control_id, False)
                for service_id in control.blocked_service_ids
            }
            next_ids = sorted((current_ids - self.last_managed_blocked_service_ids) | active_ids)
            if current_ids != set(next_ids):
                await self.client.async_update_blocked_services_config(next_ids, config["schedule"])
            self.last_managed_blocked_service_ids = set(active_ids)

        target_names = {
            control.target.identifier_value
            for control in client_controls
            if control.target is not None
        } | set(self.managed_client_blocked_services)
        if not target_names:
            return

        client_configs = {
            str(client["name"]): client
            for client in await self.client.async_get_client_configs()
        }
        for target_name in sorted(target_names):
            client = client_configs.get(target_name)
            matching = [
                control
                for control in client_controls
                if control.target is not None and control.target.identifier_value == target_name
            ]
            active_ids = {
                service_id
                for control in matching
                if self.states.get(control.control_id, False)
                for service_id in control.blocked_service_ids
            }
            tracked = self.managed_client_blocked_services.get(target_name, {})
            if client is None:
                if active_ids or tracked:
                    raise AdGuardInvalidResponseError(f"AdGuard client '{target_name}' was not found")
                continue
            current_ids = set(client.get("blocked_services", []))
            last_ids = set(tracked.get("ids", []))
            if not tracked and client.get("use_global_blocked_services", True) and global_config is not None:
                current_ids.update(global_config["ids"])
            next_ids = sorted((current_ids - last_ids) | active_ids)
            previous_use_global = bool(
                tracked.get("previous_use_global", client.get("use_global_blocked_services", True))
            )
            next_use_global = False if active_ids else previous_use_global
            if current_ids != set(next_ids) or bool(client.get("use_global_blocked_services", True)) != next_use_global:
                update = _client_update_payload(client)
                update["blocked_services"] = next_ids
                update["use_global_blocked_services"] = next_use_global
                await self.client.async_update_client_config(target_name, update)
            if active_ids:
                self.managed_client_blocked_services[target_name] = {
                    "ids": sorted(active_ids),
                    "previous_use_global": previous_use_global,
                }
            else:
                self.managed_client_blocked_services.pop(target_name, None)

    async def _async_save_state(self) -> None:
        """Persist runtime state."""
        valid_ids = {control.control_id for control in self.controls}
        await self._store.async_save(
            {
                "states": {key: value for key, value in self.states.items() if key in valid_ids},
                "last_sync": self.last_sync,
                "last_checksum": self.last_checksum,
                "control_status": {
                    key: value for key, value in self.control_status.items() if key in valid_ids
                },
                "last_managed_blocked_service_ids": sorted(self.last_managed_blocked_service_ids),
                "managed_client_blocked_services": self.managed_client_blocked_services,
                "temporary_until": {
                    key: value for key, value in self.temporary_until.items() if key in valid_ids
                },
                "temporary_restore_states": {
                    key: value
                    for key, value in self.temporary_restore_states.items()
                    if key in valid_ids and key in self.temporary_until
                },
            }
        )

    def _restore_temporary_timers(self) -> None:
        """Restore persisted temporary timers after restart."""
        valid_ids = {control.control_id for control in self.controls}
        for control_id in list(self.temporary_until):
            restore_state = self.temporary_restore_states.get(control_id, False)
            if control_id not in valid_ids or self.states.get(control_id, False) == restore_state:
                self._clear_temporary_timer(control_id)
                continue
            self._set_temporary_timer(
                control_id,
                self.temporary_until[control_id],
                restore_state,
            )

    def _discard_expired_temporary_states(self) -> None:
        """Prevent an expired temporary block from being re-applied at startup."""
        now = dt_util.utcnow()
        for control_id, deadline_iso in list(self.temporary_until.items()):
            deadline = dt_util.parse_datetime(deadline_iso)
            restore_state = self.temporary_restore_states.get(control_id, False)
            if deadline is None or dt_util.as_utc(deadline) <= now:
                self.temporary_until.pop(control_id, None)
                self.temporary_restore_states.pop(control_id, None)
                self.states[control_id] = restore_state
            elif self.states.get(control_id, False) == restore_state:
                self.temporary_until.pop(control_id, None)
                self.temporary_restore_states.pop(control_id, None)

    def _set_temporary_timer(
        self,
        control_id: str,
        deadline_iso: str,
        restore_state: bool,
    ) -> None:
        """Schedule one persisted automatic state restoration."""
        self._clear_temporary_timer(control_id)
        deadline = dt_util.parse_datetime(deadline_iso)
        if deadline is None:
            return
        deadline = dt_util.as_utc(deadline)
        delay = max(0.0, (deadline - dt_util.utcnow()).total_seconds())
        self.temporary_until[control_id] = deadline.isoformat()
        self.temporary_restore_states[control_id] = restore_state
        self._temporary_unsubs[control_id] = async_call_later(
            self.hass,
            delay,
            lambda _now: self.hass.async_create_task(self._async_expire_control(control_id)),
        )

    def _clear_temporary_timer(self, control_id: str) -> None:
        """Cancel and forget one automatic turn-off."""
        if unsub := self._temporary_unsubs.pop(control_id, None):
            unsub()
        self.temporary_until.pop(control_id, None)
        self.temporary_restore_states.pop(control_id, None)

    async def _async_expire_control(self, control_id: str) -> None:
        """Turn off a control whose temporary period ended."""
        self._temporary_unsubs.pop(control_id, None)
        self.temporary_until.pop(control_id, None)
        restore_state = self.temporary_restore_states.pop(control_id, False)
        if control_id not in {control.control_id for control in self.controls}:
            await self._async_save_state()
            return
        self.states[control_id] = restore_state
        try:
            await self.async_sync()
        except Exception as err:  # noqa: BLE001 - expose the sanitized API error on entities
            self.last_error = str(err)
            self._notify_listeners()

    async def _async_refresh_activity(self) -> None:
        """Refresh optional aggregate activity without retaining query-log rows."""
        if not self.activity_enabled:
            self.activity_summary = {}
            self.activity_last_refresh = None
            self.activity_error = None
            return
        now = dt_util.utcnow()
        if (
            self.activity_last_refresh is not None
            and (now - self.activity_last_refresh).total_seconds()
            < ACTIVITY_REFRESH_INTERVAL_SECONDS
        ):
            return
        limit = int(self.entry.options.get(CONF_ACTIVITY_LIMIT, DEFAULT_ACTIVITY_LIMIT))
        try:
            self.activity_summary = await self.client.async_get_blocked_activity(limit=limit)
            self.activity_last_refresh = now
            self.activity_error = None
        except (AdGuardConnectionError, AdGuardInvalidResponseError) as err:
            self.activity_error = str(err)

    def _create_issue(self, issue_id: str, error: str) -> None:
        """Create an actionable Home Assistant repair issue."""
        ir.async_create_issue(
            self.hass,
            DOMAIN,
            issue_id,
            is_fixable=False,
            severity=ir.IssueSeverity.WARNING,
            translation_key=issue_id,
            translation_placeholders={"error": error},
        )


_CLIENT_UPDATE_FIELDS = {
    "name",
    "ids",
    "use_global_settings",
    "filtering_enabled",
    "parental_enabled",
    "safebrowsing_enabled",
    "safesearch_enabled",
    "safe_search",
    "use_global_blocked_services",
    "blocked_services_schedule",
    "blocked_services",
    "upstreams",
    "tags",
    "ignore_querylog",
    "ignore_statistics",
    "upstreams_cache_enabled",
    "upstreams_cache_size",
}


def _client_update_payload(client: dict[str, Any]) -> dict[str, Any]:
    """Strip read-only fields before sending a full client update."""
    return {key: value for key, value in client.items() if key in _CLIENT_UPDATE_FIELDS}


def get_manager(hass: HomeAssistant, entry: ConfigEntry) -> AdGuardRuleControlManager:
    """Return the manager for an entry."""
    return hass.data[DOMAIN][entry.entry_id]
