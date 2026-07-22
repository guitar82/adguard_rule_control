"""Tests for managed blocked-service coordination."""

from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import pytest
from homeassistant.util import dt as dt_util

from custom_components.adguard_rule_control import coordinator as coordinator_module
from custom_components.adguard_rule_control.const import CONF_CONTROLS, CONF_PROFILES
from custom_components.adguard_rule_control.coordinator import (
    AdGuardRuleControlManager,
    _client_update_payload,
)
from custom_components.adguard_rule_control.models import ClientTarget, ControlProfile, RuleControl


class FakeBlockedServiceClient:
    """Small stateful client for per-client service tests."""

    def __init__(self) -> None:
        self.global_config = {"ids": ["instagram"], "schedule": {"time_zone": "Local"}}
        self.client_config: dict[str, Any] = {
            "name": "Kid Tablet",
            "ids": ["192.168.1.30"],
            "use_global_settings": True,
            "filtering_enabled": True,
            "use_global_blocked_services": True,
            "blocked_services": [],
            "whois_info": {"country": "US"},
        }
        self.updates: list[dict[str, Any]] = []

    async def async_get_blocked_services_config(self) -> dict[str, Any]:
        return self.global_config

    async def async_get_client_configs(self) -> list[dict[str, Any]]:
        return [dict(self.client_config)]

    async def async_update_client_config(self, current_name: str, data: dict[str, Any]) -> None:
        assert current_name == "Kid Tablet"
        self.client_config = dict(data)
        self.updates.append(dict(data))


def _client_service_control() -> RuleControl:
    return RuleControl(
        control_id="youtube-tablet",
        display_name="Block YouTube on Tablet",
        rules=(),
        kind="blocked_services",
        blocked_service_ids=("youtube",),
        target=ClientTarget("Kid Tablet", "client_name", "Kid Tablet"),
    )


@pytest.mark.asyncio
async def test_per_client_services_preserve_global_protection(monkeypatch: pytest.MonkeyPatch) -> None:
    control = _client_service_control()
    entry = SimpleNamespace(entry_id="entry", options={CONF_CONTROLS: [control.as_dict()]})
    client = FakeBlockedServiceClient()
    monkeypatch.setattr(coordinator_module, "Store", lambda *_args, **_kwargs: SimpleNamespace())
    manager = AdGuardRuleControlManager(SimpleNamespace(), entry, client)
    manager.states[control.control_id] = True

    await manager._async_sync_blocked_services([control])

    assert client.updates[-1]["use_global_blocked_services"] is False
    assert client.updates[-1]["blocked_services"] == ["instagram", "youtube"]
    assert "whois_info" not in client.updates[-1]


@pytest.mark.asyncio
async def test_per_client_services_restore_global_inheritance(monkeypatch: pytest.MonkeyPatch) -> None:
    control = _client_service_control()
    entry = SimpleNamespace(entry_id="entry", options={CONF_CONTROLS: [control.as_dict()]})
    client = FakeBlockedServiceClient()
    monkeypatch.setattr(coordinator_module, "Store", lambda *_args, **_kwargs: SimpleNamespace())
    manager = AdGuardRuleControlManager(SimpleNamespace(), entry, client)
    manager.states[control.control_id] = True
    await manager._async_sync_blocked_services([control])

    manager.states[control.control_id] = False
    await manager._async_sync_blocked_services([control])

    assert client.updates[-1]["use_global_blocked_services"] is True
    assert client.updates[-1]["blocked_services"] == ["instagram"]
    assert manager.managed_client_blocked_services == {}


def test_client_update_payload_removes_read_only_fields() -> None:
    payload = _client_update_payload(
        {
            "name": "Kid Tablet",
            "ids": ["192.168.1.30"],
            "blocked_services": ["youtube"],
            "whois_info": {"country": "US"},
            "ip_addrs": ["192.168.1.30"],
        }
    )
    assert payload == {
        "name": "Kid Tablet",
        "ids": ["192.168.1.30"],
        "blocked_services": ["youtube"],
    }


@pytest.mark.asyncio
async def test_temporary_block_sets_restart_safe_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    control = _client_service_control()
    entry = SimpleNamespace(entry_id="entry", options={CONF_CONTROLS: [control.as_dict()]})
    monkeypatch.setattr(coordinator_module, "Store", lambda *_args, **_kwargs: SimpleNamespace())
    monkeypatch.setattr(coordinator_module, "async_call_later", lambda *_args, **_kwargs: lambda: None)
    monkeypatch.setattr(coordinator_module.asyncio, "sleep", AsyncMock())
    manager = AdGuardRuleControlManager(SimpleNamespace(), entry, FakeBlockedServiceClient())
    manager.async_sync = AsyncMock()

    await manager.async_enable_control_for(control.control_id, 30)

    assert manager.states[control.control_id] is True
    assert manager.temporary_until_for(control.control_id) is not None
    assert manager.temporary_restore_state_for(control.control_id) is False
    manager.async_sync.assert_awaited_once()


@pytest.mark.asyncio
async def test_temporary_allow_restores_previous_block(monkeypatch: pytest.MonkeyPatch) -> None:
    control = _client_service_control()
    entry = SimpleNamespace(entry_id="entry", options={CONF_CONTROLS: [control.as_dict()]})
    monkeypatch.setattr(coordinator_module, "Store", lambda *_args, **_kwargs: SimpleNamespace())
    monkeypatch.setattr(coordinator_module, "async_call_later", lambda *_args, **_kwargs: lambda: None)
    monkeypatch.setattr(coordinator_module.asyncio, "sleep", AsyncMock())
    manager = AdGuardRuleControlManager(SimpleNamespace(), entry, FakeBlockedServiceClient())
    manager.states[control.control_id] = True
    manager.async_sync = AsyncMock()

    await manager.async_disable_control_for(control.control_id, 30)

    assert manager.states[control.control_id] is False
    assert manager.temporary_restore_state_for(control.control_id) is True

    await manager._async_expire_control(control.control_id)

    assert manager.states[control.control_id] is True
    assert manager.temporary_until_for(control.control_id) is None
    assert manager.async_sync.await_count == 2


@pytest.mark.asyncio
async def test_profile_and_allow_all_use_single_sync(monkeypatch: pytest.MonkeyPatch) -> None:
    first = _client_service_control()
    second = RuleControl(
        control_id="gaming-tablet",
        display_name="Block Gaming on Tablet",
        rules=(),
        kind="blocked_services",
        blocked_service_ids=("steam",),
        target=first.target,
    )
    profile = ControlProfile(
        profile_id="bedtime",
        display_name="Bedtime",
        control_ids=(first.control_id, second.control_id),
    )
    entry = SimpleNamespace(
        entry_id="entry",
        options={
            CONF_CONTROLS: [first.as_dict(), second.as_dict()],
            CONF_PROFILES: [profile.as_dict()],
        },
    )
    monkeypatch.setattr(coordinator_module, "Store", lambda *_args, **_kwargs: SimpleNamespace())
    monkeypatch.setattr(coordinator_module.asyncio, "sleep", AsyncMock())
    manager = AdGuardRuleControlManager(SimpleNamespace(), entry, FakeBlockedServiceClient())
    manager.async_sync = AsyncMock()

    await manager.async_set_profile_state(profile.profile_id, True)

    assert manager.profile_state_for(profile.profile_id) is True
    assert manager.async_sync.await_count == 1

    await manager.async_disable_all_controls()

    assert not any(manager.states.values())
    assert manager.async_sync.await_count == 2


def test_expired_temporary_block_is_not_reapplied(monkeypatch: pytest.MonkeyPatch) -> None:
    control = _client_service_control()
    entry = SimpleNamespace(entry_id="entry", options={CONF_CONTROLS: [control.as_dict()]})
    monkeypatch.setattr(coordinator_module, "Store", lambda *_args, **_kwargs: SimpleNamespace())
    manager = AdGuardRuleControlManager(SimpleNamespace(), entry, FakeBlockedServiceClient())
    manager.states[control.control_id] = True
    manager.temporary_until[control.control_id] = (dt_util.utcnow() - timedelta(minutes=1)).isoformat()

    manager._discard_expired_temporary_states()

    assert manager.states[control.control_id] is False
    assert manager.temporary_until_for(control.control_id) is None


def test_expired_temporary_allow_restores_block(monkeypatch: pytest.MonkeyPatch) -> None:
    control = _client_service_control()
    entry = SimpleNamespace(entry_id="entry", options={CONF_CONTROLS: [control.as_dict()]})
    monkeypatch.setattr(coordinator_module, "Store", lambda *_args, **_kwargs: SimpleNamespace())
    manager = AdGuardRuleControlManager(SimpleNamespace(), entry, FakeBlockedServiceClient())
    manager.states[control.control_id] = False
    manager.temporary_until[control.control_id] = (
        dt_util.utcnow() - timedelta(minutes=1)
    ).isoformat()
    manager.temporary_restore_states[control.control_id] = True

    manager._discard_expired_temporary_states()

    assert manager.states[control.control_id] is True
    assert manager.temporary_until_for(control.control_id) is None
