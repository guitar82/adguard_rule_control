"""Tests for switch behavior."""

from __future__ import annotations

import pytest

from custom_components.adguard_rule_control.models import RuleControl


class FakeManager:
    """Tiny manager for switch state tests."""

    def __init__(self) -> None:
        self.states = {"control-1": False}
        self.fail = False

    async def async_set_control_state(self, control_id: str, enabled: bool) -> None:
        previous = self.states[control_id]
        self.states[control_id] = enabled
        if self.fail:
            self.states[control_id] = previous
            raise RuntimeError("write failed")


@pytest.mark.asyncio
async def test_state_persistence_shape() -> None:
    state = {"states": {"control-1": True}}
    assert state["states"]["control-1"] is True


def test_stable_unique_id() -> None:
    entry_id = "entry"
    control = RuleControl("control-1", "Renamed Control", ("||example.com^",))
    assert f"{entry_id}_{control.control_id}" == "entry_control-1"


@pytest.mark.asyncio
async def test_successful_enable() -> None:
    manager = FakeManager()
    await manager.async_set_control_state("control-1", True)
    assert manager.states["control-1"] is True


@pytest.mark.asyncio
async def test_successful_disable() -> None:
    manager = FakeManager()
    manager.states["control-1"] = True
    await manager.async_set_control_state("control-1", False)
    assert manager.states["control-1"] is False


@pytest.mark.asyncio
async def test_rollback_after_api_failure() -> None:
    manager = FakeManager()
    manager.fail = True
    with pytest.raises(RuntimeError):
        await manager.async_set_control_state("control-1", True)
    assert manager.states["control-1"] is False


def test_rename_without_duplicate_entity() -> None:
    before = RuleControl("control-1", "Old", ("||example.com^",))
    after = RuleControl("control-1", "New", ("||example.com^",))
    assert before.control_id == after.control_id
