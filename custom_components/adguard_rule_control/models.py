"""Data models for AdGuard Rule Control."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .const import (
    CONF_BLOCKED_SERVICE_IDS,
    CONF_CONTROL_ID,
    CONF_DISPLAY_NAME,
    CONF_ENTITY_ENABLED,
    CONF_ICON,
    CONF_KIND,
    CONF_RULES,
    CONF_TARGET,
    CONF_TARGET_NAME,
    CONF_TARGET_TYPE,
    CONF_TARGET_VALUE,
    CONTROL_KIND_RULES,
    TARGET_GLOBAL,
)


@dataclass(frozen=True)
class ClientTarget:
    """Configured AdGuard client target."""

    display_name: str
    identifier_type: str
    identifier_value: str

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "ClientTarget | None":
        """Create a target from stored options."""
        if not data:
            return None
        identifier_type = data.get(CONF_TARGET_TYPE, TARGET_GLOBAL)
        if identifier_type == TARGET_GLOBAL:
            return None
        return cls(
            display_name=data.get(CONF_TARGET_NAME) or data.get(CONF_TARGET_VALUE, ""),
            identifier_type=identifier_type,
            identifier_value=data.get(CONF_TARGET_VALUE, ""),
        )

    def as_dict(self) -> dict[str, Any]:
        """Return a storage-safe dictionary."""
        return {
            CONF_TARGET_NAME: self.display_name,
            CONF_TARGET_TYPE: self.identifier_type,
            CONF_TARGET_VALUE: self.identifier_value,
        }


@dataclass(frozen=True)
class RuleControl:
    """A configured rule control."""

    control_id: str
    display_name: str
    rules: tuple[str, ...]
    entity_enabled: bool = True
    target: ClientTarget | None = None
    icon: str | None = None
    kind: str = CONTROL_KIND_RULES
    blocked_service_ids: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RuleControl":
        """Create a control from config entry options."""
        return cls(
            control_id=data[CONF_CONTROL_ID],
            display_name=data[CONF_DISPLAY_NAME],
            rules=tuple(data.get(CONF_RULES, [])),
            entity_enabled=data.get(CONF_ENTITY_ENABLED, True),
            target=ClientTarget.from_dict(data.get(CONF_TARGET)),
            icon=data.get(CONF_ICON) or None,
            kind=data.get(CONF_KIND, CONTROL_KIND_RULES),
            blocked_service_ids=tuple(data.get(CONF_BLOCKED_SERVICE_IDS, [])),
        )

    def as_dict(self) -> dict[str, Any]:
        """Return a storage-safe dictionary."""
        data: dict[str, Any] = {
            CONF_CONTROL_ID: self.control_id,
            CONF_DISPLAY_NAME: self.display_name,
            CONF_RULES: list(self.rules),
            CONF_ENTITY_ENABLED: self.entity_enabled,
            CONF_KIND: self.kind,
        }
        if self.blocked_service_ids:
            data[CONF_BLOCKED_SERVICE_IDS] = list(self.blocked_service_ids)
        if self.target:
            data[CONF_TARGET] = self.target.as_dict()
        if self.icon:
            data[CONF_ICON] = self.icon
        return data
