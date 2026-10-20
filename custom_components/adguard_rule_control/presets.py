
"""Dynamic presets built from the AdGuard Home service catalog."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

PRESET_CUSTOM = "custom"
PRESET_BLOCK_WEBSITE = "block_website"

BLOCKED_SERVICE_PRESET_CUSTOM = "custom"
BLOCKED_SERVICE_PRESET_ALL = "all"


@dataclass(frozen=True)
class RulePreset:
    """A rule preset displayed in the options flow."""

    key: str
    name: str
    description: str
    icon: str
    rules: tuple[str, ...]


def build_blocked_service_presets(
    catalog: dict[str, Any],
) -> dict[str, tuple[str, tuple[str, ...]]]:
    """Build service-group presets from the AdGuard API catalog."""
    services = catalog.get("blocked_services", [])
    groups = catalog.get("groups", [])

    if not isinstance(services, list):
        services = []
    if not isinstance(groups, list):
        groups = []

    group_names: dict[str, str] = {}
    for group in groups:
        if not isinstance(group, dict):
            continue
        group_id = str(group.get("id") or "").strip()
        if group_id:
            group_names[group_id] = str(
                group.get("name") or _humanize(group_id)
            )

    grouped_ids: dict[str, list[str]] = {}
    for service in services:
        if not isinstance(service, dict):
            continue

        service_id = str(service.get("id") or "").strip()
        group_id = str(service.get("group_id") or "").strip()

        if service_id and group_id:
            grouped_ids.setdefault(group_id, []).append(service_id)

    presets: dict[str, tuple[str, tuple[str, ...]]] = {}
    for group_id, service_ids in grouped_ids.items():
        presets[group_id] = (
            group_names.get(group_id, _humanize(group_id)),
            tuple(sorted(set(service_ids))),
        )

    return presets


def build_rule_presets(catalog: dict[str, Any]) -> tuple[RulePreset, ...]:
    """Build individual service rule presets from API-provided rules."""
    services = catalog.get("blocked_services", [])
    if not isinstance(services, list):
        services = []

    presets: list[RulePreset] = []
    for service in services:
        if not isinstance(service, dict):
            continue

        service_id = str(service.get("id") or "").strip()
        service_name = str(
            service.get("name") or _humanize(service_id)
        ).strip()
        raw_rules = service.get("rules", [])

        if not service_id or not isinstance(raw_rules, list):
            continue

        rules = tuple(
            rule.strip()
            for rule in raw_rules
            if isinstance(rule, str) and rule.strip()
        )
        if not rules:
            continue

        presets.append(
            RulePreset(
                key=f"service_{service_id}",
                name=f"Block {service_name}",
                description=(
                    f"Blocks {service_name} using rules supplied by AdGuard Home."
                ),
                icon="mdi:shield-block",
                rules=rules,
            )
        )

    # Generic presets are not tied to any particular service in the API.
    presets.extend(
        (
            RulePreset(
                key="block_all",
                name="Block All Internet",
                description=(
                    "Blocks all DNS lookups for the selected target. "
                    "Best used only with one device/client."
                ),
                icon="mdi:wifi-off",
                rules=("||*^",),
            ),
            RulePreset(
                key="custom_domain",
                name="Custom Domain Block",
                description="Starts with one example domain rule that you can edit.",
                icon="mdi:web-off",
                rules=("||example.com^",),
            ),
        )
    )

    return tuple(presets)


def preset_choices(
    presets: tuple[RulePreset, ...] = (),
) -> dict[str, str]:
    """Return choices for the rule-preset options flow."""
    choices = {
        PRESET_BLOCK_WEBSITE: "Block a website by name - easiest for one site",
        PRESET_CUSTOM: "Advanced custom rules",
    }
    choices.update({
        preset.key: f"{preset.name} - {preset.description}"
        for preset in presets
    })
    return choices


def get_preset(
    key: str,
    presets: tuple[RulePreset, ...] = (),
) -> RulePreset | None:
    """Return a rule preset by key."""
    return next(
        (preset for preset in presets if preset.key == key),
        None,
    )


def blocked_service_preset_choices(
    presets: dict[str, tuple[str, tuple[str, ...]]],
) -> dict[str, str]:
    """Return service-group choices built from the API catalog."""
    choices = {
        BLOCKED_SERVICE_PRESET_CUSTOM: "Choose individual services",
        BLOCKED_SERVICE_PRESET_ALL: "All services available in AdGuard",
    }
    choices.update({
        key: name
        for key, (name, _service_ids) in presets.items()
    })
    return choices


def blocked_service_preset_ids(
    key: str,
    available_ids: set[str],
    presets: dict[str, tuple[str, tuple[str, ...]]],
) -> tuple[str, ...]:
    """Return valid service IDs belonging to the selected group."""
    if key == BLOCKED_SERVICE_PRESET_ALL:
        return tuple(sorted(available_ids))

    preset = presets.get(key)
    if preset is None:
        return ()

    # The preset is (group_name, service_ids).
    # Return only IDs that are actually available from AdGuard.
    _group_name, service_ids = preset
    return tuple(
        service_id
        for service_id in service_ids
        if service_id in available_ids
    )


def blocked_service_preset_name(
    key: str,
    presets: dict[str, tuple[str, tuple[str, ...]]],
) -> str:
    """Return a display name for a blocked-service preset."""
    if key == BLOCKED_SERVICE_PRESET_ALL:
        return "Block All Services"

    preset = presets.get(key)
    return f"Block {preset[0]}" if preset else "Block Services"


def _humanize(value: str) -> str:
    """Convert an API identifier into a readable label."""
    return value.replace("_", " ").replace("-", " ").title()
