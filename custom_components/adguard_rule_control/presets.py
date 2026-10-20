from collections.abc import Mapping, Sequence

PRESET_CUSTOM = "custom"
PRESET_BLOCK_WEBSITE = "block_website"

BLOCKED_SERVICE_PRESET_CUSTOM = "custom"
BLOCKED_SERVICE_PRESET_ALL = "all"
BLOCKED_SERVICE_GROUP_PREFIX = "group:"


def _humanize_group_id(group_id: str) -> str:
    """Return a readable label for an AdGuard service group."""
    return group_id.replace("_", " ").replace("-", " ").title()


def blocked_service_preset_choices(
    groups: Mapping[str, Sequence[str]],
) -> dict[str, str]:
    """Build blocked-service preset choices from AdGuard's API data."""
    choices = {
        BLOCKED_SERVICE_PRESET_CUSTOM: "Choose individual services",
        BLOCKED_SERVICE_PRESET_ALL: "All services available in AdGuard",
    }

    for group_id, service_ids in sorted(groups.items()):
        if not service_ids:
            continue

        key = f"{BLOCKED_SERVICE_GROUP_PREFIX}{group_id}"
        name = _humanize_group_id(group_id)
        choices[key] = f"{name} ({len(service_ids)} services)"

    return choices


def blocked_service_preset_ids(
    key: str,
    available_ids: set[str],
    groups: Mapping[str, Sequence[str]],
) -> tuple[str, ...]:
    """Return service IDs for a preset generated from AdGuard's API."""
    if key == BLOCKED_SERVICE_PRESET_ALL:
        return tuple(sorted(available_ids))

    if key in {
        BLOCKED_SERVICE_PRESET_CUSTOM,
        PRESET_CUSTOM,
    }:
        return ()

    if not key.startswith(BLOCKED_SERVICE_GROUP_PREFIX):
        return ()

    group_id = key.removeprefix(BLOCKED_SERVICE_GROUP_PREFIX)
    service_ids = groups.get(group_id, ())

    return tuple(
        service_id
        for service_id in service_ids
        if service_id in available_ids
    )


def blocked_service_preset_name(
    key: str,
    groups: Mapping[str, Sequence[str]],
) -> str:
    """Return a display name for a dynamically generated service preset."""
    if key == BLOCKED_SERVICE_PRESET_ALL:
        return "Block All Services"

    if key.startswith(BLOCKED_SERVICE_GROUP_PREFIX):
        group_id = key.removeprefix(BLOCKED_SERVICE_GROUP_PREFIX)
        if group_id in groups:
            return f"Block {_humanize_group_id(group_id)}"

    return "Block Services"