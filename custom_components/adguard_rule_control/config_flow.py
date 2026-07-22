"""Config and options flow for AdGuard Rule Control."""

from __future__ import annotations

import uuid
from typing import Any
from urllib.parse import urlparse

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import (
    AdGuardAuthenticationError,
    AdGuardConnectionError,
    AdGuardInvalidResponseError,
    AdGuardRuleControlClient,
)
from .const import (
    AUDIENCE_CLIENT,
    AUDIENCE_EVERYONE,
    CLIENT_CHOICE_MANUAL,
    CONF_AUDIENCE,
    CONF_BASE_URL,
    CONF_CLIENT_CHOICE,
    CONF_CONTROL_ID,
    CONF_CONTROLS,
    CONF_DISPLAY_NAME,
    CONF_DOMAIN,
    CONF_ENTITY_ENABLED,
    CONF_HOST,
    CONF_ICON,
    CONF_PORT,
    CONF_PRESET,
    CONF_RULES,
    CONF_TARGET,
    CONF_TARGET_NAME,
    CONF_TARGET_TYPE,
    CONF_TARGET_VALUE,
    CONF_USE_SSL,
    CONF_VERIFY_SSL,
    DOMAIN,
    MAX_PREVIEW_LINES,
    NAME,
    TARGET_GLOBAL,
    TARGET_TYPES,
)
from .models import ClientTarget, RuleControl
from .presets import PRESET_BLOCK_WEBSITE, PRESET_CUSTOM, get_preset, preset_choices
from .rule_builder import (
    RuleBuilderError,
    domain_to_block_rule,
    preview_control,
    validate_client_identifier,
    validate_comment_label,
    validate_rule,
)


def normalize_base_url(host: str, port: int | None, use_ssl: bool) -> str:
    """Normalize flexible AdGuard host input into a base URL."""
    value = host.strip()
    if not value:
        raise ValueError("Host is required")
    if "://" not in value:
        value = f"{'https' if use_ssl else 'http'}://{value}"
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Invalid URL")
    netloc = parsed.netloc
    if port and parsed.port is None:
        netloc = f"{parsed.hostname}:{port}"
    path = parsed.path.rstrip("/")
    if path.endswith("/control"):
        path = path[: -len("/control")]
    return f"{parsed.scheme}://{netloc}{path}".rstrip("/")


class ConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow."""

    VERSION = 1

    async def async_step_user(self, user_input: dict[str, Any] | None = None):
        """Configure the AdGuard connection."""
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                base_url = normalize_base_url(
                    user_input[CONF_HOST],
                    user_input.get(CONF_PORT),
                    user_input[CONF_USE_SSL],
                )
                await self.async_set_unique_id(base_url)
                self._abort_if_unique_id_configured()
                client = AdGuardRuleControlClient(
                    async_get_clientsession(self.hass),
                    base_url,
                    user_input.get(CONF_USERNAME),
                    user_input.get(CONF_PASSWORD),
                    user_input[CONF_VERIFY_SSL],
                )
                await client.async_test_connection()
            except ValueError:
                errors["base"] = "invalid_url"
            except AdGuardAuthenticationError:
                errors["base"] = "invalid_auth"
            except AdGuardConnectionError:
                errors["base"] = "cannot_connect"
            except AdGuardInvalidResponseError:
                errors["base"] = "invalid_response"
            else:
                return self.async_create_entry(
                    title=NAME,
                    data={
                        CONF_BASE_URL: base_url,
                        CONF_USERNAME: user_input.get(CONF_USERNAME, ""),
                        CONF_PASSWORD: user_input.get(CONF_PASSWORD, ""),
                        CONF_VERIFY_SSL: user_input[CONF_VERIFY_SSL],
                    },
                    options={CONF_CONTROLS: []},
                )
        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_HOST): str,
                    vol.Optional(CONF_PORT): int,
                    vol.Required(CONF_USE_SSL, default=False): bool,
                    vol.Required(CONF_VERIFY_SSL, default=True): bool,
                    vol.Optional(CONF_USERNAME): str,
                    vol.Optional(CONF_PASSWORD): str,
                }
            ),
            errors=errors,
        )

    @staticmethod
    def async_get_options_flow(config_entry):
        """Return options flow handler."""
        return OptionsFlowHandler(config_entry)


class OptionsFlowHandler(config_entries.OptionsFlow):
    """Manage rule controls from integration options."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        self._config_entry = config_entry
        self._controls = list(config_entry.options.get(CONF_CONTROLS, []))
        self._edit_index: int | None = None
        self._select_action: str | None = None
        self._preset_defaults: dict[str, Any] = {}
        self._pending_control: dict[str, Any] | None = None
        self._client_choices_data: dict[str, dict[str, str]] = {}

    async def async_step_init(self, user_input: dict[str, Any] | None = None):
        """Choose an options action."""
        errors: dict[str, str] = {}
        if user_input is not None:
            action = user_input["action"]
            if action == "add":
                return await self.async_step_preset()
            if action in {"edit", "duplicate", "preview"}:
                if not self._controls:
                    errors["base"] = "no_controls"
                else:
                    self._select_action = action
                    return await self.async_step_select_control()
            if action == "delete":
                if not self._controls:
                    errors["base"] = "no_controls"
                else:
                    return await self.async_step_delete()
            if action == "move":
                if not self._controls:
                    errors["base"] = "no_controls"
                else:
                    return await self.async_step_move()
            if action == "import_state":
                return await self.async_step_import_state()
            if not errors:
                return self._save()
        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Required("action", default="add"): vol.In(
                        ["add", "edit", "duplicate", "delete", "move", "preview", "import_state", "finish"]
                    )
                }
            ),
            errors=errors,
        )

    async def async_step_preset(self, user_input: dict[str, Any] | None = None):
        """Choose a rule preset for a new control."""
        if user_input is not None:
            preset_key = user_input[CONF_PRESET]
            if preset_key == PRESET_BLOCK_WEBSITE:
                return await self.async_step_website()
            preset = get_preset(preset_key)
            if preset:
                self._preset_defaults = {
                    CONF_DISPLAY_NAME: preset.name,
                    CONF_RULES: list(preset.rules),
                    CONF_ICON: preset.icon,
                }
            else:
                self._preset_defaults = {}
            if preset_key == PRESET_CUSTOM:
                return await self.async_step_control()
            return await self.async_step_audience()
        return self.async_show_form(
            step_id="preset",
            data_schema=vol.Schema({vol.Required(CONF_PRESET, default=PRESET_BLOCK_WEBSITE): vol.In(preset_choices())}),
        )

    async def async_step_website(self, user_input: dict[str, Any] | None = None):
        """Build a simple block rule from a website name."""
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                rule = domain_to_block_rule(user_input[CONF_DOMAIN])
            except RuleBuilderError:
                errors["base"] = "invalid_domain"
            else:
                domain = rule.removeprefix("||").removesuffix("^")
                self._preset_defaults = {
                    CONF_DISPLAY_NAME: f"Block {domain}",
                    CONF_RULES: [rule],
                    CONF_ICON: "mdi:web-off",
                }
                return await self.async_step_audience()
        return self.async_show_form(
            step_id="website",
            data_schema=vol.Schema({vol.Required(CONF_DOMAIN): str}),
            errors=errors,
        )

    async def async_step_audience(self, user_input: dict[str, Any] | None = None):
        """Choose whether a new control applies globally or to one client."""
        if user_input is not None:
            if user_input[CONF_AUDIENCE] == AUDIENCE_EVERYONE:
                self._preset_defaults.pop(CONF_TARGET, None)
                return await self.async_step_control()
            return await self.async_step_client()
        return self.async_show_form(
            step_id="audience",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_AUDIENCE, default=AUDIENCE_CLIENT): vol.In(
                        {
                            AUDIENCE_CLIENT: "One device or AdGuard client",
                            AUDIENCE_EVERYONE: "Everyone using this AdGuard Home instance",
                        }
                    )
                }
            ),
        )

    async def async_step_client(self, user_input: dict[str, Any] | None = None):
        """Select a discovered AdGuard client or enter one manually."""
        if user_input is not None:
            choice_key = user_input[CONF_CLIENT_CHOICE]
            if choice_key == CLIENT_CHOICE_MANUAL:
                return await self.async_step_manual_target()
            choice = self._client_choices_data[choice_key]
            self._preset_defaults[CONF_TARGET] = {
                CONF_TARGET_NAME: choice["display_name"],
                CONF_TARGET_TYPE: choice["identifier_type"],
                CONF_TARGET_VALUE: choice["identifier_value"],
            }
            return await self.async_step_control()

        choices: dict[str, str] = {}
        manager = self.hass.data.get(DOMAIN, {}).get(self._config_entry.entry_id)
        if manager is not None:
            try:
                discovered = await manager.client.async_get_clients()
            except Exception:  # noqa: BLE001 - fallback keeps the easy flow usable
                discovered = []
            self._client_choices_data = {
                str(index): choice
                for index, choice in enumerate(discovered)
            }
            choices.update({key: choice["display_name"] for key, choice in self._client_choices_data.items()})
        else:
            self._client_choices_data = {}
        choices[CLIENT_CHOICE_MANUAL] = "Enter client manually"
        return self.async_show_form(
            step_id="client",
            data_schema=vol.Schema({vol.Required(CONF_CLIENT_CHOICE): vol.In(choices)}),
        )

    async def async_step_manual_target(self, user_input: dict[str, Any] | None = None):
        """Enter a client target manually."""
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                value = validate_client_identifier(user_input[CONF_TARGET_TYPE], user_input[CONF_TARGET_VALUE])
                target_name = validate_comment_label(user_input.get(CONF_TARGET_NAME) or value, "Target display name")
            except RuleBuilderError:
                errors["base"] = "invalid_rule"
            else:
                self._preset_defaults[CONF_TARGET] = {
                    CONF_TARGET_NAME: target_name,
                    CONF_TARGET_TYPE: user_input[CONF_TARGET_TYPE],
                    CONF_TARGET_VALUE: value,
                }
                return await self.async_step_control()
        return self.async_show_form(
            step_id="manual_target",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_TARGET_TYPE): vol.In([target for target in TARGET_TYPES if target != TARGET_GLOBAL]),
                    vol.Optional(CONF_TARGET_NAME): str,
                    vol.Required(CONF_TARGET_VALUE): str,
                }
            ),
            errors=errors,
        )

    async def async_step_select_control(self, user_input: dict[str, Any] | None = None):
        """Select a control for an action."""
        controls = _control_choices(self._controls)
        if user_input is not None:
            selected = user_input[CONF_CONTROL_ID]
            self._edit_index = _find_control_index(self._controls, selected)
            if self._select_action == "duplicate":
                duplicated = dict(self._controls[self._edit_index])
                duplicated[CONF_CONTROL_ID] = str(uuid.uuid4())
                duplicated[CONF_DISPLAY_NAME] = f"Copy of {duplicated[CONF_DISPLAY_NAME]}"
                self._controls.append(duplicated)
                return self._save()
            if self._select_action == "preview":
                return await self.async_step_preview()
            return await self.async_step_control()
        return self.async_show_form(
            step_id="select_control",
            data_schema=vol.Schema({vol.Required(CONF_CONTROL_ID): vol.In(controls)}),
        )

    async def async_step_delete(self, user_input: dict[str, Any] | None = None):
        """Delete a configured control."""
        controls = _control_choices(self._controls)
        if user_input is not None:
            selected = user_input[CONF_CONTROL_ID]
            self._controls = [control for control in self._controls if control[CONF_CONTROL_ID] != selected]
            return self._save()
        return self.async_show_form(step_id="delete", data_schema=vol.Schema({vol.Required(CONF_CONTROL_ID): vol.In(controls)}))

    async def async_step_move(self, user_input: dict[str, Any] | None = None):
        """Move a configured control up or down."""
        controls = _control_choices(self._controls)
        if user_input is not None:
            index = _find_control_index(self._controls, user_input[CONF_CONTROL_ID])
            new_index = index - 1 if user_input["direction"] == "up" else index + 1
            if 0 <= new_index < len(self._controls):
                self._controls[index], self._controls[new_index] = self._controls[new_index], self._controls[index]
            return self._save()
        return self.async_show_form(
            step_id="move",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_CONTROL_ID): vol.In(controls),
                    vol.Required("direction", default="up"): vol.In(["up", "down"]),
                }
            ),
        )

    async def async_step_preview(self, user_input: dict[str, Any] | None = None):
        """Preview generated managed rules for one control."""
        if user_input is not None:
            if user_input["next"] == "finish":
                return self._save()
            self._edit_index = None
            return await self.async_step_init()
        control = RuleControl.from_dict(self._controls[self._edit_index])
        try:
            lines = preview_control(control)
        except RuleBuilderError as err:
            preview = str(err)
        else:
            extra = len(lines) - MAX_PREVIEW_LINES
            preview_lines = lines[:MAX_PREVIEW_LINES]
            if extra > 0:
                preview_lines.append(f"... {extra} more lines")
            preview = "\n".join(preview_lines) or "No rules would be generated."
        return self.async_show_form(
            step_id="preview",
            data_schema=vol.Schema({vol.Required("next", default="back"): vol.In(["back", "finish"])}),
            description_placeholders={"preview": preview},
        )

    async def async_step_import_state(self, user_input: dict[str, Any] | None = None):
        """Import enabled states from the current AdGuard managed block."""
        if user_input is not None:
            return self._save()
        manager = self.hass.data.get(DOMAIN, {}).get(self._config_entry.entry_id)
        if manager is None:
            message = "The integration is not loaded, so current AdGuard state could not be imported."
            imported_count = 0
        else:
            try:
                imported = await manager.async_import_states_from_adguard()
            except Exception as err:  # noqa: BLE001 - show sanitized options-flow feedback
                message = str(err)
                imported_count = 0
            else:
                imported_count = len(imported)
                message = f"Imported enabled state for {imported_count} control(s)."
        return self.async_show_form(
            step_id="import_state",
            data_schema=vol.Schema({vol.Required("next", default="finish"): vol.In(["finish"])}),
            description_placeholders={"message": message, "imported_count": str(imported_count)},
        )

    async def async_step_control(self, user_input: dict[str, Any] | None = None):
        """Add or edit a control."""
        if self._pending_control is not None:
            current = self._pending_control
        elif self._edit_index is not None:
            current = self._controls[self._edit_index]
        else:
            current = self._preset_defaults
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                display_name = validate_comment_label(user_input[CONF_DISPLAY_NAME], "Display name")
                rules = [validate_rule(rule) for rule in user_input[CONF_RULES].splitlines() if rule.strip()]
                if not rules:
                    raise RuleBuilderError("At least one rule is required")
                target_type = user_input[CONF_TARGET_TYPE]
                target = None
                if target_type != TARGET_GLOBAL:
                    value = validate_client_identifier(target_type, user_input[CONF_TARGET_VALUE])
                    target_name = validate_comment_label(user_input.get(CONF_TARGET_NAME) or value, "Target display name")
                    target = ClientTarget(
                        target_name,
                        target_type,
                        value,
                    ).as_dict()
                control_id = current.get(CONF_CONTROL_ID) or str(uuid.uuid4())
                control = RuleControl(
                    control_id=control_id,
                    display_name=display_name,
                    rules=tuple(rules),
                    entity_enabled=user_input[CONF_ENTITY_ENABLED],
                    target=ClientTarget.from_dict(target),
                    icon=user_input.get(CONF_ICON) or None,
                ).as_dict()
            except RuleBuilderError:
                errors["base"] = "invalid_rule"
            else:
                self._pending_control = control
                return await self.async_step_review()

        return self.async_show_form(
            step_id="control",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_DISPLAY_NAME, default=current.get(CONF_DISPLAY_NAME, "")): str,
                    vol.Required(CONF_ENTITY_ENABLED, default=current.get(CONF_ENTITY_ENABLED, True)): bool,
                    vol.Required(CONF_RULES, default="\n".join(current.get(CONF_RULES, []))): str,
                    vol.Required(CONF_TARGET_TYPE, default=current.get(CONF_TARGET, {}).get(CONF_TARGET_TYPE, TARGET_GLOBAL)): vol.In(TARGET_TYPES),
                    vol.Optional(CONF_TARGET_NAME, default=current.get(CONF_TARGET, {}).get(CONF_TARGET_NAME, "")): str,
                    vol.Optional(CONF_TARGET_VALUE, default=current.get(CONF_TARGET, {}).get(CONF_TARGET_VALUE, "")): str,
                    vol.Optional(CONF_ICON, default=current.get(CONF_ICON, "")): str,
                }
            ),
            errors=errors,
        )

    async def async_step_review(self, user_input: dict[str, Any] | None = None):
        """Review generated rules before saving."""
        if user_input is not None:
            if user_input["next"] == "back":
                return await self.async_step_control()
            control = self._pending_control
            if control is None:
                return await self.async_step_init()
            if self._edit_index is None:
                self._controls.append(control)
            else:
                self._controls[self._edit_index] = control
            self._pending_control = None
            self._preset_defaults = {}
            return self._save()

        control = RuleControl.from_dict(self._pending_control)
        lines = preview_control(control)
        extra = len(lines) - MAX_PREVIEW_LINES
        preview_lines = lines[:MAX_PREVIEW_LINES]
        if extra > 0:
            preview_lines.append(f"... {extra} more lines")
        preview = "\n".join(preview_lines) or "No rules would be generated."
        return self.async_show_form(
            step_id="review",
            data_schema=vol.Schema({vol.Required("next", default="save"): vol.In(["save", "back"])}),
            description_placeholders={
                "entity_id": f"switch.adguard_rule_control_{_slugify_entity_id(control.display_name)}",
                "rule_count": str(len([line for line in lines if line and not line.startswith("!")])),
                "preview": preview,
            },
        )

    def _save(self):
        return self.async_create_entry(title="", data={CONF_CONTROLS: self._controls})


def _control_choices(controls: list[dict[str, Any]]) -> dict[str, str]:
    """Return a choices mapping for configured controls."""
    return {control[CONF_CONTROL_ID]: control[CONF_DISPLAY_NAME] for control in controls}


def _find_control_index(controls: list[dict[str, Any]], control_id: str) -> int:
    """Find a configured control by ID."""
    return next(index for index, control in enumerate(controls) if control[CONF_CONTROL_ID] == control_id)


def _slugify_entity_id(value: str) -> str:
    """Return a friendly entity-id preview."""
    slug = "".join(char.lower() if char.isalnum() else "_" for char in value)
    return "_".join(part for part in slug.split("_") if part) or "rule_control"
