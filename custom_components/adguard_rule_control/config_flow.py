"""Config and options flow for AdGuard Rule Control."""

from __future__ import annotations

import uuid
from typing import Any
from urllib.parse import urlparse

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.helpers import config_validation as cv
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
    CONF_BLOCKED_SERVICE_IDS,
    CONF_BLOCKED_SERVICE_PRESET,
    CONF_BLOCKED_SERVICE_TARGET,
    CONF_CLIENT_CHOICE,
    CONF_CONFIRM_BLOCK_ALL,
    CONF_CONTROL_ID,
    CONF_CONTROLS,
    CONF_DISPLAY_NAME,
    CONF_DOMAIN,
    CONF_ENTITY_ENABLED,
    CONF_HOST,
    CONF_ICON,
    CONF_KIND,
    CONF_PORT,
    CONF_PRESET,
    CONF_QUICK_BLOCK_MINUTES,
    CONF_RULES,
    CONF_TARGET,
    CONF_TARGET_NAME,
    CONF_TARGET_TYPE,
    CONF_TARGET_VALUE,
    CONF_USE_SSL,
    CONF_VERIFY_SSL,
    CONTROL_KIND_BLOCKED_SERVICES,
    CONTROL_KIND_RULES,
    DEFAULT_QUICK_BLOCK_MINUTES,
    DOMAIN,
    MAX_PREVIEW_LINES,
    MAX_TEMPORARY_BLOCK_MINUTES,
    NAME,
    TARGET_CLIENT_NAME,
    TARGET_GLOBAL,
)
from .models import ClientTarget, RuleControl
from .presets import (
    BLOCKED_SERVICE_PRESET_CUSTOM,
    PRESET_BLOCK_WEBSITE,
    PRESET_CUSTOM,
    blocked_service_preset_choices,
    blocked_service_preset_ids,
    blocked_service_preset_name,
    get_preset,
    preset_choices,
)
from .rule_builder import (
    RuleBuilderError,
    domain_to_block_rule,
    preview_control,
    validate_client_identifier,
    validate_comment_label,
    validate_rule,
)

_ACTION_CHOICES = {
    "add": "Add a website or rule preset",
    "add_blocked_services": "Add AdGuard built-in services",
    "edit": "Edit an existing control",
    "duplicate": "Duplicate an existing control",
    "delete": "Delete a control",
    "move": "Change rule order",
    "preview": "Preview a control",
    "import_state": "Import current state from AdGuard",
    "finish": "Finish without changes",
}

_TARGET_TYPE_CHOICES = {
    TARGET_GLOBAL: "Everyone",
    "ipv4": "IPv4 address",
    "ipv6": "IPv6 address",
    "mac": "MAC address",
    TARGET_CLIENT_NAME: "AdGuard client name",
}

_OPTIONS_FLOW_BASE = getattr(config_entries, "OptionsFlowWithReload", config_entries.OptionsFlow)


def normalize_base_url(host: str, port: int | None, use_ssl: bool) -> str:
    """Normalize flexible AdGuard host input into a base URL."""
    value = host.strip()
    if not value:
        raise ValueError("Host is required")
    if "://" not in value:
        value = f"{'https' if use_ssl else 'http'}://{value}"
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Invalid URL")
    hostname = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    selected_port = parsed.port or port
    netloc = f"{hostname}:{selected_port}" if selected_port else hostname
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

    async def async_step_reconfigure(self, user_input: dict[str, Any] | None = None):
        """Update the AdGuard connection without removing the integration."""
        entry = self._get_reconfigure_entry()
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                data = await self._async_connection_data(user_input, entry.data)
            except ValueError:
                errors["base"] = "invalid_url"
            except AdGuardAuthenticationError:
                errors["base"] = "invalid_auth"
            except AdGuardConnectionError:
                errors["base"] = "cannot_connect"
            except AdGuardInvalidResponseError:
                errors["base"] = "invalid_response"
            else:
                return self._update_connection_and_abort(entry, data, "reconfigure_successful")
        return self.async_show_form(
            step_id="reconfigure",
            data_schema=_connection_schema(entry.data),
            errors=errors,
        )

    async def async_step_reauth(self, entry_data: dict[str, Any]):
        """Start reauthentication after AdGuard rejects credentials."""
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(self, user_input: dict[str, Any] | None = None):
        """Collect and verify replacement AdGuard credentials."""
        entry = self._get_reauth_entry()
        errors: dict[str, str] = {}
        if user_input is not None:
            data = dict(entry.data)
            data[CONF_USERNAME] = user_input.get(CONF_USERNAME, entry.data.get(CONF_USERNAME, ""))
            data[CONF_PASSWORD] = user_input.get(CONF_PASSWORD) or entry.data.get(CONF_PASSWORD, "")
            client = AdGuardRuleControlClient(
                async_get_clientsession(self.hass),
                data[CONF_BASE_URL],
                data[CONF_USERNAME],
                data[CONF_PASSWORD],
                data.get(CONF_VERIFY_SSL, True),
            )
            try:
                await client.async_test_connection()
            except AdGuardAuthenticationError:
                errors["base"] = "invalid_auth"
            except AdGuardConnectionError:
                errors["base"] = "cannot_connect"
            except AdGuardInvalidResponseError:
                errors["base"] = "invalid_response"
            else:
                return self._update_connection_and_abort(entry, data, "reauth_successful")
        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema(
                {
                    vol.Optional(CONF_USERNAME, default=entry.data.get(CONF_USERNAME, "")): str,
                    vol.Optional(CONF_PASSWORD): str,
                }
            ),
            errors=errors,
        )

    async def _async_connection_data(
        self,
        user_input: dict[str, Any],
        existing_data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Normalize and validate connection form data."""
        existing_data = existing_data or {}
        username = user_input.get(CONF_USERNAME, existing_data.get(CONF_USERNAME, ""))
        password = user_input.get(CONF_PASSWORD) or existing_data.get(CONF_PASSWORD, "")
        base_url = normalize_base_url(user_input[CONF_HOST], user_input.get(CONF_PORT), user_input[CONF_USE_SSL])
        client = AdGuardRuleControlClient(
            async_get_clientsession(self.hass),
            base_url,
            username,
            password,
            user_input[CONF_VERIFY_SSL],
        )
        await client.async_test_connection()
        return {
            CONF_BASE_URL: base_url,
            CONF_USERNAME: username,
            CONF_PASSWORD: password,
            CONF_VERIFY_SSL: user_input[CONF_VERIFY_SSL],
        }

    def _update_connection_and_abort(
        self,
        entry: config_entries.ConfigEntry,
        data: dict[str, Any],
        reason: str,
    ):
        """Update and reload using the lifecycle supported by this HA version."""
        if hasattr(config_entries, "OptionsFlowWithReload"):
            return self.async_update_reload_and_abort(entry, data_updates=data, reason=reason)
        self.hass.config_entries.async_update_entry(entry, data=entry.data | data)
        return self.async_abort(reason=reason)

    @staticmethod
    def async_get_options_flow(config_entry):
        """Return options flow handler."""
        return OptionsFlowHandler(config_entry)


class OptionsFlowHandler(_OPTIONS_FLOW_BASE):
    """Manage rule controls from integration options."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        self._config_entry = config_entry
        self._controls = list(config_entry.options.get(CONF_CONTROLS, []))
        self._edit_index: int | None = None
        self._select_action: str | None = None
        self._preset_defaults: dict[str, Any] = {}
        self._pending_control: dict[str, Any] | None = None
        self._client_choices_data: dict[str, dict[str, str]] = {}
        self._blocked_service_defaults: dict[str, Any] = {}
        self._blocked_service_choices: dict[str, str] = {}
        self._block_all_confirmed = False

    async def async_step_init(self, user_input: dict[str, Any] | None = None):
        """Choose an options action."""
        errors: dict[str, str] = {}
        if user_input is not None:
            action = user_input["action"]
            if action == "add":
                return await self.async_step_preset()
            if action == "add_blocked_services":
                return await self.async_step_blocked_service_preset()
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
                    vol.Required("action", default="add"): vol.In(_ACTION_CHOICES)
                }
            ),
            errors=errors,
        )

    async def async_step_blocked_service_preset(self, user_input: dict[str, Any] | None = None):
        """Choose a friendly group of AdGuard blocked services."""
        errors: dict[str, str] = {}
        services = await self._async_blocked_service_choices()
        if user_input is not None:
            preset_key = user_input[CONF_BLOCKED_SERVICE_PRESET]
            service_ids = blocked_service_preset_ids(preset_key, set(services))
            if preset_key != BLOCKED_SERVICE_PRESET_CUSTOM and not service_ids:
                errors["base"] = "unsupported_service_group"
            else:
                self._blocked_service_defaults = {
                    CONF_DISPLAY_NAME: blocked_service_preset_name(preset_key),
                    CONF_BLOCKED_SERVICE_IDS: list(service_ids),
                }
                return await self.async_step_blocked_services()
        return self.async_show_form(
            step_id="blocked_service_preset",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_BLOCKED_SERVICE_PRESET,
                        default=BLOCKED_SERVICE_PRESET_CUSTOM,
                    ): vol.In(blocked_service_preset_choices())
                }
            ),
            errors=errors,
        )

    async def async_step_blocked_services(self, user_input: dict[str, Any] | None = None):
        """Add a control for AdGuard's built-in blocked services."""
        errors: dict[str, str] = {}
        services = await self._async_blocked_service_choices()
        if self._pending_control and self._pending_control.get(CONF_KIND) == CONTROL_KIND_BLOCKED_SERVICES:
            current = self._pending_control
        elif self._edit_index is not None:
            current = self._controls[self._edit_index]
        else:
            current = self._blocked_service_defaults
        targets = await self._async_blocked_service_target_choices()
        if user_input is not None:
            service_ids = tuple(user_input[CONF_BLOCKED_SERVICE_IDS])
            try:
                display_name = validate_comment_label(user_input[CONF_DISPLAY_NAME], "Display name")
                if not service_ids:
                    raise RuleBuilderError("Select at least one blocked service")
                quick_minutes = int(user_input[CONF_QUICK_BLOCK_MINUTES])
                if quick_minutes < 1 or quick_minutes > MAX_TEMPORARY_BLOCK_MINUTES:
                    raise RuleBuilderError("Temporary block duration is invalid")
            except RuleBuilderError:
                errors["base"] = "invalid_rule"
            else:
                target_key = user_input[CONF_BLOCKED_SERVICE_TARGET]
                target = None
                if target_key != TARGET_GLOBAL:
                    client_name = target_key.removeprefix("client:")
                    target = ClientTarget(client_name, TARGET_CLIENT_NAME, client_name)
                self._pending_control = RuleControl(
                    control_id=current.get(CONF_CONTROL_ID) or str(uuid.uuid4()),
                    display_name=display_name,
                    rules=(),
                    entity_enabled=True,
                    icon=user_input.get(CONF_ICON) or "mdi:block-helper",
                    kind=CONTROL_KIND_BLOCKED_SERVICES,
                    blocked_service_ids=service_ids,
                    target=target,
                    quick_block_minutes=quick_minutes,
                ).as_dict()
                return await self.async_step_review()
        current_target = current.get(CONF_TARGET, {}).get(CONF_TARGET_VALUE)
        target_default = f"client:{current_target}" if current_target else TARGET_GLOBAL
        if target_default not in targets:
            target_default = TARGET_GLOBAL
        return self.async_show_form(
            step_id="blocked_services",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_DISPLAY_NAME, default=current.get(CONF_DISPLAY_NAME, "Block Services")): str,
                    vol.Required(
                        CONF_BLOCKED_SERVICE_IDS,
                        default=list(current.get(CONF_BLOCKED_SERVICE_IDS, [])),
                    ): cv.multi_select(services),
                    vol.Required(CONF_BLOCKED_SERVICE_TARGET, default=target_default): vol.In(targets),
                    vol.Required(
                        CONF_QUICK_BLOCK_MINUTES,
                        default=current.get(CONF_QUICK_BLOCK_MINUTES, DEFAULT_QUICK_BLOCK_MINUTES),
                    ): vol.All(vol.Coerce(int), vol.Range(min=1, max=MAX_TEMPORARY_BLOCK_MINUTES)),
                    vol.Optional(CONF_ICON, default=current.get(CONF_ICON, "mdi:block-helper")): str,
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
                    vol.Required(CONF_TARGET_TYPE): vol.In(
                        {
                            key: label
                            for key, label in _TARGET_TYPE_CHOICES.items()
                            if key != TARGET_GLOBAL
                        }
                    ),
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
            if self._controls[self._edit_index].get(CONF_KIND) == CONTROL_KIND_BLOCKED_SERVICES:
                return await self.async_step_blocked_services()
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
        return self.async_show_form(
            step_id="delete",
            data_schema=vol.Schema({vol.Required(CONF_CONTROL_ID): vol.In(controls)}),
        )

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
                    vol.Required("direction", default="up"): vol.In(
                        {"up": "Move up", "down": "Move down"}
                    ),
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
        if control.kind == CONTROL_KIND_BLOCKED_SERVICES:
            target = control.target.display_name if control.target else "Everyone"
            preview = f"Target: {target}\n" + "\n".join(
                f"Blocked service: {service_id}" for service_id in control.blocked_service_ids
            )
        else:
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
            data_schema=vol.Schema(
                {vol.Required("next", default="back"): vol.In({"back": "Go back", "finish": "Finish"})}
            ),
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
            data_schema=vol.Schema({vol.Required("next", default="finish"): vol.In({"finish": "Finish"})}),
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
                    target_name = validate_comment_label(
                        user_input.get(CONF_TARGET_NAME) or value,
                        "Target display name",
                    )
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
                    kind=current.get(CONF_KIND, CONTROL_KIND_RULES),
                    quick_block_minutes=int(user_input[CONF_QUICK_BLOCK_MINUTES]),
                ).as_dict()
            except RuleBuilderError:
                errors["base"] = "invalid_rule"
            else:
                self._pending_control = control
                if "||*^" in rules and target is None and not self._block_all_confirmed:
                    return await self.async_step_confirm_block_all()
                return await self.async_step_review()

        return self.async_show_form(
            step_id="control",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_DISPLAY_NAME, default=current.get(CONF_DISPLAY_NAME, "")): str,
                    vol.Required(CONF_ENTITY_ENABLED, default=current.get(CONF_ENTITY_ENABLED, True)): bool,
                    vol.Required(CONF_RULES, default="\n".join(current.get(CONF_RULES, []))): str,
                    vol.Required(
                        CONF_TARGET_TYPE,
                        default=current.get(CONF_TARGET, {}).get(CONF_TARGET_TYPE, TARGET_GLOBAL),
                    ): vol.In(_TARGET_TYPE_CHOICES),
                    vol.Optional(CONF_TARGET_NAME, default=current.get(CONF_TARGET, {}).get(CONF_TARGET_NAME, "")): str,
                    vol.Optional(
                        CONF_TARGET_VALUE,
                        default=current.get(CONF_TARGET, {}).get(CONF_TARGET_VALUE, ""),
                    ): str,
                    vol.Optional(CONF_ICON, default=current.get(CONF_ICON, "")): str,
                    vol.Required(
                        CONF_QUICK_BLOCK_MINUTES,
                        default=current.get(CONF_QUICK_BLOCK_MINUTES, DEFAULT_QUICK_BLOCK_MINUTES),
                    ): vol.All(vol.Coerce(int), vol.Range(min=1, max=MAX_TEMPORARY_BLOCK_MINUTES)),
                }
            ),
            errors=errors,
        )

    async def async_step_confirm_block_all(self, user_input: dict[str, Any] | None = None):
        """Require explicit confirmation before globally blocking DNS."""
        errors: dict[str, str] = {}
        if user_input is not None:
            if not user_input[CONF_CONFIRM_BLOCK_ALL]:
                errors["base"] = "block_all_not_confirmed"
            else:
                self._block_all_confirmed = True
                return await self.async_step_review()
        return self.async_show_form(
            step_id="confirm_block_all",
            data_schema=vol.Schema({vol.Required(CONF_CONFIRM_BLOCK_ALL, default=False): bool}),
            errors=errors,
        )

    async def async_step_review(self, user_input: dict[str, Any] | None = None):
        """Review generated rules before saving."""
        if user_input is not None:
            if user_input["next"] == "back":
                if self._pending_control and self._pending_control.get(CONF_KIND) == CONTROL_KIND_BLOCKED_SERVICES:
                    return await self.async_step_blocked_services()
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
        if control.kind == CONTROL_KIND_BLOCKED_SERVICES:
            target = control.target.display_name if control.target else "Everyone"
            lines = [f"Target: {target}"] + [
                f"Blocked service: {service_id}" for service_id in control.blocked_service_ids
            ]
            preview = "\n".join(lines) or "No blocked services selected."
            rule_count = len(control.blocked_service_ids)
        else:
            lines = preview_control(control)
            extra = len(lines) - MAX_PREVIEW_LINES
            preview_lines = lines[:MAX_PREVIEW_LINES]
            if extra > 0:
                preview_lines.append(f"... {extra} more lines")
            preview = "\n".join(preview_lines) or "No rules would be generated."
            rule_count = len([line for line in lines if line and not line.startswith("!")])
        return self.async_show_form(
            step_id="review",
            data_schema=vol.Schema(
                {vol.Required("next", default="save"): vol.In({"save": "Save", "back": "Go back"})}
            ),
            description_placeholders={
                "entity_id": f"switch.adguard_rule_control_{_slugify_entity_id(control.display_name)}",
                "rule_count": str(rule_count),
                "preview": preview,
            },
        )

    def _save(self):
        return self.async_create_entry(title="", data={CONF_CONTROLS: self._controls})

    async def _async_blocked_service_choices(self) -> dict[str, str]:
        """Return available blocked service choices."""
        manager = self.hass.data.get(DOMAIN, {}).get(self._config_entry.entry_id)
        if manager is not None:
            try:
                services = await manager.client.async_get_available_blocked_services()
            except Exception:  # noqa: BLE001 - keep setup usable with fallback choices
                services = {}
            if services:
                self._blocked_service_choices = services
                return services
        fallback = {
            "youtube": "YouTube",
            "facebook": "Facebook",
            "instagram": "Instagram",
            "tiktok": "TikTok",
            "snapchat": "Snapchat",
            "discord": "Discord",
            "reddit": "Reddit",
            "netflix": "Netflix",
            "twitch": "Twitch",
            "steam": "Steam",
            "epic_games": "Epic Games",
            "roblox": "Roblox",
            "onlyfans": "OnlyFans",
        }
        self._blocked_service_choices = fallback
        return fallback

    async def _async_blocked_service_target_choices(self) -> dict[str, str]:
        """Return global and persistent-client targets for built-in services."""
        choices = {TARGET_GLOBAL: "Everyone using this AdGuard Home instance"}
        manager = self.hass.data.get(DOMAIN, {}).get(self._config_entry.entry_id)
        if manager is None:
            return choices
        try:
            clients = await manager.client.async_get_client_configs()
        except Exception:  # noqa: BLE001 - global service controls remain available
            return choices
        for client in clients:
            name = str(client.get("name") or "").strip()
            if name:
                choices[f"client:{name}"] = f"Only {name}"
        return choices


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


def _connection_schema(data: dict[str, Any]) -> vol.Schema:
    """Return a reusable connection form schema with saved defaults."""
    base_url = str(data.get(CONF_BASE_URL, ""))
    parsed = urlparse(base_url)
    return vol.Schema(
        {
            vol.Required(CONF_HOST, default=base_url): str,
            vol.Optional(CONF_PORT): int,
            vol.Required(CONF_USE_SSL, default=parsed.scheme == "https"): bool,
            vol.Required(CONF_VERIFY_SSL, default=data.get(CONF_VERIFY_SSL, True)): bool,
            vol.Optional(CONF_USERNAME, default=data.get(CONF_USERNAME, "")): str,
            vol.Optional(CONF_PASSWORD): str,
        }
    )
