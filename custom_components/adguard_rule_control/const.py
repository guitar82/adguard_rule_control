"""Constants for AdGuard Rule Control."""

from __future__ import annotations

DOMAIN = "adguard_rule_control"
NAME = "AdGuard Rule Control"
VERSION = "0.1.0-beta.5"

PLATFORMS = ["switch", "binary_sensor", "sensor", "button"]

CONF_BASE_URL = "base_url"
CONF_HOST = "host"
CONF_PORT = "port"
CONF_USE_SSL = "use_ssl"
CONF_VERIFY_SSL = "verify_ssl"
CONF_USERNAME = "username"
CONF_PASSWORD = "password"

CONF_CONTROLS = "controls"
CONF_CONTROL_ID = "control_id"
CONF_DISPLAY_NAME = "display_name"
CONF_RULES = "rules"
CONF_ENTITY_ENABLED = "entity_enabled"
CONF_TARGET = "target"
CONF_TARGET_TYPE = "target_type"
CONF_TARGET_VALUE = "target_value"
CONF_TARGET_NAME = "target_name"
CONF_ICON = "icon"
CONF_ENTRY_ID = "entry_id"
CONF_PRESET = "preset"
CONF_AUDIENCE = "audience"
CONF_CLIENT_CHOICE = "client_choice"
CONF_DOMAIN = "domain"
CONF_KIND = "kind"
CONF_BLOCKED_SERVICE_IDS = "blocked_service_ids"

AUDIENCE_EVERYONE = "everyone"
AUDIENCE_CLIENT = "client"
CLIENT_CHOICE_MANUAL = "manual"

CONTROL_KIND_RULES = "rules"
CONTROL_KIND_BLOCKED_SERVICES = "blocked_services"

TARGET_GLOBAL = "global"
TARGET_IPV4 = "ipv4"
TARGET_IPV6 = "ipv6"
TARGET_MAC = "mac"
TARGET_CLIENT_NAME = "client_name"
TARGET_TYPES = [TARGET_GLOBAL, TARGET_IPV4, TARGET_IPV6, TARGET_MAC, TARGET_CLIENT_NAME]

MANAGED_START = "! ADGUARD RULE CONTROL START"
MANAGED_END = "! ADGUARD RULE CONTROL END"
MAX_PREVIEW_LINES = 80

STORAGE_VERSION = 1
STORAGE_KEY_PREFIX = f"{DOMAIN}.state"

DEFAULT_TIMEOUT = 10
CONNECTION_CHECK_INTERVAL_SECONDS = 300
WRITE_DEBOUNCE_SECONDS = 1
