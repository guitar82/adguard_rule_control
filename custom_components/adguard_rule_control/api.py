"""AdGuard Home API client."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from typing import Any
from urllib.parse import urljoin

from aiohttp import BasicAuth, ClientConnectionError, ClientError, ClientResponseError
from aiohttp.client_exceptions import ContentTypeError

from .const import DEFAULT_TIMEOUT, TARGET_CLIENT_NAME, TARGET_IPV4, TARGET_IPV6, TARGET_MAC
from .rule_builder import RuleBuilderError, normalize_mac, replace_managed_block

_LOGGER = logging.getLogger(__name__)


class AdGuardRuleControlError(Exception):
    """Base error for AdGuard Rule Control."""


class AdGuardAuthenticationError(AdGuardRuleControlError):
    """Raised when AdGuard rejects credentials."""


class AdGuardConnectionError(AdGuardRuleControlError):
    """Raised when AdGuard cannot be reached."""


class AdGuardInvalidResponseError(AdGuardRuleControlError):
    """Raised when AdGuard returns an unexpected response."""


class AdGuardRuleControlClient:
    """Small async client for AdGuard Home custom filtering rules."""

    def __init__(
        self,
        session: Any,
        base_url: str,
        username: str | None = None,
        password: str | None = None,
        verify_ssl: bool = True,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        self._session = session
        self._base_url = base_url.rstrip("/") + "/"
        self._auth = BasicAuth(username, password or "") if username else None
        self._verify_ssl = verify_ssl
        self._timeout = timeout

    async def async_test_connection(self) -> None:
        """Verify AdGuard is reachable and user rules can be read."""
        await self.async_get_user_rules()

    async def async_get_user_rules(self) -> list[str]:
        """Return current AdGuard custom filtering rules."""
        data = await self._async_request("GET", "control/filtering/status")
        if not isinstance(data, dict):
            raise AdGuardInvalidResponseError("AdGuard returned an unexpected response")
        user_rules = data.get("user_rules")
        if not isinstance(user_rules, list) or not all(isinstance(rule, str) for rule in user_rules):
            raise AdGuardInvalidResponseError("AdGuard response did not include user rules")
        return user_rules

    async def async_set_user_rules(self, rules: list[str]) -> None:
        """Write the complete custom filtering rule list to AdGuard."""
        await self._async_request("POST", "control/filtering/set_rules", json={"rules": rules})

    async def async_get_clients(self) -> list[dict[str, str]]:
        """Return selectable AdGuard clients and auto-clients."""
        data = await self._async_request("GET", "control/clients")
        if not isinstance(data, dict):
            raise AdGuardInvalidResponseError("AdGuard returned an unexpected clients response")

        choices: list[dict[str, str]] = []
        clients = data.get("clients", [])
        auto_clients = data.get("auto_clients", [])
        if not isinstance(clients, list) or not isinstance(auto_clients, list):
            raise AdGuardInvalidResponseError("AdGuard clients response was malformed")

        for client in clients:
            if not isinstance(client, dict):
                continue
            name = str(client.get("name") or "").strip()
            if name:
                choices.append(
                    {
                        "display_name": name,
                        "identifier_type": TARGET_CLIENT_NAME,
                        "identifier_value": name,
                    }
                )
            ids = client.get("ids", [])
            if isinstance(ids, list):
                for identifier in ids:
                    choice = _client_identifier_choice(str(identifier), name)
                    if choice:
                        choices.append(choice)

        for client in auto_clients:
            if not isinstance(client, dict):
                continue
            name = str(client.get("name") or "Auto client").strip()
            ip = str(client.get("ip") or "").strip()
            choice = _client_identifier_choice(ip, name)
            if choice:
                choices.append(choice)

        return _deduplicate_client_choices(choices)

    async def async_replace_managed_rules(self, managed_rules: list[str]) -> None:
        """Replace only this integration's managed rule block."""
        existing_rules = await self.async_get_user_rules()
        try:
            updated_rules = replace_managed_block(existing_rules, managed_rules)
        except RuleBuilderError as err:
            raise AdGuardInvalidResponseError(str(err)) from err
        await self.async_set_user_rules(updated_rules)

    async def _async_request(self, method: str, path: str, **kwargs: Any) -> Any:
        url = urljoin(self._base_url, path)
        request_kwargs = {
            "auth": self._auth,
            "ssl": self._verify_ssl,
            "timeout": self._timeout,
            **kwargs,
        }
        try:
            async with self._session.request(method, url, **request_kwargs) as response:
                if response.status in (401, 403):
                    raise AdGuardAuthenticationError("AdGuard authentication failed")
                response.raise_for_status()
                if method == "POST":
                    return None
                try:
                    return await response.json()
                except (ContentTypeError, ValueError) as err:
                    raise AdGuardInvalidResponseError("AdGuard returned invalid JSON") from err
        except AdGuardRuleControlError:
            raise
        except asyncio.TimeoutError as err:
            raise AdGuardConnectionError("Timed out connecting to AdGuard") from err
        except ClientResponseError as err:
            _LOGGER.debug("AdGuard API returned HTTP status %s", err.status)
            raise AdGuardConnectionError("AdGuard returned an HTTP error") from err
        except (ClientConnectionError, ClientError, OSError) as err:
            raise AdGuardConnectionError("Unable to connect to AdGuard") from err


def _client_identifier_choice(identifier: str, display_name: str) -> dict[str, str] | None:
    """Return a target choice for an AdGuard client identifier."""
    identifier = identifier.strip()
    if not identifier:
        return None
    try:
        ip = ipaddress.ip_address(identifier)
    except ValueError:
        try:
            mac = normalize_mac(identifier)
        except RuleBuilderError:
            return None
        return {
            "display_name": f"{display_name or mac} ({mac})",
            "identifier_type": TARGET_MAC,
            "identifier_value": mac,
        }
    return {
        "display_name": f"{display_name or ip} ({ip})",
        "identifier_type": TARGET_IPV4 if ip.version == 4 else TARGET_IPV6,
        "identifier_value": str(ip),
    }


def _deduplicate_client_choices(choices: list[dict[str, str]]) -> list[dict[str, str]]:
    """Deduplicate client choices while preserving order."""
    seen: set[tuple[str, str]] = set()
    result: list[dict[str, str]] = []
    for choice in choices:
        key = (choice["identifier_type"], choice["identifier_value"])
        if key in seen:
            continue
        seen.add(key)
        result.append(choice)
    return result
