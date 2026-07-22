"""AdGuard Home API client."""

from __future__ import annotations

import asyncio
import logging
from typing import Any
from urllib.parse import urljoin

from aiohttp import BasicAuth, ClientConnectionError, ClientError, ClientResponseError
from aiohttp.client_exceptions import ContentTypeError

from .const import DEFAULT_TIMEOUT
from .rule_builder import RuleBuilderError, replace_managed_block

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
