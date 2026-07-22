"""Tests for the AdGuard API client."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from custom_components.adguard_rule_control.api import (
    AdGuardAuthenticationError,
    AdGuardConnectionError,
    AdGuardInvalidResponseError,
    AdGuardRuleControlClient,
)


class FakeResponse:
    """Minimal aiohttp-like response."""

    def __init__(self, status: int = 200, payload: Any = None) -> None:
        self.status = status
        self.payload = payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def raise_for_status(self) -> None:
        if self.status >= 400:
            from aiohttp import ClientResponseError

            raise ClientResponseError(None, (), status=self.status)

    async def json(self) -> Any:
        if isinstance(self.payload, Exception):
            raise self.payload
        return self.payload


class FakeSession:
    """Minimal aiohttp-like session."""

    def __init__(self, responses: list[Any]) -> None:
        self.responses = responses
        self.requests: list[tuple[str, str, dict[str, Any]]] = []

    def request(self, method: str, url: str, **kwargs: Any):
        self.requests.append((method, url, kwargs))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


@pytest.mark.asyncio
async def test_successful_connection() -> None:
    client = AdGuardRuleControlClient(FakeSession([FakeResponse(payload={"user_rules": []})]), "http://adguard.local")
    await client.async_test_connection()


@pytest.mark.asyncio
async def test_invalid_credentials() -> None:
    client = AdGuardRuleControlClient(FakeSession([FakeResponse(status=401)]), "http://adguard.local")
    with pytest.raises(AdGuardAuthenticationError):
        await client.async_test_connection()


@pytest.mark.asyncio
async def test_timeout() -> None:
    client = AdGuardRuleControlClient(FakeSession([asyncio.TimeoutError()]), "http://adguard.local")
    with pytest.raises(AdGuardConnectionError):
        await client.async_test_connection()


@pytest.mark.asyncio
async def test_invalid_json() -> None:
    from aiohttp.client_exceptions import ContentTypeError

    client = AdGuardRuleControlClient(FakeSession([FakeResponse(payload=ContentTypeError(None, ()))]) , "http://adguard.local")
    with pytest.raises(AdGuardInvalidResponseError):
        await client.async_test_connection()


@pytest.mark.asyncio
async def test_missing_user_rules() -> None:
    client = AdGuardRuleControlClient(FakeSession([FakeResponse(payload={})]), "http://adguard.local")
    with pytest.raises(AdGuardInvalidResponseError):
        await client.async_test_connection()


@pytest.mark.asyncio
async def test_successful_rules_update() -> None:
    session = FakeSession([FakeResponse(payload=None)])
    client = AdGuardRuleControlClient(session, "http://adguard.local")
    await client.async_set_user_rules(["||example.com^"])
    assert session.requests[0][0] == "POST"
    assert session.requests[0][2]["json"] == {"rules": ["||example.com^"]}


@pytest.mark.asyncio
async def test_failed_rules_update() -> None:
    client = AdGuardRuleControlClient(FakeSession([FakeResponse(status=500)]), "http://adguard.local")
    with pytest.raises(AdGuardConnectionError):
        await client.async_set_user_rules(["||example.com^"])


@pytest.mark.asyncio
async def test_get_clients() -> None:
    client = AdGuardRuleControlClient(
        FakeSession(
            [
                FakeResponse(
                    payload={
                        "clients": [{"name": "Living Room TV", "ids": ["192.168.1.25", "AA-BB-CC-DD-EE-FF"]}],
                        "auto_clients": [{"name": "Phone", "ip": "192.168.1.26"}],
                    }
                )
            ]
        ),
        "http://adguard.local",
    )
    assert await client.async_get_clients() == [
        {
            "display_name": "Living Room TV",
            "identifier_type": "client_name",
            "identifier_value": "Living Room TV",
        },
        {
            "display_name": "Living Room TV (192.168.1.25)",
            "identifier_type": "ipv4",
            "identifier_value": "192.168.1.25",
        },
        {
            "display_name": "Living Room TV (aa:bb:cc:dd:ee:ff)",
            "identifier_type": "mac",
            "identifier_value": "aa:bb:cc:dd:ee:ff",
        },
        {
            "display_name": "Phone (192.168.1.26)",
            "identifier_type": "ipv4",
            "identifier_value": "192.168.1.26",
        },
    ]


@pytest.mark.asyncio
async def test_get_clients_rejects_malformed_response() -> None:
    client = AdGuardRuleControlClient(FakeSession([FakeResponse(payload={"clients": {}})]), "http://adguard.local")
    with pytest.raises(AdGuardInvalidResponseError):
        await client.async_get_clients()
