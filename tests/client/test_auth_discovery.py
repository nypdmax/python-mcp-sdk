"""Regression tests for discover_authorization_servers and discovery helpers."""

from unittest import mock

import httpx
import pytest
from pydantic import AnyHttpUrl

from mcp.shared.auth import AuthProtocolMetadata, ProtectedResourceMetadata

from mcp.client.auth.utils import discover_authorization_servers


@pytest.mark.anyio
async def test_discover_authorization_servers_returns_protocols_from_unified_endpoint():
    async def mock_get(url: str):
        assert ".well-known/authorization_servers" in url
        response = mock.MagicMock(spec=httpx.Response)
        response.status_code = 200
        response.aread = mock.AsyncMock(
            return_value=b'{"protocols": [{"protocol_id": "oauth2", "protocol_version": "2.0"}]}'
        )
        return response

    client = mock.MagicMock(spec=httpx.AsyncClient)
    client.get = mock.AsyncMock(side_effect=mock_get)
    result = await discover_authorization_servers("https://example.com/mcp", client)
    assert len(result) == 1
    assert result[0].protocol_id == "oauth2"
    assert result[0].protocol_version == "2.0"


@pytest.mark.anyio
async def test_discover_authorization_servers_returns_empty_on_non_200():
    response = mock.MagicMock(spec=httpx.Response)
    response.status_code = 404
    client = mock.MagicMock(spec=httpx.AsyncClient)
    client.get = mock.AsyncMock(return_value=response)
    result = await discover_authorization_servers("https://example.com", client)
    assert result == []


@pytest.mark.anyio
async def test_discover_authorization_servers_fallback_to_prm():
    client = mock.MagicMock(spec=httpx.AsyncClient)
    client.get = mock.AsyncMock(return_value=mock.MagicMock(status_code=404))
    meta = AuthProtocolMetadata(protocol_id="api_key", protocol_version="1.0")
    prm = ProtectedResourceMetadata(
        resource=AnyHttpUrl("https://example.com"),
        authorization_servers=[AnyHttpUrl("https://as.example.com")],
        mcp_auth_protocols=[meta],
    )
    result = await discover_authorization_servers(
        "https://example.com",
        client,
        prm=prm,
    )
    assert len(result) == 1
    assert result[0].protocol_id == "api_key"


@pytest.mark.anyio
async def test_discover_authorization_servers_returns_empty_when_no_prm_and_request_fails():
    client = mock.MagicMock(spec=httpx.AsyncClient)
    client.get = mock.AsyncMock(side_effect=httpx.ConnectError("failed"))
    result = await discover_authorization_servers("https://example.com", client)
    assert result == []
