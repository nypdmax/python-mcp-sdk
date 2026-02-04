"""Regression tests for discover_authorization_servers and discovery helpers."""

from unittest import mock

import httpx
import pytest
from pydantic import AnyHttpUrl

from mcp.client.auth.utils import (
    build_authorization_servers_discovery_urls,
    discover_authorization_servers,
)
from mcp.shared.auth import AuthProtocolMetadata, ProtectedResourceMetadata


@pytest.mark.anyio
async def test_discover_authorization_servers_returns_protocols_from_unified_endpoint():
    """Test that unified discovery tries path-relative first, then root-based."""
    call_count = 0

    async def mock_get(url: str):
        nonlocal call_count
        call_count += 1
        # First call should be path-relative
        if call_count == 1:
            assert url == "https://example.com/.well-known/authorization_servers/mcp"
            # Return 404 to trigger next attempt
            response = mock.MagicMock(spec=httpx.Response)
            response.status_code = 404
            return response
        # Second call should be root-based
        assert url == "https://example.com/.well-known/authorization_servers"
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
    assert call_count == 2  # Should have tried both URLs


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
    """Test that returns empty list when all discovery attempts fail."""
    client = mock.MagicMock(spec=httpx.AsyncClient)
    client.get = mock.AsyncMock(side_effect=httpx.ConnectError("failed"))
    result = await discover_authorization_servers("https://example.com", client)
    assert result == []


def test_build_authorization_servers_discovery_urls_with_path():
    """Test URL building for resource with path component."""
    urls = build_authorization_servers_discovery_urls("http://localhost:8002/mcp")
    assert len(urls) == 2
    assert urls[0] == "http://localhost:8002/.well-known/authorization_servers/mcp"
    assert urls[1] == "http://localhost:8002/.well-known/authorization_servers"


def test_build_authorization_servers_discovery_urls_without_path():
    """Test URL building for resource without path component."""
    urls = build_authorization_servers_discovery_urls("http://localhost:8002")
    assert len(urls) == 1
    assert urls[0] == "http://localhost:8002/.well-known/authorization_servers"


def test_build_authorization_servers_discovery_urls_with_root_path():
    """Test URL building for resource with root path."""
    urls = build_authorization_servers_discovery_urls("http://localhost:8002/")
    assert len(urls) == 1
    assert urls[0] == "http://localhost:8002/.well-known/authorization_servers"


@pytest.mark.anyio
async def test_discover_authorization_servers_prioritizes_prm_over_unified_discovery():
    """Test that PRM mcp_auth_protocols takes priority over unified discovery."""
    meta = AuthProtocolMetadata(protocol_id="api_key", protocol_version="1.0")
    prm = ProtectedResourceMetadata(
        resource=AnyHttpUrl("https://example.com/mcp"),
        authorization_servers=[AnyHttpUrl("https://as.example.com")],
        mcp_auth_protocols=[meta],
    )

    async def mock_get(url: str):
        response = mock.MagicMock(spec=httpx.Response)
        response.status_code = 200
        response.aread = mock.AsyncMock(
            return_value=b'{"protocols": [{"protocol_id": "oauth2", "protocol_version": "2.0"}]}'
        )
        return response

    client = mock.MagicMock(spec=httpx.AsyncClient)
    client.get = mock.AsyncMock(side_effect=mock_get)
    result = await discover_authorization_servers(
        "https://example.com/mcp",
        client,
        prm=prm,
    )
    # Should use PRM protocols, not unified discovery
    assert len(result) == 1
    assert result[0].protocol_id == "api_key"
    # Should not have called unified discovery
    client.get.assert_not_called()


@pytest.mark.anyio
async def test_discover_authorization_servers_path_relative_succeeds_stops_trying():
    """Test that when path-relative discovery succeeds, root-based is not tried."""
    call_count = 0

    async def mock_get(url: str):
        nonlocal call_count
        call_count += 1
        # First call (path-relative) succeeds
        assert url == "https://example.com/.well-known/authorization_servers/mcp"
        response = mock.MagicMock(spec=httpx.Response)
        response.status_code = 200
        response.aread = mock.AsyncMock(
            return_value=b'{"protocols": [{"protocol_id": "api_key", "protocol_version": "1.0"}]}'
        )
        return response

    client = mock.MagicMock(spec=httpx.AsyncClient)
    client.get = mock.AsyncMock(side_effect=mock_get)
    result = await discover_authorization_servers("https://example.com/mcp", client)
    assert len(result) == 1
    assert result[0].protocol_id == "api_key"
    assert call_count == 1  # Should only try path-relative, not root-based


@pytest.mark.anyio
async def test_discover_authorization_servers_invalid_json_response():
    """Test handling of 200 response with invalid JSON."""

    async def mock_get(url: str):
        response = mock.MagicMock(spec=httpx.Response)
        response.status_code = 200
        response.aread = mock.AsyncMock(return_value=b"invalid json")
        return response

    client = mock.MagicMock(spec=httpx.AsyncClient)
    client.get = mock.AsyncMock(side_effect=mock_get)
    result = await discover_authorization_servers("https://example.com/mcp", client)
    # Should return empty list when JSON parsing fails
    assert result == []


@pytest.mark.anyio
async def test_discover_authorization_servers_empty_protocols_array():
    """Test handling of empty protocols array in response."""

    async def mock_get(url: str):
        response = mock.MagicMock(spec=httpx.Response)
        response.status_code = 200
        response.aread = mock.AsyncMock(return_value=b'{"protocols": []}')
        return response

    client = mock.MagicMock(spec=httpx.AsyncClient)
    client.get = mock.AsyncMock(side_effect=mock_get)
    result = await discover_authorization_servers("https://example.com/mcp", client)
    # Should return empty list when protocols array is empty
    assert result == []


@pytest.mark.anyio
async def test_discover_authorization_servers_missing_protocols_field():
    """Test handling of response without protocols field."""

    async def mock_get(url: str):
        response = mock.MagicMock(spec=httpx.Response)
        response.status_code = 200
        response.aread = mock.AsyncMock(return_value=b'{"other_field": "value"}')
        return response

    client = mock.MagicMock(spec=httpx.AsyncClient)
    client.get = mock.AsyncMock(side_effect=mock_get)
    result = await discover_authorization_servers("https://example.com/mcp", client)
    # Should return empty list when protocols field is missing
    assert result == []


@pytest.mark.anyio
async def test_discover_authorization_servers_timeout_error():
    """Test handling of timeout errors during discovery."""
    client = mock.MagicMock(spec=httpx.AsyncClient)
    client.get = mock.AsyncMock(side_effect=httpx.TimeoutException("timeout"))
    result = await discover_authorization_servers("https://example.com/mcp", client)
    assert result == []


@pytest.mark.anyio
async def test_discover_authorization_servers_500_error():
    """Test handling of 500 server errors."""
    response = mock.MagicMock(spec=httpx.Response)
    response.status_code = 500
    client = mock.MagicMock(spec=httpx.AsyncClient)
    client.get = mock.AsyncMock(return_value=response)
    result = await discover_authorization_servers("https://example.com/mcp", client)
    assert result == []


@pytest.mark.anyio
async def test_discover_authorization_servers_invalid_protocol_metadata():
    """Test handling of invalid protocol metadata in response."""

    async def mock_get(url: str):
        response = mock.MagicMock(spec=httpx.Response)
        response.status_code = 200
        # Missing required fields
        response.aread = mock.AsyncMock(
            return_value=b'{"protocols": [{"protocol_id": "oauth2"}]}'  # Missing protocol_version
        )
        return response

    client = mock.MagicMock(spec=httpx.AsyncClient)
    client.get = mock.AsyncMock(side_effect=mock_get)
    result = await discover_authorization_servers("https://example.com/mcp", client)
    # Should return empty list when protocol metadata is invalid
    assert result == []


def test_build_authorization_servers_discovery_urls_with_multiple_path_segments():
    """Test URL building for resource with multiple path segments."""
    urls = build_authorization_servers_discovery_urls("http://localhost:8002/mcp/v1")
    assert len(urls) == 2
    assert urls[0] == "http://localhost:8002/.well-known/authorization_servers/mcp/v1"
    assert urls[1] == "http://localhost:8002/.well-known/authorization_servers"


def test_build_authorization_servers_discovery_urls_with_query_params():
    """Test URL building preserves query params in base URL."""
    urls = build_authorization_servers_discovery_urls("http://localhost:8002/mcp?param=value")
    assert len(urls) == 2
    # Query params should be stripped from discovery URLs
    assert urls[0] == "http://localhost:8002/.well-known/authorization_servers/mcp"
    assert urls[1] == "http://localhost:8002/.well-known/authorization_servers"


def test_build_authorization_servers_discovery_urls_with_fragment():
    """Test URL building handles fragments correctly."""
    urls = build_authorization_servers_discovery_urls("http://localhost:8002/mcp#fragment")
    assert len(urls) == 2
    # Fragments should be stripped from discovery URLs
    assert urls[0] == "http://localhost:8002/.well-known/authorization_servers/mcp"
    assert urls[1] == "http://localhost:8002/.well-known/authorization_servers"
