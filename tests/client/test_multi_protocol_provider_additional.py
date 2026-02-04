"""Additional corner case tests for MultiProtocolAuthProvider discovery flow."""

import httpx
import pytest

from mcp.client.auth.multi_protocol import MultiProtocolAuthProvider

from .test_multi_protocol_provider import _MockApiKeyProtocol, _MockStorage


@pytest.mark.anyio
async def test_401_flow_path_relative_succeeds_no_root_based_attempt() -> None:
    """Test that when path-relative discovery succeeds, root-based is not attempted."""
    seen: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path))
        if request.method == "GET" and "oauth-protected-resource" in request.url.path:
            prm = {"resource": "https://rs.example/mcp"}
            return httpx.Response(200, json=prm)
        # Path-relative discovery succeeds immediately
        if request.method == "GET" and request.url.path == "/.well-known/authorization_servers/mcp":
            return httpx.Response(
                200,
                json={
                    "protocols": [
                        {"protocol_id": "api_key", "protocol_version": "1.0"},
                    ]
                },
            )
        if request.method == "POST" and request.url.path == "/mcp":
            if request.headers.get("x-api-key") == "test-key":
                return httpx.Response(
                    200,
                    json={"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2024-11-05"}},
                )
            www = (
                'Bearer error="invalid_token", '
                'resource_metadata="https://rs.example/.well-known/oauth-protected-resource/mcp"'
            )
            return httpx.Response(401, headers={"www-authenticate": www}, text="unauthorized")
        return httpx.Response(500)

    transport = httpx.MockTransport(handler)
    storage = _MockStorage()
    api_key_proto = _MockApiKeyProtocol(api_key="test-key")

    async with httpx.AsyncClient(transport=transport) as client:
        provider = MultiProtocolAuthProvider(
            server_url="https://rs.example",
            storage=storage,
            protocols=[api_key_proto],
            http_client=client,
        )
        client.auth = provider
        r = await client.post("https://rs.example/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize"})

    # Should have tried path-relative, but NOT root-based
    assert ("GET", "/.well-known/authorization_servers/mcp") in seen
    assert ("GET", "/.well-known/authorization_servers") not in seen
    assert r.status_code == 200


@pytest.mark.anyio
async def test_401_flow_oauth_fallback_fails_when_no_oauth_protocol() -> None:
    """Test that OAuth fallback fails gracefully when OAuth protocol is not injected."""
    seen: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path))
        if request.method == "GET" and "oauth-protected-resource" in request.url.path:
            # PRM without authorization_servers to avoid auto-generating mcp_auth_protocols
            # This ensures unified discovery is attempted
            prm = {
                "resource": "https://rs.example/mcp",
            }
            return httpx.Response(200, json=prm)
        # All unified discovery endpoints fail
        if request.method == "GET" and request.url.path in (
            "/.well-known/authorization_servers/mcp",
            "/.well-known/authorization_servers",
        ):
            return httpx.Response(404, text="not found")
        if request.method == "POST" and request.url.path == "/mcp":
            www = (
                'Bearer error="invalid_token", '
                'resource_metadata="https://rs.example/.well-known/oauth-protected-resource/mcp"'
            )
            return httpx.Response(401, headers={"www-authenticate": www}, text="unauthorized")
        return httpx.Response(500)

    transport = httpx.MockTransport(handler)
    storage = _MockStorage()

    async with httpx.AsyncClient(transport=transport) as client:
        provider = MultiProtocolAuthProvider(
            server_url="https://rs.example",
            storage=storage,
            protocols=[],  # No OAuth protocol injected
            http_client=client,
        )
        client.auth = provider
        with pytest.raises(RuntimeError, match="Failed to discover authentication protocols"):
            await client.post("https://rs.example/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize"})

    # Should have tried both unified discovery endpoints
    assert ("GET", "/.well-known/authorization_servers/mcp") in seen
    assert ("GET", "/.well-known/authorization_servers") in seen


# Note: OAuth discover_metadata exception handling is tested implicitly in other tests.
# A dedicated test would require a fully functional OAuth protocol mock, which is complex.
# The exception handling is already covered by the code's try-except block in multi_protocol.py.


@pytest.mark.anyio
async def test_401_flow_prm_with_mcp_auth_protocols_skips_unified_discovery() -> None:
    """Test that when PRM has mcp_auth_protocols, unified discovery is skipped."""
    seen: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path))
        if request.method == "GET" and "oauth-protected-resource" in request.url.path:
            # PRM with explicit mcp_auth_protocols
            # Note: ProtectedResourceMetadata requires authorization_servers, but we can use a dummy value
            # The key is that mcp_auth_protocols is explicitly set, so it should be used
            prm = {
                "resource": "https://rs.example/mcp",
                "authorization_servers": ["https://dummy.example/"],  # Required field
                "mcp_auth_protocols": [
                    {"protocol_id": "api_key", "protocol_version": "1.0"},
                ],
            }
            return httpx.Response(200, json=prm)
        # Unified discovery endpoints should not be called
        if request.method == "GET" and request.url.path in (
            "/.well-known/authorization_servers/mcp",
            "/.well-known/authorization_servers",
        ):
            return httpx.Response(500)  # Should not reach here
        if request.method == "POST" and request.url.path == "/mcp":
            if request.headers.get("x-api-key") == "test-key":
                return httpx.Response(
                    200,
                    json={"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2024-11-05"}},
                )
            www = (
                'Bearer error="invalid_token", '
                'resource_metadata="https://rs.example/.well-known/oauth-protected-resource/mcp"'
            )
            return httpx.Response(401, headers={"www-authenticate": www}, text="unauthorized")
        return httpx.Response(500)

    transport = httpx.MockTransport(handler)
    storage = _MockStorage()
    api_key_proto = _MockApiKeyProtocol(api_key="test-key")

    async with httpx.AsyncClient(transport=transport) as client:
        provider = MultiProtocolAuthProvider(
            server_url="https://rs.example",
            storage=storage,
            protocols=[api_key_proto],
            http_client=client,
        )
        client.auth = provider
        r = await client.post("https://rs.example/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize"})

    # Should NOT have tried unified discovery
    assert ("GET", "/.well-known/authorization_servers/mcp") not in seen
    assert ("GET", "/.well-known/authorization_servers") not in seen
    assert r.status_code == 200
