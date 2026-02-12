"""Tests for the unified auth protocol framework (create_unified_auth_app).

Covers all ``UnifiedAuthVariant`` values, root vs subpath ``resource_url``,
401/403 error responses, PRM ``mcp_auth_xxx`` extension fields, unified
discovery endpoints, CORS OPTIONS, and lifespan binding.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx
import pytest
from pydantic import AnyHttpUrl
from starlette.authentication import AuthCredentials, AuthenticationBackend
from starlette.requests import HTTPConnection

from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.unified_app import (
    ProtocolDiscoveryConfig,
    ResourceServerConfig,
    UnifiedAuthVariant,
    create_unified_auth_app,
)
from mcp.shared.auth import AuthProtocolMetadata

# ---------------------------------------------------------------------------
# Helpers / stubs
# ---------------------------------------------------------------------------

_TEST_SCOPE = "user"
_TEST_API_KEY = "test-key"
_PROTOCOLS = [
    AuthProtocolMetadata(protocol_id="oauth2", protocol_version="2.0"),
    AuthProtocolMetadata(protocol_id="api_key", protocol_version="1.0"),
    AuthProtocolMetadata(protocol_id="mutual_tls", protocol_version="1.0"),
]
_DEFAULT_PROTOCOL = "oauth2"
_PROTOCOL_PREFS = {"oauth2": 1, "api_key": 2, "mutual_tls": 3}


class _StubAuthBackend(AuthenticationBackend):
    """Test backend that authenticates requests with ``Authorization: Bearer test-key``."""

    def __init__(self, *, scopes: list[str] | None = None) -> None:
        self._scopes = scopes if scopes is not None else [_TEST_SCOPE]

    async def authenticate(self, conn: HTTPConnection) -> tuple[AuthCredentials, AuthenticatedUser] | None:
        auth_header = conn.headers.get("authorization", "")
        if auth_header.lower().startswith("bearer ") and auth_header[7:] == _TEST_API_KEY:
            access_token = AccessToken(
                token=_TEST_API_KEY,
                client_id="test_client",
                scopes=list(self._scopes),
                expires_at=None,
            )
            return AuthCredentials(self._scopes), AuthenticatedUser(access_token)
        return None


class _StubSessionManager:
    """Minimal stub that satisfies ``create_unified_auth_app``'s contract.

    Tracks whether ``run()`` was entered/exited and provides a working
    ``handle_request`` that returns an HTTP 200 response.
    """

    def __init__(self) -> None:
        self.run_entered = False
        self.run_exited = False

    @asynccontextmanager
    async def run(self) -> AsyncIterator[None]:
        self.run_entered = True
        try:
            yield
        finally:
            self.run_exited = True

    async def handle_request(self, scope: Any, receive: Any, send: Any) -> None:
        """Return a minimal 200 response so that authenticated requests complete."""
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        await send({"type": "http.response.body", "body": b'{"ok":true}'})


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_resource_config(
    resource_url: str = "https://rs.example",
    mcp_entry_path: str = "/mcp",
) -> ResourceServerConfig:
    return ResourceServerConfig(
        resource_url=AnyHttpUrl(resource_url),
        authorization_servers=[AnyHttpUrl("https://as.example")],
        required_scopes=[_TEST_SCOPE],
        mcp_entry_path=mcp_entry_path,
    )


def _make_discovery_config() -> ProtocolDiscoveryConfig:
    return ProtocolDiscoveryConfig(
        protocols=_PROTOCOLS,
        default_protocol=_DEFAULT_PROTOCOL,
        protocol_preferences=_PROTOCOL_PREFS,
    )


def _build_app(
    variant: UnifiedAuthVariant = UnifiedAuthVariant.FULL,
    resource_url: str = "https://rs.example",
    mcp_entry_path: str = "/mcp",
    backend_scopes: list[str] | None = None,
) -> tuple[Any, _StubSessionManager]:
    """Build the Starlette app and return (app, stub_session_manager)."""
    stub_sm = _StubSessionManager()
    # ``create_unified_auth_app`` expects a real ``StreamableHTTPSessionManager``
    # but we only need the duck-typed shape (run() + StreamableHTTPASGIApp).
    # Monkey-patch the stub so that it passes ``StreamableHTTPASGIApp.__init__``.
    app = create_unified_auth_app(
        session_manager=stub_sm,  # type: ignore[arg-type]
        auth_backend=_StubAuthBackend(scopes=backend_scopes),
        resource_config=_make_resource_config(resource_url, mcp_entry_path),
        discovery_config=_make_discovery_config(),
        variant=variant,
    )
    return app, stub_sm


def _client(app: Any, base_url: str = "https://rs.example") -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=base_url)


# ---------------------------------------------------------------------------
# Variant-parameterised tests
# ---------------------------------------------------------------------------


@pytest.mark.anyio
@pytest.mark.parametrize("variant", list(UnifiedAuthVariant))
async def test_mcp_entry_returns_401_without_credentials(variant: UnifiedAuthVariant) -> None:
    """All variants must return 401 when no credentials are provided."""
    app, _ = _build_app(variant=variant)
    async with _client(app) as client:
        response = await client.post("/mcp")

    assert response.status_code == 401
    www = response.headers["www-authenticate"]
    assert 'error="invalid_token"' in www
    # resource_metadata must always be present
    assert "resource_metadata=" in www


@pytest.mark.anyio
@pytest.mark.parametrize("variant", list(UnifiedAuthVariant))
async def test_mcp_entry_returns_200_with_valid_credentials(variant: UnifiedAuthVariant) -> None:
    """All variants allow authenticated requests through (even though the inner app is a stub)."""
    app, _ = _build_app(variant=variant)
    async with _client(app) as client:
        response = await client.post("/mcp", headers={"Authorization": f"Bearer {_TEST_API_KEY}"})

    # Auth passed and the stub transport returns 200.
    assert response.status_code == 200


@pytest.mark.anyio
@pytest.mark.parametrize("variant", list(UnifiedAuthVariant))
async def test_403_insufficient_scope(variant: UnifiedAuthVariant) -> None:
    """All variants must return 403 when authenticated user lacks required scope."""
    app, _ = _build_app(variant=variant, backend_scopes=["other_scope"])
    async with _client(app) as client:
        response = await client.post("/mcp", headers={"Authorization": f"Bearer {_TEST_API_KEY}"})

    assert response.status_code == 403
    www = response.headers["www-authenticate"]
    assert 'error="insufficient_scope"' in www
    assert "resource_metadata=" in www


# ---------------------------------------------------------------------------
# FULL variant specifics
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_full_401_includes_protocol_hints() -> None:
    app, _ = _build_app(variant=UnifiedAuthVariant.FULL)
    async with _client(app) as client:
        response = await client.post("/mcp")

    www = response.headers["www-authenticate"]
    assert 'auth_protocols="oauth2 api_key mutual_tls"' in www
    assert 'default_protocol="oauth2"' in www
    assert "protocol_preferences=" in www
    assert "oauth2:1" in www
    assert "api_key:2" in www


@pytest.mark.anyio
async def test_full_403_includes_protocol_hints() -> None:
    app, _ = _build_app(variant=UnifiedAuthVariant.FULL, backend_scopes=["wrong"])
    async with _client(app) as client:
        response = await client.post("/mcp", headers={"Authorization": f"Bearer {_TEST_API_KEY}"})

    assert response.status_code == 403
    www = response.headers["www-authenticate"]
    assert 'auth_protocols="oauth2 api_key mutual_tls"' in www


@pytest.mark.anyio
async def test_full_prm_includes_mcp_auth_extensions() -> None:
    app, _ = _build_app(variant=UnifiedAuthVariant.FULL)
    async with _client(app) as client:
        response = await client.get("/.well-known/oauth-protected-resource")

    assert response.status_code == 200
    data = response.json()
    assert len(data["mcp_auth_protocols"]) == 3
    assert data["mcp_auth_protocols"][0]["protocol_id"] == "oauth2"
    assert data["mcp_default_auth_protocol"] == "oauth2"
    assert data["mcp_auth_protocol_preferences"] == {"oauth2": 1, "api_key": 2, "mutual_tls": 3}


@pytest.mark.anyio
async def test_full_root_discovery_exists() -> None:
    app, _ = _build_app(variant=UnifiedAuthVariant.FULL)
    async with _client(app) as client:
        response = await client.get("/.well-known/authorization_servers")

    assert response.status_code == 200
    data = response.json()
    assert len(data["protocols"]) == 3
    assert data["default_protocol"] == "oauth2"
    assert data["protocol_preferences"] == {"oauth2": 1, "api_key": 2, "mutual_tls": 3}


# ---------------------------------------------------------------------------
# PRM_ONLY variant specifics
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_prm_only_prm_includes_mcp_auth_extensions() -> None:
    app, _ = _build_app(variant=UnifiedAuthVariant.PRM_ONLY)
    async with _client(app) as client:
        response = await client.get("/.well-known/oauth-protected-resource")

    assert response.status_code == 200
    data = response.json()
    assert len(data["mcp_auth_protocols"]) == 3


@pytest.mark.anyio
async def test_prm_only_no_discovery() -> None:
    app, _ = _build_app(variant=UnifiedAuthVariant.PRM_ONLY)
    async with _client(app) as client:
        response = await client.get("/.well-known/authorization_servers")

    assert response.status_code == 404


@pytest.mark.anyio
async def test_prm_only_no_www_auth_hints() -> None:
    app, _ = _build_app(variant=UnifiedAuthVariant.PRM_ONLY)
    async with _client(app) as client:
        response = await client.post("/mcp")

    www = response.headers["www-authenticate"]
    assert "auth_protocols=" not in www
    assert "default_protocol=" not in www
    assert "protocol_preferences=" not in www


# ---------------------------------------------------------------------------
# ROOT_ONLY variant specifics
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_root_only_prm_empty_protocols() -> None:
    app, _ = _build_app(variant=UnifiedAuthVariant.ROOT_ONLY)
    async with _client(app) as client:
        response = await client.get("/.well-known/oauth-protected-resource")

    assert response.status_code == 200
    data = response.json()
    assert data["mcp_auth_protocols"] == []
    assert data.get("mcp_default_auth_protocol") is None


@pytest.mark.anyio
async def test_root_only_root_discovery_exists() -> None:
    app, _ = _build_app(variant=UnifiedAuthVariant.ROOT_ONLY)
    async with _client(app) as client:
        response = await client.get("/.well-known/authorization_servers")

    assert response.status_code == 200


@pytest.mark.anyio
async def test_root_only_no_www_auth_hints() -> None:
    app, _ = _build_app(variant=UnifiedAuthVariant.ROOT_ONLY)
    async with _client(app) as client:
        response = await client.post("/mcp")

    www = response.headers["www-authenticate"]
    assert "auth_protocols=" not in www


# ---------------------------------------------------------------------------
# PATH_ONLY variant specifics
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_path_only_prm_empty_protocols() -> None:
    app, _ = _build_app(variant=UnifiedAuthVariant.PATH_ONLY)
    async with _client(app) as client:
        response = await client.get("/.well-known/oauth-protected-resource")

    assert response.status_code == 200
    data = response.json()
    assert data["mcp_auth_protocols"] == []


@pytest.mark.anyio
async def test_path_only_no_root_discovery() -> None:
    app, _ = _build_app(variant=UnifiedAuthVariant.PATH_ONLY)
    async with _client(app) as client:
        response = await client.get("/.well-known/authorization_servers")

    assert response.status_code == 404


@pytest.mark.anyio
async def test_path_only_path_discovery_exists() -> None:
    """PATH_ONLY exposes path-relative discovery at /.well-known/authorization_servers{mcp_entry_path}."""
    app, _ = _build_app(variant=UnifiedAuthVariant.PATH_ONLY)
    async with _client(app) as client:
        response = await client.get("/.well-known/authorization_servers/mcp")

    assert response.status_code == 200
    data = response.json()
    assert len(data["protocols"]) == 3


@pytest.mark.anyio
async def test_path_only_path_discovery_with_subpath_resource() -> None:
    """When resource_url has a path, path discovery uses that path."""
    app, _ = _build_app(
        variant=UnifiedAuthVariant.PATH_ONLY,
        resource_url="https://rs.example/api/v1",
        mcp_entry_path="/api/v1",
    )
    async with _client(app) as client:
        response = await client.get("/.well-known/authorization_servers/api/v1")

    assert response.status_code == 200


# ---------------------------------------------------------------------------
# OAUTH_FALLBACK variant specifics
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_oauth_fallback_prm_empty_protocols() -> None:
    app, _ = _build_app(variant=UnifiedAuthVariant.OAUTH_FALLBACK)
    async with _client(app) as client:
        response = await client.get("/.well-known/oauth-protected-resource")

    assert response.status_code == 200
    data = response.json()
    assert data["mcp_auth_protocols"] == []


@pytest.mark.anyio
async def test_oauth_fallback_no_root_discovery() -> None:
    app, _ = _build_app(variant=UnifiedAuthVariant.OAUTH_FALLBACK)
    async with _client(app) as client:
        response = await client.get("/.well-known/authorization_servers")

    assert response.status_code == 404


@pytest.mark.anyio
async def test_oauth_fallback_no_www_auth_hints() -> None:
    app, _ = _build_app(variant=UnifiedAuthVariant.OAUTH_FALLBACK)
    async with _client(app) as client:
        response = await client.post("/mcp")

    www = response.headers["www-authenticate"]
    assert "auth_protocols=" not in www


# ---------------------------------------------------------------------------
# resource_url root vs subpath PRM path coverage
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_prm_at_root_when_resource_url_has_no_path() -> None:
    """resource_url without path -> PRM at /.well-known/oauth-protected-resource."""
    app, _ = _build_app(resource_url="https://rs.example")
    async with _client(app) as client:
        response = await client.get("/.well-known/oauth-protected-resource")

    assert response.status_code == 200
    data = response.json()
    assert "authorization_servers" in data


@pytest.mark.anyio
async def test_prm_at_subpath_when_resource_url_has_path() -> None:
    """resource_url with /mcp path -> PRM at /.well-known/oauth-protected-resource/mcp."""
    app, _ = _build_app(resource_url="https://rs.example/mcp", mcp_entry_path="/mcp")
    async with _client(app) as client:
        # This specific subpath must exist
        response = await client.get("/.well-known/oauth-protected-resource/mcp")

    assert response.status_code == 200
    data = response.json()
    assert "authorization_servers" in data


@pytest.mark.anyio
async def test_prm_at_deep_subpath() -> None:
    """resource_url with /api/v1/mcp -> PRM at /.well-known/oauth-protected-resource/api/v1/mcp."""
    app, _ = _build_app(
        resource_url="https://rs.example/api/v1/mcp",
        mcp_entry_path="/api/v1/mcp",
    )
    async with _client(app) as client:
        response = await client.get("/.well-known/oauth-protected-resource/api/v1/mcp")

    assert response.status_code == 200


# ---------------------------------------------------------------------------
# 401 resource_metadata points to correct PRM URL
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_401_resource_metadata_root() -> None:
    app, _ = _build_app(resource_url="https://rs.example")
    async with _client(app) as client:
        response = await client.post("/mcp")

    www = response.headers["www-authenticate"]
    assert 'resource_metadata="https://rs.example/.well-known/oauth-protected-resource"' in www


@pytest.mark.anyio
async def test_401_resource_metadata_subpath() -> None:
    app, _ = _build_app(resource_url="https://rs.example/mcp", mcp_entry_path="/mcp")
    async with _client(app) as client:
        response = await client.post("/mcp")

    www = response.headers["www-authenticate"]
    assert 'resource_metadata="https://rs.example/.well-known/oauth-protected-resource/mcp"' in www


# ---------------------------------------------------------------------------
# CORS / OPTIONS
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_cors_options_prm() -> None:
    app, _ = _build_app()
    async with _client(app) as client:
        response = await client.options("/.well-known/oauth-protected-resource")

    assert response.status_code == 200


@pytest.mark.anyio
async def test_cors_options_root_discovery() -> None:
    app, _ = _build_app(variant=UnifiedAuthVariant.FULL)
    async with _client(app) as client:
        response = await client.options("/.well-known/authorization_servers")

    assert response.status_code == 200


@pytest.mark.anyio
async def test_cors_options_path_discovery() -> None:
    app, _ = _build_app(variant=UnifiedAuthVariant.PATH_ONLY)
    async with _client(app) as client:
        response = await client.options("/.well-known/authorization_servers/mcp")

    assert response.status_code == 200


# ---------------------------------------------------------------------------
# Lifespan: session_manager.run() is called
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_lifespan_calls_session_manager_run() -> None:
    """The factory binds session_manager.run() to the Starlette lifespan."""
    import anyio

    app, stub_sm = _build_app()

    # Track lifespan phases.
    startup_complete = False
    shutdown_complete = False
    scope: dict[str, str] = {"type": "lifespan"}

    async with anyio.create_task_group() as tg:

        async def run_lifespan() -> None:
            nonlocal startup_complete, shutdown_complete

            async def lifespan_receive() -> dict[str, str]:
                if not startup_complete:
                    return {"type": "lifespan.startup"}
                # After startup, wait briefly then request shutdown.
                await anyio.sleep(0.05)
                return {"type": "lifespan.shutdown"}

            async def lifespan_send(message: dict[str, str]) -> None:
                nonlocal startup_complete, shutdown_complete
                if message["type"] == "lifespan.startup.complete":
                    startup_complete = True
                else:
                    # Only other message in the lifespan protocol is shutdown.complete.
                    shutdown_complete = True

            await app(scope, lifespan_receive, lifespan_send)  # type: ignore[arg-type]

        tg.start_soon(run_lifespan)

        # Wait until startup completes.
        while not startup_complete:
            await anyio.sleep(0.01)

        assert stub_sm.run_entered is True
        assert stub_sm.run_exited is False

    # After shutdown completes, verify the full lifecycle.
    assert stub_sm.run_exited is True
    assert shutdown_complete is True


# ---------------------------------------------------------------------------
# PRM basic fields (authorization_servers, scopes) always present
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_prm_always_includes_base_fields() -> None:
    app, _ = _build_app(variant=UnifiedAuthVariant.OAUTH_FALLBACK)
    async with _client(app) as client:
        response = await client.get("/.well-known/oauth-protected-resource")

    data = response.json()
    # base RFC 9728 fields
    assert "resource" in data
    assert len(data["authorization_servers"]) >= 1
    assert _TEST_SCOPE in data["scopes_supported"]


# ---------------------------------------------------------------------------
# PATH_ONLY with root resource_url falls back to mcp_entry_path
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_path_only_root_resource_uses_mcp_entry_path() -> None:
    """When resource_url has no path but variant is PATH_ONLY, use mcp_entry_path for discovery route."""
    app, _ = _build_app(
        variant=UnifiedAuthVariant.PATH_ONLY,
        resource_url="https://rs.example",
        mcp_entry_path="/mcp",
    )
    async with _client(app) as client:
        response = await client.get("/.well-known/authorization_servers/mcp")

    assert response.status_code == 200


@pytest.mark.anyio
async def test_prm_scopes_supported_can_differ_from_required_scopes() -> None:
    resource_config = ResourceServerConfig(
        resource_url=AnyHttpUrl("https://rs.example"),
        authorization_servers=[AnyHttpUrl("https://as.example")],
        required_scopes=["runtime_scope"],
        scopes_supported=["runtime_scope", "extended_scope"],
    )
    app = create_unified_auth_app(
        session_manager=_StubSessionManager(),  # type: ignore[arg-type]
        auth_backend=_StubAuthBackend(scopes=["runtime_scope"]),
        resource_config=resource_config,
        discovery_config=_make_discovery_config(),
        variant=UnifiedAuthVariant.OAUTH_FALLBACK,
    )
    async with _client(app) as client:
        prm_response = await client.get("/.well-known/oauth-protected-resource")
        auth_response = await client.post("/mcp")

    prm_data = prm_response.json()
    assert prm_data["scopes_supported"] == ["runtime_scope", "extended_scope"]
    assert auth_response.status_code == 401


def test_invalid_paths_raise_value_error() -> None:
    resource_config = ResourceServerConfig(
        resource_url=AnyHttpUrl("https://rs.example"),
        authorization_servers=[AnyHttpUrl("https://as.example")],
        required_scopes=[_TEST_SCOPE],
        mcp_entry_path="mcp",
    )
    with pytest.raises(ValueError, match="mcp_entry_path"):
        create_unified_auth_app(
            session_manager=_StubSessionManager(),  # type: ignore[arg-type]
            auth_backend=_StubAuthBackend(),
            resource_config=resource_config,
            discovery_config=_make_discovery_config(),
            variant=UnifiedAuthVariant.FULL,
        )
