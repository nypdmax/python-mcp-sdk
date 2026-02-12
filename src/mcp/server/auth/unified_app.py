"""Unified authorization protocol framework for streamable-http MCP servers.

Provides a single factory ``create_unified_auth_app`` that returns a ready-to-run
Starlette application with PRM, unified discovery, authentication middleware, and
a protected MCP entry point.
"""

from __future__ import annotations

import contextlib
import enum
from collections.abc import AsyncIterator
from dataclasses import dataclass
from urllib.parse import urlparse

from pydantic import AnyHttpUrl
from starlette.applications import Starlette
from starlette.authentication import AuthenticationBackend
from starlette.middleware import Middleware
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.routing import Route

from mcp.server.auth.handlers.discovery import AuthorizationServersDiscoveryHandler
from mcp.server.auth.middleware.auth_context import AuthContextMiddleware
from mcp.server.auth.middleware.bearer_auth import RequireAuthMiddleware
from mcp.server.auth.routes import (
    build_resource_metadata_url,
    cors_middleware,
    create_authorization_servers_discovery_routes,
    create_protected_resource_routes,
)
from mcp.server.streamable_http_manager import StreamableHTTPASGIApp, StreamableHTTPSessionManager
from mcp.shared.auth import AuthProtocolMetadata

# ---------------------------------------------------------------------------
# Configuration objects
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ResourceServerConfig:
    """Runtime auth configuration for the resource server."""

    resource_url: AnyHttpUrl
    """Resource identifier (e.g. ``https://rs.example`` or ``https://rs.example/mcp``)."""

    authorization_servers: list[AnyHttpUrl]
    """Authorization server URLs that issue tokens for this resource."""

    required_scopes: list[str]
    """Scopes required by ``RequireAuthMiddleware`` for accessing the MCP entry."""

    scopes_supported: list[str] | None = None
    """Scopes advertised in PRM; defaults to ``required_scopes`` when omitted."""

    mcp_entry_path: str = "/mcp"
    """HTTP path where the streamable-http MCP endpoint is mounted."""


@dataclass(frozen=True)
class ProtocolDiscoveryConfig:
    """Protocol discovery declaration (PRM ``mcp_auth_xxx`` fields + unified discovery)."""

    protocols: list[AuthProtocolMetadata]
    """List of supported auth protocol metadata (oauth2, api_key, mutual_tls, ...)."""

    default_protocol: str | None = None
    """Default auth protocol ID."""

    protocol_preferences: dict[str, int] | None = None
    """Protocol ID to priority mapping."""


# ---------------------------------------------------------------------------
# Variant enum (predefined; avoids invalid bool combinations)
# ---------------------------------------------------------------------------


class UnifiedAuthVariant(enum.Enum):
    """Predefined discovery/hint variants for the unified auth app.

    Each variant controls:
    - Whether PRM includes ``mcp_auth_xxx`` extension fields.
    - Whether root or path-relative unified discovery is exposed.
    - Whether ``WWW-Authenticate`` 401/403 responses include protocol hints.
    """

    FULL = "full"
    """PRM includes mcp_auth_xxx, root discovery exposed, WWW-Authenticate hints enabled."""

    PRM_ONLY = "prm_only"
    """PRM includes mcp_auth_xxx, no discovery exposed, no WWW-Authenticate hints."""

    ROOT_ONLY = "root_only"
    """PRM without mcp_auth_xxx, root discovery exposed, no WWW-Authenticate hints."""

    PATH_ONLY = "path_only"
    """PRM without mcp_auth_xxx, path discovery exposed, no WWW-Authenticate hints."""

    OAUTH_FALLBACK = "oauth_fallback"
    """PRM without mcp_auth_xxx, no discovery, no hints (pure OAuth/RFC-9728 mode)."""


# Internal lookup tables for variant behaviour.
_VARIANT_PRM_INCLUDES_PROTOCOLS = {
    UnifiedAuthVariant.FULL,
    UnifiedAuthVariant.PRM_ONLY,
}
_VARIANT_EXPOSE_ROOT_DISCOVERY = {
    UnifiedAuthVariant.FULL,
    UnifiedAuthVariant.ROOT_ONLY,
}
_VARIANT_EXPOSE_PATH_DISCOVERY = {
    UnifiedAuthVariant.PATH_ONLY,
}
_VARIANT_WWW_AUTH_HINTS = {
    UnifiedAuthVariant.FULL,
}


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def create_unified_auth_app(
    *,
    session_manager: StreamableHTTPSessionManager,
    auth_backend: AuthenticationBackend,
    resource_config: ResourceServerConfig,
    discovery_config: ProtocolDiscoveryConfig,
    variant: UnifiedAuthVariant = UnifiedAuthVariant.FULL,
    debug: bool = False,
) -> Starlette:
    """Return a ready-to-run Starlette app with unified auth protocol framework.

    The returned application includes:
    - A protected MCP streamable-http entry point (``RequireAuthMiddleware``).
    - RFC 9728 Protected Resource Metadata (PRM) with optional ``mcp_auth_xxx``
      extension fields.
    - Optional unified authorization servers discovery endpoint(s).
    - ``AuthenticationMiddleware`` + ``AuthContextMiddleware``.
    - ``session_manager.run()`` bound to the Starlette lifespan.

    Args:
        session_manager: Already-constructed ``StreamableHTTPSessionManager``.
        auth_backend: Starlette ``AuthenticationBackend`` that injects
            ``AuthenticatedUser`` into the ASGI scope (may be multi-protocol).
        resource_config: Runtime auth configuration (resource URL, authorization
            servers, scopes, MCP entry path).
        discovery_config: Protocol discovery declaration (protocols list, default,
            preferences).
        variant: Predefined discovery/hint variant.
        debug: Starlette debug flag.
    """

    if not resource_config.mcp_entry_path.startswith("/"):
        raise ValueError("mcp_entry_path must start with '/'")

    # 1) Build the MCP transport ASGI app
    mcp_asgi = StreamableHTTPASGIApp(session_manager)

    # 2) Compute PRM metadata URL (for WWW-Authenticate ``resource_metadata``)
    resource_metadata_url = build_resource_metadata_url(resource_config.resource_url)

    # 3) Build RequireAuthMiddleware kwargs (protocol hints only for FULL)
    require_auth_kwargs: dict[str, object] = {
        "required_scopes": resource_config.required_scopes,
        "resource_metadata_url": resource_metadata_url,
    }
    if variant in _VARIANT_WWW_AUTH_HINTS:
        protocol_ids = [p.protocol_id for p in discovery_config.protocols]
        require_auth_kwargs["auth_protocols"] = protocol_ids
        require_auth_kwargs["default_protocol"] = discovery_config.default_protocol
        require_auth_kwargs["protocol_preferences"] = discovery_config.protocol_preferences

    protected_mcp = RequireAuthMiddleware(mcp_asgi, **require_auth_kwargs)  # type: ignore[arg-type]

    # 4) Routes
    routes: list[Route] = [
        Route(resource_config.mcp_entry_path, endpoint=protected_mcp),
    ]

    # 4a) PRM routes
    prm_includes_protocols = variant in _VARIANT_PRM_INCLUDES_PROTOCOLS
    routes.extend(
        create_protected_resource_routes(
            resource_url=resource_config.resource_url,
            authorization_servers=resource_config.authorization_servers,
            scopes_supported=resource_config.scopes_supported or resource_config.required_scopes,
            auth_protocols=discovery_config.protocols if prm_includes_protocols else [],
            default_protocol=discovery_config.default_protocol if prm_includes_protocols else None,
            protocol_preferences=discovery_config.protocol_preferences if prm_includes_protocols else None,
        )
    )

    # 4b) Unified discovery routes
    if variant in _VARIANT_EXPOSE_ROOT_DISCOVERY:
        routes.extend(
            create_authorization_servers_discovery_routes(
                protocols=discovery_config.protocols,
                default_protocol=discovery_config.default_protocol,
                protocol_preferences=discovery_config.protocol_preferences,
            )
        )
    if variant in _VARIANT_EXPOSE_PATH_DISCOVERY:
        handler = AuthorizationServersDiscoveryHandler(
            protocols=discovery_config.protocols,
            default_protocol=discovery_config.default_protocol,
            protocol_preferences=discovery_config.protocol_preferences,
        )
        # Path discovery: /.well-known/authorization_servers + resource path
        resource_path = urlparse(str(resource_config.resource_url)).path
        if not resource_path or resource_path == "/":
            resource_path = resource_config.mcp_entry_path
        path_discovery_route = f"/.well-known/authorization_servers{resource_path}"
        routes.append(
            Route(
                path_discovery_route,
                endpoint=cors_middleware(handler.handle, ["GET", "OPTIONS"]),
                methods=["GET", "OPTIONS"],
            )
        )

    # 5) Middleware
    middleware = [
        Middleware(AuthenticationMiddleware, backend=auth_backend),
        Middleware(AuthContextMiddleware),
    ]

    # 6) Lifespan (bind session_manager.run())
    @contextlib.asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[None]:
        async with session_manager.run():
            yield

    return Starlette(
        debug=debug,
        routes=routes,
        middleware=middleware,
        lifespan=lifespan,
    )
