# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/admin/overview.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Admin UI dashboard configuration routes: the overview partial, passthrough
header settings, A2A stats cache controls, and the settings view.
"""

# Standard
import html
import logging
import time
from typing import Any, Dict

# Third-Party
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import SecretStr, ValidationError
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

# First-Party
from mcpgateway import __version__, version as version_module
from mcpgateway.admin.security import enforce_admin_csrf, rate_limit
from mcpgateway.auth_context import get_user_email
from mcpgateway.cache.a2a_stats_cache import a2a_stats_cache
from mcpgateway.cache.global_config_cache import global_config_cache
from mcpgateway.config import settings
from mcpgateway.db import A2AAgent as DbA2AAgent, Gateway as DbGateway, get_db, GlobalConfig, Prompt as DbPrompt, Resource as DbResource, Server as DbServer, Tool as DbTool
from mcpgateway.middleware.rbac import get_current_user_with_permissions, require_permission
from mcpgateway.schemas import GlobalConfigRead, GlobalConfigUpdate
from mcpgateway.services.plugin_service import get_plugin_service, sync_plugin_service_from_runtime
from mcpgateway.services.prompt_service import PromptService
from mcpgateway.services.resource_service import ResourceService
from mcpgateway.services.server_service import ServerService
from mcpgateway.services.tool_service import ToolService
from mcpgateway.utils.passthrough_headers import PassthroughHeadersError
from mcpgateway.utils.paths import resolve_root_path as _resolve_root_path

LOGGER: logging.Logger = logging.getLogger("mcpgateway.admin")

# mcpgateway.admin (__init__) appends this router's routes to admin_router, so the
# prefix, tags, and CSRF dependency must mirror admin_router exactly.
router = APIRouter(
    prefix="/admin",
    tags=["Admin UI"],
    dependencies=[Depends(enforce_admin_csrf)],
)


@router.get("/overview/partial")
@require_permission("admin.overview", allow_admin_bypass=False)
async def get_overview_partial(
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> HTMLResponse:
    """Render the overview dashboard partial HTML template.

    This endpoint returns a rendered HTML partial containing an architecture
    diagram showing ContextForge inputs (Virtual Servers), middleware (Plugins),
    and outputs (A2A Agents, Gateways, Tools, etc.) along with key metrics.

    Args:
        request: FastAPI request object
        db: Database session
        user: Authenticated user

    Returns:
        HTMLResponse with rendered overview partial template
    """
    LOGGER.debug(f"User {get_user_email(user)} requested overview partial")

    try:
        # Gather counts for all entity types
        # Note: SQLAlchemy func.count requires pylint disable=not-callable
        # Virtual Servers (inputs) - uses 'enabled' field
        servers_total = db.query(func.count(DbServer.id)).scalar() or 0  # pylint: disable=not-callable
        servers_active = db.query(func.count(DbServer.id)).filter(DbServer.enabled.is_(True)).scalar() or 0  # pylint: disable=not-callable

        # Gateways - uses 'enabled' field
        gateways_total = db.query(func.count(DbGateway.id)).scalar() or 0  # pylint: disable=not-callable
        gateways_active = db.query(func.count(DbGateway.id)).filter(DbGateway.enabled.is_(True)).scalar() or 0  # pylint: disable=not-callable

        # A2A Agents (if enabled) - uses 'enabled' field
        a2a_total = 0
        a2a_active = 0
        if settings.mcpgateway_a2a_enabled:
            a2a_total = db.query(func.count(DbA2AAgent.id)).scalar() or 0  # pylint: disable=not-callable
            a2a_active = db.query(func.count(DbA2AAgent.id)).filter(DbA2AAgent.enabled.is_(True)).scalar() or 0  # pylint: disable=not-callable

        # Tools - uses 'enabled' field
        tools_total = db.query(func.count(DbTool.id)).scalar() or 0  # pylint: disable=not-callable
        tools_active = db.query(func.count(DbTool.id)).filter(DbTool.enabled.is_(True)).scalar() or 0  # pylint: disable=not-callable

        # Prompts - uses 'enabled' field
        prompts_total = db.query(func.count(DbPrompt.id)).scalar() or 0  # pylint: disable=not-callable
        prompts_active = db.query(func.count(DbPrompt.id)).filter(DbPrompt.enabled.is_(True)).scalar() or 0  # pylint: disable=not-callable

        # Resources - uses 'enabled' field
        resources_total = db.query(func.count(DbResource.id)).scalar() or 0  # pylint: disable=not-callable
        resources_active = db.query(func.count(DbResource.id)).filter(DbResource.enabled.is_(True)).scalar() or 0  # pylint: disable=not-callable

        # Plugin stats — self-heal the cache so the overview reflects the live
        # shared toggle even on a process that booted with plugins disabled.
        overview_plugin_service = get_plugin_service()
        await sync_plugin_service_from_runtime(request, overview_plugin_service)
        plugin_stats = await overview_plugin_service.get_plugin_statistics()

        # Infrastructure status (database, cache, uptime)
        _, db_reachable = version_module._database_version()  # pylint: disable=protected-access
        db_dialect = version_module.engine.dialect.name
        cache_type = settings.cache_type
        uptime_seconds = int(time.time() - version_module.START_TIME)

        # Redis status (if applicable)
        redis_available = version_module.REDIS_AVAILABLE
        redis_reachable = False
        if redis_available and cache_type.lower() == "redis" and settings.redis_url:
            try:
                # First-Party
                from mcpgateway.utils.redis_client import is_redis_available  # pylint: disable=import-outside-toplevel

                redis_reachable = await is_redis_available()
            except Exception:
                redis_reachable = False

        # Aggregate metrics from services
        overview_tool_service = ToolService()
        overview_server_service = ServerService()
        overview_prompt_service = PromptService()
        overview_resource_service = ResourceService()

        tool_metrics = await overview_tool_service.aggregate_metrics(db)
        server_metrics = await overview_server_service.aggregate_metrics(db)
        prompt_metrics = await overview_prompt_service.aggregate_metrics(db)
        resource_metrics = await overview_resource_service.aggregate_metrics(db)

        # Calculate totals
        total_executions = (
            (tool_metrics.get("total_executions", 0) if isinstance(tool_metrics, dict) else getattr(tool_metrics, "total_executions", 0))
            + (server_metrics.total_executions if hasattr(server_metrics, "total_executions") else server_metrics.get("total_executions", 0))
            + (prompt_metrics.get("total_executions", 0) if isinstance(prompt_metrics, dict) else getattr(prompt_metrics, "total_executions", 0))
            + (resource_metrics.total_executions if hasattr(resource_metrics, "total_executions") else resource_metrics.get("total_executions", 0))
        )

        successful_executions = (
            (tool_metrics.get("successful_executions", 0) if isinstance(tool_metrics, dict) else getattr(tool_metrics, "successful_executions", 0))
            + (server_metrics.successful_executions if hasattr(server_metrics, "successful_executions") else server_metrics.get("successful_executions", 0))
            + (prompt_metrics.get("successful_executions", 0) if isinstance(prompt_metrics, dict) else getattr(prompt_metrics, "successful_executions", 0))
            + (resource_metrics.successful_executions if hasattr(resource_metrics, "successful_executions") else resource_metrics.get("successful_executions", 0))
        )

        success_rate = (successful_executions / total_executions * 100) if total_executions > 0 else 100.0

        # Calculate average latency across all services
        latencies = []
        for m in [tool_metrics, server_metrics, prompt_metrics, resource_metrics]:
            avg_time = m.get("avg_response_time") if isinstance(m, dict) else getattr(m, "avg_response_time", None)
            if avg_time is not None:
                latencies.append(avg_time)
        avg_latency = sum(latencies) / len(latencies) if latencies else 0.0

        # Prepare context
        context = {
            "request": request,
            "root_path": _resolve_root_path(request),
            # Inputs
            "servers_total": servers_total,
            "servers_active": servers_active,
            # Outputs
            "gateways_total": gateways_total,
            "gateways_active": gateways_active,
            "a2a_total": a2a_total,
            "a2a_active": a2a_active,
            "a2a_enabled": settings.mcpgateway_a2a_enabled,
            "tools_total": tools_total,
            "tools_active": tools_active,
            "prompts_total": prompts_total,
            "prompts_active": prompts_active,
            "resources_total": resources_total,
            "resources_active": resources_active,
            # Plugins (plugin_stats can be dict or PluginStatsResponse)
            "plugins_total": plugin_stats.get("total_plugins", 0) if isinstance(plugin_stats, dict) else getattr(plugin_stats, "total_plugins", 0),
            "plugins_enabled": plugin_stats.get("enabled_plugins", 0) if isinstance(plugin_stats, dict) else getattr(plugin_stats, "enabled_plugins", 0),
            "plugins_by_hook": plugin_stats.get("plugins_by_hook", {}) if isinstance(plugin_stats, dict) else getattr(plugin_stats, "plugins_by_hook", {}),
            # Metrics
            "total_executions": total_executions,
            "success_rate": success_rate,
            "avg_latency_ms": avg_latency * 1000 if avg_latency else 0.0,
            # Version
            "version": __version__,
            # Infrastructure
            "db_dialect": db_dialect,
            "db_reachable": db_reachable,
            "cache_type": cache_type,
            "redis_available": redis_available,
            "redis_reachable": redis_reachable,
            "uptime_seconds": uptime_seconds,
            "mcp_runtime": version_module.mcp_runtime_status_payload(),
        }

        return request.app.state.templates.TemplateResponse(request, "overview_partial.html", context)

    except Exception as e:
        LOGGER.error(f"Error rendering overview partial: {e}")
        error_html = f"""
        <div class="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-300 px-4 py-3 rounded">
            <strong class="font-bold">Error loading overview:</strong>
            <span class="block sm:inline">{html.escape(str(e))}</span>
        </div>
        """
        return HTMLResponse(content=error_html, status_code=500)


@router.get("/config/passthrough-headers", response_model=GlobalConfigRead)
@require_permission("admin.system_config", allow_admin_bypass=False)
@rate_limit(requests_per_minute=30)  # Lower limit for config endpoints
async def get_global_passthrough_headers(
    db: Session = Depends(get_db),
    _user=Depends(get_current_user_with_permissions),
) -> GlobalConfigRead:
    """Get the global passthrough headers configuration.

    Args:
        db: Database session
        _user: Authenticated user

    Returns:
        GlobalConfigRead: The current global passthrough headers configuration

    Examples:
        >>> # Test function exists and has correct name
        >>> from mcpgateway.admin import get_global_passthrough_headers
        >>> get_global_passthrough_headers.__name__
        'get_global_passthrough_headers'
        >>> # Test it's a coroutine function
        >>> import inspect
        >>> inspect.iscoroutinefunction(get_global_passthrough_headers)
        True
    """
    # Use cache for reads (Issue #1715)
    # Pass env defaults so env/merge modes return correct headers
    passthrough_headers = global_config_cache.get_passthrough_headers(db, settings.default_passthrough_headers)
    return GlobalConfigRead(passthrough_headers=passthrough_headers)


@router.put("/config/passthrough-headers", response_model=GlobalConfigRead)
@require_permission("admin.system_config", allow_admin_bypass=False)
@rate_limit(requests_per_minute=20)  # Stricter limit for config updates
async def update_global_passthrough_headers(
    request: Request,  # pylint: disable=unused-argument
    config_update: GlobalConfigUpdate,
    db: Session = Depends(get_db),
    _user=Depends(get_current_user_with_permissions),
) -> GlobalConfigRead:
    """Update the global passthrough headers configuration.

    Args:
        request: HTTP request object
        config_update: The new configuration
        db: Database session
        _user: Authenticated user

    Raises:
        HTTPException: If there is a conflict or validation error

    Returns:
        GlobalConfigRead: The updated configuration

    Examples:
        >>> # Test function exists and has correct name
        >>> from mcpgateway.admin import update_global_passthrough_headers
        >>> update_global_passthrough_headers.__name__
        'update_global_passthrough_headers'
        >>> # Test it's a coroutine function
        >>> import inspect
        >>> inspect.iscoroutinefunction(update_global_passthrough_headers)
        True
    """
    try:
        config = db.query(GlobalConfig).first()
        if not config:
            config = GlobalConfig(passthrough_headers=config_update.passthrough_headers)
            db.add(config)
        else:
            config.passthrough_headers = config_update.passthrough_headers
        db.commit()
        # Invalidate both global and loopback caches so changes propagate immediately (Issue #1715, #3640)
        # First-Party
        from mcpgateway.utils.passthrough_headers import invalidate_passthrough_header_caches  # pylint: disable=import-outside-toplevel

        invalidate_passthrough_header_caches()
        return GlobalConfigRead(passthrough_headers=config.passthrough_headers)
    except IntegrityError as e:
        db.rollback()
        raise HTTPException(status_code=409, detail="Passthrough headers conflict") from e
    except ValidationError as e:
        db.rollback()
        raise HTTPException(status_code=422, detail="Invalid passthrough headers format") from e
    except PassthroughHeadersError as e:
        db.rollback()
        LOGGER.error(f"Passthrough headers error: {e}")
        raise HTTPException(status_code=500, detail="Passthrough headers error") from e


@router.post("/config/passthrough-headers/invalidate-cache")
@require_permission("admin.system_config", allow_admin_bypass=False)
@rate_limit(requests_per_minute=10)  # Strict limit for cache operations
async def invalidate_passthrough_headers_cache(
    _user=Depends(get_current_user_with_permissions),
    _db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Invalidate the GlobalConfig cache.

    Forces an immediate cache refresh on the next access. Use this after
    updating GlobalConfig outside the normal API flow, or when you need
    changes to propagate immediately across all workers.

    Args:
        _user: Authenticated user
        _db: Database session for permission checks.

    Returns:
        Dict with invalidation status and cache statistics

    Examples:
        >>> # Test function exists and has correct name
        >>> from mcpgateway.admin import invalidate_passthrough_headers_cache
        >>> invalidate_passthrough_headers_cache.__name__
        'invalidate_passthrough_headers_cache'
        >>> # Test it's a coroutine function
        >>> import inspect
        >>> inspect.iscoroutinefunction(invalidate_passthrough_headers_cache)
        True
    """
    # First-Party
    from mcpgateway.utils.passthrough_headers import invalidate_passthrough_header_caches  # pylint: disable=import-outside-toplevel

    invalidate_passthrough_header_caches()
    stats = global_config_cache.stats()
    return {
        "status": "invalidated",
        "message": "Passthrough header caches invalidated successfully",
        "cache_stats": stats,
    }


@router.get("/config/passthrough-headers/cache-stats")
@require_permission("admin.system_config", allow_admin_bypass=False)
@rate_limit(requests_per_minute=30)
async def get_passthrough_headers_cache_stats(
    _user=Depends(get_current_user_with_permissions),
    _db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Get GlobalConfig cache statistics.

    Returns cache hit/miss counts, hit rate, TTL, and current cache status.
    Useful for monitoring cache effectiveness and debugging.

    Args:
        _user: Authenticated user
        _db: Database session for permission checks.

    Returns:
        Dict with cache statistics

    Examples:
        >>> # Test function exists and has correct name
        >>> from mcpgateway.admin import get_passthrough_headers_cache_stats
        >>> get_passthrough_headers_cache_stats.__name__
        'get_passthrough_headers_cache_stats'
        >>> # Test it's a coroutine function
        >>> import inspect
        >>> inspect.iscoroutinefunction(get_passthrough_headers_cache_stats)
        True
    """
    return global_config_cache.stats()


# ===================================
# A2A Stats Cache Endpoints
# ===================================


@router.post("/cache/a2a-stats/invalidate")
@require_permission("admin.system_config", allow_admin_bypass=False)
@rate_limit(requests_per_minute=10)
async def invalidate_a2a_stats_cache(
    _user=Depends(get_current_user_with_permissions),
    _db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Invalidate the A2A stats cache.

    Forces an immediate cache refresh on the next access. Use this after
    modifying A2A agents outside the normal API flow, or when you need
    changes to propagate immediately.

    Args:
        _user: Authenticated user
        _db: Database session for permission checks.

    Returns:
        Dict with invalidation status and cache statistics

    Examples:
        >>> from mcpgateway.admin import invalidate_a2a_stats_cache
        >>> invalidate_a2a_stats_cache.__name__
        'invalidate_a2a_stats_cache'
        >>> import inspect
        >>> inspect.iscoroutinefunction(invalidate_a2a_stats_cache)
        True
    """
    a2a_stats_cache.invalidate()
    stats = a2a_stats_cache.stats()
    return {
        "status": "invalidated",
        "message": "A2A stats cache invalidated successfully",
        "cache_stats": stats,
    }


@router.get("/cache/a2a-stats/stats")
@require_permission("admin.system_config", allow_admin_bypass=False)
@rate_limit(requests_per_minute=30)
async def get_a2a_stats_cache_stats(
    _user=Depends(get_current_user_with_permissions),
    _db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Get A2A stats cache statistics.

    Returns cache hit/miss counts, hit rate, TTL, and current cache status.
    Useful for monitoring cache effectiveness and debugging.

    Args:
        _user: Authenticated user
        _db: Database session for permission checks.

    Returns:
        Dict with cache statistics

    Examples:
        >>> from mcpgateway.admin import get_a2a_stats_cache_stats
        >>> get_a2a_stats_cache_stats.__name__
        'get_a2a_stats_cache_stats'
        >>> import inspect
        >>> inspect.iscoroutinefunction(get_a2a_stats_cache_stats)
        True
    """
    return a2a_stats_cache.stats()


@router.get("/config/settings")
@require_permission("admin.system_config", allow_admin_bypass=False)
async def get_configuration_settings(
    _db: Session = Depends(get_db),
    _user=Depends(get_current_user_with_permissions),
) -> Dict[str, Any]:
    """Get application configuration settings grouped by category.

    Returns configuration settings with sensitive values masked.

    Args:
        _db: Database session
        _user: Authenticated user

    Returns:
        Dict with configuration groups and their settings
    """

    def mask_sensitive(value: Any, key: str) -> Any:
        """Mask sensitive configuration values.

        Args:
            value: Configuration value to potentially mask
            key: Configuration key name to check for sensitive patterns

        Returns:
            Masked value if sensitive, original value otherwise
        """
        sensitive_keys = {"password", "secret", "key", "token", "credentials", "client_secret", "private_key", "auth_encryption_secret"}
        if any(s in key.lower() for s in sensitive_keys):
            # Handle SecretStr objects
            if isinstance(value, SecretStr):
                return settings.masked_auth_value
            if value and str(value) not in ["", "None", "null"]:
                return settings.masked_auth_value
        return value

    # Group settings by category
    config_groups = {
        "Basic Settings": {
            "app_name": settings.app_name,
            "host": settings.host,
            "port": settings.port,
            "environment": settings.environment,
            "app_domain": str(settings.app_domain),
            "protocol_version": settings.protocol_version,
        },
        "Authentication & Security": {
            "auth_required": settings.auth_required,
            "basic_auth_user": settings.basic_auth_user,
            "basic_auth_password": mask_sensitive(settings.basic_auth_password, "password"),
            "jwt_algorithm": settings.jwt_algorithm,
            "jwt_secret_key": mask_sensitive(settings.jwt_secret_key, "secret_key"),
            "jwt_audience": settings.jwt_audience,
            "jwt_issuer": settings.jwt_issuer,
            "token_expiry": settings.token_expiry,
            "require_token_expiration": settings.require_token_expiration,
            "mcp_client_auth_enabled": settings.mcp_client_auth_enabled,
            "trust_proxy_auth": settings.trust_proxy_auth,
            "skip_ssl_verify": settings.skip_ssl_verify,
        },
        "SSO Configuration": {
            "sso_enabled": settings.sso_enabled,
            "sso_github_enabled": settings.sso_github_enabled,
            "sso_google_enabled": settings.sso_google_enabled,
            "sso_ibm_verify_enabled": settings.sso_ibm_verify_enabled,
            "sso_okta_enabled": settings.sso_okta_enabled,
            "sso_keycloak_enabled": settings.sso_keycloak_enabled,
            "sso_entra_enabled": settings.sso_entra_enabled,
            "sso_generic_enabled": settings.sso_generic_enabled,
            "sso_auto_create_users": settings.sso_auto_create_users,
            "sso_preserve_admin_auth": settings.sso_preserve_admin_auth,
            "sso_require_admin_approval": settings.sso_require_admin_approval,
        },
        "Email Authentication": {
            "email_auth_enabled": settings.email_auth_enabled,
            "platform_admin_email": settings.platform_admin_email,
            "platform_admin_password": mask_sensitive(settings.platform_admin_password, "password"),
        },
        "Database & Cache": {
            "database_url": settings.database_url.replace("://", "://***@") if "@" in settings.database_url else settings.database_url,
            "cache_type": settings.cache_type,
            "redis_url": settings.redis_url.replace("://", "://***@") if settings.redis_url and "@" in settings.redis_url else settings.redis_url,
            "db_pool_size": settings.db_pool_size,
            "db_max_overflow": settings.db_max_overflow,
        },
        "Feature Flags": {
            "mcpgateway_ui_enabled": settings.mcpgateway_ui_enabled,
            "mcpgateway_admin_api_enabled": settings.mcpgateway_admin_api_enabled,
            "mcpgateway_bulk_import_enabled": settings.mcpgateway_bulk_import_enabled,
            "mcpgateway_a2a_enabled": settings.mcpgateway_a2a_enabled,
            "mcpgateway_catalog_enabled": settings.mcpgateway_catalog_enabled,
            "plugins_enabled": settings.plugins.enabled,
            "well_known_enabled": settings.well_known_enabled,
            "mcpgateway_direct_proxy_enabled": settings.mcpgateway_direct_proxy_enabled,
        },
        "Connection Timeouts": {
            "federation_timeout": settings.federation_timeout,  # Gateway/server HTTP request timeout
            "mcpgateway_direct_proxy_timeout": settings.mcpgateway_direct_proxy_timeout,
        },
        "Transport": {
            "transport_type": settings.transport_type,
            "websocket_ping_interval": settings.websocket_ping_interval,
            "sse_retry_timeout": settings.sse_retry_timeout,
            "sse_keepalive_enabled": settings.sse_keepalive_enabled,
        },
        "Logging": {
            "log_level": settings.log_level,
            "log_format": settings.log_format,
            "log_to_file": settings.log_to_file,
            "log_file": settings.log_file,
            "log_rotation_enabled": settings.log_rotation_enabled,
        },
        "Resources & Tools": {
            "tool_timeout": settings.tool_timeout,
            "tool_rate_limit": settings.tool_rate_limit,
            "tool_concurrent_limit": settings.tool_concurrent_limit,
            "resource_cache_size": settings.resource_cache_size,
            "resource_cache_ttl": settings.resource_cache_ttl,
            "max_resource_size": settings.max_resource_size,
        },
        "CORS Settings": {
            "cors_enabled": settings.cors_enabled,
            "allowed_origins": list(settings.allowed_origins),
            "cors_allow_credentials": settings.cors_allow_credentials,
        },
        "Security Headers": {
            "security_headers_enabled": settings.security_headers_enabled,
            "x_frame_options": settings.x_frame_options,
            "hsts_enabled": settings.hsts_enabled,
            "hsts_max_age": settings.hsts_max_age,
            "remove_server_headers": settings.remove_server_headers,
        },
        "Observability": {
            "otel_enable_observability": settings.otel_enable_observability,
            "otel_traces_exporter": settings.otel_traces_exporter,
            "otel_service_name": settings.otel_service_name,
        },
        "Development": {
            "dev_mode": settings.dev_mode,
            "reload": settings.reload,
            "debug": settings.debug,
        },
    }

    return {
        "groups": config_groups,
        "security_status": settings.get_security_status(),
    }
