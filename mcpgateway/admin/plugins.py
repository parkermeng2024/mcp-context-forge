# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/admin/plugins.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Admin UI plugin routes: plugin marketplace listing, statistics, detail, and
global/per-plugin mode toggles, plus A2A agent plugin bindings.
"""

# Standard
import html
import json
import logging
from typing import Optional
import uuid

# Third-Party
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

# First-Party
from mcpgateway.admin.common import get_user_id
from mcpgateway.admin.security import enforce_admin_csrf
from mcpgateway.auth_context import get_user_email
from mcpgateway.db import A2AAgent as DbA2AAgent, EmailTeam, get_db
from mcpgateway.middleware.rbac import get_current_user_with_permissions, require_permission
from mcpgateway.schemas import PluginDetail, PluginListResponse, PluginModeUpdateRequest, PluginModeUpdateResponse, PluginStatsResponse, PluginToggleRequest, PluginToggleResponse
from mcpgateway.services.a2a_agent_plugin_binding_service import A2AAgentPluginBindingForbiddenError, A2AAgentPluginBindingNotFoundError, A2AAgentPluginBindingService
from mcpgateway.services.audit_trail_service import get_audit_trail_service
from mcpgateway.services.plugin_service import get_plugin_service, sync_plugin_service_from_runtime
from mcpgateway.services.structured_logger import get_structured_logger
from mcpgateway.utils.paths import resolve_root_path as _resolve_root_path

LOGGER: logging.Logger = logging.getLogger("mcpgateway.admin")

# mcpgateway.admin (__init__) appends this router's routes to admin_router, so the
# prefix, tags, and CSRF dependency must mirror admin_router exactly.
router = APIRouter(
    prefix="/admin",
    tags=["Admin UI"],
    dependencies=[Depends(enforce_admin_csrf)],
)


####################
# Plugin Routes    #
####################


@router.get("/plugins/partial")
@require_permission("admin.plugins", allow_admin_bypass=False)
async def get_plugins_partial(request: Request, db: Session = Depends(get_db), user=Depends(get_current_user_with_permissions)) -> HTMLResponse:  # pylint: disable=unused-argument
    """Render the plugins partial HTML template.

    This endpoint returns a rendered HTML partial containing plugin information,
    similar to the version_info_partial pattern. It's designed to be loaded via HTMX
    into the admin interface.

    Args:
        request: FastAPI request object
        db: Database session
        user: Authenticated user

    Returns:
        HTMLResponse with rendered plugins partial template
    """
    LOGGER.debug(f"User {get_user_email(user)} requested plugins partial")

    try:
        # Get plugin service and check if plugins are enabled
        plugin_service = get_plugin_service()

        # Self-heal the cache so the partial reflects the live shared toggle.
        await sync_plugin_service_from_runtime(request, plugin_service)

        # Get plugin data
        plugins = plugin_service.get_all_plugins()
        stats = await plugin_service.get_plugin_statistics()

        # Prepare context for template
        context = {"request": request, "plugins": plugins, "stats": stats, "plugins_enabled": plugin_service.get_plugin_manager() is not None, "root_path": _resolve_root_path(request)}

        # Render the partial template
        return request.app.state.templates.TemplateResponse(request, "plugins_partial.html", context)

    except Exception as e:
        LOGGER.error(f"Error rendering plugins partial: {e}")
        # Return error HTML that can be displayed in the UI
        error_html = f"""
        <div class="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded">
            <strong class="font-bold">Error loading plugins:</strong>
            <span class="block sm:inline">{html.escape(str(e))}</span>
        </div>
        """
        return HTMLResponse(content=error_html, status_code=500)


@router.get("/a2a/plugin-bindings/partial")
@require_permission("admin.plugins", allow_admin_bypass=False)
async def get_a2a_plugin_bindings_partial(
    request: Request,
    team_id: Optional[str] = None,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> HTMLResponse:
    """Render the A2A agent plugin bindings partial HTML template.

    This endpoint returns a rendered HTML partial containing A2A agent plugin
    bindings, designed to be loaded via HTMX into the admin interface.

    Args:
        request: FastAPI request object.
        team_id: Optional team ID to filter bindings.
        db: Database session.
        user: Authenticated user.

    Returns:
        HTMLResponse with rendered partial template.
    """
    LOGGER.debug(f"User {get_user_email(user)} requested A2A plugin bindings partial")

    try:
        return await _render_a2a_plugin_bindings_partial(request, db, team_id=team_id)

    except Exception as e:
        LOGGER.error(f"Error rendering A2A plugin bindings partial: {e}")
        error_html = f"""
        <div class="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded">
            <strong class="font-bold">Error loading A2A plugin bindings:</strong>
            <span class="block sm:inline">{html.escape(str(e))}</span>
        </div>
        """
        return HTMLResponse(content=error_html, status_code=500)


async def _render_a2a_plugin_bindings_partial(request: Request, db: Session, team_id: Optional[str] = None) -> HTMLResponse:
    """Build and return the A2A agent plugin bindings partial template."""
    plugin_service = get_plugin_service()
    await sync_plugin_service_from_runtime(request, plugin_service)
    binding_service = A2AAgentPluginBindingService()
    bindings, _ = binding_service.list_bindings(db, team_id=team_id)
    agents = db.query(DbA2AAgent.name).distinct().order_by(DbA2AAgent.name).all()
    agent_names = [a[0] for a in agents]
    plugin_ids = [p["name"] for p in plugin_service.get_all_plugins()]
    teams = db.execute(select(EmailTeam.id, EmailTeam.name).where(EmailTeam.is_active.is_(True))).all()
    context = {
        "request": request,
        "bindings": bindings,
        "agent_names": agent_names,
        "plugin_ids": plugin_ids,
        "teams": teams,
        "selected_team_id": team_id,
        "root_path": _resolve_root_path(request),
    }
    return request.app.state.templates.TemplateResponse(request, "a2a_agent_plugin_bindings_partial.html", context)


@router.post("/a2a/plugin-bindings")
@require_permission("admin.plugins", allow_admin_bypass=False)
async def admin_create_a2a_plugin_binding(
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> HTMLResponse:
    """Create an A2A agent plugin binding from the admin UI.

    Returns the refreshed partial on success or an error HTML fragment.
    """
    try:
        form = await request.form()
        team_id = form.get("team_id", "")
        agent_name = form.get("agent_name", "")
        plugin_id = form.get("plugin_id", "")
        mode = form.get("mode", "enforce")
        try:
            priority = int(form.get("priority", 50))
        except (ValueError, TypeError):
            return HTMLResponse(
                content='<div class="bg-red-50 p-4 rounded text-red-700">Invalid priority value; must be an integer</div>',
                status_code=400,
            )
        on_error = form.get("on_error") or None
        config_raw = form.get("config", "{}")

        try:
            config = json.loads(config_raw)
        except (json.JSONDecodeError, TypeError):
            return HTMLResponse(
                content=f'<div class="bg-red-50 p-4 rounded text-red-700">Invalid JSON in config: {html.escape(config_raw)}</div>',
                status_code=400,
            )

        if not team_id or not agent_name or not plugin_id:
            return HTMLResponse(
                content='<div class="bg-red-50 p-4 rounded text-red-700">team_id, agent_name, and plugin_id are required</div>',
                status_code=400,
            )

        if mode not in {"enforce", "report", "disabled"}:
            return HTMLResponse(
                content=f'<div class="bg-red-50 p-4 rounded text-red-700">Invalid mode: {html.escape(mode)}</div>',
                status_code=400,
            )
        if on_error not in {"fail", "ignore", "disable", None}:
            return HTMLResponse(
                content=f'<div class="bg-red-50 p-4 rounded text-red-700">Invalid on_error: {html.escape(on_error)}</div>',
                status_code=400,
            )

        caller_email = get_user_email(user)
        service = A2AAgentPluginBindingService()
        service.upsert_binding(
            db=db,
            team_id=team_id,
            agent_name=agent_name,
            plugin_id=plugin_id,
            mode=mode,
            priority=priority,
            config=config,
            on_error=on_error,
            caller_email=caller_email,
        )
        db.commit()

    except Exception as e:
        LOGGER.error(f"Error creating A2A plugin binding: {e}")
        return HTMLResponse(
            content=f'<div class="bg-red-50 p-4 rounded text-red-700">Error: {html.escape(str(e))}</div>',
            status_code=500,
        )

    return await _render_a2a_plugin_bindings_partial(request, db)


@router.post("/a2a/plugin-bindings/{binding_id}/delete")
@require_permission("admin.plugins", allow_admin_bypass=False)
async def admin_delete_a2a_plugin_binding(
    request: Request,
    binding_id: str,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> HTMLResponse:
    """Delete an A2A agent plugin binding from the admin UI.

    POST endpoint (HTMX-compatible) that deletes a binding and returns
    the refreshed partial.
    """
    try:
        # Validate that binding_id is a valid UUID
        try:
            uuid.UUID(binding_id)
        except ValueError:
            return HTMLResponse(
                content=f'<div class="bg-red-50 p-4 rounded text-red-700">Invalid binding ID format: {html.escape(binding_id)}</div>',
                status_code=400,
            )

        # Derive team-scoped access from the authenticated user
        is_admin = user.get("is_admin", False)
        token_teams = user.get("token_teams")
        allowed_teams = None if (is_admin and token_teams is None) else set(token_teams or [])

        service = A2AAgentPluginBindingService()
        service.delete_binding(db, binding_id, allowed_teams=allowed_teams)
        db.commit()

    except A2AAgentPluginBindingNotFoundError as e:
        return HTMLResponse(
            content=f'<div class="bg-red-50 p-4 rounded text-red-700">Not found: {html.escape(str(e))}</div>',
            status_code=404,
        )
    except A2AAgentPluginBindingForbiddenError as e:
        return HTMLResponse(
            content=f'<div class="bg-red-50 p-4 rounded text-red-700">Forbidden: {html.escape(str(e))}</div>',
            status_code=403,
        )
    except Exception as e:
        LOGGER.error(f"Error deleting A2A plugin binding {binding_id}: {e}")
        return HTMLResponse(
            content=f'<div class="bg-red-50 p-4 rounded text-red-700">Error: {html.escape(str(e))}</div>',
            status_code=500,
        )

    return await _render_a2a_plugin_bindings_partial(request, db)


@router.get("/plugins", response_model=PluginListResponse)
@require_permission("admin.plugins", allow_admin_bypass=False)
async def list_plugins(
    request: Request,
    search: Optional[str] = None,
    mode: Optional[str] = None,
    hook: Optional[str] = None,
    tag: Optional[str] = None,
    db: Session = Depends(get_db),  # pylint: disable=unused-argument
    user=Depends(get_current_user_with_permissions),
) -> PluginListResponse:
    """Get list of all plugins with optional filtering.

    Args:
        request: FastAPI request object
        search: Optional text search in name/description/author
        mode: Optional filter by mode (enforce/permissive/disabled)
        hook: Optional filter by hook type
        tag: Optional filter by tag
        db: Database session
        user: Authenticated user

    Returns:
        PluginListResponse with list of plugins and statistics

    Raises:
        HTTPException: If there's an error retrieving plugins
    """
    LOGGER.debug(f"User {get_user_email(user)} requested plugin list")
    structured_logger = get_structured_logger()

    try:
        # Get plugin service
        plugin_service = get_plugin_service()

        # Self-heal the cache from the live framework state.
        await sync_plugin_service_from_runtime(request, plugin_service)

        # Get filtered plugins
        if any([search, mode, hook, tag]):
            plugins = plugin_service.search_plugins(query=search, mode=mode, hook=hook, tag=tag)
        else:
            plugins = plugin_service.get_all_plugins()

        # Count enabled/disabled
        enabled_count = sum(1 for p in plugins if p["status"] == "enabled")
        disabled_count = sum(1 for p in plugins if p["status"] == "disabled")

        # Log plugin marketplace browsing activity
        structured_logger.info(
            "User browsed plugin marketplace",
            user_id=get_user_id(user),
            user_email=get_user_email(user),
            component="plugin_marketplace",
            category="business_logic",
            resource_type="plugin_list",
            resource_action="browse",
            custom_fields={
                "search_query": search,
                "filter_mode": mode,
                "filter_hook": hook,
                "filter_tag": tag,
                "results_count": len(plugins),
                "enabled_count": enabled_count,
                "disabled_count": disabled_count,
                "has_filters": any([search, mode, hook, tag]),
            },
        )

        # First-Party
        from mcpgateway.plugins import are_plugins_enabled_shared  # pylint: disable=import-outside-toplevel

        return PluginListResponse(plugins_globally_enabled=await are_plugins_enabled_shared(), plugins=plugins, total=len(plugins), enabled_count=enabled_count, disabled_count=disabled_count)

    except Exception as e:
        LOGGER.error(f"Error listing plugins: {e}")
        structured_logger.error("Failed to list plugins in marketplace", user_id=get_user_id(user), user_email=get_user_email(user), error=e, component="plugin_marketplace", category="business_logic")
        raise HTTPException(status_code=500, detail="Failed to list plugins")


@router.put("/plugins", response_model=PluginToggleResponse)
@require_permission("admin.plugins", allow_admin_bypass=False)
async def toggle_plugins_global(
    payload: PluginToggleRequest,
    request: Request,
    user=Depends(get_current_user_with_permissions),
) -> PluginToggleResponse:
    """Enable or disable the plugin subsystem globally and broadcast the change."""
    # pylint: disable=import-outside-toplevel
    # First-Party
    from mcpgateway.plugins import are_plugins_enabled_shared, enable_plugins_shared, get_plugin_manager

    redis_persisted = await enable_plugins_shared(payload.enabled)

    # Sync the admin-side cache so ``GET /admin/plugins`` and
    # ``GET /admin/plugins/{name}`` reflect the toggle on a process that
    # started with plugins disabled (``app.state.plugin_manager`` stayed unset
    # and ``PluginService`` was never wired). Without this, enabling plugins
    # at runtime leaves the admin surfaces reading stale/empty metadata until
    # the next restart; disabling likewise keeps the old manager visible.
    #
    # Treat the sync as best-effort: the shared toggle above already committed,
    # so an exception here (e.g. factory build failure on a degraded node) must
    # not turn into a 500 for a toggle that actually took effect. The admin
    # surfaces will self-correct on the next request that re-reads the manager.
    try:
        plugin_service = get_plugin_service()
        if payload.enabled:
            plugin_manager = await get_plugin_manager()
            if plugin_manager is not None:
                plugin_service.set_plugin_manager(plugin_manager)
                request.app.state.plugin_manager = plugin_manager
        else:
            plugin_service.set_plugin_manager(None)
            request.app.state.plugin_manager = None
    except Exception as sync_exc:
        LOGGER.warning(
            "Plugin global toggle applied (enabled=%s) but admin-cache sync failed (%s) — admin views will refresh on next request",
            payload.enabled,
            sync_exc,
        )

    LOGGER.info(f"Plugins globally {'enabled' if payload.enabled else 'disabled'} by {get_user_email(user)}")
    structured_logger = get_structured_logger()
    structured_logger.info(
        f"Plugin subsystem globally {'enabled' if payload.enabled else 'disabled'}",
        user_id=get_user_id(user),
        user_email=get_user_email(user),
        component="plugin_runtime",
        category="security",
        resource_type="plugin_global_toggle",
        resource_action="update",
        custom_fields={"enabled": payload.enabled, "redis_persisted": redis_persisted},
    )

    return PluginToggleResponse(plugins_enabled=await are_plugins_enabled_shared(), redis_persisted=redis_persisted)


@router.get("/plugins/stats", response_model=PluginStatsResponse)
@require_permission("admin.plugins", allow_admin_bypass=False)
async def get_plugin_stats(request: Request, db: Session = Depends(get_db), user=Depends(get_current_user_with_permissions)) -> PluginStatsResponse:  # pylint: disable=unused-argument
    """Get plugin statistics.

    Args:
        request: FastAPI request object
        db: Database session
        user: Authenticated user

    Returns:
        PluginStatsResponse with aggregated plugin statistics

    Raises:
        HTTPException: If there's an error getting plugin statistics
    """
    LOGGER.debug(f"User {get_user_email(user)} requested plugin statistics")
    structured_logger = get_structured_logger()

    try:
        # Get plugin service
        plugin_service = get_plugin_service()

        # Self-heal the cache from the live framework state.
        await sync_plugin_service_from_runtime(request, plugin_service)

        # Get statistics
        stats = await plugin_service.get_plugin_statistics()

        # Log marketplace analytics access
        structured_logger.info(
            "User accessed plugin marketplace statistics",
            user_id=get_user_id(user),
            user_email=get_user_email(user),
            component="plugin_marketplace",
            category="business_logic",
            resource_type="plugin_stats",
            resource_action="view",
            custom_fields={
                "total_plugins": stats.get("total_plugins", 0),
                "enabled_plugins": stats.get("enabled_plugins", 0),
                "disabled_plugins": stats.get("disabled_plugins", 0),
                "hooks_count": len(stats.get("plugins_by_hook", {})),
                "tags_count": len(stats.get("plugins_by_tag", {})),
                "authors_count": len(stats.get("plugins_by_author", {})),
            },
        )

        return PluginStatsResponse(**stats)

    except Exception as e:
        LOGGER.error(f"Error getting plugin statistics: {e}")
        structured_logger.error(
            "Failed to get plugin marketplace statistics", user_id=get_user_id(user), user_email=get_user_email(user), error=e, component="plugin_marketplace", category="business_logic"
        )
        raise HTTPException(status_code=500, detail="Failed to retrieve plugin statistics")


@router.get("/plugins/{name}", response_model=PluginDetail)
@require_permission("admin.plugins", allow_admin_bypass=False)
async def get_plugin_details(name: str, request: Request, db: Session = Depends(get_db), user=Depends(get_current_user_with_permissions)) -> PluginDetail:  # pylint: disable=unused-argument
    """Get detailed information about a specific plugin.

    Args:
        name: Plugin name
        request: FastAPI request object
        db: Database session
        user: Authenticated user

    Returns:
        PluginDetail with full plugin information

    Raises:
        HTTPException: If plugin not found
    """
    LOGGER.debug(f"User {get_user_email(user)} requested details for plugin {name}")
    structured_logger = get_structured_logger()
    audit_service = get_audit_trail_service()

    try:
        # Get plugin service
        plugin_service = get_plugin_service()

        # Self-heal the cache from the live framework state.
        await sync_plugin_service_from_runtime(request, plugin_service)

        # Get plugin details
        plugin = plugin_service.get_plugin_by_name(name)

        if not plugin:
            structured_logger.warning(
                f"Plugin '{name}' not found in marketplace",
                user_id=get_user_id(user),
                user_email=get_user_email(user),
                component="plugin_marketplace",
                category="business_logic",
                custom_fields={"plugin_name": name, "action": "view_details"},
            )
            raise HTTPException(status_code=404, detail=f"Plugin '{name}' not found")

        # Log plugin view activity
        structured_logger.info(
            f"User viewed plugin details: '{name}'",
            user_id=get_user_id(user),
            user_email=get_user_email(user),
            component="plugin_marketplace",
            category="business_logic",
            resource_type="plugin",
            resource_id=name,
            resource_action="view_details",
            custom_fields={
                "plugin_name": name,
                "plugin_version": plugin.get("version"),
                "plugin_author": plugin.get("author"),
                "plugin_status": plugin.get("status"),
                "plugin_mode": plugin.get("mode"),
                "plugin_hooks": plugin.get("hooks", []),
                "plugin_tags": plugin.get("tags", []),
            },
        )

        # Create audit trail for plugin access
        audit_service.log_audit(
            user_id=get_user_id(user), user_email=get_user_email(user), resource_type="plugin", resource_id=name, action="view", description=f"Viewed plugin '{name}' details in marketplace"
        )

        return PluginDetail(**plugin)

    except HTTPException:
        raise
    except Exception as e:
        LOGGER.error(f"Error getting plugin details: {e}")
        structured_logger.error(
            f"Failed to get plugin details: '{name}'", user_id=get_user_id(user), user_email=get_user_email(user), error=e, component="plugin_marketplace", category="business_logic"
        )
        raise HTTPException(status_code=500, detail="Failed to retrieve plugin details")


@router.put("/plugins/{name}", response_model=PluginModeUpdateResponse)
@require_permission("admin.plugins", allow_admin_bypass=False)
async def update_plugin_mode(
    name: str,
    payload: PluginModeUpdateRequest,
    _db: Session = Depends(get_db),  # required by rbac decorator's session lookup
    user=Depends(get_current_user_with_permissions),
) -> PluginModeUpdateResponse:
    """Persist a per-plugin mode override in Redis and invalidate cached managers."""
    # pylint: disable=import-outside-toplevel
    # First-Party
    from mcpgateway.plugins import invalidate_all_plugin_managers, list_configured_plugin_names, publish_plugin_mode_change

    mode = payload.mode

    # Validate against the *configured* plugin set, not the live manager. On a
    # process that booted with plugins globally disabled, no manager is wired
    # and ``PluginService.get_all_plugins()`` returns ``[]``; without this the
    # handler 404s for every valid name and blocks operators from pre-staging
    # a per-plugin mode before turning the subsystem on.
    plugin_names = list_configured_plugin_names()
    if name not in plugin_names:
        raise HTTPException(status_code=404, detail=f"Plugin '{name}' not found. Available: {', '.join(plugin_names[:10])}")

    # publish_plugin_mode_change always updates the in-process override map
    # (so single-node-no-Redis deployments still work) and additionally
    # attempts a Redis SET + publish. The Redis outcome is surfaced back to
    # the caller as redis_persisted so they know whether the change reached
    # other workers.
    redis_persisted = await publish_plugin_mode_change(name, mode)
    # The override is already stored (in-process map and/or Redis) by the line
    # above. Treat the cache sweep as best-effort — if it raises, a background
    # TTL refresh still reaches the new mode, and the operator must not see a
    # 500 for an override that actually took effect.
    try:
        await invalidate_all_plugin_managers()
    except Exception as invalidate_exc:
        LOGGER.warning(
            "Plugin '%s' mode override stored but cache invalidation failed (%s) — fresh managers will rebuild on next TTL expiry",
            name,
            invalidate_exc,
        )

    if redis_persisted:
        LOGGER.info(f"Plugin '{name}' mode changed to '{mode}' by {get_user_email(user)} (Redis persisted, 24h TTL)")
    else:
        LOGGER.warning(f"Plugin '{name}' mode changed to '{mode}' by {get_user_email(user)} (this worker only — Redis unavailable)")

    structured_logger = get_structured_logger()
    structured_logger.info(
        f"Plugin '{name}' mode changed to '{mode}'",
        user_id=get_user_id(user),
        user_email=get_user_email(user),
        component="plugin_runtime",
        category="security",
        resource_type="plugin_mode",
        resource_id=name,
        resource_action="update",
        custom_fields={"plugin_name": name, "new_mode": mode, "redis_persisted": redis_persisted},
    )

    return PluginModeUpdateResponse(plugin=name, mode=mode, redis_persisted=redis_persisted)
