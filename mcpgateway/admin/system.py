# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/admin/system.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Admin UI platform operations routes: system statistics, the support bundle,
and the maintenance partial.
"""

# Standard
from datetime import datetime
import logging
from pathlib import Path
import tempfile

# Third-Party
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, ORJSONResponse
from sqlalchemy.orm import Session
from starlette.background import BackgroundTask

# First-Party
from mcpgateway.admin.security import enforce_admin_csrf
from mcpgateway.config import settings
from mcpgateway.db import get_db
from mcpgateway.middleware.rbac import get_current_user_with_permissions, require_permission
from mcpgateway.utils.paths import resolve_root_path as _resolve_root_path

LOGGER: logging.Logger = logging.getLogger("mcpgateway.admin")

# mcpgateway.admin (__init__) appends this router's routes to admin_router, so the
# prefix, tags, and CSRF dependency must mirror admin_router exactly.
router = APIRouter(
    prefix="/admin",
    tags=["Admin UI"],
    dependencies=[Depends(enforce_admin_csrf)],
)


# ===================================
# System Metrics Endpoints
# ===================================


@router.get("/system/stats")
@require_permission("admin.system_config", allow_admin_bypass=False)
async def get_system_stats(
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    """Get comprehensive system metrics for administrators.

    Returns detailed counts across all entity types including users, teams,
    MCP resources (servers, tools, resources, prompts, A2A agents, gateways),
    API tokens, sessions, metrics, security events, and workflow state.

    Designed for capacity planning, performance optimization, and demonstrating
    system capabilities to administrators.

    Args:
        request: FastAPI request object
        db: Database session dependency
        user: Authenticated user from dependency (must have admin access)

    Returns:
        HTMLResponse or JSONResponse: Comprehensive system metrics
        Returns HTML partial when requested via HTMX, JSON otherwise

    Raises:
        HTTPException: If metrics collection fails

    Examples:
        >>> # Request system metrics via API
        >>> # GET /admin/system/stats
        >>> # Returns JSON with users, teams, mcp_resources, tokens, sessions, metrics, security, workflow
    """
    try:
        LOGGER.info(f"System metrics requested by user: {user}")

        # First-Party
        from mcpgateway.services.system_stats_service import SystemStatsService  # pylint: disable=import-outside-toplevel

        # Get metrics (using cached version for performance)
        service = SystemStatsService()
        stats = await service.get_comprehensive_stats_cached(db)

        LOGGER.info(f"System metrics retrieved successfully for user {user}")

        # Check if this is an HTMX request for HTML partial
        if request.headers.get("hx-request"):
            # Return HTML partial for HTMX
            return request.app.state.templates.TemplateResponse(
                request,
                "metrics_partial.html",
                {
                    "request": request,
                    "stats": stats,
                    "root_path": _resolve_root_path(request),
                    "db_metrics_recording_enabled": settings.db_metrics_recording_enabled,
                },
            )

        # Return JSON for API requests
        return ORJSONResponse(content=stats)

    except Exception as e:
        LOGGER.error(f"System metrics retrieval failed for user {user}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to retrieve system metrics")


# ===================================
# Support Bundle Endpoints
# ===================================


@router.get("/support-bundle/generate")
@require_permission("admin.system_config", allow_admin_bypass=False)
async def admin_generate_support_bundle(
    log_lines: int = Query(default=1000, description="Number of log lines to include"),
    include_logs: bool = Query(default=True, description="Include log files"),
    include_env: bool = Query(default=True, description="Include environment config"),
    include_system: bool = Query(default=True, description="Include system info"),
    user=Depends(get_current_user_with_permissions),
    _db: Session = Depends(get_db),
):
    """
    Generate and download a support bundle with sanitized diagnostics.

    Creates a ZIP file containing version info, system diagnostics, configuration,
    and logs with automatic sanitization of sensitive data (passwords, tokens, secrets).

    Args:
        log_lines: Number of log lines to include (default: 1000, 0 = all)
        include_logs: Include log files in bundle (default: True)
        include_env: Include environment configuration (default: True)
        include_system: Include system diagnostics (default: True)
        user: Authenticated user from dependency
        _db: Database session for permission checks.

    Returns:
        Response: ZIP file download with support bundle

    Raises:
        HTTPException: If bundle generation fails

    Examples:
        >>> # Request support bundle via API
        >>> # GET /admin/support-bundle/generate?log_lines=500
        >>> # Returns: mcpgateway-support-YYYY-MM-DD-HHMMSS.zip
    """
    try:
        LOGGER.info(f"Support bundle generation requested by user: {user}")

        # First-Party
        from mcpgateway.services.support_bundle_service import SupportBundleConfig, SupportBundleService  # pylint: disable=import-outside-toplevel

        # Create configuration
        config = SupportBundleConfig(
            include_logs=include_logs,
            include_env=include_env,
            include_system_info=include_system,
            log_tail_lines=log_lines,
            output_dir=Path(tempfile.gettempdir()),
        )

        # Generate bundle
        service = SupportBundleService()
        bundle_path = service.generate_bundle(config)

        # Return as downloadable file using FileResponse (streams asynchronously)
        timestamp = datetime.now().strftime("%Y-%m-%d-%H%M%S")
        filename = f"mcpgateway-support-{timestamp}.zip"

        # Pre-stat for Content-Length header and logging
        bundle_stat = bundle_path.stat()
        LOGGER.info(f"Support bundle generated successfully for user {user}: {filename} ({bundle_stat.st_size} bytes)")

        # Use BackgroundTask to clean up temp file after response is sent
        return FileResponse(
            path=bundle_path,
            media_type="application/zip",
            filename=filename,
            stat_result=bundle_stat,
            background=BackgroundTask(lambda: bundle_path.unlink(missing_ok=True)),
        )

    except Exception as e:
        LOGGER.error(f"Support bundle generation failed for user {user}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to generate support bundle")


# ============================================================================
# Maintenance Routes (Platform Admin Only)
# ============================================================================


@router.get("/maintenance/partial", response_class=HTMLResponse)
@require_permission("admin.system_config", allow_admin_bypass=False)
async def get_maintenance_partial(
    request: Request,
    _user=Depends(get_current_user_with_permissions),
    _db: Session = Depends(get_db),
):
    """Render the maintenance dashboard partial (platform admin only).

    This endpoint returns the maintenance UI panel which includes:
    - Metrics cleanup controls
    - Metrics rollup controls
    - System health status

    Only platform administrators can access this endpoint.

    Args:
        request: FastAPI request object
        _user: Authenticated user with admin permissions
        _db: Database session for permission checks.

    Returns:
        HTMLResponse: Rendered maintenance dashboard template

    Raises:
        HTTPException: 403 if user is not a platform admin
    """
    root_path = _resolve_root_path(request)

    # Build payload with settings for the template
    payload = {
        "settings": {
            "metrics_cleanup_enabled": getattr(settings, "metrics_cleanup_enabled", False),
            "metrics_rollup_enabled": getattr(settings, "metrics_rollup_enabled", False),
            "metrics_retention_days": getattr(settings, "metrics_retention_days", 30),
        }
    }

    return request.app.state.templates.TemplateResponse(
        request,
        "maintenance_partial.html",
        {"request": request, "payload": payload, "root_path": root_path},
    )
