# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/admin/performance.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Admin UI performance monitoring routes: aggregate performance stats, system,
worker, request, cache, and history views.
"""

# Standard
from datetime import datetime, timedelta, timezone
import logging

# Third-Party
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, ORJSONResponse
from sqlalchemy.orm import Session

# First-Party
from mcpgateway.admin.security import enforce_admin_csrf
from mcpgateway.common.query_params import QueryPeriodType
from mcpgateway.config import settings
from mcpgateway.db import get_db
from mcpgateway.middleware.rbac import get_current_user_with_permissions, require_permission
from mcpgateway.services.performance_service import get_performance_service
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
# Performance Monitoring Endpoints
# ===================================


@router.get("/performance/stats", response_class=HTMLResponse)
@require_permission("admin.system_config", allow_admin_bypass=False)
async def get_performance_stats(
    request: Request,
    db: Session = Depends(get_db),
    _user=Depends(get_current_user_with_permissions),
):
    """Get comprehensive performance metrics for the dashboard.

    Returns either an HTML partial for HTMX requests or JSON for API requests.
    Includes system metrics, request metrics, worker status, and cache stats.

    Args:
        request: FastAPI request object
        db: Database session dependency
        _user: Authenticated user (required by dependency)

    Returns:
        HTMLResponse or JSONResponse: Performance dashboard data

    Raises:
        HTTPException: 404 if performance tracking is disabled, 500 on retrieval error
    """
    if not settings.mcpgateway_performance_tracking:
        if request.headers.get("hx-request"):
            return HTMLResponse(content='<div class="text-center py-8 text-gray-500">Performance tracking is disabled. Enable with MCPGATEWAY_PERFORMANCE_TRACKING=true</div>')
        raise HTTPException(status_code=404, detail="Performance monitoring is disabled")

    try:
        service = get_performance_service(db)
        dashboard = await service.get_dashboard()

        # Convert to dict for template
        dashboard_data = dashboard.model_dump()

        # Format datetime fields for display
        if dashboard_data.get("timestamp"):
            dashboard_data["timestamp"] = dashboard_data["timestamp"].isoformat()
        if dashboard_data.get("system", {}).get("boot_time"):
            dashboard_data["system"]["boot_time"] = dashboard_data["system"]["boot_time"].isoformat()
        for worker in dashboard_data.get("workers", []):
            if worker.get("create_time"):
                worker["create_time"] = worker["create_time"].isoformat()

        if request.headers.get("hx-request"):
            root_path = _resolve_root_path(request)
            return request.app.state.templates.TemplateResponse(
                request,
                "performance_partial.html",
                {
                    "request": request,
                    "dashboard": dashboard_data,
                    "root_path": root_path,
                },
            )

        return ORJSONResponse(content=dashboard_data)

    except Exception as e:
        LOGGER.error(f"Performance metrics retrieval failed: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to retrieve performance metrics")


@router.get("/performance/system")
@require_permission("admin.system_config", allow_admin_bypass=False)
async def get_performance_system(
    db: Session = Depends(get_db),
    _user=Depends(get_current_user_with_permissions),
):
    """Get current system resource metrics.

    Args:
        db: Database session dependency
        _user: Authenticated user (required by dependency)

    Returns:
        JSONResponse: System metrics (CPU, memory, disk, network)

    Raises:
        HTTPException: 404 if performance tracking is disabled
    """
    if not settings.mcpgateway_performance_tracking:
        raise HTTPException(status_code=404, detail="Performance tracking is disabled")

    service = get_performance_service(db)
    metrics = service.get_system_metrics()
    return metrics.model_dump()


@router.get("/performance/workers")
@require_permission("admin.system_config", allow_admin_bypass=False)
async def get_performance_workers(
    db: Session = Depends(get_db),
    _user=Depends(get_current_user_with_permissions),
):
    """Get metrics for all worker processes.

    Args:
        db: Database session dependency
        _user: Authenticated user (required by dependency)

    Returns:
        JSONResponse: List of worker metrics

    Raises:
        HTTPException: 404 if performance tracking is disabled
    """
    if not settings.mcpgateway_performance_tracking:
        raise HTTPException(status_code=404, detail="Performance tracking is disabled")

    service = get_performance_service(db)
    workers = service.get_worker_metrics()
    return [w.model_dump() for w in workers]


@router.get("/performance/requests")
@require_permission("admin.system_config", allow_admin_bypass=False)
async def get_performance_requests(
    db: Session = Depends(get_db),
    _user=Depends(get_current_user_with_permissions),
):
    """Get HTTP request performance metrics.

    Args:
        db: Database session dependency
        _user: Authenticated user (required by dependency)

    Returns:
        JSONResponse: Request metrics from Prometheus

    Raises:
        HTTPException: 404 if performance tracking is disabled
    """
    if not settings.mcpgateway_performance_tracking:
        raise HTTPException(status_code=404, detail="Performance tracking is disabled")

    service = get_performance_service(db)
    metrics = service.get_request_metrics()
    return metrics.model_dump()


@router.get("/performance/cache")
@require_permission("admin.system_config", allow_admin_bypass=False)
async def get_performance_cache(
    db: Session = Depends(get_db),
    _user=Depends(get_current_user_with_permissions),
):
    """Get Redis cache metrics.

    Args:
        db: Database session dependency
        _user: Authenticated user (required by dependency)

    Returns:
        JSONResponse: Redis cache metrics

    Raises:
        HTTPException: 404 if performance tracking is disabled
    """
    if not settings.mcpgateway_performance_tracking:
        raise HTTPException(status_code=404, detail="Performance tracking is disabled")

    service = get_performance_service(db)
    metrics = await service.get_cache_metrics()
    return metrics.model_dump()


@router.get("/performance/history")
@require_permission("admin.system_config", allow_admin_bypass=False)
async def get_performance_history(
    period_type: QueryPeriodType = "hourly",
    hours: int = Query(24, ge=1, le=168, description="Number of hours to look back"),
    db: Session = Depends(get_db),
    _user=Depends(get_current_user_with_permissions),
):
    """Get historical performance aggregates.

    Args:
        period_type: Aggregation type (hourly, daily)
        hours: Hours of history to retrieve
        db: Database session dependency
        _user: Authenticated user (required by dependency)

    Returns:
        JSONResponse: Historical performance aggregates

    Raises:
        HTTPException: 404 if performance tracking is disabled
    """
    if not settings.mcpgateway_performance_tracking:
        raise HTTPException(status_code=404, detail="Performance tracking is disabled")

    service = get_performance_service(db)
    start_time = datetime.now(timezone.utc) - timedelta(hours=hours)

    history = await service.get_history(
        db=db,
        period_type=period_type,
        start_time=start_time,
    )

    return history.model_dump()
