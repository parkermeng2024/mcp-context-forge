# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/admin/metrics.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Admin UI metrics routes: aggregated per-entity metrics, the metrics partial,
and the metrics reset action.
"""

# Standard
import logging
import math
from typing import Any, Dict, Union

# Third-Party
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

# First-Party
from mcpgateway.admin.common import prompt_service, resource_service, server_service, tool_service
from mcpgateway.admin.security import enforce_admin_csrf
from mcpgateway.auth_context import get_user_email
from mcpgateway.common.query_params import QueryEntityType
from mcpgateway.config import settings
from mcpgateway.db import get_db
from mcpgateway.middleware.rbac import get_current_user_with_permissions, require_permission
from mcpgateway.schemas import PaginationMeta, PromptMetrics, ResourceMetrics, ServerMetrics, ToolMetrics
from mcpgateway.utils.paths import resolve_root_path as _resolve_root_path

LOGGER: logging.Logger = logging.getLogger("mcpgateway.admin")

# mcpgateway.admin (__init__) appends this router's routes to admin_router, so the
# prefix, tags, and CSRF dependency must mirror admin_router exactly.
router = APIRouter(
    prefix="/admin",
    tags=["Admin UI"],
    dependencies=[Depends(enforce_admin_csrf)],
)


# Metrics
MetricsDict = Dict[str, Union[ToolMetrics, ResourceMetrics, ServerMetrics, PromptMetrics]]


# @router.get("/metrics", response_model=MetricsDict)
# async def admin_get_metrics(
#     db: Session = Depends(get_db),
#     user=Depends(get_current_user_with_permissions),
# ) -> MetricsDict:
#     """
#     Retrieve aggregate metrics for all entity types via the admin UI.

#     This endpoint collects and returns usage metrics for tools, resources, servers,
#     and prompts. The metrics are retrieved by calling the aggregate_metrics method
#     on each respective service, which compiles statistics about usage patterns,
#     success rates, and other relevant metrics for administrative monitoring
#     and analysis purposes.

#     Args:
#         db (Session): Database session dependency.
#         user (str): Authenticated user dependency.

#     Returns:
#         MetricsDict: A dictionary containing the aggregated metrics for tools,
#         resources, servers, and prompts. Each value is a Pydantic model instance
#         specific to the entity type.
#     """
#     LOGGER.debug(f"User {get_user_email(user)} requested aggregate metrics")
#     tool_metrics = await tool_service.aggregate_metrics(db)
#     resource_metrics = await resource_service.aggregate_metrics(db)
#     server_metrics = await server_service.aggregate_metrics(db)
#     prompt_metrics = await prompt_service.aggregate_metrics(db)

#     # Return actual Pydantic model instances
#     return {
#         "tools": tool_metrics,
#         "resources": resource_metrics,
#         "servers": server_metrics,
#         "prompts": prompt_metrics,
#     }


@router.get("/metrics")
@require_permission("admin.system_config", allow_admin_bypass=False)
async def get_aggregated_metrics(
    db: Session = Depends(get_db),
    _user=Depends(get_current_user_with_permissions),
) -> Dict[str, Any]:
    """Retrieve aggregated metrics and top performers for all entity types.

    This endpoint collects usage metrics and top-performing entities for tools,
    resources, prompts, and servers by calling the respective service methods.
    The results are compiled into a dictionary for administrative monitoring.

    Args:
        db (Session): Database session dependency for querying metrics.

    Returns:
        Dict[str, Any]: A dictionary containing aggregated metrics and top performers
            for tools, resources, prompts, and servers. The structure includes:
            - 'tools': Metrics for tools.
            - 'resources': Metrics for resources.
            - 'prompts': Metrics for prompts.
            - 'servers': Metrics for servers.
            - 'topPerformers': A nested dictionary with all tools, resources, prompts,
              and servers with their metrics.
    """
    metrics = {
        "tools": await tool_service.aggregate_metrics(db),
        "resources": await resource_service.aggregate_metrics(db),
        "prompts": await prompt_service.aggregate_metrics(db),
        "servers": await server_service.aggregate_metrics(db),
        "topPerformers": {
            "tools": await tool_service.get_top_tools(db, limit=10),
            "resources": await resource_service.get_top_resources(db, limit=10),
            "prompts": await prompt_service.get_top_prompts(db, limit=10),
            "servers": await server_service.get_top_servers(db, limit=10),
        },
    }
    return metrics


@router.get("/metrics/partial", response_class=HTMLResponse)
@require_permission("admin.system_config", allow_admin_bypass=False)
async def admin_metrics_partial_html(
    request: Request,
    entity_type: QueryEntityType = "tools",
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    per_page: int = Query(10, ge=1, le=settings.pagination_max_page_size, description="Items per page"),
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    """
    Return HTML partial for paginated top performers (HTMX endpoint).

    Matches the /admin/tools/partial pattern for consistent pagination UX.

    Args:
        request: FastAPI request object
        entity_type: Entity type (tools, resources, prompts, servers)
        page: Page number (1-indexed)
        per_page: Items per page
        db: Database session
        user: Authenticated user

    Returns:
        HTMLResponse with paginated table and OOB pagination controls

    Raises:
        HTTPException: If entity_type is not one of the valid types
    """
    LOGGER.debug(f"User {get_user_email(user)} requested metrics partial (entity_type={entity_type}, page={page}, per_page={per_page})")

    # Validate entity type
    valid_types = ["tools", "resources", "prompts", "servers"]
    if entity_type not in valid_types:
        raise HTTPException(status_code=400, detail=f"Invalid entity_type. Must be one of: {', '.join(valid_types)}")

    # Constrain parameters
    page = max(1, page)
    per_page = max(1, min(per_page, 1000))

    # Get all items for this entity type
    if entity_type == "tools":
        all_items = await tool_service.get_top_tools(db, limit=None)
    elif entity_type == "resources":
        all_items = await resource_service.get_top_resources(db, limit=None)
    elif entity_type == "prompts":
        all_items = await prompt_service.get_top_prompts(db, limit=None)
    else:  # servers
        all_items = await server_service.get_top_servers(db, limit=None)

    # Calculate pagination
    total_items = len(all_items)
    total_pages = math.ceil(total_items / per_page) if per_page > 0 else 0
    offset = (page - 1) * per_page
    paginated_items = all_items[offset : offset + per_page]

    # Convert to JSON-serializable format
    data = jsonable_encoder(paginated_items)

    # Build pagination metadata
    pagination = PaginationMeta(
        page=page,
        per_page=per_page,
        total_items=total_items,
        total_pages=total_pages,
        has_next=page < total_pages,
        has_prev=page > 1,
    )

    # Render template
    return request.app.state.templates.TemplateResponse(
        request,
        "metrics_top_performers_partial.html",
        {
            "request": request,
            "entity_type": entity_type,
            "data": data,
            "pagination": pagination.model_dump(),
            "root_path": _resolve_root_path(request),
        },
    )


@router.post("/metrics/reset", response_model=Dict[str, object])
@require_permission("admin.system_config", allow_admin_bypass=False)
async def admin_reset_metrics(db: Session = Depends(get_db), user=Depends(get_current_user_with_permissions)) -> Dict[str, object]:
    """
    Reset all metrics for tools, resources, servers, and prompts.
    Each service must implement its own reset_metrics method.

    Args:
        db (Session): Database session dependency.
        user (str): Authenticated user dependency.

    Returns:
        Dict[str, object]: A dictionary containing a success message and status.

    Examples:
        >>> callable(admin_reset_metrics)
        True
        >>> admin_reset_metrics.__name__
        'admin_reset_metrics'
    """
    LOGGER.debug(f"User {get_user_email(user)} requested to reset all metrics")
    await tool_service.reset_metrics(db)
    await resource_service.reset_metrics(db)
    await server_service.reset_metrics(db)
    await prompt_service.reset_metrics(db)
    return {"message": "All metrics reset successfully", "success": True}
