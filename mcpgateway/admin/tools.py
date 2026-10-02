# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/admin/tools.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Admin UI tool routes: list, partial, ops partial, ids, search, detail, create,
edit, OpenAPI schema generation, delete, and state change.
"""

# Standard
import base64
import binascii
import logging
from typing import Any, Dict, Optional
import urllib.parse

# Third-Party
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.encoders import jsonable_encoder
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
import httpx
import orjson
from pydantic import ValidationError
from sqlalchemy import and_, case, false, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import joinedload, Session
from sqlalchemy.sql.functions import coalesce

# First-Party
from mcpgateway.admin.common import (
    _adjust_pagination_for_conversion_failures,
    _apply_tag_filter_groups,
    _build_admin_redirect,
    _build_search_response,
    _check_public_visibility_allowed,
    _form_team_id,
    _get_user_team_ids,
    _get_user_team_roles,
    _like_contains,
    _normalize_search_query,
    _normalize_tags_query,
    _owner_access_condition,
    _parse_tag_filter_groups,
    _read_request_json,
    _validated_team_id_param,
    tool_service,
)
from mcpgateway.admin.security import enforce_admin_csrf
from mcpgateway.auth_context import get_scoped_resource_access_context, get_token_teams_from_request, get_user_email
from mcpgateway.common.query_params import QueryGatewayIdList, QueryRenderModeControls, QueryTagsFilter
from mcpgateway.common.validators import SecurityValidator
from mcpgateway.config import settings
from mcpgateway.db import get_db, Tool as DbTool
from mcpgateway.middleware.rbac import get_current_user_with_permissions, require_permission
from mcpgateway.schemas import _encode_auth_headers_list, PaginatedResponse, ToolCreate, ToolRead, ToolUpdate
from mcpgateway.services.openapi_service import fetch_and_extract_schemas
from mcpgateway.services.team_management_service import TeamManagementService
from mcpgateway.services.tool_service import ToolError, ToolLockConflictError, ToolNameConflictError, ToolNotFoundError
from mcpgateway.utils.error_formatter import ErrorFormatter
from mcpgateway.utils.metadata_capture import MetadataCapture
from mcpgateway.utils.orjson_response import ORJSONResponse
from mcpgateway.utils.pagination import paginate_query
from mcpgateway.utils.services_auth import encode_auth
from mcpgateway.utils.paths import resolve_root_path as _resolve_root_path

LOGGER: logging.Logger = logging.getLogger("mcpgateway.admin")

# mcpgateway.admin (__init__) appends this router's routes to admin_router, so the
# prefix, tags, and CSRF dependency must mirror admin_router exactly.
router = APIRouter(
    prefix="/admin",
    tags=["Admin UI"],
    dependencies=[Depends(enforce_admin_csrf)],
)


@router.get("/tools", response_model=PaginatedResponse)
@require_permission("tools.read", allow_admin_bypass=False)
async def admin_list_tools(
    request: Request,
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    per_page: int = Query(settings.pagination_default_page_size, ge=1, le=settings.pagination_max_page_size, description="Items per page"),
    include_inactive: bool = False,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> Dict[str, Any]:
    """
    List tools for the admin UI with pagination support.

    This endpoint retrieves a paginated list of tools from the database, optionally
    including those that are inactive. Uses offset-based (page/per_page) pagination.

    Args:
        request (Request): FastAPI request object (required for token team extraction via request.state.token_teams).
        page (int): Page number (1-indexed). Default: 1.
        per_page (int): Items per page. Default: 50.
        include_inactive (bool): Whether to include inactive tools in the results.
        db (Session): Database session dependency.
        user (str): Authenticated user dependency.

    Returns:
        Dict with 'data', 'pagination', and 'links' keys containing paginated tools.

    """
    user_email = get_user_email(user)
    token_teams = get_token_teams_from_request(request)
    LOGGER.debug(f"User {user_email} requested tool list (page={page}, per_page={per_page})")
    _is_admin = bool(user.get("is_admin", False) if isinstance(user, dict) else getattr(user, "is_admin", False))
    _team_roles = _get_user_team_roles(db, user_email) if not _is_admin else {}

    # Call tool_service.list_tools with page-based pagination
    paginated_result = await tool_service.list_tools(
        db=db,
        include_inactive=include_inactive,
        page=page,
        per_page=per_page,
        user_email=user_email,
        token_teams=token_teams,
        requesting_user_email=user_email,
        requesting_user_is_admin=_is_admin,
        requesting_user_team_roles=_team_roles,
    )

    # End the read-only transaction early to avoid idle-in-transaction under load.
    db.commit()

    # Return standardized paginated response
    return {
        "data": [tool.model_dump(by_alias=True) for tool in paginated_result["data"]],
        "pagination": paginated_result["pagination"].model_dump(),
        "links": paginated_result["links"].model_dump() if paginated_result["links"] else None,
    }


@router.get("/tools/partial", response_class=HTMLResponse)
@require_permission("tools.read", allow_admin_bypass=False)
async def admin_tools_partial_html(
    request: Request,
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    per_page: int = Query(settings.pagination_default_page_size, ge=1, le=settings.pagination_max_page_size, description="Items per page"),
    q: str = Query("", max_length=500, description="Search query"),
    tags: QueryTagsFilter = None,
    include_inactive: bool = False,
    render: QueryRenderModeControls = None,
    gateway_id: QueryGatewayIdList = None,
    team_id: Optional[str] = Depends(_validated_team_id_param),
    include_public: bool = False,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    """
    Return HTML partial for paginated tools list (HTMX endpoint).

    This endpoint returns only the table body rows and pagination controls
    for HTMX-based pagination in the admin UI.

    Args:
        request (Request): FastAPI request object.
        page (int): Page number (1-indexed). Default: 1.
        per_page (int): Items per page. Default: 50.
        q (str): Free-text query string.
        tags (Optional[str]): Tag filter expression (comma=OR, plus=AND).
        include_inactive (bool): Whether to include inactive tools in the results.
        gateway_id (Optional[str]): Filter by gateway ID(s), comma-separated.
        team_id (Optional[str]): Filter by team ID.
        include_public (bool): Whether to include all public tools in the results.
        render (str): Render mode - 'controls' returns only pagination controls.
        db (Session): Database session dependency.
        user (str): Authenticated user dependency.

    Returns:
        HTMLResponse with tools table rows and pagination controls.
    """
    user_email = get_user_email(user)
    search_query = _normalize_search_query(q)
    normalized_tags = _normalize_tags_query(tags)
    tag_groups = _parse_tag_filter_groups(normalized_tags)
    LOGGER.debug(f"🔧 TOOLS PARTIAL REQUEST - User: {user_email}, team_id: {team_id}, page: {page}, render: {render}, referer: {request.headers.get('referer', 'none')}")

    # Build base query using tool_service's team filtering logic
    team_ids = await _get_user_team_ids(user, db)

    # Build query with eager loading for email_team to avoid N+1 queries
    query = select(DbTool).options(joinedload(DbTool.email_team))

    # Apply gateway filter if provided. Support special sentinel 'null' to
    # request tools with NULL gateway_id (e.g., RestTool/no gateway).
    if gateway_id:
        gateway_ids = [gid.strip() for gid in gateway_id.split(",") if gid.strip()]
        if gateway_ids:
            # Treat literal 'null' (case-insensitive) as a request for NULL gateway_id
            null_requested = any(gid.lower() == "null" for gid in gateway_ids)
            non_null_ids = [gid for gid in gateway_ids if gid.lower() != "null"]
            if non_null_ids and null_requested:
                query = query.where(or_(DbTool.gateway_id.in_(non_null_ids), DbTool.gateway_id.is_(None)))
                LOGGER.debug(f"Filtering tools by gateway IDs (including NULL): {non_null_ids} + NULL")
            elif null_requested:
                query = query.where(DbTool.gateway_id.is_(None))
                LOGGER.debug("Filtering tools by NULL gateway_id (RestTool)")
            else:
                query = query.where(DbTool.gateway_id.in_(non_null_ids))
                LOGGER.debug(f"Filtering tools by gateway IDs: {non_null_ids}")

    # Apply active/inactive filter
    if not include_inactive:
        query = query.where(DbTool.enabled.is_(True))

    # Build access conditions
    # When team_id is specified, show ONLY items from that team (simpler, team-scoped view)
    # When team_id + include_public, show team items PLUS public items from all teams
    # When team_id is NOT specified, show all accessible items (owned + team + public)
    if team_id:
        # Team-specific view: only show tools from the specified team if user is a member
        if team_id in team_ids:
            # Apply visibility check: team/public resources + user's own resources (including private)
            team_access = [
                and_(DbTool.team_id == team_id, DbTool.visibility.in_(["team", "public"])),
                and_(DbTool.team_id == team_id, DbTool.owner_email == user_email),
            ]
            if include_public:
                # Include all globally public items from any team.
                # Items with visibility='team' or 'private' from other teams are
                # blocked by the other conditions (which require team_id == selected team).
                team_access.append(DbTool.visibility == "public")
            query = query.where(or_(*team_access))
            LOGGER.debug(f"Filtering tools by team_id: {team_id}{' (include_public)' if include_public else ''}")
        else:
            # User is not a member of this team, return no results
            LOGGER.warning(f"User {user_email} attempted to filter by team {team_id} but is not a member")
            query = query.where(false())
    else:
        # All Teams view: apply standard access conditions
        access_conditions = []

        # 1. User's personal tools (owner_email matches)
        access_conditions.append(_owner_access_condition(DbTool.owner_email, DbTool.team_id, user_email=user_email, team_ids=team_ids, user=user))

        # 2. Team tools where user is member
        if team_ids:
            access_conditions.append(and_(DbTool.team_id.in_(team_ids), DbTool.visibility.in_(["team", "public"])))

        # 3. Public tools
        access_conditions.append(DbTool.visibility == "public")

        query = query.where(or_(*access_conditions))

    if search_query:
        query = query.where(
            or_(
                _like_contains(func.lower(DbTool.id), search_query),
                _like_contains(func.lower(DbTool.original_name), search_query),
                _like_contains(func.lower(coalesce(DbTool.display_name, "")), search_query),
                _like_contains(func.lower(coalesce(DbTool.custom_name, "")), search_query),
                _like_contains(func.lower(coalesce(DbTool.description, "")), search_query),
                _like_contains(func.lower(coalesce(DbTool.url, "")), search_query),
            )
        )

    query = _apply_tag_filter_groups(query, db, DbTool.tags, tag_groups)

    # Apply sorting: alphabetical by URL, then name, then ID (for UI display)
    # Different from JSON endpoint which uses created_at DESC
    query = query.order_by(DbTool.url, DbTool.original_name, DbTool.id)

    # Use unified pagination function (offset-based for UI compatibility)
    root_path = _resolve_root_path(request)
    base_url = f"{root_path}/admin/tools/partial"
    query_params_dict = {}
    if include_inactive:
        query_params_dict["include_inactive"] = "true"
    if gateway_id:
        query_params_dict["gateway_id"] = gateway_id
    if team_id:
        query_params_dict["team_id"] = team_id
    if search_query:
        query_params_dict["q"] = search_query
    if normalized_tags:
        query_params_dict["tags"] = normalized_tags

    paginated_result = await paginate_query(
        db=db,
        query=query,
        page=page,
        per_page=per_page,
        cursor=None,  # UI uses offset pagination only
        base_url=base_url,
        query_params=query_params_dict,
        use_cursor_threshold=False,  # Disable auto-cursor switching for UI
    )

    # Extract paginated tools (DbTool objects)
    tools_db = paginated_result["data"]
    pagination = paginated_result["pagination"]
    links = paginated_result["links"]

    # Team names are loaded via joinedload(DbTool.email_team) in the query
    # Batch convert to Pydantic models using tool service
    # This eliminates the N+1 query problem from calling get_tool() in a loop
    _is_admin = bool(user.get("is_admin", False) if isinstance(user, dict) else getattr(user, "is_admin", False))
    _team_roles = _get_user_team_roles(db, user_email) if not _is_admin else {}
    tools_pydantic = []
    failed_count = 0
    for t in tools_db:
        try:
            tools_pydantic.append(
                tool_service.convert_tool_to_read(
                    t,
                    include_metrics=False,
                    include_auth=False,
                    requesting_user_email=user_email,
                    requesting_user_is_admin=_is_admin,
                    requesting_user_team_roles=_team_roles,
                )
            )
        except (ValidationError, ValueError, KeyError, TypeError, binascii.Error) as e:
            failed_count += 1
            LOGGER.exception(f"Failed to convert tool {getattr(t, 'id', 'unknown')} ({getattr(t, 'name', 'unknown')}): {e}")
    _adjust_pagination_for_conversion_failures(pagination, failed_count, len(tools_pydantic))

    # Serialize tools
    data = jsonable_encoder(tools_pydantic)

    # End the read-only transaction before template rendering to avoid idle-in-transaction timeouts.
    db.commit()

    # If render=controls, return only pagination controls
    if render == "controls":
        # NOTE: hx_target/hx_swap must match what tools_partial.html sets when
        # rendering the inline pagination_controls include — currently
        # `#tools-table` with swap=outerHTML. Diverging here would cause
        # subsequent pagination clicks (after a controls-only re-render) to
        # swap into a target that the success-path doesn't own and trigger
        # the same `o.querySelector` null-fragment crash that caused the
        # `_loading` deadlock the rest of this PR fixes.
        return request.app.state.templates.TemplateResponse(
            request,
            "pagination_controls.html",
            {
                "request": request,
                "pagination": pagination.model_dump(),
                "base_url": base_url,
                "hx_target": "#tools-table",
                "hx_swap": "outerHTML",
                "hx_indicator": "#tools-loading",
                "table_name": "tools",
                "query_params": query_params_dict,
                "root_path": _resolve_root_path(request),
            },
        )

    # If render=selector, return tool selector items for infinite scroll
    if render == "selector":
        return request.app.state.templates.TemplateResponse(
            request,
            "tools_selector_items.html",
            {
                "request": request,
                "data": data,
                "pagination": pagination.model_dump(),
                "root_path": _resolve_root_path(request),
                "gateway_id": gateway_id,
                "team_id": team_id,
                "include_public": include_public,
            },
        )

    # Render template with paginated data
    return request.app.state.templates.TemplateResponse(
        request,
        "tools_partial.html",
        {
            "request": request,
            "data": data,
            "pagination": pagination.model_dump(),
            "links": links.model_dump() if links else None,
            "root_path": _resolve_root_path(request),
            "include_inactive": include_inactive,
            "query_params": query_params_dict,
            "current_user_email": user_email,
            "is_admin": _is_admin,
            "user_team_roles": _team_roles,
        },
    )


@router.get("/tool-ops/partial", response_class=HTMLResponse)
@require_permission("tools.read", allow_admin_bypass=False)
async def admin_tool_ops_partial(
    request: Request,
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(settings.pagination_default_page_size, ge=1, le=settings.pagination_max_page_size, description="Items per page"),
    include_inactive: bool = False,
    gateway_id: QueryGatewayIdList = None,
    team_id: Optional[str] = Depends(_validated_team_id_param),
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    """
    Return HTML partial for tool operations table.

    Args:
        request (Request): The request object.
        page (int): The page number. Defaults to 1.
        per_page (int): The number of items per page. Defaults to settings.pagination_default_page_size.
        include_inactive (bool): Whether to include inactive items. Defaults to False.
        gateway_id (Optional[str]): The gateway ID to filter by. Defaults to None.
        team_id (Optional[str]): The team ID to filter by. Defaults to None.
        db (Session): The database session. Defaults to Depends(get_db).
        user (Any): The current user. Defaults to Depends(get_current_user_with_permissions).

    Returns:
        HTMLResponse: The HTML partial for the tool operations table.
    """
    user_email = get_user_email(user)
    LOGGER.debug(f"Tool ops partial request - team_id: {team_id}, page: {page}")
    team_ids = await _get_user_team_ids(user, db)

    query = select(DbTool).options(joinedload(DbTool.email_team))

    if gateway_id:
        gateway_ids = [gid.strip() for gid in gateway_id.split(",") if gid.strip()]
        if gateway_ids:
            null_requested = any(gid.lower() == "null" for gid in gateway_ids)
            non_null_ids = [gid for gid in gateway_ids if gid.lower() != "null"]
            if non_null_ids and null_requested:
                query = query.where(or_(DbTool.gateway_id.in_(non_null_ids), DbTool.gateway_id.is_(None)))
                LOGGER.debug(f"Filtering tools by gateway IDs (including NULL): {non_null_ids} + NULL")
            elif null_requested:
                query = query.where(DbTool.gateway_id.is_(None))
                LOGGER.debug("Filtering tools by NULL gateway_id (RestTool)")
            else:
                query = query.where(DbTool.gateway_id.in_(non_null_ids))
                LOGGER.debug(f"Filtering tools by gateway IDs: {non_null_ids}")

    if not include_inactive:
        query = query.where(DbTool.enabled.is_(True))

    if team_id:
        if team_id in team_ids:
            team_access = [
                and_(DbTool.team_id == team_id, DbTool.visibility.in_(["team", "public"])),
                and_(DbTool.team_id == team_id, DbTool.owner_email == user_email),
            ]
            query = query.where(or_(*team_access))
            LOGGER.debug(f"Filtering tools by team_id: {team_id}")
        else:
            LOGGER.warning(f"User {user_email} attempted to filter by team {team_id} but is not a member")
            query = query.where(false())
    else:
        access_conditions = []
        access_conditions.append(_owner_access_condition(DbTool.owner_email, DbTool.team_id, user_email=user_email, team_ids=team_ids, user=user))
        if team_ids:
            access_conditions.append(and_(DbTool.team_id.in_(team_ids), DbTool.visibility.in_(["team", "public"])))
        access_conditions.append(DbTool.visibility == "public")
        query = query.where(or_(*access_conditions))

    query = query.order_by(DbTool.url, DbTool.original_name, DbTool.id)

    paginated_result = await paginate_query(
        db=db,
        query=query,
        page=page,
        per_page=per_page,
        cursor=None,
        base_url=f"{_resolve_root_path(request)}/admin/tool-ops/partial",
        query_params={
            "include_inactive": "true" if include_inactive else "false",
            "gateway_id": gateway_id or "",
            "team_id": team_id or "",
        },
        use_cursor_threshold=False,
    )

    tools_db = paginated_result["data"]
    _is_admin = bool(user.get("is_admin", False) if isinstance(user, dict) else getattr(user, "is_admin", False))
    _team_roles = _get_user_team_roles(db, user_email) if not _is_admin else {}
    tools_pydantic = [
        tool_service.convert_tool_to_read(
            t,
            include_metrics=False,
            include_auth=False,
            requesting_user_email=user_email,
            requesting_user_is_admin=_is_admin,
            requesting_user_team_roles=_team_roles,
        )
        for t in tools_db
    ]
    db.commit()

    return request.app.state.templates.TemplateResponse(
        request,
        "toolops_partial.html",
        {
            "request": request,
            "tools": tools_pydantic,
            "root_path": _resolve_root_path(request),
            "current_user_email": user_email,
            "is_admin": _is_admin,
            "user_team_roles": _team_roles,
        },
    )


@router.get("/tools/ids", response_class=JSONResponse)
@require_permission("tools.read", allow_admin_bypass=False)
async def admin_get_all_tool_ids(
    q: str = Query("", max_length=500, description="Search query"),
    include_inactive: bool = False,
    gateway_id: QueryGatewayIdList = None,
    team_id: Optional[str] = Depends(_validated_team_id_param),
    include_public: bool = False,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    """
    Return all tool IDs accessible to the current user.

    This is used by "Select All" to get all tool IDs without loading full data.

    Args:
        q (str): Search query to filter tools by name, ID, or description
        include_inactive (bool): Whether to include inactive tools in the results
        gateway_id (Optional[str]): Filter by gateway ID(s), comma-separated. Accepts the literal value 'null' to indicate NULL gateway_id (local tools).
        team_id (Optional[str]): Filter by team ID.
        include_public (bool): Whether to include all platform-public tools when filtering by team.
        db (Session): Database session dependency
        user: Current user making the request

    Returns:
        JSONResponse: List of tool IDs accessible to the user
    """
    user_email = get_user_email(user)

    # Build base query
    team_ids = await _get_user_team_ids(user, db)

    query = select(DbTool.id)

    if not include_inactive:
        query = query.where(DbTool.enabled.is_(True))

    # Apply search filter if provided
    if q:
        search_query = _normalize_search_query(q)
        if search_query:
            search_conditions = [
                _like_contains(func.lower(DbTool.id), search_query),
                _like_contains(func.lower(DbTool.original_name), search_query),
                _like_contains(func.lower(coalesce(DbTool.display_name, "")), search_query),
                _like_contains(func.lower(coalesce(DbTool.custom_name, "")), search_query),
                _like_contains(func.lower(coalesce(DbTool.description, "")), search_query),
                _like_contains(func.lower(coalesce(DbTool.url, "")), search_query),
            ]
            query = query.where(or_(*search_conditions))
            LOGGER.debug(f"Filtering tool IDs by search query: {search_query}")

    # Apply optional gateway/server scoping (comma-separated ids). Accepts the
    # literal value 'null' to indicate NULL gateway_id (local tools).
    if gateway_id:
        gateway_ids = [gid.strip() for gid in gateway_id.split(",") if gid.strip()]
        if gateway_ids:
            null_requested = any(gid.lower() == "null" for gid in gateway_ids)
            non_null_ids = [gid for gid in gateway_ids if gid.lower() != "null"]
            if non_null_ids and null_requested:
                query = query.where(or_(DbTool.gateway_id.in_(non_null_ids), DbTool.gateway_id.is_(None)))
                LOGGER.debug(f"Filtering tools by gateway IDs (including NULL): {non_null_ids} + NULL")
            elif null_requested:
                query = query.where(DbTool.gateway_id.is_(None))
                LOGGER.debug("Filtering tools by NULL gateway_id (local tools)")
            else:
                query = query.where(DbTool.gateway_id.in_(non_null_ids))
                LOGGER.debug(f"Filtering tools by gateway IDs: {non_null_ids}")

    # Build access conditions
    # When team_id is specified, show items from that team; optionally include
    # platform-public items when include_public is set (mirrors the partial endpoint).
    # Otherwise, show all accessible items (All Teams view).
    if team_id:
        if team_id in team_ids:
            team_access = [
                and_(DbTool.team_id == team_id, DbTool.visibility.in_(["team", "public"])),
                and_(DbTool.team_id == team_id, DbTool.owner_email == user_email),
            ]
            if include_public:
                team_access.append(DbTool.visibility == "public")
            query = query.where(or_(*team_access))
            LOGGER.debug(f"Filtering tool IDs by team_id: {team_id}{' (include_public)' if include_public else ''}")
        else:
            LOGGER.warning(f"User {user_email} attempted to filter tool IDs by team {team_id} but is not a member")
            query = query.where(false())
    else:
        # All Teams view: apply standard access conditions (owner, team, public)
        access_conditions = []
        access_conditions.append(_owner_access_condition(DbTool.owner_email, DbTool.team_id, user_email=user_email, team_ids=team_ids, user=user))
        access_conditions.append(DbTool.visibility == "public")
        if team_ids:
            access_conditions.append(and_(DbTool.team_id.in_(team_ids), DbTool.visibility.in_(["team", "public"])))
        query = query.where(or_(*access_conditions))

    # Get all IDs
    tool_ids = [row[0] for row in db.execute(query).all()]

    return {"tool_ids": tool_ids, "count": len(tool_ids)}


@router.get("/tools/search", response_class=JSONResponse)
@require_permission("tools.read", allow_admin_bypass=False)
async def admin_search_tools(
    q: str = Query("", max_length=500, description="Search query"),
    tags: QueryTagsFilter = None,
    include_inactive: bool = False,
    limit: int = Query(settings.pagination_default_page_size, ge=1, le=settings.pagination_max_page_size, description="Maximum number of results to return"),
    gateway_id: QueryGatewayIdList = None,
    team_id: Optional[str] = Depends(_validated_team_id_param),
    include_public: bool = False,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    """
    Search tools by name, ID, or description.

    This endpoint searches tools across all accessible tools for the current user,
    returning both IDs and names for use in search functionality like the Add Server page.

    Args:
        q (str): Search query string to match against tool names, IDs, or descriptions.
        tags (Optional[str]): Tag filter expression (comma=OR, plus=AND).
        include_inactive (bool): Whether to include inactive tools in the search results.
        limit (int): Maximum number of results to return.
        gateway_id (Optional[str]): Filter by gateway ID(s), comma-separated.
        team_id (Optional[str]): Filter by team ID.
        include_public (bool): Whether to include all public tools in the results.
        db (Session): Database session.
        user: Current user with permissions.

    Returns:
        JSONResponse: A JSON response containing a list of matching tools.
    """
    user_email = get_user_email(user)
    search_query = _normalize_search_query(q)
    normalized_tags = _normalize_tags_query(tags)
    tag_groups = _parse_tag_filter_groups(normalized_tags)

    if not search_query and not tag_groups:
        return _build_search_response(entity_key="tools", entity_type="tools", items=[], query=search_query, tags=normalized_tags, tag_groups=tag_groups)

    # Build base query
    team_ids = await _get_user_team_ids(user, db)

    query = select(DbTool.id, DbTool.original_name, DbTool.custom_name, DbTool.display_name, DbTool.description)

    # Apply gateway filter if provided. Support special sentinel 'null' to
    # request tools with NULL gateway_id (e.g., RestTool/no gateway).
    if gateway_id:
        gateway_ids = [gid.strip() for gid in gateway_id.split(",") if gid.strip()]
        if gateway_ids:
            # Treat literal 'null' (case-insensitive) as a request for NULL gateway_id
            null_requested = any(gid.lower() == "null" for gid in gateway_ids)
            non_null_ids = [gid for gid in gateway_ids if gid.lower() != "null"]
            if non_null_ids and null_requested:
                query = query.where(or_(DbTool.gateway_id.in_(non_null_ids), DbTool.gateway_id.is_(None)))
                LOGGER.debug(f"Filtering tool search by gateway IDs (including NULL): {non_null_ids} + NULL")
            elif null_requested:
                query = query.where(DbTool.gateway_id.is_(None))
                LOGGER.debug("Filtering tool search by NULL gateway_id (RestTool)")
            else:
                query = query.where(DbTool.gateway_id.in_(non_null_ids))
                LOGGER.debug(f"Filtering tool search by gateway IDs: {non_null_ids}")

    if not include_inactive:
        query = query.where(DbTool.enabled.is_(True))

    # Build access conditions
    # When team_id is specified, show ONLY items from that team (team-scoped view)
    # When team_id + include_public, show team items PLUS public items from all teams
    # Otherwise, show all accessible items (All Teams view)
    if team_id:
        if team_id in team_ids:
            # Apply visibility check: team/public resources + user's own resources (including private)
            team_access = [
                and_(DbTool.team_id == team_id, DbTool.visibility.in_(["team", "public"])),
                and_(DbTool.team_id == team_id, DbTool.owner_email == user_email),
            ]
            if include_public:
                team_access.append(DbTool.visibility == "public")
            query = query.where(or_(*team_access))
            LOGGER.debug(f"Filtering tool search by team_id: {team_id}{' (include_public)' if include_public else ''}")
        else:
            LOGGER.warning(f"User {user_email} attempted to filter tool search by team {team_id} but is not a member")
            query = query.where(false())
    else:
        # All Teams view: apply standard access conditions (owner, team, public)
        access_conditions = []
        access_conditions.append(_owner_access_condition(DbTool.owner_email, DbTool.team_id, user_email=user_email, team_ids=team_ids, user=user))
        access_conditions.append(DbTool.visibility == "public")
        if team_ids:
            access_conditions.append(and_(DbTool.team_id.in_(team_ids), DbTool.visibility.in_(["team", "public"])))
        query = query.where(or_(*access_conditions))

    # Add search conditions - search in display fields and description
    # Using the same priority as display: displayName -> customName -> original_name
    if search_query:
        search_conditions = [
            _like_contains(func.lower(DbTool.id), search_query),
            _like_contains(func.lower(DbTool.original_name), search_query),
            _like_contains(func.lower(coalesce(DbTool.display_name, "")), search_query),
            _like_contains(func.lower(coalesce(DbTool.custom_name, "")), search_query),
            _like_contains(func.lower(coalesce(DbTool.description, "")), search_query),
            _like_contains(func.lower(coalesce(DbTool.url, "")), search_query),
        ]
        query = query.where(or_(*search_conditions))

    query = _apply_tag_filter_groups(query, db, DbTool.tags, tag_groups)

    # Order by relevance - prioritize matches at start of names
    if search_query:
        query = query.order_by(
            case(
                (func.lower(DbTool.original_name).startswith(search_query), 1),
                (func.lower(coalesce(DbTool.custom_name, "")).startswith(search_query), 1),
                (func.lower(coalesce(DbTool.display_name, "")).startswith(search_query), 1),
                else_=2,
            ),
            func.lower(DbTool.original_name),
        )
    else:
        query = query.order_by(func.lower(DbTool.original_name))
    query = query.limit(limit)

    # Execute query
    results = db.execute(query).all()

    # Format results
    tools = []
    for row in results:
        tools.append({"id": row.id, "name": row.original_name, "display_name": row.display_name, "custom_name": row.custom_name})  # original_name for search matching

    return _build_search_response(entity_key="tools", entity_type="tools", items=tools, query=search_query, tags=normalized_tags, tag_groups=tag_groups)


@router.get("/tools/{tool_id}", response_model=ToolRead)
@require_permission("tools.read", allow_admin_bypass=False)
async def admin_get_tool(tool_id: str, request: Request, db: Session = Depends(get_db), user=Depends(get_current_user_with_permissions)) -> Dict[str, Any]:
    """
    Retrieve specific tool details for the admin UI.

    This endpoint fetches the details of a specific tool from the database
    by its ID. It provides access to all information about the tool for
    viewing and management purposes.

    Args:
        tool_id (str): The ID of the tool to retrieve.
        request (Request): Incoming FastAPI request (for visibility scope resolution).
        db (Session): Database session dependency.
        user (str): Authenticated user dependency.

    Returns:
        ToolRead: The tool details formatted with by_alias=True.

    Raises:
        HTTPException: If the tool is not found.
        Exception: For any other unexpected errors.

    Examples:
        >>> callable(admin_get_tool)
        True
        >>> admin_get_tool.__name__
        'admin_get_tool'
    """
    LOGGER.debug(f"User {get_user_email(user)} requested details for tool ID {tool_id}")
    auth_user_email, auth_token_teams = get_scoped_resource_access_context(request, user)
    _user_email = get_user_email(user)
    _is_admin = bool(user.get("is_admin", False) if isinstance(user, dict) else getattr(user, "is_admin", False))
    _team_roles = _get_user_team_roles(db, _user_email) if not _is_admin else {}
    try:
        tool = await tool_service.get_tool(
            db,
            tool_id,
            requesting_user_email=auth_user_email,
            requesting_user_is_admin=_is_admin,
            requesting_user_team_roles=_team_roles,
            token_teams=auth_token_teams,
        )
        return tool.model_dump(by_alias=True)
    except ToolNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        # Catch any other unexpected errors and re-raise or log as needed
        LOGGER.error(f"Error getting tool {tool_id}: {e}")
        raise e  # Re-raise for now, or return a 500 JSONResponse if preferred for API consistency


def _build_auth_obj_from_form(form: Any) -> Optional[dict[str, Any]]:
    """Parse auth fields from a form and return a serialized auth object, or None.

    Custom headers are validated by the same ``_encode_auth_headers_list`` helper the JSON
    tool/gateway schemas use, so malformed header keys and oversized header sets are rejected
    here with a 422 instead of being persisted and failing later at tool-invocation time.
    Rows with a blank key are dropped first: the admin form submits empty rows for headers the
    user never filled in, and those must keep meaning "no headers" rather than 422.

    Args:
        form: Multipart form data containing auth_type and credential fields.

    Returns:
        A dict with auth_type and encrypted auth_value, or None if no valid auth provided.

    Raises:
        HTTPException: 422 if auth_type is 'oauth' (unsupported on tools) or if the supplied
            custom headers fail validation.
    """
    auth_headers_json = form.get("auth_headers") or ""
    auth_headers: list[dict[str, Any]] = []
    if auth_headers_json:
        try:
            parsed_headers = orjson.loads(auth_headers_json)
        except (orjson.JSONDecodeError, ValueError):
            parsed_headers = []
        # orjson.loads accepts any JSON scalar (e.g. "5", "null", "true"), so guard against a
        # non-list value here rather than letting it reach the list comprehension below and raise
        # an uncaught TypeError (500). A non-list body simply means "no custom headers".
        auth_headers = parsed_headers if isinstance(parsed_headers, list) else []

    auth_type = form.get("auth_type", "")
    if auth_type and auth_type.lower() == "oauth":
        raise HTTPException(status_code=422, detail="auth_type 'oauth' is not supported on tools; configure OAuth on the gateway instead")
    auth_obj: Optional[dict[str, Any]] = None
    if auth_type:
        if auth_type == "basic":
            username = form.get("auth_username", "")
            password = form.get("auth_password", "")
            if username and password:
                creds = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode()
                auth_value = encode_auth({"Authorization": f"Basic {creds}"})
                auth_obj = {"auth_type": auth_type, "auth_value": auth_value}
        elif auth_type == "bearer":
            token = form.get("auth_token", "")
            if token:
                auth_value = encode_auth({"Authorization": f"Bearer {token}"})
                auth_obj = {"auth_type": auth_type, "auth_value": auth_value}
        elif auth_type == "authheaders":
            populated_headers = [h for h in auth_headers if isinstance(h, dict) and h.get("key")]
            if populated_headers:
                try:
                    auth_value = _encode_auth_headers_list(populated_headers)
                except ValueError as exc:
                    raise HTTPException(status_code=422, detail=str(exc)) from exc
                auth_obj = {"auth_type": auth_type, "auth_value": auth_value}
            elif not auth_headers:
                header_key = form.get("auth_header_key", "")
                header_value = form.get("auth_header_value", "")
                if header_key and header_value:
                    auth_value = encode_auth({header_key: header_value})
                    auth_obj = {"auth_type": auth_type, "auth_value": auth_value}
    return auth_obj


@router.post("/tools/")
@router.post("/tools")
@require_permission("tools.create", allow_admin_bypass=False)
async def admin_add_tool(
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> JSONResponse:
    """
    Add a tool via the admin UI with error handling.

    Expects form fields:
      - name
      - url
      - description (optional)
      - requestType (mapped to request_type; defaults to "SSE")
      - integrationType (mapped to integration_type; defaults to "MCP")
      - headers (JSON string)
      - input_schema (JSON string)
      - output_schema (JSON string, optional)
      - jsonpath_filter (optional)
      - auth_type (optional)
      - auth_username (optional)
      - auth_password (optional)
      - auth_token (optional)
      - auth_header_key (optional)
      - auth_header_value (optional)

    Logs the raw form data and assembled tool_data for debugging.

    Args:
        request (Request): the FastAPI request object containing the form data.
        db (Session): the SQLAlchemy database session.
        user (str): identifier of the authenticated user.

    Returns:
        JSONResponse: a JSON response with `{"message": ..., "success": ...}` and an appropriate HTTP status code.

    Raises:
        HTTPException: 422 when public visibility is disabled and request is team-scoped.

    Examples:
        >>> callable(admin_add_tool)
        True
        >>> admin_add_tool.__name__
        'admin_add_tool'
    """
    LOGGER.debug(f"User {get_user_email(user)} is adding a new tool")
    form = await request.form()
    LOGGER.debug(f"Received form data: {dict(form)}")
    team_id = _form_team_id(form)
    integration_type = form.get("integrationType", "REST")
    request_type = form.get("requestType")
    visibility = str(form.get("visibility", "private"))
    _check_public_visibility_allowed(visibility, team_id=team_id)

    if request_type is None:
        if integration_type == "REST":
            request_type = "GET"  # or any valid REST method default
        elif integration_type == "MCP":
            request_type = "SSE"
        else:
            request_type = "GET"

    user_email = get_user_email(user)
    team_service = TeamManagementService(db)
    team_id = await team_service.verify_team_for_user(user_email, team_id)
    # Parse tags from comma-separated string
    tags_str = str(form.get("tags", ""))
    tags: list[str] = [tag.strip() for tag in tags_str.split(",") if tag.strip()] if tags_str else []

    # Build auth object from form fields
    auth_obj = _build_auth_obj_from_form(form)

    # Safely parse potential JSON strings from form
    headers_raw = form.get("headers")
    input_schema_raw = form.get("input_schema")
    output_schema_raw = form.get("output_schema")
    annotations_raw = form.get("annotations")

    # Parse JSON fields with validation
    try:
        headers = orjson.loads(headers_raw if isinstance(headers_raw, str) and headers_raw else "{}")
        input_schema = orjson.loads(input_schema_raw if isinstance(input_schema_raw, str) and input_schema_raw else "{}")
        output_schema = orjson.loads(output_schema_raw) if isinstance(output_schema_raw, str) and output_schema_raw else None
        annotations = orjson.loads(annotations_raw if isinstance(annotations_raw, str) and annotations_raw else "{}")
        query_mapping = orjson.loads(form.get("query_mapping") or "{}")
        header_mapping = orjson.loads(form.get("header_mapping") or "{}")
        allowlist = orjson.loads(form.get("allowlist") or "[]")
        plugin_chain_pre = orjson.loads(form.get("plugin_chain_pre") or "[]")
        plugin_chain_post = orjson.loads(form.get("plugin_chain_post") or "[]")
    except orjson.JSONDecodeError as ex:
        LOGGER.error(f"Invalid JSON in form field: {str(ex)}")
        return ORJSONResponse(
            content={"message": f"Invalid JSON in form field: {str(ex)}", "success": False},
            status_code=422,
        )

    tool_data: dict[str, Any] = {
        "name": form.get("name"),
        "displayName": form.get("displayName"),
        "url": form.get("url"),
        "description": form.get("description"),
        "request_type": request_type,
        "integration_type": integration_type,
        "headers": headers,
        "input_schema": input_schema,
        "output_schema": output_schema,
        "annotations": annotations,
        "jsonpath_filter": form.get("jsonpath_filter", ""),
        "auth": auth_obj,
        "tags": tags,
        "visibility": visibility,
        "team_id": team_id,
        "owner_email": user_email,
        "query_mapping": query_mapping,
        "header_mapping": header_mapping,
        "timeout_ms": int(form.get("timeout_ms")) if form.get("timeout_ms") and form.get("timeout_ms").strip() else None,
        "expose_passthrough": form.get("expose_passthrough", "true"),
        "allowlist": allowlist,
        "plugin_chain_pre": plugin_chain_pre,
        "plugin_chain_post": plugin_chain_post,
    }
    LOGGER.debug(f"Tool data built: {tool_data}")
    try:
        tool = ToolCreate(**tool_data)
        LOGGER.debug(f"Validated tool data: {tool.model_dump(by_alias=True)}")

        # Extract creation metadata
        metadata = MetadataCapture.extract_creation_metadata(request, user)

        await tool_service.register_tool(
            db,
            tool,
            created_by=metadata["created_by"],
            created_from_ip=metadata["created_from_ip"],
            created_via=metadata["created_via"],
            created_user_agent=metadata["created_user_agent"],
            import_batch_id=metadata["import_batch_id"],
            federation_source=metadata["federation_source"],
        )
        return ORJSONResponse(
            content={"message": "Tool registered successfully!", "success": True},
            status_code=200,
        )
    except IntegrityError as ex:
        error_message = ErrorFormatter.format_database_error(ex)
        LOGGER.error(f"IntegrityError in admin_add_tool: {error_message}")
        return ORJSONResponse(status_code=409, content=error_message)
    except ToolNameConflictError as ex:
        LOGGER.error(f"ToolNameConflictError in admin_add_tool: {str(ex)}")
        return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=409)
    except ToolError as ex:
        return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=500)
    except ValidationError as ex:  # This block should catch ValidationError
        LOGGER.error(f"ValidationError in admin_add_tool: {str(ex)}")
        return ORJSONResponse(content=ErrorFormatter.format_validation_error(ex), status_code=422)
    except Exception as ex:
        LOGGER.error(f"Unexpected error in admin_add_tool: {str(ex)}")
        return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=500)


@router.post("/tools/{tool_id}/edit/", response_model=None)
@router.post("/tools/{tool_id}/edit", response_model=None)
@require_permission("tools.update", allow_admin_bypass=False)
async def admin_edit_tool(
    tool_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> Response:
    """
    Edit a tool via the admin UI.

    Expects form fields:
      - name
      - displayName (optional)
      - url
      - description (optional)
      - requestType (to be mapped to request_type)
      - integrationType (to be mapped to integration_type)
      - headers (as a JSON string)
      - input_schema (as a JSON string)
      - output_schema (as a JSON string, optional)
      - jsonpathFilter (optional)
      - auth_type (optional, string: "basic", "bearer", or empty)
      - auth_username (optional, for basic auth)
      - auth_password (optional, for basic auth)
      - auth_token (optional, for bearer auth)
      - auth_header_key (optional, for headers auth)
      - auth_header_value (optional, for headers auth)

    Assembles the tool_data dictionary by remapping form keys into the
    snake-case keys expected by the schemas.

    Args:
        tool_id (str): The ID of the tool to edit.
        request (Request): FastAPI request containing form data.
        db (Session): Database session dependency.
        user (str): Authenticated user dependency.

    Returns:
        Response: A redirect response to the tools section of the admin
            dashboard with a status code of 303 (See Other), or a JSON response with
            an error message if the update fails.

    Raises:
        HTTPException: 422 when public visibility is disabled and request is team-scoped.

    Examples:
        >>> callable(admin_edit_tool)
        True
        >>> admin_edit_tool.__name__
        'admin_edit_tool'
    """
    LOGGER.debug(f"User {get_user_email(user)} is editing tool ID {tool_id}")
    form = await request.form()
    team_id = _form_team_id(form)
    # Parse tags from comma-separated string
    tags_str = str(form.get("tags", ""))
    tags: list[str] = [tag.strip() for tag in tags_str.split(",") if tag.strip()] if tags_str else []

    # Build auth object from form fields
    auth_obj = _build_auth_obj_from_form(form)

    visibility = str(form.get("visibility", "private"))
    _check_public_visibility_allowed(visibility, team_id=team_id)

    user_email = get_user_email(user)
    LOGGER.info(f"before Verifying team for user {user_email} with team_id {team_id}")
    team_service = TeamManagementService(db)
    team_id = await team_service.verify_team_for_user(user_email, team_id)

    headers_raw2 = form.get("headers")
    input_schema_raw2 = form.get("input_schema")
    output_schema_raw2 = form.get("output_schema")
    annotations_raw2 = form.get("annotations")

    # Parse JSON fields with validation
    try:
        headers = orjson.loads(headers_raw2 if isinstance(headers_raw2, str) and headers_raw2 else "{}")
        input_schema = orjson.loads(input_schema_raw2 if isinstance(input_schema_raw2, str) and input_schema_raw2 else "{}")
        output_schema = orjson.loads(output_schema_raw2) if isinstance(output_schema_raw2, str) and output_schema_raw2 else None
        annotations = orjson.loads(annotations_raw2 if isinstance(annotations_raw2, str) and annotations_raw2 else "{}")
    except orjson.JSONDecodeError as ex:
        LOGGER.error(f"Invalid JSON in form field: {str(ex)}")
        return ORJSONResponse(
            content={"message": f"Invalid JSON in form field: {str(ex)}", "success": False},
            status_code=422,
        )

    tool_data: dict[str, Any] = {
        "name": form.get("name"),
        "displayName": form.get("displayName"),
        "custom_name": form.get("customName"),
        "url": form.get("url"),
        "description": form.get("description"),
        "headers": headers,
        "input_schema": input_schema,
        "output_schema": output_schema,
        "annotations": annotations,
        "jsonpath_filter": form.get("jsonpathFilter", ""),
        "auth": auth_obj,
        "tags": tags,
        "visibility": visibility,
        "owner_email": user_email,
        "team_id": team_id,
    }
    # Only include integration_type if it's provided (not disabled in form)
    if "integrationType" in form:
        tool_data["integration_type"] = form.get("integrationType")
    # Only include request_type if it's provided (not disabled in form)
    if "requestType" in form:
        tool_data["request_type"] = form.get("requestType")
    LOGGER.debug(f"Tool update data built: {tool_data}")
    try:
        tool = ToolUpdate(**tool_data)  # Pydantic validation happens here

        # Get current tool to extract current version
        current_tool = db.get(DbTool, tool_id)
        current_version = getattr(current_tool, "version", 0) if current_tool else 0

        # Extract modification metadata
        mod_metadata = MetadataCapture.extract_modification_metadata(request, user, current_version)

        await tool_service.update_tool(
            db,
            tool_id,
            tool,
            modified_by=mod_metadata["modified_by"],
            modified_from_ip=mod_metadata["modified_from_ip"],
            modified_via=mod_metadata["modified_via"],
            modified_user_agent=mod_metadata["modified_user_agent"],
            user_email=user_email,
        )
        return ORJSONResponse(content={"message": "Edit tool successfully", "success": True}, status_code=200)
    except PermissionError as e:
        LOGGER.info(f"Permission denied for user {get_user_email(user)}: {e}")
        return ORJSONResponse(
            content={"message": str(e), "success": False},
            status_code=403,
        )
    except IntegrityError as ex:
        error_message = ErrorFormatter.format_database_error(ex)
        LOGGER.error(f"IntegrityError in admin_tool_resource: {error_message}")
        return ORJSONResponse(status_code=409, content=error_message)
    except ToolNameConflictError as ex:
        LOGGER.error(f"ToolNameConflictError in admin_edit_tool: {str(ex)}")
        return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=409)
    except ToolError as ex:
        LOGGER.error(f"ToolError in admin_edit_tool: {str(ex)}")
        return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=500)
    except ValidationError as ex:  # Catch Pydantic validation errors
        LOGGER.error(f"ValidationError in admin_edit_tool: {str(ex)}")
        return ORJSONResponse(content=ErrorFormatter.format_validation_error(ex), status_code=422)
    except Exception as ex:  # Generic catch-all for unexpected errors
        LOGGER.exception(f"Unexpected error in admin_edit_tool: {ex}")
        return ORJSONResponse(content={"message": "An unexpected error occurred. Please try again or contact support.", "success": False}, status_code=500)


@router.post("/tools/generate-schemas-from-openapi")
# tools.create — this endpoint makes outbound HTTP requests to user-supplied
# URLs to fetch OpenAPI specs.  tools.read would let viewers probe internal
# services; tools.create scopes it to users who can already register tools.
@require_permission("tools.create", allow_admin_bypass=False)
async def generate_schemas_from_openapi(
    request: Request,
    _user=Depends(get_current_user_with_permissions),
) -> JSONResponse:
    """
    Generate input_schema and output_schema from OpenAPI specification URL.

    Expects JSON body with:
      - url: The tool URL (e.g., http://localhost:8100/calculate)
      - request_type: HTTP method (GET, POST, etc.)
      - openapi_url: (optional) Direct OpenAPI spec URL

    Args:
        request: FastAPI Request object containing JSON body

    Returns:
        JSONResponse with generated schemas or error message.
    """
    try:
        body = await _read_request_json(request)
    except Exception:
        return ORJSONResponse(
            content={"message": "Invalid JSON in request body", "success": False},
            status_code=400,
        )

    if not isinstance(body, dict):
        return ORJSONResponse(
            content={"message": "Request body must be a JSON object", "success": False},
            status_code=400,
        )

    tool_url = body.get("url", "")
    request_type = body.get("request_type", "GET")
    openapi_url = body.get("openapi_url", "")

    if not isinstance(tool_url, str) or not isinstance(request_type, str) or not isinstance(openapi_url, str):
        return ORJSONResponse(
            content={"message": "'url', 'request_type', and 'openapi_url' must be strings", "success": False},
            status_code=400,
        )

    tool_url = tool_url.strip()
    request_type = request_type.strip()
    openapi_url = openapi_url.strip()

    if not tool_url:
        return ORJSONResponse(
            content={"message": "'url' is required to identify the API path and base URL", "success": False},
            status_code=400,
        )

    try:
        SecurityValidator.validate_url(tool_url, "Tool URL")
    except ValueError as e:
        return ORJSONResponse(
            content={"message": str(e), "success": False},
            status_code=400,
        )

    parsed = urllib.parse.urlparse(tool_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    tool_path = parsed.path

    try:
        input_schema, output_schema, spec_url = await fetch_and_extract_schemas(
            base_url=base_url,
            path=tool_path,
            method=request_type,
            openapi_url=openapi_url,
            timeout=10.0,
        )
    except ValueError as e:
        return ORJSONResponse(
            content={"message": f"Security validation failed: {str(e)}", "success": False},
            status_code=400,
        )
    except KeyError as e:
        return ORJSONResponse(
            content={"message": str(e), "success": False},
            status_code=404,
        )
    except httpx.HTTPStatusError as e:
        LOGGER.warning("OpenAPI spec server returned HTTP %s", e.response.status_code, exc_info=True)
        return ORJSONResponse(
            content={"message": f"OpenAPI spec server returned HTTP {e.response.status_code}", "success": False},
            status_code=502,
        )
    except httpx.HTTPError:
        LOGGER.warning("Failed to fetch OpenAPI spec", exc_info=True)
        return ORJSONResponse(
            content={"message": "Failed to fetch OpenAPI spec from the provided URL", "success": False},
            status_code=502,
        )
    except Exception:
        LOGGER.error("Error fetching OpenAPI spec", exc_info=True)
        return ORJSONResponse(
            content={"message": "An unexpected error occurred while processing the OpenAPI spec", "success": False},
            status_code=500,
        )

    return ORJSONResponse(
        content={
            "message": "Schemas generated successfully from OpenAPI spec",
            "success": True,
            "input_schema": input_schema,
            "output_schema": output_schema,
            "spec_url": spec_url,
        },
        status_code=200,
    )


@router.post("/tools/{tool_id}/delete")
@require_permission("tools.delete", allow_admin_bypass=False)
async def admin_delete_tool(tool_id: str, request: Request, db: Session = Depends(get_db), user=Depends(get_current_user_with_permissions)) -> RedirectResponse:
    """
    Delete a tool via the admin UI.

    This endpoint permanently removes a tool from the database using its ID.
    It is irreversible and should be used with caution. The operation is logged,
    and the user must be authenticated to access this route.

    Args:
        tool_id (str): The ID of the tool to delete.
        request (Request): FastAPI request object (not used directly, but required by route signature).
        db (Session): Database session dependency.
        user (str): Authenticated user dependency.

    Returns:
        RedirectResponse: A redirect response to the tools section of the admin
        dashboard with a status code of 303 (See Other).

    Examples:
        >>> callable(admin_delete_tool)
        True
        >>> admin_delete_tool.__name__
        'admin_delete_tool'
    """
    form = await request.form()
    is_inactive_checked = str(form.get("is_inactive_checked", "false"))
    purge_metrics = str(form.get("purge_metrics", "false")).lower() == "true"
    user_email = get_user_email(user)
    LOGGER.debug(f"User {user_email} is deleting tool ID {tool_id}")
    error_message = None
    try:
        await tool_service.delete_tool(db, tool_id, user_email=user_email, purge_metrics=purge_metrics)
    except PermissionError as e:
        LOGGER.warning(f"Permission denied for user {user_email} deleting tool {tool_id}: {e}")
        error_message = str(e)
    except Exception as e:
        LOGGER.error(f"Error deleting tool: {e}")
        error_message = "Failed to delete tool. Please try again."

    root_path = _resolve_root_path(request)
    team_id = str(form.get("team_id", "") or "")
    redirect_url = _build_admin_redirect(root_path, "tools", error=error_message, include_inactive=is_inactive_checked.lower() == "true", team_id=team_id)
    return RedirectResponse(redirect_url, status_code=303)


@router.post("/tools/{tool_id}/state")
@require_permission("tools.update", allow_admin_bypass=False)
async def admin_set_tool_state(
    tool_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> RedirectResponse:
    """
    Toggle a tool's active status via the admin UI.

    This endpoint processes a form request to activate or deactivate a tool.
    It expects a form field 'activate' with value "true" to activate the tool
    or "false" to deactivate it. The endpoint handles exceptions gracefully and
    logs any errors that might occur during the status toggle operation.

    Args:
        tool_id (str): The ID of the tool whose status to toggle.
        request (Request): FastAPI request containing form data with the 'activate' field.
        db (Session): Database session dependency.
        user (str): Authenticated user dependency.

    Returns:
        RedirectResponse: A redirect to the admin dashboard tools section with a
        status code of 303 (See Other).

    Examples:
        >>> callable(admin_set_tool_state)
        True
        >>> admin_set_tool_state.__name__
        'admin_set_tool_state'
    """
    error_message = None
    user_email = get_user_email(user)
    LOGGER.debug(f"User {user_email} is toggling tool ID {tool_id}")
    form = await request.form()
    activate = str(form.get("activate", "true")).lower() == "true"
    is_inactive_checked = str(form.get("is_inactive_checked", "false"))
    try:
        await tool_service.set_tool_state(db, tool_id, activate, reachable=activate, user_email=user_email)
    except PermissionError as e:
        LOGGER.warning(f"Permission denied for user {user_email} setting tool state {tool_id}: {e}")
        error_message = str(e)
    except ToolLockConflictError as e:
        LOGGER.warning(f"Lock conflict for user {user_email} setting tool {tool_id} state: {e}")
        error_message = "Tool is being modified by another request. Please try again."
    except Exception as e:
        LOGGER.error(f"Error setting tool state: {e}")
        error_message = "Failed to set tool state. Please try again."

    root_path = _resolve_root_path(request)
    team_id = str(form.get("team_id", "") or "")
    redirect_url = _build_admin_redirect(root_path, "tools", error=error_message, include_inactive=is_inactive_checked.lower() == "true", team_id=team_id)
    return RedirectResponse(redirect_url, status_code=303)
