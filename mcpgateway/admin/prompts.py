# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/admin/prompts.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Admin UI prompt routes: list, partial, ids, search, detail, create, edit,
delete, and state change.
"""

# Standard
import binascii
import logging
from typing import Any, Dict, List, Optional

# Third-Party
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import ValidationError
from sqlalchemy import and_, case, desc, false, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
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
    _validated_team_id_param,
    prompt_service,
)
from mcpgateway.admin.security import enforce_admin_csrf
from mcpgateway.auth_context import get_scoped_resource_access_context, get_token_teams_from_request, get_user_email
from mcpgateway.common.query_params import QueryGatewayIdList, QueryRenderMode, QueryTagsFilter
from mcpgateway.config import settings
from mcpgateway.db import EmailTeam, get_db, Prompt as DbPrompt
from mcpgateway.middleware.rbac import get_current_user_with_permissions, require_permission
from mcpgateway.schemas import PaginatedResponse, PromptCreate, PromptRead, PromptUpdate
from mcpgateway.services.content_security import ContentSizeError, TemplateValidationError
from mcpgateway.services.prompt_service import PromptArgumentsJSONError, PromptNameConflictError, PromptNotFoundError
from mcpgateway.services.team_management_service import TeamManagementService
from mcpgateway.utils.error_formatter import ErrorFormatter, sanitize_validation_error_for_log
from mcpgateway.utils.metadata_capture import MetadataCapture
from mcpgateway.utils.orjson_response import ORJSONResponse
from mcpgateway.utils.pagination import paginate_query
from mcpgateway.utils.paths import resolve_root_path as _resolve_root_path

LOGGER: logging.Logger = logging.getLogger("mcpgateway.admin")

# mcpgateway.admin (__init__) appends this router's routes to admin_router, so the
# prefix, tags, and CSRF dependency must mirror admin_router exactly.
router = APIRouter(
    prefix="/admin",
    tags=["Admin UI"],
    dependencies=[Depends(enforce_admin_csrf)],
)


@router.get("/prompts", response_model=PaginatedResponse)
@require_permission("prompts.read", allow_admin_bypass=False)
async def admin_list_prompts(
    request: Request,
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    per_page: int = Query(settings.pagination_default_page_size, ge=1, le=settings.pagination_max_page_size, description="Items per page"),
    include_inactive: bool = False,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> Dict[str, Any]:
    """
    List prompts for the admin UI with pagination support.

    This endpoint retrieves a paginated list of prompts from the database, optionally
    including those that are inactive. Uses offset-based (page/per_page) pagination.

    Args:
        request (Request): FastAPI request object (required for token team extraction via request.state.token_teams).
        page (int): Page number (1-indexed) for offset pagination.
        per_page (int): Number of items per page.
        include_inactive (bool): Whether to include inactive prompts in the results.
        db (Session): Database session dependency.
        user (str): Authenticated user dependency.

    Returns:
        Dict[str, Any]: A dictionary containing:
            - data: List of prompt records formatted with by_alias=True
            - pagination: Pagination metadata
            - links: Pagination links (optional)

    Examples:
        >>> callable(admin_list_prompts)
        True
        >>> admin_list_prompts.__name__
        'admin_list_prompts'
    """
    user_email = get_user_email(user)
    token_teams = get_token_teams_from_request(request)
    LOGGER.debug(f"User {user_email} requested prompt list (page={page}, per_page={per_page})")

    # Call prompt_service.list_prompts with page-based pagination
    paginated_result = await prompt_service.list_prompts(
        db=db,
        include_inactive=include_inactive,
        page=page,
        per_page=per_page,
        user_email=user_email,
        token_teams=token_teams,
    )

    # Return standardized paginated response
    return {
        "data": [prompt.model_dump(by_alias=True) for prompt in paginated_result["data"]],
        "pagination": paginated_result["pagination"].model_dump(),
        "links": paginated_result["links"].model_dump() if paginated_result["links"] else None,
    }


@router.get("/prompts/partial", response_class=HTMLResponse)
@require_permission("prompts.read", allow_admin_bypass=False)
async def admin_prompts_partial_html(
    request: Request,
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    per_page: int = Query(settings.pagination_default_page_size, ge=1, le=settings.pagination_max_page_size, description="Items per page"),
    q: str = Query("", max_length=500, description="Search query"),
    tags: QueryTagsFilter = None,
    include_inactive: bool = False,
    render: QueryRenderMode = None,
    gateway_id: QueryGatewayIdList = None,
    team_id: Optional[str] = Depends(_validated_team_id_param),
    include_public: bool = False,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    """Return paginated prompts HTML partials for the admin UI.

    This HTMX endpoint returns only the partial HTML used by the admin UI for
    prompts. It supports three render modes:

    - default: full table partial (rows + controls)
    - ``render="controls"``: return only pagination controls
    - ``render="selector"``: return selector items for infinite scroll

    Args:
        request (Request): FastAPI request object used by the template engine.
        page (int): Page number (1-indexed).
        per_page (int): Number of items per page (bounded by settings).
        q (str): Free-text query string.
        tags (Optional[str]): Tag filter expression (comma=OR, plus=AND).
        include_inactive (bool): If True, include inactive prompts in results.
        render (Optional[str]): Render mode; one of None, "controls", "selector".
        gateway_id (Optional[str]): Filter by gateway ID(s), comma-separated.
        team_id (Optional[str]): Filter by team ID.
        include_public (bool): Whether to include all public prompts in the results.
        db (Session): Database session (dependency-injected).
        user: Authenticated user object from dependency injection.

    Returns:
        Union[HTMLResponse, TemplateResponse]: A rendered template response
        containing either the table partial, pagination controls, or selector
        items depending on ``render``. The response contains JSON-serializable
        encoded prompt data when templates expect it.
    """
    LOGGER.debug(
        f"User {get_user_email(user)} requested prompts HTML partial (page={page}, per_page={per_page}, include_inactive={include_inactive}, render={render}, gateway_id={gateway_id}, team_id={team_id})"
    )
    search_query = _normalize_search_query(q)
    normalized_tags = _normalize_tags_query(tags)
    tag_groups = _parse_tag_filter_groups(normalized_tags)
    # Normalize per_page within configured bounds
    per_page = max(settings.pagination_min_page_size, min(per_page, settings.pagination_max_page_size))

    user_email = get_user_email(user)

    # Team scoping
    team_ids = await _get_user_team_ids(user, db)

    # Build base query
    query = select(DbPrompt)

    # Apply gateway filter if provided
    if gateway_id:
        gateway_ids = [gid.strip() for gid in gateway_id.split(",") if gid.strip()]
        if gateway_ids:
            null_requested = any(gid.lower() == "null" for gid in gateway_ids)
            non_null_ids = [gid for gid in gateway_ids if gid.lower() != "null"]
            if non_null_ids and null_requested:
                query = query.where(or_(DbPrompt.gateway_id.in_(non_null_ids), DbPrompt.gateway_id.is_(None)))
                LOGGER.debug(f"Filtering prompts by gateway IDs (including NULL): {non_null_ids} + NULL")
            elif null_requested:
                query = query.where(DbPrompt.gateway_id.is_(None))
                LOGGER.debug("Filtering prompts by NULL gateway_id (RestTool)")
            else:
                query = query.where(DbPrompt.gateway_id.in_(non_null_ids))
                LOGGER.debug(f"Filtering prompts by gateway IDs: {non_null_ids}")

    if not include_inactive:
        query = query.where(DbPrompt.enabled.is_(True))

    # Build access conditions
    # When team_id is specified, show ONLY items from that team (team-scoped view)
    # When team_id + include_public, show team items PLUS public items from all teams
    # Otherwise, show all accessible items (All Teams view)
    if team_id:
        # Team-specific view: only show prompts from the specified team
        if team_id in team_ids:
            # Apply visibility check: team/public resources + user's own resources (including private)
            team_access = [
                and_(DbPrompt.team_id == team_id, DbPrompt.visibility.in_(["team", "public"])),
                and_(DbPrompt.team_id == team_id, DbPrompt.owner_email == user_email),
            ]
            if include_public:
                # Include all globally public items from any team.
                # Items with visibility='team' or 'private' from other teams are
                # blocked by the other conditions (which require team_id == selected team).
                team_access.append(DbPrompt.visibility == "public")
            query = query.where(or_(*team_access))
            LOGGER.debug(f"Filtering prompts by team_id: {team_id}{' (include_public)' if include_public else ''}")
        else:
            # User is not a member of this team, return no results using SQLAlchemy's false()
            LOGGER.warning(f"User {user_email} attempted to filter by team {team_id} but is not a member")
            query = query.where(false())
    else:
        # All Teams view: apply standard access conditions (owner, team, public)
        access_conditions = []
        access_conditions.append(_owner_access_condition(DbPrompt.owner_email, DbPrompt.team_id, user_email=user_email, team_ids=team_ids, user=user))
        if team_ids:
            access_conditions.append(and_(DbPrompt.team_id.in_(team_ids), DbPrompt.visibility.in_(["team", "public"])))
        access_conditions.append(DbPrompt.visibility == "public")
        query = query.where(or_(*access_conditions))

    if search_query:
        query = query.where(
            or_(
                _like_contains(func.lower(DbPrompt.id), search_query),
                _like_contains(func.lower(DbPrompt.original_name), search_query),
                _like_contains(func.lower(coalesce(DbPrompt.display_name, "")), search_query),
                _like_contains(func.lower(coalesce(DbPrompt.description, "")), search_query),
            )
        )

    query = _apply_tag_filter_groups(query, db, DbPrompt.tags, tag_groups)

    # Apply pagination ordering for cursor support
    query = query.order_by(desc(DbPrompt.created_at), desc(DbPrompt.id))

    # Build query params for pagination links
    query_params = {}
    if include_inactive:
        query_params["include_inactive"] = "true"
    if gateway_id:
        query_params["gateway_id"] = gateway_id
    if team_id:
        query_params["team_id"] = team_id
    if search_query:
        query_params["q"] = search_query
    if normalized_tags:
        query_params["tags"] = normalized_tags

    # Use unified pagination function
    root_path = _resolve_root_path(request)
    base_url = f"{root_path}/admin/prompts/partial"
    paginated_result = await paginate_query(
        db=db,
        query=query,
        page=page,
        per_page=per_page,
        cursor=None,  # HTMX partials use page-based navigation
        base_url=base_url,
        query_params=query_params,
        use_cursor_threshold=False,  # Disable auto-cursor switching for UI
    )

    # Extract paginated prompts (DbPrompt objects)
    prompts_db = paginated_result["data"]
    pagination = paginated_result["pagination"]
    links = paginated_result["links"]

    # Batch fetch team names for the prompts to avoid N+1 queries
    team_ids_set = {p.team_id for p in prompts_db if p.team_id}
    team_map = {}
    if team_ids_set:
        teams = db.execute(select(EmailTeam.id, EmailTeam.name).where(EmailTeam.id.in_(team_ids_set), EmailTeam.is_active.is_(True))).all()
        team_map = {team.id: team.name for team in teams}

    # Apply team names to DB objects before conversion
    for p in prompts_db:
        p.team = team_map.get(p.team_id) if p.team_id else None

    # Batch convert to Pydantic models using prompt service
    # This eliminates the N+1 query problem from calling get_prompt_details() in a loop
    prompts_pydantic = []
    failed_count = 0
    for p in prompts_db:
        try:
            prompts_pydantic.append(prompt_service.convert_prompt_to_read(p, include_metrics=False))
        except (ValidationError, ValueError, KeyError, TypeError, binascii.Error) as e:
            failed_count += 1
            LOGGER.exception(f"Failed to convert prompt {getattr(p, 'id', 'unknown')} ({getattr(p, 'name', 'unknown')}): {e}")
    _adjust_pagination_for_conversion_failures(pagination, failed_count, len(prompts_pydantic))

    data = jsonable_encoder(prompts_pydantic)

    # End the read-only transaction before template rendering to avoid idle-in-transaction timeouts.
    db.commit()

    if render == "controls":
        return request.app.state.templates.TemplateResponse(
            request,
            "pagination_controls.html",
            {
                "request": request,
                "pagination": pagination.model_dump(),
                "base_url": base_url,
                "hx_target": "#prompts-table-body",
                "hx_indicator": "#prompts-loading",
                "query_params": query_params,
                "root_path": _resolve_root_path(request),
            },
        )

    if render == "selector":
        return request.app.state.templates.TemplateResponse(
            request,
            "prompts_selector_items.html",
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

    _is_admin = bool(user.get("is_admin", False) if isinstance(user, dict) else getattr(user, "is_admin", False))
    _team_roles = _get_user_team_roles(db, user_email) if not _is_admin else {}
    return request.app.state.templates.TemplateResponse(
        request,
        "prompts_partial.html",
        {
            "request": request,
            "data": data,
            "pagination": pagination.model_dump(),
            "links": links.model_dump() if links else None,
            "root_path": _resolve_root_path(request),
            "include_inactive": include_inactive,
            "query_params": query_params,
            "current_user_email": user_email,
            "is_admin": _is_admin,
            "user_team_roles": _team_roles,
        },
    )


@router.get("/prompts/ids", response_class=JSONResponse)
@require_permission("prompts.read", allow_admin_bypass=False)
async def admin_get_all_prompt_ids(
    q: str = Query("", max_length=500, description="Search query"),
    include_inactive: bool = False,
    gateway_id: QueryGatewayIdList = None,
    team_id: Optional[str] = Depends(_validated_team_id_param),
    include_public: bool = False,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    """Return all prompt IDs accessible to the current user (select-all helper).

    This endpoint is used by UI "Select All" helpers to fetch only the IDs
    of prompts the requesting user can access (owner, team, or public).

    Args:
        q (str): Search query to filter prompts by name or description.
        include_inactive (bool): When True include prompts that are inactive.
        gateway_id (Optional[str]): Filter by gateway ID(s), comma-separated. Accepts the literal value 'null' to indicate NULL gateway_id (local prompts).
        team_id (Optional[str]): Filter by team ID.
        include_public (bool): Whether to include all platform-public prompts when filtering by team.
        db (Session): Database session (injected dependency).
        user: Authenticated user object from dependency injection.

    Returns:
        dict: A dictionary containing two keys:
            - "prompt_ids": List[str] of accessible prompt IDs.
            - "count": int number of IDs returned.
    """
    user_email = get_user_email(user)
    team_ids = await _get_user_team_ids(user, db)

    query = select(DbPrompt.id)

    if not include_inactive:
        query = query.where(DbPrompt.enabled.is_(True))

    # Apply search filter if provided
    if q:
        search_query = _normalize_search_query(q)
        if search_query:
            search_conditions = [
                _like_contains(func.lower(DbPrompt.id), search_query),
                _like_contains(func.lower(DbPrompt.original_name), search_query),
                _like_contains(func.lower(coalesce(DbPrompt.display_name, "")), search_query),
                _like_contains(func.lower(coalesce(DbPrompt.description, "")), search_query),
            ]
            query = query.where(or_(*search_conditions))
            LOGGER.debug(f"Filtering prompt IDs by search query: {search_query}")

    # Apply optional gateway/server scoping
    if gateway_id:
        gateway_ids = [gid.strip() for gid in gateway_id.split(",") if gid.strip()]
        if gateway_ids:
            null_requested = any(gid.lower() == "null" for gid in gateway_ids)
            non_null_ids = [gid for gid in gateway_ids if gid.lower() != "null"]
            if non_null_ids and null_requested:
                query = query.where(or_(DbPrompt.gateway_id.in_(non_null_ids), DbPrompt.gateway_id.is_(None)))
                LOGGER.debug(f"Filtering prompts by gateway IDs (including NULL): {non_null_ids} + NULL")
            elif null_requested:
                query = query.where(DbPrompt.gateway_id.is_(None))
                LOGGER.debug("Filtering prompts by NULL gateway_id (RestTool)")
            else:
                query = query.where(DbPrompt.gateway_id.in_(non_null_ids))
                LOGGER.debug(f"Filtering prompts by gateway IDs: {non_null_ids}")

    # Build access conditions
    # When team_id is specified, show items from that team; optionally include
    # platform-public items when include_public is set (mirrors the partial endpoint).
    # Otherwise, show all accessible items (All Teams view).
    if team_id:
        if team_id in team_ids:
            team_access = [
                and_(DbPrompt.team_id == team_id, DbPrompt.visibility.in_(["team", "public"])),
                and_(DbPrompt.team_id == team_id, DbPrompt.owner_email == user_email),
            ]
            if include_public:
                team_access.append(DbPrompt.visibility == "public")
            query = query.where(or_(*team_access))
            LOGGER.debug(f"Filtering prompt IDs by team_id: {team_id}{' (include_public)' if include_public else ''}")
        else:
            # User is not a member of this team, return no results using SQLAlchemy's false()
            LOGGER.warning(f"User {user_email} attempted to filter prompt IDs by team {team_id} but is not a member")
            query = query.where(false())
    else:
        # All Teams view: apply standard access conditions (owner, team, public)
        access_conditions = []
        access_conditions.append(_owner_access_condition(DbPrompt.owner_email, DbPrompt.team_id, user_email=user_email, team_ids=team_ids, user=user))
        if team_ids:
            access_conditions.append(and_(DbPrompt.team_id.in_(team_ids), DbPrompt.visibility.in_(["team", "public"])))
        access_conditions.append(DbPrompt.visibility == "public")
        query = query.where(or_(*access_conditions))

    prompt_ids = [row[0] for row in db.execute(query).all()]
    return {"prompt_ids": prompt_ids, "count": len(prompt_ids)}


@router.get("/prompts/search", response_class=JSONResponse)
@require_permission("prompts.read", allow_admin_bypass=False)
async def admin_search_prompts(
    q: str = Query("", max_length=500, description="Search query"),
    tags: QueryTagsFilter = None,
    include_inactive: bool = False,
    limit: int = Query(settings.pagination_default_page_size, ge=1, le=settings.pagination_max_page_size),
    gateway_id: QueryGatewayIdList = None,
    team_id: Optional[str] = Depends(_validated_team_id_param),
    include_public: bool = False,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    """Search prompts by name or description for selector search.

    Performs a case-insensitive search over prompt names and descriptions
    and returns a limited list of matching prompts suitable for selector
    UIs (id, name, description).

    Args:
        q (str): Search query string.
        tags (Optional[str]): Tag filter expression (comma=OR, plus=AND).
        include_inactive (bool): When True include prompts that are inactive.
        limit (int): Maximum number of results to return (bounded by the query parameter).
        gateway_id (Optional[str]): Filter by gateway ID(s), comma-separated.
        team_id (Optional[str]): Filter by team ID.
        include_public (bool): Whether to include all public prompts in the results.
        db (Session): Database session (injected dependency).
        user: Authenticated user object from dependency injection.

    Returns:
        dict: A dictionary containing:
            - "prompts": List[dict] where each dict has keys "id", "name", "description".
            - "count": int number of matched prompts returned.
    """
    user_email = get_user_email(user)
    search_query = _normalize_search_query(q)
    normalized_tags = _normalize_tags_query(tags)
    tag_groups = _parse_tag_filter_groups(normalized_tags)
    if not search_query and not tag_groups:
        return _build_search_response(entity_key="prompts", entity_type="prompts", items=[], query=search_query, tags=normalized_tags, tag_groups=tag_groups)

    team_ids = await _get_user_team_ids(user, db)

    query = select(DbPrompt.id, DbPrompt.original_name, DbPrompt.display_name, DbPrompt.description)

    # Apply gateway filter if provided
    if gateway_id:
        gateway_ids = [gid.strip() for gid in gateway_id.split(",") if gid.strip()]
        if gateway_ids:
            null_requested = any(gid.lower() == "null" for gid in gateway_ids)
            non_null_ids = [gid for gid in gateway_ids if gid.lower() != "null"]
            if non_null_ids and null_requested:
                query = query.where(or_(DbPrompt.gateway_id.in_(non_null_ids), DbPrompt.gateway_id.is_(None)))
                LOGGER.debug(f"Filtering prompt search by gateway IDs (including NULL): {non_null_ids} + NULL")
            elif null_requested:
                query = query.where(DbPrompt.gateway_id.is_(None))
                LOGGER.debug("Filtering prompt search by NULL gateway_id")
            else:
                query = query.where(DbPrompt.gateway_id.in_(non_null_ids))
                LOGGER.debug(f"Filtering prompt search by gateway IDs: {non_null_ids}")

    if not include_inactive:
        query = query.where(DbPrompt.enabled.is_(True))

    # Build access conditions
    # When team_id is specified, show ONLY items from that team (team-scoped view)
    # When team_id + include_public, show team items PLUS public items from all teams
    # Otherwise, show all accessible items (All Teams view)
    if team_id:
        # Team-specific view: only show prompts from the specified team
        if team_id in team_ids:
            # Apply visibility check: team/public resources + user's own resources (including private)
            team_access = [
                and_(DbPrompt.team_id == team_id, DbPrompt.visibility.in_(["team", "public"])),
                and_(DbPrompt.team_id == team_id, DbPrompt.owner_email == user_email),
            ]
            if include_public:
                team_access.append(DbPrompt.visibility == "public")
            query = query.where(or_(*team_access))
            LOGGER.debug(f"Filtering prompt search by team_id: {team_id}{' (include_public)' if include_public else ''}")
        else:
            # User is not a member of this team, return no results using SQLAlchemy's false()
            LOGGER.warning(f"User {user_email} attempted to filter prompt search by team {team_id} but is not a member")
            query = query.where(false())
    else:
        # All Teams view: apply standard access conditions (owner, team, public)
        access_conditions = []
        access_conditions.append(_owner_access_condition(DbPrompt.owner_email, DbPrompt.team_id, user_email=user_email, team_ids=team_ids, user=user))
        if team_ids:
            access_conditions.append(and_(DbPrompt.team_id.in_(team_ids), DbPrompt.visibility.in_(["team", "public"])))
        access_conditions.append(DbPrompt.visibility == "public")
        query = query.where(or_(*access_conditions))

    if search_query:
        search_conditions = [
            _like_contains(func.lower(DbPrompt.id), search_query),
            _like_contains(func.lower(DbPrompt.original_name), search_query),
            _like_contains(func.lower(coalesce(DbPrompt.display_name, "")), search_query),
            _like_contains(func.lower(coalesce(DbPrompt.description, "")), search_query),
        ]
        query = query.where(or_(*search_conditions))

    query = _apply_tag_filter_groups(query, db, DbPrompt.tags, tag_groups)

    if search_query:
        query = query.order_by(
            case(
                (func.lower(DbPrompt.original_name).startswith(search_query), 1),
                (func.lower(coalesce(DbPrompt.display_name, "")).startswith(search_query), 1),
                else_=2,
            ),
            func.lower(DbPrompt.original_name),
        )
    else:
        query = query.order_by(func.lower(DbPrompt.original_name))
    query = query.limit(limit)

    results = db.execute(query).all()
    prompts = []
    for row in results:
        prompts.append(
            {
                "id": row.id,
                "name": row.original_name,
                "original_name": row.original_name,
                "display_name": row.display_name,
                "description": row.description,
            }
        )

    return _build_search_response(entity_key="prompts", entity_type="prompts", items=prompts, query=search_query, tags=normalized_tags, tag_groups=tag_groups)


@router.get("/prompts/{prompt_id}")
@require_permission("prompts.read", allow_admin_bypass=False)
async def admin_get_prompt(prompt_id: str, request: Request, db: Session = Depends(get_db), user=Depends(get_current_user_with_permissions)) -> Dict[str, Any]:
    """Get prompt details for the admin UI.

    Args:
        prompt_id: Prompt ID.
        request: Incoming FastAPI request (for visibility scope resolution).
        db: Database session.
        user: Authenticated user.

    Returns:
        A dictionary with prompt details.

    Raises:
        HTTPException: If the prompt is not found.
        Exception: For any other unexpected errors.

    Examples:
        >>> callable(admin_get_prompt)
        True
        >>> admin_get_prompt.__name__
        'admin_get_prompt'
    """
    LOGGER.info(f"User {get_user_email(user)} requested details for prompt ID {prompt_id}")
    try:
        auth_user_email, auth_token_teams = get_scoped_resource_access_context(request, user)
        prompt_details = await prompt_service.get_prompt_details(
            db,
            prompt_id,
            user_email=auth_user_email,
            token_teams=auth_token_teams,
        )
        prompt = PromptRead.model_validate(prompt_details)
        return prompt.model_dump(by_alias=True)
    except PromptNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        LOGGER.error(f"Error getting prompt {prompt_id}: {e}")
        raise


@router.post("/prompts")
@require_permission("prompts.create", allow_admin_bypass=False)
async def admin_add_prompt(request: Request, db: Session = Depends(get_db), user=Depends(get_current_user_with_permissions)) -> JSONResponse:
    """Add a prompt via the admin UI.

    Expects form fields:
      - name
      - description (optional)
      - template
      - arguments (as a JSON string representing a list)

    Args:
        request: FastAPI request containing form data.
        db: Database session.
        user: Authenticated user.

    Returns:
        A redirect response to the admin dashboard.

    Raises:
        HTTPException: 422 when public visibility is disabled and request is team-scoped.

    Examples:
        >>> callable(admin_add_prompt)
        True
        >>> admin_add_prompt.__name__
        'admin_add_prompt'
    """
    LOGGER.debug(f"User {get_user_email(user)} is adding a new prompt")
    form = await request.form()
    team_id = _form_team_id(form)
    visibility = str(form.get("visibility", "private"))
    _check_public_visibility_allowed(visibility, team_id=team_id)
    user_email = get_user_email(user)
    team_service = TeamManagementService(db)
    team_id = await team_service.verify_team_for_user(user_email, team_id)

    # Parse tags from comma-separated string
    tags_str = str(form.get("tags", ""))
    tags: List[str] = [tag.strip() for tag in tags_str.split(",") if tag.strip()] if tags_str else []

    try:
        # Validate arguments JSON using prompt service
        arguments: List[Dict[str, Any]] = prompt_service.validate_arguments_json(args_value=form.get("arguments"), context="new prompt")
        prompt = PromptCreate(
            name=str(form["name"]),
            display_name=str(form.get("display_name") or form["name"]),
            description=str(form.get("description")),
            template=str(form["template"]),
            arguments=arguments,
            tags=tags,
            visibility=visibility,
            team_id=team_id,
            owner_email=user_email,
        )
        # Extract creation metadata
        metadata = MetadataCapture.extract_creation_metadata(request, user)

        await prompt_service.register_prompt(
            db,
            prompt,
            created_by=metadata["created_by"],
            created_from_ip=metadata["created_from_ip"],
            created_via=metadata["created_via"],
            created_user_agent=metadata["created_user_agent"],
            import_batch_id=metadata["import_batch_id"],
            federation_source=metadata["federation_source"],
            team_id=team_id,
            owner_email=user_email,
            visibility=visibility,
        )
        return ORJSONResponse(
            content={"message": "Prompt registered successfully!", "success": True},
            status_code=200,
        )
    except Exception as ex:
        if isinstance(ex, ValidationError):
            LOGGER.error("ValidationError in admin_add_prompt: %s", sanitize_validation_error_for_log(ex))
            return ORJSONResponse(content=ErrorFormatter.format_validation_error(ex), status_code=422)
        if isinstance(ex, IntegrityError):
            error_message = ErrorFormatter.format_database_error(ex)
            LOGGER.error(f"IntegrityError in admin_add_prompt: {error_message}")
            return ORJSONResponse(status_code=409, content=error_message)
        if isinstance(ex, PromptNameConflictError):
            LOGGER.error(f"PromptNameConflictError in admin_add_prompt: {ex}")
            return ORJSONResponse(status_code=409, content={"message": str(ex), "success": False})
        if isinstance(ex, PromptArgumentsJSONError):
            LOGGER.error(f"PromptArgumentsJSONError in admin_add_prompt: {ex}")
            return ORJSONResponse(
                status_code=422,
                content={
                    "message": f"Invalid JSON in {ex.field_name}: {ex.json_error}",
                    "field": ex.field_name,
                    "success": False,
                },
            )
        if isinstance(ex, ContentSizeError):
            LOGGER.error(f"ContentSizeError in admin_add_prompt: {ex}")
            return ORJSONResponse(status_code=413, content={"message": str(ex), "success": False})
        if isinstance(ex, TemplateValidationError):
            LOGGER.error(f"TemplateValidationError in admin_add_prompt: {ex}")
            return ORJSONResponse(
                status_code=400,
                content={
                    "message": f"Template validation failed: {ex.reason}",
                    "template_name": ex.template_name,
                    "reason": ex.reason,
                    "pattern": ex.pattern,
                    "success": False,
                },
            )

        LOGGER.exception(f"Unexpected error in admin_add_prompt: {ex}")
        return ORJSONResponse(content={"message": "An unexpected error occurred. Please try again or contact support.", "success": False}, status_code=500)


@router.post("/prompts/{prompt_id}/edit")
@require_permission("prompts.update", allow_admin_bypass=False)
async def admin_edit_prompt(
    prompt_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> JSONResponse:
    """Edit a prompt via the admin UI.

    Expects form fields:
        - name
        - description (optional)
        - template
        - arguments (as a JSON string representing a list)

    Args:
        prompt_id: Prompt ID.
        request: FastAPI request containing form data.
        db: Database session.
        user: Authenticated user.

    Returns:
        JSONResponse: A JSON response indicating success or failure of the server update operation.

    Raises:
        HTTPException: 422 when public visibility is disabled and request is team-scoped.

    Examples:
        >>> callable(admin_edit_prompt)
        True
        >>> admin_edit_prompt.__name__
        'admin_edit_prompt'
    """
    LOGGER.debug(f"User {get_user_email(user)} is editing prompt {prompt_id}")
    form = await request.form()
    team_id = _form_team_id(form)

    visibility = str(form.get("visibility", "private"))
    _check_public_visibility_allowed(visibility, team_id=team_id)
    user_email = get_user_email(user)

    # Preserve existing prompt's team_id when no explicit team_id is provided.
    # Without this guard, verify_team_for_user() falls back to the user's
    # personal team, silently reassigning the prompt on every edit.
    if not team_id:
        existing_prompt = db.get(DbPrompt, prompt_id)
        existing_team = getattr(existing_prompt, "team_id", None) if existing_prompt else None
        if isinstance(existing_team, str) and existing_team:
            team_id = existing_team

    team_service = TeamManagementService(db)
    team_id = await team_service.verify_team_for_user(user_email, team_id)

    # Parse tags from comma-separated string
    tags_str = str(form.get("tags", ""))
    tags: List[str] = [tag.strip() for tag in tags_str.split(",") if tag.strip()] if tags_str else []
    try:
        # Validate arguments JSON using prompt service; preserve existing when field absent
        args_value = form.get("arguments")
        arguments = prompt_service.validate_arguments_json(args_value, context="prompt update") if args_value is not None else None
        mod_metadata = MetadataCapture.extract_modification_metadata(request, user, 0)
        prompt = PromptUpdate(
            custom_name=str(form.get("customName") or form.get("name")),
            display_name=str(form.get("displayName") or form.get("display_name") or form.get("name")),
            description=str(form.get("description")),
            template=str(form["template"]),
            arguments=arguments,
            tags=tags,
            visibility=visibility,
            team_id=team_id,
            owner_email=user_email,
        )
        await prompt_service.update_prompt(
            db,
            prompt_id,
            prompt,
            modified_by=mod_metadata["modified_by"],
            modified_from_ip=mod_metadata["modified_from_ip"],
            modified_via=mod_metadata["modified_via"],
            modified_user_agent=mod_metadata["modified_user_agent"],
            user_email=user_email,
        )
        return ORJSONResponse(
            content={"message": "Prompt updated successfully!", "success": True},
            status_code=200,
        )
    except PermissionError as e:
        LOGGER.info(f"Permission denied for user {get_user_email(user)}: {e}")
        return ORJSONResponse(content={"message": str(e), "success": False}, status_code=403)
    except Exception as ex:
        if isinstance(ex, ValidationError):
            LOGGER.error("ValidationError in admin_edit_prompt: %s", sanitize_validation_error_for_log(ex))
            return ORJSONResponse(content=ErrorFormatter.format_validation_error(ex), status_code=422)
        if isinstance(ex, IntegrityError):
            error_message = ErrorFormatter.format_database_error(ex)
            LOGGER.error(f"IntegrityError in admin_edit_prompt: {error_message}")
            return ORJSONResponse(status_code=409, content=error_message)
        if isinstance(ex, PromptNameConflictError):
            LOGGER.error(f"PromptNameConflictError in admin_edit_prompt: {ex}")
            return ORJSONResponse(status_code=409, content={"message": str(ex), "success": False})
        if isinstance(ex, PromptArgumentsJSONError):
            LOGGER.error(f"PromptArgumentsJSONError in admin_edit_prompt: {ex}")
            return ORJSONResponse(
                status_code=422,
                content={
                    "message": f"Invalid JSON in {ex.field_name}: {ex.json_error}",
                    "field": ex.field_name,
                    "success": False,
                },
            )
        if isinstance(ex, ContentSizeError):
            LOGGER.error(f"ContentSizeError in admin_edit_prompt: {ex}")
            return ORJSONResponse(status_code=413, content={"message": str(ex), "success": False})
        if isinstance(ex, TemplateValidationError):
            LOGGER.error(f"TemplateValidationError in admin_edit_prompt: {ex}")
            return ORJSONResponse(
                status_code=400,
                content={
                    "message": f"Template validation failed: {ex.reason}",
                    "template_name": ex.template_name,
                    "reason": ex.reason,
                    "pattern": ex.pattern,
                    "success": False,
                },
            )
        LOGGER.exception(f"Unexpected error in admin_edit_prompt: {ex}")
        return ORJSONResponse(content={"message": "An unexpected error occurred. Please try again or contact support.", "success": False}, status_code=500)


@router.post("/prompts/{prompt_id}/delete")
@require_permission("prompts.delete", allow_admin_bypass=False)
async def admin_delete_prompt(prompt_id: str, request: Request, db: Session = Depends(get_db), user=Depends(get_current_user_with_permissions)) -> RedirectResponse:
    """
    Delete a prompt via the admin UI.

    This endpoint permanently deletes a prompt from the database using its ID.
    Deletion is irreversible and requires authentication. All actions are logged
    for administrative auditing.

    Args:
        prompt_id (str): The ID of the prompt to delete.
        request (Request): FastAPI request object (not used directly but required by the route signature).
        db (Session): Database session dependency.
        user (str): Authenticated user dependency.

    Returns:
        RedirectResponse: A redirect response to the prompts section of the admin
        dashboard with a status code of 303 (See Other).

    Examples:
        >>> callable(admin_delete_prompt)
        True
        >>> admin_delete_prompt.__name__
        'admin_delete_prompt'
    """
    form = await request.form()
    is_inactive_checked: str = str(form.get("is_inactive_checked", "false"))
    purge_metrics = str(form.get("purge_metrics", "false")).lower() == "true"
    user_email = get_user_email(user)
    LOGGER.info(f"User {get_user_email(user)} is deleting prompt id {prompt_id}")
    error_message = None
    try:
        await prompt_service.delete_prompt(db, prompt_id, user_email=user_email, purge_metrics=purge_metrics)
    except PermissionError as e:
        LOGGER.warning(f"Permission denied for user {user_email} deleting prompt {prompt_id}: {e}")
        error_message = str(e)
    except Exception as e:
        LOGGER.error(f"Error deleting prompt: {e}")
        error_message = "Failed to delete prompt. Please try again."
    root_path = _resolve_root_path(request)
    team_id = str(form.get("team_id", "") or "")
    redirect_url = _build_admin_redirect(root_path, "prompts", error=error_message, include_inactive=is_inactive_checked.lower() == "true", team_id=team_id)
    return RedirectResponse(redirect_url, status_code=303)


@router.post("/prompts/{prompt_id}/state")
@require_permission("prompts.update", allow_admin_bypass=False)
async def admin_set_prompt_state(
    prompt_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> RedirectResponse:
    """
    Toggle a prompt's active status via the admin UI.

    This endpoint processes a form request to activate or deactivate a prompt.
    It expects a form field 'activate' with value "true" to activate the prompt
    or "false" to deactivate it. The endpoint handles exceptions gracefully and
    logs any errors that might occur during the status toggle operation.

    Args:
        prompt_id (str): The ID of the prompt whose status to toggle.
        request (Request): FastAPI request containing form data with the 'activate' field.
        db (Session): Database session dependency.
        user (str): Authenticated user dependency.

    Returns:
        RedirectResponse: A redirect to the admin dashboard prompts section with a
        status code of 303 (See Other).

    Examples:
        >>> callable(admin_set_prompt_state)
        True
        >>> admin_set_prompt_state.__name__
        'admin_set_prompt_state'
    """
    user_email = get_user_email(user)
    LOGGER.debug(f"User {user_email} is toggling prompt ID {prompt_id}")
    error_message = None
    form = await request.form()
    activate: bool = str(form.get("activate", "true")).lower() == "true"
    is_inactive_checked: str = str(form.get("is_inactive_checked", "false"))
    try:
        await prompt_service.set_prompt_state(db, prompt_id, activate, user_email=user_email)
    except PermissionError as e:
        LOGGER.warning(f"Permission denied for user {user_email} setting prompt state {prompt_id}: {e}")
        error_message = str(e)
    except Exception as e:
        LOGGER.error(f"Error setting prompt state: {e}")
        error_message = "Failed to set prompt state. Please try again."

    root_path = _resolve_root_path(request)
    team_id = str(form.get("team_id", "") or "")
    redirect_url = _build_admin_redirect(root_path, "prompts", error=error_message, include_inactive=is_inactive_checked.lower() == "true", team_id=team_id)
    return RedirectResponse(redirect_url, status_code=303)
