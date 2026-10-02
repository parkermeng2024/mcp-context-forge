# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/admin/resources.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Admin UI resource routes: list, partial, ids, search, test, detail, create,
edit, delete, and state change.
"""

# Standard
import binascii
import logging
from typing import Any, Dict, List, Optional

# Third-Party
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.encoders import jsonable_encoder
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import ValidationError
from sqlalchemy import and_, case, desc, false, func, or_, select
from sqlalchemy.exc import IntegrityError, InvalidRequestError, OperationalError
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
    resource_service,
)
from mcpgateway.admin.security import enforce_admin_csrf
from mcpgateway.auth_context import get_scoped_resource_access_context, get_token_teams_from_request, get_user_email
from mcpgateway.common.query_params import QueryGatewayIdList, QueryRenderModeControls, QueryTagsFilter
from mcpgateway.config import settings
from mcpgateway.db import EmailTeam, get_db, Resource as DbResource
from mcpgateway.middleware.rbac import get_current_user_with_permissions, require_permission
from mcpgateway.schemas import PaginatedResponse, ResourceCreate, ResourceUpdate
from mcpgateway.services.content_security import ContentSizeError, ContentTypeError
from mcpgateway.services.resource_service import ResourceError, ResourceNotFoundError, ResourceURIConflictError, ResourceValidationError
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


@router.get("/resources", response_model=PaginatedResponse)
@require_permission("resources.read", allow_admin_bypass=False)
async def admin_list_resources(
    request: Request,
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    per_page: int = Query(settings.pagination_default_page_size, ge=1, le=settings.pagination_max_page_size, description="Items per page"),
    include_inactive: bool = False,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> Dict[str, Any]:
    """
    List resources for the admin UI with pagination support.

    This endpoint retrieves a paginated list of resources from the database, optionally
    including those that are inactive. Uses offset-based (page/per_page) pagination.

    Args:
        request (Request): FastAPI request object (required for token team extraction via request.state.token_teams).
        page (int): Page number (1-indexed). Default: 1.
        per_page (int): Items per page. Default: 50.
        include_inactive (bool): Whether to include inactive resources in the results.
        db (Session): Database session dependency.
        user (str): Authenticated user dependency.

    Returns:
        Dict with 'data', 'pagination', and 'links' keys containing paginated resources.

    Examples:
        >>> callable(admin_list_resources)
        True
        >>> admin_list_resources.__name__
        'admin_list_resources'
    """
    user_email = get_user_email(user)
    token_teams = get_token_teams_from_request(request)
    LOGGER.debug(f"User {user_email} requested resource list (page={page}, per_page={per_page})")

    # Call resource_service.list_resources with page-based pagination
    paginated_result = await resource_service.list_resources(
        db=db,
        include_inactive=include_inactive,
        page=page,
        per_page=per_page,
        user_email=user_email,
        token_teams=token_teams,
    )

    # Return standardized paginated response
    return {
        "data": [resource.model_dump(by_alias=True) for resource in paginated_result["data"]],
        "pagination": paginated_result["pagination"].model_dump(),
        "links": paginated_result["links"].model_dump() if paginated_result["links"] else None,
    }


@router.get("/resources/partial", response_class=HTMLResponse)
@require_permission("resources.read", allow_admin_bypass=False)
async def admin_resources_partial_html(
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
    """Return HTML partial for paginated resources list (HTMX endpoint).

    This endpoint mirrors the behavior of the tools and prompts partial
    endpoints. It returns a template fragment suitable for HTMX-based
    pagination/infinite-scroll within the admin UI.

    Args:
        request (Request): FastAPI request object used by the template engine.
        page (int): Page number (1-indexed).
        per_page (int): Number of items per page (bounded by settings).
        q (str): Free-text query string.
        tags (Optional[str]): Tag filter expression (comma=OR, plus=AND).
        include_inactive (bool): If True, include inactive resources in results.
        render (Optional[str]): Render mode; when set to "controls" returns only
            pagination controls. Other supported value: "selector" for selector
            items used by infinite scroll selectors.
        gateway_id (Optional[str]): Filter by gateway ID(s), comma-separated.
        team_id (Optional[str]): Filter by team ID.
        include_public (bool): Whether to include all public resources in the results.
        db (Session): Database session (dependency-injected).
        user: Authenticated user object from dependency injection.

    Returns:
        Union[HTMLResponse, TemplateResponse]: Rendered template response with the
        resources partial (rows + controls), pagination controls only, or selector
        items depending on the ``render`` parameter.
    """

    LOGGER.debug(
        f"[RESOURCES FILTER DEBUG] User {get_user_email(user)} requested resources HTML partial (page={page}, per_page={per_page}, render={render}, gateway_id={gateway_id}, team_id={team_id})"
    )
    search_query = _normalize_search_query(q)
    normalized_tags = _normalize_tags_query(tags)
    tag_groups = _parse_tag_filter_groups(normalized_tags)

    # Normalize per_page
    per_page = max(settings.pagination_min_page_size, min(per_page, settings.pagination_max_page_size))

    user_email = get_user_email(user)

    # Team scoping
    team_ids = await _get_user_team_ids(user, db)

    # Build base query
    query = select(DbResource)

    # Apply gateway filter if provided
    if gateway_id:
        gateway_ids = [gid.strip() for gid in gateway_id.split(",") if gid.strip()]
        if gateway_ids:
            null_requested = any(gid.lower() == "null" for gid in gateway_ids)
            non_null_ids = [gid for gid in gateway_ids if gid.lower() != "null"]
            if non_null_ids and null_requested:
                query = query.where(or_(DbResource.gateway_id.in_(non_null_ids), DbResource.gateway_id.is_(None)))
                LOGGER.debug(f"[RESOURCES FILTER DEBUG] Filtering resources by gateway IDs (including NULL): {non_null_ids} + NULL")
            elif null_requested:
                query = query.where(DbResource.gateway_id.is_(None))
                LOGGER.debug("[RESOURCES FILTER DEBUG] Filtering resources by NULL gateway_id (RestTool)")
            else:
                query = query.where(DbResource.gateway_id.in_(non_null_ids))
                LOGGER.debug(f"[RESOURCES FILTER DEBUG] Filtering resources by gateway IDs: {non_null_ids}")
    else:
        LOGGER.debug("[RESOURCES FILTER DEBUG] No gateway_id filter provided, showing all resources")

    # Apply active/inactive filter
    if not include_inactive:
        query = query.where(DbResource.enabled.is_(True))

    # Build access conditions
    # When team_id is specified, show ONLY items from that team (team-scoped view)
    # When team_id + include_public, show team items PLUS public items from all teams
    # Otherwise, show all accessible items (All Teams view)
    if team_id:
        # Team-specific view: only show resources from the specified team
        if team_id in team_ids:
            # Apply visibility check: team/public resources + user's own resources (including private)
            team_access = [
                and_(DbResource.team_id == team_id, DbResource.visibility.in_(["team", "public"])),
                and_(DbResource.team_id == team_id, DbResource.owner_email == user_email),
            ]
            if include_public:
                # Include all globally public items from any team.
                # Items with visibility='team' or 'private' from other teams are
                # blocked by the other conditions (which require team_id == selected team).
                team_access.append(DbResource.visibility == "public")
            query = query.where(or_(*team_access))
            LOGGER.debug(f"Filtering resources by team_id: {team_id}{' (include_public)' if include_public else ''}")
        else:
            # User is not a member of this team, return no results using SQLAlchemy's false()
            LOGGER.warning(f"User {user_email} attempted to filter by team {team_id} but is not a member")
            query = query.where(false())
    else:
        # All Teams view: apply standard access conditions (owner, team, public)
        access_conditions = []
        access_conditions.append(_owner_access_condition(DbResource.owner_email, DbResource.team_id, user_email=user_email, team_ids=team_ids, user=user))
        if team_ids:
            access_conditions.append(and_(DbResource.team_id.in_(team_ids), DbResource.visibility.in_(["team", "public"])))
        access_conditions.append(DbResource.visibility == "public")
        query = query.where(or_(*access_conditions))

    if search_query:
        query = query.where(
            or_(
                _like_contains(func.lower(DbResource.id), search_query),
                _like_contains(func.lower(DbResource.name), search_query),
                _like_contains(func.lower(coalesce(DbResource.uri, "")), search_query),
                _like_contains(func.lower(coalesce(DbResource.description, "")), search_query),
            )
        )

    query = _apply_tag_filter_groups(query, db, DbResource.tags, tag_groups)

    # Add sorting for consistent pagination
    query = query.order_by(desc(DbResource.created_at), desc(DbResource.id))

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
    base_url = f"{root_path}/admin/resources/partial"
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

    # Extract paginated resources (DbResource objects)
    resources_db = paginated_result["data"]
    pagination = paginated_result["pagination"]
    links = paginated_result["links"]

    # Batch fetch team names for the resources to avoid N+1 queries
    team_ids_set = {r.team_id for r in resources_db if r.team_id}
    team_map = {}
    if team_ids_set:
        teams = db.execute(select(EmailTeam.id, EmailTeam.name).where(EmailTeam.id.in_(team_ids_set), EmailTeam.is_active.is_(True))).all()
        team_map = {team.id: team.name for team in teams}

    # Apply team names to DB objects before conversion
    for r in resources_db:
        r.team = team_map.get(r.team_id) if r.team_id else None

    # Batch convert to Pydantic models using resource service
    resources_pydantic = []
    failed_count = 0
    for r in resources_db:
        try:
            resources_pydantic.append(resource_service.convert_resource_to_read(r, include_metrics=False))
        except (ValidationError, ValueError, KeyError, TypeError, binascii.Error) as e:
            failed_count += 1
            LOGGER.exception(f"Failed to convert resource {getattr(r, 'id', 'unknown')} ({getattr(r, 'name', 'unknown')}): {e}")
    _adjust_pagination_for_conversion_failures(pagination, failed_count, len(resources_pydantic))

    data = jsonable_encoder(resources_pydantic)

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
                "hx_target": "#resources-table-body",
                "hx_indicator": "#resources-loading",
                "query_params": query_params,
                "root_path": _resolve_root_path(request),
            },
        )

    if render == "selector":
        return request.app.state.templates.TemplateResponse(
            request,
            "resources_selector_items.html",
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
        "resources_partial.html",
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


@router.get("/resources/ids", response_class=JSONResponse)
@require_permission("resources.read", allow_admin_bypass=False)
async def admin_get_all_resource_ids(
    q: str = Query("", max_length=500, description="Search query"),
    include_inactive: bool = False,
    gateway_id: QueryGatewayIdList = None,
    team_id: Optional[str] = Depends(_validated_team_id_param),
    include_public: bool = False,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    """Return all resource IDs accessible to the current user (select-all helper).

    This endpoint is used by UI "Select All" helpers to fetch only the IDs
    of resources the requesting user can access (owner, team, or public).

    Args:
        q (str): Search query to filter resources by name, URI, or description.
        include_inactive (bool): Whether to include inactive resources in the results.
        gateway_id (Optional[str]): Filter by gateway ID(s), comma-separated. Accepts the literal value 'null' to indicate NULL gateway_id (local resources).
        team_id (Optional[str]): Filter by team ID.
        include_public (bool): Whether to include all platform-public resources when filtering by team.
        db (Session): Database session dependency.
        user: Authenticated user object from dependency injection.

    Returns:
        dict: A dictionary containing two keys:
            - "resource_ids": List[str] of accessible resource IDs.
            - "count": int number of IDs returned.
    """
    user_email = get_user_email(user)
    team_ids = await _get_user_team_ids(user, db)

    query = select(DbResource.id)

    if not include_inactive:
        query = query.where(DbResource.enabled.is_(True))

    # Apply search filter if provided
    if q:
        search_query = _normalize_search_query(q)
        if search_query:
            search_conditions = [
                _like_contains(func.lower(DbResource.id), search_query),
                _like_contains(func.lower(DbResource.name), search_query),
                _like_contains(func.lower(coalesce(DbResource.uri, "")), search_query),
                _like_contains(func.lower(coalesce(DbResource.description, "")), search_query),
            ]
            query = query.where(or_(*search_conditions))
            LOGGER.debug(f"Filtering resource IDs by search query: {search_query}")

    # Apply optional gateway/server scoping
    if gateway_id:
        gateway_ids = [gid.strip() for gid in gateway_id.split(",") if gid.strip()]
        if gateway_ids:
            null_requested = any(gid.lower() == "null" for gid in gateway_ids)
            non_null_ids = [gid for gid in gateway_ids if gid.lower() != "null"]
            if non_null_ids and null_requested:
                query = query.where(or_(DbResource.gateway_id.in_(non_null_ids), DbResource.gateway_id.is_(None)))
                LOGGER.debug(f"Filtering resources by gateway IDs (including NULL): {non_null_ids} + NULL")
            elif null_requested:
                query = query.where(DbResource.gateway_id.is_(None))
                LOGGER.debug("Filtering resources by NULL gateway_id (RestTool)")
            else:
                query = query.where(DbResource.gateway_id.in_(non_null_ids))
                LOGGER.debug(f"Filtering resources by gateway IDs: {non_null_ids}")

    # Build access conditions
    # When team_id is specified, show items from that team; optionally include
    # platform-public items when include_public is set (mirrors the partial endpoint).
    # Otherwise, show all accessible items (All Teams view).
    if team_id:
        if team_id in team_ids:
            team_access = [
                and_(DbResource.team_id == team_id, DbResource.visibility.in_(["team", "public"])),
                and_(DbResource.team_id == team_id, DbResource.owner_email == user_email),
            ]
            if include_public:
                team_access.append(DbResource.visibility == "public")
            query = query.where(or_(*team_access))
            LOGGER.debug(f"Filtering resource IDs by team_id: {team_id}{' (include_public)' if include_public else ''}")
        else:
            # User is not a member of this team, return no results using SQLAlchemy's false()
            LOGGER.warning(f"User {user_email} attempted to filter resource IDs by team {team_id} but is not a member")
            query = query.where(false())
    else:
        # All Teams view: apply standard access conditions (owner, team, public)
        access_conditions = []
        access_conditions.append(_owner_access_condition(DbResource.owner_email, DbResource.team_id, user_email=user_email, team_ids=team_ids, user=user))
        if team_ids:
            access_conditions.append(and_(DbResource.team_id.in_(team_ids), DbResource.visibility.in_(["team", "public"])))
        access_conditions.append(DbResource.visibility == "public")
        query = query.where(or_(*access_conditions))

    resource_ids = [row[0] for row in db.execute(query).all()]
    return {"resource_ids": resource_ids, "count": len(resource_ids)}


@router.get("/resources/search", response_class=JSONResponse)
@require_permission("resources.read", allow_admin_bypass=False)
async def admin_search_resources(
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
    """Search resources by name or description for selector search.

    Performs a case-insensitive search over resource names and descriptions
    and returns a limited list of matching resources suitable for selector
    UIs (id, name, description).

    Args:
        q (str): Search query string.
        tags (Optional[str]): Tag filter expression (comma=OR, plus=AND).
        include_inactive (bool): When True include resources that are inactive.
        limit (int): Maximum number of results to return (bounded by the query parameter).
        gateway_id (Optional[str]): Filter by gateway ID(s), comma-separated.
        team_id (Optional[str]): Filter by team ID.
        include_public (bool): Whether to include all public resources in the results.
        db (Session): Database session (injected dependency).
        user: Authenticated user object from dependency injection.

    Returns:
        dict: A dictionary containing:
            - "resources": List[dict] where each dict has keys "id", "name", "description".
            - "count": int number of matched resources returned.
    """
    user_email = get_user_email(user)
    search_query = _normalize_search_query(q)
    normalized_tags = _normalize_tags_query(tags)
    tag_groups = _parse_tag_filter_groups(normalized_tags)
    if not search_query and not tag_groups:
        return _build_search_response(entity_key="resources", entity_type="resources", items=[], query=search_query, tags=normalized_tags, tag_groups=tag_groups)

    team_ids = await _get_user_team_ids(user, db)

    query = select(DbResource.id, DbResource.name, DbResource.description)

    # Apply gateway filter if provided
    if gateway_id:
        gateway_ids = [gid.strip() for gid in gateway_id.split(",") if gid.strip()]
        if gateway_ids:
            null_requested = any(gid.lower() == "null" for gid in gateway_ids)
            non_null_ids = [gid for gid in gateway_ids if gid.lower() != "null"]
            if non_null_ids and null_requested:
                query = query.where(or_(DbResource.gateway_id.in_(non_null_ids), DbResource.gateway_id.is_(None)))
                LOGGER.debug(f"Filtering resource search by gateway IDs (including NULL): {non_null_ids} + NULL")
            elif null_requested:
                query = query.where(DbResource.gateway_id.is_(None))
                LOGGER.debug("Filtering resource search by NULL gateway_id")
            else:
                query = query.where(DbResource.gateway_id.in_(non_null_ids))
                LOGGER.debug(f"Filtering resource search by gateway IDs: {non_null_ids}")

    if not include_inactive:
        query = query.where(DbResource.enabled.is_(True))

    # Build access conditions
    # When team_id is specified, show ONLY items from that team (team-scoped view)
    # When team_id + include_public, show team items PLUS public items from all teams
    # Otherwise, show all accessible items (All Teams view)
    if team_id:
        # Team-specific view: only show resources from the specified team
        if team_id in team_ids:
            # Apply visibility check: team/public resources + user's own resources (including private)
            team_access = [
                and_(DbResource.team_id == team_id, DbResource.visibility.in_(["team", "public"])),
                and_(DbResource.team_id == team_id, DbResource.owner_email == user_email),
            ]
            if include_public:
                team_access.append(DbResource.visibility == "public")
            query = query.where(or_(*team_access))
            LOGGER.debug(f"Filtering resource search by team_id: {team_id}{' (include_public)' if include_public else ''}")
        else:
            # User is not a member of this team, return no results using SQLAlchemy's false()
            LOGGER.warning(f"User {user_email} attempted to filter resource search by team {team_id} but is not a member")
            query = query.where(false())
    else:
        # All Teams view: apply standard access conditions (owner, team, public)
        access_conditions = []
        access_conditions.append(_owner_access_condition(DbResource.owner_email, DbResource.team_id, user_email=user_email, team_ids=team_ids, user=user))
        if team_ids:
            access_conditions.append(and_(DbResource.team_id.in_(team_ids), DbResource.visibility.in_(["team", "public"])))
        access_conditions.append(DbResource.visibility == "public")
        query = query.where(or_(*access_conditions))

    if search_query:
        search_conditions = [
            _like_contains(func.lower(DbResource.id), search_query),
            _like_contains(func.lower(DbResource.name), search_query),
            _like_contains(func.lower(coalesce(DbResource.uri, "")), search_query),
            _like_contains(func.lower(coalesce(DbResource.description, "")), search_query),
        ]
        query = query.where(or_(*search_conditions))

    query = _apply_tag_filter_groups(query, db, DbResource.tags, tag_groups)

    if search_query:
        query = query.order_by(
            case(
                (func.lower(DbResource.name).startswith(search_query), 1),
                else_=2,
            ),
            func.lower(DbResource.name),
        )
    else:
        query = query.order_by(func.lower(DbResource.name))
    query = query.limit(limit)

    results = db.execute(query).all()
    resources = []
    for row in results:
        resources.append({"id": row.id, "name": row.name, "description": row.description})

    return _build_search_response(entity_key="resources", entity_type="resources", items=resources, query=search_query, tags=normalized_tags, tag_groups=tag_groups)


@router.get("/resources/test/{resource_uri:path}")
@require_permission("resources.read", allow_admin_bypass=False)
async def admin_test_resource(resource_uri: str, db: Session = Depends(get_db), user=Depends(get_current_user_with_permissions)) -> Dict[str, Any]:
    """
    Test reading a resource by its URI for the admin UI.

    Args:
        resource_uri: The full resource URI (may include encoded characters).
        db: Database session dependency.
        user: Authenticated user with proper permissions.

    Returns:
        A dictionary containing the resolved resource content.

    Raises:
        HTTPException: If the resource is not found.
        Exception: For unexpected errors.

    Examples:
        >>> callable(admin_test_resource)
        True
        >>> admin_test_resource.__name__
        'admin_test_resource'
    """
    user_email = get_user_email(user)
    LOGGER.debug(f"User {user_email} requested details for resource ID {resource_uri}")

    # For admin UI, pass user email and token_teams=None
    # Since admin UI requires admin permissions, the user should have full access
    # via the admin bypass (is_admin + token_teams=None)
    is_admin = user.get("is_admin", False) if isinstance(user, dict) else False

    try:
        # Admin users get unrestricted access (user_email=None, token_teams=None)
        # Non-admin users get team-based access (user_email=email, token_teams=None for lookup)
        resource_content = await resource_service.read_resource(
            db,
            resource_uri=resource_uri,
            user=None if is_admin else user_email,
            token_teams=None,
        )
        return {"content": resource_content}
    except ResourceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ResourceError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        LOGGER.error(f"Error getting resource for {resource_uri}: {e}")
        raise e


@router.get("/resources/{resource_id}")
@require_permission("resources.read", allow_admin_bypass=False)
async def admin_get_resource(resource_id: str, request: Request, db: Session = Depends(get_db), user=Depends(get_current_user_with_permissions)) -> Dict[str, Any]:
    """Get resource details for the admin UI.

    Args:
        resource_id: Resource ID.
        request: Incoming FastAPI request (for visibility scope resolution).
        db: Database session.
        user: Authenticated user.

    Returns:
        A dictionary containing resource details.

    Raises:
        HTTPException: If the resource is not found.
        Exception: For any other unexpected errors.

    Examples:
        >>> callable(admin_get_resource)
        True
        >>> admin_get_resource.__name__
        'admin_get_resource'
    """
    LOGGER.debug(f"User {get_user_email(user)} requested details for resource ID {resource_id}")
    try:
        auth_user_email, auth_token_teams = get_scoped_resource_access_context(request, user)
        resource = await resource_service.get_resource_by_id(
            db,
            resource_id,
            include_inactive=True,
            user_email=auth_user_email,
            token_teams=auth_token_teams,
        )
        return {"resource": resource.model_dump(by_alias=True)}
    except ResourceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        LOGGER.error(f"Error getting resource {resource_id}: {e}")
        raise e


@router.post("/resources")
@require_permission("resources.create", allow_admin_bypass=False)
async def admin_add_resource(request: Request, db: Session = Depends(get_db), user=Depends(get_current_user_with_permissions)) -> Response:
    """
    Add a resource via the admin UI.

    Expects form fields:
      - uri
      - name
      - description (optional)
      - mime_type (optional)
      - content

    Args:
        request: FastAPI request containing form data.
        db: Database session.
        user: Authenticated user.

    Returns:
        A redirect response to the admin dashboard.

    Raises:
        HTTPException: 422 when public visibility is disabled and request is team-scoped.

    Examples:
        >>> callable(admin_add_resource)
        True
        >>> admin_add_resource.__name__
        'admin_add_resource'
    """
    LOGGER.debug(f"User {get_user_email(user)} is adding a new resource")
    form = await request.form()
    team_id = _form_team_id(form)

    # Parse tags from comma-separated string
    tags_str = str(form.get("tags", ""))
    tags: List[str] = [tag.strip() for tag in tags_str.split(",") if tag.strip()] if tags_str else []
    visibility = str(form.get("visibility", "public"))
    _check_public_visibility_allowed(visibility, team_id=team_id)
    user_email = get_user_email(user)
    team_service = TeamManagementService(db)
    team_id = await team_service.verify_team_for_user(user_email, team_id)

    try:
        # Handle template field: convert empty string to None for optional field
        template = None
        template_value = form.get("uri_template")
        template = template_value if template_value else None
        template_value = form.get("uri_template")
        uri_value = form.get("uri")

        # Ensure uri_value is a string
        if isinstance(uri_value, str) and "{" in uri_value and "}" in uri_value:
            template = uri_value

        resource = ResourceCreate(
            uri=str(form["uri"]),
            name=str(form["name"]),
            description=str(form.get("description", "")),
            mime_type=str(form.get("mimeType", "")),
            uri_template=template,
            content=str(form["content"]),
            tags=tags,
            visibility=visibility,
            team_id=team_id,
            owner_email=user_email,
        )

        metadata = MetadataCapture.extract_creation_metadata(request, user)

        await resource_service.register_resource(
            db,
            resource,
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
            content={"message": "Add resource registered successfully!", "success": True},
            status_code=200,
        )
    except Exception as ex:
        # Roll back only when a transaction is active to avoid sqlite3 "no transaction" errors.
        try:
            active_transaction = db.get_transaction() if hasattr(db, "get_transaction") else None
            if db.is_active and active_transaction is not None:
                db.rollback()
        except (InvalidRequestError, OperationalError) as rollback_error:
            LOGGER.warning(
                "Rollback failed (ignoring for SQLite compatibility): %s",
                rollback_error,
            )

        if isinstance(ex, ValidationError):
            LOGGER.error("ValidationError in admin_add_resource: %s", sanitize_validation_error_for_log(ex))
            return ORJSONResponse(content=ErrorFormatter.format_validation_error(ex), status_code=422)
        if isinstance(ex, IntegrityError):
            error_message = ErrorFormatter.format_database_error(ex)
            LOGGER.error(f"IntegrityError in admin_add_resource: {error_message}")
            return ORJSONResponse(status_code=409, content=error_message)
        if isinstance(ex, ResourceValidationError):
            LOGGER.error(f"ResourceValidationError in admin_add_resource: {ex}")
            return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=422)
        if isinstance(ex, ResourceURIConflictError):
            LOGGER.error(f"ResourceURIConflictError in admin_add_resource: {ex}")
            return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=409)
        if isinstance(ex, ContentSizeError):
            LOGGER.error(f"ContentSizeError in admin_add_resource: {ex}")
            return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=413)
        if isinstance(ex, ContentTypeError):
            LOGGER.error(f"ContentTypeError in admin_add_resource: {ex}")
            return ORJSONResponse(
                content={
                    "message": str(ex),
                    "success": False,
                    "mime_type": ex.mime_type,
                    "allowed_types": ex.allowed_types,
                },
                status_code=415,
            )
        LOGGER.exception(f"Unexpected error in admin_add_resource: {ex}")
        return ORJSONResponse(content={"message": "An unexpected error occurred. Please try again or contact support.", "success": False}, status_code=500)


@router.post("/resources/{resource_id}/edit")
@require_permission("resources.update", allow_admin_bypass=False)
async def admin_edit_resource(
    resource_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> JSONResponse:
    """
    Edit a resource via the admin UI.

    Expects form fields:
      - name
      - description (optional)
      - mime_type (optional)
      - content

    Args:
        resource_id: Resource ID.
        request: FastAPI request containing form data.
        db: Database session.
        user: Authenticated user.

    Returns:
        JSONResponse: A JSON response indicating success or failure of the resource update operation.

    Raises:
        HTTPException: 422 when public visibility is disabled and request is team-scoped.

    Examples:
        >>> callable(admin_edit_resource)
        True
        >>> admin_edit_resource.__name__
        'admin_edit_resource'
    """
    LOGGER.debug(f"User {get_user_email(user)} is editing resource ID {resource_id}")
    form = await request.form()
    LOGGER.info(f"Form data received for resource edit: {form}")
    team_id = _form_team_id(form)
    visibility = str(form.get("visibility", "private"))
    _check_public_visibility_allowed(visibility, team_id=team_id)

    user_email = get_user_email(user)

    # Preserve existing resource's team_id when no explicit team_id is provided.
    # Without this guard, verify_team_for_user() falls back to the user's
    # personal team, silently reassigning the resource on every edit.
    if not team_id:
        existing_resource = db.get(DbResource, resource_id)
        existing_team = getattr(existing_resource, "team_id", None) if existing_resource else None
        if isinstance(existing_team, str) and existing_team:
            team_id = existing_team

    team_service = TeamManagementService(db)
    team_id = await team_service.verify_team_for_user(user_email, team_id)

    # Parse tags from comma-separated string
    tags_str = str(form.get("tags", ""))
    tags: List[str] = [tag.strip() for tag in tags_str.split(",") if tag.strip()] if tags_str else []

    try:
        mod_metadata = MetadataCapture.extract_modification_metadata(request, user, 0)
        resource = ResourceUpdate(
            uri=str(form.get("uri", "")),
            **({"name": str(form["name"])} if "name" in form else {}),
            custom_name=str(form["customName"]) if "customName" in form else None,
            description=str(form.get("description")),
            mime_type=str(form.get("mimeType")),
            content=str(form.get("content", "")),
            template=str(form.get("template")),
            tags=tags,
            visibility=visibility,
            team_id=team_id,
            owner_email=user_email,
        )
        LOGGER.info(f"ResourceUpdate object created: {resource}")
        await resource_service.update_resource(
            db,
            resource_id,
            resource,
            modified_by=mod_metadata["modified_by"],
            modified_from_ip=mod_metadata["modified_from_ip"],
            modified_via=mod_metadata["modified_via"],
            modified_user_agent=mod_metadata["modified_user_agent"],
            user_email=get_user_email(user),
        )
        return ORJSONResponse(
            content={"message": "Resource updated successfully!", "success": True},
            status_code=200,
        )
    except PermissionError as e:
        LOGGER.info(f"Permission denied for user {get_user_email(user)}: {e}")
        return ORJSONResponse(content={"message": str(e), "success": False}, status_code=403)
    except Exception as ex:
        # Roll back to discard any dirty tracked state from the failed update.
        try:
            active_transaction = db.get_transaction() if hasattr(db, "get_transaction") else None
            if db.is_active and active_transaction is not None:
                db.rollback()
        except (InvalidRequestError, OperationalError) as rollback_error:
            LOGGER.warning("Rollback failed (ignoring for SQLite compatibility): %s", rollback_error)

        if isinstance(ex, ValidationError):
            LOGGER.error("ValidationError in admin_edit_resource: %s", sanitize_validation_error_for_log(ex))
            return ORJSONResponse(content=ErrorFormatter.format_validation_error(ex), status_code=422)
        if isinstance(ex, IntegrityError):
            error_message = ErrorFormatter.format_database_error(ex)
            LOGGER.error(f"IntegrityError in admin_edit_resource: {error_message}")
            return ORJSONResponse(status_code=409, content=error_message)
        if isinstance(ex, ResourceValidationError):
            LOGGER.error(f"ResourceValidationError in admin_edit_resource: {ex}")
            return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=422)
        if isinstance(ex, ResourceURIConflictError):
            LOGGER.error(f"ResourceURIConflictError in admin_edit_resource: {ex}")
            return ORJSONResponse(status_code=409, content={"message": str(ex), "success": False})
        if isinstance(ex, ContentSizeError):
            LOGGER.error(f"ContentSizeError in admin_edit_resource: {ex}")
            return ORJSONResponse(status_code=413, content={"message": str(ex), "success": False})
        if isinstance(ex, ContentTypeError):
            LOGGER.error(f"ContentTypeError in admin_edit_resource: {ex}")
            return ORJSONResponse(
                status_code=415,
                content={
                    "message": str(ex),
                    "success": False,
                    "mime_type": ex.mime_type,
                    "allowed_types": ex.allowed_types,
                },
            )
        LOGGER.exception(f"Unexpected error in admin_edit_resource: {ex}")
        return ORJSONResponse(content={"message": "An unexpected error occurred. Please try again or contact support.", "success": False}, status_code=500)


@router.post("/resources/{resource_id}/delete")
@require_permission("resources.delete", allow_admin_bypass=False)
async def admin_delete_resource(resource_id: str, request: Request, db: Session = Depends(get_db), user=Depends(get_current_user_with_permissions)) -> RedirectResponse:
    """
    Delete a resource via the admin UI.

    This endpoint permanently removes a resource from the database using its resource ID.
    The operation is irreversible and should be used with caution. It requires
    user authentication and logs the deletion attempt.

    Args:
        resource_id (str): The ID of the resource to delete.
        request (Request): FastAPI request object (not used directly but required by the route signature).
        db (Session): Database session dependency.
        user (str): Authenticated user dependency.

    Returns:
        RedirectResponse: A redirect response to the resources section of the admin
        dashboard with a status code of 303 (See Other).

    Examples:
        >>> callable(admin_delete_resource)
        True
        >>> admin_delete_resource.__name__
        'admin_delete_resource'
    """

    form = await request.form()
    is_inactive_checked: str = str(form.get("is_inactive_checked", "false"))
    purge_metrics = str(form.get("purge_metrics", "false")).lower() == "true"
    user_email = get_user_email(user)
    LOGGER.debug(f"User {get_user_email(user)} is deleting resource ID {resource_id}")
    error_message = None
    try:
        await resource_service.delete_resource(
            db,  # Use endpoint's db session (user["db"] is now closed early)
            resource_id,
            user_email=user_email,
            purge_metrics=purge_metrics,
        )
    except PermissionError as e:
        LOGGER.warning(f"Permission denied for user {user_email} deleting resource {resource_id}: {e}")
        error_message = str(e)
    except Exception as e:
        LOGGER.error(f"Error deleting resource: {e}")
        error_message = "Failed to delete resource. Please try again."
    root_path = _resolve_root_path(request)
    team_id = str(form.get("team_id", "") or "")
    redirect_url = _build_admin_redirect(root_path, "resources", error=error_message, include_inactive=is_inactive_checked.lower() == "true", team_id=team_id)
    return RedirectResponse(redirect_url, status_code=303)


@router.post("/resources/{resource_id}/state")
@require_permission("resources.update", allow_admin_bypass=False)
async def admin_set_resource_state(
    resource_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> RedirectResponse:
    """
    Toggle a resource's active status via the admin UI.

    This endpoint processes a form request to activate or deactivate a resource.
    It expects a form field 'activate' with value "true" to activate the resource
    or "false" to deactivate it. The endpoint handles exceptions gracefully and
    logs any errors that might occur during the status toggle operation.

    Args:
        resource_id (str): The ID of the resource whose status to toggle.
        request (Request): FastAPI request containing form data with the 'activate' field.
        db (Session): Database session dependency.
        user (str): Authenticated user dependency.

    Returns:
        RedirectResponse: A redirect to the admin dashboard resources section with a
        status code of 303 (See Other).

    Examples:
        >>> callable(admin_set_resource_state)
        True
        >>> admin_set_resource_state.__name__
        'admin_set_resource_state'
    """
    user_email = get_user_email(user)
    LOGGER.debug(f"User {user_email} is toggling resource ID {resource_id}")
    form = await request.form()
    error_message = None
    activate = str(form.get("activate", "true")).lower() == "true"
    is_inactive_checked = str(form.get("is_inactive_checked", "false"))
    try:
        await resource_service.set_resource_state(db, resource_id, activate, user_email=user_email)
    except PermissionError as e:
        LOGGER.warning(f"Permission denied for user {user_email} setting resource state {resource_id}: {e}")
        error_message = str(e)
    except Exception as e:
        LOGGER.error(f"Error setting resource state: {e}")
        error_message = "Failed to set resource state. Please try again."

    root_path = _resolve_root_path(request)
    team_id = str(form.get("team_id", "") or "")
    redirect_url = _build_admin_redirect(root_path, "resources", error=error_message, include_inactive=is_inactive_checked.lower() == "true", team_id=team_id)
    return RedirectResponse(redirect_url, status_code=303)
