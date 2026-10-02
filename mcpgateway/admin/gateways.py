# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/admin/gateways.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Admin UI gateway routes: list, partial, ids, search, detail, create, update,
delete, ownership transfer, OAuth discovery, and connectivity test.
"""

# Standard
import binascii
import logging
from typing import Any, Dict, List, Optional, cast as typing_cast
import orjson

# Third-Party
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.encoders import jsonable_encoder
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, ValidationError
from sqlalchemy import and_, case, desc, false, func, or_, select
from sqlalchemy.exc import DataError, IntegrityError
from sqlalchemy.orm import joinedload, Session
from sqlalchemy.sql.functions import coalesce

# First-Party
from mcpgateway.admin.common import (
    _adjust_pagination_for_conversion_failures,
    _apply_tag_filter_groups,
    _assemble_oauth_config_from_fields,
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
    _parse_auth_headers_field,
    _parse_oauth_config_json_field,
    _parse_passthrough_headers_field,
    _parse_tag_filter_groups,
    _validated_team_id_param,
    gateway_service,
)
from mcpgateway.admin.security import enforce_admin_csrf
from mcpgateway.auth_context import extract_token_team_ids, get_scoped_resource_access_context, get_token_teams_from_request, get_user_email
from mcpgateway.common.query_params import QueryRenderMode, QueryTagsFilter
from mcpgateway.common.validators import SecurityValidator
from mcpgateway.config import settings
from mcpgateway.db import Gateway as DbGateway, get_db
from mcpgateway.middleware.rbac import get_current_user_with_permissions, require_admin_permission, require_permission
from mcpgateway.schemas import GatewayCreate, GatewayOwnershipTransferRequest, GatewayRead, GatewayTestRequest, GatewayTestResponse, GatewayUpdate, PaginatedResponse
from mcpgateway.services.encryption_service import get_encryption_service
from mcpgateway.services.gateway_service import (
    gateway_capability_loaders,
    GatewayConnectionError,
    GatewayCredentialError,
    GatewayDuplicateConflictError,
    GatewayLookupConflictError,
    GatewayNameConflictError,
    GatewayNotFoundError,
    GatewayToolNameConflictError,
    test_gateway_connectivity,
)
from mcpgateway.services.team_management_service import TeamManagementService
from mcpgateway.utils.error_formatter import ErrorFormatter
from mcpgateway.utils.metadata_capture import MetadataCapture
from mcpgateway.utils.orjson_response import ORJSONResponse
from mcpgateway.utils.pagination import paginate_query
from mcpgateway.utils.paths import resolve_root_path as _resolve_root_path
from mcpgateway.utils.validate_signature import sign_data

LOGGER: logging.Logger = logging.getLogger("mcpgateway.admin")

# mcpgateway.admin (__init__) appends this router's routes to admin_router, so the
# prefix, tags, and CSRF dependency must mirror admin_router exactly.
router = APIRouter(
    prefix="/admin",
    tags=["Admin UI"],
    dependencies=[Depends(enforce_admin_csrf)],
)


async def _parse_gateway_data_from_request(request: Request) -> dict[str, Any]:
    """Parse gateway data from either JSON body or form data.

    This helper function enables endpoints to accept both application/json and
    multipart/form-data content types, supporting both API clients and the HTMX UI.

    Args:
        request: FastAPI request object.

    Returns:
        Dictionary containing parsed gateway data.

    Raises:
        HTTPException: If content type is unsupported or data is malformed.
    """
    content_type = request.headers.get("content-type", "").lower()

    # Handle JSON requests
    if "application/json" in content_type:
        try:
            data = await request.json()
            # Normalize tags if provided as string
            if isinstance(data.get("tags"), str):
                data["tags"] = [tag.strip() for tag in data["tags"].split(",") if tag.strip()]
            return data
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid JSON body: {e}")

    # Handle form data requests (multipart/form-data or application/x-www-form-urlencoded)
    elif "multipart/form-data" in content_type or "application/x-www-form-urlencoded" in content_type:
        form = await request.form()
        data: dict[str, Any] = {}

        # Extract all form fields
        for key in form.keys():
            value = form.get(key)
            if value is not None:
                data[key] = value

        # Parse tags from comma-separated string
        if "tags" in data and isinstance(data["tags"], str):
            tags_str = str(data["tags"])
            data["tags"] = [tag.strip() for tag in tags_str.split(",") if tag.strip()] if tags_str else []

        # Parse auth_headers JSON if present
        if "auth_headers" in data and isinstance(data["auth_headers"], str):
            try:
                data["auth_headers"] = orjson.loads(data["auth_headers"])
            except (orjson.JSONDecodeError, ValueError):
                data["auth_headers"] = []

        # Parse passthrough_headers
        if "passthrough_headers" in data and isinstance(data["passthrough_headers"], str):
            passthrough_str = str(data["passthrough_headers"]).strip()
            if passthrough_str:
                try:
                    data["passthrough_headers"] = orjson.loads(passthrough_str)
                except (orjson.JSONDecodeError, ValueError):
                    # Fallback to comma-separated parsing
                    data["passthrough_headers"] = [h.strip() for h in passthrough_str.split(",") if h.strip()]
            else:
                data["passthrough_headers"] = None

        # Parse OAuth configuration - support both JSON string and individual form fields
        oauth_config: Optional[dict[str, Any]] = None
        oauth_config_json = str(data.get("oauth_config", ""))

        # Option 1: Pre-assembled oauth_config JSON (from API calls)
        # If oauth_config field is present (even if invalid), don't fall back to Option 2
        oauth_config_field_provided = "oauth_config" in data
        if oauth_config_json and oauth_config_json != "None":
            try:
                oauth_config = orjson.loads(oauth_config_json)
            except (orjson.JSONDecodeError, ValueError):
                # Invalid JSON - set to None in data and don't try Option 2
                oauth_config = None
                data["oauth_config"] = None
        elif oauth_config_json == "None":
            # Explicit "None" string - set to None in data
            oauth_config = None
            data["oauth_config"] = None

        # Option 2: Assemble from individual UI form fields
        # Only try this if oauth_config field was NOT provided
        # (client_secret encryption happens downstream in the service layer)
        if not oauth_config and not oauth_config_field_provided:
            oauth_config = await _assemble_oauth_config_from_fields(data, encrypt_secret=False)

        if oauth_config:
            data["oauth_config"] = oauth_config

        return data

    else:
        raise HTTPException(status_code=415, detail=f"Unsupported content type: {content_type}. Use application/json or multipart/form-data")


def _gateway_result_status(result: Any) -> Optional[str]:
    """Return lifecycle status from a gateway service result when present."""
    if isinstance(result, dict):
        status_value = result.get("status")
        return status_value if isinstance(status_value, str) else None
    if isinstance(result, BaseModel):
        status_value = getattr(result, "status", None)
        return status_value if isinstance(status_value, str) else None
    return None


def _gateway_result_payload(result: Any) -> Optional[dict[str, Any]]:
    """Serialize concrete gateway results while tolerating mocked return values."""
    if isinstance(result, dict):
        return result
    if isinstance(result, BaseModel):
        return result.model_dump(mode="json", by_alias=True)
    return None


@router.get("/gateways", response_model=PaginatedResponse)
@require_permission("gateways.read", allow_admin_bypass=False)
async def admin_list_gateways(
    request: Request,
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    per_page: int = Query(settings.pagination_default_page_size, ge=1, le=settings.pagination_max_page_size, description="Items per page"),
    include_inactive: bool = False,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> Dict[str, Any]:
    """
    List gateways for the admin UI with pagination support.

    This endpoint retrieves a paginated list of gateways from the database, optionally
    including those that are inactive. Uses offset-based (page/per_page) pagination.

    Args:
        request (Request): FastAPI request object (required for token team extraction via request.state.token_teams).
        page (int): Page number (1-indexed) for offset pagination.
        per_page (int): Number of items per page.
        include_inactive (bool): Whether to include inactive gateways in the results.
        db (Session): Database session dependency.
        user (str): Authenticated user dependency.

    Returns:
        Dict[str, Any]: A dictionary containing:
            - data: List of gateway records formatted with by_alias=True
            - pagination: Pagination metadata
            - links: Pagination links (optional)

    Examples:
        >>> callable(admin_list_gateways)
        True
        >>> admin_list_gateways.__name__
        'admin_list_gateways'
    """
    user_email = get_user_email(user)
    token_teams = get_token_teams_from_request(request)
    LOGGER.debug(f"User {user_email} requested gateway list (page={page}, per_page={per_page})")

    # Call gateway_service.list_gateways with page-based pagination
    paginated_result = await gateway_service.list_gateways(
        db=db,
        include_inactive=include_inactive,
        page=page,
        per_page=per_page,
        user_email=user_email,
        token_teams=token_teams,
    )

    # Return standardized paginated response
    return {
        "data": [gateway.model_dump(by_alias=True) for gateway in paginated_result["data"]],
        "pagination": paginated_result["pagination"].model_dump(),
        "links": paginated_result["links"].model_dump() if paginated_result["links"] else None,
    }


@router.post("/gateways/{gateway_id}/state")
@require_permission("gateways.update", allow_admin_bypass=False)
async def admin_set_gateway_state(
    gateway_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> RedirectResponse:
    """
    Set the active status of a gateway via the admin UI.

    This endpoint allows an admin to set the active status of a gateway.
    It expects a form field 'activate' with a value of "true" or "false" to
    determine the new status of the gateway.

    Args:
        gateway_id (str): The ID of the gateway to set state for.
        request (Request): The FastAPI request object containing form data.
        db (Session): The database session dependency.
        user (str): The authenticated user dependency.

    Returns:
        RedirectResponse: A redirect response to the admin dashboard with a
        status code of 303 (See Other).

    Examples:
        >>> callable(admin_set_gateway_state)
        True
        >>> admin_set_gateway_state.__name__
        'admin_set_gateway_state'
    """
    error_message = None
    user_email = get_user_email(user)
    LOGGER.debug(f"User {user_email} is setting gateway state for ID {gateway_id}")
    form = await request.form()
    activate = str(form.get("activate", "true")).lower() == "true"
    is_inactive_checked = str(form.get("is_inactive_checked", "false"))

    try:
        await gateway_service.set_gateway_state(db, gateway_id, activate, user_email=user_email)
    except PermissionError as e:
        LOGGER.warning("Permission denied for user %s setting gateway state %s: %s", SecurityValidator.sanitize_log_message(user_email), SecurityValidator.sanitize_log_message(gateway_id), e)
        error_message = str(e)
    except GatewayToolNameConflictError as e:
        error_message = str(e)
    except Exception as e:
        LOGGER.error(f"Error setting gateway state: {e}")
        error_message = "Failed to set gateway state. Please try again."

    root_path = _resolve_root_path(request)
    team_id = str(form.get("team_id", "") or "")
    redirect_url = _build_admin_redirect(root_path, "gateways", error=error_message, include_inactive=is_inactive_checked.lower() == "true", team_id=team_id)
    return RedirectResponse(redirect_url, status_code=303)


@router.get("/gateways/partial", response_class=HTMLResponse)
@require_permission("gateways.read", allow_admin_bypass=False)
async def admin_gateways_partial_html(
    request: Request,
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    per_page: int = Query(settings.pagination_default_page_size, ge=1, le=settings.pagination_max_page_size, description="Items per page"),
    q: str = Query("", max_length=500, description="Search query"),
    tags: QueryTagsFilter = None,
    include_inactive: bool = True,
    render: QueryRenderMode = None,
    team_id: Optional[str] = Depends(_validated_team_id_param),
    include_public: bool = False,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    """Return paginated gateways HTML partials for the admin UI.

    This HTMX endpoint returns only the partial HTML used by the admin UI for
    gateways. It supports three render modes:

    - default: full table partial (rows + controls)
    - ``render="controls"``: return only pagination controls
    - ``render="selector"``: return selector items for infinite scroll

    Args:
        request (Request): FastAPI request object used by the template engine.
        page (int): Page number (1-indexed).
        per_page (int): Number of items per page (bounded by settings).
        q (str): Free-text query string.
        tags (Optional[str]): Tag filter expression (comma=OR, plus=AND).
        include_inactive (bool): If True, include inactive gateways in results.
        render (Optional[str]): Render mode; one of None, "controls", "selector".
        team_id (Optional[str]): Filter by team ID.
        include_public (bool): Whether to include all public gateways in the results.
        db (Session): Database session (dependency-injected).
        user: Authenticated user object from dependency injection.

    Returns:
        Union[HTMLResponse, TemplateResponse]: A rendered template response
        containing either the table partial, pagination controls, or selector
        items depending on ``render``. The response contains JSON-serializable
        encoded gateway data when templates expect it.
    """
    user_email = get_user_email(user)
    search_query = _normalize_search_query(q)
    normalized_tags = _normalize_tags_query(tags)
    tag_groups = _parse_tag_filter_groups(normalized_tags)
    LOGGER.debug(f"🔷 GATEWAYS PARTIAL REQUEST - User: {user_email}, team_id: {team_id}, page: {page}, render: {render}, referer: {request.headers.get('referer', 'none')}")
    # Normalize per_page within configured bounds
    per_page = max(settings.pagination_min_page_size, min(per_page, settings.pagination_max_page_size))

    # Team scoping
    team_ids = await _get_user_team_ids(user, db)

    # Build base query
    query = select(DbGateway).options(joinedload(DbGateway.email_team), *gateway_capability_loaders())

    if not include_inactive:
        query = query.where(DbGateway.enabled.is_(True))

    # Build access conditions
    # When team_id is specified, show ONLY items from that team (simpler, team-scoped view)
    # When team_id + include_public, show team items PLUS public items from all teams
    # When team_id is NOT specified, show all accessible items (owned + team + public)
    if team_id:
        # Team-specific view: only show gateways from the specified team if user is a member
        if team_id in team_ids:
            # Apply visibility check: team/public resources + user's own resources (including private)
            team_access = [
                and_(DbGateway.team_id == team_id, DbGateway.visibility.in_(["team", "public"])),
                and_(DbGateway.team_id == team_id, DbGateway.owner_email == user_email),
            ]
            if include_public:
                # Include all globally public items from any team.
                # Items with visibility='team' or 'private' from other teams are
                # blocked by the other conditions (which require team_id == selected team).
                team_access.append(DbGateway.visibility == "public")
            query = query.where(or_(*team_access))
            LOGGER.debug(f"Filtering gateways by team_id: {team_id}{' (include_public)' if include_public else ''}")
        else:
            # User is not a member of this team, return no results
            LOGGER.warning(f"User {user_email} attempted to filter by team {team_id} but is not a member")
            query = query.where(false())
    else:
        # All Teams view: apply standard access conditions
        access_conditions = []
        access_conditions.append(_owner_access_condition(DbGateway.owner_email, DbGateway.team_id, user_email=user_email, team_ids=team_ids, user=user))
        if team_ids:
            access_conditions.append(and_(DbGateway.team_id.in_(team_ids), DbGateway.visibility.in_(["team", "public"])))
        access_conditions.append(DbGateway.visibility == "public")

        query = query.where(or_(*access_conditions))

    if search_query:
        query = query.where(
            or_(
                _like_contains(func.lower(DbGateway.id), search_query),
                _like_contains(func.lower(DbGateway.name), search_query),
                _like_contains(func.lower(coalesce(DbGateway.url, "")), search_query),
                _like_contains(func.lower(coalesce(DbGateway.description, "")), search_query),
            )
        )

    query = _apply_tag_filter_groups(query, db, DbGateway.tags, tag_groups)

    # Apply pagination ordering for cursor support
    query = query.order_by(desc(DbGateway.created_at), desc(DbGateway.id))

    # Build query params for pagination links
    query_params = {}
    if include_inactive:
        query_params["include_inactive"] = "true"
    if team_id:
        query_params["team_id"] = team_id
    if search_query:
        query_params["q"] = search_query
    if normalized_tags:
        query_params["tags"] = normalized_tags

    # Use unified pagination function
    root_path = _resolve_root_path(request)
    base_url = f"{root_path}/admin/gateways/partial"
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

    # Extract paginated gateways (DbGateway objects)
    gateways_db = paginated_result["data"]
    pagination = paginated_result["pagination"]
    links = paginated_result["links"]

    # Batch convert to Pydantic models using gateway service
    # This eliminates the N+1 query problem from calling get_gateway_details() in a loop
    gateways_pydantic = []
    failed_count = 0
    for g in gateways_db:
        try:
            gateways_pydantic.append(gateway_service.convert_gateway_to_read(g))
        except (ValidationError, ValueError, KeyError, TypeError, binascii.Error) as e:
            failed_count += 1
            LOGGER.exception(f"Failed to convert gateway {getattr(g, 'id', 'unknown')} ({getattr(g, 'name', 'unknown')}): {e}")
    _adjust_pagination_for_conversion_failures(pagination, failed_count, len(gateways_pydantic))
    data = jsonable_encoder(gateways_pydantic)

    # End the read-only transaction before template rendering to avoid idle-in-transaction timeouts.
    db.commit()

    LOGGER.info(f"🔷 GATEWAYS PARTIAL RESPONSE - Returning {len(data)} gateways, render mode: {render or 'default'}, team_id used in query: {team_id}")

    if render == "controls":
        return request.app.state.templates.TemplateResponse(
            request,
            "pagination_controls.html",
            {
                "request": request,
                "pagination": pagination.model_dump(),
                "base_url": base_url,
                "hx_target": "#gateways-table-body",
                "hx_indicator": "#gateways-loading",
                "query_params": query_params,
                "root_path": _resolve_root_path(request),
            },
        )

    if render == "selector":
        return request.app.state.templates.TemplateResponse(
            request,
            "gateways_selector_items.html",
            {"request": request, "data": data, "pagination": pagination.model_dump(), "root_path": _resolve_root_path(request), "team_id": team_id, "include_public": include_public},
        )

    _is_admin = bool(user.get("is_admin", False) if isinstance(user, dict) else getattr(user, "is_admin", False))
    _team_roles = _get_user_team_roles(db, user_email) if not _is_admin else {}
    return request.app.state.templates.TemplateResponse(
        request,
        "gateways_partial.html",
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


@router.get("/gateways/ids", response_class=JSONResponse)
@require_permission("gateways.read", allow_admin_bypass=False)
async def admin_get_all_gateways_ids(
    include_inactive: bool = False,
    team_id: Optional[str] = Depends(_validated_team_id_param),
    include_public: bool = False,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    """Return all gateway IDs accessible to the current user (select-all helper).

    This endpoint is used by UI "Select All" helpers to fetch only the IDs
    of gateways the requesting user can access (owner, team, or public).

    Args:
        include_inactive (bool): When True include prompts that are inactive.
        team_id (Optional[str]): Filter by team ID.
        include_public (bool): Whether to include all public gateways in the results.
        db (Session): Database session (injected dependency).
        user: Authenticated user object from dependency injection.

    Returns:
        dict: A dictionary containing two keys:
            - "prompt_ids": List[str] of accessible prompt IDs.
            - "count": int number of IDs returned.
    """
    user_email = get_user_email(user)
    team_ids = await _get_user_team_ids(user, db)

    query = select(DbGateway.id)

    if not include_inactive:
        query = query.where(DbGateway.enabled.is_(True))

    # Build access conditions
    # When team_id is specified, show ONLY items from that team (team-scoped view)
    # When team_id + include_public, show team items PLUS public items from all teams
    # Otherwise, show all accessible items (All Teams view)
    if team_id:
        if team_id in team_ids:
            # Apply visibility check: team/public resources + user's own resources (including private)
            team_access = [
                and_(DbGateway.team_id == team_id, DbGateway.visibility.in_(["team", "public"])),
                and_(DbGateway.team_id == team_id, DbGateway.owner_email == user_email),
            ]
            if include_public:
                team_access.append(DbGateway.visibility == "public")
            query = query.where(or_(*team_access))
            LOGGER.debug(f"Filtering gateway IDs by team_id: {team_id}{' (include_public)' if include_public else ''}")
        else:
            LOGGER.warning(f"User {user_email} attempted to filter gateway IDs by team {team_id} but is not a member")
            query = query.where(false())
    else:
        # All Teams view: apply standard access conditions (owner, team, public)
        access_conditions = []
        access_conditions.append(_owner_access_condition(DbGateway.owner_email, DbGateway.team_id, user_email=user_email, team_ids=team_ids, user=user))
        access_conditions.append(DbGateway.visibility == "public")
        if team_ids:
            access_conditions.append(and_(DbGateway.team_id.in_(team_ids), DbGateway.visibility.in_(["team", "public"])))
        query = query.where(or_(*access_conditions))

    gateway_ids = [row[0] for row in db.execute(query).all()]
    return {"gateway_ids": gateway_ids, "count": len(gateway_ids)}


@router.get("/gateways/search", response_class=JSONResponse)
@require_permission("gateways.read", allow_admin_bypass=False)
async def admin_search_gateways(
    q: str = Query("", max_length=500, description="Search query"),
    tags: QueryTagsFilter = None,
    include_inactive: bool = False,
    limit: int = Query(settings.pagination_default_page_size, ge=1, le=settings.pagination_max_page_size),
    team_id: Optional[str] = Depends(_validated_team_id_param),
    include_public: bool = False,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    """Search gateways by name or description for selector search.

    Performs a case-insensitive search over prompt names and descriptions
    and returns a limited list of matching gateways suitable for selector
    UIs (id, name, description).

    Args:
        q (str): Search query string.
        tags (Optional[str]): Tag filter expression (comma=OR, plus=AND).
        include_inactive (bool): When True include gateways that are inactive.
        limit (int): Maximum number of results to return (bounded by the query parameter).
        team_id (Optional[str]): Filter by team ID.
        include_public (bool): Whether to include all public gateways in the results.
        db (Session): Database session (injected dependency).
        user: Authenticated user object from dependency injection.

    Returns:
        dict: A dictionary containing:
            - "gateways": List[dict] where each dict has keys "id", "name", "description".
            - "count": int number of matched gateways returned.
    """
    user_email = get_user_email(user)
    search_query = _normalize_search_query(q)
    normalized_tags = _normalize_tags_query(tags)
    tag_groups = _parse_tag_filter_groups(normalized_tags)
    if not search_query and not tag_groups:
        return _build_search_response(entity_key="gateways", entity_type="gateways", items=[], query=search_query, tags=normalized_tags, tag_groups=tag_groups)

    team_ids = await _get_user_team_ids(user, db)

    query = select(DbGateway.id, DbGateway.name, DbGateway.url, DbGateway.description)

    if not include_inactive:
        query = query.where(DbGateway.enabled.is_(True))

    # Build access conditions
    # When team_id is specified, show ONLY items from that team (team-scoped view)
    # When team_id + include_public, show team items PLUS public items from all teams
    # Otherwise, show all accessible items (All Teams view)
    if team_id:
        if team_id in team_ids:
            # Apply visibility check: team/public resources + user's own resources (including private)
            team_access = [
                and_(DbGateway.team_id == team_id, DbGateway.visibility.in_(["team", "public"])),
                and_(DbGateway.team_id == team_id, DbGateway.owner_email == user_email),
            ]
            if include_public:
                team_access.append(DbGateway.visibility == "public")
            query = query.where(or_(*team_access))
            LOGGER.debug(f"Filtering gateway search by team_id: {team_id}{' (include_public)' if include_public else ''}")
        else:
            LOGGER.warning(f"User {user_email} attempted to filter gateway search by team {team_id} but is not a member")
            query = query.where(false())
    else:
        # All Teams view: apply standard access conditions (owner, team, public)
        access_conditions = []
        access_conditions.append(_owner_access_condition(DbGateway.owner_email, DbGateway.team_id, user_email=user_email, team_ids=team_ids, user=user))
        access_conditions.append(DbGateway.visibility == "public")
        if team_ids:
            access_conditions.append(and_(DbGateway.team_id.in_(team_ids), DbGateway.visibility.in_(["team", "public"])))
        query = query.where(or_(*access_conditions))

    if search_query:
        search_conditions = [
            _like_contains(func.lower(DbGateway.id), search_query),
            _like_contains(func.lower(DbGateway.name), search_query),
            _like_contains(func.lower(coalesce(DbGateway.url, "")), search_query),
            _like_contains(func.lower(coalesce(DbGateway.description, "")), search_query),
        ]
        query = query.where(or_(*search_conditions))

    query = _apply_tag_filter_groups(query, db, DbGateway.tags, tag_groups)

    if search_query:
        query = query.order_by(
            case(
                (func.lower(DbGateway.name).startswith(search_query), 1),
                (func.lower(coalesce(DbGateway.url, "")).startswith(search_query), 1),
                else_=2,
            ),
            func.lower(DbGateway.name),
        )
    else:
        query = query.order_by(func.lower(DbGateway.name))
    query = query.limit(limit)

    results = db.execute(query).all()
    gateways = []
    for row in results:
        gateways.append(
            {
                "id": row.id,
                "name": row.name,
                "url": row.url,
                "description": row.description,
            }
        )

    return _build_search_response(entity_key="gateways", entity_type="gateways", items=gateways, query=search_query, tags=normalized_tags, tag_groups=tag_groups)


@router.get("/gateways/{gateway_id}", response_model=GatewayRead)
@require_permission("gateways.read", allow_admin_bypass=False)
async def admin_get_gateway(gateway_id: str, request: Request, db: Session = Depends(get_db), user=Depends(get_current_user_with_permissions)) -> Dict[str, Any]:
    """Get gateway details for the admin UI.

    Args:
        gateway_id: Gateway ID.
        request: Incoming FastAPI request (for visibility scope resolution).
        db: Database session.
        user: Authenticated user.

    Returns:
        Gateway details.

    Raises:
        HTTPException: If the gateway is not found.
        Exception: For any other unexpected errors.

    Examples:
        >>> callable(admin_get_gateway)
        True
        >>> admin_get_gateway.__name__
        'admin_get_gateway'
    """
    LOGGER.debug(f"User {get_user_email(user)} requested details for gateway ID {gateway_id}")
    try:
        auth_user_email, auth_token_teams = get_scoped_resource_access_context(request, user)
        gateway = await gateway_service.get_gateway(db, gateway_id, user_email=auth_user_email, token_teams=auth_token_teams)
        return gateway.model_dump(by_alias=True)
    except GatewayLookupConflictError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except GatewayNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        LOGGER.error(f"Error getting gateway {gateway_id}: {e}")
        raise e


@router.post("/gateways/discover-oauth")
@require_permission("gateways.create", allow_admin_bypass=False)
async def admin_discover_oauth(
    request: Request,
    user: dict[str, Any] = Depends(get_current_user_with_permissions),  # pylint: disable=unused-argument
) -> JSONResponse:
    """Discover OAuth/OIDC endpoints from an issuer URL (RFC 8414 / OIDC discovery).

    Args:
        request: FastAPI request containing JSON body with 'issuer' field.
        user: Authenticated user.

    Returns:
        JSONResponse with discovered endpoints or error message.

    Examples:
        >>> callable(admin_discover_oauth)
        True
    """
    # First-Party
    from mcpgateway.services.dcr_service import DcrService  # pylint: disable=import-outside-toplevel
    from mcpgateway.utils.url_auth import sanitize_exception_message  # pylint: disable=import-outside-toplevel

    try:
        body = await request.json()
    except Exception:
        LOGGER.warning("OAuth discovery failed: invalid JSON body")
        return JSONResponse(
            {"success": False, "error": "Invalid JSON body"},
            status_code=400,
        )

    if not isinstance(body, dict):
        return JSONResponse(
            {"success": False, "error": "Request body must be a JSON object"},
            status_code=400,
        )

    issuer = body.get("issuer", "").strip()
    if not issuer:
        return JSONResponse(
            {"success": False, "error": "issuer is required"},
            status_code=400,
        )

    try:
        SecurityValidator.validate_url(issuer, "OAuth issuer URL")
    except ValueError as _e:
        return JSONResponse(
            {"success": False, "error": f"Invalid issuer URL: {_e}"},
            status_code=400,
        )

    try:
        dcr = DcrService()
        metadata = await dcr.discover_as_metadata(issuer)

        def _safe_endpoint(raw: str | None, name: str) -> str | None:
            """Validate and return an OAuth endpoint URL, or None if invalid.

            Args:
                raw: The raw endpoint URL string or None.
                name: The name of the endpoint for validation error messages.

            Returns:
                The validated URL string if valid, None otherwise.
            """
            if not raw:
                return None
            try:
                SecurityValidator.validate_url(raw, name)
                return raw
            except ValueError:
                return None

        return JSONResponse(
            {
                "success": True,
                "token_endpoint": _safe_endpoint(metadata.get("token_endpoint"), "token_endpoint"),
                "authorization_endpoint": _safe_endpoint(metadata.get("authorization_endpoint"), "authorization_endpoint"),
                "jwks_uri": _safe_endpoint(metadata.get("jwks_uri"), "jwks_uri"),
                "registration_endpoint": _safe_endpoint(metadata.get("registration_endpoint"), "registration_endpoint"),
                "dcr_available": bool(metadata.get("registration_endpoint")),
                "scopes_supported": metadata.get("scopes_supported", []),
                "grant_types_supported": metadata.get("grant_types_supported", []),
            }
        )
    except Exception as e:
        LOGGER.warning("OAuth discovery failed: %s", e)
        sanitized = sanitize_exception_message(str(e))
        return JSONResponse(
            {
                "success": False,
                "error": sanitized,
                "message": "Discovery failed. Please configure token and authorization endpoints manually.",
            },
            status_code=502,
        )


@router.post("/gateways", response_model=None)
@require_permission("gateways.create", allow_admin_bypass=False)
async def admin_add_gateway(
    request: Request,
    db: Session = Depends(get_db),
    user: dict[str, Any] = Depends(get_current_user_with_permissions),
) -> JSONResponse:
    """Add a gateway via Admin API.

    Accepts both JSON (application/json) and form data (multipart/form-data).

    **JSON Example:**
    ```json
    {
      "name": "my-gateway",
      "url": "http://localhost:9000/sse",
      "transport": "SSE",
      "description": "My gateway",
      "tags": ["tag1", "tag2"],
      "visibility": "private"
    }
    ```

    **Form Data Example:**
    ```
    name=my-gateway
    url=http://localhost:9000/sse
    transport=SSE
    tags=tag1,tag2
    ```

    Args:
        request: FastAPI request containing JSON or form data.
        gateway_data: Optional pre-parsed Pydantic model (for JSON requests).
        db: Database session.
        user: Authenticated user.

    Returns:
        JSON response with success status and message.

    Raises:
        HTTPException: 422 when public visibility is disabled and request is team-scoped.
    """
    LOGGER.debug(f"User {get_user_email(user)} is adding a new gateway")

    # Parse request data (supports both JSON and form-data)
    try:
        data = await _parse_gateway_data_from_request(request)
    except HTTPException:
        raise
    except Exception as e:
        return ORJSONResponse(content={"message": f"Invalid request data: {e}", "success": False}, status_code=400)

    team_id = data.get("team_id")
    if team_id and isinstance(team_id, str):
        team_id = team_id.strip() or None
    visibility = str(data.get("visibility", "private"))

    _check_public_visibility_allowed(visibility, team_id=team_id)

    try:
        # Handle OAuth client secret encryption if present
        oauth_config = data.get("oauth_config")
        if oauth_config and isinstance(oauth_config, dict) and "client_secret" in oauth_config:
            client_secret = oauth_config.get("client_secret")
            if client_secret and isinstance(client_secret, str):
                encryption = get_encryption_service(settings.auth_encryption_secret)
                oauth_config["client_secret"] = await encryption.encrypt_secret_async(client_secret)
                data["oauth_config"] = oauth_config

        # Handle CA certificate signing
        ca_certificate = data.get("ca_certificate")
        sig: Optional[str] = None
        if ca_certificate and isinstance(ca_certificate, str) and ca_certificate.strip():
            ca_certificate = ca_certificate.strip()
            if settings.enable_ed25519_signing:
                try:
                    private_key_pem = settings.ed25519_private_key.get_secret_value()
                    sig = sign_data(ca_certificate.encode(), private_key_pem)
                    data["ca_certificate_sig"] = sig
                    data["signing_algorithm"] = "ed25519"
                except Exception as e:
                    LOGGER.error(f"Error signing CA certificate: {e}")
                    raise RuntimeError("Failed to sign CA certificate") from e
            else:
                # Explicitly set to None when signing is disabled
                data["ca_certificate_sig"] = None
                data["signing_algorithm"] = None

        # Auto-detect OAuth auth_type
        if oauth_config and not data.get("auth_type"):
            data["auth_type"] = "oauth"
            LOGGER.info("✅ Auto-detected OAuth configuration, setting auth_type='oauth'")

        # Create GatewayCreate model from data
        gateway = GatewayCreate(**data)

    except ValidationError as ex:
        # --- Getting only the custom message from the ValueError ---
        error_ctx = [str(err.get("ctx", {}).get("error", err.get("msg", str(err)))) for err in ex.errors()]
        return ORJSONResponse(content={"success": False, "message": "; ".join(error_ctx)}, status_code=422)

    except RuntimeError as err:
        # --- Getting only the custom message from the RuntimeError ---
        error_ctx = [str(err)]
        return ORJSONResponse(content={"success": False, "message": "; ".join(error_ctx)}, status_code=422)

    user_email = get_user_email(user)

    team_service = TeamManagementService(db)
    team_id = await team_service.verify_team_for_user(user_email, team_id)

    try:
        # Extract creation metadata
        metadata = MetadataCapture.extract_creation_metadata(request, user)

        team_id_cast = typing_cast(Optional[str], team_id)
        result = await gateway_service.register_gateway(
            db,
            gateway,
            created_by=metadata["created_by"],
            created_from_ip=metadata["created_from_ip"],
            created_via=metadata["created_via"],
            created_user_agent=metadata["created_user_agent"],
            visibility=visibility,
            team_id=team_id_cast,
            owner_email=user_email,
            initialize_timeout=settings.httpx_admin_read_timeout,
        )

        # Provide specific guidance for OAuth Authorization Code flow
        is_pending = _gateway_result_status(result) == "pending"
        message = "Gateway registration accepted and pending initialization." if is_pending else "Gateway registered successfully!"
        if oauth_config and isinstance(oauth_config, dict) and oauth_config.get("grant_type") == "authorization_code":
            message = (
                "Gateway registered successfully! 🎉\n\n"
                "⚠️  IMPORTANT: This gateway uses OAuth Authorization Code flow.\n"
                "You must complete the OAuth authorization before tools will work:\n\n"
                "1. Go to the Gateways list\n"
                "2. Click the '🔐 Authorize' button for this gateway\n"
                "3. Complete the OAuth consent flow\n"
                "4. Return to the admin panel\n\n"
                "Tools will not work until OAuth authorization is completed."
            )
        skipped_tools = result.skipped_tools if isinstance(getattr(result, "skipped_tools", None), list) else []
        # `message` is for accepted/success lifecycle state. Failure responses use
        # `error` so admin UI can style async progress separately from errors.
        content: dict[str, Any] = {"message": message, "success": True, "skipped_tools": skipped_tools}
        gateway_payload = _gateway_result_payload(result)
        if gateway_payload is not None:
            content["gateway"] = gateway_payload
        return ORJSONResponse(content=content, status_code=202 if is_pending else 200)

    except PermissionError as ex:
        return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=403)
    except GatewayCredentialError as ex:
        return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=422)
    except GatewayConnectionError as ex:
        return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=502)
    except GatewayDuplicateConflictError as ex:
        return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=409)
    except GatewayNameConflictError as ex:
        return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=409)
    except GatewayToolNameConflictError as ex:
        return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=409)
    except RuntimeError as ex:
        return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=500)
    except ValidationError as ex:
        return ORJSONResponse(content=ErrorFormatter.format_validation_error(ex), status_code=422)
    # NOTE: Pydantic's ValidationError subclasses ValueError, so ValidationError must be handled first.
    except ValueError as ex:
        return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=400)
    except IntegrityError as ex:
        return ORJSONResponse(content=ErrorFormatter.format_database_error(ex), status_code=409)
    except DataError as ex:
        return ORJSONResponse(content=ErrorFormatter.format_database_error(ex), status_code=400)
    except Exception as ex:
        LOGGER.exception(f"Unexpected error in admin_add_gateway: {ex}")
        return ORJSONResponse(content={"message": "An unexpected error occurred. Please try again or contact support.", "success": False}, status_code=500)


# RESTful PUT endpoint for gateway updates (JSON/form-data support)
@router.put("/gateways/{gateway_id}", response_model=None)
@require_permission("gateways.update", allow_admin_bypass=False)
async def admin_update_gateway_rest(
    gateway_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: dict[str, Any] = Depends(get_current_user_with_permissions),
) -> JSONResponse:
    """Update a gateway via REST API (PUT).

    Accepts both JSON (application/json) and form data (multipart/form-data).

    **JSON Example:**
    ```json
    {
      "name": "updated-gateway",
      "url": "http://localhost:9001/sse",
      "description": "Updated description"
    }
    ```

    Args:
        gateway_id: Gateway ID to update.
        request: FastAPI request containing JSON or form data.
        gateway_data: Optional pre-parsed Pydantic model (for JSON requests).
        db: Database session.
        user: Authenticated user.

    Returns:
        JSON response with success status and message.
    """
    LOGGER.debug(f"User {get_user_email(user)} is updating gateway ID {gateway_id}")

    # Parse request data (supports both JSON and form-data)
    try:
        data = await _parse_gateway_data_from_request(request)
    except HTTPException:
        raise
    except Exception as e:
        return ORJSONResponse(content={"message": f"Invalid request data: {e}", "success": False}, status_code=400)

    team_id = data.get("team_id")
    if team_id and isinstance(team_id, str):
        team_id = team_id.strip() or None
    visibility = str(data.get("visibility", "private"))

    _check_public_visibility_allowed(visibility, team_id=team_id)

    try:
        # Handle OAuth client secret encryption if present
        oauth_config = data.get("oauth_config")
        if oauth_config and isinstance(oauth_config, dict) and "client_secret" in oauth_config:
            client_secret = oauth_config.get("client_secret")
            if client_secret and isinstance(client_secret, str):
                encryption = get_encryption_service(settings.auth_encryption_secret)
                oauth_config["client_secret"] = await encryption.encrypt_secret_async(client_secret)
                data["oauth_config"] = oauth_config

        # Auto-detect OAuth auth_type
        if oauth_config and not data.get("auth_type"):
            data["auth_type"] = "oauth"

        user_email = get_user_email(user)

        # Fetch existing gateway to preserve owner_email and team_id
        existing_gateway = db.get(DbGateway, gateway_id)
        if not existing_gateway:
            return ORJSONResponse(content={"message": "Gateway not found", "success": False}, status_code=404)

        # Preserve existing owner_email (don't transfer ownership)
        existing_owner = getattr(existing_gateway, "owner_email", None)
        if existing_owner:
            data["owner_email"] = existing_owner

        # Preserve existing gateway's team_id when no explicit team_id is provided
        if not team_id:
            existing_team = getattr(existing_gateway, "team_id", None)
            if isinstance(existing_team, str) and existing_team:
                team_id = existing_team

        team_service = TeamManagementService(db)
        team_id = await team_service.verify_team_for_user(user_email, team_id)

        # Set team_id (but not owner_email, which was preserved above)
        data["team_id"] = team_id

        # Create GatewayUpdate model from data
        gateway = GatewayUpdate(**data)

        mod_metadata = MetadataCapture.extract_modification_metadata(request, user, 0)
        result = await gateway_service.update_gateway(
            db,
            gateway_id,
            gateway,
            modified_by=mod_metadata["modified_by"],
            modified_from_ip=mod_metadata["modified_from_ip"],
            modified_via=mod_metadata["modified_via"],
            modified_user_agent=mod_metadata["modified_user_agent"],
            user_email=user_email,
        )
        is_pending = _gateway_result_status(result) == "pending"
        # Keep accepted/success text in `message`; reserve `error` for failures.
        content: dict[str, Any] = {
            "message": "Gateway update accepted and pending initialization." if is_pending else "Gateway updated successfully!",
            "success": True,
        }
        gateway_payload = _gateway_result_payload(result)
        if gateway_payload is not None:
            content["gateway"] = gateway_payload
        return ORJSONResponse(content=content, status_code=202 if is_pending else 200)
    except PermissionError as e:
        LOGGER.info(f"Permission denied for user {get_user_email(user)}: {e}")
        return ORJSONResponse(content={"message": str(e), "success": False}, status_code=403)
    except HTTPException:
        raise
    except GatewayNotFoundError as e:
        return ORJSONResponse(content={"message": str(e), "success": False}, status_code=404)
    except Exception as ex:
        if isinstance(ex, GatewayToolNameConflictError):
            return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=409)
        if isinstance(ex, GatewayCredentialError):
            return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=422)
        if isinstance(ex, GatewayConnectionError):
            return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=502)
        if isinstance(ex, RuntimeError):
            return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=500)
        if isinstance(ex, ValidationError):
            return ORJSONResponse(content=ErrorFormatter.format_validation_error(ex), status_code=422)
        if isinstance(ex, IntegrityError):
            return ORJSONResponse(status_code=409, content=ErrorFormatter.format_database_error(ex))
        if isinstance(ex, ValueError):
            return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=400)
        LOGGER.exception(f"Unexpected error in admin_update_gateway_rest: {ex}")
        return ORJSONResponse(content={"message": "An unexpected error occurred. Please try again or contact support.", "success": False}, status_code=500)


# RESTful DELETE endpoint for gateway deletion
@router.delete("/gateways/{gateway_id}", response_model=None, status_code=204)
@require_permission("gateways.delete", allow_admin_bypass=False)
async def admin_delete_gateway_rest(
    gateway_id: str,
    db: Session = Depends(get_db),
    user: dict[str, Any] = Depends(get_current_user_with_permissions),
) -> Response:
    """Delete a gateway via REST API (DELETE).

    **Example Request:**
    ```bash
    curl -X DELETE http://localhost:4444/admin/gateways/gw-123 \
         -H "Authorization: Bearer $TOKEN"
    ```

    **Example Response (204):**
    ```
    (No content - empty response body)
    ```

    Args:
        gateway_id: The ID of the gateway to delete.
        db: Database session.
        user: Authenticated user.

    Returns:
        204 No Content on success, or error response with appropriate status code.
    """
    user_email = get_user_email(user)
    LOGGER.debug(f"User {user_email} is deleting gateway ID {gateway_id}")

    try:
        result = await gateway_service.delete_gateway(db, gateway_id, user_email=user_email)
        if getattr(result, "status", None) == "deleting":
            return ORJSONResponse(
                content={
                    "message": "Gateway deletion accepted and pending cleanup.",
                    "success": True,
                    "gateway": result.model_dump(mode="json", by_alias=True),
                },
                status_code=202,
            )
        return Response(status_code=204)
    except PermissionError as e:
        LOGGER.warning("Permission denied for user %s deleting gateway %s: %s", SecurityValidator.sanitize_log_message(user_email), SecurityValidator.sanitize_log_message(gateway_id), e)
        return ORJSONResponse(content={"message": str(e), "success": False}, status_code=403)
    except GatewayNotFoundError as e:
        return ORJSONResponse(content={"message": str(e), "success": False}, status_code=404)
    except Exception as e:
        LOGGER.error(f"Error deleting gateway: {e}")
        return ORJSONResponse(
            content={"message": "Failed to delete gateway. Please try again.", "success": False},
            status_code=500,
        )


# Ownership transfer endpoint for gateways
@router.post("/gateways/{gateway_id}/transfer-ownership", response_model=GatewayRead)
@require_admin_permission()
async def transfer_gateway_ownership(
    gateway_id: str,
    transfer: GatewayOwnershipTransferRequest,
    db: Session = Depends(get_db),
    _user=Depends(get_current_user_with_permissions),
) -> GatewayRead:
    """Transfer ownership of a gateway to another user.

    Args:
        gateway_id: The ID of the gateway to transfer.
        transfer: Transfer request with target owner email and optional team.
        db: Database session.
        _user: Authenticated admin user.

    Returns:
        Updated GatewayRead with new ownership.
    """
    actor_email = get_user_email(_user)
    token_teams = extract_token_team_ids(_user)
    try:
        result = await gateway_service.transfer_gateway_ownership(
            db=db,
            gateway_id=gateway_id,
            target_owner_email=transfer.target_owner_email,
            actor_email=actor_email,
            target_team_id=transfer.target_team_id,
            token_teams=token_teams,
        )
        return result
    except GatewayNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# Legacy POST endpoint for backward compatibility with HTMX UI
# OAuth callback is now handled by the dedicated OAuth router at /oauth/callback
# This route has been removed to avoid conflicts with the complete implementation
@router.post("/gateways/{gateway_id}/edit")
@require_permission("gateways.update", allow_admin_bypass=False)
async def admin_edit_gateway(
    gateway_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> JSONResponse:
    """Edit a gateway via the admin UI.

    Expects form fields:
      - name
      - url
      - description (optional)
      - tags (optional, comma-separated)

    Args:
        gateway_id: Gateway ID.
        request: FastAPI request containing form data.
        db: Database session.
        user: Authenticated user.

    Returns:
        A redirect response to the admin dashboard.

    Raises:
        HTTPException: 422 when public visibility is disabled and request is team-scoped.

    Examples:
        >>> callable(admin_edit_gateway)
        True
        >>> admin_edit_gateway.__name__
        'admin_edit_gateway'
    """
    LOGGER.debug(f"User {get_user_email(user)} is editing gateway ID {gateway_id}")
    form = await request.form()
    team_id = _form_team_id(form)
    try:
        # Parse tags from comma-separated string
        tags_str = str(form.get("tags", ""))
        tags: List[str] = [tag.strip() for tag in tags_str.split(",") if tag.strip()] if tags_str else []

        visibility = str(form.get("visibility", "private"))
        _check_public_visibility_allowed(visibility, team_id=team_id)

        auth_headers = _parse_auth_headers_field(form)

        passthrough_headers = _parse_passthrough_headers_field(form)

        oauth_config: Optional[dict[str, Any]] = await _parse_oauth_config_json_field(form.get("oauth_config"), encrypt_client_secret=True)

        # Assemble from individual UI form fields when no pre-assembled JSON was sent.
        if not oauth_config:
            oauth_config = await _assemble_oauth_config_from_fields(form, encrypt_secret=True)
            if oauth_config:
                LOGGER.info(f"✅ Assembled OAuth config from UI form fields (edit): grant_type={oauth_config.get('grant_type')}, issuer={oauth_config.get('issuer')}")

        user_email = get_user_email(user)
        # Fetch existing gateway once to preserve team_id and any oauth_config fields that
        # the UI edit form does not expose (e.g. redirect_uri_after_oauth).
        existing_gateway = db.get(DbGateway, gateway_id)

        # Preserve existing gateway's team_id when no explicit team_id is provided.
        # Without this guard, verify_team_for_user() falls back to the user's
        # personal team, silently reassigning the gateway on every edit.
        if not team_id:
            existing_team = getattr(existing_gateway, "team_id", None) if existing_gateway else None
            if isinstance(existing_team, str) and existing_team:
                team_id = existing_team

        # Preserve redirect_uri_after_oauth when this deployment does not render the
        # field. A rendered but blank field explicitly disables the redirect.
        if oauth_config is not None and existing_gateway is not None:
            existing_oauth: dict = existing_gateway.oauth_config or {}
            if "redirect_uri_after_success" not in form and "redirect_uri_after_oauth" not in oauth_config and "redirect_uri_after_oauth" in existing_oauth:
                oauth_config["redirect_uri_after_oauth"] = existing_oauth["redirect_uri_after_oauth"]

        team_service = TeamManagementService(db)
        team_id = await team_service.verify_team_for_user(user_email, team_id)

        # Auto-detect OAuth: if oauth_config is present and auth_type not explicitly set, use "oauth"
        auth_type_from_form = str(form.get("auth_type", ""))
        if oauth_config and not auth_type_from_form:
            auth_type_from_form = "oauth"
            LOGGER.info("Auto-detected OAuth configuration in edit, setting auth_type='oauth'")

        gateway = GatewayUpdate(  # Pydantic validation happens here
            name=str(form.get("name")),
            url=str(form["url"]),
            description=str(form.get("description")),
            transport=str(form.get("transport", "SSE")),
            tags=tags,
            auth_type=auth_type_from_form,
            auth_username=str(form.get("auth_username", "")),
            auth_password=str(form.get("auth_password", "")),
            auth_token=str(form.get("auth_token", "")),
            auth_header_key=str(form.get("auth_header_key", "")),
            auth_header_value=str(form.get("auth_header_value", "")),
            auth_value=str(form.get("auth_value", "")),
            auth_headers=auth_headers if auth_headers else None,
            auth_query_param_key=str(form.get("auth_query_param_key", "")) or None,
            auth_query_param_value=str(form.get("auth_query_param_value", "")) or None,
            one_time_auth=form.get("one_time_auth", False),
            passthrough_headers=passthrough_headers,
            oauth_config=oauth_config,
            visibility=visibility,
            owner_email=user_email,
            team_id=team_id,
        )

        mod_metadata = MetadataCapture.extract_modification_metadata(request, user, 0)
        result = await gateway_service.update_gateway(
            db,
            gateway_id,
            gateway,
            modified_by=mod_metadata["modified_by"],
            modified_from_ip=mod_metadata["modified_from_ip"],
            modified_via=mod_metadata["modified_via"],
            modified_user_agent=mod_metadata["modified_user_agent"],
            user_email=user_email,
        )
        is_pending = _gateway_result_status(result) == "pending"
        # Keep accepted/success text in `message`; reserve `error` for failures.
        content: dict[str, Any] = {
            "message": "Gateway update accepted and pending initialization." if is_pending else "Gateway updated successfully!",
            "success": True,
        }
        gateway_payload = _gateway_result_payload(result)
        if gateway_payload is not None:
            content["gateway"] = gateway_payload
        return ORJSONResponse(content=content, status_code=202 if is_pending else 200)
    except PermissionError as e:
        LOGGER.info(f"Permission denied for user {get_user_email(user)}: {e}")
        return ORJSONResponse(
            content={"message": str(e), "success": False},
            status_code=403,
        )
    except HTTPException:
        raise
    except Exception as ex:
        if isinstance(ex, GatewayToolNameConflictError):
            return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=409)
        if isinstance(ex, GatewayCredentialError):
            return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=422)
        if isinstance(ex, GatewayConnectionError):
            return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=502)
        if isinstance(ex, RuntimeError):
            return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=500)
        if isinstance(ex, ValidationError):
            return ORJSONResponse(content=ErrorFormatter.format_validation_error(ex), status_code=422)
        if isinstance(ex, IntegrityError):
            return ORJSONResponse(status_code=409, content=ErrorFormatter.format_database_error(ex))
        # NOTE: Pydantic's ValidationError subclasses ValueError, so ValidationError must be handled first.
        if isinstance(ex, ValueError):
            return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=400)
        LOGGER.exception(f"Unexpected error in admin_edit_gateway: {ex}")
        return ORJSONResponse(content={"message": "An unexpected error occurred. Please try again or contact support.", "success": False}, status_code=500)


@router.post("/gateways/{gateway_id}/delete")
@require_permission("gateways.delete", allow_admin_bypass=False)
async def admin_delete_gateway(gateway_id: str, request: Request, db: Session = Depends(get_db), user=Depends(get_current_user_with_permissions)) -> RedirectResponse:
    """
    Delete a gateway via the admin UI.

    This endpoint removes a gateway from the database by its ID. The deletion is
    permanent and cannot be undone. It requires authentication and logs the
    operation for auditing purposes.

    Args:
        gateway_id (str): The ID of the gateway to delete.
        request (Request): FastAPI request object (not used directly but required by the route signature).
        db (Session): Database session dependency.
        user (str): Authenticated user dependency.

    Returns:
        RedirectResponse: A redirect response to the gateways section of the admin
        dashboard with a status code of 303 (See Other).

    Examples:
        >>> callable(admin_delete_gateway)
        True
        >>> admin_delete_gateway.__name__
        'admin_delete_gateway'
    """
    user_email = get_user_email(user)
    LOGGER.debug(f"User {user_email} is deleting gateway ID {gateway_id}")
    error_message = None
    accepted_message = None
    try:
        result = await gateway_service.delete_gateway(db, gateway_id, user_email=user_email)
        if getattr(result, "status", None) == "deleting":
            accepted_message = "Gateway deletion accepted and pending cleanup."
    except PermissionError as e:
        LOGGER.warning("Permission denied for user %s deleting gateway %s: %s", SecurityValidator.sanitize_log_message(user_email), SecurityValidator.sanitize_log_message(gateway_id), e)
        error_message = str(e)
    except Exception as e:
        LOGGER.error(f"Error deleting gateway: {e}")
        error_message = "Failed to delete gateway. Please try again."

    form = await request.form()
    is_inactive_checked = str(form.get("is_inactive_checked", "false"))
    root_path = _resolve_root_path(request)
    team_id = str(form.get("team_id", "") or "")
    redirect_url = _build_admin_redirect(
        root_path,
        "gateways",
        error=error_message,
        message=accepted_message,
        include_inactive=is_inactive_checked.lower() == "true",
        team_id=team_id,
    )
    return RedirectResponse(redirect_url, status_code=303)


@router.post("/gateways/test", response_model=GatewayTestResponse)
@require_permission("gateways.read", allow_admin_bypass=False)
async def admin_test_gateway(
    request: GatewayTestRequest, team_id: Optional[str] = Depends(_validated_team_id_param), user=Depends(get_current_user_with_permissions), db: Session = Depends(get_db)
) -> GatewayTestResponse:
    """
    Test a gateway by sending a request to its URL.
    This endpoint allows administrators to test the connectivity and response

    Args:
        request (GatewayTestRequest): The request object containing the gateway URL and request details.
        team_id (Optional[str]): Optional team ID for team-specific gateways.
        user (str): Authenticated user dependency.
        db (Session): Database session dependency.

    Returns:
        GatewayTestResponse: The response from the gateway, including status code, latency, and body

    Examples:
        >>> callable(admin_test_gateway)
        True
        >>> admin_test_gateway.__name__
        'admin_test_gateway'
    """
    # Reject cross-team access: token_teams=None means admin bypass; a list means the
    # caller is scoped to those teams only. A caller-supplied team_id outside that list
    # would allow enumerating other teams' registered gateway hostnames (SSRF allowlist).
    if team_id is not None:
        token_teams = user.get("token_teams") if isinstance(user, dict) else None
        if token_teams is not None and team_id not in token_teams:
            raise HTTPException(status_code=403, detail="Access to requested team is not permitted")
    return await test_gateway_connectivity(request, team_id, user, db)
