# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/admin/servers.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Admin UI server routes: list, partial, ids, search, detail, create, edit,
delete, and state change.
"""

# Standard
import binascii
import logging
from typing import Any, Dict, Optional, cast as typing_cast

# Third-Party
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.encoders import jsonable_encoder
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import ValidationError
from pydantic_core import ValidationError as CoreValidationError
from sqlalchemy import and_, case, desc, false, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import joinedload, selectinload, Session, with_loader_criteria
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
    _merge_select_all_ids,
    _normalize_search_query,
    _normalize_tags_query,
    _owner_access_condition,
    _parse_tag_filter_groups,
    _validated_team_id_param,
    server_service,
)
from mcpgateway.admin.security import enforce_admin_csrf
from mcpgateway.auth_context import get_scoped_resource_access_context, get_token_teams_from_request, get_user_email
from mcpgateway.common.query_params import QueryRenderMode, QueryTagsFilter
from mcpgateway.common.validators import SecurityValidator
from mcpgateway.config import settings
from mcpgateway.db import A2AAgent as DbA2AAgent, get_db, Prompt as DbPrompt, Resource as DbResource, Server as DbServer, Tool as DbTool
from mcpgateway.middleware.rbac import get_current_user_with_permissions, require_permission
from mcpgateway.schemas import PaginatedResponse, ServerCreate, ServerRead, ServerUpdate
from mcpgateway.services.server_service import ServerError, ServerLockConflictError, ServerNameConflictError, ServerNotFoundError
from mcpgateway.services.team_management_service import TeamManagementService
from mcpgateway.utils.error_formatter import ErrorFormatter
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


@router.get("/servers", response_model=PaginatedResponse)
@require_permission("servers.read", allow_admin_bypass=False)
async def admin_list_servers(
    request: Request,
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    per_page: int = Query(settings.pagination_default_page_size, ge=1, le=settings.pagination_max_page_size, description="Items per page"),
    include_inactive: bool = False,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> Dict[str, Any]:
    """
    List servers for the admin UI with pagination support.

    This endpoint retrieves a paginated list of servers from the database, optionally
    including those that are inactive. Uses offset-based (page/per_page) pagination.

    Args:
        request (Request): FastAPI request object (required for token team extraction via request.state.token_teams).
        page (int): Page number (1-indexed) for offset pagination.
        per_page (int): Number of items per page.
        include_inactive (bool): Whether to include inactive servers.
        db (Session): The database session dependency.
        user (str): The authenticated user dependency.

    Returns:
        Dict[str, Any]: A dictionary containing:
            - data: List of server records formatted with by_alias=True
            - pagination: Pagination metadata
            - links: Pagination links (optional)

    Examples:
        >>> callable(admin_list_servers)
        True
        >>> admin_list_servers.__name__
        'admin_list_servers'
    """
    LOGGER.debug(f"User {get_user_email(user)} requested server list (page={page}, per_page={per_page})")
    user_email = get_user_email(user)
    token_teams = get_token_teams_from_request(request)

    # Call server_service.list_servers with page-based pagination
    paginated_result = await server_service.list_servers(
        db=db,
        include_inactive=include_inactive,
        page=page,
        per_page=per_page,
        user_email=user_email,
        token_teams=token_teams,
    )

    # End the read-only transaction early to avoid idle-in-transaction under load.
    db.commit()

    # Return standardized paginated response
    return {
        "data": [server.model_dump(by_alias=True) for server in paginated_result["data"]],
        "pagination": paginated_result["pagination"].model_dump(),
        "links": paginated_result["links"].model_dump() if paginated_result["links"] else None,
    }


@router.get("/servers/partial", response_class=HTMLResponse)
@require_permission("servers.read", allow_admin_bypass=False)
async def admin_servers_partial_html(
    request: Request,
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    per_page: int = Query(settings.pagination_default_page_size, ge=1, le=settings.pagination_max_page_size, description="Items per page"),
    q: str = Query("", max_length=500, description="Search query"),
    tags: QueryTagsFilter = None,
    include_inactive: bool = True,
    render: QueryRenderMode = None,
    team_id: Optional[str] = Depends(_validated_team_id_param),
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user_with_permissions),
) -> Response:
    """Return paginated servers HTML partials for the admin UI.

    This HTMX endpoint returns only the partial HTML used by the admin UI for
    servers. It supports three render modes:

    - default: full table partial (rows + controls)
    - ``render="controls"``: return only pagination controls
    - ``render="selector"``: return selector items for infinite scroll

    Args:
        request (Request): FastAPI request object used by the template engine.
        page (int): Page number (1-indexed).
        per_page (int): Number of items per page (bounded by settings).
        q (str): Free-text query string.
        tags (Optional[str]): Tag filter expression (comma=OR, plus=AND).
        include_inactive (bool): If True, include inactive servers in results.
        render (Optional[str]): Render mode; one of None, "controls", "selector".
        team_id (Optional[str]): Filter by team ID.
        db (Session): Database session (dependency-injected).
        user: Authenticated user object from dependency injection.

    Returns:
        Union[HTMLResponse, TemplateResponse]: A rendered template response
        containing either the table partial, pagination controls, or selector
        items depending on ``render``. The response contains JSON-serializable
        encoded server data when templates expect it.
    """
    LOGGER.debug(f"User {get_user_email(user)} requested servers HTML partial (page={page}, per_page={per_page}, include_inactive={include_inactive}, render={render}, team_id={team_id})")
    search_query = _normalize_search_query(q)
    normalized_tags = _normalize_tags_query(tags)
    tag_groups = _parse_tag_filter_groups(normalized_tags)

    # Normalize per_page within configured bounds
    per_page = max(settings.pagination_min_page_size, min(per_page, settings.pagination_max_page_size))

    user_email = get_user_email(user)

    # Team scoping
    team_ids = await _get_user_team_ids(user, db)

    # Build base query with eager loading to avoid N+1 queries
    # Filter out deactivated tools, resources, prompts, and agents at query level
    query = select(DbServer).options(
        selectinload(DbServer.tools),
        with_loader_criteria(DbTool, DbTool.enabled.is_(True)),
        selectinload(DbServer.resources),
        with_loader_criteria(DbResource, DbResource.enabled.is_(True)),
        selectinload(DbServer.prompts),
        with_loader_criteria(DbPrompt, DbPrompt.enabled.is_(True)),
        selectinload(DbServer.a2a_agents),
        with_loader_criteria(DbA2AAgent, DbA2AAgent.enabled.is_(True)),
        joinedload(DbServer.email_team),
    )

    if not include_inactive:
        query = query.where(DbServer.enabled.is_(True))

    # Build access conditions
    # When team_id is specified, show ONLY items from that team (team-scoped view)
    # Otherwise, show all accessible items (All Teams view)
    if team_id:
        # Team-specific view: only show servers from the specified team
        if team_id in team_ids:
            # Apply visibility check: team/public resources + user's own resources (including private)
            team_access = [
                and_(DbServer.team_id == team_id, DbServer.visibility.in_(["team", "public"])),
                and_(DbServer.team_id == team_id, DbServer.owner_email == user_email),
            ]
            query = query.where(or_(*team_access))
            LOGGER.debug(f"Filtering servers by team_id: {team_id}")
        else:
            # User is not a member of this team, return no results using SQLAlchemy's false()
            LOGGER.warning("User %s attempted to filter by team %s but is not a member", SecurityValidator.sanitize_log_message(user_email), SecurityValidator.sanitize_log_message(str(team_id)))
            query = query.where(false())
    else:
        # All Teams view: apply standard access conditions (owner, team, public)
        access_conditions = []
        access_conditions.append(_owner_access_condition(DbServer.owner_email, DbServer.team_id, user_email=user_email, team_ids=team_ids, user=user))
        if team_ids:
            access_conditions.append(and_(DbServer.team_id.in_(team_ids), DbServer.visibility.in_(["team", "public"])))
        access_conditions.append(DbServer.visibility == "public")
        query = query.where(or_(*access_conditions))

    if search_query:
        query = query.where(
            or_(
                _like_contains(func.lower(DbServer.id), search_query),
                _like_contains(func.lower(DbServer.name), search_query),
                _like_contains(func.lower(coalesce(DbServer.description, "")), search_query),
            )
        )

    query = _apply_tag_filter_groups(query, db, DbServer.tags, tag_groups)

    # Apply pagination ordering for cursor support
    query = query.order_by(desc(DbServer.created_at), desc(DbServer.id))

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
    base_url = f"{root_path}/admin/servers/partial"
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

    # Extract paginated servers (DbServer objects)
    servers_db = paginated_result["data"]
    pagination = paginated_result["pagination"]
    links = paginated_result["links"]

    # Team names are loaded via joinedload(DbServer.email_team) and accessed via server.team property

    # Batch convert to Pydantic models using server service
    # This eliminates the N+1 query problem from calling get_server_details() in a loop
    servers_pydantic = []
    failed_count = 0
    for s in servers_db:
        try:
            servers_pydantic.append(server_service.convert_server_to_read(s, include_metrics=False))
        except (ValidationError, ValueError, KeyError, TypeError, binascii.Error) as e:
            failed_count += 1
            LOGGER.exception(f"Failed to convert server {getattr(s, 'id', 'unknown')} ({getattr(s, 'name', 'unknown')}): {e}")
    _adjust_pagination_for_conversion_failures(pagination, failed_count, len(servers_pydantic))
    data = jsonable_encoder(servers_pydantic)

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
                "hx_target": "#servers-table-body",
                "hx_indicator": "#servers-loading",
                "query_params": query_params,
                "root_path": _resolve_root_path(request),
            },
        )

    if render == "selector":
        return request.app.state.templates.TemplateResponse(
            request,
            "servers_selector_items.html",
            {
                "request": request,
                "data": data,
                "pagination": pagination.model_dump(),
                "root_path": _resolve_root_path(request),
            },
        )

    _is_admin = bool(user.get("is_admin", False) if isinstance(user, dict) else getattr(user, "is_admin", False))
    _team_roles = _get_user_team_roles(db, user_email) if not _is_admin else {}
    return request.app.state.templates.TemplateResponse(
        request,
        "servers_partial.html",
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


@router.get("/servers/{server_id}", response_model=ServerRead)
@require_permission("servers.read", allow_admin_bypass=False)
async def admin_get_server(server_id: str, request: Request, db: Session = Depends(get_db), user=Depends(get_current_user_with_permissions)) -> Dict[str, Any]:
    """
    Retrieve server details for the admin UI.

    Args:
        server_id (str): The ID of the server to retrieve.
        request (Request): Incoming FastAPI request (for visibility scope resolution).
        db (Session): The database session dependency.
        user (str): The authenticated user dependency.

    Returns:
        Dict[str, Any]: The server details.

    Raises:
        HTTPException: If the server is not found.
        Exception: For any other unexpected errors.

    Examples:
        >>> callable(admin_get_server)
        True
        >>> admin_get_server.__name__
        'admin_get_server'
    """
    try:
        LOGGER.debug(f"User {get_user_email(user)} requested details for server ID {server_id}")
        auth_user_email, auth_token_teams = get_scoped_resource_access_context(request, user)
        server = await server_service.get_server(db, server_id, user_email=auth_user_email, token_teams=auth_token_teams)
        return server.masked().model_dump(by_alias=True)
    except ServerNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        LOGGER.error("Error getting server %s: %s", SecurityValidator.sanitize_log_message(str(server_id)), e)
        raise e


@router.post("/servers", response_model=ServerRead)
@require_permission("servers.create", allow_admin_bypass=False)
async def admin_add_server(request: Request, db: Session = Depends(get_db), user=Depends(get_current_user_with_permissions)) -> JSONResponse:
    """
    Add a new server via the admin UI.

    This endpoint processes form data to create a new server entry in the database.
    It handles exceptions gracefully and logs any errors that occur during server
    registration.

    Expects form fields:
      - name (required): The name of the server
      - description (optional): A description of the server's purpose
      - icon (optional): URL or path to the server's icon
      - associatedTools (optional, multiple values): Tools associated with this server
      - associatedResources (optional, multiple values): Resources associated with this server
      - associatedPrompts (optional, multiple values): Prompts associated with this server

    Args:
        request (Request): FastAPI request containing form data.
        db (Session): Database session dependency
        user (str): Authenticated user dependency

    Returns:
        JSONResponse: A JSON response indicating success or failure of the server creation operation.

    Raises:
        HTTPException: 422 when public visibility is disabled and request is team-scoped.

    Examples:
        >>> # Test function exists and has correct name
        >>> from mcpgateway.admin import admin_add_server
        >>> admin_add_server.__name__
        'admin_add_server'
        >>> # Test it's a coroutine function
        >>> import inspect
        >>> inspect.iscoroutinefunction(admin_add_server)
        True
    """
    form = await request.form()
    # is_inactive_checked = form.get("is_inactive_checked", "false")
    team_id = _form_team_id(form)

    # Parse tags from comma-separated string
    tags_str = str(form.get("tags", ""))
    tags: list[str] = [tag.strip() for tag in tags_str.split(",") if tag.strip()] if tags_str else []

    visibility = str(form.get("visibility", "private"))
    _check_public_visibility_allowed(visibility, team_id=team_id)

    try:
        LOGGER.debug(f"User {get_user_email(user)} is adding a new server with name: {form['name']}")

        # Handle "Select All" for tools, resources, and prompts.
        # _merge_select_all_ids takes the union of the server-fetched paginated IDs
        # (allToolIds etc.) with the explicitly checked form values so that
        # platform-public items visible in the UI are never silently dropped.
        associated_tools_list = _merge_select_all_ids(form, "selectAllTools", "allToolIds", form.getlist("associatedTools"))
        associated_resources_list = _merge_select_all_ids(form, "selectAllResources", "allResourceIds", form.getlist("associatedResources"))
        associated_prompts_list = _merge_select_all_ids(form, "selectAllPrompts", "allPromptIds", form.getlist("associatedPrompts"))

        # Handle OAuth 2.0 configuration (RFC 9728)
        oauth_enabled = form.get("oauth_enabled") == "on"
        oauth_config = None
        if oauth_enabled:
            authorization_server = str(form.get("oauth_authorization_server", "")).strip()
            scopes_str = str(form.get("oauth_scopes", "")).strip()
            token_endpoint = str(form.get("oauth_token_endpoint", "")).strip()

            if authorization_server:
                oauth_config = {"authorization_servers": [authorization_server]}
                if scopes_str:
                    # Convert space-separated scopes to list
                    oauth_config["scopes_supported"] = scopes_str.split()
                if token_endpoint:
                    oauth_config["token_endpoint"] = token_endpoint

                # Add audience parameter (for Atlassian, Auth0, and other non-RFC-8707 providers)
                oauth_audience = str(form.get("oauth_audience", "")).strip()
                if oauth_audience:
                    oauth_config["audience"] = oauth_audience
            else:
                # Invalid or incomplete OAuth configuration; disable OAuth to avoid inconsistent state
                LOGGER.warning(
                    "OAuth was enabled for server '%s' but no authorization server was provided; disabling OAuth for this server.",
                    form.get("name"),
                )
                oauth_enabled = False
                oauth_config = None

        server = ServerCreate(
            id=form.get("id") or None,
            name=form.get("name"),
            description=form.get("description"),
            icon=form.get("icon"),
            associated_tools=",".join(str(x) for x in associated_tools_list),
            associated_resources=",".join(str(x) for x in associated_resources_list),
            associated_prompts=",".join(str(x) for x in associated_prompts_list),
            tags=tags,
            visibility=visibility,
            oauth_enabled=oauth_enabled,
            oauth_config=oauth_config,
        )
    except KeyError as e:
        # Convert KeyError to ValidationError-like response
        return ORJSONResponse(content={"message": f"Missing required field: {e}", "success": False}, status_code=422)
    try:
        user_email = get_user_email(user)
        team_service = TeamManagementService(db)
        team_id = await team_service.verify_team_for_user(user_email, team_id)

        # Extract metadata for server creation
        creation_metadata = MetadataCapture.extract_creation_metadata(request, user)

        # Ensure default visibility is private and assign to personal team when available
        team_id_cast = typing_cast(Optional[str], team_id)
        await server_service.register_server(
            db,
            server,
            created_by=user_email,  # Use the consistent user_email
            created_from_ip=creation_metadata["created_from_ip"],
            created_via=creation_metadata["created_via"],
            created_user_agent=creation_metadata["created_user_agent"],
            team_id=team_id_cast,
            visibility=visibility,
        )
        return ORJSONResponse(
            content={"message": "Server created successfully!", "success": True},
            status_code=200,
        )

    except CoreValidationError as ex:
        return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=422)
    except ServerNameConflictError as ex:
        return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=409)
    except ServerError as ex:
        return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=500)
    # NOTE: Pydantic validation errors subclass ValueError; CoreValidationError must be handled first.
    except ValueError as ex:
        return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=400)
    except IntegrityError as ex:
        return ORJSONResponse(content=ErrorFormatter.format_database_error(ex), status_code=409)
    except Exception as ex:
        LOGGER.exception(f"Unexpected error in admin_add_server: {ex}")
        return ORJSONResponse(content={"message": "An unexpected error occurred. Please try again or contact support.", "success": False}, status_code=500)


@router.post("/servers/{server_id}/edit")
@require_permission("servers.update", allow_admin_bypass=False)
async def admin_edit_server(
    server_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> JSONResponse:
    """
    Edit an existing server via the admin UI.

    This endpoint processes form data to update an existing server's properties.
    It handles exceptions gracefully and logs any errors that occur during the
    update operation.

    Expects form fields:
      - id (optional): Updated UUID for the server
      - name (optional): The updated name of the server
      - description (optional): An updated description of the server's purpose
      - icon (optional): Updated URL or path to the server's icon
      - associatedTools (optional, multiple values): Updated list of tools associated with this server
      - associatedResources (optional, multiple values): Updated list of resources associated with this server
      - associatedPrompts (optional, multiple values): Updated list of prompts associated with this server

    Args:
        server_id (str): The ID of the server to edit
        request (Request): FastAPI request containing form data
        db (Session): Database session dependency
        user (str): Authenticated user dependency

    Returns:
        JSONResponse: A JSON response indicating success or failure of the server update operation.

    Raises:
        HTTPException: 422 when public visibility is disabled and request is team-scoped.

    Examples:
        >>> callable(admin_edit_server)
        True
        >>> admin_edit_server.__name__
        'admin_edit_server'
    """
    form = await request.form()
    team_id = _form_team_id(form)

    # Parse tags from comma-separated string
    tags_str = str(form.get("tags", ""))
    tags: list[str] = [tag.strip() for tag in tags_str.split(",") if tag.strip()] if tags_str else []
    try:
        LOGGER.debug(f"User {get_user_email(user)} is editing server ID {server_id} with name: {form.get('name')}")
        visibility = str(form.get("visibility", "private"))
        _check_public_visibility_allowed(visibility, team_id=team_id)
        user_email = get_user_email(user)

        # Preserve existing server's team_id when no explicit team_id is provided.
        # Without this guard, verify_team_for_user() falls back to the user's
        # personal team, silently reassigning the server on every edit.
        if not team_id:
            existing_server = db.get(DbServer, server_id)
            existing_team = getattr(existing_server, "team_id", None) if existing_server else None
            if isinstance(existing_team, str) and existing_team:
                team_id = existing_team

        team_service = TeamManagementService(db)
        team_id = await team_service.verify_team_for_user(user_email, team_id)

        mod_metadata = MetadataCapture.extract_modification_metadata(request, user, 0)

        # Handle "Select All" for tools, resources, and prompts.
        # _merge_select_all_ids takes the union of the server-fetched paginated IDs
        # (allToolIds etc.) with the explicitly checked form values so that
        # platform-public items visible in the UI are never silently dropped.
        associated_tools_list = _merge_select_all_ids(form, "selectAllTools", "allToolIds", form.getlist("associatedTools"))
        associated_resources_list = _merge_select_all_ids(form, "selectAllResources", "allResourceIds", form.getlist("associatedResources"))
        associated_prompts_list = _merge_select_all_ids(form, "selectAllPrompts", "allPromptIds", form.getlist("associatedPrompts"))

        # Handle OAuth 2.0 configuration (RFC 9728)
        oauth_enabled = form.get("oauth_enabled") == "on"
        oauth_config = None
        if oauth_enabled:
            authorization_server = str(form.get("oauth_authorization_server", "")).strip()
            scopes_str = str(form.get("oauth_scopes", "")).strip()
            token_endpoint = str(form.get("oauth_token_endpoint", "")).strip()

            if authorization_server:
                oauth_config = {"authorization_servers": [authorization_server]}
                if scopes_str:
                    # Convert space-separated scopes to list
                    oauth_config["scopes_supported"] = scopes_str.split()
                if token_endpoint:
                    oauth_config["token_endpoint"] = token_endpoint

                # Add audience parameter (for Atlassian, Auth0, and other non-RFC-8707 providers)
                oauth_audience = str(form.get("oauth_audience", "")).strip()
                if oauth_audience:
                    oauth_config["audience"] = oauth_audience
            else:
                # Invalid or incomplete OAuth configuration; disable OAuth to avoid inconsistent state
                LOGGER.warning(
                    "OAuth was enabled for server '%s' but no authorization server was provided; disabling OAuth for this server.",
                    form.get("name"),
                )
                oauth_enabled = False
                oauth_config = None

        server = ServerUpdate(
            id=form.get("id"),
            name=form.get("name"),
            description=form.get("description"),
            icon=form.get("icon"),
            associated_tools=",".join(str(x) for x in associated_tools_list),
            associated_resources=",".join(str(x) for x in associated_resources_list),
            associated_prompts=",".join(str(x) for x in associated_prompts_list),
            tags=tags,
            visibility=visibility,
            team_id=team_id,
            owner_email=user_email,
            oauth_enabled=oauth_enabled,
            oauth_config=oauth_config,
        )

        await server_service.update_server(
            db,
            server_id,
            server,
            user_email,
            modified_by=mod_metadata["modified_by"],
            modified_from_ip=mod_metadata["modified_from_ip"],
            modified_via=mod_metadata["modified_via"],
            modified_user_agent=mod_metadata["modified_user_agent"],
        )

        return ORJSONResponse(
            content={"message": "Server updated successfully!", "success": True},
            status_code=200,
        )
    except (ValidationError, CoreValidationError) as ex:
        # Catch both Pydantic and pydantic_core validation errors
        return ORJSONResponse(content=ErrorFormatter.format_validation_error(ex), status_code=422)
    except ServerNameConflictError as ex:
        return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=409)
    except ServerError as ex:
        return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=500)
    except ValueError as ex:
        return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=400)
    except RuntimeError as ex:
        return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=500)
    except IntegrityError as ex:
        return ORJSONResponse(content=ErrorFormatter.format_database_error(ex), status_code=409)
    except PermissionError as e:
        LOGGER.info("Permission denied for user %s: %s", SecurityValidator.sanitize_log_message(get_user_email(user)), e)
        return ORJSONResponse(content={"message": str(e), "success": False}, status_code=403)
    except HTTPException:
        raise
    except Exception as ex:
        LOGGER.exception(f"Unexpected error in admin_edit_server: {ex}")
        return ORJSONResponse(content={"message": "An unexpected error occurred. Please try again or contact support.", "success": False}, status_code=500)


@router.post("/servers/{server_id}/state")
@require_permission("servers.update", allow_admin_bypass=False)
async def admin_set_server_state(
    server_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> Response:
    """
    Set a server's active status via the admin UI.

    This endpoint processes a form request to activate or deactivate a server.
    It expects a form field 'activate' with value "true" to activate the server
    or "false" to deactivate it. The endpoint handles exceptions gracefully and
    logs any errors that might occur during the status change operation.

    Args:
        server_id (str): The ID of the server whose status to set.
        request (Request): FastAPI request containing form data with the 'activate' field.
        db (Session): Database session dependency.
        user (str): Authenticated user dependency.

    Returns:
        Response: A redirect to the admin dashboard catalog section with a
        status code of 303 (See Other).

    Examples:
        >>> callable(admin_set_server_state)
        True
        >>> admin_set_server_state.__name__
        'admin_set_server_state'
    """
    form = await request.form()
    error_message = None
    user_email = get_user_email(user)
    LOGGER.debug(f"User {user_email} is setting server ID {server_id} state with activate: {form.get('activate')}")
    activate = str(form.get("activate", "true")).lower() == "true"
    is_inactive_checked = str(form.get("is_inactive_checked", "false"))
    try:
        await server_service.set_server_state(db, server_id, activate, user_email=user_email)
    except PermissionError as e:
        LOGGER.warning("Permission denied for user %s setting server %s state: %s", SecurityValidator.sanitize_log_message(user_email), SecurityValidator.sanitize_log_message(server_id), e)
        error_message = str(e)
    except ServerLockConflictError as e:
        LOGGER.warning("Lock conflict for user %s setting server %s state: %s", SecurityValidator.sanitize_log_message(user_email), SecurityValidator.sanitize_log_message(server_id), e)
        error_message = "Server is being modified by another request. Please try again."
    except Exception as e:
        LOGGER.error(f"Error setting server status: {e}")
        error_message = "Error setting server status. Please try again."

    root_path = _resolve_root_path(request)
    team_id = str(form.get("team_id", "") or "")
    redirect_url = _build_admin_redirect(root_path, "catalog", error=error_message, include_inactive=is_inactive_checked.lower() == "true", team_id=team_id)
    return RedirectResponse(redirect_url, status_code=303)


@router.post("/servers/{server_id}/delete")
@require_permission("servers.delete", allow_admin_bypass=False)
async def admin_delete_server(server_id: str, request: Request, db: Session = Depends(get_db), user=Depends(get_current_user_with_permissions)) -> RedirectResponse:
    """
    Delete a server via the admin UI.

    This endpoint removes a server from the database by its ID. It handles exceptions
    gracefully and logs any errors that occur during the deletion process.

    Args:
        server_id (str): The ID of the server to delete
        request (Request): FastAPI request object (not used but required by route signature).
        db (Session): Database session dependency
        user (str): Authenticated user dependency

    Returns:
        RedirectResponse: A redirect to the admin dashboard catalog section with a
        status code of 303 (See Other)

    Examples:
        >>> callable(admin_delete_server)
        True
        >>> admin_delete_server.__name__
        'admin_delete_server'
    """
    form = await request.form()
    is_inactive_checked = str(form.get("is_inactive_checked", "false"))
    purge_metrics = str(form.get("purge_metrics", "false")).lower() == "true"
    error_message = None
    try:
        user_email = get_user_email(user)
        LOGGER.debug(f"User {user_email} is deleting server ID {server_id}")
        await server_service.delete_server(db, server_id, user_email=user_email, purge_metrics=purge_metrics)
    except PermissionError as e:
        LOGGER.warning("Permission denied for user %s deleting server %s: %s", SecurityValidator.sanitize_log_message(get_user_email(user)), SecurityValidator.sanitize_log_message(server_id), e)
        error_message = str(e)
    except Exception as e:
        LOGGER.error(f"Error deleting server: {e}")
        error_message = "Failed to delete server. Please try again."

    root_path = _resolve_root_path(request)
    team_id = str(form.get("team_id", "") or "")
    redirect_url = _build_admin_redirect(root_path, "catalog", error=error_message, include_inactive=is_inactive_checked.lower() == "true", team_id=team_id)
    return RedirectResponse(redirect_url, status_code=303)


@router.get("/servers/ids", response_class=JSONResponse)
@require_permission("servers.read", allow_admin_bypass=False)
async def admin_get_all_server_ids(
    include_inactive: bool = False,
    team_id: Optional[str] = Depends(_validated_team_id_param),
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    """Return all server IDs accessible to the current user (select-all helper).

    This endpoint is used by UI "Select All" helpers to fetch only the IDs
    of servers the requesting user can access (owner, team, or public).

    Args:
        include_inactive (bool): When True include servers that are inactive.
        team_id (Optional[str]): Filter by team ID.
        db (Session): Database session (injected dependency).
        user: Authenticated user object from dependency injection.

    Returns:
        dict: A dictionary containing two keys:
            - "server_ids": List[str] of accessible server IDs.
            - "count": int number of IDs returned.
    """
    user_email = get_user_email(user)
    team_ids = await _get_user_team_ids(user, db)

    query = select(DbServer.id)

    if not include_inactive:
        query = query.where(DbServer.enabled.is_(True))

    # Build access conditions
    # When team_id is specified, show ONLY items from that team (team-scoped view)
    # Otherwise, show all accessible items (All Teams view)
    if team_id:
        # Team-specific view: only show servers from the specified team
        if team_id in team_ids:
            # Apply visibility check: team/public resources + user's own resources (including private)
            team_access = [
                and_(DbServer.team_id == team_id, DbServer.visibility.in_(["team", "public"])),
                and_(DbServer.team_id == team_id, DbServer.owner_email == user_email),
            ]
            query = query.where(or_(*team_access))
            LOGGER.debug(f"Filtering server IDs by team_id: {team_id}")
        else:
            # User is not a member of this team, return no results using SQLAlchemy's false()
            LOGGER.warning(f"User {user_email} attempted to filter server IDs by team {team_id} but is not a member")
            query = query.where(false())
    else:
        # All Teams view: apply standard access conditions (owner, team, public)
        access_conditions = []
        access_conditions.append(_owner_access_condition(DbServer.owner_email, DbServer.team_id, user_email=user_email, team_ids=team_ids, user=user))
        if team_ids:
            access_conditions.append(and_(DbServer.team_id.in_(team_ids), DbServer.visibility.in_(["team", "public"])))
        access_conditions.append(DbServer.visibility == "public")
        query = query.where(or_(*access_conditions))

    server_ids = [row[0] for row in db.execute(query).all()]
    return {"server_ids": server_ids, "count": len(server_ids)}


@router.get("/servers/search", response_class=JSONResponse)
@require_permission("servers.read", allow_admin_bypass=False)
async def admin_search_servers(
    q: str = Query("", max_length=500, description="Search query"),
    tags: QueryTagsFilter = None,
    include_inactive: bool = False,
    limit: int = Query(settings.pagination_default_page_size, ge=1, le=settings.pagination_max_page_size),
    team_id: Optional[str] = Depends(_validated_team_id_param),
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    """Search servers by name or description for selector search.

    Performs a case-insensitive search over prompt names and descriptions
    and returns a limited list of matching servers suitable for selector
    UIs (id, name, description).

    Args:
        q (str): Search query string.
        tags (Optional[str]): Tag filter expression (comma=OR, plus=AND).
        include_inactive (bool): When True include servers that are inactive.
        limit (int): Maximum number of results to return (bounded by the query parameter).
        team_id (Optional[str]): Filter by team ID.
        db (Session): Database session (injected dependency).
        user: Authenticated user object from dependency injection.

    Returns:
        dict: A dictionary containing:
            - "servers": List[dict] where each dict has keys "id", "name", "description".
            - "count": int number of matched servers returned.
    """
    user_email = get_user_email(user)
    search_query = _normalize_search_query(q)
    normalized_tags = _normalize_tags_query(tags)
    tag_groups = _parse_tag_filter_groups(normalized_tags)
    if not search_query and not tag_groups:
        return _build_search_response(entity_key="servers", entity_type="servers", items=[], query=search_query, tags=normalized_tags, tag_groups=tag_groups)

    team_ids = await _get_user_team_ids(user, db)

    query = select(DbServer.id, DbServer.name, DbServer.description)

    if not include_inactive:
        query = query.where(DbServer.enabled.is_(True))

    # Build access conditions
    # When team_id is specified, show ONLY items from that team (team-scoped view)
    # Otherwise, show all accessible items (All Teams view)
    if team_id:
        # Team-specific view: only show servers from the specified team
        if team_id in team_ids:
            # Apply visibility check: team/public resources + user's own resources (including private)
            team_access = [
                and_(DbServer.team_id == team_id, DbServer.visibility.in_(["team", "public"])),
                and_(DbServer.team_id == team_id, DbServer.owner_email == user_email),
            ]
            query = query.where(or_(*team_access))
            LOGGER.debug(f"Filtering server search by team_id: {team_id}")
        else:
            # User is not a member of this team, return no results using SQLAlchemy's false()
            LOGGER.warning(f"User {user_email} attempted to filter server search by team {team_id} but is not a member")
            query = query.where(false())
    else:
        # All Teams view: apply standard access conditions (owner, team, public)
        access_conditions = []
        access_conditions.append(_owner_access_condition(DbServer.owner_email, DbServer.team_id, user_email=user_email, team_ids=team_ids, user=user))
        if team_ids:
            access_conditions.append(and_(DbServer.team_id.in_(team_ids), DbServer.visibility.in_(["team", "public"])))
        access_conditions.append(DbServer.visibility == "public")
        query = query.where(or_(*access_conditions))

    if search_query:
        search_conditions = [
            _like_contains(func.lower(DbServer.id), search_query),
            _like_contains(func.lower(DbServer.name), search_query),
            _like_contains(func.lower(coalesce(DbServer.description, "")), search_query),
        ]
        query = query.where(or_(*search_conditions))

    query = _apply_tag_filter_groups(query, db, DbServer.tags, tag_groups)

    if search_query:
        query = query.order_by(
            case(
                (func.lower(DbServer.name).startswith(search_query), 1),
                else_=2,
            ),
            func.lower(DbServer.name),
        )
    else:
        query = query.order_by(func.lower(DbServer.name))
    query = query.limit(limit)

    results = db.execute(query).all()
    servers = []
    for row in results:
        servers.append(
            {
                "id": row.id,
                "name": row.name,
                "description": row.description,
            }
        )

    return _build_search_response(entity_key="servers", entity_type="servers", items=servers, query=search_query, tags=normalized_tags, tag_groups=tag_groups)
