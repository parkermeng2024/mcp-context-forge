# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/admin/a2a.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Admin UI A2A agent routes: list, detail, create, edit, state change, delete,
and connectivity test.
"""

# Standard
import binascii
import logging
import time
from typing import Any, Dict, Optional

# Third-Party
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
import orjson
from pydantic import ValidationError
from pydantic_core import ValidationError as CoreValidationError
from sqlalchemy import and_, case, desc, false, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
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
    _read_request_json,
    _validated_team_id_param,
    a2a_service,
)
from mcpgateway.admin.security import enforce_admin_csrf
from mcpgateway.admin.visibility import get_user_action_permissions
from mcpgateway.auth_context import get_token_teams_from_request, get_user_email
from mcpgateway.common.query_params import QueryGatewayIdList, QueryRenderMode, QueryTagsFilter
from mcpgateway.common.validators import SecurityValidator
from mcpgateway.config import settings
from mcpgateway.db import A2AAgent as DbA2AAgent, EmailTeam, get_db
from mcpgateway.middleware.rbac import get_current_user_with_permissions, require_permission
from mcpgateway.schemas import A2AAgentCreate, A2AAgentRead, A2AAgentUpdate, PaginatedResponse, PaginationMeta
from mcpgateway.services.a2a_service import A2AAgentError, A2AAgentNameConflictError, A2AAgentNotFoundError
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


# ============================================================================ #
#                             A2A AGENT ADMIN ROUTES                          #
# ============================================================================ #


@router.get("/a2a", response_model=PaginatedResponse)
@require_permission("a2a.read", allow_admin_bypass=False)
async def admin_list_a2a_agents(
    request: Request,
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    per_page: int = Query(settings.pagination_default_page_size, ge=1, le=settings.pagination_max_page_size, description="Items per page"),
    include_inactive: bool = False,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> Dict[str, Any]:
    """
    List A2A Agents for the admin UI with pagination support.

    This endpoint retrieves a paginated list of A2A (Agent-to-Agent) agents associated with
    the current user. Administrators can optionally include inactive agents for
    management or auditing purposes. Uses offset-based (page/per_page) pagination.

    Args:
        page (int): Page number (1-indexed) for offset pagination.
        per_page (int): Number of items per page.
        include_inactive (bool): Whether to include inactive agents in the results.
        request (Request): FastAPI request object (required for token team extraction via request.state.token_teams).
        db (Session): Database session dependency.
        user (dict): Authenticated user dependency.

    Returns:
        Dict[str, Any]: A dictionary containing:
            - data: List of A2A agent records formatted with by_alias=True
            - pagination: Pagination metadata
            - links: Pagination links (optional)

    Raises:
        HTTPException (500): If an error occurs while retrieving the agent list.

    Examples:
        >>> callable(admin_list_a2a_agents)
        True
        >>> admin_list_a2a_agents.__name__
        'admin_list_a2a_agents'
    """
    if a2a_service is None:
        LOGGER.warning("A2A features are disabled, returning empty paginated response")
        # First-Party

        return {
            "data": [],
            "pagination": PaginationMeta(page=page, per_page=per_page, total_items=0, total_pages=0, has_next=False, has_prev=False).model_dump(),
            "links": None,
        }

    LOGGER.debug(f"User {get_user_email(user)} requested A2A Agent list (page={page}, per_page={per_page})")
    user_email = get_user_email(user)
    token_teams = get_token_teams_from_request(request)

    # Call a2a_service.list_agents with page-based pagination
    paginated_result = await a2a_service.list_agents(
        db=db,
        include_inactive=include_inactive,
        page=page,
        per_page=per_page,
        user_email=user_email,
        token_teams=token_teams,
    )

    # Return standardized paginated response
    return {
        "data": [agent.model_dump(by_alias=True) for agent in paginated_result["data"]],
        "pagination": paginated_result["pagination"].model_dump(),
        "links": paginated_result["links"].model_dump() if paginated_result["links"] else None,
    }


@router.post("/a2a")
@require_permission("a2a.create", allow_admin_bypass=False)
async def admin_add_a2a_agent(
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> JSONResponse:
    """Add a new A2A agent via admin UI.

    Args:
        request: FastAPI request object
        db: Database session
        user: Authenticated user

    Returns:
        JSONResponse with success/error status

    Raises:
        HTTPException: If A2A features are disabled
    """
    LOGGER.info(f"A2A agent creation request from user {user}")

    if not a2a_service or not settings.mcpgateway_a2a_enabled:
        LOGGER.warning("A2A agent creation attempted but A2A features are disabled")
        return ORJSONResponse(
            content={"message": "A2A features are disabled!", "success": False},
            status_code=403,
        )

    form = await request.form()
    team_id = _form_team_id(form)
    try:
        LOGGER.info(f"A2A agent creation form data: {dict(form)}")

        _check_public_visibility_allowed(str(form.get("visibility", "private")), team_id=team_id)

        user_email = get_user_email(user)
        team_service = TeamManagementService(db)
        team_id = await team_service.verify_team_for_user(user_email, team_id)

        # Process tags
        ts_val = form.get("tags", "")
        tags_str = ts_val if isinstance(ts_val, str) else ""
        tags = [tag.strip() for tag in tags_str.split(",") if tag.strip()] if tags_str else []

        auth_headers: list[dict[str, Any]] = _parse_auth_headers_field(form)

        # Parse OAuth configuration - support both JSON string and individual form fields
        oauth_config_json = str(form.get("oauth_config"))

        LOGGER.info(f"DEBUG: oauth_config_json from form = '{oauth_config_json}'")
        LOGGER.info(f"DEBUG: Individual OAuth fields - grant_type='{form.get('oauth_grant_type')}', issuer='{form.get('oauth_issuer')}'")

        # Pre-assembled oauth_config JSON (from API calls). The create path encrypts
        # any submitted secret, including an empty one, unlike the edit path.
        oauth_config: Optional[dict[str, Any]] = await _parse_oauth_config_json_field(oauth_config_json, encrypt_client_secret=True, skip_empty_client_secret=False)

        # Assemble from individual UI form fields when no pre-assembled JSON was sent.
        # include_resource=False: A2A agents do not consume oauth_config["resource"]
        # (no per-user token storage / audience validation on the A2A path), so the
        # field is not offered on A2A forms and is not assembled here.
        if not oauth_config:
            oauth_config = await _assemble_oauth_config_from_fields(form, encrypt_secret=True, include_resource=False)
            if oauth_config:
                LOGGER.info(f"✅ Assembled OAuth config from UI form fields: grant_type={oauth_config.get('grant_type')}, issuer={oauth_config.get('issuer')}")

        passthrough_headers = _parse_passthrough_headers_field(form)

        # Auto-detect OAuth: if oauth_config is present and auth_type not explicitly set, use "oauth"
        auth_type_from_form = str(form.get("auth_type", ""))
        LOGGER.info(f"DEBUG: auth_type from form: '{auth_type_from_form}', oauth_config present: {oauth_config is not None}")
        if oauth_config and not auth_type_from_form:
            auth_type_from_form = "oauth"
            LOGGER.info("✅ Auto-detected OAuth configuration, setting auth_type='oauth'")
        elif oauth_config and auth_type_from_form:
            LOGGER.info(f"✅ OAuth config present with explicit auth_type='{auth_type_from_form}'")

        # Extract UAID fields from form
        generate_uaid = form.get("generate_uaid") == "true"  # Checkbox sends "true" string
        uaid_registry = str(form.get("uaid_registry", "context-forge"))
        uaid_protocol = str(form.get("uaid_protocol", "a2a"))
        uaid_native_id_override = form.get("uaid_native_id_override") or None

        agent_data = A2AAgentCreate(
            name=form["name"],
            description=form.get("description"),
            endpoint_url=form["endpoint_url"],
            agent_type=form.get("agent_type", "generic"),
            protocol_version=str(form.get("protocol_version", "1.0")),
            auth_type=auth_type_from_form,
            auth_username=str(form.get("auth_username", "")),
            auth_password=str(form.get("auth_password", "")),
            auth_token=str(form.get("auth_token", "")),
            auth_header_key=str(form.get("auth_header_key", "")),
            auth_header_value=str(form.get("auth_header_value", "")),
            auth_headers=auth_headers if auth_headers else None,
            oauth_config=oauth_config,
            auth_value=form.get("auth_value") if form.get("auth_value") else None,
            auth_query_param_key=str(form.get("auth_query_param_key", "")) or None,
            auth_query_param_value=str(form.get("auth_query_param_value", "")) or None,
            tags=tags,
            visibility=form.get("visibility", "private"),
            team_id=team_id,
            owner_email=user_email,
            passthrough_headers=passthrough_headers,
            # UAID fields for cross-gateway routing
            generate_uaid=generate_uaid,
            uaid_registry=uaid_registry if generate_uaid else None,
            uaid_protocol=uaid_protocol if generate_uaid else None,
            uaid_native_id_override=uaid_native_id_override if generate_uaid else None,
        )

        LOGGER.info(f"Creating A2A agent: {agent_data.name} at {agent_data.endpoint_url}")

        # Extract metadata from request
        metadata = MetadataCapture.extract_creation_metadata(request, user)

        await a2a_service.register_agent(
            db,
            agent_data,
            created_by=metadata["created_by"],
            created_from_ip=metadata["created_from_ip"],
            created_via=metadata["created_via"],
            created_user_agent=metadata["created_user_agent"],
            import_batch_id=metadata["import_batch_id"],
            federation_source=metadata["federation_source"],
            team_id=team_id,
            owner_email=user_email,
            visibility=form.get("visibility", "private"),
        )

        return ORJSONResponse(
            content={"message": "A2A agent created successfully!", "success": True},
            status_code=200,
        )

    except CoreValidationError as ex:
        return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=422)
    except A2AAgentNameConflictError as ex:
        LOGGER.error(f"A2A agent name conflict: {ex}")
        return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=409)
    except A2AAgentError as ex:
        LOGGER.error(f"A2A agent error: {ex}")
        return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=500)
    except IntegrityError as ex:
        return ORJSONResponse(
            content=ErrorFormatter.format_database_error(ex),
            status_code=409,
        )
    except HTTPException:
        raise
    except Exception as ex:
        LOGGER.exception(f"Unexpected error creating A2A agent: {ex}")
        return ORJSONResponse(content={"message": "An unexpected error occurred. Please try again or contact support.", "success": False}, status_code=500)


@router.post("/a2a/{agent_id}/edit")
@require_permission("a2a.update", allow_admin_bypass=False)
async def admin_edit_a2a_agent(
    agent_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> JSONResponse:
    """
    Edit an existing A2A agent via the admin UI.

    Expects form fields:
      - name
      - description (optional)
      - endpoint_url
      - agent_type
      - tags (optional, comma-separated)
      - auth_type (optional)
      - auth_username (optional)
      - auth_password (optional)
      - auth_token (optional)
      - auth_header_key / auth_header_value (optional)
      - auth_headers (JSON array, optional)
      - oauth_config (JSON string or individual OAuth fields)
      - visibility (optional)
      - team_id (optional)
      - capabilities (JSON, optional)
      - config (JSON, optional)
      - passthrough_headers: Optional[List[str]]

    Args:
        agent_id (str): The ID of the agent being edited.
        request (Request): The incoming FastAPI request containing form data.
        db (Session): Active database session.
        user: The authenticated admin user performing the edit.

    Returns:
        JSONResponse: A JSON response indicating success or failure.

    Raises:
        HTTPException: 422 when public visibility is disabled and request is team-scoped.

    Examples:
        >>> callable(admin_edit_a2a_agent)
        True
        >>> admin_edit_a2a_agent.__name__
        'admin_edit_a2a_agent'
    """

    try:
        form = await request.form()
        team_id = _form_team_id(form)

        # Normalize tags
        tags_raw = str(form.get("tags", ""))
        tags = [t.strip() for t in tags_raw.split(",") if t.strip()] if tags_raw else []

        # Visibility
        visibility = str(form.get("visibility", "private"))
        _check_public_visibility_allowed(visibility, team_id=team_id)

        # Agent Type
        agent_type = str(form.get("agent_type", "generic"))

        # Capabilities
        raw_capabilities = form.get("capabilities")
        capabilities = {}
        if raw_capabilities:
            try:
                capabilities = orjson.loads(raw_capabilities)
            except (ValueError, orjson.JSONDecodeError):
                capabilities = {}

        # Config
        raw_config = form.get("config")
        config = {}
        if raw_config:
            try:
                config = orjson.loads(raw_config)
            except (ValueError, orjson.JSONDecodeError):
                config = {}

        auth_headers = _parse_auth_headers_field(form)

        passthrough_headers = _parse_passthrough_headers_field(form)

        oauth_config: Optional[dict[str, Any]] = await _parse_oauth_config_json_field(form.get("oauth_config"), encrypt_client_secret=True)

        # Assemble from individual UI form fields when no pre-assembled JSON was sent.
        # include_resource=False: A2A agents do not consume oauth_config["resource"]
        # (no per-user token storage / audience validation on the A2A path), so the
        # field is not offered on A2A forms and is not assembled here.
        if not oauth_config:
            oauth_config = await _assemble_oauth_config_from_fields(form, encrypt_secret=True, include_resource=False)
            if oauth_config:
                LOGGER.info(f"✅ Assembled OAuth config from UI form fields (edit): grant_type={oauth_config.get('grant_type')}, issuer={oauth_config.get('issuer')}")

        user_email = get_user_email(user)

        # Preserve existing agent's team_id when no explicit team_id is provided.
        # Without this guard, verify_team_for_user() falls back to the user's
        # personal team, silently reassigning the agent on every edit.
        if not team_id:
            existing_agent = db.get(DbA2AAgent, agent_id)
            existing_team = getattr(existing_agent, "team_id", None) if existing_agent else None
            if isinstance(existing_team, str) and existing_team:
                team_id = existing_team

        team_service = TeamManagementService(db)
        team_id = await team_service.verify_team_for_user(user_email, team_id)

        # Extract UAID generation fields - allow adding UAID to agents that don't have one
        # UAID is immutable: once generated, it cannot be changed
        generate_uaid = form.get("generate_uaid") == "true"
        uaid_registry = str(form.get("uaid_registry", "")) if generate_uaid else None
        uaid_protocol = str(form.get("uaid_protocol", "")) if generate_uaid else None
        uaid_native_id_override = form.get("uaid_native_id_override") or None

        # Auto-detect OAuth: if oauth_config is present and auth_type not explicitly set, use "oauth"
        auth_type_from_form = str(form.get("auth_type", ""))
        if oauth_config and not auth_type_from_form:
            auth_type_from_form = "oauth"
            LOGGER.info("Auto-detected OAuth configuration in edit, setting auth_type='oauth'")

        agent_update = A2AAgentUpdate(
            name=form.get("name"),
            description=form.get("description"),
            endpoint_url=form.get("endpoint_url"),
            agent_type=agent_type,
            tags=tags,
            auth_type=auth_type_from_form,
            auth_username=str(form.get("auth_username", "")),
            auth_password=str(form.get("auth_password", "")),
            auth_token=str(form.get("auth_token", "")),
            auth_header_key=str(form.get("auth_header_key", "")),
            auth_header_value=str(form.get("auth_header_value", "")),
            auth_value=str(form.get("auth_value", "")),
            auth_query_param_key=str(form.get("auth_query_param_key", "")) or None,
            auth_query_param_value=str(form.get("auth_query_param_value", "")) or None,
            auth_headers=auth_headers if auth_headers else None,
            passthrough_headers=passthrough_headers,
            oauth_config=oauth_config,
            visibility=visibility,
            team_id=team_id,
            capabilities=capabilities,  # Optional, not editable via UI
            config=config,  # Optional, not editable via UI
            # UAID generation fields (only applies if agent doesn't have UAID yet)
            generate_uaid=generate_uaid,
            uaid_registry=uaid_registry,
            uaid_protocol=uaid_protocol,
            uaid_native_id_override=uaid_native_id_override if generate_uaid else None,
        )
        # Only update protocol_version when the field is explicitly submitted.
        # Defaulting on edit would silently coerce an existing 0.3 agent back
        # to "1.0" for any caller (cached form, scripted PATCH) that omits the field.
        if form.get("protocol_version"):
            agent_update.protocol_version = str(form["protocol_version"])

        mod_metadata = MetadataCapture.extract_modification_metadata(request, user, 0)
        await a2a_service.update_agent(
            db=db,
            agent_id=agent_id,
            agent_data=agent_update,
            modified_by=mod_metadata["modified_by"],
            modified_from_ip=mod_metadata["modified_from_ip"],
            modified_via=mod_metadata["modified_via"],
            modified_user_agent=mod_metadata["modified_user_agent"],
            user_email=user_email,
        )

        return ORJSONResponse({"message": "A2A agent updated successfully", "success": True}, status_code=200)

    except ValidationError as ve:
        return ORJSONResponse({"message": str(ve), "success": False}, status_code=422)
    except IntegrityError as ie:
        return ORJSONResponse({"message": str(ie), "success": False}, status_code=409)
    except PermissionError as e:
        LOGGER.warning(
            "Permission denied for user %s editing A2A agent %s: %s",
            SecurityValidator.sanitize_log_message(get_user_email(user)),
            SecurityValidator.sanitize_log_message(agent_id),
            e,
        )
        return ORJSONResponse({"message": str(e), "success": False}, status_code=403)
    except A2AAgentNotFoundError:
        return ORJSONResponse({"message": "A2A agent not found.", "success": False}, status_code=404)
    except HTTPException:
        raise
    except Exception as e:
        LOGGER.exception("Unexpected error in admin_edit_a2a_agent: %s", e)
        return ORJSONResponse(
            {"message": "An unexpected error occurred. Please try again or contact support.", "success": False},
            status_code=500,
        )


@router.post("/a2a/{agent_id}/state")
@require_permission("a2a.update", allow_admin_bypass=False)
async def admin_set_a2a_agent_state(
    agent_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),  # pylint: disable=unused-argument
) -> RedirectResponse:
    """Toggle A2A agent status via admin UI.

    Args:
        agent_id: Agent ID
        request: FastAPI request object
        db: Database session
        user: Authenticated user

    Returns:
        Redirect response to admin page with A2A tab

    Raises:
        HTTPException: If A2A features are disabled
    """
    if not a2a_service or not settings.mcpgateway_a2a_enabled:
        root_path = _resolve_root_path(request)
        return RedirectResponse(f"{root_path}/admin#a2a-agents", status_code=303)

    user_email = get_user_email(user)
    error_message = None
    is_inactive_checked = "false"
    team_id = ""
    try:
        form = await request.form()
        act_val = form.get("activate", "false")
        activate = act_val.lower() == "true" if isinstance(act_val, str) else False
        is_inactive_checked = str(form.get("is_inactive_checked", "false"))
        team_id = str(form.get("team_id", "") or "")

        await a2a_service.set_agent_state(db, agent_id, activate, user_email=user_email)

    except PermissionError as e:
        LOGGER.warning(f"Permission denied for user {user_email} setting A2A agent state {agent_id}: {e}")
        error_message = str(e)
    except A2AAgentNotFoundError as e:
        LOGGER.error(f"A2A agent state change failed - not found: {e}")
        error_message = "A2A agent not found."
    except Exception as e:
        LOGGER.error(f"Error setting A2A agent state: {e}")
        error_message = "Failed to set state of A2A agent. Please try again."

    root_path = _resolve_root_path(request)
    redirect_url = _build_admin_redirect(root_path, "a2a-agents", error=error_message, include_inactive=is_inactive_checked.lower() == "true", team_id=team_id)
    return RedirectResponse(redirect_url, status_code=303)


@router.post("/a2a/{agent_id}/delete")
@require_permission("a2a.delete", allow_admin_bypass=False)
async def admin_delete_a2a_agent(
    agent_id: str,
    request: Request,  # pylint: disable=unused-argument
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),  # pylint: disable=unused-argument
) -> RedirectResponse:
    """Delete A2A agent via admin UI.

    Args:
        agent_id: Agent ID
        request: FastAPI request object
        db: Database session
        user: Authenticated user

    Returns:
        Redirect response to admin page with A2A tab

    Raises:
        HTTPException: If A2A features are disabled
    """
    if not a2a_service or not settings.mcpgateway_a2a_enabled:
        root_path = _resolve_root_path(request)
        return RedirectResponse(f"{root_path}/admin#a2a-agents", status_code=303)

    error_message = None
    is_inactive_checked = "false"
    team_id = ""
    try:
        form = await request.form()
        purge_metrics = str(form.get("purge_metrics", "false")).lower() == "true"
        is_inactive_checked = str(form.get("is_inactive_checked", "false"))
        team_id = str(form.get("team_id", "") or "")
        user_email = get_user_email(user)
        await a2a_service.delete_agent(db, agent_id, user_email=user_email, purge_metrics=purge_metrics)
    except PermissionError as e:
        LOGGER.warning(f"Permission denied for user {get_user_email(user)} deleting A2A agent {agent_id}: {e}")
        error_message = str(e)
    except A2AAgentNotFoundError as e:
        LOGGER.error(f"A2A agent delete failed - not found: {e}")
        error_message = "A2A agent not found."
    except Exception as e:
        LOGGER.error(f"Error deleting A2A agent: {e}")
        error_message = "Failed to delete A2A agent. Please try again."

    root_path = _resolve_root_path(request)
    redirect_url = _build_admin_redirect(root_path, "a2a-agents", error=error_message, include_inactive=is_inactive_checked.lower() == "true", team_id=team_id)
    return RedirectResponse(redirect_url, status_code=303)


@router.post("/a2a/{agent_id}/test")
@require_permission("a2a.invoke", allow_admin_bypass=False)
async def admin_test_a2a_agent(
    agent_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> JSONResponse:
    """Test A2A agent via admin UI.

    Invokes the specified A2A agent with a test message and returns the result.
    Returns appropriate HTTP status codes based on the failure type:
    - 404: Agent not found or user lacks access
    - 502: Agent disabled, unreachable, or returning errors
    - 422: Invalid test parameters
    - 500: Unexpected system errors

    Args:
        agent_id: Agent ID
        request: FastAPI request object containing optional 'query' field
        db: Database session
        user: Authenticated user

    Returns:
        JSON response with test results. On success, includes:
        - success: True
        - result: Agent response
        - agent_name: Name of the tested agent
        - test_timestamp: Unix timestamp of the test

        On failure, includes:
        - success: False
        - error: Error message (sanitized to prevent credential leakage)
        - error_type: Type of error (not_found, agent_error, validation_error, internal_error)
        - agent_id: ID of the agent that was tested

    Raises:
        HTTPException: If A2A features are disabled (403)

    Note:
        Error messages are sanitized by a2a_service to prevent credential leakage.
        Returns 404 (not 403) for access denied to avoid leaking agent existence.
    """
    if not a2a_service or not settings.mcpgateway_a2a_enabled:
        return ORJSONResponse(content={"success": False, "error": "A2A features are disabled"}, status_code=403)

    try:
        user_email = get_user_email(user)
        is_admin = user.get("is_admin", False) if isinstance(user, dict) else False
        token_teams = user.get("token_teams") if isinstance(user, dict) else None
        # Missing token_teams key for non-admin = public-only (per normalize_token_teams rules).
        # Only admin users retain None (admin bypass); all others default to [].
        if not is_admin and token_teams is None:
            token_teams = []
        # Admin users with unrestricted tokens get full bypass (both None);
        # non-admin users pass their actual email and team scoping.
        invoke_user_email = None if (is_admin and token_teams is None) else user_email
        # Get the agent by ID
        agent = await a2a_service.get_agent(db, agent_id, user_email=invoke_user_email, token_teams=token_teams)

        # Parse request body to get user-provided query
        default_message = "Hello from ContextForge Admin UI test!"
        try:
            body = await _read_request_json(request)
            # Use 'or' to also handle empty string queries
            user_query = (body.get("query") if body else None) or default_message
        except Exception:
            user_query = default_message

        # Prepare test parameters based on agent type and endpoint
        if agent.agent_type in ["generic", "jsonrpc"] or agent.endpoint_url.endswith("/"):
            # Let the A2A protocol helper choose v1 or legacy wire format from the agent record.
            test_params = {"query": user_query}
        else:
            # Generic test format
            test_params = {"query": user_query, "message": user_query, "test": True, "timestamp": int(time.time())}

        # Invoke the agent
        result = await a2a_service.invoke_agent(
            db,
            agent.name,
            test_params,
            "admin_test",
            user_email=invoke_user_email,
            user_id=user_email,
            token_teams=token_teams,
        )

        return ORJSONResponse(content={"success": True, "result": result, "agent_name": agent.name, "test_timestamp": time.time()})

    except A2AAgentNotFoundError as e:
        LOGGER.warning(f"A2A agent not found or access denied for {agent_id}: {e}")
        return ORJSONResponse(
            content={"success": False, "error": str(e), "error_type": "not_found", "agent_id": agent_id},
            status_code=404,
        )
    except A2AAgentError as e:
        LOGGER.error(f"A2A agent error for {agent_id}: {e}")
        return ORJSONResponse(
            content={"success": False, "error": str(e), "error_type": "agent_error", "agent_id": agent_id},
            status_code=502,
        )
    except ValidationError as e:
        LOGGER.warning(f"Validation error testing A2A agent {agent_id}: {e}")
        return ORJSONResponse(
            content={"success": False, "error": str(e), "error_type": "validation_error", "agent_id": agent_id},
            status_code=422,
        )
    except Exception as e:
        LOGGER.error(f"Unexpected error testing A2A agent {agent_id}: {e}")
        return ORJSONResponse(
            content={"success": False, "error": str(e), "error_type": "internal_error", "agent_id": agent_id},
            status_code=500,
        )


@router.get("/a2a/partial", response_class=HTMLResponse)
@require_permission("a2a.read", allow_admin_bypass=False)
async def admin_a2a_partial_html(
    request: Request,
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    per_page: int = Query(settings.pagination_default_page_size, ge=1, le=settings.pagination_max_page_size, description="Items per page"),
    q: str = Query("", max_length=500, description="Search query"),
    tags: QueryTagsFilter = None,
    include_inactive: bool = False,
    render: QueryRenderMode = None,
    gateway_id: QueryGatewayIdList = None,
    team_id: Optional[str] = Depends(_validated_team_id_param),
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    """Return paginated a2a agents HTML partials for the admin UI.

    This HTMX endpoint returns only the partial HTML used by the admin UI for
    a2a agents. It supports three render modes:

    - default: full table partial (rows + controls)
    - ``render="controls"``: return only pagination controls
    - ``render="selector"``: return selector items for infinite scroll

    Args:
        request (Request): FastAPI request object used by the template engine.
        page (int): Page number (1-indexed).
        per_page (int): Number of items per page (bounded by settings).
        q (str): Free-text query string.
        tags (Optional[str]): Tag filter expression (comma=OR, plus=AND).
        include_inactive (bool): If True, include inactive a2a agents in results.
        render (Optional[str]): Render mode; one of None, "controls", "selector".
        gateway_id (Optional[str]): Filter by gateway ID(s), comma-separated.
        team_id (Optional[str]): Filter by team ID.
        db (Session): Database session (dependency-injected).
        user: Authenticated user object from dependency injection.

    Returns:
        Union[HTMLResponse, TemplateResponse]: A rendered template response
        containing either the table partial, pagination controls, or selector
        items depending on ``render``. The response contains JSON-serializable
        encoded a2a agent data when templates expect it.
    """
    LOGGER.debug(
        f"User {get_user_email(user)} requested a2a_agents HTML partial (page={page}, per_page={per_page}, include_inactive={include_inactive}, render={render}, gateway_id={gateway_id}, team_id={team_id})"
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
    query = select(DbA2AAgent)

    # Note: A2A agents don't have gateway_id field, they connect directly via endpoint_url
    # The gateway_id parameter is ignored for A2A agents

    if not include_inactive:
        query = query.where(DbA2AAgent.enabled.is_(True))

    # Build access conditions
    # When team_id is specified, show ONLY items from that team (team-scoped view)
    # Otherwise, show all accessible items (All Teams view)
    if team_id:
        # Team-specific view: only show a2a agents from the specified team
        if team_id in team_ids:
            # Apply visibility check: team/public resources + user's own resources (including private)
            team_access = [
                and_(DbA2AAgent.team_id == team_id, DbA2AAgent.visibility.in_(["team", "public"])),
                and_(DbA2AAgent.team_id == team_id, DbA2AAgent.owner_email == user_email),
            ]
            query = query.where(or_(*team_access))
            LOGGER.debug(f"Filtering a2a agents by team_id: {team_id}")
        else:
            # User is not a member of this team, return no results using SQLAlchemy's false()
            LOGGER.warning(f"User {user_email} attempted to filter by team {team_id} but is not a member")
            query = query.where(false())
    else:
        # All Teams view: apply standard access conditions (owner, team, public)
        access_conditions = []
        access_conditions.append(_owner_access_condition(DbA2AAgent.owner_email, DbA2AAgent.team_id, user_email=user_email, team_ids=team_ids, user=user))
        if team_ids:
            access_conditions.append(and_(DbA2AAgent.team_id.in_(team_ids), DbA2AAgent.visibility.in_(["team", "public"])))
        access_conditions.append(DbA2AAgent.visibility == "public")
        query = query.where(or_(*access_conditions))

    if search_query:
        query = query.where(
            or_(
                _like_contains(func.lower(DbA2AAgent.id), search_query),
                _like_contains(func.lower(DbA2AAgent.name), search_query),
                _like_contains(func.lower(coalesce(DbA2AAgent.endpoint_url, "")), search_query),
                _like_contains(func.lower(coalesce(DbA2AAgent.description, "")), search_query),
            )
        )

    query = _apply_tag_filter_groups(query, db, DbA2AAgent.tags, tag_groups)

    # Apply pagination ordering for cursor support
    query = query.order_by(desc(DbA2AAgent.created_at), desc(DbA2AAgent.id))

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
    base_url = f"{root_path}/admin/a2a/partial"
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

    # Extract paginated a2a_agents (DbA2AAgent objects)
    a2a_agents_db = paginated_result["data"]
    pagination = paginated_result["pagination"]
    links = paginated_result["links"]

    # Batch fetch team names for the a2a_agents to avoid N+1 queries
    team_ids_set = {p.team_id for p in a2a_agents_db if p.team_id}
    team_map = {}
    if team_ids_set:
        teams = db.execute(select(EmailTeam.id, EmailTeam.name).where(EmailTeam.id.in_(team_ids_set), EmailTeam.is_active.is_(True))).all()
        team_map = {team.id: team.name for team in teams}

    # Apply team names to DB objects before conversion
    for p in a2a_agents_db:
        p.team = team_map.get(p.team_id) if p.team_id else None

    # Batch convert to Pydantic models using a2a service
    # This eliminates the N+1 query problem from calling get_a2a_details() in a loop
    a2a_agents_pydantic = []
    failed_count = 0
    for a in a2a_agents_db:
        try:
            a2a_agents_pydantic.append(a2a_service.convert_agent_to_read(a, include_metrics=False))
        except (ValidationError, ValueError, KeyError, TypeError, binascii.Error) as e:
            failed_count += 1
            LOGGER.exception(f"Failed to convert a2a agent {getattr(a, 'id', 'unknown')} ({getattr(a, 'name', 'unknown')}): {e}")
    _adjust_pagination_for_conversion_failures(pagination, failed_count, len(a2a_agents_pydantic))
    data = jsonable_encoder(a2a_agents_pydantic)

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
                "hx_target": "#agents-table-body",
                "hx_indicator": "#agents-loading",
                "query_params": query_params,
                "root_path": _resolve_root_path(request),
            },
        )

    if render == "selector":
        return request.app.state.templates.TemplateResponse(
            request,
            "agents_selector_items.html",
            {
                "request": request,
                "data": data,
                "pagination": pagination.model_dump(),
                "root_path": _resolve_root_path(request),
                "gateway_id": gateway_id,
            },
        )

    _is_admin = bool(user.get("is_admin", False) if isinstance(user, dict) else getattr(user, "is_admin", False))
    _team_roles = _get_user_team_roles(db, user_email) if not _is_admin else {}
    _user_permissions = await get_user_action_permissions(db=db, user_email=user_email, is_admin=_is_admin, token_teams=get_token_teams_from_request(request))
    return request.app.state.templates.TemplateResponse(
        request,
        "agents_partial.html",
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
            "user_permissions": _user_permissions,
        },
    )


@router.get("/a2a/ids", response_class=JSONResponse)
@require_permission("a2a.read", allow_admin_bypass=False)
async def admin_get_all_agent_ids(
    include_inactive: bool = False,
    team_id: Optional[str] = Depends(_validated_team_id_param),
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    """Return all agent IDs accessible to the current user (select-all helper).

    This endpoint is used by UI "Select All" helpers to fetch only the IDs
    of a2a agents the requesting user can access (owner, team, or public).

    Args:
        include_inactive (bool): When True include a2a agents that are inactive.
        team_id (Optional[str]): Filter by team ID.
        db (Session): Database session (injected dependency).
        user: Authenticated user object from dependency injection.

    Returns:
        dict: A dictionary containing two keys:
            - "agent_ids": List[str] of accessible agent IDs.
            - "count": int number of IDs returned.
    """
    user_email = get_user_email(user)
    team_ids = await _get_user_team_ids(user, db)

    query = select(DbA2AAgent.id)

    if not include_inactive:
        query = query.where(DbA2AAgent.enabled.is_(True))

    # Build access conditions
    # When team_id is specified, show ONLY items from that team (team-scoped view)
    # Otherwise, show all accessible items (All Teams view)
    if team_id:
        if team_id in team_ids:
            # Apply visibility check: team/public resources + user's own resources (including private)
            team_access = [
                and_(DbA2AAgent.team_id == team_id, DbA2AAgent.visibility.in_(["team", "public"])),
                and_(DbA2AAgent.team_id == team_id, DbA2AAgent.owner_email == user_email),
            ]
            query = query.where(or_(*team_access))
            LOGGER.debug(f"Filtering A2A agent IDs by team_id: {team_id}")
        else:
            LOGGER.warning(f"User {user_email} attempted to filter A2A agent IDs by team {team_id} but is not a member")
            query = query.where(false())
    else:
        # All Teams view: apply standard access conditions (owner, team, public)
        access_conditions = []
        access_conditions.append(_owner_access_condition(DbA2AAgent.owner_email, DbA2AAgent.team_id, user_email=user_email, team_ids=team_ids, user=user))
        access_conditions.append(DbA2AAgent.visibility == "public")
        if team_ids:
            access_conditions.append(and_(DbA2AAgent.team_id.in_(team_ids), DbA2AAgent.visibility.in_(["team", "public"])))
        query = query.where(or_(*access_conditions))

    agent_ids = [row[0] for row in db.execute(query).all()]
    return {"agent_ids": agent_ids, "count": len(agent_ids)}


@router.get("/a2a/search", response_class=JSONResponse)
@require_permission("a2a.read", allow_admin_bypass=False)
async def admin_search_a2a_agents(
    q: str = Query("", max_length=500, description="Search query"),
    tags: QueryTagsFilter = None,
    include_inactive: bool = False,
    limit: int = Query(settings.pagination_default_page_size, ge=1, le=settings.pagination_max_page_size),
    team_id: Optional[str] = Depends(_validated_team_id_param),
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    """Search a2a agents by name or description for selector search.

    Performs a case-insensitive search over prompt names and descriptions
    and returns a limited list of matching a2a agents suitable for selector
    UIs (id, name, description).

    Args:
        q (str): Search query string.
        tags (Optional[str]): Tag filter expression (comma=OR, plus=AND).
        include_inactive (bool): When True include a2a agents that are inactive.
        limit (int): Maximum number of results to return (bounded by the query parameter).
        team_id (Optional[str]): Filter by team ID.
        db (Session): Database session (injected dependency).
        user: Authenticated user object from dependency injection.

    Returns:
        dict: A dictionary containing:
            - "agents": List[dict] where each dict has keys "id", "name", "description".
            - "count": int number of matched a2a agents returned.
    """
    user_email = get_user_email(user)
    search_query = _normalize_search_query(q)
    normalized_tags = _normalize_tags_query(tags)
    tag_groups = _parse_tag_filter_groups(normalized_tags)
    if not search_query and not tag_groups:
        return _build_search_response(entity_key="agents", entity_type="agents", items=[], query=search_query, tags=normalized_tags, tag_groups=tag_groups)

    team_ids = await _get_user_team_ids(user, db)

    query = select(DbA2AAgent.id, DbA2AAgent.name, DbA2AAgent.endpoint_url, DbA2AAgent.description)

    if not include_inactive:
        query = query.where(DbA2AAgent.enabled.is_(True))

    # Build access conditions
    # When team_id is specified, show ONLY items from that team (team-scoped view)
    # Otherwise, show all accessible items (All Teams view)
    if team_id:
        if team_id in team_ids:
            # Apply visibility check: team/public resources + user's own resources (including private)
            team_access = [
                and_(DbA2AAgent.team_id == team_id, DbA2AAgent.visibility.in_(["team", "public"])),
                and_(DbA2AAgent.team_id == team_id, DbA2AAgent.owner_email == user_email),
            ]
            query = query.where(or_(*team_access))
            LOGGER.debug(f"Filtering A2A agent search by team_id: {team_id}")
        else:
            LOGGER.warning(f"User {user_email} attempted to filter A2A agent search by team {team_id} but is not a member")
            query = query.where(false())
    else:
        # All Teams view: apply standard access conditions (owner, team, public)
        access_conditions = []
        access_conditions.append(_owner_access_condition(DbA2AAgent.owner_email, DbA2AAgent.team_id, user_email=user_email, team_ids=team_ids, user=user))
        access_conditions.append(DbA2AAgent.visibility == "public")
        if team_ids:
            access_conditions.append(and_(DbA2AAgent.team_id.in_(team_ids), DbA2AAgent.visibility.in_(["team", "public"])))
        query = query.where(or_(*access_conditions))

    if search_query:
        search_conditions = [
            _like_contains(func.lower(DbA2AAgent.id), search_query),
            _like_contains(func.lower(DbA2AAgent.name), search_query),
            _like_contains(func.lower(coalesce(DbA2AAgent.endpoint_url, "")), search_query),
            _like_contains(func.lower(coalesce(DbA2AAgent.description, "")), search_query),
        ]
        query = query.where(or_(*search_conditions))

    query = _apply_tag_filter_groups(query, db, DbA2AAgent.tags, tag_groups)

    if search_query:
        query = query.order_by(
            case(
                (func.lower(DbA2AAgent.name).startswith(search_query), 1),
                (func.lower(coalesce(DbA2AAgent.endpoint_url, "")).startswith(search_query), 1),
                else_=2,
            ),
            func.lower(DbA2AAgent.name),
        )
    else:
        query = query.order_by(func.lower(DbA2AAgent.name))
    query = query.limit(limit)

    results = db.execute(query).all()
    agents = []
    for row in results:
        agents.append(
            {
                "id": row.id,
                "name": row.name,
                "endpoint_url": row.endpoint_url,
                "description": row.description,
            }
        )

    return _build_search_response(entity_key="agents", entity_type="agents", items=agents, query=search_query, tags=normalized_tags, tag_groups=tag_groups)


# ============================================================================ #
#                     A2A AGENT DETAIL ROUTE (MUST STAY LAST)                  #
# ============================================================================ #
# FastAPI matches routes in registration order, and ``/a2a/{agent_id}`` also
# matches ``/a2a/ids``, ``/a2a/partial`` and ``/a2a/search``. Registering this
# route after those static paths keeps them reachable.


@router.get("/a2a/{agent_id}", response_model=A2AAgentRead)
@require_permission("a2a.read", allow_admin_bypass=False)
async def admin_get_agent(
    agent_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> Dict[str, Any]:
    """Get A2A agent details for the admin UI.

    Args:
        agent_id: Agent ID.
        request: FastAPI request object (required for token team extraction via request.state.token_teams).
        db: Database session.
        user: Authenticated user.

    Returns:
        Agent details.

    Raises:
        HTTPException: If the agent is not found.
        Exception: For any other unexpected errors.

    Examples:
        >>> callable(admin_get_agent)
        True
        >>> admin_get_agent.__name__
        'admin_get_agent'
    """
    LOGGER.debug(f"User {get_user_email(user)} requested details for agent ID {agent_id}")
    user_email = get_user_email(user)
    token_teams = get_token_teams_from_request(request)

    try:
        agent = await a2a_service.get_agent(db, agent_id, user_email=user_email, token_teams=token_teams)
        return agent.model_dump(by_alias=True)
    except A2AAgentNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        LOGGER.error(f"Error getting agent {agent_id}: {e}")
        raise
