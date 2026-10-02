# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/admin/a2a.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Admin UI A2A agent routes: list, detail, create, edit, state change, delete,
and connectivity test.
"""

# Standard
import logging
import time
from typing import Any, Dict, Optional

# Third-Party
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse, RedirectResponse
import orjson
from pydantic import ValidationError
from pydantic_core import ValidationError as CoreValidationError
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

# First-Party
from mcpgateway.admin.common import _assemble_oauth_config_from_fields, _build_admin_redirect, _check_public_visibility_allowed, _form_team_id, _read_request_json, a2a_service
from mcpgateway.admin.security import enforce_admin_csrf
from mcpgateway.auth_context import get_token_teams_from_request, get_user_email
from mcpgateway.common.validators import SecurityValidator
from mcpgateway.config import settings
from mcpgateway.db import A2AAgent as DbA2AAgent, get_db
from mcpgateway.middleware.rbac import get_current_user_with_permissions, require_permission
from mcpgateway.schemas import A2AAgentCreate, A2AAgentRead, A2AAgentUpdate, PaginatedResponse, PaginationMeta
from mcpgateway.services.a2a_service import A2AAgentError, A2AAgentNameConflictError, A2AAgentNotFoundError
from mcpgateway.services.encryption_service import get_encryption_service
from mcpgateway.services.team_management_service import TeamManagementService
from mcpgateway.utils.error_formatter import ErrorFormatter
from mcpgateway.utils.metadata_capture import MetadataCapture
from mcpgateway.utils.orjson_response import ORJSONResponse
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

        # Parse auth_headers JSON if present
        auth_headers_json = form.get("auth_headers") or ""
        auth_headers: list[dict[str, Any]] = []
        if auth_headers_json:
            try:
                auth_headers = orjson.loads(auth_headers_json)
            except (orjson.JSONDecodeError, ValueError):
                auth_headers = []

        # Parse OAuth configuration - support both JSON string and individual form fields
        oauth_config_json = str(form.get("oauth_config"))
        oauth_config: Optional[dict[str, Any]] = None

        LOGGER.info(f"DEBUG: oauth_config_json from form = '{oauth_config_json}'")
        LOGGER.info(f"DEBUG: Individual OAuth fields - grant_type='{form.get('oauth_grant_type')}', issuer='{form.get('oauth_issuer')}'")

        # Option 1: Pre-assembled oauth_config JSON (from API calls)
        if oauth_config_json and oauth_config_json != "None":
            try:
                oauth_config = orjson.loads(oauth_config_json)
                # Encrypt the client secret if present
                if oauth_config and "client_secret" in oauth_config:
                    encryption = get_encryption_service(settings.auth_encryption_secret)
                    oauth_config["client_secret"] = await encryption.encrypt_secret_async(oauth_config["client_secret"])
            except (orjson.JSONDecodeError, ValueError) as e:
                LOGGER.error(f"Failed to parse OAuth config: {e}")
                oauth_config = None

        # Option 2: Assemble from individual UI form fields.
        # include_resource=False: A2A agents do not consume oauth_config["resource"]
        # (no per-user token storage / audience validation on the A2A path), so the
        # field is not offered on A2A forms and is not assembled here.
        if not oauth_config:
            oauth_config = await _assemble_oauth_config_from_fields(form, encrypt_secret=True, include_resource=False)
            if oauth_config:
                LOGGER.info(f"✅ Assembled OAuth config from UI form fields: grant_type={oauth_config.get('grant_type')}, issuer={oauth_config.get('issuer')}")

        passthrough_headers = str(form.get("passthrough_headers"))
        if passthrough_headers and passthrough_headers.strip():
            try:
                passthrough_headers = orjson.loads(passthrough_headers)
            except (orjson.JSONDecodeError, ValueError):
                # Fallback to comma-separated parsing
                passthrough_headers = [h.strip() for h in passthrough_headers.split(",") if h.strip()]
        else:
            passthrough_headers = None

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

        # Parse auth_headers JSON if present
        auth_headers_json = form.get("auth_headers") or ""
        auth_headers = []
        if auth_headers_json:
            try:
                auth_headers = orjson.loads(auth_headers_json)
            except (orjson.JSONDecodeError, ValueError):
                auth_headers = []

        # Passthrough headers
        passthrough_headers = str(form.get("passthrough_headers"))
        if passthrough_headers and passthrough_headers.strip():
            try:
                passthrough_headers = orjson.loads(passthrough_headers)
            except (orjson.JSONDecodeError, ValueError):
                # Fallback to comma-separated parsing
                passthrough_headers = [h.strip() for h in passthrough_headers.split(",") if h.strip()]
        else:
            passthrough_headers = None

        # Parse OAuth configuration - support both JSON string and individual form fields
        oauth_config_json = str(form.get("oauth_config"))
        oauth_config: Optional[dict[str, Any]] = None

        # Option 1: Pre-assembled oauth_config JSON (from API calls)
        if oauth_config_json and oauth_config_json != "None":
            try:
                oauth_config = orjson.loads(oauth_config_json)
                # Encrypt the client secret if present and not empty
                if oauth_config and "client_secret" in oauth_config and oauth_config["client_secret"]:
                    encryption = get_encryption_service(settings.auth_encryption_secret)
                    oauth_config["client_secret"] = await encryption.encrypt_secret_async(oauth_config["client_secret"])
            except (orjson.JSONDecodeError, ValueError) as e:
                LOGGER.error(f"Failed to parse OAuth config: {e}")
                oauth_config = None

        # Option 2: Assemble from individual UI form fields.
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
