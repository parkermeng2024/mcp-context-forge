# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/admin/dashboard.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Admin UI dashboard route: the single-page admin console.
"""

# Standard
from datetime import datetime, timedelta, timezone
import logging
from typing import Any, Optional
import uuid

# Third-Party
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

# First-Party
from mcpgateway.admin.assets import get_bundle_css_files, get_bundle_js_filename, load_sri_hashes
from mcpgateway.admin.common import _validated_team_id_param, a2a_service, gateway_service, prompt_service, resource_service, root_service, server_service, tool_service
from mcpgateway.admin.grpc import GRPC_AVAILABLE, grpc_service_mgr
from mcpgateway.admin.security import _set_admin_csrf_cookie, enforce_admin_csrf
from mcpgateway.admin.visibility import get_hidden_sections_for_user, get_ui_visibility_config, get_user_action_permissions, UI_ACTION_PERMISSIONS, UI_HIDE_SECTIONS_COOKIE_MAX_AGE, UI_HIDE_SECTIONS_COOKIE_NAME
from mcpgateway.auth_context import get_user_email, is_unrestricted_platform_admin
from mcpgateway.config import settings
from mcpgateway.db import EmailUser, get_db
from mcpgateway.middleware.rbac import get_current_user_with_permissions, require_permission
from mcpgateway.services.password_policy_service import PasswordPolicyService
from mcpgateway.services.team_management_service import TeamManagementService
from mcpgateway.utils.create_jwt_token import create_jwt_token, get_jwt_token
from mcpgateway.utils.paths import resolve_root_path as _resolve_root_path
from mcpgateway.utils.security_cookies import set_auth_cookie
from mcpgateway.utils.verify_credentials import verify_jwt_token_cached

LOGGER: logging.Logger = logging.getLogger("mcpgateway.admin")

# mcpgateway.admin (__init__) appends this router's routes to admin_router, so the
# prefix, tags, and CSRF dependency must mirror admin_router exactly.
router = APIRouter(
    prefix="/admin",
    tags=["Admin UI"],
    dependencies=[Depends(enforce_admin_csrf)],
)


@router.get("/", name="admin_home", response_class=HTMLResponse)
@require_permission("admin.dashboard", allow_admin_bypass=False)
async def admin_ui(
    request: Request,
    team_id: Optional[str] = Depends(_validated_team_id_param),
    include_inactive: bool = False,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
    _jwt_token: str = Depends(get_jwt_token),
) -> Any:
    """
    Render the admin dashboard HTML page.

    This endpoint serves as the main entry point to the admin UI. It fetches data for
    servers, tools, resources, prompts, gateways, and roots from their respective
    services, then renders the admin dashboard template with this data.

    Supports optional `team_id` query param to scope the returned data to a team.
    If `team_id` is provided and email-based team management is enabled, we
    validate the user is a member of that team. We attempt to pass team_id into
    service listing functions (preferred). If the service API does not accept a
    team_id parameter we fall back to post-filtering the returned items.

    The endpoint also sets a JWT token as a cookie for authentication in subsequent
    requests. This token is HTTP-only for security reasons.

    Args:
        request (Request): FastAPI request object.
        team_id (Optional[str]): Optional team ID to filter data by team.
        include_inactive (bool): Whether to include inactive items in all listings.
        db (Session): Database session dependency.
        user (dict): Authenticated user context with permissions.

    Returns:
        Any: Rendered HTML template for the admin dashboard.

    Raises:
        HTTPException: 403 if a non-admin user supplies a team_id they do not belong to.

    Examples:
        >>> callable(admin_ui)
        True
        >>> admin_ui.__name__
        'admin_ui'
    """
    LOGGER.debug(f"User {get_user_email(user)} accessed the admin UI (team_id={team_id})")
    user_email = get_user_email(user)
    is_admin = bool(user.get("is_admin", False) if isinstance(user, dict) else getattr(user, "is_admin", False))
    ui_visibility_config = get_ui_visibility_config(request, is_admin=is_admin)
    hidden_sections = set(ui_visibility_config["hidden_sections"])
    hidden_header_items = set(ui_visibility_config["hidden_header_items"])

    # --------------------------------------------------------------------------------
    # Determine team loading requirements BEFORE permission-based hiding
    # This ensures teams load based on query-param visibility, not permission restrictions
    # --------------------------------------------------------------------------------
    sections_requiring_user_teams = {
        "teams",
        "tokens",
        "users",
        "tools",
        "servers",
        "resources",
        "prompts",
        "gateways",
        "agents",
    }
    # Check visibility based on query-param/static hidden sections only
    any_data_section_visible = any(section not in hidden_sections for section in sections_requiring_user_teams)

    # --------------------------------------------------------------------------------
    # Add permission-based hiding (merge with static config)
    # Only apply permission-based hiding when email auth is enabled
    # --------------------------------------------------------------------------------
    is_admin_user = bool(user.get("is_admin", False) if isinstance(user, dict) else getattr(user, "is_admin", False))
    token_teams = user.get("token_teams") if isinstance(user, dict) else getattr(user, "token_teams", None)

    if getattr(settings, "email_auth_enabled", False):
        permission_hidden_sections = await get_hidden_sections_for_user(
            db=db,
            user_email=user_email,
            is_admin=is_admin_user,
            token_teams=token_teams,
            static_hidden=hidden_sections,
        )

        # Merge permission-based hiding with query-param and static config
        hidden_sections = hidden_sections | permission_hidden_sections

    can_manage_roots = await is_unrestricted_platform_admin(request, user, db)
    if not can_manage_roots:
        hidden_sections.add("roots")

    # --------------------------------------------------------------------------------
    # Get user action permissions for UI button visibility
    # Only check permissions when email auth is enabled (same as section hiding)
    # When email auth is disabled, default to all permissions enabled
    # --------------------------------------------------------------------------------
    if getattr(settings, "email_auth_enabled", False):
        user_permissions = await get_user_action_permissions(
            db=db,
            user_email=user_email,
            is_admin=is_admin_user,
            token_teams=token_teams,
        )
    else:
        # Default to all permissions enabled when email auth is disabled
        user_permissions = {flag: True for flag in UI_ACTION_PERMISSIONS}

    # --------------------------------------------------------------------------------
    # Load user teams so we can validate team_id
    # --------------------------------------------------------------------------------
    user_teams = []
    team_service = None
    # Load teams if: team_id is specified, team_selector is visible, OR any data section is visible
    should_load_user_teams = getattr(settings, "email_auth_enabled", False) and (team_id is not None or "team_selector" not in hidden_header_items or any_data_section_visible)
    if should_load_user_teams:
        try:
            team_service = TeamManagementService(db)
            if user_email and "@" in user_email:
                raw_teams = await team_service.get_user_teams(user_email)

                # Batch fetch all data in 2 queries instead of 2N queries (N+1 elimination)
                team_ids = [str(team.id) for team in raw_teams]
                member_counts = await team_service.get_member_counts_batch_cached(team_ids)
                user_roles = team_service.get_user_roles_batch(user_email, team_ids)

                user_teams = []
                for team in raw_teams:
                    try:
                        current_team_id = str(team.id) if team.id else ""
                        team_dict = {
                            "id": current_team_id,
                            "name": str(team.name) if team.name else "",
                            "type": str(getattr(team, "type", "organization")),
                            "is_personal": bool(getattr(team, "is_personal", False)),
                            "member_count": member_counts.get(current_team_id, 0),
                            "role": user_roles.get(current_team_id) or "member",
                        }
                        user_teams.append(team_dict)
                    except Exception as team_error:
                        LOGGER.warning(f"Failed to serialize team {getattr(team, 'id', 'unknown')}: {team_error}")
                        continue
        except Exception as e:
            LOGGER.warning(f"Failed to load user teams: {e}")
            user_teams = []

    # --------------------------------------------------------------------------------
    # Validate team_id if provided (only when email-based teams are enabled).
    # Platform admins with unrestricted tokens (is_admin AND token_teams is None)
    # bypass the membership check. Team-scoped admin tokens can still view any
    # team for governance. Non-admins get their team filter reset when they
    # supply a team_id they do not belong to.
    # --------------------------------------------------------------------------------
    selected_team_id = team_id
    admin_viewing_non_member_team = False

    if team_id and getattr(settings, "email_auth_enabled", False):
        _token_teams = user.get("token_teams") if isinstance(user, dict) else getattr(user, "token_teams", None)
        if not (is_admin_user and _token_teams is None):
            if not user_teams:
                LOGGER.warning("team_id requested but user_teams not available; rejecting (team_id=%s)", team_id)
                raise HTTPException(status_code=403, detail="Unable to verify team membership")

            valid_team_ids = {t["id"] for t in user_teams if t.get("id")}
            if str(team_id) not in valid_team_ids:
                if not is_admin_user:
                    LOGGER.warning("Non-admin requested team_id not in their teams; ignoring team filter (team_id=%s)", team_id)
                    selected_team_id = None
                else:
                    # Admin selected a team they don't belong to; show banner and default content to All Teams
                    LOGGER.info("Admin viewing non-member team for governance (team_id=%s)", team_id)
                    admin_viewing_non_member_team = True
                    selected_team_id = None

    # --------------------------------------------------------------------------------
    # Helper: attempt to call a listing function with team_id if it supports it.
    # If the method signature doesn't accept team_id, fall back to calling it without
    # and then (optionally) filter the returned results.
    # --------------------------------------------------------------------------------
    async def _call_list_with_team_support(method, *args, **kwargs):
        """
        Attempt to call a method with an optional `team_id` parameter.

        This function tries to call the given asynchronous `method` with all provided
        arguments and an additional `team_id=selected_team_id`, assuming `selected_team_id`
        is defined and not None. If the method does not accept a `team_id` keyword argument
        (raises TypeError), the function retries the call without it.

        This is useful in scenarios where some service methods optionally support team
        scoping via a `team_id` parameter, but not all do.

        Args:
            method (Callable): The async function to be called.
            *args: Positional arguments to pass to the method.
            **kwargs: Keyword arguments to pass to the method.

        Returns:
            Any: The result of the awaited method call, typically a list of model instances.

        Raises:
            Any exception raised by the method itself, except TypeError when `team_id` is unsupported.


        Doctest:
            >>> async def sample_method(a, b):
            ...     return [a, b]
            >>> async def sample_method_with_team(a, b, team_id=None):
            ...     return [a, b, team_id]
            >>> selected_team_id = 42
            >>> import asyncio
            >>> asyncio.run(_call_list_with_team_support(sample_method_with_team, 1, 2))
            [1, 2, 42]
            >>> asyncio.run(_call_list_with_team_support(sample_method, 1, 2))
            [1, 2]

        Notes:
            - This function depends on a global `selected_team_id` variable.
            - If `selected_team_id` is None, the method is called without `team_id`.
        """
        if selected_team_id is None:
            return await method(*args, **kwargs)

        try:
            # Preferred: pass team_id to the service method if it accepts it
            return await method(*args, team_id=selected_team_id, **kwargs)
        except TypeError:
            # The method doesn't accept team_id -> fall back to original API
            LOGGER.debug("Service method %s does not accept team_id; falling back and will post-filter", getattr(method, "__name__", str(method)))
            return await method(*args, **kwargs)

    # Small utility to check if a returned model or dict matches the selected_team_id.
    def _matches_selected_team(item, tid: str) -> bool:
        """
        Determine whether the given item is associated with the specified team ID.

        This function attempts to determine if the input `item` (which may be a Pydantic model,
        an object with attributes, or a dictionary) is associated with the given team ID (`tid`).
        It checks several common attribute names (e.g., `team_id`, `team_ids`, `teams`) to see
        if any of them match the provided team ID. These fields may contain either a single ID
        or a list of IDs.

        If `tid` is falsy (e.g., empty string), the function returns True.

        Args:
            item: An object or dictionary that may contain team identification fields.
            tid (str): The team ID to match.

        Returns:
            bool: True if the item is associated with the specified team ID, otherwise False.

        Examples:
            >>> class Obj:
            ...     team_id = 'abc123'
            >>> _matches_selected_team(Obj(), 'abc123')
            True

            >>> class Obj:
            ...     team_ids = ['abc123', 'def456']
            >>> _matches_selected_team(Obj(), 'def456')
            True

            >>> _matches_selected_team({'teamId': 'xyz789'}, 'xyz789')
            True

            >>> _matches_selected_team({'teamIds': ['123', '456']}, '789')
            False

            >>> _matches_selected_team({'teams': ['t1', 't2']}, 't1')
            True

            >>> _matches_selected_team(None, 'abc')
            False
        """
        # If an item is explicitly public, it should be visible to any team
        try:
            vis = getattr(item, "visibility", None)
            if vis is None and isinstance(item, dict):
                vis = item.get("visibility")
            if isinstance(vis, str) and vis.lower() == "public":
                return True
        except Exception as exc:  # pragma: no cover - defensive logging for unexpected types
            LOGGER.debug(
                "Error checking visibility on item (type=%s): %s",
                type(item),
                exc,
                exc_info=True,
            )
        # item may be a pydantic model or dict-like
        # check common fields for team membership
        candidates = []
        # Extract team IDs from object attributes, catching exceptions from each property
        for attr_name in ["team_id", "teamId", "team_ids", "teamIds", "teams"]:
            try:
                val = getattr(item, attr_name, None)
                candidates.append(val)
            except Exception:
                pass  # nosec B110 - Intentionally ignore errors when extracting team IDs from properties
        # Extract team IDs from dict keys, catching exceptions from each .get() call
        if isinstance(item, dict):
            for key_name in ["team_id", "teamId", "team_ids", "teamIds", "teams"]:
                try:
                    val = item.get(key_name)
                    candidates.append(val)
                except Exception:
                    pass  # nosec B110 - Intentionally ignore errors when extracting team IDs from dict .get() calls

        for c in candidates:
            if c is None:
                continue
            # Some fields may be single id or list of ids
            if isinstance(c, (list, tuple, set)):
                if str(tid) in [str(x) for x in c]:
                    return True
            else:
                if str(c) == str(tid):
                    return True
        return False

    # --------------------------------------------------------------------------------
    # Load each resource list using the safe _call_list_with_team_support helper.
    # For each returned list, try to produce consistent "model_dump(by_alias=True)" dicts,
    # applying server-side filtering as a fallback if the service didn't accept team_id.
    # --------------------------------------------------------------------------------
    raw_tools = []
    if "tools" not in hidden_sections:
        try:
            raw_tools = await _call_list_with_team_support(tool_service.list_tools, db, include_inactive=include_inactive, user_email=user_email, limit=0)
            if isinstance(raw_tools, tuple):
                raw_tools = raw_tools[0]
        except Exception as e:
            LOGGER.exception("Failed to load tools for user: %s", e)

    raw_servers = []
    if "servers" not in hidden_sections:
        try:
            raw_servers = await _call_list_with_team_support(server_service.list_servers, db, include_inactive=include_inactive, user_email=user_email, limit=0)
            # Handle tuple return (list, cursor)
            if isinstance(raw_servers, tuple):
                raw_servers = raw_servers[0]
        except Exception as e:
            LOGGER.exception("Failed to load servers for user: %s", e)

    raw_resources = []
    if "resources" not in hidden_sections:
        try:
            raw_resources = await _call_list_with_team_support(resource_service.list_resources, db, include_inactive=include_inactive, user_email=user_email, limit=0)
            if isinstance(raw_resources, tuple):
                raw_resources = raw_resources[0]
        except Exception as e:
            LOGGER.exception("Failed to load resources for user: %s", e)

    raw_prompts = []
    if "prompts" not in hidden_sections:
        try:
            raw_prompts = await _call_list_with_team_support(prompt_service.list_prompts, db, include_inactive=include_inactive, user_email=user_email, limit=0)
            # Handle tuple return (list, cursor)
            if isinstance(raw_prompts, tuple):
                raw_prompts = raw_prompts[0]
        except Exception as e:
            LOGGER.exception("Failed to load prompts for user: %s", e)

    gateways_raw = []
    if "gateways" not in hidden_sections:
        try:
            gateways_raw = await _call_list_with_team_support(gateway_service.list_gateways, db, include_inactive=include_inactive, user_email=user_email, limit=0)
            # Handle tuple return (list, cursor)
            if isinstance(gateways_raw, tuple):
                gateways_raw = gateways_raw[0]
        except Exception as e:
            LOGGER.exception("Failed to load gateways: %s", e)

    # Convert models to dicts and filter as needed
    def _to_dict_and_filter(raw_list):
        """
        Convert a list of items (Pydantic models, dicts, or similar) to dictionaries and filter them
        based on a globally defined `selected_team_id`.

        For each item:
        - Try to convert it to a dictionary via `.model_dump(by_alias=True)` (if it's a Pydantic model),
        or keep it as-is if it's already a dictionary.
        - If the conversion fails, try to coerce the item to a dictionary via `dict(item)`.
        - If `selected_team_id` is set, include only items that match it via `_matches_selected_team`.

        Args:
            raw_list (list): A list of Pydantic models, dictionaries, or similar objects.

        Returns:
            list: A filtered list of dictionaries.

        Examples:
            >>> global selected_team_id
            >>> selected_team_id = 'team123'
            >>> class Model:
            ...     def __init__(self, team_id): self.team_id = team_id
            ...     def model_dump(self, by_alias=False): return {'team_id': self.team_id}
            >>> items = [Model('team123'), Model('team999')]
            >>> _to_dict_and_filter(items)
            [{'team_id': 'team123'}]

            >>> selected_team_id = None
            >>> _to_dict_and_filter([{'team_id': 'any_team'}])
            [{'team_id': 'any_team'}]

            >>> selected_team_id = 't1'
            >>> _to_dict_and_filter([{'team_ids': ['t1', 't2']}, {'team_ids': ['t3']}])
            [{'team_ids': ['t1', 't2']}]
        """
        out = []
        for item in raw_list or []:
            try:
                dumped = item.model_dump(by_alias=True) if hasattr(item, "model_dump") else (item if isinstance(item, dict) else None)
            except Exception:
                # if dumping failed, try to coerce to dict
                try:
                    dumped = dict(item) if hasattr(item, "__iter__") else None
                except Exception:
                    dumped = None
            if dumped is None:
                continue

            # If we passed team_id to service, server-side filtering applied.
            # Otherwise, filter by common team-aware fields if selected_team_id is set.
            if selected_team_id:
                if _matches_selected_team(item, selected_team_id) or _matches_selected_team(dumped, selected_team_id):
                    out.append(dumped)
                else:
                    # skip items that don't match the selected team
                    continue
            else:
                out.append(dumped)
        return out

    tools = list(sorted(_to_dict_and_filter(raw_tools), key=lambda t: ((t.get("url") or "").lower(), (t.get("original_name") or "").lower())))
    servers = _to_dict_and_filter(raw_servers)
    resources = _to_dict_and_filter(raw_resources)  # pylint: disable=unnecessary-comprehension
    prompts = _to_dict_and_filter(raw_prompts)
    gateways = [g.model_dump(by_alias=True) if hasattr(g, "model_dump") else (g if isinstance(g, dict) else {}) for g in (gateways_raw or [])]
    # If gateways need team filtering as dicts too, apply _to_dict_and_filter similarly:
    gateways = _to_dict_and_filter(gateways_raw) if isinstance(gateways_raw, (list, tuple)) else gateways

    # roots are global platform configuration; scoped admins see dashboard without root data.
    roots = []
    if can_manage_roots:
        roots = [root.model_dump(by_alias=True) for root in await root_service.list_roots()]

    # Load A2A agents if enabled
    a2a_agents = []
    if "agents" not in hidden_sections and a2a_service and settings.mcpgateway_a2a_enabled:
        a2a_agents_raw = await a2a_service.list_agents_for_user(
            db,
            user_info=user_email,
            include_inactive=include_inactive,
        )
        a2a_agents = [agent.model_dump(by_alias=True) for agent in a2a_agents_raw]
        a2a_agents = _to_dict_and_filter(a2a_agents) if isinstance(a2a_agents, (list, tuple)) else a2a_agents

    # Load gRPC services if enabled and available
    grpc_services = []
    try:
        if "grpc-services" not in hidden_sections and GRPC_AVAILABLE and grpc_service_mgr and settings.mcpgateway_grpc_enabled:
            grpc_services_raw = await grpc_service_mgr.list_services(
                db,
                include_inactive=include_inactive,
                user_email=user_email,
                team_id=selected_team_id,
            )
            grpc_services = [service.model_dump(by_alias=True) for service in grpc_services_raw]
            grpc_services = _to_dict_and_filter(grpc_services) if isinstance(grpc_services, (list, tuple)) else grpc_services
    except Exception as e:
        LOGGER.exception("Failed to load gRPC services: %s", e)
        grpc_services = []

    # Template variables and context: include selected_team_id so the template and frontend can read it
    root_path = settings.app_root_path
    max_name_length = settings.validation_max_name_length

    # End the read-only transaction before template rendering to avoid idle-in-transaction timeouts.
    db.commit()

    response = request.app.state.templates.TemplateResponse(
        request,
        "admin.html",
        {
            "request": request,
            "servers": servers,
            "tools": tools,
            "resources": resources,
            "prompts": prompts,
            "gateways": gateways,
            "a2a_agents": a2a_agents,
            "grpc_services": grpc_services,
            "roots": roots,
            "include_inactive": include_inactive,
            "root_path": root_path,
            "bundle_js": get_bundle_js_filename(),
            "bundle_css": get_bundle_css_files(),
            "max_name_length": max_name_length,
            "gateway_tool_name_separator": settings.gateway_tool_name_separator,
            "bulk_import_max_tools": settings.mcpgateway_bulk_import_max_tools,
            "a2a_enabled": settings.mcpgateway_a2a_enabled,
            "grpc_enabled": GRPC_AVAILABLE and settings.mcpgateway_grpc_enabled,
            "catalog_enabled": settings.mcpgateway_catalog_enabled,
            "llmchat_enabled": getattr(settings, "llmchat_enabled", False),
            "toolops_enabled": getattr(settings, "toolops_enabled", False),
            "observability_enabled": getattr(settings, "observability_enabled", False),
            "performance_enabled": getattr(settings, "mcpgateway_performance_tracking", False),
            "current_user": get_user_email(user),
            "email_auth_enabled": getattr(settings, "email_auth_enabled", False),
            "is_admin": is_admin,
            "user_teams": user_teams,
            "mcpgateway_ui_tool_test_timeout": settings.mcpgateway_ui_tool_test_timeout,
            "allow_public_visibility": settings.allow_public_visibility,
            "auth_header_name": settings.auth_header_name,
            "selected_team_id": selected_team_id,
            "admin_viewing_non_member_team": admin_viewing_non_member_team,
            "ui_airgapped": settings.mcpgateway_ui_airgapped,
            "ui_hidden_sections": sorted(hidden_sections),
            "ui_hidden_header_items": ui_visibility_config["hidden_header_items"],
            "ui_hidden_tabs": ui_visibility_config["hidden_tabs"],
            "user_permissions": user_permissions,
            # Password policy - pass actual requirements dict for user creation
            "password_requirements": PasswordPolicyService.get_password_requirements(is_privileged=False),
            "password_policy_enabled": getattr(settings, "password_policy_enabled", True),
            # Token policy flags
            "require_token_expiration": getattr(settings, "require_token_expiration", True),
            "sri_hashes": load_sri_hashes(),
            "max_members_per_team": settings.max_members_per_team,
            "oauth_redirect_allowed_origin": settings.oauth_redirect_allowed_origin,
        },
    )

    csrf_user_id: str | None = None
    csrf_session_id: str | None = None
    try:
        # Determine the admin user email
        admin_email = get_user_email(user)
        is_admin_flag = bool(user.get("is_admin") if isinstance(user, dict) else True)
        full_name = getattr(settings, "platform_admin_full_name", "Platform User")
        if isinstance(user, dict):
            full_name = user.get("full_name") or full_name
        else:
            full_name = getattr(user, "full_name", full_name) or full_name

        # Preserve auth provider across admin UI token refreshes so logout behavior
        # can reliably detect SSO sessions (e.g., Keycloak) later.
        auth_provider = "local"
        if isinstance(user, dict):
            provider_from_user = user.get("auth_provider")
            if isinstance(provider_from_user, str) and provider_from_user.strip():
                auth_provider = provider_from_user.strip()
        else:
            provider_from_user = getattr(user, "auth_provider", None)
            if isinstance(provider_from_user, str) and provider_from_user.strip():
                auth_provider = provider_from_user.strip()

        # get_current_user_with_permissions may not include auth_provider in its dict.
        # Fall back to the current jwt_token cookie payload before refreshing it,
        # but only reuse cookie metadata after confirming it matches this user.
        existing_payload: dict[str, Any] | None = None
        jwt_cookie = request.cookies.get("jwt_token")
        if isinstance(jwt_cookie, str) and jwt_cookie:
            try:
                existing_payload = await verify_jwt_token_cached(jwt_cookie, request)
            except Exception as provider_error:  # nosec B110 - best-effort provider preservation
                LOGGER.warning("Could not verify existing JWT cookie for admin session refresh: %s", provider_error)
                if settings.sso_keycloak_enabled:
                    auth_provider = "keycloak"

        # Generate a lightweight session JWT token for browser admin calls in every auth mode.
        email_user = db.query(EmailUser).filter(EmailUser.email == admin_email).first()
        sub_claim = str(email_user.id) if email_user else admin_email
        existing_token_teams: list[str] | None = None
        if isinstance(existing_payload, dict):
            existing_user = existing_payload.get("user")
            provider_from_token = existing_user.get("auth_provider") if isinstance(existing_user, dict) else None
            if not provider_from_token:
                provider_from_token = existing_payload.get("auth_provider")
            if auth_provider == "local" and isinstance(provider_from_token, str) and provider_from_token.strip():
                auth_provider = provider_from_token.strip()

            existing_email = existing_payload.get("email")
            if not existing_email and isinstance(existing_user, dict):
                existing_email = existing_user.get("email")
            existing_sub = existing_payload.get("sub")
            cookie_matches_user = existing_email == admin_email or (isinstance(existing_sub, str) and existing_sub in {admin_email, sub_claim})

            if cookie_matches_user:
                raw_existing_teams = existing_payload.get("teams")
                if isinstance(raw_existing_teams, list) and raw_existing_teams:
                    copied_teams: list[str] = []
                    for raw_team in raw_existing_teams:
                        if isinstance(raw_team, str) and raw_team:
                            copied_teams.append(raw_team)
                        elif isinstance(raw_team, dict) and raw_team.get("id"):
                            copied_teams.append(str(raw_team["id"]))
                    if copied_teams:
                        existing_token_teams = copied_teams

        now = datetime.now(timezone.utc)
        payload = {
            "sub": sub_claim,
            "iss": settings.jwt_issuer,
            "aud": settings.jwt_audience,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=settings.token_expiry)).timestamp()),
            "jti": str(uuid.uuid4()),
            "auth_provider": auth_provider,
            "token_use": "session",  # nosec B105 - token type marker, not a password
            "scopes": {"server_id": None, "permissions": ["*"] if is_admin_flag else [], "ip_restrictions": [], "time_restrictions": {}},
        }
        if existing_token_teams:
            payload["teams"] = existing_token_teams

        # Generate token using centralized token creation
        token = await create_jwt_token(payload)

        # Set HTTP-only cookie using centralized security cookie utility
        set_auth_cookie(response, token, remember_me=False)
        # CSRF tokens are HMAC-bound to the identity CSRFMiddleware derives from
        # request.state.user, which is EmailUser.email — not EmailUser.id (the PK
        # used for the JWT `sub` claim). Matches routers/auth.py and
        # routers/email_auth.py, which already bind to the email.
        csrf_user_id = admin_email
        csrf_session_id = str(payload["jti"])
        LOGGER.debug(f"Set session JWT token cookie for user: {admin_email}")
    except Exception as e:
        LOGGER.exception("Failed to initialize admin browser session for user %s", get_user_email(user))
        raise HTTPException(status_code=500, detail="Unable to initialize admin session") from e

    cookie_action = ui_visibility_config.get("cookie_action")
    if cookie_action:
        scope_root_path = _resolve_root_path(request)
        ui_cookie_path = f"{scope_root_path}/admin" if scope_root_path else "/admin"
        use_secure = (settings.environment == "production") or settings.secure_cookies
        samesite = settings.cookie_samesite
        if cookie_action == "set":
            response.set_cookie(
                key=UI_HIDE_SECTIONS_COOKIE_NAME,
                value=ui_visibility_config.get("cookie_value", ""),
                max_age=UI_HIDE_SECTIONS_COOKIE_MAX_AGE,
                path=ui_cookie_path,
                httponly=True,
                secure=use_secure,
                samesite=samesite,
            )
        elif cookie_action == "delete":
            response.delete_cookie(
                key=UI_HIDE_SECTIONS_COOKIE_NAME,
                path=ui_cookie_path,
                secure=use_secure,
                httponly=True,
                samesite=samesite,
            )

    _set_admin_csrf_cookie(request, response, user_id=csrf_user_id, session_id=csrf_session_id)
    return response
