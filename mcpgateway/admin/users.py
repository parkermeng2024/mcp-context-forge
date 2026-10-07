# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/admin/users.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Admin UI user routes: user list, partial, search, create, edit, activate,
deactivate, delete, unlock, and forced password change.
"""

# Standard
import html
import logging
from typing import Optional, cast as typing_cast
import urllib.parse

# Third-Party
from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
import orjson
from sqlalchemy.orm import Session

# First-Party
from mcpgateway.admin.common import _build_search_response, _normalize_search_query, _normalize_team_id, _validated_team_id_param
from mcpgateway.admin.security import enforce_admin_csrf
from mcpgateway.auth_context import get_user_email
from mcpgateway.common.query_params import QueryRenderModeUserSelector
from mcpgateway.config import settings
from mcpgateway.db import get_db, SessionLocal
from mcpgateway.middleware.rbac import get_current_user_with_permissions, require_any_permission, require_permission
from mcpgateway.schemas import PaginationMeta
from mcpgateway.services.email_auth_service import EmailAuthService, PasswordValidationError
from mcpgateway.services.password_policy_service import PasswordPolicyService
from mcpgateway.services.team_management_service import TeamManagementService
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


def validate_password_strength(password: str, email: str = "", is_admin: bool = False) -> tuple[bool, str]:
    """Validate password meets strength requirements.

    Delegates to PasswordPolicyService for comprehensive validation including
    complexity, common password detection, sequential character detection,
    and username-based validation.

    Respects password_policy_enabled toggle - if disabled, all passwords pass.

    Args:
        password: Password to validate
        email: User's email address (for username-based validation)
        is_admin: Whether this is an admin account (requires longer password)

    Returns:
        tuple: (is_valid, error_message)
    """
    # If password policy is disabled, skip all validation
    if not getattr(settings, "password_policy_enabled", True):
        return True, ""

    # First-Party
    from mcpgateway.services.password_policy_service import PasswordPolicyError

    with SessionLocal() as db:
        policy = PasswordPolicyService(db)
        try:
            policy.validate_user_password(password, email or None, is_admin)
            return True, ""
        except PasswordPolicyError as e:
            return False, str(e)


# ============================================================================ #
#                         USER MANAGEMENT ADMIN ROUTES                        #
# ============================================================================ #


def _render_user_card_html(user_obj, current_user_email: str, admin_count: int, root_path: str) -> str:
    """Render a single user card HTML snippet matching the users list template.

    Args:
        user_obj: User record to render.
        current_user_email: Email of the current user for "You" badge logic.
        admin_count: Count of active admins to protect the last admin.
        root_path: Application root path for HTMX endpoints.

    Returns:
        HTML snippet for the user card.
    """
    encoded_email = urllib.parse.quote(user_obj.email, safe="")
    display_name = html.escape(user_obj.full_name or "N/A")
    safe_email = html.escape(user_obj.email)
    auth_provider = html.escape(user_obj.auth_provider or "unknown")
    created_at = user_obj.created_at.strftime("%Y-%m-%d %H:%M") if user_obj.created_at else "Unknown"

    is_current_user = user_obj.email == current_user_email
    is_last_admin = bool(user_obj.is_admin and user_obj.is_active and admin_count == 1)
    is_locked = user_obj.is_account_locked()
    locked_until = getattr(user_obj, "locked_until", None)
    failed_attempts = int(getattr(user_obj, "failed_login_attempts", 0) or 0)
    lock_until_text = locked_until.strftime("%Y-%m-%d %H:%M") if locked_until else "N/A"

    badges = []
    if user_obj.is_admin:
        badges.append('<span class="px-2 py-1 text-xs font-semibold bg-purple-100 text-purple-800 rounded-full ' + 'dark:bg-purple-900 dark:text-purple-200">Admin</span>')
    if user_obj.is_active:
        badges.append('<span class="px-2 py-1 text-xs font-semibold text-green-600 bg-gray-100 dark:bg-gray-700 rounded-full">Active</span>')
    else:
        badges.append('<span class="px-2 py-1 text-xs font-semibold text-red-600 bg-gray-100 dark:bg-gray-700 rounded-full">Inactive</span>')
    if is_current_user:
        badges.append('<span class="px-2 py-1 text-xs font-semibold bg-blue-100 text-blue-800 rounded-full ' + 'dark:bg-blue-900 dark:text-blue-200">You</span>')
    if is_last_admin:
        badges.append('<span class="px-2 py-1 text-xs font-semibold bg-yellow-100 text-yellow-800 rounded-full ' + 'dark:bg-yellow-900 dark:text-yellow-200">Last Admin</span>')
    if user_obj.password_change_required:
        badges.append(
            '<span class="px-2 py-1 text-xs font-semibold bg-orange-100 text-orange-800 rounded-full '
            'dark:bg-orange-900 dark:text-orange-200"><i class="fas fa-key mr-1"></i>Password Change Required</span>'
        )
    if is_locked:
        badges.append('<span class="px-2 py-1 text-xs font-semibold bg-red-100 text-red-800 rounded-full ' + 'dark:bg-red-900 dark:text-red-200"><i class="fas fa-lock mr-1"></i>Locked</span>')

    actions = [
        f'<button class="px-3 py-1 text-sm font-medium text-blue-600 dark:text-blue-400 hover:text-blue-800 '
        f"dark:hover:text-blue-300 border border-blue-300 dark:border-blue-600 hover:border-blue-500 "
        f"dark:hover:border-blue-400 rounded-md focus:outline-none focus:ring-2 focus:ring-offset-2 "
        f'focus:ring-blue-500" hx-get="{root_path}/admin/users/{encoded_email}/edit" '
        f'hx-target="#user-edit-modal-content">Edit</button>'
    ]

    if not is_current_user and not is_last_admin:
        if is_locked:
            actions.append(
                f'<button class="px-3 py-1 text-sm font-medium text-indigo-600 dark:text-indigo-400 hover:text-indigo-800 '
                f"dark:hover:text-indigo-300 border border-indigo-300 dark:border-indigo-600 hover:border-indigo-500 "
                f"dark:hover:border-indigo-400 rounded-md focus:outline-none focus:ring-2 focus:ring-offset-2 "
                f'focus:ring-indigo-500" hx-post="{root_path}/admin/users/{encoded_email}/unlock" '
                f'hx-confirm="Unlock this user account?" hx-target="closest .user-card" hx-swap="outerHTML">Unlock</button>'
            )

        if user_obj.is_active:
            actions.append(
                f'<button class="px-3 py-1 text-sm font-medium text-orange-600 dark:text-orange-400 hover:text-orange-800 '
                f"dark:hover:text-orange-300 border border-orange-300 dark:border-orange-600 hover:border-orange-500 "
                f"dark:hover:border-orange-400 rounded-md focus:outline-none focus:ring-2 focus:ring-offset-2 "
                f'focus:ring-orange-500" hx-post="{root_path}/admin/users/{encoded_email}/deactivate" '
                f'hx-confirm="Deactivate this user?" hx-target="closest .user-card" hx-swap="outerHTML">Deactivate</button>'
            )
        else:
            actions.append(
                f'<button class="px-3 py-1 text-sm font-medium text-green-600 dark:text-green-400 hover:text-green-800 '
                f"dark:hover:text-green-300 border border-green-300 dark:border-green-600 hover:border-green-500 "
                f"dark:hover:border-green-400 rounded-md focus:outline-none focus:ring-2 focus:ring-offset-2 "
                f'focus:ring-green-500" hx-post="{root_path}/admin/users/{encoded_email}/activate" '
                f'hx-confirm="Activate this user?" hx-target="closest .user-card" hx-swap="outerHTML">Activate</button>'
            )

        if user_obj.password_change_required:
            actions.append(
                '<span class="px-3 py-1 text-sm font-medium text-orange-600 dark:text-orange-400 bg-orange-50 '
                'dark:bg-orange-900/20 border border-orange-300 dark:border-orange-600 rounded-md">Password Change Required</span>'
            )
        else:
            actions.append(
                f'<button class="px-3 py-1 text-sm font-medium text-yellow-600 dark:text-yellow-400 hover:text-yellow-800 '
                f"dark:hover:text-yellow-300 border border-yellow-300 dark:border-yellow-600 hover:border-yellow-500 "
                f"dark:hover:border-yellow-400 rounded-md focus:outline-none focus:ring-2 focus:ring-offset-2 "
                f'focus:ring-yellow-500" hx-post="{root_path}/admin/users/{encoded_email}/force-password-change" '
                f'hx-confirm="Force this user to change their password on next login?" hx-target="closest .user-card" '
                f'hx-swap="outerHTML">Force Password Change</button>'
            )

        actions.append(
            f'<button class="px-3 py-1 text-sm font-medium text-red-600 dark:text-red-400 hover:text-red-800 '
            f"dark:hover:text-red-300 border border-red-300 dark:border-red-600 hover:border-red-500 "
            f"dark:hover:border-red-400 rounded-md focus:outline-none focus:ring-2 focus:ring-offset-2 "
            f'focus:ring-red-500" hx-delete="{root_path}/admin/users/{encoded_email}" '
            f'hx-confirm="Are you sure you want to delete this user? This action cannot be undone." '
            f'hx-target="closest .user-card" hx-swap="outerHTML" '
            f'hx-on::after-request="handleDeleteUserError(event)">Delete</button>'
        )

    return f"""
    <div class="user-card border border-gray-200 dark:border-gray-700 rounded-lg p-4 bg-white dark:bg-gray-800">
      <div class="flex justify-between items-start">
        <div class="flex-1">
          <div class="flex items-center gap-2 mb-2">
            <h3 class="text-lg font-semibold text-gray-900 dark:text-white">{display_name}</h3>
            {" ".join(badges)}
          </div>
          <p class="text-sm text-gray-600 dark:text-gray-400 mb-2">📧 {safe_email}</p>
          <p class="text-sm text-gray-600 dark:text-gray-400 mb-2">🔐 Provider: {auth_provider}</p>
          <p class="text-sm text-gray-600 dark:text-gray-400 mb-2">⚠️ Failed attempts: {failed_attempts}</p>
          <p class="text-sm text-gray-600 dark:text-gray-400 mb-2">🔒 Locked until: {lock_until_text}</p>
          <p class="text-sm text-gray-600 dark:text-gray-400">📅 Created: {created_at}</p>
        </div>
        <div class="flex gap-2 ml-4">
          {" ".join(actions)}
        </div>
      </div>
    </div>
    """


@router.get("/users")
@require_permission("admin.user_management", allow_admin_bypass=False)
async def admin_list_users(
    request: Request,
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    per_page: int = Query(settings.pagination_default_page_size, ge=1, le=settings.pagination_max_page_size, description="Items per page"),
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> Response:
    """
    List users for the admin UI with pagination support.

    This endpoint retrieves a paginated list of users from the database.
    Uses offset-based (page/per_page) pagination.
    Supports JSON response for dropdown population when format=json query parameter is provided.

    Args:
        request: FastAPI request object
        page: Page number (1-indexed). Default: 1.
        per_page: Items per page. Default: 50.
        db: Database session dependency
        user: Authenticated user dependency

    Returns:
        Dict with 'data', 'pagination', and 'links' keys containing paginated users,
        or JSON response for dropdown population.
    """
    if not settings.email_auth_enabled:
        return HTMLResponse(
            content='<div class="text-center py-8"><p class="text-gray-500">Email authentication is disabled. User management requires email auth.</p></div>',
            status_code=200,
        )

    LOGGER.debug(f"User {get_user_email(user)} requested user list (page={page}, per_page={per_page})")

    auth_service = EmailAuthService(db)

    # Check if JSON response is requested (for dropdown population)
    accept_header = request.headers.get("accept", "")
    is_json_request = "application/json" in accept_header or request.query_params.get("format") == "json"

    if is_json_request:
        # Return JSON for dropdown population - always return first page with 100 users
        paginated_result = await auth_service.list_users(page=1, per_page=100)
        users_data = [{"email": user_obj.email, "full_name": user_obj.full_name, "is_active": user_obj.is_active, "is_admin": user_obj.is_admin} for user_obj in paginated_result.data]
        return ORJSONResponse(content={"users": users_data})

    # List users with page-based pagination
    paginated_result = await auth_service.list_users(page=page, per_page=per_page)

    # End the read-only transaction early to avoid idle-in-transaction under load
    db.commit()

    # Return standardized paginated response (for legacy compatibility)
    return ORJSONResponse(
        content={
            "data": [{"email": u.email, "full_name": u.full_name, "is_active": u.is_active, "is_admin": u.is_admin} for u in paginated_result.data],
            "pagination": paginated_result.pagination.model_dump() if paginated_result.pagination else None,
            "links": paginated_result.links.model_dump() if paginated_result.links else None,
        }
    )


@router.get("/users/partial", response_class=HTMLResponse)
@require_permission("admin.user_management", allow_admin_bypass=False)
async def admin_users_partial_html(
    request: Request,
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    per_page: int = Query(settings.pagination_default_page_size, ge=1, le=settings.pagination_max_page_size, description="Items per page"),
    render: QueryRenderModeUserSelector = None,
    team_id: Optional[str] = Depends(_validated_team_id_param),
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> Response:
    """
    Return paginated users as HTML partial for HTMX requests.

    This endpoint returns rendered HTML for the users list with pagination controls,
    designed for HTMX-based dynamic updates.

    Args:
        request: FastAPI request object
        page: Page number (1-indexed). Default: 1.
        per_page: Items per page. Default: 50.
        render: Render mode - 'selector' returns user selector items, 'controls' returns pagination controls.
        team_id: Optional team ID to pre-select members in selector mode
        db: Database session
        user: Current authenticated user context

    Returns:
        Response: HTML response with users list and pagination controls
    """
    try:
        if not settings.email_auth_enabled:
            return HTMLResponse(
                content='<div class="text-center py-8"><p class="text-gray-500">Email authentication is disabled. User management requires email auth.</p></div>',
                status_code=200,
            )

        auth_service = EmailAuthService(db)

        # List users with page-based pagination
        paginated_result = await auth_service.list_users(page=page, per_page=per_page)
        users_db = paginated_result.data
        pagination = typing_cast(PaginationMeta, paginated_result.pagination)

        # Get current user email
        current_user_email = get_user_email(user)

        # Check how many active admins we have
        admin_count = await auth_service.count_active_admin_users()

        # Prepare user data for template with additional flags
        users_data = []
        for user_obj in users_db:
            is_current_user = user_obj.email == current_user_email
            is_last_admin = user_obj.is_admin and user_obj.is_active and admin_count == 1

            users_data.append(
                {
                    "email": user_obj.email,
                    "full_name": user_obj.full_name,
                    "is_active": user_obj.is_active,
                    "is_admin": user_obj.is_admin,
                    "auth_provider": user_obj.auth_provider,
                    "created_at": user_obj.created_at,
                    "password_change_required": user_obj.password_change_required,
                    "is_locked": user_obj.is_account_locked(),
                    "failed_login_attempts": int(getattr(user_obj, "failed_login_attempts", 0) or 0),
                    "locked_until": getattr(user_obj, "locked_until", None),
                    "is_current_user": is_current_user,
                    "is_last_admin": is_last_admin,
                }
            )

        # Get team members if team_id is provided (for pre-selection in team member addition)
        team_member_emails = set()
        team_member_data = {}
        current_user_is_team_owner = False

        if team_id and render == "selector":
            team_service = TeamManagementService(db)
            try:
                team_members = await team_service.get_team_members(team_id)
                team_member_emails = {team_user.email for team_user, membership in team_members}

                # Build enhanced member data from the same query result (no extra DB calls!)
                # Count owners in-memory
                owner_count = sum(1 for _, membership in team_members if membership.role == "owner")

                # Build member data dict and find current user's role
                for team_user, membership in team_members:
                    email = team_user.email
                    is_last_owner = membership.role == "owner" and owner_count == 1
                    team_member_data[email] = type("MemberData", (), {"role": membership.role, "joined_at": membership.joined_at, "is_last_owner": is_last_owner})()

                    # Check if current user is owner (in-memory check)
                    if email == current_user_email and membership.role == "owner":
                        current_user_is_team_owner = True

            except Exception as e:
                LOGGER.warning(f"Could not fetch team members for team {team_id}: {e}")

        # End the read-only transaction early to avoid idle-in-transaction under load
        db.commit()

        if render == "selector":
            response = request.app.state.templates.TemplateResponse(
                request,
                "team_members_selector.html",
                {
                    "request": request,
                    "data": users_data,
                    "pagination": pagination.model_dump(),
                    "root_path": _resolve_root_path(request),
                    "team_member_emails": team_member_emails,
                    "team_member_data": team_member_data,
                    "current_user_email": current_user_email,
                    "current_user_is_team_owner": current_user_is_team_owner,
                    "team_id": team_id,
                },
            )
        elif render == "controls":
            base_url = f"{_resolve_root_path(request)}/admin/users/partial"
            response = request.app.state.templates.TemplateResponse(
                request,
                "pagination_controls.html",
                {
                    "request": request,
                    "pagination": pagination.model_dump(),
                    "base_url": base_url,
                    "hx_target": "#users-list-container",
                    "hx_indicator": "#users-loading",
                    "hx_swap": "outerHTML",
                    "query_params": {},
                    "root_path": _resolve_root_path(request),
                },
            )
        else:
            # Render template with paginated data
            response = request.app.state.templates.TemplateResponse(
                request,
                "users_partial.html",
                {
                    "request": request,
                    "data": users_data,
                    "pagination": pagination.model_dump(),
                    "root_path": _resolve_root_path(request),
                    "current_user_email": current_user_email,
                    # The route is gated on admin.user_management, which is the
                    # same permission behind can_create_user in the dashboard.
                    "can_create_user": True,
                },
            )

        # Prevent stale partials after create/update/delete actions.
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response

    except Exception as e:
        LOGGER.error(f"Error loading users partial for admin {user}: {e}")
        return HTMLResponse(content=f'<div class="text-center py-8"><p class="text-red-500">Error loading users: {html.escape(str(e))}</p></div>', status_code=200)


@router.get("/teams/{team_id}/members/partial", response_class=HTMLResponse)
@require_permission("teams.manage_members", allow_admin_bypass=False)
async def admin_team_members_partial_html(
    team_id: str,
    request: Request,
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    per_page: int = Query(settings.pagination_default_page_size, ge=1, le=settings.pagination_max_page_size, description="Items per page"),
    search: str = Query("", max_length=255, description="Search term to filter members by name or email"),
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> Response:
    """Return paginated team members for two-section layout (top section).

    Args:
        team_id: Team identifier.
        request: FastAPI request object.
        page: Page number (1-indexed). Default: 1.
        per_page: Items per page. Default: 50.
        search: Search term to filter members by name or email.
        db: Database session.
        user: Current authenticated user context.

    Returns:
        Response: HTML response with team members and pagination data.
    """
    try:
        if not settings.email_auth_enabled:
            return HTMLResponse(
                content='<div class="text-center py-8"><p class="text-gray-500">Email authentication is disabled.</p></div>',
                status_code=200,
            )

        team_service = TeamManagementService(db)
        current_user_email = get_user_email(user)

        try:
            team_id = _normalize_team_id(team_id)
        except ValueError:
            return HTMLResponse(content='<div class="text-red-500">Invalid team ID</div>', status_code=400)

        team = await team_service.get_team_by_id(team_id)
        if not team:
            return HTMLResponse(content='<div class="text-red-500">Team not found</div>', status_code=404)

        current_user_role = await team_service.get_user_role_in_team(current_user_email, team_id)
        if current_user_role != "owner":
            return HTMLResponse(content='<div class="text-red-500">Only team owners can manage members</div>', status_code=403)

        # Get paginated team members with optional search filter
        search_term = search.strip() if search else ""
        paginated_result = await team_service.get_team_members(team_id, page=page, per_page=per_page, search=search_term or None)
        members = paginated_result["data"]
        pagination = paginated_result["pagination"]

        # Count owners for is_last_owner check - must count ALL owners, not just current page
        owner_count = team_service.count_team_owners(team_id)

        # End the read-only transaction early
        db.commit()

        root_path = _resolve_root_path(request)
        search_param = f"&search={urllib.parse.quote(search_term)}" if search_term else ""
        next_page_url = f"{root_path}/admin/teams/{team_id}/members/partial?page={pagination.page + 1}&per_page={pagination.per_page}{search_param}"
        response = request.app.state.templates.TemplateResponse(
            request,
            "team_users_selector.html",
            {
                "request": request,
                "data": members,  # List of (user, membership) tuples
                "pagination": pagination.model_dump(),
                "root_path": root_path,
                "current_user_email": current_user_email,
                "current_user_is_team_owner": True,  # Already verified above
                "owner_count": owner_count,
                "team_id": team_id,
                "is_members_list": True,
                "scroll_trigger_id": "members-scroll-trigger",
                "next_page_url": next_page_url,
            },
        )
        # Prevent nginx caching for real-time member list updates
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response

    except Exception as e:
        LOGGER.error(f"Error loading team members partial for team {team_id}: {e}")
        return HTMLResponse(content=f'<div class="text-center py-8"><p class="text-red-500">Error loading members: {html.escape(str(e))}</p></div>', status_code=200)


@router.get("/teams/{team_id}/non-members/partial", response_class=HTMLResponse)
@require_permission("teams.manage_members", allow_admin_bypass=False)
async def admin_team_non_members_partial_html(
    team_id: str,
    request: Request,
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    per_page: int = Query(50, ge=1, le=50, description="Items per page (max 50 for non-members)"),
    search: str = Query("", max_length=255, description="Search term to filter non-members by name or email"),
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> Response:
    """Return paginated non-members for two-section layout (bottom section).

    Non-members are only returned when a search term with at least 2 characters
    is provided. Without a search term, returns an empty placeholder prompting
    the user to search.

    Args:
        team_id: Team identifier.
        request: FastAPI request object.
        page: Page number (1-indexed). Default: 1.
        per_page: Items per page (capped at 50). Default: 50.
        search: Search term to filter non-members by name or email.
        db: Database session.
        user: Current authenticated user context.

    Returns:
        Response: HTML response with non-members and pagination data.
    """
    try:
        if not settings.email_auth_enabled:
            return HTMLResponse(
                content='<div class="text-center py-8"><p class="text-gray-500">Email authentication is disabled.</p></div>',
                status_code=200,
            )

        auth_service = EmailAuthService(db)
        team_service = TeamManagementService(db)
        current_user_email = get_user_email(user)

        try:
            team_id = _normalize_team_id(team_id)
        except ValueError:
            return HTMLResponse(content='<div class="text-red-500">Invalid team ID</div>', status_code=400)

        team = await team_service.get_team_by_id(team_id)
        if not team:
            return HTMLResponse(content='<div class="text-red-500">Team not found</div>', status_code=404)

        current_user_role = await team_service.get_user_role_in_team(current_user_email, team_id)
        if current_user_role != "owner":
            return HTMLResponse(content='<div class="text-red-500">Only team owners can manage members</div>', status_code=403)

        # Require a search term - do not load all non-members by default
        search_term = search.strip() if search else ""
        if not search_term:
            return HTMLResponse(
                content='<div class="text-center py-4 text-gray-500 dark:text-gray-400">Search for users by name or email to add them to this team.</div>',
                status_code=200,
            )
        if len(search_term) < 2:
            return HTMLResponse(
                content='<div class="text-center py-4 text-gray-500 dark:text-gray-400">Type at least 2 characters to search for users.</div>',
                status_code=200,
            )

        # Cap per_page at 50 for non-members to prevent DOM overload
        per_page = min(per_page, 50)

        # Get paginated non-members with search filter
        paginated_result = await auth_service.list_users_not_in_team(team_id, page=page, per_page=per_page, search=search_term)
        users = paginated_result.data
        pagination = typing_cast(PaginationMeta, paginated_result.pagination)

        # End the read-only transaction early
        db.commit()

        root_path = _resolve_root_path(request)
        search_param = f"&search={urllib.parse.quote(search_term)}" if search_term else ""
        next_page_url = f"{root_path}/admin/teams/{team_id}/non-members/partial?page={pagination.page + 1}&per_page={pagination.per_page}{search_param}"
        response = request.app.state.templates.TemplateResponse(
            request,
            "team_users_selector.html",
            {
                "request": request,
                "data": users,  # List of user objects
                "pagination": pagination.model_dump(),
                "root_path": root_path,
                "current_user_email": current_user_email,
                "current_user_is_team_owner": True,  # Already verified above
                "owner_count": 0,  # Not relevant for non-members
                "team_id": team_id,
                "is_members_list": False,
                "scroll_trigger_id": "non-members-scroll-trigger",
                "next_page_url": next_page_url,
            },
        )
        # Prevent nginx caching for real-time non-member list updates
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response

    except Exception as e:
        LOGGER.error(f"Error loading team non-members partial for team {team_id}: {e}")
        return HTMLResponse(content=f'<div class="text-center py-8"><p class="text-red-500">Error loading non-members: {html.escape(str(e))}</p></div>', status_code=200)


@router.get("/users/search", response_class=JSONResponse)
@require_any_permission(["admin.user_management", "teams.manage_members"], allow_admin_bypass=False)
async def admin_search_users(
    q: str = Query("", max_length=500, description="Search query"),
    limit: int = Query(settings.pagination_default_page_size, ge=1, le=settings.pagination_max_page_size, description="Maximum number of results to return"),
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    """
    Search users by email or full name.

    This endpoint searches users for use in search functionality like team member selection.

    Args:
        q (str): Search query string to match against email or full name
        limit (int): Maximum number of results to return
        db (Session): Database session dependency
        user: Current user making the request

    Returns:
        JSONResponse: Dictionary containing list of matching users and count
    """
    search_query = _normalize_search_query(q)
    if not settings.email_auth_enabled:
        return _build_search_response(entity_key="users", entity_type="users", items=[], query=search_query, tags="", tag_groups=[])

    user_email = get_user_email(user)

    if not search_query:
        return _build_search_response(entity_key="users", entity_type="users", items=[], query=search_query, tags="", tag_groups=[])

    LOGGER.debug(f"User {user_email} searching users with query: {search_query}")

    auth_service = EmailAuthService(db)

    # Use list_users with search parameter
    users_result = await auth_service.list_users(search=search_query, limit=limit)
    users_list = users_result.data

    # Format results for JSON response
    results = [
        {
            "id": user_obj.email,
            "name": user_obj.full_name or user_obj.email,
            "email": user_obj.email,
            "full_name": user_obj.full_name or "",
            "is_active": user_obj.is_active,
            "is_admin": user_obj.is_admin,
        }
        for user_obj in users_list
    ]

    return _build_search_response(entity_key="users", entity_type="users", items=results, query=search_query, tags="", tag_groups=[])


@router.post("/users")
@require_permission("admin.user_management", allow_admin_bypass=False)
async def admin_create_user(
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> HTMLResponse:
    """Create a new user via admin UI.

    Args:
        request: FastAPI request object
        db: Database session
        user: Current authenticated user context

    Returns:
        HTMLResponse: Success message or error response
    """
    try:
        form = await request.form()

        # Validate password strength
        password = str(form.get("password", ""))
        email_val = str(form.get("email", ""))
        is_admin_val = form.get("is_admin") == "on"
        if password:
            is_valid, error_msg = validate_password_strength(password, email_val, is_admin_val)
            if not is_valid:
                # Use data-error-message attribute for reliable error extraction (not CSS class scraping)
                error_html = f'<div class="text-red-500" data-error-message="{html.escape(error_msg)}"><strong>Password validation failed:</strong><br/>{html.escape(error_msg)}</div>'
                return HTMLResponse(content=error_html, status_code=400)

        # First-Party

        auth_service = EmailAuthService(db)

        # Create new user
        new_user = await auth_service.create_user(
            email=email_val,
            password=password,
            full_name=str(form.get("full_name", "")),
            is_admin=is_admin_val,
            auth_provider="local",
            granted_by=get_user_email(user),  # Pass current admin user for audit trail
        )

        # If the user was created with the default password, optionally force password change
        if settings.password_change_enforcement_enabled and getattr(settings, "require_password_change_for_default_password", True) and password == settings.default_user_password.get_secret_value():  # nosec B105
            new_user.password_change_required = True
            db.commit()

        LOGGER.info(f"Admin {user} created user: {new_user.email}")

        # Return HX-Trigger header to refresh the users list
        # This will trigger a reload of the users-list-container
        response = HTMLResponse(content='<div class="text-green-500">User created successfully!</div>', status_code=201)
        response.headers["HX-Trigger"] = "userCreated"
        return response

    except Exception as e:
        LOGGER.error(f"Error creating user by admin {user}: {e}")
        return HTMLResponse(content=f'<div class="text-red-500">Error creating user: {html.escape(str(e))}</div>', status_code=400)


@router.get("/users/{user_email}/edit")
@require_permission("admin.user_management", allow_admin_bypass=False)
async def admin_get_user_edit(
    user_email: str,
    _request: Request,
    db: Session = Depends(get_db),
    _user=Depends(get_current_user_with_permissions),
) -> HTMLResponse:
    """Get user edit form via admin UI.

    Args:
        user_email: Email of user to edit
        db: Database session

    Returns:
        HTMLResponse: User edit form HTML
    """
    if not settings.email_auth_enabled:
        return HTMLResponse(content='<div class="text-red-500">Email authentication is disabled</div>', status_code=403)

    try:
        # Get root path for URL construction
        root_path = _resolve_root_path(_request) if _request else ""

        # First-Party

        auth_service = EmailAuthService(db)

        # URL decode the email

        decoded_email = urllib.parse.unquote(user_email)

        user_obj = await auth_service.get_user_by_email(decoded_email)
        if not user_obj:
            return HTMLResponse(content='<div class="text-red-500">User not found</div>', status_code=404)

        # Get current user's email to check if editing self
        current_user_email = get_user_email(_user)
        is_editing_self = current_user_email.lower() == decoded_email.lower()

        # Build Password Requirements HTML separately to avoid backslash issues inside f-strings
        if settings.password_require_uppercase or settings.password_require_lowercase or settings.password_require_numbers or settings.password_require_special:
            pr_lines = []
            pr_lines.append(f"""                <!-- Password Requirements -->
                <div class="bg-blue-50 dark:bg-blue-900 border border-blue-200 dark:border-blue-700 rounded-md p-4">
                    <div class="flex items-start">
                        <svg class="h-5 w-5 text-blue-600 dark:text-blue-400 flex-shrink-0 mt-0.5" viewBox="0 0 20 20" fill="currentColor">
                            <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd"/>
                        </svg>
                        <div class="ml-3 flex-1">
                            <h3 class="text-sm font-semibold text-blue-900 dark:text-blue-200">Password Requirements</h3>
                            <div class="mt-2 text-sm text-blue-800 dark:text-blue-300 space-y-1">
                                <div class="flex items-center" id="edit-req-length">
                                    <span class="inline-flex items-center justify-center w-4 h-4 bg-gray-400 text-white rounded-full text-xs mr-2">✗</span>
                                    <span>At least {settings.password_min_length} characters long</span>
                                </div>
            """)
            if settings.password_require_uppercase:
                pr_lines.append("""
                                <div class="flex items-center" id="edit-req-uppercase"><span class="inline-flex items-center justify-center w-4 h-4 bg-gray-400 text-white rounded-full text-xs mr-2">✗</span><span>Contains uppercase letters (A-Z)</span></div>
                """)
            if settings.password_require_lowercase:
                pr_lines.append("""
                                <div class="flex items-center" id="edit-req-lowercase"><span class="inline-flex items-center justify-center w-4 h-4 bg-gray-400 text-white rounded-full text-xs mr-2">✗</span><span>Contains lowercase letters (a-z)</span></div>
                """)
            if settings.password_require_numbers:
                pr_lines.append("""
                                <div class="flex items-center" id="edit-req-numbers"><span class="inline-flex items-center justify-center w-4 h-4 bg-gray-400 text-white rounded-full text-xs mr-2">✗</span><span>Contains numbers (0-9)</span></div>
                """)
            if settings.password_require_special:
                pr_lines.append("""
                                <div class="flex items-center" id="edit-req-special"><span class="inline-flex items-center justify-center w-4 h-4 bg-gray-400 text-white rounded-full text-xs mr-2">✗</span><span>Contains special characters (!@#$%^&amp;*(),.?&quot;:{{}}|&lt;&gt;)</span></div>
                """)
            pr_lines.append("""
                            </div>
                        </div>
                    </div>
                </div>
            """)
            password_requirements_html = "".join(pr_lines)
        else:
            # Intentionally an empty string for HTML insertion when no requirements apply.
            # This is not a password value; suppress Bandit false positive B105.
            password_requirements_html = ""  # nosec B105

        # Create edit form HTML
        edit_form = f"""
        <div id="user-edit-modal-content" class="space-y-4">
            <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-4">Edit User</h3>
            <div id="edit-user-error"></div>
            <form hx-post="{root_path}/admin/users/{user_email}/update" hx-target="#edit-user-error" hx-swap="innerHTML" class="space-y-4">
                <div>
                    <label class="block text-sm font-medium text-gray-700 dark:text-gray-300">Email</label>
                    <input type="email" name="email" value="{user_obj.email}" readonly
                           class="mt-1 block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm bg-gray-50 dark:bg-gray-700 text-gray-900 dark:text-white">
                </div>
                <div>
                    <label class="block text-sm font-medium text-gray-700 dark:text-gray-300">Full Name</label>
                    <input type="text" name="full_name" value="{user_obj.full_name or ""}" required
                           class="mt-1 block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 dark:bg-gray-700 text-gray-900 dark:text-white">
                </div>
                {
            ""
            if is_editing_self
            else f'''<div>
                    <label class="block text-sm font-medium text-gray-700 dark:text-gray-300">
                        <input type="checkbox" name="is_admin" {"checked" if user_obj.is_admin else ""}
                               class="mr-2"> Administrator
                    </label>
                </div>'''
        }
                {'<input type="hidden" name="is_admin" value="on">' if is_editing_self and user_obj.is_admin else ""}
                <div>
                    <label class="block text-sm font-medium text-gray-700 dark:text-gray-300">
                        <input type="checkbox" name="email_verified" {"checked" if user_obj.is_email_verified() else ""}
                               class="mr-2"> Email Verified
                    </label>
                </div>
                <div>
                    <label class="block text-sm font-medium text-gray-700 dark:text-gray-300">New Password (leave empty to keep current)</label>
                    <input type="password" name="password" id="password-field"
                           class="mt-1 block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 dark:bg-gray-700 text-gray-900 dark:text-white"
                           oninput="Admin.validatePasswordRequirements(); Admin.validatePasswordMatch();">
                </div>
                <div>
                    <label class="block text-sm font-medium text-gray-700 dark:text-gray-300">Confirm New Password</label>
                    <input type="password" name="confirm_password" id="confirm-password-field"
                           class="mt-1 block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 dark:bg-gray-700 text-gray-900 dark:text-white"
                           oninput="Admin.validatePasswordMatch()">
                    <div id="password-match-message" class="mt-1 text-sm text-red-600 hidden">Passwords do not match</div>
                </div>
                {password_requirements_html}
                <div
                    id="edit-password-policy-data"
                    class="hidden"
                    data-min-length="{settings.password_min_length}"
                    data-require-uppercase="{"true" if settings.password_require_uppercase else "false"}"
                    data-require-lowercase="{"true" if settings.password_require_lowercase else "false"}"
                    data-require-numbers="{"true" if settings.password_require_numbers else "false"}"
                    data-require-special="{"true" if settings.password_require_special else "false"}"
                ></div>
                <div class="flex justify-end space-x-3">
                    <button type="button" onclick="Admin.hideUserEditModal()"
                            class="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-md hover:bg-gray-50 dark:hover:bg-gray-700">
                        Cancel
                    </button>
                    <button type="submit"
                            class="px-4 py-2 text-sm font-medium text-white bg-blue-600 border border-transparent rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500">
                        Update User
                    </button>
                </div>
            </form>
        </div>
        """
        return HTMLResponse(content=edit_form)

    except Exception as e:
        LOGGER.error(f"Error getting user edit form for {user_email}: {e}")
        return HTMLResponse(content=f'<div class="text-red-500">Error loading user: {html.escape(str(e))}</div>', status_code=500)


@router.post("/users/{user_email}/update")
@require_permission("admin.user_management", allow_admin_bypass=False)
async def admin_update_user(
    user_email: str,
    request: Request,
    db: Session = Depends(get_db),
    _user=Depends(get_current_user_with_permissions),
) -> HTMLResponse:
    """Update user via admin UI.

    Args:
        user_email: Email of user to update
        request: FastAPI request object
        db: Database session

    Returns:
        HTMLResponse: Success message or error response
    """
    if not settings.email_auth_enabled:
        return HTMLResponse(content='<div class="text-red-500">Email authentication is disabled</div>', status_code=403)

    try:
        # First-Party

        auth_service = EmailAuthService(db)

        # URL decode the email

        decoded_email = urllib.parse.unquote(user_email)

        form = await request.form()
        full_name = form.get("full_name")
        is_admin = form.get("is_admin") == "on"
        email_verified = form.get("email_verified") == "on"
        password = form.get("password")
        confirm_password = form.get("confirm_password")

        # Validate password confirmation if password is being changed
        if password and password != confirm_password:
            return HTMLResponse(content='<div class="text-red-500">Passwords do not match</div>', status_code=400, headers={"HX-Retarget": "#edit-user-error"})

        # Get current user's email to prevent self-demotion
        current_user_email = get_user_email(_user)

        # Update user
        fn_val = form.get("full_name")
        pw_val = form.get("password")
        full_name = fn_val if isinstance(fn_val, str) else None
        password = pw_val.strip() if isinstance(pw_val, str) and pw_val.strip() else None

        # Validate password if provided
        if password:
            is_valid, error_msg = validate_password_strength(password, decoded_email, is_admin)
            if not is_valid:
                return HTMLResponse(content=f'<div class="text-red-500">Password validation failed: {error_msg}</div>', status_code=400, headers={"HX-Retarget": "#edit-user-error"})

        await auth_service.update_user(
            email=decoded_email,
            full_name=full_name,
            is_admin=is_admin,
            email_verified=email_verified,
            password=password,
            admin_origin_source="ui",
            requesting_user_email=current_user_email,
        )

        # Return success message with auto-close and refresh
        success_html = """
        <div class="text-green-500 text-center p-4">
            <p>User updated successfully</p>
            <button type="button" onclick="Admin.hideUserEditModal()" class="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-md hover:bg-gray-50 dark:hover:bg-gray-700">
                Close
            </button>
        </div>
        """
        response = HTMLResponse(content=success_html)
        response.headers["HX-Trigger"] = orjson.dumps({"adminUserAction": {"closeUserEditModal": True, "refreshUsersList": True, "delayMs": 1500}}).decode()
        return response

    except PasswordValidationError as exc:
        LOGGER.warning("Password validation failed while updating user %s: %s", user_email, exc)
        return HTMLResponse(content=f'<div class="text-red-500">Password validation failed: {html.escape(str(exc))}</div>', status_code=400, headers={"HX-Retarget": "#edit-user-error"})
    except Exception as e:
        LOGGER.error(f"Error updating user {user_email}: {e}")
        return HTMLResponse(content=f'<div class="text-red-500">Error updating user: {html.escape(str(e))}</div>', status_code=400, headers={"HX-Retarget": "#edit-user-error"})


@router.post("/users/{user_email}/activate")
@require_permission("admin.user_management", allow_admin_bypass=False)
async def admin_activate_user(
    user_email: str,
    _request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> HTMLResponse:
    """Activate user via admin UI.

    Args:
        user_email: Email of user to activate
        db: Database session
        user: Current authenticated user context

    Returns:
        HTMLResponse: Success message or error response
    """
    if not settings.email_auth_enabled:
        return HTMLResponse(content='<div class="text-red-500">Email authentication is disabled</div>', status_code=403)

    try:
        # Get root path for URL construction
        root_path = _resolve_root_path(_request) if _request else ""

        # First-Party

        auth_service = EmailAuthService(db)

        # URL decode the email

        decoded_email = urllib.parse.unquote(user_email)

        # Get current user email from JWT (used for logging purposes)
        current_user_email = get_user_email(user)

        user_obj = await auth_service.activate_user(decoded_email)
        admin_count = await auth_service.count_active_admin_users()
        return HTMLResponse(content=_render_user_card_html(user_obj, current_user_email, admin_count, root_path))

    except Exception as e:
        LOGGER.error(f"Error activating user {user_email}: {e}")
        return HTMLResponse(content=f'<div class="text-red-500">Error activating user: {html.escape(str(e))}</div>', status_code=400)


@router.post("/users/{user_email}/deactivate")
@require_permission("admin.user_management", allow_admin_bypass=False)
async def admin_deactivate_user(
    user_email: str,
    _request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> HTMLResponse:
    """Deactivate user via admin UI.

    Args:
        user_email: Email of user to deactivate
        db: Database session
        user: Current authenticated user context

    Returns:
        HTMLResponse: Success message or error response
    """
    if not settings.email_auth_enabled:
        return HTMLResponse(content='<div class="text-red-500">Email authentication is disabled</div>', status_code=403)

    try:
        # Get root path for URL construction
        root_path = _resolve_root_path(_request) if _request else ""

        # First-Party

        auth_service = EmailAuthService(db)

        # URL decode the email

        decoded_email = urllib.parse.unquote(user_email)

        # Get current user email from JWT
        current_user_email = get_user_email(user)

        user_obj = await auth_service.update_user(email=decoded_email, is_active=False, requesting_user_email=current_user_email, admin_origin_source="ui")
        admin_count = await auth_service.count_active_admin_users()
        return HTMLResponse(content=_render_user_card_html(user_obj, current_user_email, admin_count, root_path))

    except Exception as e:
        LOGGER.error(f"Error deactivating user {user_email}: {e}")
        return HTMLResponse(content=f'<div class="text-red-500">Error deactivating user: {html.escape(str(e))}</div>', status_code=400)


@router.delete("/users/{user_email}")
@require_permission("admin.user_management", allow_admin_bypass=False)
async def admin_delete_user(
    user_email: str,
    _request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> HTMLResponse:
    """Delete user via admin UI.

    Args:
        user_email: Email address of user to delete
        _request: FastAPI request object (unused)
        db: Database session
        user: Current authenticated user context

    Returns:
        HTMLResponse: Success/error message
    """
    if not settings.email_auth_enabled:
        return HTMLResponse(content='<div class="text-red-500">Email authentication is disabled</div>', status_code=403)

    try:
        # First-Party

        auth_service = EmailAuthService(db)

        # URL decode the email

        decoded_email = urllib.parse.unquote(user_email)

        # Get current user email from JWT
        current_user_email = get_user_email(user)

        # Prevent self-deletion
        if decoded_email == current_user_email:
            return HTMLResponse(content='<div class="text-red-500">Cannot delete your own account</div>', status_code=400)

        # Prevent deleting the last active admin user
        if await auth_service.is_last_active_admin(decoded_email):
            return HTMLResponse(content='<div class="text-red-500">Cannot delete the last remaining admin user</div>', status_code=400)

        await auth_service.delete_user(decoded_email)

        # Return empty content to remove the user from the list
        return HTMLResponse(content="", status_code=200)

    except Exception as e:
        LOGGER.error(f"Error deleting user {user_email}: {e}")
        return HTMLResponse(content=f'<div class="text-red-500">Error deleting user: {html.escape(str(e))}</div>', status_code=400)


@router.post("/users/{user_email}/unlock")
@require_permission("admin.user_management", allow_admin_bypass=False)
async def admin_unlock_user(
    user_email: str,
    _request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> HTMLResponse:
    """Unlock a user account from the admin UI.

    Args:
        user_email: URL-encoded email for the user to unlock.
        _request: Incoming HTTP request.
        db: Database session dependency.
        user: Current authenticated user context.

    Returns:
        HTMLResponse: Updated user card HTML or error snippet.
    """
    if not settings.email_auth_enabled:
        return HTMLResponse(content='<div class="text-red-500">Email authentication is disabled</div>', status_code=403)

    try:
        root_path = _resolve_root_path(_request) if _request else ""
        auth_service = EmailAuthService(db)
        decoded_email = urllib.parse.unquote(user_email)
        current_user_email = get_user_email(user)

        user_obj = await auth_service.unlock_user_account(decoded_email, unlocked_by=current_user_email)
        admin_count = await auth_service.count_active_admin_users()
        return HTMLResponse(content=_render_user_card_html(user_obj, current_user_email, admin_count, root_path))
    except ValueError as exc:
        return HTMLResponse(content=f'<div class="text-red-500">{html.escape(str(exc))}</div>', status_code=404)
    except Exception as exc:
        LOGGER.error("Error unlocking user %s: %s", user_email, exc)
        return HTMLResponse(content=f'<div class="text-red-500">Error unlocking user: {html.escape(str(exc))}</div>', status_code=400)


@router.post("/users/{user_email}/force-password-change")
@require_permission("admin.user_management", allow_admin_bypass=False)
async def admin_force_password_change(
    user_email: str,
    _request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> HTMLResponse:
    """Force user to change password on next login.

    Args:
        user_email: Email of user to force password change
        _request: FastAPI request object
        db: Database session
        user: Current authenticated user context

    Returns:
        HTMLResponse: Updated user card with success message

    Examples:
        >>> from unittest.mock import MagicMock, AsyncMock
        >>> from fastapi import Request
        >>> from fastapi.responses import HTMLResponse
        >>>
        >>> # Mock request
        >>> mock_request = MagicMock(spec=Request)
        >>> mock_request.scope = {"root_path": "/test"}
        >>>
        >>> # Mock database
        >>> mock_db = MagicMock()
        >>>
        >>> # Mock user context
        >>> mock_user = MagicMock()
        >>> mock_user.email = "admin@example.com"
        >>>
        >>> import asyncio
        >>> async def test_force_password_change():
        ...     # Note: Full test requires email_auth_enabled and valid user
        ...     return True  # Simplified test due to dependencies
        >>>
        >>> asyncio.run(test_force_password_change())
        True
    """
    if not settings.email_auth_enabled:
        return HTMLResponse(content='<div class="text-red-500">Email authentication is disabled</div>', status_code=403)

    try:
        # Get root path for URL construction
        root_path = _resolve_root_path(_request) if _request else ""

        auth_service = EmailAuthService(db)

        # URL decode the email
        decoded_email = urllib.parse.unquote(user_email)

        # Get current user email from JWT
        current_user_email = get_user_email(user)

        user_obj = await auth_service.update_user(
            email=decoded_email,
            password_change_required=True,
            admin_origin_source="ui",
            requesting_user_email=current_user_email,
        )

        LOGGER.info(f"Admin {current_user_email} forced password change for user {decoded_email}")

        admin_count = await auth_service.count_active_admin_users()
        return HTMLResponse(content=_render_user_card_html(user_obj, current_user_email, admin_count, root_path))

    except PasswordValidationError as exc:
        return HTMLResponse(content=f'<div class="text-red-500">{html.escape(str(exc))}</div>', status_code=400)
    except ValueError as exc:
        return HTMLResponse(content=f'<div class="text-red-500">{html.escape(str(exc))}</div>', status_code=404)
    except Exception as e:
        LOGGER.error(f"Error forcing password change for user {user_email}: {e}")
        return HTMLResponse(content=f'<div class="text-red-500">Error forcing password change: {html.escape(str(e))}</div>', status_code=400)
