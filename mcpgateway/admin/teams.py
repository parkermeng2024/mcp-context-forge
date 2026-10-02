# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/admin/teams.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Admin UI team routes: team list, search, ids, detail, create, update, delete,
membership management, and self-service actions.
"""

# Standard
import html
import logging
import math
import re
from typing import Optional, Union
import urllib.parse

# Third-Party
from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
import orjson
from pydantic import ValidationError
from pydantic_core import ValidationError as CoreValidationError
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

# First-Party
from mcpgateway.admin.common import _get_user_team_ids, _normalize_search_query
from mcpgateway.admin.security import enforce_admin_csrf
from mcpgateway.auth_context import extract_token_team_ids, get_user_email
from mcpgateway.common.query_params import QueryRelationship, QueryRenderModeControls, QueryVisibility, QueryVisibilityCompact
from mcpgateway.common.validators import SecurityValidator
from mcpgateway.config import settings
from mcpgateway.db import get_db
from mcpgateway.middleware.rbac import get_current_user_with_permissions, require_permission
from mcpgateway.schemas import PaginationMeta
from mcpgateway.services.email_auth_service import EmailAuthService
from mcpgateway.services.team_management_service import TeamManagementService, UNSET
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
#                            TEAM ADMIN ROUTES                                #
# ============================================================================ #


async def _generate_unified_teams_view(team_service, current_user, root_path, scoped_team_ids: Optional[list[str]] = None):  # pylint: disable=unused-argument
    """Generate unified team view with relationship badges.

    Args:
        team_service: Service for team operations
        current_user: Current authenticated user
        root_path: Application root path
        scoped_team_ids: Explicit token team scope to apply to the generated list

    Returns:
        HTML string containing the unified teams view
    """
    # Get user's teams (owned + member)
    user_teams = await team_service.get_user_teams(current_user.email)

    # Get public teams user can join
    public_teams = await team_service.discover_public_teams(current_user.email)

    if scoped_team_ids is not None:
        allowed_team_ids = set(scoped_team_ids)
        user_teams = [team for team in user_teams if str(team.id) in allowed_team_ids]
        public_teams = [team for team in public_teams if str(team.id) in allowed_team_ids]

    # Batch fetch ALL data upfront - 3 queries instead of 3N queries (N+1 elimination)
    user_team_ids = [str(t.id) for t in user_teams]
    public_team_ids = [str(t.id) for t in public_teams]
    all_team_ids = user_team_ids + public_team_ids

    member_counts = await team_service.get_member_counts_batch_cached(all_team_ids)
    user_roles = team_service.get_user_roles_batch(current_user.email, user_team_ids)
    pending_requests = team_service.get_pending_join_requests_batch(current_user.email, public_team_ids)

    # Combine teams with relationship information
    all_teams = []

    # Add user's teams (owned and member)
    for team in user_teams:
        team_id = str(team.id)
        user_role = user_roles.get(team_id)
        relationship = "owner" if user_role == "owner" else "member"
        all_teams.append({"team": team, "relationship": relationship, "member_count": member_counts.get(team_id, 0)})

    # Add public teams user can join
    for team in public_teams:
        team_id = str(team.id)
        pending_request = pending_requests.get(team_id)
        relationship_data = {"team": team, "relationship": "join", "member_count": member_counts.get(team_id, 0), "pending_request": pending_request}
        all_teams.append(relationship_data)

    # Generate HTML for unified team view
    teams_html = ""
    for item in all_teams:
        team = item["team"]
        relationship = item["relationship"]
        member_count = item["member_count"]
        pending_request = item.get("pending_request")

        # Relationship badge - special handling for personal teams
        if team.is_personal:
            badge_html = '<span class="relationship-badge inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-300">PERSONAL</span>'
        elif relationship == "owner":
            badge_html = (
                '<span class="relationship-badge inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300">OWNER</span>'
            )
        elif relationship == "member":
            badge_html = (
                '<span class="relationship-badge inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300">MEMBER</span>'
            )
        else:  # join
            badge_html = '<span class="relationship-badge inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-300">CAN JOIN</span>'

        # Visibility badge
        visibility_badge = (
            f'<span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-300">{team.visibility.upper()}</span>'
        )

        # Subtitle based on relationship - special handling for personal teams
        if team.is_personal:
            subtitle = "Your personal team • Private workspace"
        elif relationship == "owner":
            subtitle = "You own this team"
        elif relationship == "member":
            subtitle = f"You are a member • Owner: {team.created_by}"
        else:  # join
            subtitle = f"Public team • Owner: {team.created_by}"

        # Escape team name for safe HTML attributes
        safe_team_name = html.escape(team.name)

        # Actions based on relationship - special handling for personal teams
        actions_html = ""
        if team.is_personal:
            # Personal teams have no management actions - they're private workspaces
            actions_html = """
            <div class="flex flex-wrap gap-2 mt-3">
                <span class="px-3 py-1 text-sm font-medium text-gray-500 dark:text-gray-400 bg-gray-100 dark:bg-gray-700 rounded-md">
                    Personal workspace - no actions available
                </span>
            </div>
            """
        elif relationship == "owner":
            delete_button = f'<button data-team-id="{team.id}" data-team-name="{safe_team_name}" onclick="deleteTeamSafe(this)" class="px-3 py-1 text-sm font-medium text-red-600 dark:text-red-400 hover:text-red-800 dark:hover:text-red-300 border border-red-300 dark:border-red-600 hover:border-red-500 dark:hover:border-red-400 rounded-md focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500">Delete Team</button>'
            join_requests_button = (
                f'<button data-team-id="{team.id}" onclick="viewJoinRequestsSafe(this)" class="px-3 py-1 text-sm font-medium text-purple-600 dark:text-purple-400 hover:text-purple-800 dark:hover:text-purple-300 border border-purple-300 dark:border-purple-600 hover:border-purple-500 dark:hover:border-purple-400 rounded-md focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-purple-500">Join Requests</button>'
                if team.visibility == "public"
                else ""
            )
            actions_html = f"""
            <div class="flex flex-wrap gap-2 mt-3">
                <button data-team-id="{team.id}" onclick="manageTeamMembersSafe(this)" class="px-3 py-1 text-sm font-medium text-blue-600 dark:text-blue-400 hover:text-blue-800 dark:hover:text-blue-300 border border-blue-300 dark:border-blue-600 hover:border-blue-500 dark:hover:border-blue-400 rounded-md focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500">
                    Manage Members
                </button>
                <button data-team-id="{team.id}" onclick="editTeamSafe(this)" class="px-3 py-1 text-sm font-medium text-green-600 dark:text-green-400 hover:text-green-800 dark:hover:text-green-300 border border-green-300 dark:border-green-600 hover:border-green-500 dark:hover:border-green-400 rounded-md focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500">
                    Edit Settings
                </button>
                {join_requests_button}
                {delete_button}
            </div>
            """
        elif relationship == "member":
            leave_button = f'<button data-team-id="{team.id}" data-team-name="{safe_team_name}" onclick="leaveTeamSafe(this)" class="px-3 py-1 text-sm font-medium text-orange-600 dark:text-orange-400 hover:text-orange-800 dark:hover:text-orange-300 border border-orange-300 dark:border-orange-600 hover:border-orange-500 dark:hover:border-orange-400 rounded-md focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-orange-500">Leave Team</button>'
            actions_html = f"""
            <div class="flex flex-wrap gap-2 mt-3">
                {leave_button}
            </div>
            """
        else:  # join
            if pending_request:
                # Show "Requested to Join [Cancel Request]" state
                actions_html = f"""
                <div class="flex flex-wrap gap-2 mt-3">
                    <span class="px-3 py-1 text-sm font-medium text-yellow-600 dark:text-yellow-400 bg-yellow-100 dark:bg-yellow-900 rounded-md border border-yellow-300 dark:border-yellow-600">
                        ⏳ Requested to Join
                    </span>
                    <button onclick="cancelJoinRequest('{team.id}', '{pending_request.id}')" class="px-3 py-1 text-sm font-medium text-red-600 dark:text-red-400 hover:text-red-800 dark:hover:text-red-300 border border-red-300 dark:border-red-600 hover:border-red-500 dark:hover:border-red-400 rounded-md focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500">
                        Cancel Request
                    </button>
                </div>
                """
            else:
                # Show "Request to Join" button (disabled if feature is disabled)
                allow_join_requests = getattr(settings, "allow_team_join_requests", True)
                if allow_join_requests:
                    actions_html = f"""
                <div class="flex flex-wrap gap-2 mt-3">
                    <button data-team-id="{team.id}" data-team-name="{safe_team_name}" onclick="requestToJoinTeamSafe(this)" class="px-3 py-1 text-sm font-medium text-indigo-600 dark:text-indigo-400 hover:text-indigo-800 dark:hover:text-indigo-300 border border-indigo-300 dark:border-indigo-600 hover:border-indigo-500 dark:hover:border-indigo-400 rounded-md focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500">
                        Request to Join
                    </button>
                </div>
                """
                else:
                    actions_html = """
                <div class="flex flex-wrap gap-2 mt-3">
                    <button disabled class="px-3 py-1 text-sm font-medium text-gray-400 dark:text-gray-600 border border-gray-300 dark:border-gray-600 rounded-md cursor-not-allowed opacity-50" title="Team join requests are currently disabled">
                        Request to Join
                    </button>
                </div>
                """

        # Truncated description (properly escaped)
        description_text = ""
        if team.description:
            safe_description = html.escape(team.description)
            truncated = safe_description[:80] + "..." if len(safe_description) > 80 else safe_description
            description_text = f'<p class="team-description text-sm text-gray-600 dark:text-gray-400 mt-1">{truncated}</p>'

        teams_html += f"""
        <div class="team-card bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-600 rounded-lg p-4 shadow-sm hover:shadow-md transition-shadow" data-relationship="{relationship}">
            <div class="flex justify-between items-start mb-3">
                <div class="flex-1">
                    <div class="flex items-center gap-3 mb-2">
                        <h4 class="team-name text-lg font-medium text-gray-900 dark:text-white">🏢 {safe_team_name}</h4>
                        {badge_html}
                        {visibility_badge}
                        <span class="text-sm text-gray-500 dark:text-gray-400">{member_count} members</span>
                    </div>
                    <p class="text-sm text-gray-600 dark:text-gray-400">{subtitle}</p>
                    {description_text}
                </div>
            </div>
            {actions_html}
        </div>
        """

    if not teams_html:
        teams_html = '<div class="text-center py-12"><p class="text-gray-500 dark:text-gray-400">No teams found. Create your first team using the button above.</p></div>'

    return HTMLResponse(content=teams_html)


@router.get("/teams/ids", response_class=JSONResponse)
@require_permission("teams.read", allow_admin_bypass=False)
async def admin_get_all_team_ids(
    include_inactive: bool = False,
    visibility: QueryVisibilityCompact = None,
    q: Optional[str] = Query(None, max_length=500, description="Search query"),
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    """Return all team IDs accessible to the current user.

    Args:
        include_inactive (bool): Whether to include inactive teams.
        visibility (Optional[str]): Filter by team visibility.
        q (Optional[str]): Search query string.
        db (Session): Database session dependency.
        user: Current authenticated user.

    Returns:
        JSONResponse: Dictionary with list of team IDs and count.
    """
    team_service = TeamManagementService(db)
    user_email = get_user_email(user)

    auth_service = EmailAuthService(db)
    current_user = await auth_service.get_user_by_email(user_email)

    if not current_user:
        return {"team_ids": [], "count": 0}

    # If admin, get all teams (filtered)
    # If regular user, get user teams + accessible public teams?
    # For now, admin only per usage pattern?
    # But tools/ids handles team_id scoping. Here we filter by teams user can see.
    # get_all_team_ids supports search/visibility.

    # Check admin
    if current_user.is_admin:
        # Admin sees all non-personal teams plus their own personal team (single query)
        team_ids = await team_service.get_all_team_ids(include_inactive=include_inactive, visibility_filter=visibility, include_personal=False, search_query=q, personal_owner_email=user_email)
    else:
        # For non-admins, get user's teams + public teams logic?
        # get_user_teams gets all teams user is in.
        # discover_public_teams gets public teams.
        # unified search across them?
        # Simpler: just reuse list_teams logic but with huge limit?
        # Or, just return user's teams IDs filtering in memory (since user won't have millions of teams)
        all_teams = await team_service.get_user_teams(user_email, include_personal=True)
        # Apply filters
        # Note: get_user_teams includes visibility/inactive implicitly? No, it returns what they are member of.
        # But we might need public teams too?
        # Let's align with list_teams logic.

        filtered = []
        for t in all_teams:
            if not include_inactive and not t.is_active:
                continue
            if visibility and t.visibility != visibility:
                continue
            if q:
                if q.lower() not in t.name.lower() and q.lower() not in t.slug.lower():
                    continue
            filtered.append(t.id)
        team_ids = filtered

    return {"team_ids": team_ids, "count": len(team_ids)}


@router.get("/teams/search", response_class=JSONResponse)
@require_permission("teams.read", allow_admin_bypass=False)
async def admin_search_teams(
    q: str = Query("", max_length=500, description="Search query"),
    include_inactive: bool = False,
    limit: int = Query(settings.pagination_default_page_size, ge=1, le=settings.pagination_max_page_size, description="Max results"),
    visibility: QueryVisibility = None,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    """Search teams by name/slug/description.

    Args:
        q (str): Search query string.
        include_inactive (bool): Whether to include inactive teams.
        limit (int): Maximum number of results to return.
        visibility (Optional[str]): Filter by team visibility.
        db (Session): Database session dependency.
        user: Current authenticated user.

    Returns:
        JSONResponse: List of matching teams with basic info.
    """
    search_query = _normalize_search_query(q)
    team_service = TeamManagementService(db)
    user_email = get_user_email(user)

    auth_service = EmailAuthService(db)
    current_user = await auth_service.get_user_by_email(user_email)

    if not current_user:
        return []

    # Use list_teams logic
    # For admin: search globally
    # For user: search user teams (and maybe public?)
    # existing list_teams handles this via include_personal/logic?
    # list_teams handles admin vs user distinction?
    # Wait, list_teams in service doesn't know about user per se. It lists ALL teams based on query.
    # The CALLER (admin.py) distinguishes.

    if current_user.is_admin:
        # Honor explicit token narrowing even for admins (Layer 1 constrains
        # visibility independently of RBAC/admin status). token_teams is None for
        # full admin bypass (unrestricted); an explicit list (including []) scopes
        # the result. The scope is pushed into the query so it applies before
        # pagination (an allowed team must not be dropped for sorting past the
        # first page) and so an explicit scope no longer surfaces the personal team.
        admin_scoped_team_ids = extract_token_team_ids(user)
        result = await team_service.list_teams(
            page=1,
            per_page=limit,
            include_inactive=include_inactive,
            visibility_filter=visibility,
            include_personal=False,
            search_query=search_query,
            personal_owner_email=user_email,
            team_ids=admin_scoped_team_ids,
        )
        # Result is dict {data, pagination...} (since page provided)
        teams = result["data"]
    else:
        # Non-admin search
        # Reuse user team fetching
        all_teams = await team_service.get_user_teams(user_email, include_personal=True)
        # Narrow to the caller's normalized token scope (Layer 1). get_user_teams
        # returns every membership and ignores token scope, so a token narrowed to
        # a team subset would otherwise leak sibling teams the caller belongs to but
        # is scoped out of. _get_user_team_ids honors token_teams/_cached_team_ids;
        # an unscoped caller's own memberships (including their personal team) are in
        # this set, while an explicit scope (including [] = public-only) does not add
        # a personal-team fallback, matching normalize_token_teams()/get_team_from_token().
        scoped_team_ids = set(await _get_user_team_ids(user, db))
        # Filter in memory
        filtered = []
        for t in all_teams:
            if t.id not in scoped_team_ids:
                continue
            if not include_inactive and not t.is_active:
                continue
            if visibility and t.visibility != visibility:
                continue
            if search_query:
                description_text = (t.description or "").lower()
                if search_query not in t.name.lower() and search_query not in t.slug.lower() and search_query not in description_text:
                    continue
            filtered.append(t)

        # Paginate manually
        teams = filtered[:limit]

    serialized_teams = [{"id": t.id, "name": t.name, "slug": t.slug, "description": t.description, "visibility": t.visibility, "is_active": t.is_active} for t in teams]
    return serialized_teams


@router.get("/teams/partial")
@require_permission("teams.read", allow_admin_bypass=False)
async def admin_teams_partial_html(
    request: Request,
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(settings.pagination_default_page_size, ge=1, le=settings.pagination_max_page_size, description="Items per page"),
    include_inactive: bool = Query(False, description="Include inactive teams"),
    visibility: QueryVisibilityCompact = None,
    render: QueryRenderModeControls = None,
    q: Optional[str] = Query(None, max_length=500, description="Search query"),
    relationship: QueryRelationship = None,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> HTMLResponse:
    """Return HTML partial for paginated teams list (HTMX).

    Args:
        request (Request): FastAPI request object.
        page (int): Page number for pagination.
        per_page (int): Number of items per page.
        include_inactive (bool): Whether to include inactive teams.
        visibility (Optional[str]): Filter by team visibility.
        render (Optional[str]): Render mode, e.g., 'controls' for pagination controls only.
        q (Optional[str]): Search query string.
        relationship (Optional[str]): Filter by relationship: owner, member, public.
        db (Session): Database session dependency.
        user: Current authenticated user.

    Returns:
        HTMLResponse: Rendered HTML partial for teams list or pagination controls.

    """
    team_service = TeamManagementService(db)
    user_email = get_user_email(user)
    root_path = _resolve_root_path(request)

    # Base URL for pagination links - preserve search query and relationship filter
    base_url = f"{root_path}/admin/teams/partial"
    query_parts = []
    if q:
        query_parts.append(f"q={urllib.parse.quote(q, safe='')}")
    if relationship:
        query_parts.append(f"relationship={urllib.parse.quote(relationship, safe='')}")
    if query_parts:
        base_url += "?" + "&".join(query_parts)

    # Check permissions and get current user
    auth_service = EmailAuthService(db)
    current_user = await auth_service.get_user_by_email(user_email)

    if not current_user:
        return HTMLResponse(content='<div class="text-center py-8"><p class="text-red-500">User not found</p></div>', status_code=404)

    scoped_team_ids = extract_token_team_ids(user)

    # Get user's teams and public teams for relationship info
    user_teams = await team_service.get_user_teams(user_email, include_personal=True)
    user_team_ids = {str(t.id) for t in user_teams}

    # Get user roles for owned/member distinction
    user_roles = team_service.get_user_roles_batch(user_email, list(user_team_ids))

    # Get public teams the user can join (not already a member)
    # NOTE: Limited to 500 for memory safety. Non-admin users with "public" filter
    # will only see up to 500 joinable teams. For deployments with >500 public teams,
    # consider implementing SQL-level pagination for non-admin users.
    public_teams_limit = 500
    public_teams = await team_service.discover_public_teams(user_email, limit=public_teams_limit)
    if len(public_teams) >= public_teams_limit:
        LOGGER.warning(f"Public teams discovery hit limit of {public_teams_limit} for user {user_email}. Some teams may not be visible.")

    if current_user.is_admin and not relationship:
        # Admin sees all non-personal teams plus their own personal team (single query, correct pagination)
        paginated_result = await team_service.list_teams(
            page=page,
            per_page=per_page,
            include_inactive=include_inactive,
            visibility_filter=visibility,
            base_url=base_url,
            include_personal=False,
            search_query=q,
            personal_owner_email=user_email,
            team_ids=scoped_team_ids,
        )
        data = paginated_result["data"]
        pagination = paginated_result["pagination"]
        links = paginated_result["links"]
    else:
        # Filter by relationship or regular user view
        all_teams = []

        if relationship == "owner":
            # Only teams user owns
            all_teams = [t for t in user_teams if user_roles.get(str(t.id)) == "owner"]
        elif relationship == "member":
            # Only teams user is a member of (not owner)
            all_teams = [t for t in user_teams if user_roles.get(str(t.id)) == "member"]
        elif relationship == "public":
            # Only public teams user can join
            all_teams = list(public_teams)
        else:
            # All teams: user's teams + public teams they can join
            all_teams = list(user_teams) + list(public_teams)

        if scoped_team_ids is not None:
            allowed_team_ids = set(scoped_team_ids)
            all_teams = [t for t in all_teams if str(t.id) in allowed_team_ids]

        # Apply search filter
        if q:
            q_lower = q.lower()
            all_teams = [t for t in all_teams if q_lower in t.name.lower() or q_lower in (t.slug or "").lower() or q_lower in (t.description or "").lower()]

        # Apply visibility filter
        if visibility:
            all_teams = [t for t in all_teams if t.visibility == visibility]

        if not include_inactive:
            all_teams = [t for t in all_teams if t.is_active]

        total = len(all_teams)
        total_pages = math.ceil(total / per_page) if per_page else 1
        # Clamp page to valid range (matches offset_paginate behavior)
        if total_pages > 0:
            page = min(page, total_pages)
        start = (page - 1) * per_page
        end = start + per_page
        data = all_teams[start:end]

        pagination = PaginationMeta(page=page, per_page=per_page, total_items=total, total_pages=total_pages, has_next=end < total, has_prev=page > 1)
        links = None

    if render == "controls":
        # Return only pagination controls
        return request.app.state.templates.TemplateResponse(
            request,
            "pagination_controls.html",
            {
                "request": request,
                "pagination": pagination if isinstance(pagination, dict) else pagination.model_dump(),
                "links": links.model_dump() if links and not isinstance(links, dict) else links,
                "root_path": root_path,
                "hx_target": "#unified-teams-list",
                "hx_indicator": "#teams-loading",
                "query_params": {"include_inactive": include_inactive, "visibility": visibility, "q": q, "relationship": relationship},
                "base_url": base_url,
            },
        )

    if render == "selector":
        # Return team selector items for infinite scroll dropdown
        # Add member counts for display
        team_ids = [str(t.id) for t in data]
        counts = await team_service.get_member_counts_batch_cached(team_ids)
        for t in data:
            t.member_count = counts.get(str(t.id), 0)

        query_params_dict = {}
        if q:
            query_params_dict["q"] = q

        return request.app.state.templates.TemplateResponse(
            request,
            "teams_selector_items.html",
            {
                "request": request,
                "data": data,
                "pagination": pagination if isinstance(pagination, dict) else pagination.model_dump(),
                "root_path": root_path,
                "query_params": query_params_dict,
            },
        )

    # Batch count members
    team_ids = [str(t.id) for t in data]
    counts = await team_service.get_member_counts_batch_cached(team_ids)

    # Build enriched data with relationship info
    enriched_data = []
    for t in data:
        team_id = str(t.id)
        t.member_count = counts.get(team_id, 0)

        # Determine relationship
        t.relationship = "none"
        t.pending_request = None
        if t.is_personal:
            t.relationship = "personal"
        elif team_id in user_team_ids:
            role = user_roles.get(team_id)
            t.relationship = "owner" if role == "owner" else "member"
        elif getattr(t, "created_by", None) == user_email:
            # Safety net: creator should always see owner controls even if
            # membership cache lags behind team creation (Issue #3883)
            t.relationship = "owner"
        elif t.visibility == "public" and t.is_active:
            # Public teams show join button for ALL non-members (including admins)
            # This ensures platform admins go through the normal join request workflow
            # for public teams, respecting team ownership boundaries. Issue #3488
            t.relationship = "public"
        elif current_user.is_admin:
            # Admins get admin controls ONLY for non-public teams they're not members of
            # This allows emergency access to private teams for platform maintenance
            t.relationship = "none"  # Falls through to admin controls in template

        enriched_data.append(t)

    # Get pending join requests for all public teams on current page
    public_team_ids_on_page = [str(t.id) for t in enriched_data if t.relationship == "public"]
    pending_requests = team_service.get_pending_join_requests_batch(user_email, public_team_ids_on_page)
    for t in enriched_data:
        if t.relationship == "public":
            t.pending_request = pending_requests.get(str(t.id))

    # Build query params dict for pagination controls
    query_params_dict = {}
    if q:
        query_params_dict["q"] = q
    if relationship:
        query_params_dict["relationship"] = relationship
    if include_inactive:
        query_params_dict["include_inactive"] = "true"
    if visibility:
        query_params_dict["visibility"] = visibility

    response = request.app.state.templates.TemplateResponse(
        request,
        "teams_partial.html",
        {
            "request": request,
            "data": enriched_data,
            "pagination": pagination if isinstance(pagination, dict) else pagination.model_dump(),
            "links": links.model_dump() if links and not isinstance(links, dict) else links,
            "root_path": root_path,
            "query_params": query_params_dict,
        },
    )
    # Prevent nginx caching for real-time team updates
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@router.get("/teams")
@require_permission("teams.read", allow_admin_bypass=False)
async def admin_list_teams(
    request: Request,
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(settings.pagination_default_page_size, ge=1, le=settings.pagination_max_page_size, description="Items per page"),
    q: Optional[str] = Query(None, max_length=500, description="Search query"),
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
    unified: bool = False,
) -> HTMLResponse:
    """List teams for admin UI via HTMX.

    Args:
        request: FastAPI request object
        page: Page number
        per_page: Items per page
        q: Search query
        db: Database session
        user: Authenticated admin user
        unified: If True, return unified team view with relationship badges

    Returns:
        HTML response with teams list

    Raises:
        HTTPException: If email auth is disabled or user not found
    """
    if not getattr(settings, "email_auth_enabled", False):
        return HTMLResponse(content='<div class="text-center py-8"><p class="text-gray-500">Email authentication is disabled. Teams feature requires email auth.</p></div>', status_code=200)

    try:
        auth_service = EmailAuthService(db)
        team_service = TeamManagementService(db)

        # Get current user
        user_email = get_user_email(user)
        current_user = await auth_service.get_user_by_email(user_email)
        if not current_user:
            return HTMLResponse(content='<div class="text-center py-8"><p class="text-red-500">User not found</p></div>', status_code=200)

        root_path = _resolve_root_path(request)
        scoped_team_ids = extract_token_team_ids(user)

        if unified:
            # Generate unified team view
            return await _generate_unified_teams_view(team_service, current_user, root_path, scoped_team_ids=scoped_team_ids)

        # Traditional admin view refactored to use partial logic
        # We can reuse the logic by calling the service directly or redirecting?
        # Redirection requires a round trip. Calling logic allows server-side render.
        # We'll re-use the logic by calling default params.

        # Call list_teams logic (similar to admin_teams_partial_html but inline)
        if current_user.is_admin:
            # Default first page
            base_url = f"{root_path}/admin/teams/partial"
            if q:
                base_url += f"?q={urllib.parse.quote(q, safe='')}"

            # Admin sees all non-personal teams plus their own personal team (single query, correct pagination)
            paginated_result = await team_service.list_teams(
                page=page,
                per_page=per_page,
                base_url=base_url,
                include_personal=False,
                search_query=q,
                personal_owner_email=user_email,
                team_ids=scoped_team_ids,
            )
            data = paginated_result["data"]
            pagination = paginated_result["pagination"]
            links = paginated_result["links"]
        else:
            all_teams = await team_service.get_user_teams(current_user.email, include_personal=True)
            if scoped_team_ids is not None:
                allowed_team_ids = set(scoped_team_ids)
                all_teams = [team for team in all_teams if str(team.id) in allowed_team_ids]
            # Basic pagination for user view
            total = len(all_teams)
            start = (page - 1) * per_page
            end = start + per_page
            data = all_teams[start:end]
            pagination = PaginationMeta(page=page, per_page=per_page, total_items=total, total_pages=math.ceil(total / per_page) if per_page else 1, has_next=end < total, has_prev=page > 1)
            links = None

        # Batch counts
        team_ids = [str(t.id) for t in data]
        counts = await team_service.get_member_counts_batch_cached(team_ids)
        for t in data:
            t.member_count = counts.get(str(t.id), 0)

        # Render template
        return request.app.state.templates.TemplateResponse(
            request,
            "teams_partial.html",
            {
                "request": request,
                "data": data,
                "pagination": pagination if isinstance(pagination, dict) else pagination.model_dump(),
                "links": links.model_dump() if links and not isinstance(links, dict) else links,
                "root_path": root_path,
            },
        )

    except Exception as e:
        LOGGER.error(f"Error listing teams for admin {user}: {e}")
        return HTMLResponse(content=f'<div class="text-center py-8"><p class="text-red-500">Error loading teams: {html.escape(str(e))}</p></div>', status_code=200)


def _parse_form_max_members(raw: object) -> Optional[int]:
    """Parse and validate a max_members value from a form field.

    Args:
        raw: The raw form value (typically a string or None).

    Returns:
        The parsed integer, or ``None`` when the field is blank or non-numeric.

    Raises:
        ValueError: When the parsed integer is less than 1.
    """
    if raw and str(raw).strip().isdigit():
        parsed = int(str(raw).strip())
        if parsed < 1:
            raise ValueError("Maximum members must be at least 1")
        return parsed
    return None


@router.post("/teams")
@require_permission("teams.create", allow_admin_bypass=False)
async def admin_create_team(
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> HTMLResponse:
    """Create team via admin UI form submission.

    Args:
        request: FastAPI request object
        db: Database session
        user: Authenticated admin user

    Returns:
        HTML response with new team or error message

    Raises:
        HTTPException: If email auth is disabled or validation fails
    """
    if not getattr(settings, "email_auth_enabled", False):
        error_content = '<div class="text-red-500 p-3 bg-red-50 dark:bg-red-900/20 rounded-md">Email authentication is disabled</div>'
        response = HTMLResponse(content=error_content, status_code=403)
        return response

    if not getattr(settings, "allow_team_creation", True) and not (isinstance(user, dict) and user.get("is_admin")):
        return HTMLResponse(content='<div class="text-red-500 p-3 bg-red-50 dark:bg-red-900/20 rounded-md">Team creation is currently disabled</div>', status_code=403)

    try:
        form = await request.form()
        name = form.get("name")
        slug = form.get("slug") or None
        description = form.get("description") or None
        visibility = form.get("visibility", "private")
        max_members = _parse_form_max_members(form.get("max_members"))

        if not name:
            response = HTMLResponse(
                content='<div class="text-red-500 p-3 bg-red-50 dark:bg-red-900/20 rounded-md">Team name is required</div>',
                status_code=400,
            )
            return response

        # Create team
        # First-Party
        from mcpgateway.schemas import TeamCreateRequest  # pylint: disable=import-outside-toplevel

        team_service = TeamManagementService(db)

        team_data = TeamCreateRequest(name=name, slug=slug, description=description, visibility=visibility, max_members=max_members)

        # Extract user email from user dict
        user_email = get_user_email(user)

        is_admin = isinstance(user, dict) and user.get("is_admin")
        await team_service.create_team(
            name=team_data.name, description=team_data.description, created_by=user_email, visibility=team_data.visibility, max_members=team_data.max_members, skip_limits=bool(is_admin)
        )

        response = HTMLResponse(content="", status_code=201)
        return response

    except (ValidationError, CoreValidationError) as e:
        LOGGER.warning(f"Validation error creating team: {e}")
        # Extract user-friendly error message from Pydantic validation error
        error_messages = []
        for error in e.errors():
            msg = error.get("msg", "Invalid value")
            # Clean up common Pydantic prefixes
            if msg.startswith("Value error, "):
                msg = msg[13:]
            error_messages.append(f"{msg}")
        error_text = "; ".join(error_messages) if error_messages else "Invalid input"
        response = HTMLResponse(
            content=f'<div class="text-red-500 p-3 bg-red-50 dark:bg-red-900/20 rounded-md">{html.escape(error_text)}</div>',
            status_code=400,
        )
        return response
    except ValueError as e:
        LOGGER.warning(f"Validation error creating team: {e}")
        return HTMLResponse(
            content=f'<div class="text-red-500 p-3 bg-red-50 dark:bg-red-900/20 rounded-md">{html.escape(str(e))}</div>',
            status_code=400,
        )
    except IntegrityError as e:
        LOGGER.error(f"Error creating team for admin {user}: {e}")
        if "UNIQUE constraint failed: email_teams.slug" in str(e):
            error_content = '<div class="text-red-500 p-3 bg-red-50 dark:bg-red-900/20 rounded-md">A team with this name already exists. Please choose a different name.</div>'
        else:
            error_content = f'<div class="text-red-500 p-3 bg-red-50 dark:bg-red-900/20 rounded-md">Database error: {html.escape(str(e))}</div>'
        response = HTMLResponse(content=error_content, status_code=400)
        return response
    except Exception as e:
        LOGGER.error(f"Error creating team for admin {user}: {e}")
        response = HTMLResponse(
            content=f'<div class="text-red-500 p-3 bg-red-50 dark:bg-red-900/20 rounded-md">Error creating team: {html.escape(str(e))}</div>',
            status_code=400,
        )
        return response


@router.get("/teams/{team_id}/members")
@require_permission("teams.read", allow_admin_bypass=False)
async def admin_view_team_members(
    team_id: str,
    request: Request,
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    per_page: int = Query(settings.pagination_default_page_size, ge=1, le=settings.pagination_max_page_size, description="Items per page"),
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> HTMLResponse:
    """View and manage team members via admin UI (unified view).

    This replaces the old separate "view members" and "add members" screens with a unified
    interface that shows all users with checkboxes. Members are pre-checked and can be
    unchecked to remove them. Non-members can be checked to add them.

    Args:
        team_id: ID of the team to view members for
        request: FastAPI request object
        page: Page number (1-indexed).
        per_page: Items per page.
        db: Database session
        user: Current authenticated user context

    Returns:
        HTMLResponse: Rendered unified team members management view
    """
    if not settings.email_auth_enabled:
        response = HTMLResponse(
            content='<div class="text-red-500 p-3 bg-red-50 dark:bg-red-900/20 rounded-md mb-4">Email authentication is disabled</div>',
            status_code=403,
        )
        response.headers["HX-Retarget"] = "#edit-team-error"
        response.headers["HX-Reswap"] = "innerHTML"
        return response

    try:
        # Get root_path from request
        root_path = _resolve_root_path(request)

        # Get current user context for logging and authorization
        user_email = get_user_email(user)
        LOGGER.info(f"User {user_email} viewing/managing members for team {team_id}")

        # First-Party
        team_service = TeamManagementService(db)
        EmailAuthService(db)

        # Get team details
        team = await team_service.get_team_by_id(team_id)
        if not team:
            return HTMLResponse(content='<div class="text-red-500">Team not found</div>', status_code=404)

        # Check if current user is team owner
        current_user_role = await team_service.get_user_role_in_team(user_email, team_id)
        is_team_owner = current_user_role == "owner"

        # Escape team name to prevent XSS
        safe_team_name = html.escape(team.name)

        # Build the two-section management interface with form
        interface_html = f"""
        <div class="mb-4">
            <div class="flex justify-between items-center mb-4">
                <h3 class="text-lg font-medium text-gray-900 dark:text-white">
                    Team Members: {safe_team_name}
                </h3>
                <button data-action-click="hideElement" data-arg0="team-edit-modal"
                        class="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300">
                    <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round"
                            stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                    </svg>
                </button>
            </div>

            <div class="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
                <div class="px-6 py-4 border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-900">
                    <h4 class="text-sm font-semibold text-gray-900 dark:text-white">
                        Manage Team Members • Change roles • Add or remove members
                    </h4>
                </div>

                <form id="team-members-form-{team.id}" data-team-id="{team.id}"
                      hx-post="{root_path}/admin/teams/{team.id}/add-member"
                      hx-target="#team-edit-modal-content"
                      hx-swap="innerHTML"
                      class="px-6 py-4">

                    <!-- Current Members Section -->
                    <div class="mb-6">
                        <div class="flex items-center justify-between mb-2">
                            <h5 class="text-sm font-medium text-gray-700 dark:text-gray-300">Current Members</h5>
                            <input
                                type="text"
                                id="member-search-{team.id}"
                                placeholder="Search members..."
                                class="w-48 px-2 py-1 text-sm border border-gray-300 dark:border-gray-600 rounded-md dark:bg-gray-700 dark:text-white"
                                oninput="Admin.debouncedMemberSearch('{team.id}', this.value)"
                            />
                        </div>
                        <div
                            id="team-members-container-{team.id}"
                            class="border border-gray-300 dark:border-gray-600 rounded-md p-3 max-h-64 overflow-y-auto dark:bg-gray-700"
                            data-per-page="{per_page}"
                            hx-get="{root_path}/admin/teams/{team.id}/members/partial?page={page}&per_page={per_page}"
                            hx-trigger="load delay:100ms"
                            hx-target="this"
                            hx-swap="innerHTML"
                        >
                            <!-- Current members will be loaded here via HTMX -->
                        </div>
                    </div>

                    <!-- Add Users Section -->
                    <div class="mb-4">
                        <div class="flex items-center justify-between mb-2">
                            <h5 class="text-sm font-medium text-gray-700 dark:text-gray-300">Add Users</h5>
                            <input
                                type="text"
                                id="non-member-search-{team.id}"
                                placeholder="Search users by name or email..."
                                class="w-64 px-2 py-1 text-sm border border-gray-300 dark:border-gray-600 rounded-md dark:bg-gray-700 dark:text-white"
                                oninput="Admin.debouncedNonMemberSearch('{team.id}', this.value)"
                            />
                        </div>
                        <div
                            id="team-non-members-container-{team.id}"
                            class="border border-gray-300 dark:border-gray-600 rounded-md p-3 max-h-64 overflow-y-auto dark:bg-gray-700"
                            data-per-page="50"
                        >
                            <div class="text-center py-4 text-gray-500 dark:text-gray-400">Search for users by name or email to add them to this team.</div>
                        </div>
                    </div>

                    <!-- Submit button (only for team owners) -->
                    {
            ""
            if not is_team_owner
            else '''
                    <div class="flex justify-end space-x-3 pt-4 border-t border-gray-200 dark:border-gray-700">
                        <button type="submit"
                                class="px-4 py-2 text-sm font-medium text-white bg-blue-600 border border-transparent rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500">
                            Save Changes
                        </button>
                    </div>
                    '''
        }
                </form>
            </div>
        </div>
        """  # nosec B608 - HTML template f-string, not SQL (uses SQLAlchemy ORM for DB)

        response = HTMLResponse(content=interface_html)
        # Prevent nginx caching for real-time team member updates
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response

    except Exception as e:
        LOGGER.error(f"Error viewing team members {team_id}: {e}")
        return HTMLResponse(content=f'<div class="text-red-500">Error loading members: {html.escape(str(e))}</div>', status_code=500)


@router.get("/teams/{team_id}/members/add")
@require_permission("teams.manage_members", allow_admin_bypass=False)
async def admin_add_team_members_view(
    team_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> HTMLResponse:
    """Show add members interface with paginated user selector.

    Args:
        team_id: ID of the team to add members to
        request: FastAPI request object
        db: Database session
        user: Current authenticated user context

    Returns:
        HTMLResponse: Rendered add members interface
    """
    if not settings.email_auth_enabled:
        return HTMLResponse(content='<div class="text-red-500">Email authentication is disabled</div>', status_code=403)

    try:
        # Get root_path from request
        root_path = _resolve_root_path(request)

        # Get current user context for logging and authorization
        user_email = get_user_email(user)
        LOGGER.info(f"User {user_email} adding members to team {team_id}")

        # First-Party
        team_service = TeamManagementService(db)

        # Get team details
        team = await team_service.get_team_by_id(team_id)
        if not team:
            return HTMLResponse(content='<div class="text-red-500">Team not found</div>', status_code=404)

        # Check if current user is team owner
        current_user_role = await team_service.get_user_role_in_team(user_email, team_id)
        if current_user_role != "owner":
            return HTMLResponse(content='<div class="text-red-500">Only team owners can add members</div>', status_code=403)

        # Get current team members to exclude from selection
        team_members = await team_service.get_team_members(team_id)
        member_emails = {team_user.email for team_user, membership in team_members}
        # Use orjson to safely serialize the list for JavaScript consumption (prevents XSS/injection)
        member_emails_json = orjson.dumps(list(member_emails)).decode()  # nosec B105 - JSON array of emails, not password

        # Escape team name to prevent XSS
        safe_team_name = html.escape(team.name)

        # Build add members interface with paginated user selector
        add_members_html = f"""
        <div class="mb-4">
            <div class="flex justify-between items-center mb-4">
                <h3 class="text-lg font-medium text-gray-900 dark:text-white">Add Members to: {safe_team_name}</h3>
                <div class="flex items-center space-x-2">
                    <button data-action-click="loadTeamMembersView" data-arg0="{team.id}" class="px-3 py-1 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-md hover:bg-gray-50 dark:hover:bg-gray-700">
                        ← Back to Members
                    </button>
                    <button data-action-click="hideElement" data-arg0="team-edit-modal" class="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300">
                        <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                        </svg>
                    </button>
                </div>
            </div>

            <div class="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
                <div class="px-6 py-4 border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-900">
                    <h4 class="text-sm font-semibold text-gray-900 dark:text-white">Select Users to Add</h4>
                </div>

                <div class="px-6 py-4">
                    <form id="add-members-form-{team.id}" data-team-id="{team.id}" hx-post="{root_path}/admin/teams/{team.id}/add-member" hx-target="#team-edit-modal-content" hx-swap="innerHTML">
                        <!-- Search box -->
                        <div class="mb-4">
                            <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Search Users</label>
                            <input
                                type="text"
                                id="user-search-{team.id}"
                                data-team-id="{team.id}"
                                data-search-url="{root_path}/admin/users/search"
                                data-search-limit="10"
                                placeholder="Search by name or email..."
                                class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 text-gray-900 dark:text-white"
                                autocomplete="off"
                            />
                            <div id="user-search-loading-{team.id}" class="mt-2 text-sm text-gray-500 dark:text-gray-400 hidden">Searching...</div>
                            <div id="user-search-results-{team.id}" data-member-emails="{html.escape(member_emails_json)}" class="mt-2"></div>
                        </div>

                        <!-- User selector with infinite scroll -->
                        <div class="mb-4">
                            <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Available Users</label>
                            <div
                                id="user-selector-container-{team.id}"
                                class="border border-gray-300 dark:border-gray-600 rounded-md p-3 max-h-64 overflow-y-auto dark:bg-gray-700"
                                hx-get="{root_path}/admin/users/partial?page=1&per_page=20&render=selector&team_id={team.id}"
                                hx-trigger="load"
                                hx-swap="innerHTML"
                                hx-target="#user-selector-container-{team.id}"
                            >
                                <!-- User selector items will be loaded here via HTMX -->
                            </div>
                            <p class="text-xs text-gray-500 dark:text-gray-400 mt-1">
                                Note: Users already in the team will be ignored if selected.
                            </p>
                        </div>

                        <!-- Action buttons -->
                        <div class="flex justify-between items-center">
                            <div id="selected-count-{team.id}" class="text-sm text-gray-600 dark:text-gray-400">
                                No users selected
                            </div>
                            <button
                                type="submit"
                                class="px-4 py-2 bg-blue-600 text-white text-sm font-medium rounded-md shadow-sm hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 transition-colors duration-200"
                            >
                                Add Selected Members
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
        """  # nosec B608 - HTML template f-string, not SQL (uses SQLAlchemy ORM for DB)

        return HTMLResponse(content=add_members_html)

    except Exception as e:
        LOGGER.error(f"Error loading add members view for team {team_id}: {e}")
        return HTMLResponse(content=f'<div class="text-red-500">Error loading add members view: {html.escape(str(e))}</div>', status_code=500)


@router.get("/teams/{team_id}/edit")
@require_permission("teams.update", allow_admin_bypass=False)
async def admin_get_team_edit(
    team_id: str,
    _request: Request,
    db: Session = Depends(get_db),
    _user=Depends(get_current_user_with_permissions),
) -> HTMLResponse:
    """Get team edit form via admin UI.

    Args:
        team_id: ID of the team to edit
        db: Database session

    Returns:
        HTMLResponse: Rendered team edit form
    """
    if not settings.email_auth_enabled:
        return HTMLResponse(content='<div class="text-red-500">Email authentication is disabled</div>', status_code=403)

    try:
        # Get root path for URL construction
        root_path = _resolve_root_path(_request) if _request else ""
        team_service = TeamManagementService(db)

        team = await team_service.get_team_by_id(team_id)
        if not team:
            return HTMLResponse(content='<div class="text-red-500">Team not found</div>', status_code=404)

        # Personal teams cannot be updated (service rejects all personal team updates)
        if team.is_personal:
            return HTMLResponse(content='<div class="text-red-500">Personal teams cannot be edited</div>', status_code=403)

        safe_team_name = html.escape(team.name, quote=True)
        safe_description = html.escape(team.description or "")
        is_admin_edit = isinstance(_user, dict) and _user.get("is_admin")
        max_members_limit = settings.max_members_per_team
        current_exceeds_limit = bool(team.max_members is not None and team.max_members > max_members_limit)
        max_attr = "" if is_admin_edit else f'max="{max_members_limit}"'
        use_default_checked = "checked" if team.max_members is None else ""
        max_members_disabled = "disabled" if team.max_members is None else ""
        # When the existing value exceeds the configured limit for a non-admin,
        # show an empty field to avoid browser validation blocking form submission.
        # Submitting empty preserves the current value server-side.
        max_members_value: Union[str, int] = ""
        if team.max_members is None:
            max_members_value = ""
            max_members_hint = f"Currently using global default ({max_members_limit})."
        elif is_admin_edit:
            max_members_value = team.max_members
            max_members_hint = "Admins can set any limit."
        elif current_exceeds_limit:
            max_members_value = ""
            max_members_hint = f"Current: {team.max_members} (above max {max_members_limit}). Leave empty to keep, or set a new value \u2264 {max_members_limit}."
        else:
            max_members_value = team.max_members
            max_members_hint = f"Max {max_members_limit}."
        edit_form = rf"""
        <div class="space-y-4">
            <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-4">Edit Team</h3>
            <div id="edit-team-error"></div>
            <form method="post" action="{root_path}/admin/teams/{team_id}/update" hx-post="{root_path}/admin/teams/{team_id}/update" hx-target="#edit-team-error" hx-swap="innerHTML" class="space-y-4" data-team-validation="true">
                <div>
                    <label class="block text-sm font-medium text-gray-700 dark:text-gray-300">Name</label>
                    <input type="text" name="name" value="{safe_team_name}" required
                           class="mt-1 block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 dark:bg-gray-700 text-gray-900 dark:text-white">
                    <p class="text-xs text-gray-500 dark:text-gray-400 mt-1">Letters, numbers, spaces, underscores, periods, and dashes only</p>
                </div>
                <div>
                    <label class="block text-sm font-medium text-gray-700 dark:text-gray-300">Slug</label>
                    <input type="text" name="slug" value="{team.slug}" readonly
                           class="mt-1 block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm bg-gray-50 dark:bg-gray-700 text-gray-900 dark:text-white">
                    <p class="text-xs text-gray-500 dark:text-gray-400 mt-1">Slug cannot be changed</p>
                </div>
                <div>
                    <label class="block text-sm font-medium text-gray-700 dark:text-gray-300">Description</label>
                    <textarea name="description" rows="3"
                              class="mt-1 block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 dark:bg-gray-700 text-gray-900 dark:text-white">{safe_description}</textarea>
                </div>
                <div>
                    <label class="block text-sm font-medium text-gray-700 dark:text-gray-300">Visibility</label>
                    <select name="visibility"
                            class="mt-1 block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 dark:bg-gray-700 text-gray-900 dark:text-white">
                        <option value="private" {"selected" if team.visibility == "private" else ""}>Private</option>
                        <option value="public" {"selected" if team.visibility == "public" else ""}>Public</option>
                    </select>
                </div>
                <div>
                    <label class="block text-sm font-medium text-gray-700 dark:text-gray-300">Maximum Members</label>
                    <div class="flex items-center mt-1 mb-2">
                        <input type="checkbox" name="use_default_max_members" id="use-default-max-members" {use_default_checked}
                               onchange="var mi = this.closest('div').parentElement.querySelector('input[name=max_members]'); mi.disabled = this.checked; if(this.checked) mi.value = '';"
                               class="h-4 w-4 text-indigo-600 focus:ring-indigo-500 border-gray-300 rounded">
                        <label for="use-default-max-members" class="ml-2 text-sm text-gray-700 dark:text-gray-300">Use global default ({max_members_limit})</label>
                    </div>
                    <input type="number" name="max_members" min="1" {max_attr} value="{max_members_value}" {max_members_disabled}
                           class="mt-1 block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 dark:bg-gray-700 text-gray-900 dark:text-white">
                    <p class="text-xs text-gray-500 dark:text-gray-400 mt-1">{max_members_hint}</p>
                </div>
                <div class="flex justify-end space-x-3">
                    <button type="button" onclick="Admin.hideTeamEditModal()"
                            class="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-md hover:bg-gray-50 dark:hover:bg-gray-700">
                        Cancel
                    </button>
                    <button type="submit"
                            class="px-4 py-2 text-sm font-medium text-white bg-blue-600 border border-transparent rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500">
                        Update Team
                    </button>
                </div>
            </form>
        </div>
        """
        return HTMLResponse(content=edit_form)

    except Exception as e:
        LOGGER.error(f"Error getting team edit form for {team_id}: {e}")
        return HTMLResponse(content=f'<div class="text-red-500">Error loading team: {html.escape(str(e))}</div>', status_code=500)


@router.post("/teams/{team_id}/update")
@require_permission("teams.update", allow_admin_bypass=False)
async def admin_update_team(
    team_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> Response:
    """Update team via admin UI.

    Args:
        team_id: ID of the team to update
        request: FastAPI request object
        db: Database session
        user: Current authenticated user context

    Returns:
        Response: Result of team update operation
    """
    # Ensure root_path is available for URL construction in all branches
    root_path = _resolve_root_path(request) if request else ""

    if not settings.email_auth_enabled:
        return HTMLResponse(content='<div class="text-red-500">Email authentication is disabled</div>', status_code=403)

    try:
        team_service = TeamManagementService(db)

        form = await request.form()
        name_val = form.get("name")
        desc_val = form.get("description")
        vis_val = form.get("visibility", "private")
        use_default_max_members = form.get("use_default_max_members")
        # Trim before presence check for consistent error messages
        name = name_val.strip() if isinstance(name_val, str) else None
        description = desc_val.strip() if isinstance(desc_val, str) and desc_val.strip() != "" else None
        visibility = vis_val if isinstance(vis_val, str) else "private"
        max_members = _parse_form_max_members(form.get("max_members"))

        if not name:
            is_htmx = request.headers.get("HX-Request") == "true"
            if is_htmx:
                response = HTMLResponse(
                    content='<div class="text-red-500 p-3 bg-red-50 dark:bg-red-900/20 rounded-md mb-4">Team name is required</div>',
                    status_code=400,
                )
                response.headers["HX-Retarget"] = "#edit-team-error"
                response.headers["HX-Reswap"] = "innerHTML"
                return response
            error_msg = urllib.parse.quote("Team name is required")
            return RedirectResponse(url=f"{root_path}/admin/?error={error_msg}#teams", status_code=303)

        # Validate name and description for XSS (same validation as schema)
        if not re.match(settings.validation_name_pattern, name):
            is_htmx = request.headers.get("HX-Request") == "true"
            if is_htmx:
                response = HTMLResponse(
                    content='<div class="text-red-500 p-3 bg-red-50 dark:bg-red-900/20 rounded-md mb-4">Team name can only contain letters, numbers, spaces, underscores, periods, and dashes</div>',
                    status_code=400,
                )
                response.headers["HX-Retarget"] = "#edit-team-error"
                response.headers["HX-Reswap"] = "innerHTML"
                return response
            error_msg = urllib.parse.quote("Team name contains invalid characters")
            return RedirectResponse(url=f"{root_path}/admin/?error={error_msg}#teams", status_code=303)

        try:
            SecurityValidator.validate_no_xss(name, "Team name")
            if re.search(SecurityValidator.DANGEROUS_JS_PATTERN, name, re.IGNORECASE):
                raise ValueError("Team name contains script patterns that may cause security issues")
            if description:
                SecurityValidator.validate_no_xss(description, "Team description")
                if re.search(SecurityValidator.DANGEROUS_JS_PATTERN, description, re.IGNORECASE):
                    raise ValueError("Team description contains script patterns that may cause security issues")
        except ValueError as ve:
            is_htmx = request.headers.get("HX-Request") == "true"
            if is_htmx:
                response = HTMLResponse(
                    content=f'<div class="text-red-500 p-3 bg-red-50 dark:bg-red-900/20 rounded-md mb-4">{html.escape(str(ve))}</div>',
                    status_code=400,
                )
                response.headers["HX-Retarget"] = "#edit-team-error"
                response.headers["HX-Reswap"] = "innerHTML"
                return response
            error_msg = urllib.parse.quote(str(ve))
            return RedirectResponse(url=f"{root_path}/admin/?error={error_msg}#teams", status_code=303)

        # Update team
        user_email = getattr(user, "email", None) or str(user)
        is_admin = isinstance(user, dict) and user.get("is_admin")
        # Three-way max_members resolution:
        #   checkbox checked  → None  (clear per-team override, revert to global default)
        #   number provided   → int   (set explicit per-team limit)
        #   neither           → UNSET (leave current value unchanged)
        if use_default_max_members:
            max_members_kwarg = None
        elif max_members is not None:
            max_members_kwarg = max_members
        else:
            max_members_kwarg = UNSET
        updated = await team_service.update_team(
            team_id=team_id, name=name, description=description, visibility=visibility, max_members=max_members_kwarg, updated_by=user_email, skip_limits=bool(is_admin)
        )

        if not updated:
            is_htmx = request.headers.get("HX-Request") == "true"
            error_html = '<div class="text-red-500 p-3 bg-red-50 dark:bg-red-900/20 rounded-md mb-4">Team cannot be updated</div>'
            if is_htmx:
                response = HTMLResponse(content=error_html, status_code=400)
                response.headers["HX-Retarget"] = "#edit-team-error"
                response.headers["HX-Reswap"] = "innerHTML"
                return response
            error_msg = urllib.parse.quote("Team cannot be updated")
            return RedirectResponse(url=f"{root_path}/admin/?error={error_msg}#teams", status_code=303)

        # Check if this is an HTMX request
        is_htmx = request.headers.get("HX-Request") == "true"

        if is_htmx:
            # Return success message with auto-close and refresh for HTMX
            success_html = """
            <div class="text-green-500 text-center p-4">
                <p>Team updated successfully</p>
            </div>
            """
            response = HTMLResponse(content=success_html)
            response.headers["HX-Trigger"] = orjson.dumps({"adminTeamAction": {"closeTeamEditModal": True, "refreshUnifiedTeamsList": True, "delayMs": 1500}}).decode()
            return response
        # For regular form submission, redirect to admin page with teams section
        return RedirectResponse(url=f"{root_path}/admin/#teams", status_code=303)

    except ValueError as e:
        # Rollback to discard any partial mutations (e.g. name/description set before max_members check failed)
        db.rollback()
        LOGGER.warning(f"Validation error updating team {team_id}: {e}")
        is_htmx = request.headers.get("HX-Request") == "true"
        if is_htmx:
            response = HTMLResponse(content=f'<div class="text-red-500 p-3 bg-red-50 dark:bg-red-900/20 rounded-md mb-4">{html.escape(str(e))}</div>', status_code=400)
            response.headers["HX-Retarget"] = "#edit-team-error"
            response.headers["HX-Reswap"] = "innerHTML"
            return response
        error_msg = urllib.parse.quote(str(e))
        return RedirectResponse(url=f"{root_path}/admin/?error={error_msg}#teams", status_code=303)
    except Exception as e:
        db.rollback()
        LOGGER.error(f"Error updating team {team_id}: {e}")

        # Check if this is an HTMX request for error handling too
        is_htmx = request.headers.get("HX-Request") == "true"

        if is_htmx:
            return HTMLResponse(content=f'<div class="text-red-500">Error updating team: {html.escape(str(e))}</div>', status_code=500)
        # For regular form submission, redirect to admin page with error parameter
        error_msg = urllib.parse.quote(f"Error updating team: {str(e)}")
        return RedirectResponse(url=f"{root_path}/admin/?error={error_msg}#teams", status_code=303)


@router.delete("/teams/{team_id}")
@require_permission("teams.delete", allow_admin_bypass=False)
async def admin_delete_team(
    team_id: str,
    _request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> HTMLResponse:
    """Delete team via admin UI.

    Args:
        team_id: ID of the team to delete
        db: Database session
        user: Current authenticated user context

    Returns:
        HTMLResponse: Success message or error response
    """
    if not settings.email_auth_enabled:
        return HTMLResponse(content='<div class="text-red-500">Email authentication is disabled</div>', status_code=403)

    try:
        team_service = TeamManagementService(db)

        # Get team name for success message
        team = await team_service.get_team_by_id(team_id)
        team_name = team.name if team else "Unknown"

        # Delete team (get user email from JWT payload)
        user_email = get_user_email(user)
        deleted = await team_service.delete_team(team_id, deleted_by=user_email)

        if not deleted:
            return HTMLResponse(content='<div class="text-red-500">Team cannot be deleted due to business constraints</div>', status_code=409)

        # Return success message with script to refresh teams list
        safe_team_name = html.escape(team_name)
        success_html = f"""
        <div class="text-green-500 text-center p-4">
            <p>Team "{safe_team_name}" deleted successfully</p>
        </div>
        """
        response = HTMLResponse(content=success_html)
        # Prevent nginx caching for real-time updates
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        response.headers["HX-Trigger"] = orjson.dumps({"adminTeamAction": {"refreshUnifiedTeamsList": True, "delayMs": 1000}}).decode()
        return response

    except Exception as e:
        LOGGER.error(f"Error deleting team {team_id}: {e}")
        return HTMLResponse(content=f'<div class="text-red-500">Error deleting team: {html.escape(str(e))}</div>', status_code=400)


@router.post("/teams/{team_id}/add-member")
@require_permission("teams.manage_members", allow_admin_bypass=False)
async def admin_add_team_members(
    team_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> HTMLResponse:
    """Add member(s) to team via admin UI.

    Supports both single user (user_email field) and multiple users (associatedUsers field).

    Args:
        team_id: ID of the team to add member(s) to
        request: FastAPI request object
        db: Database session
        user: Current authenticated user context

    Returns:
        HTMLResponse: Success message or error response
    """
    if not settings.email_auth_enabled:
        return HTMLResponse(content='<div class="text-red-500">Email authentication is disabled</div>', status_code=403)

    try:
        # First-Party
        team_service = TeamManagementService(db)
        auth_service = EmailAuthService(db)

        # Check if team exists and validate visibility
        team = await team_service.get_team_by_id(team_id)
        if not team:
            return HTMLResponse(content='<div class="text-red-500">Team not found</div>', status_code=404)

        # For private teams, only team owners can add members directly
        user_email_from_jwt = get_user_email(user)
        if team.visibility == "private":
            user_role = await team_service.get_user_role_in_team(user_email_from_jwt, team_id)
            if user_role != "owner":
                return HTMLResponse(content='<div class="text-red-500">Only team owners can add members to private teams. Use the invitation system instead.</div>', status_code=403)

        form = await request.form()

        # Get loaded members - these are members that were visible in the form (for safe removal with pagination)
        loaded_members_list = form.getlist("loadedMembers")
        loaded_members = {email.strip() for email in loaded_members_list if isinstance(email, str) and email.strip()}

        # Check if this is single user or multiple users
        single_user_email = form.get("user_email")
        multiple_user_emails = form.getlist("associatedUsers")

        # Determine which mode we're in
        if single_user_email:
            # Single user mode (legacy form) - get single role
            user_emails = [single_user_email] if isinstance(single_user_email, str) else []
            default_role = form.get("role", "member")
            default_role = default_role if isinstance(default_role, str) else "member"
        elif multiple_user_emails:
            # Multiple users mode (new paginated selector)
            seen = set()
            user_emails = []
            for email in multiple_user_emails:
                if not isinstance(email, str):
                    continue
                cleaned = email.strip()
                if not cleaned or cleaned in seen:
                    continue
                seen.add(cleaned)
                user_emails.append(cleaned)
            default_role = "member"  # Default if no per-user role specified
        else:
            return HTMLResponse(content='<div class="text-red-500">No users selected</div>', status_code=400)

        # Get current team members
        team_members = await team_service.get_team_members(team_id)
        existing_member_emails = {team_user.email for team_user, membership in team_members}

        # Build a map of existing member roles
        existing_member_roles = {}
        owner_count = team_service.count_team_owners(team_id)
        for team_user, membership in team_members:
            email = team_user.email
            is_last_owner = membership.role == "owner" and owner_count == 1
            existing_member_roles[email] = {"role": membership.role, "is_last_owner": is_last_owner}

        # Track results
        added = []
        updated = []
        removed = []
        errors = []

        # Process submitted users (checked boxes)
        submitted_user_emails = set(user_emails)

        # 1. Handle additions and updates for checked users
        for user_email in user_emails:
            user_email = user_email.strip()
            if not user_email:
                continue

            try:
                # Check if user exists
                target_user = await auth_service.get_user_by_email(user_email)
                if not target_user:
                    errors.append(f"{user_email} (user not found)")
                    continue

                # Get per-user role from form (format: role_<url-encoded-email>)
                encoded_email = urllib.parse.quote(user_email, safe="")
                user_role_key = f"role_{encoded_email}"
                user_role_val = form.get(user_role_key, default_role)
                user_role = user_role_val if isinstance(user_role_val, str) else default_role

                if user_email in existing_member_emails:
                    # User is already a member - check if role changed
                    current_role = existing_member_roles[user_email]["role"]
                    if current_role != user_role:
                        # Don't allow changing role of last owner
                        if existing_member_roles[user_email]["is_last_owner"]:
                            errors.append(f"{user_email} (cannot change role of last owner)")
                            continue
                        # Update role
                        await team_service.update_member_role(team_id=team_id, user_email=user_email, new_role=user_role, updated_by=user_email_from_jwt)
                        updated.append(f"{user_email} (role: {user_role})")
                else:
                    # New member - add them
                    await team_service.add_member_to_team(team_id=team_id, user_email=user_email, role=user_role, invited_by=user_email_from_jwt)
                    added.append(user_email)

            except Exception as member_error:
                LOGGER.error(f"Error processing {user_email} for team {team_id}: {member_error}")
                errors.append(f"{user_email} ({str(member_error)})")

        # 2. Handle removals - only remove members who were LOADED in the form AND unchecked
        # This prevents accidentally removing members from pages that weren't loaded yet (infinite scroll safety)
        for existing_email in existing_member_emails:
            # Only consider removal if the member was visible in the form (in loadedMembers)
            if existing_email not in loaded_members:
                continue  # Member wasn't loaded in form, skip (safe for pagination)
            if existing_email in submitted_user_emails:
                continue  # Member is checked, don't remove

            member_info = existing_member_roles.get(existing_email, {})

            # Validate removal is allowed - server-side protection
            # Current user cannot be removed
            if existing_email == user_email_from_jwt:
                errors.append(f"{existing_email} (cannot remove yourself)")
                continue
            # Last owner cannot be removed
            if member_info.get("is_last_owner", False):
                errors.append(f"{existing_email} (cannot remove last owner)")
                continue

            # This member was unchecked and removal is allowed - remove them
            try:
                await team_service.remove_member_from_team(team_id=team_id, user_email=existing_email, removed_by=user_email_from_jwt)
                removed.append(existing_email)
            except Exception as removal_error:
                LOGGER.error(f"Error removing {existing_email} from team {team_id}: {removal_error}")
                errors.append(f"{existing_email} (removal failed: {str(removal_error)})")

        # Build result message
        result_parts = []
        if added:
            result_parts.append(f'<p class="text-green-600 dark:text-green-400">✓ Added {len(added)} member(s)</p>')
        if updated:
            result_parts.append(f'<p class="text-blue-600 dark:text-blue-400">↻ Updated {len(updated)} member(s)</p>')
        if removed:
            result_parts.append(f'<p class="text-orange-600 dark:text-orange-400">− Removed {len(removed)} member(s)</p>')
        if errors:
            result_parts.append(f'<p class="text-red-600 dark:text-red-400">✗ {len(errors)} error(s)</p>')
            for error in errors[:5]:  # Show first 5 errors
                result_parts.append(f'<p class="text-xs text-red-500 dark:text-red-400 ml-4">• {error}</p>')
            if len(errors) > 5:
                result_parts.append(f'<p class="text-xs text-red-500 dark:text-red-400 ml-4">... and {len(errors) - 5} more</p>')

        if not result_parts:
            result_parts.append('<p class="text-gray-600 dark:text-gray-400">No changes made</p>')

        result_html = "\n".join(result_parts)

        # Return success message and close modal
        success_html = f"""
        <div class="text-center p-4">
            {result_html}
        </div>
        <script>
            // Close modal after showing success message briefly
            setTimeout(() => {{
                const modal = document.getElementById('team-edit-modal');
                if (modal) {{
                    modal.classList.add('hidden');
                }}
            }}, 1000);
        </script>
        """
        response = HTMLResponse(content=success_html)

        # Prevent nginx caching for real-time updates
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"

        # Trigger refresh of teams list (but don't reopen modal)
        response.headers["HX-Trigger"] = orjson.dumps(
            {
                "adminTeamAction": {
                    "teamId": team_id,
                    "refreshUnifiedTeamsList": True,
                }
            }
        ).decode()
        return response

    except Exception as e:
        LOGGER.error(f"Error adding member(s) to team {team_id}: {e}")
        return HTMLResponse(content=f'<div class="text-red-500">Error adding member(s): {html.escape(str(e))}</div>', status_code=400)


@router.post("/teams/{team_id}/update-member-role")
@require_permission("teams.manage_members", allow_admin_bypass=False)
async def admin_update_team_member_role(
    team_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> HTMLResponse:
    """Update team member role via admin UI.

    Args:
        team_id: ID of the team containing the member
        request: FastAPI request object
        db: Database session
        user: Current authenticated user context

    Returns:
        HTMLResponse: Success message or error response
    """
    if not settings.email_auth_enabled:
        return HTMLResponse(content='<div class="text-red-500">Email authentication is disabled</div>', status_code=403)

    try:
        team_service = TeamManagementService(db)

        # Check if team exists and validate user permissions
        team = await team_service.get_team_by_id(team_id)
        if not team:
            return HTMLResponse(content='<div class="text-red-500">Team not found</div>', status_code=404)

        # Only team owners can modify member roles
        user_email_from_jwt = get_user_email(user)
        user_role = await team_service.get_user_role_in_team(user_email_from_jwt, team_id)
        if user_role != "owner":
            return HTMLResponse(content='<div class="text-red-500">Only team owners can modify member roles</div>', status_code=403)

        form = await request.form()
        ue_val = form.get("user_email")
        nr_val = form.get("role", "member")
        user_email = ue_val if isinstance(ue_val, str) else None
        new_role = nr_val if isinstance(nr_val, str) else "member"

        if not user_email:
            return HTMLResponse(content='<div class="text-red-500">User email is required</div>', status_code=400)

        if not new_role:
            return HTMLResponse(content='<div class="text-red-500">Role is required</div>', status_code=400)

        # Update member role
        await team_service.update_member_role(team_id=team_id, user_email=user_email, new_role=new_role, updated_by=user_email_from_jwt)

        # Return success message with auto-close and refresh
        success_html = f"""
        <div class="text-green-500 text-center p-4">
            <p>Role updated successfully for {user_email}</p>
        </div>
        """
        response = HTMLResponse(content=success_html)
        response.headers["HX-Trigger"] = orjson.dumps(
            {
                "adminTeamAction": {
                    "teamId": team_id,
                    "refreshTeamMembers": True,
                    "refreshUnifiedTeamsList": True,
                    "closeRoleModal": True,
                    "delayMs": 1000,
                }
            }
        ).decode()
        return response

    except Exception as e:
        LOGGER.error(f"Error updating member role in team {team_id}: {e}")
        return HTMLResponse(content=f'<div class="text-red-500">Error updating role: {html.escape(str(e))}</div>', status_code=400)


@router.post("/teams/{team_id}/remove-member")
@require_permission("teams.manage_members", allow_admin_bypass=False)
async def admin_remove_team_member(
    team_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> HTMLResponse:
    """Remove member from team via admin UI.

    Args:
        team_id: ID of the team to remove member from
        request: FastAPI request object
        db: Database session
        user: Current authenticated user context

    Returns:
        HTMLResponse: Success message or error response
    """
    if not settings.email_auth_enabled:
        return HTMLResponse(content='<div class="text-red-500">Email authentication is disabled</div>', status_code=403)

    try:
        team_service = TeamManagementService(db)

        # Check if team exists and validate user permissions
        team = await team_service.get_team_by_id(team_id)
        if not team:
            return HTMLResponse(content='<div class="text-red-500">Team not found</div>', status_code=404)

        # Only team owners can remove members
        user_email_from_jwt = get_user_email(user)
        user_role = await team_service.get_user_role_in_team(user_email_from_jwt, team_id)
        if user_role != "owner":
            return HTMLResponse(content='<div class="text-red-500">Only team owners can remove members</div>', status_code=403)

        form = await request.form()
        ue_val = form.get("user_email")
        user_email = ue_val if isinstance(ue_val, str) else None

        if not user_email:
            return HTMLResponse(content='<div class="text-red-500">User email is required</div>', status_code=400)

        # Remove member from team

        try:
            success = await team_service.remove_member_from_team(team_id=team_id, user_email=user_email, removed_by=user_email_from_jwt)
            if not success:
                return HTMLResponse(content='<div class="text-red-500">Failed to remove member from team</div>', status_code=400)
        except ValueError as e:
            # Handle specific business logic errors (like last owner)
            return HTMLResponse(content=f'<div class="text-red-500">{html.escape(str(e))}</div>', status_code=400)

        # Return success message with script to refresh modal
        success_html = f"""
        <div class="text-green-500 text-center p-4">
            <p>Member {user_email} removed successfully</p>
        </div>
        """
        response = HTMLResponse(content=success_html)
        response.headers["HX-Trigger"] = orjson.dumps(
            {
                "adminTeamAction": {
                    "teamId": team_id,
                    "refreshTeamMembers": True,
                    "refreshUnifiedTeamsList": True,
                    "delayMs": 1000,
                }
            }
        ).decode()
        return response

    except Exception as e:
        LOGGER.error(f"Error removing member from team {team_id}: {e}")
        return HTMLResponse(content=f'<div class="text-red-500">Error removing member: {html.escape(str(e))}</div>', status_code=400)


@router.post("/teams/{team_id}/leave")
@require_permission("teams.join", allow_admin_bypass=False)  # Users who can join can also leave
async def admin_leave_team(
    team_id: str,
    request: Request,  # pylint: disable=unused-argument
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> HTMLResponse:
    """Leave a team via admin UI.

    Args:
        team_id: ID of the team to leave
        request: FastAPI request object
        db: Database session
        user: Current authenticated user context

    Returns:
        HTMLResponse: Success message or error response
    """
    if not settings.email_auth_enabled:
        return HTMLResponse(content='<div class="text-red-500">Email authentication is disabled</div>', status_code=403)

    try:
        team_service = TeamManagementService(db)

        # Check if team exists
        team = await team_service.get_team_by_id(team_id)
        if not team:
            return HTMLResponse(content='<div class="text-red-500">Team not found</div>', status_code=404)

        # Get current user email
        user_email = get_user_email(user)

        # Check if user is a member of the team
        user_role = await team_service.get_user_role_in_team(user_email, team_id)
        if not user_role:
            return HTMLResponse(content='<div class="text-red-500">You are not a member of this team</div>', status_code=400)

        # Prevent leaving personal teams
        if team.is_personal:
            return HTMLResponse(content='<div class="text-red-500">Cannot leave your personal team</div>', status_code=400)

        # Check if user is the last owner (use SQL COUNT instead of loading all members)
        if user_role == "owner":
            owner_count = team_service.count_team_owners(team_id)
            if owner_count <= 1:
                return HTMLResponse(content='<div class="text-red-500">Cannot leave team as the last owner. Transfer ownership or delete the team instead.</div>', status_code=400)

        # Remove user from team
        success = await team_service.remove_member_from_team(team_id=team_id, user_email=user_email, removed_by=user_email)
        if not success:
            return HTMLResponse(content='<div class="text-red-500">Failed to leave team</div>', status_code=400)

        # Return success message with redirect
        success_html = """
        <div class="text-green-500 text-center p-4">
            <p>Successfully left the team</p>
        </div>
        """
        response = HTMLResponse(content=success_html)
        response.headers["HX-Trigger"] = orjson.dumps({"adminTeamAction": {"refreshUnifiedTeamsList": True, "closeAllModals": True, "delayMs": 1500}}).decode()
        return response

    except Exception as e:
        LOGGER.error(f"Error leaving team {team_id}: {e}")
        return HTMLResponse(content=f'<div class="text-red-500">Error leaving team: {html.escape(str(e))}</div>', status_code=400)
