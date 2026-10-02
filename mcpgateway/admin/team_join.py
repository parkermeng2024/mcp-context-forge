# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/admin/team_join.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Admin UI team join request routes: create, cancel, list, approve, and reject.
"""

# Standard
import html
import logging

# Third-Party
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
import orjson
from sqlalchemy.orm import Session

# First-Party
from mcpgateway.admin.security import enforce_admin_csrf
from mcpgateway.auth_context import get_user_email
from mcpgateway.config import settings
from mcpgateway.db import get_db
from mcpgateway.middleware.rbac import get_current_user_with_permissions, require_permission
from mcpgateway.services.team_management_service import JoinRequestNotFoundError, TeamManagementService

LOGGER: logging.Logger = logging.getLogger("mcpgateway.admin")

# mcpgateway.admin (__init__) appends this router's routes to admin_router, so the
# prefix, tags, and CSRF dependency must mirror admin_router exactly.
router = APIRouter(
    prefix="/admin",
    tags=["Admin UI"],
    dependencies=[Depends(enforce_admin_csrf)],
)


# ============================================================================ #
#                         TEAM JOIN REQUEST ADMIN ROUTES                      #
# ============================================================================ #


@router.post("/teams/{team_id}/join-request")
@require_permission("teams.join", allow_admin_bypass=False)
async def admin_create_join_request(
    team_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> HTMLResponse:
    """Create a join request for a team via admin UI.

    Args:
        team_id: ID of the team to request to join
        request: FastAPI request object
        db: Database session
        user: Authenticated user

    Returns:
        HTML response with success message or error
    """
    if not getattr(settings, "email_auth_enabled", False):
        return HTMLResponse(content='<div class="text-red-500">Email authentication is disabled</div>', status_code=403)

    if not getattr(settings, "allow_team_join_requests", True):
        return HTMLResponse(content='<div class="text-red-500">Team join requests are currently disabled</div>', status_code=403)

    try:
        team_service = TeamManagementService(db)
        user_email = get_user_email(user)

        # Get team to verify it's public
        team = await team_service.get_team_by_id(team_id)
        if not team:
            return HTMLResponse(content='<div class="text-red-500">Team not found</div>', status_code=404)

        if team.visibility != "public":
            return HTMLResponse(content='<div class="text-red-500">Can only request to join public teams</div>', status_code=400)

        # Check if user is already a member
        user_role = await team_service.get_user_role_in_team(user_email, team_id)
        if user_role:
            return HTMLResponse(content='<div class="text-red-500">You are already a member of this team</div>', status_code=400)

        # Check if user already has a pending request
        existing_requests = await team_service.get_user_join_requests(user_email, team_id)
        pending_request = next((req for req in existing_requests if req.status == "pending"), None)
        if pending_request:
            return HTMLResponse(
                content=f"""
            <div class="text-yellow-600">
                <p>You already have a pending request to join this team.</p>
                <button onclick="cancelJoinRequest('{team_id}', '{pending_request.id}')"
                        class="mt-2 px-3 py-1 text-sm font-medium text-red-600 dark:text-red-400 hover:text-red-800 dark:hover:text-red-300 border border-red-300 dark:border-red-600 hover:border-red-500 dark:hover:border-red-400 rounded-md focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500">
                    Cancel Request
                </button>
            </div>
            """,
                status_code=200,
            )

        # Get form data for optional message
        form = await request.form()
        msg_val = form.get("message", "")
        message = msg_val if isinstance(msg_val, str) else ""

        # Create join request
        join_request = await team_service.create_join_request(team_id=team_id, user_email=user_email, message=message)

        return HTMLResponse(
            content=f"""
        <div class="text-green-600">
            <p>Join request submitted successfully!</p>
            <button onclick="cancelJoinRequest('{team_id}', '{join_request.id}')"
                    class="mt-2 px-3 py-1 text-sm font-medium text-red-600 dark:text-red-400 hover:text-red-800 dark:hover:text-red-300 border border-red-300 dark:border-red-600 hover:border-red-500 dark:hover:border-red-400 rounded-md focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500">
                Cancel Request
            </button>
        </div>
        """,
            status_code=201,
        )

    except ValueError as e:
        # Handle validation errors with user-friendly HTML error
        error_msg = html.escape(str(e))
        return HTMLResponse(content=f'<div class="text-red-500">{error_msg}</div>', status_code=400)
    except Exception as e:
        LOGGER.error(f"Error creating join request for team {team_id}: {e}")
        return HTMLResponse(content=f'<div class="text-red-500">Error creating join request: {html.escape(str(e))}</div>', status_code=400)


@router.delete("/teams/{team_id}/join-request/{request_id}")
@require_permission("teams.join", allow_admin_bypass=False)
async def admin_cancel_join_request(
    team_id: str,
    request_id: str,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> HTMLResponse:
    """Cancel a join request via admin UI.

    Args:
        team_id: ID of the team
        request_id: ID of the join request to cancel
        db: Database session
        user: Authenticated user

    Returns:
        HTML response with updated button state
    """
    if not getattr(settings, "email_auth_enabled", False):
        return HTMLResponse(content='<div class="text-red-500">Email authentication is disabled</div>', status_code=403)

    try:
        team_service = TeamManagementService(db)
        user_email = get_user_email(user)

        # Cancel the join request
        success = await team_service.cancel_join_request(request_id, user_email)
        if not success:
            return HTMLResponse(content='<div class="text-red-500">Failed to cancel join request</div>', status_code=400)

        # Return the "Request to Join" button with HX-Trigger for list refresh
        # Check if join requests are currently enabled
        allow_join_requests = getattr(settings, "allow_team_join_requests", True)

        if allow_join_requests:
            button_html = f"""
        <button data-team-id="{team_id}" data-team-name="Team" onclick="requestToJoinTeamSafe(this)"
                class="px-3 py-1 text-sm font-medium text-indigo-600 dark:text-indigo-400 hover:text-indigo-800 dark:hover:text-indigo-300 border border-indigo-300 dark:border-indigo-600 hover:border-indigo-500 dark:hover:border-indigo-400 rounded-md focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500">
            Request to Join
        </button>
        """
        else:
            button_html = """
        <button disabled
                class="px-3 py-1 text-sm font-medium text-gray-400 dark:text-gray-600 border border-gray-300 dark:border-gray-600 rounded-md cursor-not-allowed opacity-50"
                title="Team join requests are currently disabled">
            Request to Join (Disabled)
        </button>
        """

        response = HTMLResponse(content=button_html, status_code=200)
        response.headers["HX-Trigger"] = orjson.dumps({"adminTeamAction": {"refreshUnifiedTeamsList": True, "delayMs": 1000}}).decode()
        return response

    except Exception as e:
        LOGGER.error(f"Error canceling join request {request_id}: {e}")
        return HTMLResponse(content=f'<div class="text-red-500">Error canceling join request: {html.escape(str(e))}</div>', status_code=400)


@router.get("/teams/{team_id}/join-requests")
@require_permission("teams.manage_members", allow_admin_bypass=False)
async def admin_list_join_requests(
    team_id: str,
    _request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> HTMLResponse:
    """List join requests for a team via admin UI.

    Args:
        team_id: ID of the team
        _request: FastAPI request object (unused, required by route signature)
        db: Database session
        user: Authenticated user

    Returns:
        HTML response with join requests list
    """
    if not getattr(settings, "email_auth_enabled", False):
        return HTMLResponse(content='<div class="text-red-500">Email authentication is disabled</div>', status_code=403)

    try:
        team_service = TeamManagementService(db)
        user_email = get_user_email(user)
        # Get team and verify ownership
        team = await team_service.get_team_by_id(team_id)
        if not team:
            return HTMLResponse(content='<div class="text-red-500">Team not found</div>', status_code=404)

        user_role = await team_service.get_user_role_in_team(user_email, team_id)
        if user_role != "owner":
            return HTMLResponse(content='<div class="text-red-500">Only team owners can view join requests</div>', status_code=403)

        # Get join requests
        join_requests = await team_service.list_join_requests(team_id)

        if not join_requests:
            return HTMLResponse(
                content="""
            <div class="text-center py-8">
                <p class="text-gray-500 dark:text-gray-400">No pending join requests</p>
            </div>
            """,
                status_code=200,
            )

        requests_html = ""
        for req in join_requests:
            safe_email = html.escape(req.user_email)
            safe_message = html.escape(req.message) if req.message else ""
            safe_status = html.escape(req.status.upper())
            requests_html += f"""
            <div class="flex justify-between items-center p-4 border border-gray-200 dark:border-gray-600 rounded-lg mb-3">
                <div>
                    <p class="font-medium text-gray-900 dark:text-white">{safe_email}</p>
                    <p class="text-sm text-gray-600 dark:text-gray-400">Requested: {req.requested_at.strftime("%Y-%m-%d %H:%M") if req.requested_at else "Unknown"}</p>
                    {f'<p class="text-sm text-gray-600 dark:text-gray-400 mt-1">Message: {safe_message}</p>' if req.message else ""}
                    <span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300">{safe_status}</span>
                </div>
                <div class="flex gap-2">
                    <button data-action-click="approveJoinRequest" data-arg0="{team_id}" data-arg1="{req.id}"
                            class="px-3 py-1 text-sm font-medium text-green-600 dark:text-green-400 hover:text-green-800 dark:hover:text-green-300 border border-green-300 dark:border-green-600 hover:border-green-500 dark:hover:border-green-400 rounded-md focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500">
                        Approve
                    </button>
                    <button data-action-click="rejectJoinRequest" data-arg0="{team_id}" data-arg1="{req.id}"
                            class="px-3 py-1 text-sm font-medium text-red-600 dark:text-red-400 hover:text-red-800 dark:hover:text-red-300 border border-red-300 dark:border-red-600 hover:border-red-500 dark:hover:border-red-400 rounded-md focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500">
                        Reject
                    </button>
                </div>
            </div>
            """

        safe_team_name = html.escape(team.name)
        return HTMLResponse(
            content=f"""
        <div class="space-y-4">
            <h3 class="text-lg font-medium text-gray-900 dark:text-white mb-4">Join Requests for {safe_team_name}</h3>
            {requests_html}
        </div>
        """,
            status_code=200,
        )

    except Exception as e:
        LOGGER.error(f"Error listing join requests for team {team_id}: {e}")
        return HTMLResponse(content=f'<div class="text-red-500">Error loading join requests: {html.escape(str(e))}</div>', status_code=400)


@router.post("/teams/{team_id}/join-requests/{request_id}/approve")
@require_permission("teams.manage_members", allow_admin_bypass=False)
async def admin_approve_join_request(
    team_id: str,
    request_id: str,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> HTMLResponse:
    """Approve a join request via admin UI.

    Args:
        team_id: ID of the team
        request_id: ID of the join request to approve
        db: Database session
        user: Authenticated user

    Returns:
        HTML response with success message
    """
    if not getattr(settings, "email_auth_enabled", False):
        return HTMLResponse(content='<div class="text-red-500">Email authentication is disabled</div>', status_code=403)

    try:
        team_service = TeamManagementService(db)
        user_email = get_user_email(user)

        # Verify team ownership
        user_role = await team_service.get_user_role_in_team(user_email, team_id)
        if user_role != "owner":
            return HTMLResponse(content='<div class="text-red-500">Only team owners can approve join requests</div>', status_code=403)

        # Approve join request
        member = await team_service.approve_join_request(team_id, request_id, approved_by=user_email)

        response = HTMLResponse(
            content=f"""
        <div class="text-green-600 text-center p-4">
            <p>Join request approved! {member.user_email} is now a team member.</p>
        </div>
        """,
            status_code=200,
        )
        response.headers["HX-Trigger"] = orjson.dumps({"adminTeamAction": {"teamId": team_id, "refreshJoinRequests": True, "delayMs": 1000}}).decode()
        return response

    except JoinRequestNotFoundError as e:
        return HTMLResponse(content=f'<div class="text-red-500">{html.escape(str(e))}</div>', status_code=404)
    except ValueError as e:
        return HTMLResponse(content=f'<div class="text-red-500">Error approving join request: {html.escape(str(e))}</div>', status_code=400)
    except Exception as e:
        LOGGER.error(f"Error approving join request {request_id}: {e}")
        return HTMLResponse(content=f'<div class="text-red-500">Error approving join request: {html.escape(str(e))}</div>', status_code=400)


@router.post("/teams/{team_id}/join-requests/{request_id}/reject")
@require_permission("teams.manage_members", allow_admin_bypass=False)
async def admin_reject_join_request(
    team_id: str,
    request_id: str,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> HTMLResponse:
    """Reject a join request via admin UI.

    Args:
        team_id: ID of the team
        request_id: ID of the join request to reject
        db: Database session
        user: Authenticated user

    Returns:
        HTML response with success message
    """
    if not getattr(settings, "email_auth_enabled", False):
        return HTMLResponse(content='<div class="text-red-500">Email authentication is disabled</div>', status_code=403)

    try:
        team_service = TeamManagementService(db)
        user_email = get_user_email(user)

        # Verify team ownership
        user_role = await team_service.get_user_role_in_team(user_email, team_id)
        if user_role != "owner":
            return HTMLResponse(content='<div class="text-red-500">Only team owners can reject join requests</div>', status_code=403)

        # Reject join request
        await team_service.reject_join_request(team_id, request_id, rejected_by=user_email)

        response = HTMLResponse(
            content="""
        <div class="text-green-600 text-center p-4">
            <p>Join request rejected.</p>
        </div>
        """,
            status_code=200,
        )
        response.headers["HX-Trigger"] = orjson.dumps({"adminTeamAction": {"teamId": team_id, "refreshJoinRequests": True, "delayMs": 1000}}).decode()
        return response

    except JoinRequestNotFoundError as e:
        return HTMLResponse(content=f'<div class="text-red-500">{html.escape(str(e))}</div>', status_code=404)
    except ValueError as e:
        return HTMLResponse(content=f'<div class="text-red-500">Error rejecting join request: {html.escape(str(e))}</div>', status_code=400)
    except Exception as e:
        LOGGER.error(f"Error rejecting join request {request_id}: {e}")
        return HTMLResponse(content=f'<div class="text-red-500">Error rejecting join request: {html.escape(str(e))}</div>', status_code=400)
