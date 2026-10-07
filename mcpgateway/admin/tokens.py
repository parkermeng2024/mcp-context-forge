# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/admin/tokens.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Admin UI API token routes: token partial, search, and revoke.
"""

# Standard
import logging
from typing import Any, Dict, Optional
import orjson

# Third-Party
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy import and_, desc, or_, select
from sqlalchemy.orm import Session

# First-Party
from mcpgateway.admin.common import _escape_like, _validated_team_id_param
from mcpgateway.admin.security import enforce_admin_csrf
from mcpgateway.admin.visibility import get_user_action_permissions
from mcpgateway.auth_context import get_token_teams_from_request, get_user_email
from mcpgateway.common.query_params import QueryRenderMode
from mcpgateway.config import settings
from mcpgateway.db import EmailApiToken, EmailTeam, get_db, utc_now
from mcpgateway.middleware.rbac import get_current_user_with_permissions, require_permission
from mcpgateway.services.token_catalog_service import TokenCatalogService
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


@router.get("/tokens/partial", response_class=HTMLResponse)
@require_permission("tokens.read", allow_admin_bypass=False)
async def admin_tokens_partial_html(
    request: Request,
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    per_page: int = Query(settings.pagination_default_page_size, ge=1, le=settings.pagination_max_page_size, description="Items per page"),
    include_inactive: bool = False,
    render: QueryRenderMode = None,
    q: Optional[str] = Query(None, max_length=500, description="Search query for token name"),
    team_id: Optional[str] = Depends(_validated_team_id_param),
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    """Return paginated tokens HTML partials for the admin UI.

    This HTMX endpoint returns only the partial HTML used by the admin UI for
    API tokens. It supports two render modes:

    - default: full token cards + pagination controls
    - ``render="controls"``: return only pagination controls

    Args:
        request: FastAPI request object used by the template engine.
        page: Page number (1-indexed).
        per_page: Number of items per page (bounded by settings).
        include_inactive: If True, include inactive/expired tokens in results.
        render: Render mode; one of None or "controls".
        q: Search query string to filter tokens by name.
        team_id: Filter by team ID.
        db: Database session (dependency-injected).
        user: Authenticated user object from dependency injection.

    Returns:
        HTMLResponse: A rendered template response containing either the token
        cards partial or pagination controls depending on ``render``.
    """
    user_email = get_user_email(user)
    LOGGER.debug(f"User {user_email} requested tokens HTML partial (page={page}, per_page={per_page}, include_inactive={include_inactive}, render={render}, q={q}, team_id={team_id})")

    # Normalize per_page within configured bounds
    per_page = max(settings.pagination_min_page_size, min(per_page, settings.pagination_max_page_size))

    # Build base query: tokens owned by this user OR in user's teams
    token_service = TokenCatalogService(db)
    user_team_ids = await token_service.get_user_team_ids(user_email)

    conditions = [EmailApiToken.user_email == user_email]
    if user_team_ids:
        conditions.append(EmailApiToken.team_id.in_(user_team_ids))

    query = select(EmailApiToken).where(or_(*conditions))

    if team_id:
        query = query.where(EmailApiToken.team_id == team_id)

    if not include_inactive:
        query = query.where(and_(EmailApiToken.is_active.is_(True), or_(EmailApiToken.expires_at.is_(None), EmailApiToken.expires_at > utc_now())))

    # Apply search filter on name (case-insensitive)
    if q and isinstance(q, str):
        query = query.where(EmailApiToken.name.ilike(f"%{_escape_like(q.strip().lower())}%", escape="\\"))

    query = query.order_by(desc(EmailApiToken.created_at))

    # Build query params for pagination links
    query_params: Dict[str, Any] = {}
    if include_inactive:
        query_params["include_inactive"] = "true"
    if team_id:
        query_params["team_id"] = team_id
    if q and isinstance(q, str):
        query_params["q"] = q

    # Use unified pagination function
    paginated_result = await paginate_query(
        db=db,
        query=query,
        page=page,
        per_page=per_page,
        cursor=None,
        base_url=f"{settings.app_root_path}/admin/tokens/partial",
        query_params=query_params,
        use_cursor_threshold=False,
    )

    tokens_db = paginated_result["data"]
    pagination = paginated_result["pagination"]
    links = paginated_result["links"]

    base_url = f"{settings.app_root_path}/admin/tokens/partial"

    if render == "controls":
        db.commit()
        return request.app.state.templates.TemplateResponse(
            request,
            "pagination_controls.html",
            {
                "request": request,
                "pagination": pagination.model_dump(),
                "base_url": base_url,
                "hx_target": "#tokens-table",
                "hx_indicator": "#tokens-loading",
                "query_params": query_params,
                "root_path": _resolve_root_path(request),
            },
        )

    # Build token data with revocation info and team names

    # Batch fetch team names
    team_ids_set = {t.team_id for t in tokens_db if t.team_id}
    team_map: Dict[str, str] = {}
    if team_ids_set:
        teams = db.execute(select(EmailTeam.id, EmailTeam.name).where(EmailTeam.id.in_(team_ids_set), EmailTeam.is_active.is_(True))).all()
        team_map = {team.id: team.name for team in teams}

    # Batch fetch revocation info (single query instead of N+1)
    revocation_map = await token_service.get_token_revocations_batch([t.jti for t in tokens_db])

    # Build token data list
    data = []
    for token in tokens_db:
        revocation_info = revocation_map.get(token.jti)
        data.append(
            {
                "id": token.id,
                "name": token.name,
                "description": token.description,
                "user_email": token.user_email,
                "team_id": token.team_id,
                "team_name": team_map.get(token.team_id) if token.team_id else None,
                "created_at": token.created_at,
                "expires_at": token.expires_at,
                "last_used": token.last_used,
                "is_active": token.is_active,
                "is_revoked": revocation_info is not None,
                "revoked_at": revocation_info.revoked_at if revocation_info else None,
                "revoked_by": revocation_info.revoked_by if revocation_info else None,
                "revocation_reason": revocation_info.reason if revocation_info else None,
                "tags": token.tags or [],
                "server_id": token.server_id,
                "resource_scopes": token.resource_scopes or [],
                "ip_restrictions": token.ip_restrictions or [],
                "time_restrictions": token.time_restrictions or {},
                "usage_limits": token.usage_limits or {},
            }
        )
    data = jsonable_encoder(data)
    for item in data:
        item["_json"] = orjson.dumps(item).decode()

    db.commit()

    _is_admin = bool(user.get("is_admin", False) if isinstance(user, dict) else getattr(user, "is_admin", False))
    return request.app.state.templates.TemplateResponse(
        request,
        "tokens_partial.html",
        {
            "request": request,
            "data": data,
            "pagination": pagination.model_dump(),
            "links": links.model_dump() if links else None,
            "root_path": _resolve_root_path(request),
            "include_inactive": include_inactive,
            "team_id": team_id,
            "user_permissions": await get_user_action_permissions(db=db, user_email=user_email, is_admin=_is_admin, token_teams=get_token_teams_from_request(request)),
        },
    )


@router.get("/tokens/search", response_class=JSONResponse)
@require_permission("tokens.read", allow_admin_bypass=False)
async def admin_search_tokens(
    q: str = Query("", max_length=500, description="Search query"),
    include_inactive: bool = False,
    limit: int = Query(settings.pagination_default_page_size, ge=1, le=settings.pagination_max_page_size, description="Max results"),
    team_id: Optional[str] = Depends(_validated_team_id_param),
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    """Search API tokens by name.

    Args:
        q (str): Search query string to match against token names.
        include_inactive (bool): Whether to include inactive/revoked tokens.
        limit (int): Maximum number of results to return.
        team_id (Optional[str]): Filter by team ID.
        db (Session): Database session dependency.
        user: Current authenticated user.

    Returns:
        JSONResponse: List of matching tokens with basic info.
    """
    user_email = get_user_email(user)
    LOGGER.debug(f"User {user_email} searching tokens with query='{q}', include_inactive={include_inactive}, limit={limit}, team_id={team_id}")

    # Build base query: tokens owned by this user OR in user's teams
    token_service = TokenCatalogService(db)
    user_team_ids = await token_service.get_user_team_ids(user_email)

    conditions = [EmailApiToken.user_email == user_email]
    if user_team_ids:
        conditions.append(EmailApiToken.team_id.in_(user_team_ids))

    query = select(EmailApiToken).where(or_(*conditions))

    if team_id:
        query = query.where(EmailApiToken.team_id == team_id)

    if not include_inactive:
        query = query.where(and_(EmailApiToken.is_active.is_(True), or_(EmailApiToken.expires_at.is_(None), EmailApiToken.expires_at > utc_now())))

    # Apply search filter on name (case-insensitive)
    if q and isinstance(q, str):
        query = query.where(EmailApiToken.name.ilike(f"%{_escape_like(q.strip().lower())}%", escape="\\"))

    query = query.order_by(desc(EmailApiToken.created_at)).limit(limit)

    result = db.execute(query)
    tokens = result.scalars().all()

    # Batch fetch revocation info (single query instead of N+1)
    revocation_map = await token_service.get_token_revocations_batch([t.jti for t in tokens])

    token_data = []
    for token in tokens:
        revocation_info = revocation_map.get(token.jti)
        token_data.append(
            {
                "id": token.id,
                "name": token.name,
                "description": token.description,
                "user_email": token.user_email,
                "team_id": token.team_id,
                "created_at": token.created_at,
                "expires_at": token.expires_at,
                "last_used": token.last_used,
                "is_active": token.is_active,
                "is_revoked": revocation_info is not None,
                "tags": token.tags or [],
                "server_id": token.server_id,
            }
        )

    db.commit()
    return token_data


@router.delete("/tokens/{token_id}", status_code=204)
@require_permission("tokens.revoke", allow_admin_bypass=False)
async def admin_revoke_token(
    token_id: str,
    current_user=Depends(get_current_user_with_permissions),
    db: Session = Depends(get_db),
) -> None:
    """Revoke a token from the admin UI.

    This endpoint uses the admin CSRF protection already enforced by the admin router.
    """
    token_service = TokenCatalogService(db)
    success = await token_service.revoke_token(
        token_id=token_id,
        user_email=current_user["email"],
        revoked_by=current_user["email"],
        reason="Revoked by user via admin interface",
    )
    if not success:
        raise HTTPException(status_code=404, detail="Token not found")

    db.commit()
