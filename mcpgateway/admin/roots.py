# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/admin/roots.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Admin UI root routes: search, export, detail, add, update, and delete.
"""

# Standard
from datetime import datetime
import logging
from typing import Any, Optional
import orjson

# Third-Party
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.orm import Session

# First-Party
from mcpgateway.admin.common import _build_admin_redirect, _build_search_response, _normalize_search_query, root_service
from mcpgateway.admin.security import enforce_admin_csrf
from mcpgateway.auth_context import get_user_email, is_unrestricted_platform_admin
from mcpgateway.config import settings
from mcpgateway.db import get_db
from mcpgateway.middleware.rbac import _ACCESS_DENIED_MSG, get_current_user_with_permissions, require_permission
from mcpgateway.services.root_service import RootServiceError, RootServiceNotFoundError, RootServiceValidationError
from mcpgateway.utils.paths import resolve_root_path as _resolve_root_path

LOGGER: logging.Logger = logging.getLogger("mcpgateway.admin")

# mcpgateway.admin (__init__) appends this router's routes to admin_router, so the
# prefix, tags, and CSRF dependency must mirror admin_router exactly.
router = APIRouter(
    prefix="/admin",
    tags=["Admin UI"],
    dependencies=[Depends(enforce_admin_csrf)],
)


async def _require_unrestricted_root_admin(request: Optional[Request], user: Any, db: Session) -> None:
    """Require unrestricted platform-admin authority for global roots."""
    if not await is_unrestricted_platform_admin(request, user, db):
        raise HTTPException(status_code=403, detail=_ACCESS_DENIED_MSG)


@router.get("/roots/search", response_class=JSONResponse)
@require_permission("admin.system_config", allow_admin_bypass=False)
async def admin_search_roots(
    request: Request = None,
    q: str = Query("", max_length=500, description="Search query"),
    limit: int = Query(settings.pagination_default_page_size, ge=1, le=settings.pagination_max_page_size, description="Maximum number of results to return"),
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> dict:
    """Search roots by name or URI.

    Roots are held in-memory by :class:`~mcpgateway.services.root_service.RootService`,
    so this function fetches the full list before filtering. Registered roots are
    typically a small set, making the in-memory scan negligible. If root counts grow
    substantially, consider adding filtering support directly to
    :meth:`~mcpgateway.services.root_service.RootService.list_roots`.

    Args:
        request: Current request object.
        q (str): Free-text search query matched against root name and URI.
        limit (int): Maximum number of results to return.
        db: Database session.
        user: Authenticated user context.

    Returns:
        dict: Unified search payload containing matching roots.

    Examples:
        >>> callable(admin_search_roots)
        True
        >>> admin_search_roots.__name__
        'admin_search_roots'
    """
    await _require_unrestricted_root_admin(request, user, db)
    search_query = _normalize_search_query(q)
    # Defense-in-depth clamp: FastAPI validates ge/le at the HTTP layer, but direct
    # Python calls (e.g. from admin_unified_search) bypass that validation.
    limit = max(1, min(limit, settings.pagination_max_page_size))
    all_roots = await root_service.list_roots()

    results: list[dict[str, Any]] = []
    for r in all_roots:
        if len(results) >= limit:
            break
        uri_str = str(r.uri)
        name_str = r.name or uri_str
        if not search_query or search_query in uri_str.lower() or search_query in name_str.lower():
            results.append({"id": uri_str, "name": name_str, "uri": uri_str})

    LOGGER.debug(f"User {get_user_email(user)} searched roots with query '{search_query}': {len(results)} results")
    return _build_search_response(entity_key="roots", entity_type="roots", items=results, query=search_query, tags="", tag_groups=[])


@router.get("/roots/export")
@require_permission("admin.system_config", allow_admin_bypass=False)
async def admin_export_root(
    uri: str,
    request: Request = None,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    """
    Export a single root configuration as JSON.

    Args:
        uri: Root URI to export (query parameter)
        request: Current request object.
        db: Database session.
        user: Authenticated user

    Returns:
        JSON file download with root configuration

    Raises:
        HTTPException: If root not found or export fails
    """
    try:
        await _require_unrestricted_root_admin(request, user, db)
        LOGGER.info("Admin user %s requested root export", get_user_email(user))

        # Get the root by URI
        root = await root_service.get_root_by_uri(uri)

        # Extract username from user
        username = get_user_email(user)

        # Create export data
        export_data = {
            "exported_at": datetime.now().isoformat(),
            "exported_by": username,
            "export_type": "root",
            "version": "1.0",
            "root": {
                "uri": str(root.uri),
                "name": root.name,
            },
        }

        # Generate filename - sanitize URI for filename
        # Remove protocol and special characters
        safe_uri = uri.replace("://", "_").replace("/", "_").replace("\\", "_")
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        filename = f"root-export-{safe_uri}-{timestamp}.json"

        # Return as downloadable file
        content = orjson.dumps(export_data, option=orjson.OPT_INDENT_2).decode()
        return Response(
            content=content,
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
            },
        )

    except RootServiceNotFoundError as e:
        LOGGER.error(f"Root not found for export by user {get_user_email(user)}: {str(e)}")
        raise HTTPException(status_code=404, detail=str(e))
    except RootServiceValidationError as e:
        raise HTTPException(status_code=400, detail={"message": "Root URI rejected by policy", "reason_code": e.reason_code}) from e
    except HTTPException:
        raise
    except Exception as e:
        LOGGER.error(f"Unexpected root export error for user {get_user_email(user)}: {str(e)}")
        raise HTTPException(status_code=500, detail="Root export failed")


@router.get("/roots/{uri:path}")
@require_permission("admin.system_config", allow_admin_bypass=False)
async def admin_get_root(uri: str, request: Request = None, db: Session = Depends(get_db), user=Depends(get_current_user_with_permissions)) -> dict:
    """Get a specific root by URI via the admin UI.

    This endpoint retrieves details for a specific root URI from the system.
    It requires authentication and logs the operation for audit purposes.

    Args:
        uri (str): The URI of the root to retrieve.
        request: Current request object.
        db: Database session.
        user: Authenticated user dependency.

    Returns:
        dict: A dictionary containing the root information.

    Raises:
        HTTPException: If the root is not found.
        Exception: For any other unexpected errors.

    Examples:
        >>> callable(admin_get_root)
        True
        >>> admin_get_root.__name__
        'admin_get_root'
    """
    await _require_unrestricted_root_admin(request, user, db)
    LOGGER.debug("User %s is retrieving root", get_user_email(user))
    try:
        root = await root_service.get_root_by_uri(uri)
        return root.model_dump(by_alias=True)
    except RootServiceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except RootServiceValidationError as e:
        raise HTTPException(status_code=400, detail={"message": "Root URI rejected by policy", "reason_code": e.reason_code}) from e
    except Exception as e:
        LOGGER.error(f"Error getting root {uri}: {e}")
        raise e


@router.post("/roots")
@require_permission("admin.system_config", allow_admin_bypass=False)
async def admin_add_root(request: Request, user=Depends(get_current_user_with_permissions), db: Session = Depends(get_db)) -> RedirectResponse:
    """Add a new root via the admin UI.

    Expects form fields:
      - uri
      - name (optional)

    Args:
        request: FastAPI request containing form data.
        user: Authenticated user.
        db: Database session for permission checks.

    Returns:
        RedirectResponse: A redirect response to the admin dashboard.

    Examples:
        >>> callable(admin_add_root)
        True
        >>> admin_add_root.__name__
        'admin_add_root'
    """
    error_message = None
    await _require_unrestricted_root_admin(request, user, db)
    user_email = get_user_email(user)
    LOGGER.debug(f"User {user_email} is adding a new root")

    form = await request.form()
    uri = str(form.get("uri", ""))
    name_value = form.get("name")
    name: str | None = None
    if isinstance(name_value, str) and name_value.strip():
        name = name_value.strip()

    try:
        if not uri:
            raise ValueError("URI is required")
        await root_service.add_root(str(uri), name)

    except RootServiceValidationError as e:
        LOGGER.warning("Failed to add root for user %s: reason=%s", user_email, e.reason_code)
        error_message = "Failed to add root. Please check the URI format."
    except RootServiceError:
        LOGGER.warning("Failed to add root for user %s", user_email)
        error_message = "Failed to add root. Please check the URI format."
    except ValueError as e:
        LOGGER.warning(f"Invalid input from user {user_email}: {e}")
        error_message = "Invalid input. Please try again."
    except Exception as e:
        LOGGER.error(f"Error adding root: {e}")
        error_message = "Failed to add root. Please try again."

    root_path = _resolve_root_path(request)
    team_id = str(form.get("team_id", "") or "")
    redirect_url = _build_admin_redirect(root_path, "roots", error=error_message, team_id=team_id)
    return RedirectResponse(redirect_url, status_code=303)


@router.post("/roots/{uri:path}/update")
@require_permission("admin.system_config", allow_admin_bypass=False)
async def admin_update_root(uri: str, request: Request, db: Session = Depends(get_db), user=Depends(get_current_user_with_permissions)) -> RedirectResponse:
    """Update a root via the admin UI.

    This endpoint updates an existing root URI in the system. It expects form
    fields for the new values and requires authentication.

    Expects form fields:
    - name (optional): New name for the root
    - is_inactive_checked: Whether the root should be marked as inactive

    Args:
        uri (str): The URI of the root to update.
        request (Request): FastAPI request object containing form data.
        db: Database session.
        user: Authenticated user dependency.

    Returns:
        RedirectResponse: A redirect response to the roots section of the admin
        dashboard with a status code of 303 (See Other).

    Raises:
        HTTPException: If the root is not found (404) or other errors occur.
        Exception: For any other unexpected errors.

    Examples:
        >>> callable(admin_update_root)
        True
        >>> admin_update_root.__name__
        'admin_update_root'
    """
    await _require_unrestricted_root_admin(request, user, db)
    LOGGER.debug("User %s is updating root", get_user_email(user))

    try:
        form = await request.form()
        name_value = form.get("name")
        name: str | None = None

        if isinstance(name_value, str):
            name = name_value

        await root_service.update_root(uri, name)

        root_path = _resolve_root_path(request)
        is_inactive_checked: str = str(form.get("is_inactive_checked", "false"))
        team_id = str(form.get("team_id", "") or "")
        redirect_url = _build_admin_redirect(root_path, "roots", include_inactive=is_inactive_checked.lower() == "true", team_id=team_id)
        return RedirectResponse(redirect_url, status_code=303)

    except RootServiceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except RootServiceValidationError:
        root_path = _resolve_root_path(request)
        return RedirectResponse(_build_admin_redirect(root_path, "roots", error="Failed to update root. Please check the URI format."), status_code=303)
    except Exception as e:
        LOGGER.error(f"Error updating root {uri}: {e}")
        raise e


@router.post("/roots/{uri:path}/delete")
@require_permission("admin.system_config", allow_admin_bypass=False)
async def admin_delete_root(uri: str, request: Request, user=Depends(get_current_user_with_permissions), db: Session = Depends(get_db)) -> RedirectResponse:
    """
    Delete a root via the admin UI.

    This endpoint removes a registered root URI from the system. The deletion is
    permanent and cannot be undone. It requires authentication and logs the
    operation for audit purposes.

    Args:
        uri (str): The URI of the root to delete.
        request (Request): FastAPI request object (not used directly but required by the route signature).
        user (str): Authenticated user dependency.
        db: Database session for permission checks.

    Returns:
        RedirectResponse: A redirect response to the roots section of the admin
        dashboard with a status code of 303 (See Other).

    Examples:
        >>> callable(admin_delete_root)
        True
        >>> admin_delete_root.__name__
        'admin_delete_root'
    """
    await _require_unrestricted_root_admin(request, user, db)
    LOGGER.debug("User %s is deleting root", get_user_email(user))
    form = await request.form()
    root_path = _resolve_root_path(request)
    is_inactive_checked: str = str(form.get("is_inactive_checked", "false"))
    team_id = str(form.get("team_id", "") or "")
    try:
        await root_service.remove_root(uri)
    except RootServiceValidationError:
        redirect_url = _build_admin_redirect(root_path, "roots", error="Failed to delete root. Please check the URI format.", include_inactive=is_inactive_checked.lower() == "true", team_id=team_id)
        return RedirectResponse(redirect_url, status_code=303)
    redirect_url = _build_admin_redirect(root_path, "roots", include_inactive=is_inactive_checked.lower() == "true", team_id=team_id)
    return RedirectResponse(redirect_url, status_code=303)
