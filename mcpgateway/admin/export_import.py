# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/admin/export_import.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Admin UI configuration export and import routes: full export, selective export,
import preview, import apply, and import status.
"""

# Standard
from datetime import datetime
import logging
from typing import Any, Optional

# Third-Party
from fastapi import APIRouter, Depends, HTTPException, Request, Response
import orjson
from sqlalchemy.orm import Session

# First-Party
from mcpgateway.admin.common import _read_request_json, export_service, import_service
from mcpgateway.admin.security import enforce_admin_csrf
from mcpgateway.auth_context import configuration_export_includes_roots, import_envelope_includes_roots, selective_selection_includes_roots
from mcpgateway.config import settings
from mcpgateway.db import get_db
from mcpgateway.middleware.rbac import _ACCESS_DENIED_MSG, get_current_user_with_permissions, require_permission
from mcpgateway.services.export_service import ExportError
from mcpgateway.services.import_service import ConflictStrategy, ImportError as ImportServiceError, ImportValidationError
from mcpgateway.utils.orjson_response import ORJSONResponse

LOGGER: logging.Logger = logging.getLogger("mcpgateway.admin")

# mcpgateway.admin (__init__) appends this router's routes to admin_router, so the
# prefix, tags, and CSRF dependency must mirror admin_router exactly.
router = APIRouter(
    prefix="/admin",
    tags=["Admin UI"],
    dependencies=[Depends(enforce_admin_csrf)],
)


async def _require_unrestricted_root_admin(request: Optional[Request], user: Any, db: Session) -> None:
    """Require unrestricted platform-admin authority for global configuration.

    ``is_unrestricted_platform_admin`` is read from mcpgateway.admin because
    tests replace it there.
    """
    # First-Party
    import mcpgateway.admin as _admin  # pylint: disable=import-outside-toplevel

    if not await _admin.is_unrestricted_platform_admin(request, user, db):
        raise HTTPException(status_code=403, detail=_ACCESS_DENIED_MSG)


@router.get("/export/configuration")
@require_permission("admin.system_config", allow_admin_bypass=False)
async def admin_export_configuration(
    request: Request,  # pylint: disable=unused-argument
    types: Optional[str] = None,
    exclude_types: Optional[str] = None,
    tags: Optional[str] = None,
    include_inactive: bool = False,
    include_dependencies: bool = True,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    """
    Export gateway configuration via Admin UI.

    Args:
        request: FastAPI request object for extracting root path
        types: Comma-separated entity types to include
        exclude_types: Comma-separated entity types to exclude
        tags: Comma-separated tags to filter by
        include_inactive: Include inactive entities
        include_dependencies: Include dependent entities
        db: Database session
        user: Authenticated user

    Returns:
        JSON file download with configuration export

    Raises:
        HTTPException: If export fails
    """
    try:
        LOGGER.info(f"Admin user {user} requested configuration export")

        # Parse parameters
        include_types = None
        if types:
            include_types = [t.strip() for t in types.split(",") if t.strip()]

        exclude_types_list = None
        if exclude_types:
            exclude_types_list = [t.strip() for t in exclude_types.split(",") if t.strip()]

        tags_list = None
        if tags:
            tags_list = [t.strip() for t in tags.split(",") if t.strip()]

        if configuration_export_includes_roots(include_types, exclude_types_list):
            await _require_unrestricted_root_admin(request, user, db)

        # Extract username from user (which could be string or dict with token)
        username = user if isinstance(user, str) else user.get("username", "unknown")

        # Get root path for URL construction - prefer configured APP_ROOT_PATH
        root_path = settings.app_root_path

        # Perform export
        export_data = await export_service.export_configuration(
            db=db,
            include_types=include_types,
            exclude_types=exclude_types_list,
            tags=tags_list,
            include_inactive=include_inactive,
            include_dependencies=include_dependencies,
            exported_by=username,
            root_path=root_path,
        )

        # Generate filename
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        filename = f"mcpgateway-config-export-{timestamp}.json"

        # Return as downloadable file
        content = orjson.dumps(export_data, option=orjson.OPT_INDENT_2).decode()
        return Response(
            content=content,
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
            },
        )

    except ExportError as e:
        LOGGER.error(f"Admin export failed for user {user}: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        LOGGER.error(f"Unexpected admin export error for user {user}: {str(e)}")
        raise HTTPException(status_code=500, detail="Export failed")


@router.post("/export/selective")
@require_permission("admin.system_config", allow_admin_bypass=False)
async def admin_export_selective(request: Request, db: Session = Depends(get_db), user=Depends(get_current_user_with_permissions)):
    """
    Export selected entities via Admin UI with entity selection.

    Args:
        request: FastAPI request object
        db: Database session
        user: Authenticated user

    Returns:
        JSON file download with selective export data

    Raises:
        HTTPException: If export fails

    Expects JSON body with entity selections:
    {
        "entity_selections": {
            "tools": ["tool1", "tool2"],
            "servers": ["server1"]
        },
        "include_dependencies": true
    }
    """
    try:
        LOGGER.info(f"Admin user {user} requested selective configuration export")

        body = await _read_request_json(request)
        entity_selections = body.get("entity_selections", {})
        include_dependencies = body.get("include_dependencies", True)

        if selective_selection_includes_roots(entity_selections):
            await _require_unrestricted_root_admin(request, user, db)

        # Extract username from user (which could be string or dict with token)
        username = user if isinstance(user, str) else user.get("username", "unknown")

        # Get root path for URL construction - prefer configured APP_ROOT_PATH
        root_path = settings.app_root_path

        # Perform selective export
        export_data = await export_service.export_selective(db=db, entity_selections=entity_selections, include_dependencies=include_dependencies, exported_by=username, root_path=root_path)

        # Generate filename
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        filename = f"mcpgateway-selective-export-{timestamp}.json"

        # Return as downloadable file
        content = orjson.dumps(export_data, option=orjson.OPT_INDENT_2).decode()
        return Response(
            content=content,
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
            },
        )

    except ExportError as e:
        LOGGER.error(f"Admin selective export failed for user {user}: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        LOGGER.error(f"Unexpected admin selective export error for user {user}: {str(e)}")
        raise HTTPException(status_code=500, detail="Export failed")


@router.post("/import/preview")
@require_permission("admin.system_config", allow_admin_bypass=False)
async def admin_import_preview(request: Request, db: Session = Depends(get_db), user=Depends(get_current_user_with_permissions)):
    """
    Preview import file to show available items for selective import.

    Args:
        request: FastAPI request object with import file data
        db: Database session
        user: Authenticated user

    Returns:
        JSON response with categorized import preview data

    Raises:
        HTTPException: 400 for invalid JSON or missing data field, validation errors;
                      500 for unexpected preview failures

    Expects JSON body:
    {
        "data": { ... }  // The import file content
    }
    """
    try:
        LOGGER.info(f"Admin import preview requested by user: {user}")

        # Parse request data
        try:
            data = await _read_request_json(request)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid JSON in request body")

        # Extract import data
        import_data = data.get("data")
        if not import_data:
            raise HTTPException(status_code=400, detail="Missing 'data' field with import content")

        if import_envelope_includes_roots(import_data):
            await _require_unrestricted_root_admin(request, user, db)

        # Validate user permissions for import preview
        username = user if isinstance(user, str) else user.get("username", "unknown")
        LOGGER.info(f"Processing import preview for user: {username}")

        # Generate preview
        preview_data = await import_service.preview_import(db=db, import_data=import_data)

        return ORJSONResponse(content={"success": True, "preview": preview_data, "message": f"Import preview generated. Found {preview_data['summary']['total_items']} total items."})

    except ImportValidationError as e:
        LOGGER.error(f"Import validation failed for user {user}: {str(e)}")
        raise HTTPException(status_code=400, detail="Invalid import data")
    except HTTPException:
        raise
    except Exception as e:
        LOGGER.error(f"Import preview failed for user {user}: {str(e)}")
        raise HTTPException(status_code=500, detail="Preview failed")


@router.post("/import/configuration")
@require_permission("admin.system_config", allow_admin_bypass=False)
async def admin_import_configuration(request: Request, db: Session = Depends(get_db), user=Depends(get_current_user_with_permissions)):
    """
    Import configuration via Admin UI.

    Args:
        request: FastAPI request object
        db: Database session
        user: Authenticated user

    Returns:
        JSON response with import status

    Raises:
        HTTPException: If import fails

    Expects JSON body with import data and options:
    {
        "import_data": { ... },
        "conflict_strategy": "update",
        "dry_run": false,
        "rekey_secret": "optional-new-secret",  # pragma: allowlist secret
        "selected_entities": { ... }
    }
    """
    try:
        LOGGER.info(f"Admin user {user} requested configuration import")

        body = await _read_request_json(request)
        import_data = body.get("import_data")
        if not import_data:
            raise HTTPException(status_code=400, detail="Missing import_data in request body")

        conflict_strategy_str = body.get("conflict_strategy", "update")
        dry_run = body.get("dry_run", False)
        rekey_secret = body.get("rekey_secret")
        selected_entities = body.get("selected_entities")

        if import_envelope_includes_roots(import_data, selected_entities):
            await _require_unrestricted_root_admin(request, user, db)

        # Validate conflict strategy
        try:
            conflict_strategy = ConflictStrategy(conflict_strategy_str.lower())
        except ValueError:
            allowed = [s.value for s in ConflictStrategy.__members__.values()]
            raise HTTPException(status_code=400, detail=f"Invalid conflict strategy. Must be one of: {allowed}")

        # Extract username from user (which could be string or dict with token)
        username = user if isinstance(user, str) else user.get("username", "unknown")

        # Perform import
        status = await import_service.import_configuration(
            db=db, import_data=import_data, conflict_strategy=conflict_strategy, dry_run=dry_run, rekey_secret=rekey_secret, imported_by=username, selected_entities=selected_entities
        )

        return ORJSONResponse(content=status.to_dict())

    except ImportServiceError as e:
        LOGGER.error(f"Admin import failed for user {user}: {str(e)}")
        raise HTTPException(status_code=400, detail="Import failed")
    except HTTPException:
        raise
    except Exception as e:
        LOGGER.error(f"Unexpected admin import error for user {user}: {str(e)}")
        raise HTTPException(status_code=500, detail="Import failed")


@router.get("/import/status/{import_id}")
@require_permission("admin.system_config", allow_admin_bypass=False)
async def admin_get_import_status(import_id: str, user=Depends(get_current_user_with_permissions), _db: Session = Depends(get_db)):
    """Get import status via Admin UI.

    Args:
        import_id: Import operation ID
        user: Authenticated user
        _db: Database session for permission checks.

    Returns:
        JSON response with import status

    Raises:
        HTTPException: If import not found
    """
    LOGGER.debug(f"Admin user {user} requested import status for {import_id}")

    status = import_service.get_import_status(import_id)
    if not status:
        raise HTTPException(status_code=404, detail=f"Import {import_id} not found")

    return ORJSONResponse(content=status.to_dict())


@router.get("/import/status")
@require_permission("admin.system_config", allow_admin_bypass=False)
async def admin_list_import_statuses(user=Depends(get_current_user_with_permissions), _db: Session = Depends(get_db)):
    """List all import statuses via Admin UI.

    Args:
        user: Authenticated user
        _db: Database session for permission checks.

    Returns:
        JSON response with list of import statuses
    """
    LOGGER.debug(f"Admin user {user} requested all import statuses")

    statuses = import_service.list_import_statuses()
    return ORJSONResponse(content=[status.to_dict() for status in statuses])
