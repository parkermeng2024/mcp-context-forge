# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/admin/tools_import.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Admin UI tools bulk import route.
"""

# Standard
import logging
from typing import Any, Dict, cast as typing_cast
import uuid

# Third-Party
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
import orjson
from pydantic import ValidationError
from pydantic_core import ValidationError as CoreValidationError
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.datastructures import UploadFile as StarletteUploadFile

# First-Party
from mcpgateway.admin.common import _read_request_json, tool_service
from mcpgateway.admin.security import enforce_admin_csrf, rate_limit
from mcpgateway.config import settings
from mcpgateway.db import get_db
from mcpgateway.middleware.rbac import get_current_user_with_permissions, require_permission
from mcpgateway.schemas import ToolCreate
from mcpgateway.services.tool_service import ToolError
from mcpgateway.utils.error_formatter import ErrorFormatter
from mcpgateway.utils.metadata_capture import MetadataCapture
from mcpgateway.utils.orjson_response import ORJSONResponse

LOGGER: logging.Logger = logging.getLogger("mcpgateway.admin")

# mcpgateway.admin (__init__) appends this router's routes to admin_router, so the
# prefix, tags, and CSRF dependency must mirror admin_router exactly.
router = APIRouter(
    prefix="/admin",
    tags=["Admin UI"],
    dependencies=[Depends(enforce_admin_csrf)],
)


@router.post("/tools/import/")
@router.post("/tools/import")
@require_permission("tools.create", allow_admin_bypass=False)
@rate_limit(requests_per_minute=settings.mcpgateway_bulk_import_rate_limit)
async def admin_import_tools(
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> JSONResponse:
    """Bulk import multiple tools in a single request.

    Accepts a JSON array of tool definitions and registers them individually.
    Provides per-item validation and error reporting without failing the entire batch.

    Args:
        request: FastAPI Request containing the tools data
        db: Database session
        user: Authenticated username

    Returns:
        JSONResponse with success status, counts, and details of created/failed tools

    Raises:
        HTTPException: For authentication or rate limiting failures
    """
    # Check if bulk import is enabled
    if not settings.mcpgateway_bulk_import_enabled:
        LOGGER.warning("Bulk import attempted but feature is disabled")
        raise HTTPException(status_code=403, detail="Bulk import feature is disabled. Enable MCPGATEWAY_BULK_IMPORT_ENABLED to use this endpoint.")

    LOGGER.debug("bulk tool import: user=%s", user)
    try:
        # ---------- robust payload parsing ----------
        ctype = (request.headers.get("content-type") or "").lower()
        if "application/json" in ctype:
            try:
                payload = await _read_request_json(request)
            except Exception as ex:
                LOGGER.exception("Invalid JSON body")
                return ORJSONResponse({"success": False, "message": f"Invalid JSON: {ex}"}, status_code=422)
        else:
            try:
                form = await request.form()
            except Exception as ex:
                LOGGER.exception("Invalid form body")
                return ORJSONResponse({"success": False, "message": f"Invalid form data: {ex}"}, status_code=422)
            # Check for file upload first
            if "tools_file" in form:
                file = form["tools_file"]
                if isinstance(file, StarletteUploadFile):
                    content = await file.read()
                    try:
                        payload = orjson.loads(content.decode("utf-8"))
                    except (orjson.JSONDecodeError, UnicodeDecodeError) as ex:
                        LOGGER.exception("Invalid JSON file")
                        return ORJSONResponse({"success": False, "message": f"Invalid JSON file: {ex}"}, status_code=422)
                else:
                    return ORJSONResponse({"success": False, "message": "Invalid file upload"}, status_code=422)
            else:
                # Check for JSON in form fields
                raw_val = form.get("tools") or form.get("tools_json") or form.get("json") or form.get("payload")
                raw = raw_val if isinstance(raw_val, str) else None
                if not raw:
                    return ORJSONResponse({"success": False, "message": "Missing tools/tools_json/json/payload form field."}, status_code=422)
                try:
                    payload = orjson.loads(raw)
                except Exception as ex:
                    LOGGER.exception("Invalid JSON in form field")
                    return ORJSONResponse({"success": False, "message": f"Invalid JSON: {ex}"}, status_code=422)

        if not isinstance(payload, list):
            return ORJSONResponse({"success": False, "message": "Payload must be a JSON array of tools."}, status_code=422)

        max_batch = settings.mcpgateway_bulk_import_max_tools
        if len(payload) > max_batch:
            return ORJSONResponse({"success": False, "message": f"Too many tools ({len(payload)}). Max {max_batch}."}, status_code=413)

        created, errors = [], []

        # ---------- import loop ----------
        # Generate import batch ID for this bulk operation
        import_batch_id = str(uuid.uuid4())

        # Extract base metadata for bulk import
        base_metadata = MetadataCapture.extract_creation_metadata(request, user, import_batch_id=import_batch_id)
        for i, item in enumerate(payload):
            name = (item or {}).get("name")
            try:
                tool = ToolCreate(**item)  # pydantic validation
                await tool_service.register_tool(
                    db,
                    tool,
                    created_by=base_metadata["created_by"],
                    created_from_ip=base_metadata["created_from_ip"],
                    created_via="import",  # Override to show this is bulk import
                    created_user_agent=base_metadata["created_user_agent"],
                    import_batch_id=import_batch_id,
                    federation_source=base_metadata["federation_source"],
                )
                created.append({"index": i, "name": name})
            except IntegrityError as ex:
                # The formatter can itself throw; guard it.
                try:
                    formatted = ErrorFormatter.format_database_error(ex)
                except Exception:
                    formatted = {"message": str(ex)}
                errors.append({"index": i, "name": name, "error": formatted})
            except (ValidationError, CoreValidationError) as ex:
                # Ditto: guard the formatter
                try:
                    formatted = ErrorFormatter.format_validation_error(ex)
                except Exception:
                    formatted = {"message": str(ex)}
                errors.append({"index": i, "name": name, "error": formatted})
            except ToolError as ex:
                errors.append({"index": i, "name": name, "error": {"message": str(ex)}})
            except Exception as ex:
                LOGGER.exception("Unexpected error importing tool %r at index %d", name, i)
                errors.append({"index": i, "name": name, "error": {"message": str(ex)}})

        # Format response to match both frontend and test expectations
        response_data = {
            "success": len(errors) == 0,
            # New format for frontend
            "imported": len(created),
            "failed": len(errors),
            "total": len(payload),
            # Original format for tests
            "created_count": len(created),
            "failed_count": len(errors),
            "created": created,
            "errors": errors,
            # Detailed format for frontend
            "details": {
                "success": [item["name"] for item in created if item.get("name")],
                "failed": [{"name": item["name"], "error": item["error"].get("message") or item["error"].get("detail", str(item["error"]))} for item in errors],
            },
        }

        rd = typing_cast(Dict[str, Any], response_data)
        if len(errors) == 0:
            rd["message"] = f"Successfully imported all {len(created)} tools"
        else:
            rd["message"] = f"Imported {len(created)} of {len(payload)} tools. {len(errors)} failed."

        return ORJSONResponse(
            response_data,
            status_code=200,  # Always return 200, success field indicates if all succeeded
        )

    except HTTPException:
        # let FastAPI semantics (e.g., auth) pass through
        raise
    except Exception as ex:
        # absolute catch-all: report instead of crashing
        LOGGER.exception("Fatal error in admin_import_tools")
        return ORJSONResponse({"success": False, "message": str(ex)}, status_code=500)
