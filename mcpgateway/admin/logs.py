# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/admin/logs.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Admin UI log routes: log listing, live SSE streaming, log file download, and
log export.
"""

# Standard
import csv
from datetime import datetime
from email.utils import formatdate
import hashlib
import io
import logging
import os
from pathlib import Path
import re
from typing import Any, Dict, Optional, cast as typing_cast
import urllib.parse

# Third-Party
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import StreamingResponse
import orjson
from sqlalchemy.orm import Session
from starlette.background import BackgroundTask

# First-Party
from mcpgateway.admin.security import enforce_admin_csrf
from mcpgateway.common.models import LogLevel
from mcpgateway.common.query_params import QueryExportFormatAliased
from mcpgateway.config import settings
from mcpgateway.db import get_db
from mcpgateway.middleware.rbac import _ACCESS_DENIED_MSG, get_current_user_with_permissions, require_permission
from mcpgateway.services.logging_service import LoggingService
from mcpgateway.utils.log_sanitizer import sanitize_for_log
from mcpgateway.utils.paths import is_path_within, open_confined

LOGGER: logging.Logger = logging.getLogger("mcpgateway.admin")

# mcpgateway.admin (__init__) appends this router's routes to admin_router, so the
# prefix, tags, and CSRF dependency must mirror admin_router exactly.
router = APIRouter(
    prefix="/admin",
    tags=["Admin UI"],
    dependencies=[Depends(enforce_admin_csrf)],
)


def _get_logging_service() -> Optional[LoggingService]:
    """Return the mutable logging-service anchor owned by mcpgateway.admin.

    ``set_logging_service()`` replaces ``mcpgateway.admin.logging_service`` at
    startup, so read the anchor from the package instead of binding it here.
    """
    # First-Party
    # The back-reference to mcpgateway.admin is deliberate: the package owns the
    # anchor and appends this router, so the import cannot move to module scope.
    import mcpgateway.admin as _admin  # pylint: disable=import-outside-toplevel,cyclic-import

    return typing_cast(Any, _admin.logging_service)


####################
# Log Endpoints
####################


@router.get("/logs")
@require_permission("admin.system_config", allow_admin_bypass=False)
async def admin_get_logs(
    entity_type: Optional[str] = None,
    entity_id: Optional[str] = None,
    level: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    request_id: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    order: str = "desc",
    user=Depends(get_current_user_with_permissions),  # pylint: disable=unused-argument
    _db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Get filtered log entries from the in-memory buffer.

    Args:
        entity_type: Filter by entity type (tool, resource, server, gateway)
        entity_id: Filter by entity ID
        level: Minimum log level (debug, info, warning, error, critical)
        start_time: ISO format start time
        end_time: ISO format end time
        request_id: Filter by request ID
        search: Search in message text
        limit: Maximum number of results (default 100, max 1000)
        offset: Number of results to skip
        order: Sort order (asc or desc)
        user: Authenticated user
        _db: Database session for permission checks.

    Returns:
        Dictionary with logs and metadata

    Raises:
        HTTPException: If validation fails or service unavailable
    """
    # Get log storage from logging service
    storage = typing_cast(Any, _get_logging_service()).get_storage()
    if not storage:
        return {"logs": [], "total": 0, "stats": {}}

    # Parse timestamps if provided
    start_dt = None
    end_dt = None
    if start_time:
        try:
            start_dt = datetime.fromisoformat(start_time.replace("Z", "+00:00"))
        except ValueError:
            raise HTTPException(400, f"Invalid start_time format: {start_time}")

    if end_time:
        try:
            end_dt = datetime.fromisoformat(end_time.replace("Z", "+00:00"))
        except ValueError:
            raise HTTPException(400, f"Invalid end_time format: {end_time}")

    # Parse log level
    log_level = None
    if level:
        try:
            log_level = LogLevel(level.lower())
        except ValueError:
            raise HTTPException(400, f"Invalid log level: {level}")

    # Limit max results
    limit = min(limit, 1000)

    # Get filtered logs
    logs = await storage.get_logs(
        entity_type=entity_type,
        entity_id=entity_id,
        level=log_level,
        start_time=start_dt,
        end_time=end_dt,
        request_id=request_id,
        search=search,
        limit=limit,
        offset=offset,
        order=order,
    )

    # Get statistics
    stats = storage.get_stats()

    return {
        "logs": logs,
        "total": stats.get("total_logs", 0),
        "stats": stats,
    }


@router.get("/logs/stream")
@require_permission("admin.system_config", allow_admin_bypass=False)
async def admin_stream_logs(
    request: Request,
    entity_type: Optional[str] = None,
    entity_id: Optional[str] = None,
    level: Optional[str] = None,
    user=Depends(get_current_user_with_permissions),  # pylint: disable=unused-argument
    _db: Session = Depends(get_db),
):
    """Stream real-time log updates via Server-Sent Events.

    Args:
        request: FastAPI request object
        entity_type: Filter by entity type
        entity_id: Filter by entity ID
        level: Minimum log level
        user: Authenticated user
        _db: Database session for permission checks.

    Returns:
        SSE response with real-time log updates

    Raises:
        HTTPException: If log level is invalid or service unavailable
    """
    # Get log storage from logging service
    storage = typing_cast(Any, _get_logging_service()).get_storage()
    if not storage:
        raise HTTPException(503, "Log storage not available")

    # Parse log level filter
    min_level = None
    if level:
        try:
            min_level = LogLevel(level.lower())
        except ValueError:
            raise HTTPException(400, f"Invalid log level: {level}")

    async def generate():
        """Generate SSE events for log streaming.

        Yields:
            Formatted SSE events containing log data
        """
        try:
            async for event in storage.subscribe():
                # Check if client disconnected
                if await request.is_disconnected():
                    break

                # Apply filters
                log_data = event.get("data", {})

                # Entity type filter
                if entity_type and log_data.get("entity_type") != entity_type:
                    continue

                # Entity ID filter
                if entity_id and log_data.get("entity_id") != entity_id:
                    continue

                # Level filter
                if min_level:
                    log_level = log_data.get("level")
                    if log_level:
                        try:
                            if not storage._meets_level_threshold(LogLevel(log_level), min_level):  # pylint: disable=protected-access
                                continue
                        except ValueError:
                            continue

                # Send SSE event
                yield f"data: {orjson.dumps(event).decode()}\n\n"

        except Exception as e:
            LOGGER.error(f"Error in log streaming: {e}")
            yield f"event: error\ndata: {orjson.dumps({'error': str(e)}).decode()}\n\n"

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # Disable Nginx buffering
        },
    )


@router.get("/logs/file")
@require_permission("admin.system_config", allow_admin_bypass=False)
async def admin_get_log_file(
    request: Request,
    filename: Optional[str] = None,
    user=Depends(get_current_user_with_permissions),  # pylint: disable=unused-argument
    _db: Session = Depends(get_db),
):
    """Download log file.

    Args:
        request: Incoming request, used to read a conditional/range header for resumable downloads.
        filename: Specific log file to download (optional)
        user: Authenticated user
        _db: Database session for permission checks.

    Returns:
        File download response or list of available files

    Raises:
        HTTPException: If file doesn't exist or access denied
    """
    # Check if file logging is enabled
    if not settings.log_to_file or not settings.log_file:
        raise HTTPException(404, "File logging is not enabled")

    # Determine log directory
    log_dir = Path(settings.log_folder) if settings.log_folder else Path(".")

    if filename:
        # Download specific file.
        #
        # Security: the download is confined to LOG_FOLDER by two independent checks.
        #
        #   1. Reject obviously hostile input *before* joining it onto the log
        #      directory: absolute paths and drive/UNC anchors would make ``/`` discard
        #      log_dir entirely, ``..`` segments walk upwards, and a NUL byte can
        #      truncate the path at the OS layer.
        #   2. Resolve the joined path (collapsing symlinks and any remaining relative
        #      segments) and require it to stay inside the resolved log directory.
        #
        # Check 2 is the real control; ``is_path_within`` compares whole path
        # components, so a sibling directory that merely shares a textual prefix with
        # LOG_FOLDER is rejected.
        if "\x00" in filename:
            raise HTTPException(400, "Invalid file path")

        candidate = Path(filename)
        if candidate.is_absolute() or candidate.drive or candidate.root or ".." in candidate.parts:
            raise HTTPException(400, "Invalid file path")

        try:
            file_path = (log_dir / candidate).resolve()
            log_dir_resolved = log_dir.resolve()
        except (OSError, ValueError, RuntimeError):
            raise HTTPException(400, "Invalid file path")

        if not is_path_within(file_path, log_dir_resolved):
            raise HTTPException(403, _ACCESS_DENIED_MSG)

        # Check if it's a log file (name check only; no filesystem access yet)
        if not (file_path.suffix in [".log", ".jsonl", ".json"] or file_path.stem.startswith(Path(settings.log_file).stem)):
            raise HTTPException(403, "Not a log file")

        # Open the verified fd directly via a component-by-component confined open
        # instead of handing a pathname to FileResponse, which reopens the path when it
        # streams. A process able to write into log_dir_resolved could otherwise rename
        # the checked file away and put a symlink in its place between the confinement
        # check above and that later reopen (TOCTOU), causing this privileged endpoint
        # to stream an attacker-chosen target. On POSIX, open_confined() resolves and
        # opens each path component with O_NOFOLLOW relative to its already-open
        # parent, so the fd it returns refers to exactly the inode that was validated.
        # On platforms without that atomic chaining (Windows), it falls back to a
        # per-component symlink/reparse-point rejection that is not atomic but still
        # rejects every reparse point present at check time.
        try:
            file_fd, file_stat = open_confined(log_dir_resolved, candidate)
        except FileNotFoundError:
            raise HTTPException(404, f"Log file not found: {filename}")
        except (OSError, ValueError) as e:
            LOGGER.warning("Log file access denied for %s: %s", sanitize_for_log(filename), sanitize_for_log(e))
            raise HTTPException(403, _ACCESS_DENIED_MSG)
        except Exception as e:
            LOGGER.error("Error opening log file for download: %s", sanitize_for_log(e))
            raise HTTPException(500, f"Error reading file for download: {e}")

        LOGGER.info(f"Serving log file download: {file_path.name} ({file_stat.st_size} bytes)")

        chunk_size = 64 * 1024
        quoted_name = urllib.parse.quote(file_path.name)
        content_disposition = f"attachment; filename*=utf-8''{quoted_name}" if quoted_name != file_path.name else f'attachment; filename="{file_path.name}"'

        file_size = file_stat.st_size
        last_modified = formatdate(file_stat.st_mtime, usegmt=True)
        etag = f'"{hashlib.md5(f"{file_stat.st_mtime}-{file_size}".encode(), usedforsecurity=False).hexdigest()}"'  # nosec B324 - cache validator, not a security control

        # file_fd was validated and opened by open_confined() above (see the comment on that
        # call); wrap it in a Python file object now, outside the generator, so a single owner
        # (this handle) exists regardless of whether the generator body ever runs. Starlette can
        # cancel a StreamingResponse before its body generator is first iterated (e.g. the client
        # disconnects immediately) -- in that case the generator's own `finally` never executes,
        # so the BackgroundTask below is the fallback that guarantees the fd is closed. handle.close()
        # is idempotent, so running both paths is safe.
        handle = os.fdopen(file_fd, "rb")

        headers = {
            "Content-Disposition": content_disposition,
            "Accept-Ranges": "bytes",
            "Last-Modified": last_modified,
            "ETag": etag,
        }

        range_header = request.headers.get("range")
        if_range = request.headers.get("if-range")
        start, end = 0, file_size
        status_code = 200
        if range_header and (if_range is None or if_range in (etag, last_modified)):
            range_unit, has_value, spec_value = range_header.strip().partition("=")
            if not has_value or range_unit.strip().lower() != "bytes":
                handle.close()
                raise HTTPException(400, "Malformed Range header")
            if "," in spec_value:
                # Multiple ranges (e.g. "bytes=0-1,4-5"): multipart/byteranges responses
                # aren't implemented here. Per RFC 7233 SS3.1, a server may ignore a Range
                # header it can't satisfy the way the client wants and return the full
                # entity instead of erroring, so fall through and serve start/end as set
                # above (0, file_size) rather than rejecting the request outright.
                pass
            else:
                range_match = re.fullmatch(r"(\d*)-(\d*)", spec_value)
                if not range_match or not (range_match.group(1) or range_match.group(2)):
                    handle.close()
                    raise HTTPException(400, "Malformed Range header")
                range_start, range_end = range_match.group(1), range_match.group(2)
                try:
                    if range_start:
                        start = int(range_start)
                        end = int(range_end) + 1 if range_end else file_size
                    else:
                        # Suffix range (e.g. "bytes=-500"): last N bytes of the file.
                        start = max(file_size - int(range_end), 0)
                        end = file_size
                except ValueError:
                    # int() enforces sys.get_int_max_str_digits(); an oversized numeric
                    # range value hits that limit and must not surface as a 500.
                    handle.close()
                    raise HTTPException(400, "Malformed Range header")
                if start >= file_size or start >= end:
                    handle.close()
                    raise HTTPException(416, "Requested range not satisfiable", headers={"Content-Range": f"bytes */{file_size}"})
                end = min(end, file_size)
                status_code = 206
                headers["Content-Range"] = f"bytes {start}-{end - 1}/{file_size}"

        headers["Content-Length"] = str(end - start)
        handle.seek(start)
        remaining = end - start

        def _iter_log_file():
            """Yield the requested byte range in chunks, closing the fd when done."""
            nonlocal remaining
            try:
                while remaining > 0:
                    chunk = handle.read(min(chunk_size, remaining))
                    if not chunk:
                        break
                    remaining -= len(chunk)
                    yield chunk
            finally:
                handle.close()

        return StreamingResponse(
            _iter_log_file(),
            status_code=status_code,
            media_type="application/octet-stream",
            headers=headers,
            background=BackgroundTask(handle.close),
        )

    # List available log files
    log_files = []

    try:
        # Main log file
        main_log = log_dir / settings.log_file
        if main_log.exists():
            stat = main_log.stat()
            log_files.append(
                {
                    "name": main_log.name,
                    "size": stat.st_size,
                    "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    "type": "main",
                }
            )

            # Rotated log files
            if settings.log_rotation_enabled:
                pattern = f"{Path(settings.log_file).stem}.*"
                for file in log_dir.glob(pattern):
                    if file.is_file() and file.name != main_log.name:  # Exclude main log file
                        stat = file.stat()
                        log_files.append(
                            {
                                "name": file.name,
                                "size": stat.st_size,
                                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                                "type": "rotated",
                            }
                        )

            # Storage log file (JSON lines)
            storage_log = log_dir / f"{Path(settings.log_file).stem}_storage.jsonl"
            if storage_log.exists():
                stat = storage_log.stat()
                log_files.append(
                    {
                        "name": storage_log.name,
                        "size": stat.st_size,
                        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                        "type": "storage",
                    }
                )

        # Sort by modified time (newest first)
        log_files.sort(key=lambda x: x["modified"], reverse=True)

    except Exception as e:
        LOGGER.error(f"Error listing log files: {e}")
        raise HTTPException(500, f"Error listing log files: {e}")

    return {
        "log_directory": str(log_dir),
        "files": log_files,
        "total": len(log_files),
    }


@router.get("/logs/export")
@require_permission("admin.system_config", allow_admin_bypass=False)
async def admin_export_logs(
    export_format: QueryExportFormatAliased = "json",
    entity_type: Optional[str] = None,
    entity_id: Optional[str] = None,
    level: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    request_id: Optional[str] = None,
    search: Optional[str] = None,
    user=Depends(get_current_user_with_permissions),  # pylint: disable=unused-argument
    _db: Session = Depends(get_db),
):
    """Export filtered logs in JSON or CSV format.

    Args:
        export_format: Export format (json or csv)
        entity_type: Filter by entity type
        entity_id: Filter by entity ID
        level: Minimum log level
        start_time: ISO format start time
        end_time: ISO format end time
        request_id: Filter by request ID
        search: Search in message text
        user: Authenticated user
        _db: Database session for permission checks.

    Returns:
        File download response with exported logs

    Raises:
        HTTPException: If validation fails or export format invalid
    """
    # Standard
    # Validate format
    if export_format not in ["json", "csv"]:
        raise HTTPException(400, f"Invalid format: {export_format}. Use 'json' or 'csv'")

    # Get log storage from logging service
    storage = typing_cast(Any, _get_logging_service()).get_storage()
    if not storage:
        raise HTTPException(503, "Log storage not available")

    # Parse timestamps if provided
    start_dt = None
    end_dt = None
    if start_time:
        try:
            start_dt = datetime.fromisoformat(start_time.replace("Z", "+00:00"))
        except ValueError:
            raise HTTPException(400, f"Invalid start_time format: {start_time}")

    if end_time:
        try:
            end_dt = datetime.fromisoformat(end_time.replace("Z", "+00:00"))
        except ValueError:
            raise HTTPException(400, f"Invalid end_time format: {end_time}")

    # Parse log level
    log_level = None
    if level:
        try:
            log_level = LogLevel(level.lower())
        except ValueError:
            raise HTTPException(400, f"Invalid log level: {level}")

    # Get all matching logs (no pagination for export)
    logs = await storage.get_logs(
        entity_type=entity_type,
        entity_id=entity_id,
        level=log_level,
        start_time=start_dt,
        end_time=end_dt,
        request_id=request_id,
        search=search,
        limit=10000,  # Reasonable max for export
        offset=0,
        order="desc",
    )

    # Generate filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"logs_export_{timestamp}.{export_format}"

    if export_format == "json":
        # Export as JSON
        content = orjson.dumps(logs, default=str, option=orjson.OPT_INDENT_2).decode()
        return Response(
            content=content,
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
            },
        )

    # CSV format
    # Create CSV content
    output = io.StringIO()

    if logs:
        # Use first log to determine columns
        fieldnames = [
            "timestamp",
            "level",
            "entity_type",
            "entity_id",
            "entity_name",
            "message",
            "logger",
            "request_id",
        ]

        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()

        for log in logs:
            # Flatten the log entry for CSV
            row = {k: log.get(k, "") for k in fieldnames}
            writer.writerow(row)

    content = output.getvalue()

    return Response(
        content=content,
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )
