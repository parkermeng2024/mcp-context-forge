# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/admin/observability.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Admin UI observability routes: trace browsing, saved queries, latency metrics, and per-entity usage/performance/error statistics.
"""

# Standard
from collections import defaultdict
from datetime import datetime, timedelta, timezone
import logging
import re
from typing import Dict, List, Optional

# Third-Party
from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import bindparam, case, cast, desc, func, or_, select, String, text
from sqlalchemy.orm import joinedload, Session

# First-Party
from mcpgateway.admin.security import enforce_admin_csrf
from mcpgateway.common.query_params import QueryHttpMethod, QueryStatusFilter, QueryTimeRange, QueryToolName, QueryUserIdentifierNoDescription
from mcpgateway.config import settings
from mcpgateway.db import extract_json_field, get_db, ObservabilitySavedQuery, ObservabilitySpan, ObservabilityTrace, utc_now
from mcpgateway.middleware.rbac import get_current_user_with_permissions, require_permission
from mcpgateway.services.observability_service import ensure_timezone_aware
from mcpgateway.utils.paths import resolve_root_path as _resolve_root_path

LOGGER: logging.Logger = logging.getLogger("mcpgateway.admin")

# mcpgateway.admin (__init__) appends this router's routes to admin_router, so the
# prefix, tags, and CSRF dependency must mirror admin_router exactly.
router = APIRouter(
    prefix="/admin",
    tags=["Admin UI"],
    dependencies=[Depends(enforce_admin_csrf)],
)


def _get_span_entity_performance(
    db: Session,
    cutoff_time: datetime,
    cutoff_time_naive: datetime,
    span_names: List[str],
    json_key: str,
    result_key: str,
    limit: int = 20,
) -> List[dict]:
    """Shared helper to compute performance metrics for spans grouped by a JSON attribute.

    Args:
        db: Database session.
        cutoff_time: Timezone-aware datetime for filtering spans.
        cutoff_time_naive: Naive datetime for SQLite compatibility.
        span_names: List of span names to filter (e.g., ["tool.invoke"]).
        json_key: JSON attribute key to group by (e.g., "tool.name").
        result_key: Key name for the entity in returned dicts (e.g., "tool_name").
        limit: Maximum number of results to return (default: 20).

    Returns:
        List[dict]: List of dicts with entity key and performance metrics (count, avg, min, max, percentiles).

    Raises:
        ValueError: If `json_key` is not a valid identifier (only letters, digits, underscore, dot or hyphen),
            this function will raise a ValueError to prevent unsafe SQL interpolation when using
            PostgreSQL native percentile queries.

    Note:
        Uses PostgreSQL `percentile_cont` when available and enabled via USE_POSTGRESDB_PERCENTILES config,
        otherwise falls back to Python aggregation.
    """
    # Validate json_key to prevent SQL injection in both PostgreSQL and SQLite paths
    if not isinstance(json_key, str) or not re.match(r"^[A-Za-z0-9_.-]+$", json_key):
        raise ValueError("Invalid json_key for percentile query")

    dialect_name = db.get_bind().dialect.name

    # Use database-native percentiles only if enabled in config and using PostgreSQL
    if dialect_name == "postgresql" and settings.use_postgresdb_percentiles:
        # Safe: uses SQLAlchemy's bindparam for the IN-list
        stats_sql = text("""
            SELECT
                (attributes->> :json_key) AS entity,
                COUNT(*) AS count,
                AVG(duration_ms) AS avg_duration_ms,
                MIN(duration_ms) AS min_duration_ms,
                MAX(duration_ms) AS max_duration_ms,
                percentile_cont(0.50) WITHIN GROUP (ORDER BY duration_ms) AS p50,
                percentile_cont(0.90) WITHIN GROUP (ORDER BY duration_ms) AS p90,
                percentile_cont(0.95) WITHIN GROUP (ORDER BY duration_ms) AS p95,
                percentile_cont(0.99) WITHIN GROUP (ORDER BY duration_ms) AS p99
            FROM observability_spans
            WHERE name IN :names
              AND start_time >= :cutoff_time
              AND duration_ms IS NOT NULL
              AND (attributes->> :json_key) IS NOT NULL
            GROUP BY entity
            ORDER BY avg_duration_ms DESC
            LIMIT :limit
            """).bindparams(bindparam("names", expanding=True))

        results = db.execute(
            stats_sql,
            {"cutoff_time": cutoff_time, "limit": limit, "names": span_names, "json_key": json_key},
        ).fetchall()

        items: List[dict] = []
        for row in results:
            items.append(
                {
                    result_key: row.entity,
                    "count": int(row.count) if row.count is not None else 0,
                    "avg_duration_ms": round(float(row.avg_duration_ms), 2) if row.avg_duration_ms is not None else 0,
                    "min_duration_ms": round(float(row.min_duration_ms), 2) if row.min_duration_ms is not None else 0,
                    "max_duration_ms": round(float(row.max_duration_ms), 2) if row.max_duration_ms is not None else 0,
                    "p50": round(float(row.p50), 2) if row.p50 is not None else 0,
                    "p90": round(float(row.p90), 2) if row.p90 is not None else 0,
                    "p95": round(float(row.p95), 2) if row.p95 is not None else 0,
                    "p99": round(float(row.p99), 2) if row.p99 is not None else 0,
                }
            )

        return items

    # Fallback: Python aggregation (SQLite or other DBs, or PostgreSQL with USE_POSTGRESDB_PERCENTILES=False)
    # Pass dialect_name to extract_json_field to ensure correct SQL syntax for the actual database
    # Use timezone-aware cutoff for PostgreSQL to avoid timezone drift, naive for SQLite
    effective_cutoff = cutoff_time if dialect_name == "postgresql" else cutoff_time_naive
    spans = (
        db.query(
            extract_json_field(ObservabilitySpan.attributes, f'$."{json_key}"', dialect_name=dialect_name).label("entity"),
            ObservabilitySpan.duration_ms,
        )
        .filter(
            ObservabilitySpan.name.in_(span_names),
            ObservabilitySpan.start_time >= effective_cutoff,
            ObservabilitySpan.duration_ms.isnot(None),
            extract_json_field(ObservabilitySpan.attributes, f'$."{json_key}"', dialect_name=dialect_name).isnot(None),
        )
        .all()
    )

    durations_by_entity: Dict[str, List[float]] = defaultdict(list)
    for span in spans:
        durations_by_entity[span.entity].append(span.duration_ms)

    def percentile(data: List[float], p: float) -> float:
        """Calculate percentile using linear interpolation (matches PostgreSQL percentile_cont).

        Args:
            data: Sorted, non-empty list of numeric values.
            p: Percentile to calculate (0.0 to 1.0).

        Returns:
            float: The interpolated percentile value.
        """
        n = len(data)
        k = p * (n - 1)
        f = int(k)
        c = k - f
        next_i = min(f + 1, n - 1)
        return data[f] + c * (data[next_i] - data[f])

    items: List[dict] = []
    for entity, durations in durations_by_entity.items():
        durations_sorted = sorted(durations)
        n = len(durations_sorted)
        items.append(
            {
                result_key: entity,
                "count": n,
                "avg_duration_ms": round(sum(durations) / n, 2),
                "min_duration_ms": round(min(durations), 2),
                "max_duration_ms": round(max(durations), 2),
                "p50": round(percentile(durations_sorted, 0.50), 2),
                "p90": round(percentile(durations_sorted, 0.90), 2),
                "p95": round(percentile(durations_sorted, 0.95), 2),
                "p99": round(percentile(durations_sorted, 0.99), 2),
            }
        )

    items.sort(key=lambda x: x.get("avg_duration_ms", 0), reverse=True)
    return items[:limit]


# ============================================================================
# Observability Routes
# ============================================================================


@router.get("/observability/partial", response_class=HTMLResponse)
@require_permission("admin.system_config", allow_admin_bypass=False)
async def get_observability_partial(request: Request, _user=Depends(get_current_user_with_permissions), _db: Session = Depends(get_db)):
    """Render the observability dashboard partial.

    Args:
        request: FastAPI request object
        _user: Authenticated user with admin permissions (required by dependency)
        _db: Database session for permission checks.

    Returns:
        HTMLResponse: Rendered observability dashboard template
    """
    root_path = _resolve_root_path(request)
    return request.app.state.templates.TemplateResponse(request, "observability_partial.html", {"request": request, "root_path": root_path})


@router.get("/observability/metrics/partial", response_class=HTMLResponse)
@require_permission("admin.system_config", allow_admin_bypass=False)
async def get_observability_metrics_partial(request: Request, _user=Depends(get_current_user_with_permissions), _db: Session = Depends(get_db)):
    """Render the advanced metrics dashboard partial.

    Args:
        request: FastAPI request object
        _user: Authenticated user with admin permissions (required by dependency)
        _db: Database session for permission checks.

    Returns:
        HTMLResponse: Rendered metrics dashboard template
    """
    root_path = _resolve_root_path(request)
    return request.app.state.templates.TemplateResponse(request, "observability_metrics.html", {"request": request, "root_path": root_path})


@router.get("/observability/stats", response_class=HTMLResponse)
@require_permission("admin.system_config", allow_admin_bypass=False)
async def get_observability_stats(request: Request, hours: int = Query(24, ge=1, le=168), _user=Depends(get_current_user_with_permissions), db: Session = Depends(get_db)):
    """Get observability statistics for the dashboard.

    Args:
        request: FastAPI request object
        hours: Number of hours to look back for statistics (1-168)
        _user: Authenticated user with admin permissions (required by dependency)
        db: Database session for permission checks.

    Returns:
        HTMLResponse: Rendered statistics template with trace counts and averages
    """
    db = next(get_db())
    try:
        cutoff_time = datetime.now() - timedelta(hours=hours)

        # Consolidate multiple count queries into a single aggregated select
        # Filter by start_time first (uses index), then aggregate by status
        result = db.execute(
            select(
                func.count(ObservabilityTrace.trace_id).label("total_traces"),  # pylint: disable=not-callable
                func.sum(case((ObservabilityTrace.status == "ok", 1), else_=0)).label("success_count"),
                func.sum(case((ObservabilityTrace.status == "error", 1), else_=0)).label("error_count"),
                func.avg(ObservabilityTrace.duration_ms).label("avg_duration_ms"),
            ).where(ObservabilityTrace.start_time >= cutoff_time)
        ).one()

        stats = {
            "total_traces": int(result.total_traces or 0),
            "success_count": int(result.success_count or 0),
            "error_count": int(result.error_count or 0),
            "avg_duration_ms": float(result.avg_duration_ms or 0),
        }

        return request.app.state.templates.TemplateResponse(request, "observability_stats.html", {"request": request, "stats": stats})
    finally:
        # Ensure close() always runs even if commit() fails
        try:
            db.commit()  # Commit read-only transaction to avoid implicit rollback
        finally:
            db.close()


@router.get("/observability/traces", response_class=HTMLResponse)
@require_permission("admin.system_config", allow_admin_bypass=False)
async def get_observability_traces(
    request: Request,
    time_range: QueryTimeRange = "24h",
    status_filter: QueryStatusFilter = "all",
    limit: int = Query(50, ge=1, le=1000),
    min_duration: Optional[float] = Query(None, ge=0),
    max_duration: Optional[float] = Query(None, ge=0),
    http_method: QueryHttpMethod = None,
    user_email: QueryUserIdentifierNoDescription = None,
    name_search: Optional[str] = Query(None, max_length=500),
    attribute_search: Optional[str] = Query(None, max_length=500),
    # tool_name pattern follows MCP SEP-986 (Specify Format for Tool Names), matching
    # mcpgateway.config.Settings.validation_tool_name_pattern. Allows namespacing via '/'.
    tool_name: QueryToolName = None,
    _user=Depends(get_current_user_with_permissions),
    db: Session = Depends(get_db),
):
    """Get list of traces for the dashboard.

    Args:
        request: FastAPI request object
        time_range: Time range filter (1h, 6h, 24h, 7d)
        status_filter: Status filter (all, ok, error)
        limit: Maximum number of traces to return
        min_duration: Minimum duration in ms
        max_duration: Maximum duration in ms
        http_method: HTTP method filter
        user_email: User email filter
        name_search: Trace name search
        attribute_search: Full-text attribute search
        tool_name: Filter by tool name (shows traces that invoked this tool)
        _user: Authenticated user with admin permissions (required by dependency)
        db: Database session for permission checks.

    Returns:
        HTMLResponse: Rendered traces list template
    """
    db = next(get_db())
    try:
        # Parse time range
        time_map = {"1h": 1, "6h": 6, "24h": 24, "7d": 168}
        hours = time_map.get(time_range, 24)
        cutoff_time = datetime.now() - timedelta(hours=hours)

        query = db.query(ObservabilityTrace).filter(ObservabilityTrace.start_time >= cutoff_time)

        # Apply status filter
        if status_filter != "all":
            query = query.filter(ObservabilityTrace.status == status_filter)

        # Apply duration filters
        if min_duration is not None:
            query = query.filter(ObservabilityTrace.duration_ms >= min_duration)
        if max_duration is not None:
            query = query.filter(ObservabilityTrace.duration_ms <= max_duration)

        # Apply HTTP method filter
        if http_method:
            query = query.filter(ObservabilityTrace.http_method == http_method)

        # Apply user email filter
        if user_email:
            query = query.filter(ObservabilityTrace.user_email.ilike(f"%{user_email}%"))

        # Apply name search
        if name_search:
            query = query.filter(ObservabilityTrace.name.ilike(f"%{name_search}%"))

        # Apply attribute search
        if attribute_search:
            # Escape special characters for SQL LIKE
            safe_search = attribute_search.replace("%", "\\%").replace("_", "\\_")
            query = query.filter(cast(ObservabilityTrace.attributes, String).ilike(f"%{safe_search}%"))

        # Apply tool name filter (join with spans to find traces that invoked a specific tool)
        if tool_name:
            # Subquery to find trace_ids that have tool invocations matching the tool name
            tool_trace_ids = (
                db.query(ObservabilitySpan.trace_id)
                .filter(
                    ObservabilitySpan.name == "tool.invoke",
                    extract_json_field(ObservabilitySpan.attributes, '$."tool.name"').ilike(f"%{tool_name}%"),
                )
                .distinct()
                .subquery()
            )
            query = query.filter(ObservabilityTrace.trace_id.in_(select(tool_trace_ids.c.trace_id)))

        # Get traces ordered by most recent
        traces = query.order_by(ObservabilityTrace.start_time.desc()).limit(limit).all()

        root_path = _resolve_root_path(request)
        return request.app.state.templates.TemplateResponse(request, "observability_traces_list.html", {"request": request, "traces": traces, "root_path": root_path})
    finally:
        # Ensure close() always runs even if commit() fails
        try:
            db.commit()  # Commit read-only transaction to avoid implicit rollback
        finally:
            db.close()


@router.get("/observability/trace/{trace_id}", response_class=HTMLResponse)
@require_permission("admin.system_config", allow_admin_bypass=False)
async def get_observability_trace_detail(request: Request, trace_id: str, _user=Depends(get_current_user_with_permissions), db: Session = Depends(get_db)):
    """Get detailed trace information with spans.

    Args:
        request: FastAPI request object
        trace_id: UUID of the trace to retrieve
        _user: Authenticated user with admin permissions (required by dependency)
        db: Database session for permission checks.

    Returns:
        HTMLResponse: Rendered trace detail template with waterfall view

    Raises:
        HTTPException: 404 if trace not found
    """
    db = next(get_db())
    try:
        trace = db.query(ObservabilityTrace).filter_by(trace_id=trace_id).options(joinedload(ObservabilityTrace.spans).joinedload(ObservabilitySpan.events)).first()

        if not trace:
            raise HTTPException(status_code=404, detail="Trace not found")

        root_path = _resolve_root_path(request)
        return request.app.state.templates.TemplateResponse(request, "observability_trace_detail.html", {"request": request, "trace": trace, "root_path": root_path})
    finally:
        # Ensure close() always runs even if commit() fails
        try:
            db.commit()  # Commit read-only transaction to avoid implicit rollback
        finally:
            db.close()


@router.post("/observability/queries", response_model=dict)
@require_permission("admin.system_config", allow_admin_bypass=False)
async def save_observability_query(
    request: Request,  # pylint: disable=unused-argument
    name: str = Body(..., description="Name for the saved query"),
    description: Optional[str] = Body(None, description="Optional description"),
    filter_config: dict = Body(..., description="Filter configuration as JSON"),
    is_shared: bool = Body(False, description="Whether query is shared with team"),
    user=Depends(get_current_user_with_permissions),
    db: Session = Depends(get_db),
):
    """Save a new observability query filter configuration.

    Args:
        request: FastAPI request object
        name: User-given name for the query
        description: Optional description
        filter_config: Dictionary containing all filter values
        is_shared: Whether this query is visible to other users
        user: Authenticated user (required by dependency)
        db: Database session for permission checks.

    Returns:
        dict: Created query details with id

    Raises:
        HTTPException: 400 if validation fails
    """
    db = next(get_db())
    try:
        # Get user email from authenticated user
        user_email = user.email if hasattr(user, "email") else "unknown"

        # Create new saved query
        query = ObservabilitySavedQuery(name=name, description=description, user_email=user_email, filter_config=filter_config, is_shared=is_shared)

        db.add(query)
        db.commit()
        db.refresh(query)

        return {"id": query.id, "name": query.name, "description": query.description, "filter_config": query.filter_config, "is_shared": query.is_shared, "created_at": query.created_at.isoformat()}
    except Exception as e:
        db.rollback()
        LOGGER.error(f"Failed to save query: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        # Ensure close() always runs even if commit() fails
        try:
            db.commit()  # Commit read-only transaction to avoid implicit rollback
        finally:
            db.close()


@router.get("/observability/queries", response_model=list)
@require_permission("admin.system_config", allow_admin_bypass=False)
async def list_observability_queries(request: Request, user=Depends(get_current_user_with_permissions), db: Session = Depends(get_db)):  # pylint: disable=unused-argument
    """List saved observability queries for the current user.

    Returns user's own queries plus any shared queries.

    Args:
        request: FastAPI request object
        user: Authenticated user (required by dependency)
        db: Database session for permission checks.

    Returns:
        list: List of saved query dictionaries
    """
    db = next(get_db())
    try:
        user_email = user.email if hasattr(user, "email") else "unknown"

        # Get user's own queries + shared queries
        queries = (
            db.query(ObservabilitySavedQuery)
            .filter(or_(ObservabilitySavedQuery.user_email == user_email, ObservabilitySavedQuery.is_shared is True))
            .order_by(desc(ObservabilitySavedQuery.created_at))
            .all()
        )

        return [
            {
                "id": q.id,
                "name": q.name,
                "description": q.description,
                "filter_config": q.filter_config,
                "is_shared": q.is_shared,
                "user_email": q.user_email,
                "created_at": q.created_at.isoformat(),
                "last_used_at": q.last_used_at.isoformat() if q.last_used_at else None,
                "use_count": q.use_count,
            }
            for q in queries
        ]
    finally:
        # Ensure close() always runs even if commit() fails
        try:
            db.commit()  # Commit read-only transaction to avoid implicit rollback
        finally:
            db.close()


@router.get("/observability/queries/{query_id}", response_model=dict)
@require_permission("admin.system_config", allow_admin_bypass=False)
async def get_observability_query(request: Request, query_id: int, user=Depends(get_current_user_with_permissions), db: Session = Depends(get_db)):  # pylint: disable=unused-argument
    """Get a specific saved query by ID.

    Args:
        request: FastAPI request object
        query_id: ID of the saved query
        user: Authenticated user (required by dependency)
        db: Database session for permission checks.

    Returns:
        dict: Query details

    Raises:
        HTTPException: 404 if query not found or unauthorized
    """
    db = next(get_db())
    try:
        user_email = user.email if hasattr(user, "email") else "unknown"

        # Can only access own queries or shared queries
        query = (
            db.query(ObservabilitySavedQuery).filter(ObservabilitySavedQuery.id == query_id, or_(ObservabilitySavedQuery.user_email == user_email, ObservabilitySavedQuery.is_shared is True)).first()
        )

        if not query:
            raise HTTPException(status_code=404, detail="Query not found or unauthorized")

        return {
            "id": query.id,
            "name": query.name,
            "description": query.description,
            "filter_config": query.filter_config,
            "is_shared": query.is_shared,
            "user_email": query.user_email,
            "created_at": query.created_at.isoformat(),
            "last_used_at": query.last_used_at.isoformat() if query.last_used_at else None,
            "use_count": query.use_count,
        }
    finally:
        # Ensure close() always runs even if commit() fails
        try:
            db.commit()  # Commit read-only transaction to avoid implicit rollback
        finally:
            db.close()


@router.put("/observability/queries/{query_id}", response_model=dict)
@require_permission("admin.system_config", allow_admin_bypass=False)
async def update_observability_query(
    request: Request,  # pylint: disable=unused-argument
    query_id: int,
    name: Optional[str] = Body(None),
    description: Optional[str] = Body(None),
    filter_config: Optional[dict] = Body(None),
    is_shared: Optional[bool] = Body(None),
    user=Depends(get_current_user_with_permissions),
    db: Session = Depends(get_db),
):
    """Update an existing saved query.

    Args:
        request: FastAPI request object
        query_id: ID of the query to update
        name: New name (optional)
        description: New description (optional)
        filter_config: New filter configuration (optional)
        is_shared: New sharing status (optional)
        user: Authenticated user (required by dependency)
        db: Database session for permission checks.

    Returns:
        dict: Updated query details

    Raises:
        HTTPException: 404 if query not found, 403 if unauthorized
    """
    db = next(get_db())
    try:
        user_email = user.email if hasattr(user, "email") else "unknown"

        # Can only update own queries
        query = db.query(ObservabilitySavedQuery).filter(ObservabilitySavedQuery.id == query_id, ObservabilitySavedQuery.user_email == user_email).first()

        if not query:
            raise HTTPException(status_code=404, detail="Query not found or unauthorized")

        # Update fields if provided
        if name is not None:
            query.name = name
        if description is not None:
            query.description = description
        if filter_config is not None:
            query.filter_config = filter_config
        if is_shared is not None:
            query.is_shared = is_shared

        db.commit()
        db.refresh(query)

        return {
            "id": query.id,
            "name": query.name,
            "description": query.description,
            "filter_config": query.filter_config,
            "is_shared": query.is_shared,
            "updated_at": query.updated_at.isoformat(),
        }
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        LOGGER.error(f"Failed to update query: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        # Ensure close() always runs even if commit() fails
        try:
            db.commit()  # Commit read-only transaction to avoid implicit rollback
        finally:
            db.close()


@router.delete("/observability/queries/{query_id}", status_code=204)
@require_permission("admin.system_config", allow_admin_bypass=False)
async def delete_observability_query(request: Request, query_id: int, user=Depends(get_current_user_with_permissions), db: Session = Depends(get_db)):  # pylint: disable=unused-argument
    """Delete a saved query.

    Args:
        request: FastAPI request object
        query_id: ID of the query to delete
        user: Authenticated user (required by dependency)
        db: Database session for permission checks.

    Raises:
        HTTPException: 404 if query not found, 403 if unauthorized
    """
    db = next(get_db())
    try:
        user_email = user.email if hasattr(user, "email") else "unknown"

        # Can only delete own queries
        query = db.query(ObservabilitySavedQuery).filter(ObservabilitySavedQuery.id == query_id, ObservabilitySavedQuery.user_email == user_email).first()

        if not query:
            raise HTTPException(status_code=404, detail="Query not found or unauthorized")

        db.delete(query)
        db.commit()
    finally:
        # Ensure close() always runs even if commit() fails
        try:
            db.commit()  # Commit read-only transaction to avoid implicit rollback
        finally:
            db.close()


@router.post("/observability/queries/{query_id}/use", response_model=dict)
@require_permission("admin.system_config", allow_admin_bypass=False)
async def track_query_usage(request: Request, query_id: int, user=Depends(get_current_user_with_permissions), db: Session = Depends(get_db)):  # pylint: disable=unused-argument
    """Track usage of a saved query (increments use count and updates last_used_at).

    Args:
        request: FastAPI request object
        query_id: ID of the query being used
        user: Authenticated user (required by dependency)
        db: Database session for permission checks.

    Returns:
        dict: Updated query usage stats

    Raises:
        HTTPException: 404 if query not found or unauthorized
    """
    db = next(get_db())
    try:
        user_email = user.email if hasattr(user, "email") else "unknown"

        # Can track usage for own queries or shared queries
        query = (
            db.query(ObservabilitySavedQuery).filter(ObservabilitySavedQuery.id == query_id, or_(ObservabilitySavedQuery.user_email == user_email, ObservabilitySavedQuery.is_shared is True)).first()
        )

        if not query:
            raise HTTPException(status_code=404, detail="Query not found or unauthorized")

        # Update usage tracking
        query.use_count += 1
        query.last_used_at = utc_now()

        db.commit()
        db.refresh(query)

        return {"use_count": query.use_count, "last_used_at": query.last_used_at.isoformat()}
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        LOGGER.error(f"Failed to track query usage: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        # Ensure close() always runs even if commit() fails
        try:
            db.commit()  # Commit read-only transaction to avoid implicit rollback
        finally:
            db.close()


@router.get("/observability/metrics/percentiles", response_model=dict)
@require_permission("admin.system_config", allow_admin_bypass=False)
async def get_latency_percentiles(
    request: Request,  # pylint: disable=unused-argument
    hours: int = Query(24, ge=1, le=168, description="Time range in hours"),
    interval_minutes: int = Query(60, ge=5, le=1440, description="Aggregation interval in minutes"),
    _user=Depends(get_current_user_with_permissions),
    db: Session = Depends(get_db),
):
    """Get latency percentiles (p50, p90, p95, p99) over time.

    Args:
        request: FastAPI request object
        hours: Number of hours to look back (1-168)
        interval_minutes: Aggregation interval in minutes (5-1440)
        _user: Authenticated user (required by dependency)
        db: Database session for permission checks.

    Returns:
        dict: Time-series data with percentiles

    Raises:
        HTTPException: 500 if calculation fails
    """
    db = next(get_db())
    try:
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)

        # Use SQL aggregation for PostgreSQL, Python fallback for SQLite
        dialect_name = db.get_bind().dialect.name
        if dialect_name == "postgresql":
            return _get_latency_percentiles_postgresql(db, cutoff_time, interval_minutes)
        return _get_latency_percentiles_python(db, cutoff_time, interval_minutes)
    except Exception as e:
        LOGGER.error(f"Failed to calculate latency percentiles: {e}")
        raise HTTPException(status_code=500, detail="Failed to calculate latency percentiles")
    finally:
        # Ensure close() always runs even if commit() fails
        try:
            db.commit()  # Commit read-only transaction to avoid implicit rollback
        finally:
            db.close()


def _get_latency_percentiles_postgresql(db: Session, cutoff_time: datetime, interval_minutes: int) -> dict:
    """Compute time-bucketed latency percentiles using PostgreSQL.

    Args:
        db: Database session
        cutoff_time: Start time for analysis
        interval_minutes: Bucket size in minutes

    Returns:
        dict: Time-series percentile data
    """
    # PostgreSQL query with epoch-based bucketing (works for any interval including > 60 min)
    stats_sql = text("""
        SELECT
            TO_TIMESTAMP(FLOOR(EXTRACT(EPOCH FROM start_time) / :interval_seconds) * :interval_seconds) as bucket,
            percentile_cont(0.50) WITHIN GROUP (ORDER BY duration_ms) as p50,
            percentile_cont(0.90) WITHIN GROUP (ORDER BY duration_ms) as p90,
            percentile_cont(0.95) WITHIN GROUP (ORDER BY duration_ms) as p95,
            percentile_cont(0.99) WITHIN GROUP (ORDER BY duration_ms) as p99
        FROM observability_traces
        WHERE start_time >= :cutoff_time AND duration_ms IS NOT NULL
        GROUP BY bucket
        ORDER BY bucket
        """)

    interval_seconds = interval_minutes * 60
    results = db.execute(stats_sql, {"cutoff_time": cutoff_time, "interval_seconds": interval_seconds}).fetchall()

    if not results:
        return {"timestamps": [], "p50": [], "p90": [], "p95": [], "p99": []}

    timestamps = []
    p50_values = []
    p90_values = []
    p95_values = []
    p99_values = []

    for row in results:
        timestamps.append(ensure_timezone_aware(row.bucket).astimezone(timezone.utc).isoformat() if row.bucket else "")
        p50_values.append(round(float(row.p50), 2) if row.p50 else 0)
        p90_values.append(round(float(row.p90), 2) if row.p90 else 0)
        p95_values.append(round(float(row.p95), 2) if row.p95 else 0)
        p99_values.append(round(float(row.p99), 2) if row.p99 else 0)

    return {"timestamps": timestamps, "p50": p50_values, "p90": p90_values, "p95": p95_values, "p99": p99_values}


def _get_latency_percentiles_python(db: Session, cutoff_time: datetime, interval_minutes: int) -> dict:
    """Compute time-bucketed latency percentiles using Python (fallback for SQLite).

    Args:
        db: Database session
        cutoff_time: Start time for analysis
        interval_minutes: Bucket size in minutes

    Returns:
        dict: Time-series percentile data
    """
    # Query all traces with duration in time range
    traces = (
        db.query(ObservabilityTrace.start_time, ObservabilityTrace.duration_ms)
        .filter(ObservabilityTrace.start_time >= cutoff_time, ObservabilityTrace.duration_ms.isnot(None))
        .order_by(ObservabilityTrace.start_time)
        .all()
    )

    if not traces:
        return {"timestamps": [], "p50": [], "p90": [], "p95": [], "p99": []}

    # Group traces into time buckets using epoch-based bucketing (works for any interval)
    interval_seconds = interval_minutes * 60
    buckets: Dict[datetime, List[float]] = defaultdict(list)
    for trace in traces:
        trace_time = trace.start_time
        if trace_time.tzinfo is None:
            trace_time = trace_time.replace(tzinfo=timezone.utc)
        epoch = trace_time.timestamp()
        bucket_epoch = (epoch // interval_seconds) * interval_seconds
        bucket_time = datetime.fromtimestamp(bucket_epoch, tz=timezone.utc)
        buckets[bucket_time].append(trace.duration_ms)

    # Calculate percentiles for each bucket
    timestamps = []
    p50_values = []
    p90_values = []
    p95_values = []
    p99_values = []

    def percentile_cont(data: List[float], p: float) -> float:
        """Linear interpolation percentile matching PostgreSQL percentile_cont.

        Args:
            data: Sorted list of float values.
            p: Percentile value between 0 and 1.

        Returns:
            float: Interpolated percentile value.
        """
        n = len(data)
        k = p * (n - 1)
        f = int(k)
        c = k - f
        next_i = min(f + 1, n - 1)
        return data[f] + c * (data[next_i] - data[f])

    for bucket_time in sorted(buckets.keys()):
        durations = sorted(buckets[bucket_time])

        if durations:
            timestamps.append(bucket_time.isoformat())
            p50_values.append(round(percentile_cont(durations, 0.50), 2))
            p90_values.append(round(percentile_cont(durations, 0.90), 2))
            p95_values.append(round(percentile_cont(durations, 0.95), 2))
            p99_values.append(round(percentile_cont(durations, 0.99), 2))

    return {"timestamps": timestamps, "p50": p50_values, "p90": p90_values, "p95": p95_values, "p99": p99_values}


@router.get("/observability/metrics/timeseries", response_model=dict)
@require_permission("admin.system_config", allow_admin_bypass=False)
async def get_timeseries_metrics(
    request: Request,  # pylint: disable=unused-argument
    hours: int = Query(24, ge=1, le=168, description="Time range in hours"),
    interval_minutes: int = Query(60, ge=5, le=1440, description="Aggregation interval in minutes"),
    _user=Depends(get_current_user_with_permissions),
    db: Session = Depends(get_db),
):
    """Get time-series metrics (request rate, error rate, throughput).

    Args:
        request: FastAPI request object
        hours: Number of hours to look back (1-168)
        interval_minutes: Aggregation interval in minutes (5-1440)
        _user: Authenticated user (required by dependency)
        db: Database session for permission checks.

    Returns:
        dict: Time-series data with request counts, error rates, and throughput

    Raises:
        HTTPException: 500 if calculation fails
    """
    db = next(get_db())
    try:
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)

        # Use SQL aggregation for PostgreSQL, Python fallback for SQLite
        dialect_name = db.get_bind().dialect.name
        if dialect_name == "postgresql":
            return _get_timeseries_metrics_postgresql(db, cutoff_time, interval_minutes)
        return _get_timeseries_metrics_python(db, cutoff_time, interval_minutes)
    except Exception as e:
        LOGGER.error(f"Failed to calculate timeseries metrics: {e}")
        raise HTTPException(status_code=500, detail="Failed to calculate timeseries metrics")
    finally:
        # Ensure close() always runs even if commit() fails
        try:
            db.commit()  # Commit read-only transaction to avoid implicit rollback
        finally:
            db.close()


def _get_timeseries_metrics_postgresql(db: Session, cutoff_time: datetime, interval_minutes: int) -> dict:
    """Compute time-series metrics using PostgreSQL.

    Args:
        db: Database session
        cutoff_time: Start time for analysis
        interval_minutes: Bucket size in minutes

    Returns:
        dict: Time-series metrics data
    """
    # Use epoch-based bucketing (works for any interval including > 60 min)
    stats_sql = text("""
        SELECT
            TO_TIMESTAMP(FLOOR(EXTRACT(EPOCH FROM start_time) / :interval_seconds) * :interval_seconds) as bucket,
            COUNT(*) as total,
            SUM(CASE WHEN status = 'ok' THEN 1 ELSE 0 END) as success,
            SUM(CASE WHEN status = 'error' THEN 1 ELSE 0 END) as error
        FROM observability_traces
        WHERE start_time >= :cutoff_time
        GROUP BY bucket
        ORDER BY bucket
        """)

    interval_seconds = interval_minutes * 60
    results = db.execute(stats_sql, {"cutoff_time": cutoff_time, "interval_seconds": interval_seconds}).fetchall()

    if not results:
        return {"timestamps": [], "request_count": [], "success_count": [], "error_count": [], "error_rate": []}

    timestamps = []
    request_counts = []
    success_counts = []
    error_counts = []
    error_rates = []

    for row in results:
        total = row.total or 0
        error = row.error or 0
        error_rate = (error / total * 100) if total > 0 else 0

        timestamps.append(ensure_timezone_aware(row.bucket).astimezone(timezone.utc).isoformat() if row.bucket else "")
        request_counts.append(total)
        success_counts.append(row.success or 0)
        error_counts.append(error)
        error_rates.append(round(error_rate, 2))

    return {
        "timestamps": timestamps,
        "request_count": request_counts,
        "success_count": success_counts,
        "error_count": error_counts,
        "error_rate": error_rates,
    }


def _get_timeseries_metrics_python(db: Session, cutoff_time: datetime, interval_minutes: int) -> dict:
    """Compute time-series metrics using Python (fallback for SQLite).

    Args:
        db: Database session
        cutoff_time: Start time for analysis
        interval_minutes: Bucket size in minutes

    Returns:
        dict: Time-series metrics data
    """
    # Query traces grouped by time bucket
    traces = db.query(ObservabilityTrace.start_time, ObservabilityTrace.status).filter(ObservabilityTrace.start_time >= cutoff_time).order_by(ObservabilityTrace.start_time).all()

    if not traces:
        return {"timestamps": [], "request_count": [], "success_count": [], "error_count": [], "error_rate": []}

    # Group traces into time buckets using epoch-based bucketing (works for any interval)
    interval_seconds = interval_minutes * 60
    buckets: Dict[datetime, Dict[str, int]] = defaultdict(lambda: {"total": 0, "success": 0, "error": 0})
    for trace in traces:
        trace_time = trace.start_time
        if trace_time.tzinfo is None:
            trace_time = trace_time.replace(tzinfo=timezone.utc)
        epoch = trace_time.timestamp()
        bucket_epoch = (epoch // interval_seconds) * interval_seconds
        bucket_time = datetime.fromtimestamp(bucket_epoch, tz=timezone.utc)

        buckets[bucket_time]["total"] += 1
        if trace.status == "ok":
            buckets[bucket_time]["success"] += 1
        elif trace.status == "error":
            buckets[bucket_time]["error"] += 1

    # Build time-series arrays
    timestamps = []
    request_counts = []
    success_counts = []
    error_counts = []
    error_rates = []

    for bucket_time in sorted(buckets.keys()):
        bucket = buckets[bucket_time]
        error_rate = (bucket["error"] / bucket["total"] * 100) if bucket["total"] > 0 else 0

        timestamps.append(bucket_time.isoformat())
        request_counts.append(bucket["total"])
        success_counts.append(bucket["success"])
        error_counts.append(bucket["error"])
        error_rates.append(round(error_rate, 2))

    return {
        "timestamps": timestamps,
        "request_count": request_counts,
        "success_count": success_counts,
        "error_count": error_counts,
        "error_rate": error_rates,
    }


def _get_latency_heatmap_postgresql(db: Session, cutoff_time: datetime, hours: int, time_buckets: int, latency_buckets: int) -> dict:
    """Compute latency heatmap using PostgreSQL (optimized path).

    Uses SQL arithmetic for efficient 2D histogram computation.

    Args:
        db: Database session
        cutoff_time: Start time for analysis
        hours: Time range in hours
        time_buckets: Number of time buckets
        latency_buckets: Number of latency buckets

    Returns:
        dict: Heatmap data with time and latency dimensions
    """
    # First, get min/max durations
    stats_query = text("""
        SELECT MIN(duration_ms) as min_d, MAX(duration_ms) as max_d
        FROM observability_traces
        WHERE start_time >= :cutoff_time AND duration_ms IS NOT NULL
    """)
    stats_row = db.execute(stats_query, {"cutoff_time": cutoff_time}).fetchone()

    if not stats_row or stats_row.min_d is None:
        return {"time_labels": [], "latency_labels": [], "data": []}

    min_duration = float(stats_row.min_d)
    max_duration = float(stats_row.max_d)
    latency_range = max_duration - min_duration

    # Handle case where all durations are the same
    if latency_range == 0:
        latency_range = 1.0

    time_range_minutes = hours * 60
    latency_bucket_size = latency_range / latency_buckets
    time_bucket_minutes = time_range_minutes / time_buckets

    # Use SQL arithmetic for 2D histogram bucketing
    heatmap_query = text("""
        SELECT
            LEAST(GREATEST(
                (EXTRACT(EPOCH FROM (start_time - :cutoff_time)) / 60.0 / :time_bucket_minutes)::int,
                0
            ), :time_buckets - 1) as time_idx,
            LEAST(GREATEST(
                ((duration_ms - :min_duration) / :latency_bucket_size)::int,
                0
            ), :latency_buckets - 1) as latency_idx,
            COUNT(*) as cnt
        FROM observability_traces
        WHERE start_time >= :cutoff_time AND duration_ms IS NOT NULL
        GROUP BY time_idx, latency_idx
    """)

    rows = db.execute(
        heatmap_query,
        {
            "cutoff_time": cutoff_time,
            "time_bucket_minutes": time_bucket_minutes,
            "time_buckets": time_buckets,
            "min_duration": min_duration,
            "latency_bucket_size": latency_bucket_size,
            "latency_buckets": latency_buckets,
        },
    ).fetchall()

    # Initialize heatmap matrix
    heatmap = [[0 for _ in range(time_buckets)] for _ in range(latency_buckets)]

    # Populate from SQL results
    for row in rows:
        time_idx = int(row.time_idx)
        latency_idx = int(row.latency_idx)
        if 0 <= time_idx < time_buckets and 0 <= latency_idx < latency_buckets:
            heatmap[latency_idx][time_idx] = int(row.cnt)

    # Generate labels
    time_labels = []
    for i in range(time_buckets):
        bucket_time = cutoff_time + timedelta(minutes=i * time_bucket_minutes)
        time_labels.append(bucket_time.strftime("%H:%M"))

    latency_labels = []
    for i in range(latency_buckets):
        bucket_min = min_duration + i * latency_bucket_size
        bucket_max = bucket_min + latency_bucket_size
        latency_labels.append(f"{bucket_min:.0f}-{bucket_max:.0f}ms")

    return {"time_labels": time_labels, "latency_labels": latency_labels, "data": heatmap}


def _get_latency_heatmap_python(db: Session, cutoff_time: datetime, hours: int, time_buckets: int, latency_buckets: int) -> dict:
    """Compute latency heatmap using Python (fallback for SQLite).

    Args:
        db: Database session
        cutoff_time: Start time for analysis
        hours: Time range in hours
        time_buckets: Number of time buckets
        latency_buckets: Number of latency buckets

    Returns:
        dict: Heatmap data with time and latency dimensions
    """
    # Query all traces with duration
    traces = (
        db.query(ObservabilityTrace.start_time, ObservabilityTrace.duration_ms)
        .filter(ObservabilityTrace.start_time >= cutoff_time, ObservabilityTrace.duration_ms.isnot(None))
        .order_by(ObservabilityTrace.start_time)
        .all()
    )

    if not traces:
        return {"time_labels": [], "latency_labels": [], "data": []}

    # Calculate time bucket size
    time_range = hours * 60  # minutes
    time_bucket_minutes = time_range / time_buckets

    # Find latency range and create buckets
    durations = [t.duration_ms for t in traces]
    min_duration = min(durations)
    max_duration = max(durations)
    latency_range = max_duration - min_duration
    latency_bucket_size = latency_range / latency_buckets if latency_range > 0 else 1

    # Initialize heatmap matrix
    heatmap = [[0 for _ in range(time_buckets)] for _ in range(latency_buckets)]

    # Populate heatmap
    for trace in traces:
        trace_time = trace.start_time
        # Convert naive SQLite datetime to UTC aware
        if trace_time.tzinfo is None:
            trace_time = trace_time.replace(tzinfo=timezone.utc)

        # Calculate time bucket index
        time_diff = (trace_time - cutoff_time).total_seconds() / 60  # minutes
        time_idx = min(int(time_diff / time_bucket_minutes), time_buckets - 1)

        # Calculate latency bucket index
        latency_idx = min(int((trace.duration_ms - min_duration) / latency_bucket_size), latency_buckets - 1)

        heatmap[latency_idx][time_idx] += 1

    # Generate labels
    time_labels = []
    for i in range(time_buckets):
        bucket_time = cutoff_time + timedelta(minutes=i * time_bucket_minutes)
        time_labels.append(bucket_time.strftime("%H:%M"))

    latency_labels = []
    for i in range(latency_buckets):
        bucket_min = min_duration + i * latency_bucket_size
        bucket_max = bucket_min + latency_bucket_size
        latency_labels.append(f"{bucket_min:.0f}-{bucket_max:.0f}ms")

    return {"time_labels": time_labels, "latency_labels": latency_labels, "data": heatmap}


@router.get("/observability/metrics/top-slow", response_model=dict)
@require_permission("admin.system_config", allow_admin_bypass=False)
async def get_top_slow_endpoints(
    request: Request,  # pylint: disable=unused-argument
    hours: int = Query(24, ge=1, le=168, description="Time range in hours"),
    limit: int = Query(10, ge=1, le=settings.pagination_max_page_size, description="Number of results"),
    _user=Depends(get_current_user_with_permissions),
    db: Session = Depends(get_db),
):
    """Get top N slowest endpoints by average duration.

    Args:
        request: FastAPI request object
        hours: Number of hours to look back (1-168)
        limit: Number of results to return (1-pagination_max_page_size)
        _user: Authenticated user (required by dependency)
        db: Database session for permission checks.

    Returns:
        dict: List of slowest endpoints with stats

    Raises:
        HTTPException: 500 if query fails
    """
    db = next(get_db())
    try:
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)

        # Group by endpoint and calculate average duration
        results = (
            db.query(
                ObservabilityTrace.http_url,
                ObservabilityTrace.http_method,
                func.count(ObservabilityTrace.trace_id).label("count"),  # pylint: disable=not-callable
                func.avg(ObservabilityTrace.duration_ms).label("avg_duration"),
                func.max(ObservabilityTrace.duration_ms).label("max_duration"),
            )
            .filter(ObservabilityTrace.start_time >= cutoff_time, ObservabilityTrace.duration_ms.isnot(None))
            .group_by(ObservabilityTrace.http_url, ObservabilityTrace.http_method)
            .order_by(desc("avg_duration"))
            .limit(limit)
            .all()
        )

        endpoints = []
        for row in results:
            endpoints.append(
                {
                    "endpoint": f"{row.http_method} {row.http_url}",
                    "method": row.http_method,
                    "url": row.http_url,
                    "count": row.count,
                    "avg_duration_ms": round(row.avg_duration, 2),
                    "max_duration_ms": round(row.max_duration, 2),
                }
            )

        return {"endpoints": endpoints}
    except Exception as e:
        LOGGER.error(f"Failed to get top slow endpoints: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve slow endpoints")
    finally:
        # Ensure close() always runs even if commit() fails
        try:
            db.commit()  # Commit read-only transaction to avoid implicit rollback
        finally:
            db.close()


@router.get("/observability/metrics/top-volume", response_model=dict)
@require_permission("admin.system_config", allow_admin_bypass=False)
async def get_top_volume_endpoints(
    request: Request,  # pylint: disable=unused-argument
    hours: int = Query(24, ge=1, le=168, description="Time range in hours"),
    limit: int = Query(10, ge=1, le=settings.pagination_max_page_size, description="Number of results"),
    _user=Depends(get_current_user_with_permissions),
    db: Session = Depends(get_db),
):
    """Get top N highest volume endpoints by request count.

    Args:
        request: FastAPI request object
        hours: Number of hours to look back (1-168)
        limit: Number of results to return (1-pagination_max_page_size)
        _user: Authenticated user (required by dependency)
        db: Database session for permission checks.

    Returns:
        dict: List of highest volume endpoints with stats

    Raises:
        HTTPException: 500 if query fails
    """
    db = next(get_db())
    try:
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)

        # Group by endpoint and count requests
        results = (
            db.query(
                ObservabilityTrace.http_url,
                ObservabilityTrace.http_method,
                func.count(ObservabilityTrace.trace_id).label("count"),  # pylint: disable=not-callable
                func.avg(ObservabilityTrace.duration_ms).label("avg_duration"),
            )
            .filter(ObservabilityTrace.start_time >= cutoff_time)
            .group_by(ObservabilityTrace.http_url, ObservabilityTrace.http_method)
            .order_by(desc("count"))
            .limit(limit)
            .all()
        )

        endpoints = []
        for row in results:
            endpoints.append(
                {
                    "endpoint": f"{row.http_method} {row.http_url}",
                    "method": row.http_method,
                    "url": row.http_url,
                    "count": row.count,
                    "avg_duration_ms": round(row.avg_duration, 2) if row.avg_duration else 0,
                }
            )

        return {"endpoints": endpoints}
    except Exception as e:
        LOGGER.error(f"Failed to get top volume endpoints: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve volume endpoints")
    finally:
        # Ensure close() always runs even if commit() fails
        try:
            db.commit()  # Commit read-only transaction to avoid implicit rollback
        finally:
            db.close()


@router.get("/observability/metrics/top-errors", response_model=dict)
@require_permission("admin.system_config", allow_admin_bypass=False)
async def get_top_error_endpoints(
    request: Request,  # pylint: disable=unused-argument
    hours: int = Query(24, ge=1, le=168, description="Time range in hours"),
    limit: int = Query(10, ge=1, le=settings.pagination_max_page_size, description="Number of results"),
    _user=Depends(get_current_user_with_permissions),
    db: Session = Depends(get_db),
):
    """Get top N error-prone endpoints by error count and rate.

    Args:
        request: FastAPI request object
        hours: Number of hours to look back (1-168)
        limit: Number of results to return (1-pagination_max_page_size)
        _user: Authenticated user (required by dependency)
        db: Database session for permission checks.

    Returns:
        dict: List of error-prone endpoints with stats

    Raises:
        HTTPException: 500 if query fails
    """
    db = next(get_db())
    try:
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)

        # Group by endpoint and count errors
        results = (
            db.query(
                ObservabilityTrace.http_url,
                ObservabilityTrace.http_method,
                func.count(ObservabilityTrace.trace_id).label("total_count"),  # pylint: disable=not-callable
                func.sum(case((ObservabilityTrace.status == "error", 1), else_=0)).label("error_count"),
            )
            .filter(ObservabilityTrace.start_time >= cutoff_time)
            .group_by(ObservabilityTrace.http_url, ObservabilityTrace.http_method)
            .having(func.sum(case((ObservabilityTrace.status == "error", 1), else_=0)) > 0)
            .order_by(desc("error_count"))
            .limit(limit)
            .all()
        )

        endpoints = []
        for row in results:
            error_rate = (row.error_count / row.total_count * 100) if row.total_count > 0 else 0
            endpoints.append(
                {
                    "endpoint": f"{row.http_method} {row.http_url}",
                    "method": row.http_method,
                    "url": row.http_url,
                    "total_count": row.total_count,
                    "error_count": row.error_count,
                    "error_rate": round(error_rate, 2),
                }
            )

        return {"endpoints": endpoints}
    except Exception as e:
        LOGGER.error(f"Failed to get top error endpoints: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve error endpoints")
    finally:
        # Ensure close() always runs even if commit() fails
        try:
            db.commit()  # Commit read-only transaction to avoid implicit rollback
        finally:
            db.close()


@router.get("/observability/metrics/heatmap", response_model=dict)
@require_permission("admin.system_config", allow_admin_bypass=False)
async def get_latency_heatmap(
    request: Request,  # pylint: disable=unused-argument
    hours: int = Query(24, ge=1, le=168, description="Time range in hours"),
    time_buckets: int = Query(24, ge=10, le=100, description="Number of time buckets"),
    latency_buckets: int = Query(20, ge=5, le=50, description="Number of latency buckets"),
    _user=Depends(get_current_user_with_permissions),
    db: Session = Depends(get_db),
):
    """Get latency distribution heatmap data.

    Uses PostgreSQL SQL aggregation for efficient computation when available,
    falls back to Python for SQLite.

    Args:
        request: FastAPI request object
        hours: Number of hours to look back (1-168)
        time_buckets: Number of time buckets (10-100)
        latency_buckets: Number of latency buckets (5-50)
        _user: Authenticated user (required by dependency)
        db: Database session for permission checks.

    Returns:
        dict: Heatmap data with time and latency dimensions

    Raises:
        HTTPException: 500 if calculation fails
    """
    db = next(get_db())
    try:
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)

        # Route to appropriate implementation based on database dialect
        dialect_name = db.get_bind().dialect.name
        if dialect_name == "postgresql":
            return _get_latency_heatmap_postgresql(db, cutoff_time, hours, time_buckets, latency_buckets)
        return _get_latency_heatmap_python(db, cutoff_time, hours, time_buckets, latency_buckets)
    except Exception as e:
        LOGGER.error(f"Failed to generate latency heatmap: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate latency heatmap")
    finally:
        # Ensure close() always runs even if commit() fails
        try:
            db.commit()  # Commit read-only transaction to avoid implicit rollback
        finally:
            db.close()


@router.get("/observability/tools/usage", response_model=dict)
@require_permission("admin.system_config", allow_admin_bypass=False)
async def get_tool_usage(
    request: Request,  # pylint: disable=unused-argument
    hours: int = Query(24, ge=1, le=168, description="Time range in hours"),
    limit: int = Query(20, ge=5, le=settings.pagination_max_page_size, description="Number of tools to return"),
    _user=Depends(get_current_user_with_permissions),
    db: Session = Depends(get_db),
):
    """Get tool usage frequency statistics.

    Args:
        request: FastAPI request object
        hours: Number of hours to look back (1-168)
        limit: Maximum number of tools to return (5-pagination_max_page_size)
        _user: Authenticated user (required by dependency)
        db: Database session for permission checks.

    Returns:
        dict: Tool usage statistics with counts and percentages

    Raises:
        HTTPException: 500 if calculation fails
    """
    db = next(get_db())
    try:
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)
        cutoff_time_naive = cutoff_time.replace(tzinfo=None)
        dialect_name = db.get_bind().dialect.name

        # Query tool invocations from spans
        # Note: Using $."tool.name" because the JSON key contains a dot
        # Create expression once and reuse to avoid PostgreSQL GROUP BY errors
        tool_name_expr = extract_json_field(ObservabilitySpan.attributes, '$."tool.name"', dialect_name=dialect_name)
        tool_usage = (
            db.query(
                tool_name_expr.label("tool_name"),
                func.count(ObservabilitySpan.span_id).label("count"),  # pylint: disable=not-callable
            )
            .filter(
                ObservabilitySpan.name == "tool.invoke",
                ObservabilitySpan.start_time >= cutoff_time_naive,
                tool_name_expr.isnot(None),
            )
            .group_by(tool_name_expr)
            .order_by(func.count(ObservabilitySpan.span_id).desc())  # pylint: disable=not-callable
            .limit(limit)
            .all()
        )

        total_invocations = sum(row.count for row in tool_usage)

        tools = [
            {
                "tool_name": row.tool_name,
                "count": row.count,
                "percentage": round((row.count / total_invocations * 100) if total_invocations > 0 else 0, 2),
            }
            for row in tool_usage
        ]

        return {"tools": tools, "total_invocations": total_invocations, "time_range_hours": hours}
    except Exception as e:
        LOGGER.error(f"Failed to get tool usage statistics: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve tool usage statistics")
    finally:
        # Ensure close() always runs even if commit() fails
        try:
            db.commit()  # Commit read-only transaction to avoid implicit rollback
        finally:
            db.close()


@router.get("/observability/tools/performance", response_model=dict)
@require_permission("admin.system_config", allow_admin_bypass=False)
async def get_tool_performance(
    request: Request,  # pylint: disable=unused-argument
    hours: int = Query(24, ge=1, le=168, description="Time range in hours"),
    limit: int = Query(20, ge=5, le=settings.pagination_max_page_size, description="Number of tools to return"),
    _user=Depends(get_current_user_with_permissions),
    db: Session = Depends(get_db),
):
    """Get tool performance metrics (avg, min, max duration).

    Args:
        request: FastAPI request object
        hours: Number of hours to look back (1-168)
        limit: Maximum number of tools to return (5-pagination_max_page_size)
        _user: Authenticated user (required by dependency)
        db: Database session for permission checks.

    Returns:
        dict: Tool performance metrics

    Raises:
        HTTPException: 500 if calculation fails
    """
    db = next(get_db())
    try:
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)
        cutoff_time_naive = cutoff_time.replace(tzinfo=None)

        # Use shared helper to compute performance grouped by the JSON attribute
        tools = _get_span_entity_performance(
            db=db,
            cutoff_time=cutoff_time,
            cutoff_time_naive=cutoff_time_naive,
            span_names=["tool.invoke"],
            json_key="tool.name",
            result_key="tool_name",
            limit=limit,
        )

        return {"tools": tools, "time_range_hours": hours}
    except Exception as e:
        LOGGER.error(f"Failed to get tool performance metrics: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve tool performance metrics")
    finally:
        # Ensure close() always runs even if commit() fails
        try:
            db.commit()  # Commit read-only transaction to avoid implicit rollback
        finally:
            db.close()


@router.get("/observability/tools/errors", response_model=dict)
@require_permission("admin.system_config", allow_admin_bypass=False)
async def get_tool_errors(
    request: Request,  # pylint: disable=unused-argument
    hours: int = Query(24, ge=1, le=168, description="Time range in hours"),
    limit: int = Query(20, ge=5, le=settings.pagination_max_page_size, description="Number of tools to return"),
    _user=Depends(get_current_user_with_permissions),
    db: Session = Depends(get_db),
):
    """Get tool error rates and statistics.

    Args:
        request: FastAPI request object
        hours: Number of hours to look back (1-168)
        limit: Maximum number of tools to return (5-pagination_max_page_size)
        _user: Authenticated user (required by dependency)
        db: Database session for permission checks.

    Returns:
        dict: Tool error statistics

    Raises:
        HTTPException: 500 if calculation fails
    """
    db = next(get_db())
    try:
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)
        cutoff_time_naive = cutoff_time.replace(tzinfo=None)
        dialect_name = db.get_bind().dialect.name

        # Query tool error rates
        # Create expression once and reuse to avoid PostgreSQL GROUP BY errors
        tool_name_expr = extract_json_field(ObservabilitySpan.attributes, '$."tool.name"', dialect_name=dialect_name)
        tool_errors = (
            db.query(
                tool_name_expr.label("tool_name"),
                func.count(ObservabilitySpan.span_id).label("total_count"),  # pylint: disable=not-callable
                func.sum(case((ObservabilitySpan.status == "error", 1), else_=0)).label("error_count"),  # pylint: disable=not-callable
            )
            .filter(
                ObservabilitySpan.name == "tool.invoke",
                ObservabilitySpan.start_time >= cutoff_time_naive,
                tool_name_expr.isnot(None),
            )
            .group_by(tool_name_expr)
            .order_by(func.sum(case((ObservabilitySpan.status == "error", 1), else_=0)).desc())  # pylint: disable=not-callable
            .limit(limit)
            .all()
        )

        tools = [
            {
                "tool_name": row.tool_name,
                "total_count": row.total_count,
                "error_count": row.error_count or 0,
                "error_rate": round((row.error_count / row.total_count * 100) if row.total_count > 0 and row.error_count else 0, 2),
            }
            for row in tool_errors
        ]

        return {"tools": tools, "time_range_hours": hours}
    except Exception as e:
        LOGGER.error(f"Failed to get tool error statistics: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve tool error statistics")
    finally:
        # Ensure close() always runs even if commit() fails
        try:
            db.commit()  # Commit read-only transaction to avoid implicit rollback
        finally:
            db.close()


@router.get("/observability/tools/chains", response_model=dict)
@require_permission("admin.system_config", allow_admin_bypass=False)
async def get_tool_chains(
    request: Request,  # pylint: disable=unused-argument
    hours: int = Query(24, ge=1, le=168, description="Time range in hours"),
    limit: int = Query(20, ge=5, le=settings.pagination_max_page_size, description="Number of chains to return"),
    _user=Depends(get_current_user_with_permissions),
    db: Session = Depends(get_db),
):
    """Get tool chain analysis (which tools are invoked together in the same trace).

    Args:
        request: FastAPI request object
        hours: Number of hours to look back (1-168)
        limit: Maximum number of chains to return (5-pagination_max_page_size)
        _user: Authenticated user (required by dependency)
        db: Database session for permission checks.

    Returns:
        dict: Tool chain statistics showing common tool sequences

    Raises:
        HTTPException: 500 if calculation fails
    """
    db = next(get_db())
    try:
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)
        cutoff_time_naive = cutoff_time.replace(tzinfo=None)
        dialect_name = db.get_bind().dialect.name

        # Get all tool invocations grouped by trace_id
        # Create expression once and reuse to avoid PostgreSQL GROUP BY errors
        tool_name_expr = extract_json_field(ObservabilitySpan.attributes, '$."tool.name"', dialect_name=dialect_name)
        tool_spans = (
            db.query(
                ObservabilitySpan.trace_id,
                tool_name_expr.label("tool_name"),
                ObservabilitySpan.start_time,
            )
            .filter(
                ObservabilitySpan.name == "tool.invoke",
                ObservabilitySpan.start_time >= cutoff_time_naive,
                tool_name_expr.isnot(None),
            )
            .order_by(ObservabilitySpan.trace_id, ObservabilitySpan.start_time)
            .all()
        )

        # Group tools by trace and create chains
        trace_tools = {}
        for span in tool_spans:
            if span.trace_id not in trace_tools:
                trace_tools[span.trace_id] = []
            trace_tools[span.trace_id].append(span.tool_name)

        # Count tool chain frequencies
        chain_counts = {}
        for tools in trace_tools.values():
            if len(tools) > 1:
                # Create a chain string (sorted to treat [A,B] and [B,A] as same chain)
                chain = " -> ".join(tools)
                chain_counts[chain] = chain_counts.get(chain, 0) + 1

        # Sort by frequency and take top N
        sorted_chains = sorted(chain_counts.items(), key=lambda x: x[1], reverse=True)[:limit]

        chains = [{"chain": chain, "count": count} for chain, count in sorted_chains]

        return {"chains": chains, "total_traces_with_tools": len(trace_tools), "time_range_hours": hours}
    except Exception as e:
        LOGGER.error(f"Failed to get tool chain statistics: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve tool chain statistics")
    finally:
        # Ensure close() always runs even if commit() fails
        try:
            db.commit()  # Commit read-only transaction to avoid implicit rollback
        finally:
            db.close()


@router.get("/observability/tools/partial", response_class=HTMLResponse)
@require_permission("admin.system_config", allow_admin_bypass=False)
async def get_tools_partial(
    request: Request,
    _user=Depends(get_current_user_with_permissions),
    _db: Session = Depends(get_db),
):
    """Render the tool invocation metrics dashboard HTML partial.

    Args:
        request: FastAPI request object
        _user: Authenticated user (required by dependency)
        _db: Database session for permission checks.

    Returns:
        HTMLResponse: Rendered tool metrics dashboard partial
    """
    root_path = _resolve_root_path(request)
    return request.app.state.templates.TemplateResponse(
        request,
        "observability_tools.html",
        {
            "request": request,
            "root_path": root_path,
        },
    )


# ==============================================================================
# Prompts Observability Endpoints
# ==============================================================================


@router.get("/observability/prompts/usage", response_model=dict)
@require_permission("admin.system_config", allow_admin_bypass=False)
async def get_prompt_usage(
    request: Request,  # pylint: disable=unused-argument
    hours: int = Query(24, ge=1, le=168, description="Time range in hours"),
    limit: int = Query(20, ge=5, le=settings.pagination_max_page_size, description="Number of prompts to return"),
    _user=Depends(get_current_user_with_permissions),
    db: Session = Depends(get_db),
):
    """Get prompt rendering frequency statistics.

    Args:
        request: FastAPI request object
        hours: Number of hours to look back (1-168)
        limit: Maximum number of prompts to return (5-pagination_max_page_size)
        _user: Authenticated user (required by dependency)
        db: Database session for permission checks.

    Returns:
        dict: Prompt usage statistics with counts and percentages

    Raises:
        HTTPException: 500 if calculation fails
    """
    db = next(get_db())
    try:
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)
        cutoff_time_naive = cutoff_time.replace(tzinfo=None)
        dialect_name = db.get_bind().dialect.name

        # Query prompt renders from spans (looking for prompts/get calls)
        # The prompt id should be in attributes as "prompt.id"
        # Create expression once and reuse to avoid PostgreSQL GROUP BY errors
        prompt_id_expr = extract_json_field(ObservabilitySpan.attributes, '$."prompt.id"', dialect_name=dialect_name)
        prompt_usage = (
            db.query(
                prompt_id_expr.label("prompt_id"),
                func.count(ObservabilitySpan.span_id).label("count"),  # pylint: disable=not-callable
            )
            .filter(
                ObservabilitySpan.name.in_(["prompt.get", "prompts.get", "prompt.render"]),
                ObservabilitySpan.start_time >= cutoff_time_naive,
                prompt_id_expr.isnot(None),
            )
            .group_by(prompt_id_expr)
            .order_by(func.count(ObservabilitySpan.span_id).desc())  # pylint: disable=not-callable
            .limit(limit)
            .all()
        )

        total_renders = sum(row.count for row in prompt_usage)

        prompts = [
            {
                "prompt_id": row.prompt_id,
                "count": row.count,
                "percentage": round((row.count / total_renders * 100) if total_renders > 0 else 0, 2),
            }
            for row in prompt_usage
        ]

        return {"prompts": prompts, "total_renders": total_renders, "time_range_hours": hours}
    except Exception as e:
        LOGGER.error(f"Failed to get prompt usage statistics: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve prompt usage statistics")
    finally:
        # Ensure close() always runs even if commit() fails
        try:
            db.commit()  # Commit read-only transaction to avoid implicit rollback
        finally:
            db.close()


@router.get("/observability/prompts/performance", response_model=dict)
@require_permission("admin.system_config", allow_admin_bypass=False)
async def get_prompt_performance(
    request: Request,  # pylint: disable=unused-argument
    hours: int = Query(24, ge=1, le=168, description="Time range in hours"),
    limit: int = Query(20, ge=5, le=settings.pagination_max_page_size, description="Number of prompts to return"),
    _user=Depends(get_current_user_with_permissions),
    db: Session = Depends(get_db),
):
    """Get prompt performance metrics (avg, min, max duration).

    Args:
        request: FastAPI request object
        hours: Number of hours to look back (1-168)
        limit: Maximum number of prompts to return (5-pagination_max_page_size)
        _user: Authenticated user (required by dependency)
        db: Database session for permission checks.

    Returns:
        dict: Prompt performance metrics

    Raises:
        HTTPException: 500 if calculation fails
    """
    db = next(get_db())
    try:
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)
        cutoff_time_naive = cutoff_time.replace(tzinfo=None)

        # Use shared helper to compute performance grouped by the JSON attribute
        prompts = _get_span_entity_performance(
            db=db,
            cutoff_time=cutoff_time,
            cutoff_time_naive=cutoff_time_naive,
            span_names=["prompt.get", "prompts.get", "prompt.render"],
            json_key="prompt.id",
            result_key="prompt_id",
            limit=limit,
        )

        return {"prompts": prompts, "time_range_hours": hours}
    except Exception as e:
        LOGGER.error(f"Failed to get prompt performance metrics: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve prompt performance metrics")
    finally:
        # Ensure close() always runs even if commit() fails
        try:
            db.commit()  # Commit read-only transaction to avoid implicit rollback
        finally:
            db.close()


@router.get("/observability/prompts/errors", response_model=dict)
@require_permission("admin.system_config", allow_admin_bypass=False)
async def get_prompts_errors(
    hours: int = Query(24, description="Time range in hours"),
    limit: int = Query(20, description="Maximum number of results"),
    _user=Depends(get_current_user_with_permissions),
    db: Session = Depends(get_db),
):
    """Get prompt error rates.

    Args:
        hours: Time range in hours to analyze
        limit: Maximum number of prompts to return
        _user: Authenticated user (required by dependency)
        db: Database session for permission checks.

    Returns:
        dict: Prompt error statistics
    """
    db = next(get_db())
    try:
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)
        cutoff_time_naive = cutoff_time.replace(tzinfo=None)
        dialect_name = db.get_bind().dialect.name

        # Get all prompt spans with their status
        # Create expression once and reuse to avoid PostgreSQL GROUP BY errors
        prompt_id_expr = extract_json_field(ObservabilitySpan.attributes, '$."prompt.id"', dialect_name=dialect_name)
        prompt_stats = (
            db.query(
                prompt_id_expr.label("prompt_id"),
                func.count().label("total_count"),  # pylint: disable=not-callable
                func.sum(case((ObservabilitySpan.status == "error", 1), else_=0)).label("error_count"),
            )
            .filter(
                ObservabilitySpan.name == "prompt.render",
                ObservabilitySpan.start_time >= cutoff_time_naive,
                prompt_id_expr.isnot(None),
            )
            .group_by(prompt_id_expr)
            .all()
        )

        prompts_data = []
        for stat in prompt_stats:
            total = stat.total_count
            errors = stat.error_count or 0
            error_rate = round((errors / total * 100), 2) if total > 0 else 0

            prompts_data.append({"prompt_id": stat.prompt_id, "total_count": total, "error_count": errors, "error_rate": error_rate})

        # Sort by error rate descending
        prompts_data.sort(key=lambda x: x["error_rate"], reverse=True)
        prompts_data = prompts_data[:limit]

        return {"prompts": prompts_data, "time_range_hours": hours}
    finally:
        # Ensure close() always runs even if commit() fails
        try:
            db.commit()  # Commit read-only transaction to avoid implicit rollback
        finally:
            db.close()


@router.get("/observability/prompts/partial", response_class=HTMLResponse)
@require_permission("admin.system_config", allow_admin_bypass=False)
async def get_prompts_partial(
    request: Request,
    _user=Depends(get_current_user_with_permissions),
    _db: Session = Depends(get_db),
):
    """Render the prompt rendering metrics dashboard HTML partial.

    Args:
        request: FastAPI request object
        _user: Authenticated user (required by dependency)
        _db: Database session for permission checks.

    Returns:
        HTMLResponse: Rendered prompt metrics dashboard partial
    """
    root_path = _resolve_root_path(request)
    return request.app.state.templates.TemplateResponse(
        request,
        "observability_prompts.html",
        {
            "request": request,
            "root_path": root_path,
        },
    )


# ==============================================================================
# Resources Observability Endpoints
# ==============================================================================


@router.get("/observability/resources/usage", response_model=dict)
@require_permission("admin.system_config", allow_admin_bypass=False)
async def get_resource_usage(
    request: Request,  # pylint: disable=unused-argument
    hours: int = Query(24, ge=1, le=168, description="Time range in hours"),
    limit: int = Query(20, ge=5, le=settings.pagination_max_page_size, description="Number of resources to return"),
    _user=Depends(get_current_user_with_permissions),
    db: Session = Depends(get_db),
):
    """Get resource fetch frequency statistics.

    Args:
        request: FastAPI request object
        hours: Number of hours to look back (1-168)
        limit: Maximum number of resources to return (5-pagination_max_page_size)
        _user: Authenticated user (required by dependency)
        db: Database session for permission checks.

    Returns:
        dict: Resource usage statistics with counts and percentages

    Raises:
        HTTPException: 500 if calculation fails
    """
    db = next(get_db())
    try:
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)
        cutoff_time_naive = cutoff_time.replace(tzinfo=None)
        dialect_name = db.get_bind().dialect.name

        # Query resource reads from spans (looking for resources/read calls)
        # The resource URI should be in attributes
        # Create expression once and reuse to avoid PostgreSQL GROUP BY errors
        resource_uri_expr = extract_json_field(ObservabilitySpan.attributes, '$."resource.uri"', dialect_name=dialect_name)
        resource_usage = (
            db.query(
                resource_uri_expr.label("resource_uri"),
                func.count(ObservabilitySpan.span_id).label("count"),  # pylint: disable=not-callable
            )
            .filter(
                ObservabilitySpan.name.in_(["resource.read", "resources.read", "resource.fetch"]),
                ObservabilitySpan.start_time >= cutoff_time_naive,
                resource_uri_expr.isnot(None),
            )
            .group_by(resource_uri_expr)
            .order_by(func.count(ObservabilitySpan.span_id).desc())  # pylint: disable=not-callable
            .limit(limit)
            .all()
        )

        total_fetches = sum(row.count for row in resource_usage)

        resources = [
            {
                "resource_uri": row.resource_uri,
                "count": row.count,
                "percentage": round((row.count / total_fetches * 100) if total_fetches > 0 else 0, 2),
            }
            for row in resource_usage
        ]

        return {"resources": resources, "total_fetches": total_fetches, "time_range_hours": hours}
    except Exception as e:
        LOGGER.error(f"Failed to get resource usage statistics: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve resource usage statistics")
    finally:
        # Ensure close() always runs even if commit() fails
        try:
            db.commit()  # Commit read-only transaction to avoid implicit rollback
        finally:
            db.close()


@router.get("/observability/resources/performance", response_model=dict)
@require_permission("admin.system_config", allow_admin_bypass=False)
async def get_resource_performance(
    request: Request,  # pylint: disable=unused-argument
    hours: int = Query(24, ge=1, le=168, description="Time range in hours"),
    limit: int = Query(20, ge=5, le=settings.pagination_max_page_size, description="Number of resources to return"),
    _user=Depends(get_current_user_with_permissions),
    db: Session = Depends(get_db),
):
    """Get resource performance metrics (avg, min, max duration).

    Args:
        request: FastAPI request object
        hours: Number of hours to look back (1-168)
        limit: Maximum number of resources to return (5-pagination_max_page_size)
        _user: Authenticated user (required by dependency)
        db: Database session for permission checks.

    Returns:
        dict: Resource performance metrics

    Raises:
        HTTPException: 500 if calculation fails
    """
    db = next(get_db())
    try:
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)
        cutoff_time_naive = cutoff_time.replace(tzinfo=None)

        # Use shared helper to compute performance grouped by the JSON attribute
        resources = _get_span_entity_performance(
            db=db,
            cutoff_time=cutoff_time,
            cutoff_time_naive=cutoff_time_naive,
            span_names=["resource.read", "resources.read", "resource.fetch"],
            json_key="resource.uri",
            result_key="resource_uri",
            limit=limit,
        )

        return {"resources": resources, "time_range_hours": hours}
    except Exception as e:
        LOGGER.error(f"Failed to get resource performance metrics: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve resource performance metrics")
    finally:
        # Ensure close() always runs even if commit() fails
        try:
            db.commit()  # Commit read-only transaction to avoid implicit rollback
        finally:
            db.close()


@router.get("/observability/resources/errors", response_model=dict)
@require_permission("admin.system_config", allow_admin_bypass=False)
async def get_resources_errors(
    hours: int = Query(24, description="Time range in hours"),
    limit: int = Query(20, description="Maximum number of results"),
    _user=Depends(get_current_user_with_permissions),
    db: Session = Depends(get_db),
):
    """Get resource error rates.

    Args:
        hours: Time range in hours to analyze
        limit: Maximum number of resources to return
        _user: Authenticated user (required by dependency)
        db: Database session for permission checks.

    Returns:
        dict: Resource error statistics
    """
    db = next(get_db())
    try:
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)
        cutoff_time_naive = cutoff_time.replace(tzinfo=None)
        dialect_name = db.get_bind().dialect.name

        # Get all resource spans with their status
        # Create expression once and reuse to avoid PostgreSQL GROUP BY errors
        resource_uri_expr = extract_json_field(ObservabilitySpan.attributes, '$."resource.uri"', dialect_name=dialect_name)
        resource_stats = (
            db.query(
                resource_uri_expr.label("resource_uri"),
                func.count().label("total_count"),  # pylint: disable=not-callable
                func.sum(case((ObservabilitySpan.status == "error", 1), else_=0)).label("error_count"),
            )
            .filter(
                ObservabilitySpan.name.in_(["resource.read", "resources.read", "resource.fetch"]),
                ObservabilitySpan.start_time >= cutoff_time_naive,
                resource_uri_expr.isnot(None),
            )
            .group_by(resource_uri_expr)
            .all()
        )

        resources_data = []
        for stat in resource_stats:
            total = stat.total_count
            errors = stat.error_count or 0
            error_rate = round((errors / total * 100), 2) if total > 0 else 0

            resources_data.append({"resource_uri": stat.resource_uri, "total_count": total, "error_count": errors, "error_rate": error_rate})

        # Sort by error rate descending
        resources_data.sort(key=lambda x: x["error_rate"], reverse=True)
        resources_data = resources_data[:limit]

        return {"resources": resources_data, "time_range_hours": hours}
    finally:
        # Ensure close() always runs even if commit() fails
        try:
            db.commit()  # Commit read-only transaction to avoid implicit rollback
        finally:
            db.close()


@router.get("/observability/resources/partial", response_class=HTMLResponse)
@require_permission("admin.system_config", allow_admin_bypass=False)
async def get_resources_partial(
    request: Request,
    _user=Depends(get_current_user_with_permissions),
    _db: Session = Depends(get_db),
):
    """Render the resource fetch metrics dashboard HTML partial.

    Args:
        request: FastAPI request object
        _user: Authenticated user (required by dependency)
        _db: Database session for permission checks.

    Returns:
        HTMLResponse: Rendered resource metrics dashboard partial
    """
    root_path = _resolve_root_path(request)
    return request.app.state.templates.TemplateResponse(
        request,
        "observability_resources.html",
        {
            "request": request,
            "root_path": root_path,
        },
    )
