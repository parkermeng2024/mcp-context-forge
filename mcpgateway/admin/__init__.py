# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/admin/__init__.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Admin UI Routes for ContextForge AI Gateway.
This module contains all the administrative UI endpoints for ContextForge AI Gateway.
It provides a comprehensive interface for managing servers, tools, resources,
prompts, gateways, and roots through RESTful API endpoints. The module handles
all aspects of CRUD operations for these entities, including creation,
reading, updating, deletion, and status toggling.

All endpoints in this module require authentication, which is enforced via
the require_auth or require_basic_auth dependency. The module integrates with
various services to perform the actual business logic operations on the
underlying data.
"""

# Standard
import base64
import binascii
from datetime import datetime, timedelta, timezone
import html
import logging
import math
import re
import time
from typing import Any
from typing import cast as typing_cast
from typing import Dict, List, Optional, Union
import urllib.parse
import uuid

# Third-Party
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.encoders import jsonable_encoder
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials
import httpx
import orjson
from pydantic import BaseModel, SecretStr, ValidationError
from pydantic_core import ValidationError as CoreValidationError
from sqlalchemy import and_, case, desc, false, func, or_, select
from sqlalchemy.exc import DataError, IntegrityError, InvalidRequestError, OperationalError
from sqlalchemy.orm import joinedload, selectinload, Session, with_loader_criteria
from sqlalchemy.sql.functions import coalesce

# First-Party
from mcpgateway import __version__
from mcpgateway import version as version_module

# Authentication and password-related imports
from mcpgateway.auth import get_current_user
from mcpgateway.auth_user_helpers import is_passwordless_user

# Re-export canonical get_user_email from auth_context for backward compatibility.
from mcpgateway.auth_context import (
    configuration_export_includes_roots as configuration_export_includes_roots,
    extract_token_team_ids,
    get_scoped_resource_access_context,
    get_token_teams_from_request,
    get_user_email,
    import_envelope_includes_roots as import_envelope_includes_roots,
    is_unrestricted_platform_admin,
    selective_selection_includes_roots as selective_selection_includes_roots,
)
from mcpgateway.cache.a2a_stats_cache import a2a_stats_cache
from mcpgateway.cache.global_config_cache import global_config_cache
from mcpgateway.common.models import LogLevel as LogLevel
from mcpgateway.common.query_params import (
    QueryEntityType as QueryEntityType,
    QueryEntityTypes,
    QueryExportFormatAliased as QueryExportFormatAliased,
    QueryGatewayIdList,
    QueryPeriodType as QueryPeriodType,
    QueryRelationship,
    QueryRenderMode,
    QueryRenderModeControls,
    QueryRenderModeUserSelector,
    QueryTagsFilter,
    QueryVisibility,
    QueryVisibilityCompact,
)
from mcpgateway.common.validators import SecurityValidator
from mcpgateway.config import settings, UI_HIDABLE_HEADER_ITEMS as UI_HIDABLE_HEADER_ITEMS, UI_HIDABLE_SECTIONS as UI_HIDABLE_SECTIONS, UI_HIDE_SECTION_ALIASES as UI_HIDE_SECTION_ALIASES
from mcpgateway.db import A2AAgent as DbA2AAgent
from mcpgateway.db import EmailApiToken, EmailTeam, EmailUser
from mcpgateway.db import Gateway as DbGateway
from mcpgateway.db import get_db, GlobalConfig
from mcpgateway.db import Prompt as DbPrompt
from mcpgateway.db import Resource as DbResource
from mcpgateway.db import Server as DbServer
from mcpgateway.db import SessionLocal
from mcpgateway.db import Tool as DbTool
from mcpgateway.db import utc_now
from mcpgateway.i18n import t as i18n_t
from mcpgateway.middleware.rbac import _ACCESS_DENIED_MSG, get_current_user_with_permissions, require_admin_permission, require_any_permission, require_permission
from mcpgateway.routers.email_auth import create_access_token
from mcpgateway.schemas import (
    _encode_auth_headers_list,
    A2AAgentCreate as A2AAgentCreate,
    A2AAgentRead as A2AAgentRead,
    A2AAgentUpdate as A2AAgentUpdate,
    CatalogBulkRegisterRequest as CatalogBulkRegisterRequest,
    CatalogBulkRegisterResponse as CatalogBulkRegisterResponse,
    CatalogListRequest,
    CatalogListResponse as CatalogListResponse,
    CatalogServerRegisterRequest as CatalogServerRegisterRequest,
    CatalogServerRegisterResponse as CatalogServerRegisterResponse,
    CatalogServerStatusResponse as CatalogServerStatusResponse,
    GatewayCreate,
    GatewayOwnershipTransferRequest,
    GatewayRead,
    GatewayTestRequest,
    GatewayTestResponse,
    GatewayUpdate,
    GlobalConfigRead,
    GlobalConfigUpdate,
    PaginatedResponse,
    PaginationMeta,
    PluginDetail as PluginDetail,
    PluginListResponse as PluginListResponse,
    PluginModeUpdateRequest as PluginModeUpdateRequest,
    PluginModeUpdateResponse as PluginModeUpdateResponse,
    PluginStatsResponse as PluginStatsResponse,
    PluginToggleRequest as PluginToggleRequest,
    PluginToggleResponse as PluginToggleResponse,
    PromptCreate,
    PromptMetrics as PromptMetrics,
    PromptRead,
    PromptUpdate,
    ResourceCreate,
    ResourceMetrics as ResourceMetrics,
    ResourceUpdate,
    ServerCreate,
    ServerMetrics as ServerMetrics,
    ServerRead,
    ServerUpdate,
    ToolCreate,
    ToolMetrics as ToolMetrics,
    ToolRead,
    ToolUpdate,
)
from mcpgateway.services.a2a_agent_plugin_binding_service import (
    A2AAgentPluginBindingForbiddenError as A2AAgentPluginBindingForbiddenError,
    A2AAgentPluginBindingNotFoundError as A2AAgentPluginBindingNotFoundError,
    A2AAgentPluginBindingService as A2AAgentPluginBindingService,
)
from mcpgateway.services.a2a_service import (
    A2AAgentError as A2AAgentError,
    A2AAgentNameConflictError as A2AAgentNameConflictError,
    A2AAgentNotFoundError as A2AAgentNotFoundError,
    A2AAgentService as A2AAgentService,
)
from mcpgateway.services.argon2_service import Argon2PasswordService
from mcpgateway.services.audit_trail_service import get_audit_trail_service as get_audit_trail_service
from mcpgateway.services.catalog_service import catalog_service, CatalogRegistrationPermissionError as CatalogRegistrationPermissionError
from mcpgateway.services.content_security import ContentSizeError, ContentTypeError, TemplateValidationError
from mcpgateway.services.csrf_service import get_csrf_service as get_csrf_service
from mcpgateway.services.email_auth_service import AuthenticationError, EmailAuthService, PasswordValidationError
from mcpgateway.services.encryption_service import get_encryption_service
from mcpgateway.services.export_service import ExportError as ExportError, ExportService as ExportService
from mcpgateway.services.gateway_service import (
    gateway_capability_loaders,
    GatewayConnectionError,
    GatewayCredentialError,
    GatewayDuplicateConflictError,
    GatewayLookupConflictError,
    GatewayNameConflictError,
    GatewayNotFoundError,
    GatewayToolNameConflictError,
    GatewayService,
    test_gateway_connectivity,
)
from mcpgateway.services.import_service import ConflictStrategy as ConflictStrategy
from mcpgateway.services.import_service import ImportService as ImportService, ImportValidationError as ImportValidationError
from mcpgateway.services.logging_service import LoggingService
from mcpgateway.services.openapi_service import fetch_and_extract_schemas
from mcpgateway.services.password_policy_service import PasswordPolicyService
from mcpgateway.services.performance_service import get_performance_service as get_performance_service
from mcpgateway.services.permission_service import PermissionService
from mcpgateway.services.plugin_service import get_plugin_service, sync_plugin_service_from_runtime
from mcpgateway.services.prompt_service import PromptArgumentsJSONError, PromptNameConflictError, PromptNotFoundError, PromptService
from mcpgateway.services.resource_service import ResourceError, ResourceNotFoundError, ResourceService, ResourceURIConflictError, ResourceValidationError
from mcpgateway.services.root_service import RootService as RootService, RootServiceError, RootServiceNotFoundError, RootServiceValidationError
from mcpgateway.services.server_service import ServerError, ServerLockConflictError, ServerNameConflictError, ServerNotFoundError, ServerService
from mcpgateway.services.structured_logger import get_structured_logger as get_structured_logger
from mcpgateway.services.tag_service import TagService as TagService
from mcpgateway.services.team_management_service import JoinRequestNotFoundError as JoinRequestNotFoundError, TeamManagementService, UNSET
from mcpgateway.services.token_catalog_service import TokenCatalogService
from mcpgateway.services.tool_service import ToolError, ToolLockConflictError, ToolNameConflictError, ToolNotFoundError, ToolService
from mcpgateway.utils.create_jwt_token import create_jwt_token, get_jwt_token
from mcpgateway.utils.error_formatter import ErrorFormatter, sanitize_validation_error_for_log
from mcpgateway.utils.log_sanitizer import sanitize_for_log as sanitize_for_log
from mcpgateway.utils.metadata_capture import MetadataCapture
from mcpgateway.utils.oauth_resource import parse_oauth_resource_form as parse_oauth_resource_form
from mcpgateway.utils.orjson_response import ORJSONResponse
from mcpgateway.utils.pagination import paginate_query
from mcpgateway.utils.passthrough_headers import PassthroughHeadersError
from mcpgateway.utils.paths import is_path_within as is_path_within, open_confined as open_confined
from mcpgateway.utils.paths import resolve_root_path as _resolve_root_path
from mcpgateway.utils.security_cookies import clear_auth_cookie, CookieTooLargeError, set_auth_cookie
from mcpgateway.utils.services_auth import encode_auth
from mcpgateway.utils.sqlalchemy_modifier import json_contains_tag_expr as json_contains_tag_expr
from mcpgateway.utils.validate_signature import sign_data
from mcpgateway.utils.origin import is_allowed_redirect as is_allowed_redirect, normalize_origin_parts as normalize_origin_parts, origin_from_url as origin_from_url
from mcpgateway.utils.verify_credentials import verify_jwt_token_cached

# Re-export cross-cutting helpers from the focused submodules extracted out of
# this package so existing ``from mcpgateway.admin import X`` sites (and test
# patch targets) keep working unchanged.
from mcpgateway.admin.assets import _bundle_css_cache as _bundle_css_cache, _bundle_js_cache as _bundle_js_cache, get_bundle_css_files, get_bundle_js_filename, load_sri_hashes  # noqa: PLC2701
from mcpgateway.admin.common import (  # noqa: PLC2701
    _adjust_pagination_for_conversion_failures as _adjust_pagination_for_conversion_failures,
    _apply_tag_filter_groups,
    _assemble_oauth_config_from_fields as _assemble_oauth_config_from_fields,
    _build_admin_redirect,
    _build_search_response,
    _check_public_visibility_allowed,
    _escape_like,
    _form_team_id,
    _get_user_team_ids,
    _get_user_team_roles as _get_user_team_roles,
    _is_explicit_token_team_scope as _is_explicit_token_team_scope,
    _like_contains,
    _merge_select_all_ids,
    _normalize_int_query,
    _normalize_search_query,
    _normalize_tags_query,
    _normalize_team_id,
    _owner_access_condition,
    _parse_tag_filter_groups,
    _read_request_json as _read_request_json,
    _TAG_MAX_GROUPS as _TAG_MAX_GROUPS,
    _TAG_MAX_TERMS_PER_GROUP as _TAG_MAX_TERMS_PER_GROUP,
    _validated_team_id_param,
    a2a_service,
    export_service as export_service,
    gateway_service,
    get_user_id as get_user_id,
    import_service as import_service,
    prompt_service,
    resource_service,
    root_service,
    server_service,
    tool_service,
)
from mcpgateway.admin.security import (  # noqa: PLC2701
    _admin_cookie_path as _admin_cookie_path,
    _clear_admin_csrf_cookie,
    _request_origin_matches as _request_origin_matches,
    _set_admin_csrf_cookie,
    ADMIN_CSRF_COOKIE_NAME as ADMIN_CSRF_COOKIE_NAME,
    ADMIN_CSRF_FORM_FIELD as ADMIN_CSRF_FORM_FIELD,
    ADMIN_CSRF_HEADER_NAME as ADMIN_CSRF_HEADER_NAME,
    enforce_admin_csrf,
    get_client_ip,
    get_user_agent,
    rate_limit,
    rate_limit_storage as rate_limit_storage,
)
from mcpgateway.admin.visibility import (  # noqa: PLC2701
    _extract_permission_from_route as _extract_permission_from_route,
    _normalize_ui_hide_values as _normalize_ui_hide_values,
    _SECTION_TO_ROUTE_PATH as _SECTION_TO_ROUTE_PATH,
    get_hidden_sections_for_user,
    get_ui_visibility_config,
    get_user_action_permissions,
    SECTION_PERMISSIONS as SECTION_PERMISSIONS,
    UI_ACTION_PERMISSIONS,
    UI_EMBEDDED_DEFAULT_HIDDEN_HEADER_ITEMS as UI_EMBEDDED_DEFAULT_HIDDEN_HEADER_ITEMS,
    UI_HIDE_SECTIONS_COOKIE_MAX_AGE,
    UI_HIDE_SECTIONS_COOKIE_NAME,
    UI_SECTION_TO_TABS as UI_SECTION_TO_TABS,
    validate_section_permissions as validate_section_permissions,
)
from mcpgateway.admin.observability import (  # noqa: PLC2701
    _get_latency_heatmap_postgresql as _get_latency_heatmap_postgresql,
    _get_latency_heatmap_python as _get_latency_heatmap_python,
    _get_latency_percentiles_postgresql as _get_latency_percentiles_postgresql,
    _get_latency_percentiles_python as _get_latency_percentiles_python,
    _get_span_entity_performance as _get_span_entity_performance,
    _get_timeseries_metrics_postgresql as _get_timeseries_metrics_postgresql,
    _get_timeseries_metrics_python as _get_timeseries_metrics_python,
    router as _observability_router,
)
from mcpgateway.admin.mcp_registry import (  # noqa: PLC2701
    bulk_register_catalog_servers as bulk_register_catalog_servers,
    catalog_partial as catalog_partial,
    check_catalog_server_status as check_catalog_server_status,
    list_catalog_servers as list_catalog_servers,
    register_catalog_server as register_catalog_server,
    router as _mcp_registry_router,
)
from mcpgateway.admin.plugins import (  # noqa: PLC2701
    _render_a2a_plugin_bindings_partial as _render_a2a_plugin_bindings_partial,
    admin_create_a2a_plugin_binding as admin_create_a2a_plugin_binding,
    admin_delete_a2a_plugin_binding as admin_delete_a2a_plugin_binding,
    get_a2a_plugin_bindings_partial as get_a2a_plugin_bindings_partial,
    get_plugin_details as get_plugin_details,
    get_plugin_stats as get_plugin_stats,
    get_plugins_partial as get_plugins_partial,
    list_plugins as list_plugins,
    toggle_plugins_global as toggle_plugins_global,
    update_plugin_mode as update_plugin_mode,
    router as _plugins_router,
)
from mcpgateway.admin.performance import (  # noqa: PLC2701
    get_performance_cache as get_performance_cache,
    get_performance_history as get_performance_history,
    get_performance_requests as get_performance_requests,
    get_performance_stats as get_performance_stats,
    get_performance_system as get_performance_system,
    get_performance_workers as get_performance_workers,
    router as _performance_router,
)
from mcpgateway.admin.system import (  # noqa: PLC2701
    admin_generate_support_bundle as admin_generate_support_bundle,
    get_maintenance_partial as get_maintenance_partial,
    get_system_stats as get_system_stats,
    router as _system_router,
)
from mcpgateway.admin.events import (  # noqa: PLC2701
    admin_events as admin_events,
    router as _events_router,
)
from mcpgateway.admin.metrics import (  # noqa: PLC2701
    admin_metrics_partial_html as admin_metrics_partial_html,
    admin_reset_metrics as admin_reset_metrics,
    get_aggregated_metrics as get_aggregated_metrics,
    router as _metrics_router,
)
from mcpgateway.admin.team_join import (  # noqa: PLC2701
    admin_approve_join_request as admin_approve_join_request,
    admin_cancel_join_request as admin_cancel_join_request,
    admin_create_join_request as admin_create_join_request,
    admin_list_join_requests as admin_list_join_requests,
    admin_reject_join_request as admin_reject_join_request,
    router as _team_join_router,
)
from mcpgateway.admin.tags import (  # noqa: PLC2701
    admin_list_tags as admin_list_tags,
    router as _tags_router,
)
from mcpgateway.admin.tools_import import (  # noqa: PLC2701
    admin_import_tools as admin_import_tools,
    router as _tools_import_router,
)
from mcpgateway.admin.logs import (  # noqa: PLC2701
    admin_export_logs as admin_export_logs,
    admin_get_log_file as admin_get_log_file,
    admin_get_logs as admin_get_logs,
    admin_stream_logs as admin_stream_logs,
    router as _logs_router,
)
from mcpgateway.admin.export_import import (  # noqa: PLC2701
    admin_export_configuration as admin_export_configuration,
    admin_export_selective as admin_export_selective,
    admin_get_import_status as admin_get_import_status,
    admin_import_configuration as admin_import_configuration,
    admin_import_preview as admin_import_preview,
    admin_list_import_statuses as admin_list_import_statuses,
    router as _export_import_router,
)
from mcpgateway.admin.a2a import (  # noqa: PLC2701
    admin_add_a2a_agent as admin_add_a2a_agent,
    admin_delete_a2a_agent as admin_delete_a2a_agent,
    admin_edit_a2a_agent as admin_edit_a2a_agent,
    admin_get_agent as admin_get_agent,
    admin_get_all_agent_ids as admin_get_all_agent_ids,
    admin_list_a2a_agents as admin_list_a2a_agents,
    admin_a2a_partial_html as admin_a2a_partial_html,
    admin_search_a2a_agents as admin_search_a2a_agents,
    admin_set_a2a_agent_state as admin_set_a2a_agent_state,
    admin_test_a2a_agent as admin_test_a2a_agent,
    router as _a2a_router,
)
from mcpgateway.admin.grpc import (  # noqa: PLC2701
    admin_create_grpc_service as admin_create_grpc_service,
    admin_delete_grpc_service as admin_delete_grpc_service,
    admin_get_grpc_methods as admin_get_grpc_methods,
    admin_get_grpc_service as admin_get_grpc_service,
    admin_list_grpc_services as admin_list_grpc_services,
    admin_reflect_grpc_service as admin_reflect_grpc_service,
    admin_set_grpc_service_state as admin_set_grpc_service_state,
    admin_update_grpc_service as admin_update_grpc_service,
    GRPC_AVAILABLE as GRPC_AVAILABLE,
    GrpcService as GrpcService,
    GrpcServiceCreate as GrpcServiceCreate,
    GrpcServiceError as GrpcServiceError,
    GrpcServiceNameConflictError as GrpcServiceNameConflictError,
    GrpcServiceNotFoundError as GrpcServiceNotFoundError,
    GrpcServiceRead as GrpcServiceRead,
    GrpcServiceUpdate as GrpcServiceUpdate,
    grpc_service_mgr as grpc_service_mgr,
    router as _grpc_router,
)

# Import the shared logging service from main
# This will be set by main.py when it imports admin_router
logging_service: Optional[LoggingService] = None
LOGGER: logging.Logger = logging.getLogger("mcpgateway.admin")


def set_logging_service(service: LoggingService):
    """Set the logging service instance to use.

    This should be called by main.py to share the same logging service.

    Args:
        service: The LoggingService instance to use

    Examples:
        >>> from mcpgateway.services.logging_service import LoggingService
        >>> from mcpgateway import admin
        >>> logging_svc = LoggingService()
        >>> admin.set_logging_service(logging_svc)
        >>> admin.logging_service is not None
        True
        >>> admin.LOGGER is not None
        True

        Test with different service instance:
        >>> new_svc = LoggingService()
        >>> admin.set_logging_service(new_svc)
        >>> admin.logging_service == new_svc
        True
        >>> admin.LOGGER.name
        'mcpgateway.admin'

        Test that global variables are properly set:
        >>> admin.set_logging_service(logging_svc)
        >>> hasattr(admin, 'logging_service')
        True
        >>> hasattr(admin, 'LOGGER')
        True
    """
    global logging_service, LOGGER  # pylint: disable=global-statement
    logging_service = service
    LOGGER = logging_service.get_logger("mcpgateway.admin")


# Fallback for testing - create a temporary instance if not set
if logging_service is None:
    logging_service = LoggingService()
    LOGGER = logging_service.get_logger("mcpgateway.admin")


# Initialize gRPC service only if gRPC features are enabled AND grpcio is installed


async def _parse_gateway_data_from_request(request: Request) -> dict[str, Any]:
    """Parse gateway data from either JSON body or form data.

    This helper function enables endpoints to accept both application/json and
    multipart/form-data content types, supporting both API clients and the HTMX UI.

    Args:
        request: FastAPI request object.

    Returns:
        Dictionary containing parsed gateway data.

    Raises:
        HTTPException: If content type is unsupported or data is malformed.
    """
    content_type = request.headers.get("content-type", "").lower()

    # Handle JSON requests
    if "application/json" in content_type:
        try:
            data = await request.json()
            # Normalize tags if provided as string
            if isinstance(data.get("tags"), str):
                data["tags"] = [tag.strip() for tag in data["tags"].split(",") if tag.strip()]
            return data
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid JSON body: {e}")

    # Handle form data requests (multipart/form-data or application/x-www-form-urlencoded)
    elif "multipart/form-data" in content_type or "application/x-www-form-urlencoded" in content_type:
        form = await request.form()
        data: dict[str, Any] = {}

        # Extract all form fields
        for key in form.keys():
            value = form.get(key)
            if value is not None:
                data[key] = value

        # Parse tags from comma-separated string
        if "tags" in data and isinstance(data["tags"], str):
            tags_str = str(data["tags"])
            data["tags"] = [tag.strip() for tag in tags_str.split(",") if tag.strip()] if tags_str else []

        # Parse auth_headers JSON if present
        if "auth_headers" in data and isinstance(data["auth_headers"], str):
            try:
                data["auth_headers"] = orjson.loads(data["auth_headers"])
            except (orjson.JSONDecodeError, ValueError):
                data["auth_headers"] = []

        # Parse passthrough_headers
        if "passthrough_headers" in data and isinstance(data["passthrough_headers"], str):
            passthrough_str = str(data["passthrough_headers"]).strip()
            if passthrough_str:
                try:
                    data["passthrough_headers"] = orjson.loads(passthrough_str)
                except (orjson.JSONDecodeError, ValueError):
                    # Fallback to comma-separated parsing
                    data["passthrough_headers"] = [h.strip() for h in passthrough_str.split(",") if h.strip()]
            else:
                data["passthrough_headers"] = None

        # Parse OAuth configuration - support both JSON string and individual form fields
        oauth_config: Optional[dict[str, Any]] = None
        oauth_config_json = str(data.get("oauth_config", ""))

        # Option 1: Pre-assembled oauth_config JSON (from API calls)
        # If oauth_config field is present (even if invalid), don't fall back to Option 2
        oauth_config_field_provided = "oauth_config" in data
        if oauth_config_json and oauth_config_json != "None":
            try:
                oauth_config = orjson.loads(oauth_config_json)
            except (orjson.JSONDecodeError, ValueError):
                # Invalid JSON - set to None in data and don't try Option 2
                oauth_config = None
                data["oauth_config"] = None
        elif oauth_config_json == "None":
            # Explicit "None" string - set to None in data
            oauth_config = None
            data["oauth_config"] = None

        # Option 2: Assemble from individual UI form fields
        # Only try this if oauth_config field was NOT provided
        # (client_secret encryption happens downstream in the service layer)
        if not oauth_config and not oauth_config_field_provided:
            oauth_config = await _assemble_oauth_config_from_fields(data, encrypt_secret=False)

        if oauth_config:
            data["oauth_config"] = oauth_config

        return data

    else:
        raise HTTPException(status_code=415, detail=f"Unsupported content type: {content_type}. Use application/json or multipart/form-data")


def _gateway_result_status(result: Any) -> Optional[str]:
    """Return lifecycle status from a gateway service result when present."""
    if isinstance(result, dict):
        status_value = result.get("status")
        return status_value if isinstance(status_value, str) else None
    if isinstance(result, BaseModel):
        status_value = getattr(result, "status", None)
        return status_value if isinstance(status_value, str) else None
    return None


def _gateway_result_payload(result: Any) -> Optional[dict[str, Any]]:
    """Serialize concrete gateway results while tolerating mocked return values."""
    if isinstance(result, dict):
        return result
    if isinstance(result, BaseModel):
        return result.model_dump(mode="json", by_alias=True)
    return None


def serialize_datetime(obj):
    """Convert datetime objects to ISO format strings for JSON serialization.

    Args:
        obj: Object to serialize, potentially a datetime

    Returns:
        str: ISO format string if obj is datetime, otherwise returns obj unchanged

    Examples:
        Test with datetime object:
        >>> from mcpgateway import admin
        >>> from datetime import datetime, timezone
        >>> dt = datetime(2025, 1, 15, 10, 30, 45, tzinfo=timezone.utc)
        >>> admin.serialize_datetime(dt)
        '2025-01-15T10:30:45+00:00'

        Test with naive datetime:
        >>> dt_naive = datetime(2025, 3, 20, 14, 15, 30)
        >>> result = admin.serialize_datetime(dt_naive)
        >>> '2025-03-20T14:15:30' in result
        True

        Test with datetime with microseconds:
        >>> dt_micro = datetime(2025, 6, 10, 9, 25, 12, 500000)
        >>> result = admin.serialize_datetime(dt_micro)
        >>> '2025-06-10T09:25:12.500000' in result
        True

        Test with non-datetime objects (should return unchanged):
        >>> admin.serialize_datetime("2025-01-15T10:30:45")
        '2025-01-15T10:30:45'
        >>> admin.serialize_datetime(12345)
        12345
        >>> admin.serialize_datetime(['a', 'list'])
        ['a', 'list']
        >>> admin.serialize_datetime({'key': 'value'})
        {'key': 'value'}
        >>> admin.serialize_datetime(None)
        >>> admin.serialize_datetime(True)
        True

        Test with current datetime:
        >>> import datetime as dt_module
        >>> now = dt_module.datetime.now()
        >>> result = admin.serialize_datetime(now)
        >>> isinstance(result, str)
        True
        >>> 'T' in result  # ISO format contains 'T' separator
        True

        Test edge case with datetime min/max:
        >>> dt_min = datetime.min
        >>> result = admin.serialize_datetime(dt_min)
        >>> result.startswith('0001-01-01T')
        True
    """
    if isinstance(obj, datetime):
        return obj.isoformat()
    return obj


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


admin_router = APIRouter(
    prefix="/admin",
    tags=["Admin UI"],
    dependencies=[Depends(enforce_admin_csrf)],
)

####################
# Admin UI Routes  #
####################


async def _has_permission(
    *,
    db: Session,
    user: dict,
    permission: str,
    team_id: Optional[str] = None,
    allow_admin_bypass: bool = False,
    check_any_team: bool = False,
) -> bool:
    """Check a permission for the current user context.

    Args:
        db (Session): Database session.
        user (dict): Authenticated user context.
        permission (str): Permission to evaluate.
        team_id (Optional[str]): Optional team scope for the permission check.
        allow_admin_bypass (bool): Whether admin bypass is allowed.
        check_any_team (bool): Whether to check across all team-scoped roles.

    Returns:
        bool: True when permission is granted.
    """
    permission_service = PermissionService(db)
    return await permission_service.check_permission(
        user_email=get_user_email(user),
        permission=permission,
        team_id=team_id,
        token_teams=user.get("token_teams"),
        ip_address=user.get("ip_address"),
        user_agent=user.get("user_agent"),
        allow_admin_bypass=allow_admin_bypass,
        check_any_team=check_any_team,
    )


@admin_router.get("/overview/partial")
@require_permission("admin.overview", allow_admin_bypass=False)
async def get_overview_partial(
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> HTMLResponse:
    """Render the overview dashboard partial HTML template.

    This endpoint returns a rendered HTML partial containing an architecture
    diagram showing ContextForge inputs (Virtual Servers), middleware (Plugins),
    and outputs (A2A Agents, Gateways, Tools, etc.) along with key metrics.

    Args:
        request: FastAPI request object
        db: Database session
        user: Authenticated user

    Returns:
        HTMLResponse with rendered overview partial template
    """
    LOGGER.debug(f"User {get_user_email(user)} requested overview partial")

    try:
        # Gather counts for all entity types
        # Note: SQLAlchemy func.count requires pylint disable=not-callable
        # Virtual Servers (inputs) - uses 'enabled' field
        servers_total = db.query(func.count(DbServer.id)).scalar() or 0  # pylint: disable=not-callable
        servers_active = db.query(func.count(DbServer.id)).filter(DbServer.enabled.is_(True)).scalar() or 0  # pylint: disable=not-callable

        # Gateways - uses 'enabled' field
        gateways_total = db.query(func.count(DbGateway.id)).scalar() or 0  # pylint: disable=not-callable
        gateways_active = db.query(func.count(DbGateway.id)).filter(DbGateway.enabled.is_(True)).scalar() or 0  # pylint: disable=not-callable

        # A2A Agents (if enabled) - uses 'enabled' field
        a2a_total = 0
        a2a_active = 0
        if settings.mcpgateway_a2a_enabled:
            a2a_total = db.query(func.count(DbA2AAgent.id)).scalar() or 0  # pylint: disable=not-callable
            a2a_active = db.query(func.count(DbA2AAgent.id)).filter(DbA2AAgent.enabled.is_(True)).scalar() or 0  # pylint: disable=not-callable

        # Tools - uses 'enabled' field
        tools_total = db.query(func.count(DbTool.id)).scalar() or 0  # pylint: disable=not-callable
        tools_active = db.query(func.count(DbTool.id)).filter(DbTool.enabled.is_(True)).scalar() or 0  # pylint: disable=not-callable

        # Prompts - uses 'enabled' field
        prompts_total = db.query(func.count(DbPrompt.id)).scalar() or 0  # pylint: disable=not-callable
        prompts_active = db.query(func.count(DbPrompt.id)).filter(DbPrompt.enabled.is_(True)).scalar() or 0  # pylint: disable=not-callable

        # Resources - uses 'enabled' field
        resources_total = db.query(func.count(DbResource.id)).scalar() or 0  # pylint: disable=not-callable
        resources_active = db.query(func.count(DbResource.id)).filter(DbResource.enabled.is_(True)).scalar() or 0  # pylint: disable=not-callable

        # Plugin stats — self-heal the cache so the overview reflects the live
        # shared toggle even on a process that booted with plugins disabled.
        overview_plugin_service = get_plugin_service()
        await sync_plugin_service_from_runtime(request, overview_plugin_service)
        plugin_stats = await overview_plugin_service.get_plugin_statistics()

        # Infrastructure status (database, cache, uptime)
        _, db_reachable = version_module._database_version()  # pylint: disable=protected-access
        db_dialect = version_module.engine.dialect.name
        cache_type = settings.cache_type
        uptime_seconds = int(time.time() - version_module.START_TIME)

        # Redis status (if applicable)
        redis_available = version_module.REDIS_AVAILABLE
        redis_reachable = False
        if redis_available and cache_type.lower() == "redis" and settings.redis_url:
            try:
                # First-Party
                from mcpgateway.utils.redis_client import is_redis_available  # pylint: disable=import-outside-toplevel

                redis_reachable = await is_redis_available()
            except Exception:
                redis_reachable = False

        # Aggregate metrics from services
        overview_tool_service = ToolService()
        overview_server_service = ServerService()
        overview_prompt_service = PromptService()
        overview_resource_service = ResourceService()

        tool_metrics = await overview_tool_service.aggregate_metrics(db)
        server_metrics = await overview_server_service.aggregate_metrics(db)
        prompt_metrics = await overview_prompt_service.aggregate_metrics(db)
        resource_metrics = await overview_resource_service.aggregate_metrics(db)

        # Calculate totals
        total_executions = (
            (tool_metrics.get("total_executions", 0) if isinstance(tool_metrics, dict) else getattr(tool_metrics, "total_executions", 0))
            + (server_metrics.total_executions if hasattr(server_metrics, "total_executions") else server_metrics.get("total_executions", 0))
            + (prompt_metrics.get("total_executions", 0) if isinstance(prompt_metrics, dict) else getattr(prompt_metrics, "total_executions", 0))
            + (resource_metrics.total_executions if hasattr(resource_metrics, "total_executions") else resource_metrics.get("total_executions", 0))
        )

        successful_executions = (
            (tool_metrics.get("successful_executions", 0) if isinstance(tool_metrics, dict) else getattr(tool_metrics, "successful_executions", 0))
            + (server_metrics.successful_executions if hasattr(server_metrics, "successful_executions") else server_metrics.get("successful_executions", 0))
            + (prompt_metrics.get("successful_executions", 0) if isinstance(prompt_metrics, dict) else getattr(prompt_metrics, "successful_executions", 0))
            + (resource_metrics.successful_executions if hasattr(resource_metrics, "successful_executions") else resource_metrics.get("successful_executions", 0))
        )

        success_rate = (successful_executions / total_executions * 100) if total_executions > 0 else 100.0

        # Calculate average latency across all services
        latencies = []
        for m in [tool_metrics, server_metrics, prompt_metrics, resource_metrics]:
            avg_time = m.get("avg_response_time") if isinstance(m, dict) else getattr(m, "avg_response_time", None)
            if avg_time is not None:
                latencies.append(avg_time)
        avg_latency = sum(latencies) / len(latencies) if latencies else 0.0

        # Prepare context
        context = {
            "request": request,
            "root_path": _resolve_root_path(request),
            # Inputs
            "servers_total": servers_total,
            "servers_active": servers_active,
            # Outputs
            "gateways_total": gateways_total,
            "gateways_active": gateways_active,
            "a2a_total": a2a_total,
            "a2a_active": a2a_active,
            "a2a_enabled": settings.mcpgateway_a2a_enabled,
            "tools_total": tools_total,
            "tools_active": tools_active,
            "prompts_total": prompts_total,
            "prompts_active": prompts_active,
            "resources_total": resources_total,
            "resources_active": resources_active,
            # Plugins (plugin_stats can be dict or PluginStatsResponse)
            "plugins_total": plugin_stats.get("total_plugins", 0) if isinstance(plugin_stats, dict) else getattr(plugin_stats, "total_plugins", 0),
            "plugins_enabled": plugin_stats.get("enabled_plugins", 0) if isinstance(plugin_stats, dict) else getattr(plugin_stats, "enabled_plugins", 0),
            "plugins_by_hook": plugin_stats.get("plugins_by_hook", {}) if isinstance(plugin_stats, dict) else getattr(plugin_stats, "plugins_by_hook", {}),
            # Metrics
            "total_executions": total_executions,
            "success_rate": success_rate,
            "avg_latency_ms": avg_latency * 1000 if avg_latency else 0.0,
            # Version
            "version": __version__,
            # Infrastructure
            "db_dialect": db_dialect,
            "db_reachable": db_reachable,
            "cache_type": cache_type,
            "redis_available": redis_available,
            "redis_reachable": redis_reachable,
            "uptime_seconds": uptime_seconds,
            "mcp_runtime": version_module.mcp_runtime_status_payload(),
        }

        return request.app.state.templates.TemplateResponse(request, "overview_partial.html", context)

    except Exception as e:
        LOGGER.error(f"Error rendering overview partial: {e}")
        error_html = f"""
        <div class="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-300 px-4 py-3 rounded">
            <strong class="font-bold">Error loading overview:</strong>
            <span class="block sm:inline">{html.escape(str(e))}</span>
        </div>
        """
        return HTMLResponse(content=error_html, status_code=500)


@admin_router.get("/config/passthrough-headers", response_model=GlobalConfigRead)
@require_permission("admin.system_config", allow_admin_bypass=False)
@rate_limit(requests_per_minute=30)  # Lower limit for config endpoints
async def get_global_passthrough_headers(
    db: Session = Depends(get_db),
    _user=Depends(get_current_user_with_permissions),
) -> GlobalConfigRead:
    """Get the global passthrough headers configuration.

    Args:
        db: Database session
        _user: Authenticated user

    Returns:
        GlobalConfigRead: The current global passthrough headers configuration

    Examples:
        >>> # Test function exists and has correct name
        >>> from mcpgateway.admin import get_global_passthrough_headers
        >>> get_global_passthrough_headers.__name__
        'get_global_passthrough_headers'
        >>> # Test it's a coroutine function
        >>> import inspect
        >>> inspect.iscoroutinefunction(get_global_passthrough_headers)
        True
    """
    # Use cache for reads (Issue #1715)
    # Pass env defaults so env/merge modes return correct headers
    passthrough_headers = global_config_cache.get_passthrough_headers(db, settings.default_passthrough_headers)
    return GlobalConfigRead(passthrough_headers=passthrough_headers)


@admin_router.put("/config/passthrough-headers", response_model=GlobalConfigRead)
@require_permission("admin.system_config", allow_admin_bypass=False)
@rate_limit(requests_per_minute=20)  # Stricter limit for config updates
async def update_global_passthrough_headers(
    request: Request,  # pylint: disable=unused-argument
    config_update: GlobalConfigUpdate,
    db: Session = Depends(get_db),
    _user=Depends(get_current_user_with_permissions),
) -> GlobalConfigRead:
    """Update the global passthrough headers configuration.

    Args:
        request: HTTP request object
        config_update: The new configuration
        db: Database session
        _user: Authenticated user

    Raises:
        HTTPException: If there is a conflict or validation error

    Returns:
        GlobalConfigRead: The updated configuration

    Examples:
        >>> # Test function exists and has correct name
        >>> from mcpgateway.admin import update_global_passthrough_headers
        >>> update_global_passthrough_headers.__name__
        'update_global_passthrough_headers'
        >>> # Test it's a coroutine function
        >>> import inspect
        >>> inspect.iscoroutinefunction(update_global_passthrough_headers)
        True
    """
    try:
        config = db.query(GlobalConfig).first()
        if not config:
            config = GlobalConfig(passthrough_headers=config_update.passthrough_headers)
            db.add(config)
        else:
            config.passthrough_headers = config_update.passthrough_headers
        db.commit()
        # Invalidate both global and loopback caches so changes propagate immediately (Issue #1715, #3640)
        # First-Party
        from mcpgateway.utils.passthrough_headers import invalidate_passthrough_header_caches  # pylint: disable=import-outside-toplevel

        invalidate_passthrough_header_caches()
        return GlobalConfigRead(passthrough_headers=config.passthrough_headers)
    except IntegrityError as e:
        db.rollback()
        raise HTTPException(status_code=409, detail="Passthrough headers conflict") from e
    except ValidationError as e:
        db.rollback()
        raise HTTPException(status_code=422, detail="Invalid passthrough headers format") from e
    except PassthroughHeadersError as e:
        db.rollback()
        LOGGER.error(f"Passthrough headers error: {e}")
        raise HTTPException(status_code=500, detail="Passthrough headers error") from e


@admin_router.post("/config/passthrough-headers/invalidate-cache")
@require_permission("admin.system_config", allow_admin_bypass=False)
@rate_limit(requests_per_minute=10)  # Strict limit for cache operations
async def invalidate_passthrough_headers_cache(
    _user=Depends(get_current_user_with_permissions),
    _db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Invalidate the GlobalConfig cache.

    Forces an immediate cache refresh on the next access. Use this after
    updating GlobalConfig outside the normal API flow, or when you need
    changes to propagate immediately across all workers.

    Args:
        _user: Authenticated user
        _db: Database session for permission checks.

    Returns:
        Dict with invalidation status and cache statistics

    Examples:
        >>> # Test function exists and has correct name
        >>> from mcpgateway.admin import invalidate_passthrough_headers_cache
        >>> invalidate_passthrough_headers_cache.__name__
        'invalidate_passthrough_headers_cache'
        >>> # Test it's a coroutine function
        >>> import inspect
        >>> inspect.iscoroutinefunction(invalidate_passthrough_headers_cache)
        True
    """
    # First-Party
    from mcpgateway.utils.passthrough_headers import invalidate_passthrough_header_caches  # pylint: disable=import-outside-toplevel

    invalidate_passthrough_header_caches()
    stats = global_config_cache.stats()
    return {
        "status": "invalidated",
        "message": "Passthrough header caches invalidated successfully",
        "cache_stats": stats,
    }


@admin_router.get("/config/passthrough-headers/cache-stats")
@require_permission("admin.system_config", allow_admin_bypass=False)
@rate_limit(requests_per_minute=30)
async def get_passthrough_headers_cache_stats(
    _user=Depends(get_current_user_with_permissions),
    _db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Get GlobalConfig cache statistics.

    Returns cache hit/miss counts, hit rate, TTL, and current cache status.
    Useful for monitoring cache effectiveness and debugging.

    Args:
        _user: Authenticated user
        _db: Database session for permission checks.

    Returns:
        Dict with cache statistics

    Examples:
        >>> # Test function exists and has correct name
        >>> from mcpgateway.admin import get_passthrough_headers_cache_stats
        >>> get_passthrough_headers_cache_stats.__name__
        'get_passthrough_headers_cache_stats'
        >>> # Test it's a coroutine function
        >>> import inspect
        >>> inspect.iscoroutinefunction(get_passthrough_headers_cache_stats)
        True
    """
    return global_config_cache.stats()


# ===================================
# A2A Stats Cache Endpoints
# ===================================


@admin_router.post("/cache/a2a-stats/invalidate")
@require_permission("admin.system_config", allow_admin_bypass=False)
@rate_limit(requests_per_minute=10)
async def invalidate_a2a_stats_cache(
    _user=Depends(get_current_user_with_permissions),
    _db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Invalidate the A2A stats cache.

    Forces an immediate cache refresh on the next access. Use this after
    modifying A2A agents outside the normal API flow, or when you need
    changes to propagate immediately.

    Args:
        _user: Authenticated user
        _db: Database session for permission checks.

    Returns:
        Dict with invalidation status and cache statistics

    Examples:
        >>> from mcpgateway.admin import invalidate_a2a_stats_cache
        >>> invalidate_a2a_stats_cache.__name__
        'invalidate_a2a_stats_cache'
        >>> import inspect
        >>> inspect.iscoroutinefunction(invalidate_a2a_stats_cache)
        True
    """
    a2a_stats_cache.invalidate()
    stats = a2a_stats_cache.stats()
    return {
        "status": "invalidated",
        "message": "A2A stats cache invalidated successfully",
        "cache_stats": stats,
    }


@admin_router.get("/cache/a2a-stats/stats")
@require_permission("admin.system_config", allow_admin_bypass=False)
@rate_limit(requests_per_minute=30)
async def get_a2a_stats_cache_stats(
    _user=Depends(get_current_user_with_permissions),
    _db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Get A2A stats cache statistics.

    Returns cache hit/miss counts, hit rate, TTL, and current cache status.
    Useful for monitoring cache effectiveness and debugging.

    Args:
        _user: Authenticated user
        _db: Database session for permission checks.

    Returns:
        Dict with cache statistics

    Examples:
        >>> from mcpgateway.admin import get_a2a_stats_cache_stats
        >>> get_a2a_stats_cache_stats.__name__
        'get_a2a_stats_cache_stats'
        >>> import inspect
        >>> inspect.iscoroutinefunction(get_a2a_stats_cache_stats)
        True
    """
    return a2a_stats_cache.stats()


@admin_router.get("/config/settings")
@require_permission("admin.system_config", allow_admin_bypass=False)
async def get_configuration_settings(
    _db: Session = Depends(get_db),
    _user=Depends(get_current_user_with_permissions),
) -> Dict[str, Any]:
    """Get application configuration settings grouped by category.

    Returns configuration settings with sensitive values masked.

    Args:
        _db: Database session
        _user: Authenticated user

    Returns:
        Dict with configuration groups and their settings
    """

    def mask_sensitive(value: Any, key: str) -> Any:
        """Mask sensitive configuration values.

        Args:
            value: Configuration value to potentially mask
            key: Configuration key name to check for sensitive patterns

        Returns:
            Masked value if sensitive, original value otherwise
        """
        sensitive_keys = {"password", "secret", "key", "token", "credentials", "client_secret", "private_key", "auth_encryption_secret"}
        if any(s in key.lower() for s in sensitive_keys):
            # Handle SecretStr objects
            if isinstance(value, SecretStr):
                return settings.masked_auth_value
            if value and str(value) not in ["", "None", "null"]:
                return settings.masked_auth_value
        return value

    # Group settings by category
    config_groups = {
        "Basic Settings": {
            "app_name": settings.app_name,
            "host": settings.host,
            "port": settings.port,
            "environment": settings.environment,
            "app_domain": str(settings.app_domain),
            "protocol_version": settings.protocol_version,
        },
        "Authentication & Security": {
            "auth_required": settings.auth_required,
            "basic_auth_user": settings.basic_auth_user,
            "basic_auth_password": mask_sensitive(settings.basic_auth_password, "password"),
            "jwt_algorithm": settings.jwt_algorithm,
            "jwt_secret_key": mask_sensitive(settings.jwt_secret_key, "secret_key"),
            "jwt_audience": settings.jwt_audience,
            "jwt_issuer": settings.jwt_issuer,
            "token_expiry": settings.token_expiry,
            "require_token_expiration": settings.require_token_expiration,
            "mcp_client_auth_enabled": settings.mcp_client_auth_enabled,
            "trust_proxy_auth": settings.trust_proxy_auth,
            "skip_ssl_verify": settings.skip_ssl_verify,
        },
        "SSO Configuration": {
            "sso_enabled": settings.sso_enabled,
            "sso_github_enabled": settings.sso_github_enabled,
            "sso_google_enabled": settings.sso_google_enabled,
            "sso_ibm_verify_enabled": settings.sso_ibm_verify_enabled,
            "sso_okta_enabled": settings.sso_okta_enabled,
            "sso_keycloak_enabled": settings.sso_keycloak_enabled,
            "sso_entra_enabled": settings.sso_entra_enabled,
            "sso_generic_enabled": settings.sso_generic_enabled,
            "sso_auto_create_users": settings.sso_auto_create_users,
            "sso_preserve_admin_auth": settings.sso_preserve_admin_auth,
            "sso_require_admin_approval": settings.sso_require_admin_approval,
        },
        "Email Authentication": {
            "email_auth_enabled": settings.email_auth_enabled,
            "platform_admin_email": settings.platform_admin_email,
            "platform_admin_password": mask_sensitive(settings.platform_admin_password, "password"),
        },
        "Database & Cache": {
            "database_url": settings.database_url.replace("://", "://***@") if "@" in settings.database_url else settings.database_url,
            "cache_type": settings.cache_type,
            "redis_url": settings.redis_url.replace("://", "://***@") if settings.redis_url and "@" in settings.redis_url else settings.redis_url,
            "db_pool_size": settings.db_pool_size,
            "db_max_overflow": settings.db_max_overflow,
        },
        "Feature Flags": {
            "mcpgateway_ui_enabled": settings.mcpgateway_ui_enabled,
            "mcpgateway_admin_api_enabled": settings.mcpgateway_admin_api_enabled,
            "mcpgateway_bulk_import_enabled": settings.mcpgateway_bulk_import_enabled,
            "mcpgateway_a2a_enabled": settings.mcpgateway_a2a_enabled,
            "mcpgateway_catalog_enabled": settings.mcpgateway_catalog_enabled,
            "plugins_enabled": settings.plugins.enabled,
            "well_known_enabled": settings.well_known_enabled,
            "mcpgateway_direct_proxy_enabled": settings.mcpgateway_direct_proxy_enabled,
        },
        "Connection Timeouts": {
            "federation_timeout": settings.federation_timeout,  # Gateway/server HTTP request timeout
            "mcpgateway_direct_proxy_timeout": settings.mcpgateway_direct_proxy_timeout,
        },
        "Transport": {
            "transport_type": settings.transport_type,
            "websocket_ping_interval": settings.websocket_ping_interval,
            "sse_retry_timeout": settings.sse_retry_timeout,
            "sse_keepalive_enabled": settings.sse_keepalive_enabled,
        },
        "Logging": {
            "log_level": settings.log_level,
            "log_format": settings.log_format,
            "log_to_file": settings.log_to_file,
            "log_file": settings.log_file,
            "log_rotation_enabled": settings.log_rotation_enabled,
        },
        "Resources & Tools": {
            "tool_timeout": settings.tool_timeout,
            "tool_rate_limit": settings.tool_rate_limit,
            "tool_concurrent_limit": settings.tool_concurrent_limit,
            "resource_cache_size": settings.resource_cache_size,
            "resource_cache_ttl": settings.resource_cache_ttl,
            "max_resource_size": settings.max_resource_size,
        },
        "CORS Settings": {
            "cors_enabled": settings.cors_enabled,
            "allowed_origins": list(settings.allowed_origins),
            "cors_allow_credentials": settings.cors_allow_credentials,
        },
        "Security Headers": {
            "security_headers_enabled": settings.security_headers_enabled,
            "x_frame_options": settings.x_frame_options,
            "hsts_enabled": settings.hsts_enabled,
            "hsts_max_age": settings.hsts_max_age,
            "remove_server_headers": settings.remove_server_headers,
        },
        "Observability": {
            "otel_enable_observability": settings.otel_enable_observability,
            "otel_traces_exporter": settings.otel_traces_exporter,
            "otel_service_name": settings.otel_service_name,
        },
        "Development": {
            "dev_mode": settings.dev_mode,
            "reload": settings.reload,
            "debug": settings.debug,
        },
    }

    return {
        "groups": config_groups,
        "security_status": settings.get_security_status(),
    }


@admin_router.get("/servers", response_model=PaginatedResponse)
@require_permission("servers.read", allow_admin_bypass=False)
async def admin_list_servers(
    request: Request,
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    per_page: int = Query(settings.pagination_default_page_size, ge=1, le=settings.pagination_max_page_size, description="Items per page"),
    include_inactive: bool = False,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> Dict[str, Any]:
    """
    List servers for the admin UI with pagination support.

    This endpoint retrieves a paginated list of servers from the database, optionally
    including those that are inactive. Uses offset-based (page/per_page) pagination.

    Args:
        request (Request): FastAPI request object (required for token team extraction via request.state.token_teams).
        page (int): Page number (1-indexed) for offset pagination.
        per_page (int): Number of items per page.
        include_inactive (bool): Whether to include inactive servers.
        db (Session): The database session dependency.
        user (str): The authenticated user dependency.

    Returns:
        Dict[str, Any]: A dictionary containing:
            - data: List of server records formatted with by_alias=True
            - pagination: Pagination metadata
            - links: Pagination links (optional)

    Examples:
        >>> callable(admin_list_servers)
        True
        >>> admin_list_servers.__name__
        'admin_list_servers'
    """
    LOGGER.debug(f"User {get_user_email(user)} requested server list (page={page}, per_page={per_page})")
    user_email = get_user_email(user)
    token_teams = get_token_teams_from_request(request)

    # Call server_service.list_servers with page-based pagination
    paginated_result = await server_service.list_servers(
        db=db,
        include_inactive=include_inactive,
        page=page,
        per_page=per_page,
        user_email=user_email,
        token_teams=token_teams,
    )

    # End the read-only transaction early to avoid idle-in-transaction under load.
    db.commit()

    # Return standardized paginated response
    return {
        "data": [server.model_dump(by_alias=True) for server in paginated_result["data"]],
        "pagination": paginated_result["pagination"].model_dump(),
        "links": paginated_result["links"].model_dump() if paginated_result["links"] else None,
    }


@admin_router.get("/servers/partial", response_class=HTMLResponse)
@require_permission("servers.read", allow_admin_bypass=False)
async def admin_servers_partial_html(
    request: Request,
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    per_page: int = Query(settings.pagination_default_page_size, ge=1, le=settings.pagination_max_page_size, description="Items per page"),
    q: str = Query("", max_length=500, description="Search query"),
    tags: QueryTagsFilter = None,
    include_inactive: bool = True,
    render: QueryRenderMode = None,
    team_id: Optional[str] = Depends(_validated_team_id_param),
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user_with_permissions),
) -> Response:
    """Return paginated servers HTML partials for the admin UI.

    This HTMX endpoint returns only the partial HTML used by the admin UI for
    servers. It supports three render modes:

    - default: full table partial (rows + controls)
    - ``render="controls"``: return only pagination controls
    - ``render="selector"``: return selector items for infinite scroll

    Args:
        request (Request): FastAPI request object used by the template engine.
        page (int): Page number (1-indexed).
        per_page (int): Number of items per page (bounded by settings).
        q (str): Free-text query string.
        tags (Optional[str]): Tag filter expression (comma=OR, plus=AND).
        include_inactive (bool): If True, include inactive servers in results.
        render (Optional[str]): Render mode; one of None, "controls", "selector".
        team_id (Optional[str]): Filter by team ID.
        db (Session): Database session (dependency-injected).
        user: Authenticated user object from dependency injection.

    Returns:
        Union[HTMLResponse, TemplateResponse]: A rendered template response
        containing either the table partial, pagination controls, or selector
        items depending on ``render``. The response contains JSON-serializable
        encoded server data when templates expect it.
    """
    LOGGER.debug(f"User {get_user_email(user)} requested servers HTML partial (page={page}, per_page={per_page}, include_inactive={include_inactive}, render={render}, team_id={team_id})")
    search_query = _normalize_search_query(q)
    normalized_tags = _normalize_tags_query(tags)
    tag_groups = _parse_tag_filter_groups(normalized_tags)

    # Normalize per_page within configured bounds
    per_page = max(settings.pagination_min_page_size, min(per_page, settings.pagination_max_page_size))

    user_email = get_user_email(user)

    # Team scoping
    team_ids = await _get_user_team_ids(user, db)

    # Build base query with eager loading to avoid N+1 queries
    # Filter out deactivated tools, resources, prompts, and agents at query level
    query = select(DbServer).options(
        selectinload(DbServer.tools),
        with_loader_criteria(DbTool, DbTool.enabled.is_(True)),
        selectinload(DbServer.resources),
        with_loader_criteria(DbResource, DbResource.enabled.is_(True)),
        selectinload(DbServer.prompts),
        with_loader_criteria(DbPrompt, DbPrompt.enabled.is_(True)),
        selectinload(DbServer.a2a_agents),
        with_loader_criteria(DbA2AAgent, DbA2AAgent.enabled.is_(True)),
        joinedload(DbServer.email_team),
    )

    if not include_inactive:
        query = query.where(DbServer.enabled.is_(True))

    # Build access conditions
    # When team_id is specified, show ONLY items from that team (team-scoped view)
    # Otherwise, show all accessible items (All Teams view)
    if team_id:
        # Team-specific view: only show servers from the specified team
        if team_id in team_ids:
            # Apply visibility check: team/public resources + user's own resources (including private)
            team_access = [
                and_(DbServer.team_id == team_id, DbServer.visibility.in_(["team", "public"])),
                and_(DbServer.team_id == team_id, DbServer.owner_email == user_email),
            ]
            query = query.where(or_(*team_access))
            LOGGER.debug(f"Filtering servers by team_id: {team_id}")
        else:
            # User is not a member of this team, return no results using SQLAlchemy's false()
            LOGGER.warning("User %s attempted to filter by team %s but is not a member", SecurityValidator.sanitize_log_message(user_email), SecurityValidator.sanitize_log_message(str(team_id)))
            query = query.where(false())
    else:
        # All Teams view: apply standard access conditions (owner, team, public)
        access_conditions = []
        access_conditions.append(_owner_access_condition(DbServer.owner_email, DbServer.team_id, user_email=user_email, team_ids=team_ids, user=user))
        if team_ids:
            access_conditions.append(and_(DbServer.team_id.in_(team_ids), DbServer.visibility.in_(["team", "public"])))
        access_conditions.append(DbServer.visibility == "public")
        query = query.where(or_(*access_conditions))

    if search_query:
        query = query.where(
            or_(
                _like_contains(func.lower(DbServer.id), search_query),
                _like_contains(func.lower(DbServer.name), search_query),
                _like_contains(func.lower(coalesce(DbServer.description, "")), search_query),
            )
        )

    query = _apply_tag_filter_groups(query, db, DbServer.tags, tag_groups)

    # Apply pagination ordering for cursor support
    query = query.order_by(desc(DbServer.created_at), desc(DbServer.id))

    # Build query params for pagination links
    query_params = {}
    if include_inactive:
        query_params["include_inactive"] = "true"
    if team_id:
        query_params["team_id"] = team_id
    if search_query:
        query_params["q"] = search_query
    if normalized_tags:
        query_params["tags"] = normalized_tags

    # Use unified pagination function
    root_path = _resolve_root_path(request)
    base_url = f"{root_path}/admin/servers/partial"
    paginated_result = await paginate_query(
        db=db,
        query=query,
        page=page,
        per_page=per_page,
        cursor=None,  # HTMX partials use page-based navigation
        base_url=base_url,
        query_params=query_params,
        use_cursor_threshold=False,  # Disable auto-cursor switching for UI
    )

    # Extract paginated servers (DbServer objects)
    servers_db = paginated_result["data"]
    pagination = paginated_result["pagination"]
    links = paginated_result["links"]

    # Team names are loaded via joinedload(DbServer.email_team) and accessed via server.team property

    # Batch convert to Pydantic models using server service
    # This eliminates the N+1 query problem from calling get_server_details() in a loop
    servers_pydantic = []
    failed_count = 0
    for s in servers_db:
        try:
            servers_pydantic.append(server_service.convert_server_to_read(s, include_metrics=False))
        except (ValidationError, ValueError, KeyError, TypeError, binascii.Error) as e:
            failed_count += 1
            LOGGER.exception(f"Failed to convert server {getattr(s, 'id', 'unknown')} ({getattr(s, 'name', 'unknown')}): {e}")
    _adjust_pagination_for_conversion_failures(pagination, failed_count, len(servers_pydantic))
    data = jsonable_encoder(servers_pydantic)

    # End the read-only transaction before template rendering to avoid idle-in-transaction timeouts.
    db.commit()

    if render == "controls":
        return request.app.state.templates.TemplateResponse(
            request,
            "pagination_controls.html",
            {
                "request": request,
                "pagination": pagination.model_dump(),
                "base_url": base_url,
                "hx_target": "#servers-table-body",
                "hx_indicator": "#servers-loading",
                "query_params": query_params,
                "root_path": _resolve_root_path(request),
            },
        )

    if render == "selector":
        return request.app.state.templates.TemplateResponse(
            request,
            "servers_selector_items.html",
            {
                "request": request,
                "data": data,
                "pagination": pagination.model_dump(),
                "root_path": _resolve_root_path(request),
            },
        )

    _is_admin = bool(user.get("is_admin", False) if isinstance(user, dict) else getattr(user, "is_admin", False))
    _team_roles = _get_user_team_roles(db, user_email) if not _is_admin else {}
    return request.app.state.templates.TemplateResponse(
        request,
        "servers_partial.html",
        {
            "request": request,
            "data": data,
            "pagination": pagination.model_dump(),
            "links": links.model_dump() if links else None,
            "root_path": _resolve_root_path(request),
            "include_inactive": include_inactive,
            "query_params": query_params,
            "current_user_email": user_email,
            "is_admin": _is_admin,
            "user_team_roles": _team_roles,
        },
    )


@admin_router.get("/servers/{server_id}", response_model=ServerRead)
@require_permission("servers.read", allow_admin_bypass=False)
async def admin_get_server(server_id: str, request: Request, db: Session = Depends(get_db), user=Depends(get_current_user_with_permissions)) -> Dict[str, Any]:
    """
    Retrieve server details for the admin UI.

    Args:
        server_id (str): The ID of the server to retrieve.
        request (Request): Incoming FastAPI request (for visibility scope resolution).
        db (Session): The database session dependency.
        user (str): The authenticated user dependency.

    Returns:
        Dict[str, Any]: The server details.

    Raises:
        HTTPException: If the server is not found.
        Exception: For any other unexpected errors.

    Examples:
        >>> callable(admin_get_server)
        True
        >>> admin_get_server.__name__
        'admin_get_server'
    """
    try:
        LOGGER.debug(f"User {get_user_email(user)} requested details for server ID {server_id}")
        auth_user_email, auth_token_teams = get_scoped_resource_access_context(request, user)
        server = await server_service.get_server(db, server_id, user_email=auth_user_email, token_teams=auth_token_teams)
        return server.masked().model_dump(by_alias=True)
    except ServerNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        LOGGER.error("Error getting server %s: %s", SecurityValidator.sanitize_log_message(str(server_id)), e)
        raise e


@admin_router.post("/servers", response_model=ServerRead)
@require_permission("servers.create", allow_admin_bypass=False)
async def admin_add_server(request: Request, db: Session = Depends(get_db), user=Depends(get_current_user_with_permissions)) -> JSONResponse:
    """
    Add a new server via the admin UI.

    This endpoint processes form data to create a new server entry in the database.
    It handles exceptions gracefully and logs any errors that occur during server
    registration.

    Expects form fields:
      - name (required): The name of the server
      - description (optional): A description of the server's purpose
      - icon (optional): URL or path to the server's icon
      - associatedTools (optional, multiple values): Tools associated with this server
      - associatedResources (optional, multiple values): Resources associated with this server
      - associatedPrompts (optional, multiple values): Prompts associated with this server

    Args:
        request (Request): FastAPI request containing form data.
        db (Session): Database session dependency
        user (str): Authenticated user dependency

    Returns:
        JSONResponse: A JSON response indicating success or failure of the server creation operation.

    Raises:
        HTTPException: 422 when public visibility is disabled and request is team-scoped.

    Examples:
        >>> # Test function exists and has correct name
        >>> from mcpgateway.admin import admin_add_server
        >>> admin_add_server.__name__
        'admin_add_server'
        >>> # Test it's a coroutine function
        >>> import inspect
        >>> inspect.iscoroutinefunction(admin_add_server)
        True
    """
    form = await request.form()
    # is_inactive_checked = form.get("is_inactive_checked", "false")
    team_id = _form_team_id(form)

    # Parse tags from comma-separated string
    tags_str = str(form.get("tags", ""))
    tags: list[str] = [tag.strip() for tag in tags_str.split(",") if tag.strip()] if tags_str else []

    visibility = str(form.get("visibility", "private"))
    _check_public_visibility_allowed(visibility, team_id=team_id)

    try:
        LOGGER.debug(f"User {get_user_email(user)} is adding a new server with name: {form['name']}")

        # Handle "Select All" for tools, resources, and prompts.
        # _merge_select_all_ids takes the union of the server-fetched paginated IDs
        # (allToolIds etc.) with the explicitly checked form values so that
        # platform-public items visible in the UI are never silently dropped.
        associated_tools_list = _merge_select_all_ids(form, "selectAllTools", "allToolIds", form.getlist("associatedTools"))
        associated_resources_list = _merge_select_all_ids(form, "selectAllResources", "allResourceIds", form.getlist("associatedResources"))
        associated_prompts_list = _merge_select_all_ids(form, "selectAllPrompts", "allPromptIds", form.getlist("associatedPrompts"))

        # Handle OAuth 2.0 configuration (RFC 9728)
        oauth_enabled = form.get("oauth_enabled") == "on"
        oauth_config = None
        if oauth_enabled:
            authorization_server = str(form.get("oauth_authorization_server", "")).strip()
            scopes_str = str(form.get("oauth_scopes", "")).strip()
            token_endpoint = str(form.get("oauth_token_endpoint", "")).strip()

            if authorization_server:
                oauth_config = {"authorization_servers": [authorization_server]}
                if scopes_str:
                    # Convert space-separated scopes to list
                    oauth_config["scopes_supported"] = scopes_str.split()
                if token_endpoint:
                    oauth_config["token_endpoint"] = token_endpoint

                # Add audience parameter (for Atlassian, Auth0, and other non-RFC-8707 providers)
                oauth_audience = str(form.get("oauth_audience", "")).strip()
                if oauth_audience:
                    oauth_config["audience"] = oauth_audience
            else:
                # Invalid or incomplete OAuth configuration; disable OAuth to avoid inconsistent state
                LOGGER.warning(
                    "OAuth was enabled for server '%s' but no authorization server was provided; disabling OAuth for this server.",
                    form.get("name"),
                )
                oauth_enabled = False
                oauth_config = None

        server = ServerCreate(
            id=form.get("id") or None,
            name=form.get("name"),
            description=form.get("description"),
            icon=form.get("icon"),
            associated_tools=",".join(str(x) for x in associated_tools_list),
            associated_resources=",".join(str(x) for x in associated_resources_list),
            associated_prompts=",".join(str(x) for x in associated_prompts_list),
            tags=tags,
            visibility=visibility,
            oauth_enabled=oauth_enabled,
            oauth_config=oauth_config,
        )
    except KeyError as e:
        # Convert KeyError to ValidationError-like response
        return ORJSONResponse(content={"message": f"Missing required field: {e}", "success": False}, status_code=422)
    try:
        user_email = get_user_email(user)
        team_service = TeamManagementService(db)
        team_id = await team_service.verify_team_for_user(user_email, team_id)

        # Extract metadata for server creation
        creation_metadata = MetadataCapture.extract_creation_metadata(request, user)

        # Ensure default visibility is private and assign to personal team when available
        team_id_cast = typing_cast(Optional[str], team_id)
        await server_service.register_server(
            db,
            server,
            created_by=user_email,  # Use the consistent user_email
            created_from_ip=creation_metadata["created_from_ip"],
            created_via=creation_metadata["created_via"],
            created_user_agent=creation_metadata["created_user_agent"],
            team_id=team_id_cast,
            visibility=visibility,
        )
        return ORJSONResponse(
            content={"message": "Server created successfully!", "success": True},
            status_code=200,
        )

    except CoreValidationError as ex:
        return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=422)
    except ServerNameConflictError as ex:
        return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=409)
    except ServerError as ex:
        return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=500)
    # NOTE: Pydantic validation errors subclass ValueError; CoreValidationError must be handled first.
    except ValueError as ex:
        return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=400)
    except IntegrityError as ex:
        return ORJSONResponse(content=ErrorFormatter.format_database_error(ex), status_code=409)
    except Exception as ex:
        LOGGER.exception(f"Unexpected error in admin_add_server: {ex}")
        return ORJSONResponse(content={"message": "An unexpected error occurred. Please try again or contact support.", "success": False}, status_code=500)


@admin_router.post("/servers/{server_id}/edit")
@require_permission("servers.update", allow_admin_bypass=False)
async def admin_edit_server(
    server_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> JSONResponse:
    """
    Edit an existing server via the admin UI.

    This endpoint processes form data to update an existing server's properties.
    It handles exceptions gracefully and logs any errors that occur during the
    update operation.

    Expects form fields:
      - id (optional): Updated UUID for the server
      - name (optional): The updated name of the server
      - description (optional): An updated description of the server's purpose
      - icon (optional): Updated URL or path to the server's icon
      - associatedTools (optional, multiple values): Updated list of tools associated with this server
      - associatedResources (optional, multiple values): Updated list of resources associated with this server
      - associatedPrompts (optional, multiple values): Updated list of prompts associated with this server

    Args:
        server_id (str): The ID of the server to edit
        request (Request): FastAPI request containing form data
        db (Session): Database session dependency
        user (str): Authenticated user dependency

    Returns:
        JSONResponse: A JSON response indicating success or failure of the server update operation.

    Raises:
        HTTPException: 422 when public visibility is disabled and request is team-scoped.

    Examples:
        >>> callable(admin_edit_server)
        True
        >>> admin_edit_server.__name__
        'admin_edit_server'
    """
    form = await request.form()
    team_id = _form_team_id(form)

    # Parse tags from comma-separated string
    tags_str = str(form.get("tags", ""))
    tags: list[str] = [tag.strip() for tag in tags_str.split(",") if tag.strip()] if tags_str else []
    try:
        LOGGER.debug(f"User {get_user_email(user)} is editing server ID {server_id} with name: {form.get('name')}")
        visibility = str(form.get("visibility", "private"))
        _check_public_visibility_allowed(visibility, team_id=team_id)
        user_email = get_user_email(user)

        # Preserve existing server's team_id when no explicit team_id is provided.
        # Without this guard, verify_team_for_user() falls back to the user's
        # personal team, silently reassigning the server on every edit.
        if not team_id:
            existing_server = db.get(DbServer, server_id)
            existing_team = getattr(existing_server, "team_id", None) if existing_server else None
            if isinstance(existing_team, str) and existing_team:
                team_id = existing_team

        team_service = TeamManagementService(db)
        team_id = await team_service.verify_team_for_user(user_email, team_id)

        mod_metadata = MetadataCapture.extract_modification_metadata(request, user, 0)

        # Handle "Select All" for tools, resources, and prompts.
        # _merge_select_all_ids takes the union of the server-fetched paginated IDs
        # (allToolIds etc.) with the explicitly checked form values so that
        # platform-public items visible in the UI are never silently dropped.
        associated_tools_list = _merge_select_all_ids(form, "selectAllTools", "allToolIds", form.getlist("associatedTools"))
        associated_resources_list = _merge_select_all_ids(form, "selectAllResources", "allResourceIds", form.getlist("associatedResources"))
        associated_prompts_list = _merge_select_all_ids(form, "selectAllPrompts", "allPromptIds", form.getlist("associatedPrompts"))

        # Handle OAuth 2.0 configuration (RFC 9728)
        oauth_enabled = form.get("oauth_enabled") == "on"
        oauth_config = None
        if oauth_enabled:
            authorization_server = str(form.get("oauth_authorization_server", "")).strip()
            scopes_str = str(form.get("oauth_scopes", "")).strip()
            token_endpoint = str(form.get("oauth_token_endpoint", "")).strip()

            if authorization_server:
                oauth_config = {"authorization_servers": [authorization_server]}
                if scopes_str:
                    # Convert space-separated scopes to list
                    oauth_config["scopes_supported"] = scopes_str.split()
                if token_endpoint:
                    oauth_config["token_endpoint"] = token_endpoint

                # Add audience parameter (for Atlassian, Auth0, and other non-RFC-8707 providers)
                oauth_audience = str(form.get("oauth_audience", "")).strip()
                if oauth_audience:
                    oauth_config["audience"] = oauth_audience
            else:
                # Invalid or incomplete OAuth configuration; disable OAuth to avoid inconsistent state
                LOGGER.warning(
                    "OAuth was enabled for server '%s' but no authorization server was provided; disabling OAuth for this server.",
                    form.get("name"),
                )
                oauth_enabled = False
                oauth_config = None

        server = ServerUpdate(
            id=form.get("id"),
            name=form.get("name"),
            description=form.get("description"),
            icon=form.get("icon"),
            associated_tools=",".join(str(x) for x in associated_tools_list),
            associated_resources=",".join(str(x) for x in associated_resources_list),
            associated_prompts=",".join(str(x) for x in associated_prompts_list),
            tags=tags,
            visibility=visibility,
            team_id=team_id,
            owner_email=user_email,
            oauth_enabled=oauth_enabled,
            oauth_config=oauth_config,
        )

        await server_service.update_server(
            db,
            server_id,
            server,
            user_email,
            modified_by=mod_metadata["modified_by"],
            modified_from_ip=mod_metadata["modified_from_ip"],
            modified_via=mod_metadata["modified_via"],
            modified_user_agent=mod_metadata["modified_user_agent"],
        )

        return ORJSONResponse(
            content={"message": "Server updated successfully!", "success": True},
            status_code=200,
        )
    except (ValidationError, CoreValidationError) as ex:
        # Catch both Pydantic and pydantic_core validation errors
        return ORJSONResponse(content=ErrorFormatter.format_validation_error(ex), status_code=422)
    except ServerNameConflictError as ex:
        return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=409)
    except ServerError as ex:
        return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=500)
    except ValueError as ex:
        return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=400)
    except RuntimeError as ex:
        return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=500)
    except IntegrityError as ex:
        return ORJSONResponse(content=ErrorFormatter.format_database_error(ex), status_code=409)
    except PermissionError as e:
        LOGGER.info("Permission denied for user %s: %s", SecurityValidator.sanitize_log_message(get_user_email(user)), e)
        return ORJSONResponse(content={"message": str(e), "success": False}, status_code=403)
    except HTTPException:
        raise
    except Exception as ex:
        LOGGER.exception(f"Unexpected error in admin_edit_server: {ex}")
        return ORJSONResponse(content={"message": "An unexpected error occurred. Please try again or contact support.", "success": False}, status_code=500)


@admin_router.post("/servers/{server_id}/state")
@require_permission("servers.update", allow_admin_bypass=False)
async def admin_set_server_state(
    server_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> Response:
    """
    Set a server's active status via the admin UI.

    This endpoint processes a form request to activate or deactivate a server.
    It expects a form field 'activate' with value "true" to activate the server
    or "false" to deactivate it. The endpoint handles exceptions gracefully and
    logs any errors that might occur during the status change operation.

    Args:
        server_id (str): The ID of the server whose status to set.
        request (Request): FastAPI request containing form data with the 'activate' field.
        db (Session): Database session dependency.
        user (str): Authenticated user dependency.

    Returns:
        Response: A redirect to the admin dashboard catalog section with a
        status code of 303 (See Other).

    Examples:
        >>> callable(admin_set_server_state)
        True
        >>> admin_set_server_state.__name__
        'admin_set_server_state'
    """
    form = await request.form()
    error_message = None
    user_email = get_user_email(user)
    LOGGER.debug(f"User {user_email} is setting server ID {server_id} state with activate: {form.get('activate')}")
    activate = str(form.get("activate", "true")).lower() == "true"
    is_inactive_checked = str(form.get("is_inactive_checked", "false"))
    try:
        await server_service.set_server_state(db, server_id, activate, user_email=user_email)
    except PermissionError as e:
        LOGGER.warning("Permission denied for user %s setting server %s state: %s", SecurityValidator.sanitize_log_message(user_email), SecurityValidator.sanitize_log_message(server_id), e)
        error_message = str(e)
    except ServerLockConflictError as e:
        LOGGER.warning("Lock conflict for user %s setting server %s state: %s", SecurityValidator.sanitize_log_message(user_email), SecurityValidator.sanitize_log_message(server_id), e)
        error_message = "Server is being modified by another request. Please try again."
    except Exception as e:
        LOGGER.error(f"Error setting server status: {e}")
        error_message = "Error setting server status. Please try again."

    root_path = _resolve_root_path(request)
    team_id = str(form.get("team_id", "") or "")
    redirect_url = _build_admin_redirect(root_path, "catalog", error=error_message, include_inactive=is_inactive_checked.lower() == "true", team_id=team_id)
    return RedirectResponse(redirect_url, status_code=303)


@admin_router.post("/servers/{server_id}/delete")
@require_permission("servers.delete", allow_admin_bypass=False)
async def admin_delete_server(server_id: str, request: Request, db: Session = Depends(get_db), user=Depends(get_current_user_with_permissions)) -> RedirectResponse:
    """
    Delete a server via the admin UI.

    This endpoint removes a server from the database by its ID. It handles exceptions
    gracefully and logs any errors that occur during the deletion process.

    Args:
        server_id (str): The ID of the server to delete
        request (Request): FastAPI request object (not used but required by route signature).
        db (Session): Database session dependency
        user (str): Authenticated user dependency

    Returns:
        RedirectResponse: A redirect to the admin dashboard catalog section with a
        status code of 303 (See Other)

    Examples:
        >>> callable(admin_delete_server)
        True
        >>> admin_delete_server.__name__
        'admin_delete_server'
    """
    form = await request.form()
    is_inactive_checked = str(form.get("is_inactive_checked", "false"))
    purge_metrics = str(form.get("purge_metrics", "false")).lower() == "true"
    error_message = None
    try:
        user_email = get_user_email(user)
        LOGGER.debug(f"User {user_email} is deleting server ID {server_id}")
        await server_service.delete_server(db, server_id, user_email=user_email, purge_metrics=purge_metrics)
    except PermissionError as e:
        LOGGER.warning("Permission denied for user %s deleting server %s: %s", SecurityValidator.sanitize_log_message(get_user_email(user)), SecurityValidator.sanitize_log_message(server_id), e)
        error_message = str(e)
    except Exception as e:
        LOGGER.error(f"Error deleting server: {e}")
        error_message = "Failed to delete server. Please try again."

    root_path = _resolve_root_path(request)
    team_id = str(form.get("team_id", "") or "")
    redirect_url = _build_admin_redirect(root_path, "catalog", error=error_message, include_inactive=is_inactive_checked.lower() == "true", team_id=team_id)
    return RedirectResponse(redirect_url, status_code=303)


@admin_router.get("/resources", response_model=PaginatedResponse)
@require_permission("resources.read", allow_admin_bypass=False)
async def admin_list_resources(
    request: Request,
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    per_page: int = Query(settings.pagination_default_page_size, ge=1, le=settings.pagination_max_page_size, description="Items per page"),
    include_inactive: bool = False,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> Dict[str, Any]:
    """
    List resources for the admin UI with pagination support.

    This endpoint retrieves a paginated list of resources from the database, optionally
    including those that are inactive. Uses offset-based (page/per_page) pagination.

    Args:
        request (Request): FastAPI request object (required for token team extraction via request.state.token_teams).
        page (int): Page number (1-indexed). Default: 1.
        per_page (int): Items per page. Default: 50.
        include_inactive (bool): Whether to include inactive resources in the results.
        db (Session): Database session dependency.
        user (str): Authenticated user dependency.

    Returns:
        Dict with 'data', 'pagination', and 'links' keys containing paginated resources.

    Examples:
        >>> callable(admin_list_resources)
        True
        >>> admin_list_resources.__name__
        'admin_list_resources'
    """
    user_email = get_user_email(user)
    token_teams = get_token_teams_from_request(request)
    LOGGER.debug(f"User {user_email} requested resource list (page={page}, per_page={per_page})")

    # Call resource_service.list_resources with page-based pagination
    paginated_result = await resource_service.list_resources(
        db=db,
        include_inactive=include_inactive,
        page=page,
        per_page=per_page,
        user_email=user_email,
        token_teams=token_teams,
    )

    # Return standardized paginated response
    return {
        "data": [resource.model_dump(by_alias=True) for resource in paginated_result["data"]],
        "pagination": paginated_result["pagination"].model_dump(),
        "links": paginated_result["links"].model_dump() if paginated_result["links"] else None,
    }


@admin_router.get("/prompts", response_model=PaginatedResponse)
@require_permission("prompts.read", allow_admin_bypass=False)
async def admin_list_prompts(
    request: Request,
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    per_page: int = Query(settings.pagination_default_page_size, ge=1, le=settings.pagination_max_page_size, description="Items per page"),
    include_inactive: bool = False,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> Dict[str, Any]:
    """
    List prompts for the admin UI with pagination support.

    This endpoint retrieves a paginated list of prompts from the database, optionally
    including those that are inactive. Uses offset-based (page/per_page) pagination.

    Args:
        request (Request): FastAPI request object (required for token team extraction via request.state.token_teams).
        page (int): Page number (1-indexed) for offset pagination.
        per_page (int): Number of items per page.
        include_inactive (bool): Whether to include inactive prompts in the results.
        db (Session): Database session dependency.
        user (str): Authenticated user dependency.

    Returns:
        Dict[str, Any]: A dictionary containing:
            - data: List of prompt records formatted with by_alias=True
            - pagination: Pagination metadata
            - links: Pagination links (optional)

    Examples:
        >>> callable(admin_list_prompts)
        True
        >>> admin_list_prompts.__name__
        'admin_list_prompts'
    """
    user_email = get_user_email(user)
    token_teams = get_token_teams_from_request(request)
    LOGGER.debug(f"User {user_email} requested prompt list (page={page}, per_page={per_page})")

    # Call prompt_service.list_prompts with page-based pagination
    paginated_result = await prompt_service.list_prompts(
        db=db,
        include_inactive=include_inactive,
        page=page,
        per_page=per_page,
        user_email=user_email,
        token_teams=token_teams,
    )

    # Return standardized paginated response
    return {
        "data": [prompt.model_dump(by_alias=True) for prompt in paginated_result["data"]],
        "pagination": paginated_result["pagination"].model_dump(),
        "links": paginated_result["links"].model_dump() if paginated_result["links"] else None,
    }


@admin_router.get("/gateways", response_model=PaginatedResponse)
@require_permission("gateways.read", allow_admin_bypass=False)
async def admin_list_gateways(
    request: Request,
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    per_page: int = Query(settings.pagination_default_page_size, ge=1, le=settings.pagination_max_page_size, description="Items per page"),
    include_inactive: bool = False,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> Dict[str, Any]:
    """
    List gateways for the admin UI with pagination support.

    This endpoint retrieves a paginated list of gateways from the database, optionally
    including those that are inactive. Uses offset-based (page/per_page) pagination.

    Args:
        request (Request): FastAPI request object (required for token team extraction via request.state.token_teams).
        page (int): Page number (1-indexed) for offset pagination.
        per_page (int): Number of items per page.
        include_inactive (bool): Whether to include inactive gateways in the results.
        db (Session): Database session dependency.
        user (str): Authenticated user dependency.

    Returns:
        Dict[str, Any]: A dictionary containing:
            - data: List of gateway records formatted with by_alias=True
            - pagination: Pagination metadata
            - links: Pagination links (optional)

    Examples:
        >>> callable(admin_list_gateways)
        True
        >>> admin_list_gateways.__name__
        'admin_list_gateways'
    """
    user_email = get_user_email(user)
    token_teams = get_token_teams_from_request(request)
    LOGGER.debug(f"User {user_email} requested gateway list (page={page}, per_page={per_page})")

    # Call gateway_service.list_gateways with page-based pagination
    paginated_result = await gateway_service.list_gateways(
        db=db,
        include_inactive=include_inactive,
        page=page,
        per_page=per_page,
        user_email=user_email,
        token_teams=token_teams,
    )

    # Return standardized paginated response
    return {
        "data": [gateway.model_dump(by_alias=True) for gateway in paginated_result["data"]],
        "pagination": paginated_result["pagination"].model_dump(),
        "links": paginated_result["links"].model_dump() if paginated_result["links"] else None,
    }


@admin_router.post("/gateways/{gateway_id}/state")
@require_permission("gateways.update", allow_admin_bypass=False)
async def admin_set_gateway_state(
    gateway_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> RedirectResponse:
    """
    Set the active status of a gateway via the admin UI.

    This endpoint allows an admin to set the active status of a gateway.
    It expects a form field 'activate' with a value of "true" or "false" to
    determine the new status of the gateway.

    Args:
        gateway_id (str): The ID of the gateway to set state for.
        request (Request): The FastAPI request object containing form data.
        db (Session): The database session dependency.
        user (str): The authenticated user dependency.

    Returns:
        RedirectResponse: A redirect response to the admin dashboard with a
        status code of 303 (See Other).

    Examples:
        >>> callable(admin_set_gateway_state)
        True
        >>> admin_set_gateway_state.__name__
        'admin_set_gateway_state'
    """
    error_message = None
    user_email = get_user_email(user)
    LOGGER.debug(f"User {user_email} is setting gateway state for ID {gateway_id}")
    form = await request.form()
    activate = str(form.get("activate", "true")).lower() == "true"
    is_inactive_checked = str(form.get("is_inactive_checked", "false"))

    try:
        await gateway_service.set_gateway_state(db, gateway_id, activate, user_email=user_email)
    except PermissionError as e:
        LOGGER.warning("Permission denied for user %s setting gateway state %s: %s", SecurityValidator.sanitize_log_message(user_email), SecurityValidator.sanitize_log_message(gateway_id), e)
        error_message = str(e)
    except GatewayToolNameConflictError as e:
        error_message = str(e)
    except Exception as e:
        LOGGER.error(f"Error setting gateway state: {e}")
        error_message = "Failed to set gateway state. Please try again."

    root_path = _resolve_root_path(request)
    team_id = str(form.get("team_id", "") or "")
    redirect_url = _build_admin_redirect(root_path, "gateways", error=error_message, include_inactive=is_inactive_checked.lower() == "true", team_id=team_id)
    return RedirectResponse(redirect_url, status_code=303)


@admin_router.get("/", name="admin_home", response_class=HTMLResponse)
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


@admin_router.get("/login")
async def admin_login_page(request: Request) -> Response:
    """
    Render the admin login page.

    This endpoint serves the login form for email-based authentication.
    If email auth is disabled, redirects to the main admin page.
    If user is already authenticated, redirects to the dashboard.

    Args:
        request (Request): FastAPI request object.

    Returns:
        Response: Rendered HTML or redirect response.

    Examples:
        >>> from fastapi import Request
        >>> from fastapi.responses import HTMLResponse
        >>> from unittest.mock import MagicMock
        >>>
        >>> # Mock request
        >>> mock_request = MagicMock(spec=Request)
        >>> mock_request.scope = {"root_path": "/test"}
        >>> mock_request.app.state.templates = MagicMock()
        >>> mock_response = HTMLResponse("<html>Login</html>")
        >>> mock_request.app.state.templates.TemplateResponse.return_value = mock_response
        >>>
        >>> import asyncio
        >>> async def test_login_page():
        ...     response = await admin_login_page(mock_request)
        ...     return isinstance(response, HTMLResponse)
        >>>
        >>> asyncio.run(test_login_page())
        True
    """
    # Check if email auth is enabled
    if not getattr(settings, "email_auth_enabled", False):
        root_path = _resolve_root_path(request)
        return RedirectResponse(url=f"{root_path}/admin", status_code=303)

    root_path = settings.app_root_path

    # Check if user is already authenticated via JWT cookie
    # Skip redirect when an error param is present — the user was sent here
    # intentionally (e.g. admin_required, account_disabled).
    clear_invalid_cookies = False
    if not request.query_params.get("error"):
        jwt_token = request.cookies.get("jwt_token") or request.cookies.get("access_token")
        if jwt_token:
            try:
                # First-Party
                from mcpgateway.auth import validate_token_user

                auth_user = await validate_token_user(request, jwt_token)
                token_teams = getattr(request.state, "token_teams", None)

                # Preserve public-only denial invariant — same as AdminAuthMiddleware
                if token_teams is not None and len(token_teams) == 0:
                    pass  # Render login page; do not redirect to /admin
                elif auth_user.is_admin:
                    return RedirectResponse(url=f"{root_path}/admin", status_code=303)
                else:
                    # Non-admin with valid token: check RBAC admin permission
                    with SessionLocal() as db:
                        permission_service = PermissionService(db)
                        has_admin_access = await permission_service.has_admin_permission(
                            auth_user.email,
                            team_id=None,
                            token_teams=token_teams,
                        )
                        if has_admin_access:
                            return RedirectResponse(url=f"{root_path}/admin", status_code=303)
                        # else: render login page; token is valid but lacks admin access
            except Exception:
                clear_invalid_cookies = True

    # Only show secure cookie warning if there's a login error AND problematic config
    secure_cookie_warning = None
    if settings.secure_cookies and settings.environment == "development":
        secure_cookie_warning = i18n_t("login.warning.secureCookies")

    # Preserve email from failed login attempt
    prefill_email = request.query_params.get("email", "")

    # Use external template file
    response = request.app.state.templates.TemplateResponse(
        request,
        "login.html",
        {
            "request": request,
            "root_path": root_path,
            "secure_cookie_warning": secure_cookie_warning,
            "ui_airgapped": settings.mcpgateway_ui_airgapped,
            "prefill_email": prefill_email,
            "password_reset_enabled": getattr(settings, "password_reset_enabled", True),
            "sri_hashes": load_sri_hashes(),
            "bundle_css": get_bundle_css_files(),
        },
    )

    # Set CSRF cookie first, then clear invalid JWT cookies
    # This ensures CSRF cookie appears in set-cookie header
    _set_admin_csrf_cookie(request, response)

    # Clear invalid JWT cookies to prevent redirect loop
    if clear_invalid_cookies:
        response.delete_cookie("jwt_token", path="/")
        response.delete_cookie("access_token", path="/")

    return response


@admin_router.post("/login")
async def admin_login_handler(request: Request, db: Session = Depends(get_db)) -> RedirectResponse:
    """
    Handle admin login form submission.

    This endpoint processes the email/password login form, authenticates the user,
    sets the JWT cookie, and redirects to the admin panel or back to login with error.

    Args:
        request (Request): FastAPI request object.
        db (Session): Database session dependency.

    Returns:
        RedirectResponse: Redirect to admin panel on success or login page on failure.

    Examples:
        >>> from fastapi import Request
        >>> from fastapi.responses import RedirectResponse
        >>> from unittest.mock import MagicMock, AsyncMock
        >>>
        >>> # Mock request with form data
        >>> mock_request = MagicMock(spec=Request)
        >>> mock_request.scope = {"root_path": "/test"}
        >>> mock_form = {"email": "admin@example.com", "password": "changeme"}  # pragma: allowlist secret
        >>> mock_request.form = AsyncMock(return_value=mock_form)
        >>>
        >>> mock_db = MagicMock()
        >>>
        >>> import asyncio
        >>> async def test_login_handler():
        ...     try:
        ...         response = await admin_login_handler(mock_request, mock_db)
        ...         return isinstance(response, RedirectResponse)
        ...     except Exception:
        ...         return True  # Expected due to mocked dependencies
        >>>
        >>> asyncio.run(test_login_handler())
        True
    """
    root_path = _resolve_root_path(request)

    if not getattr(settings, "email_auth_enabled", False):
        return RedirectResponse(url=f"{root_path}/admin", status_code=303)

    try:
        form = await request.form()
        email_val = form.get("email")
        password_val = form.get("password")
        email = email_val if isinstance(email_val, str) else None
        password = password_val if isinstance(password_val, str) else None

        if not email or not password:
            params = "error=missing_fields"
            if email:
                params += f"&email={urllib.parse.quote(email)}"
            return RedirectResponse(url=f"{root_path}/admin/login?{params}", status_code=303)

        # Authenticate using the email auth service
        auth_service = EmailAuthService(db)

        try:
            # Authenticate user
            LOGGER.debug(f"Attempting authentication for {email}")
            user = await auth_service.authenticate_user(email, password)
            LOGGER.debug(f"Authentication result: {user}")

            if not user:
                LOGGER.warning(f"Authentication failed for {email} - user is None")
                return RedirectResponse(url=f"{root_path}/admin/login?error=invalid_credentials&email={urllib.parse.quote(email)}", status_code=303)

            if settings.sso_enabled and settings.sso_preserve_admin_auth and not bool(getattr(user, "is_admin", False)):
                LOGGER.info("Blocking local password login for non-admin user %s because SSO_PRESERVE_ADMIN_AUTH is enabled", email)
                return RedirectResponse(url=f"{root_path}/admin/login?error=sso_required&email={urllib.parse.quote(email)}", status_code=303)

            # Password change enforcement respects master switch and toggles
            needs_password_change = False

            if settings.password_change_enforcement_enabled:
                # If flag is set on the user, always honor it (flag is cleared when password is changed)
                if getattr(user, "password_change_required", False):
                    needs_password_change = True
                    LOGGER.debug("User %s has password_change_required flag set", email)

                # Enforce expiry-based password change if configured and not already required
                if not needs_password_change:
                    try:
                        pwd_changed = getattr(user, "password_changed_at", None)
                        if pwd_changed:
                            age_days = (utc_now() - pwd_changed).days
                            max_age = getattr(settings, "password_max_age_days", 90)
                            if age_days >= max_age:
                                needs_password_change = True
                                LOGGER.debug("User %s password expired (%s days >= %s)", email, age_days, max_age)
                    except Exception as exc:
                        LOGGER.debug("Failed to evaluate password age for %s: %s", email, exc)

                # Detect default password on login if enabled
                if getattr(settings, "detect_default_password_on_login", True) and not is_passwordless_user(user):
                    current_password_hash = typing_cast(str, user.password_hash)
                    password_service = Argon2PasswordService()
                    is_using_default_password = await password_service.verify_password_async(settings.default_user_password.get_secret_value(), current_password_hash)  # nosec B105
                    if is_using_default_password:
                        if getattr(settings, "require_password_change_for_default_password", True):
                            user.password_change_required = True
                            needs_password_change = True
                            try:
                                db.commit()
                            except Exception as exc:  # log commit failures
                                LOGGER.warning("Failed to commit password_change_required flag for %s: %s", email, exc)
                        else:
                            LOGGER.info("User %s is using default password but enforcement is disabled", email)

            if needs_password_change:
                LOGGER.info(f"User {email} requires password change - redirecting to change password page")

                # Mint the session id up front so the CSRF cookie can be HMAC-bound to
                # the exact JWT we are about to set. Without it the cookie falls back to
                # an opaque value that passes enforce_admin_csrf but fails
                # CSRFMiddleware, so /admin/** and /v1/admin/** diverge until the
                # dashboard rotates the cookie.
                session_jti = str(uuid.uuid4())

                # Create temporary JWT token for password change process
                token, _ = await create_access_token(user, jti=session_jti)

                # Create redirect response to password change page
                response = RedirectResponse(url=f"{root_path}/admin/change-password-required", status_code=303)

                # Set JWT token as secure cookie for the password change process
                try:
                    set_auth_cookie(response, token, remember_me=False)
                except CookieTooLargeError:
                    return RedirectResponse(
                        url=f"{root_path}/admin/login?error=token_too_large&email={urllib.parse.quote(email)}",
                        status_code=303,
                    )

                _set_admin_csrf_cookie(request, response, user_id=user.email, session_id=session_jti)
                return response

            # Mint the session id up front so the CSRF cookie is HMAC-bound to this
            # exact JWT from the first request of the session, matching routers/auth.py
            # and routers/email_auth.py.
            session_jti = str(uuid.uuid4())

            # Create JWT token with proper audience and issuer claims
            token, _ = await create_access_token(user, jti=session_jti)  # expires_seconds not needed here

            # Create redirect response
            response = RedirectResponse(url=f"{root_path}/admin", status_code=303)

            # Set JWT token as secure cookie
            try:
                set_auth_cookie(response, token, remember_me=False)
            except CookieTooLargeError:
                return RedirectResponse(
                    url=f"{root_path}/admin/login?error=token_too_large&email={urllib.parse.quote(email)}",
                    status_code=303,
                )

            _set_admin_csrf_cookie(request, response, user_id=user.email, session_id=session_jti)
            LOGGER.info(f"Admin user {email} logged in successfully")
            return response

        except Exception as e:
            LOGGER.warning(f"Login failed for {email}: {e}")

            if settings.secure_cookies and settings.environment == "development":
                LOGGER.warning("Login failed - set SECURE_COOKIES to false in config for HTTP development")

            return RedirectResponse(url=f"{root_path}/admin/login?error=invalid_credentials&email={urllib.parse.quote(email)}", status_code=303)

    except Exception as e:
        LOGGER.error(f"Login handler error: {e}")
        return RedirectResponse(url=f"{root_path}/admin/login?error=server_error", status_code=303)


@admin_router.get("/forgot-password")
async def admin_forgot_password_page(request: Request) -> Response:
    """Render forgot-password page.

    Args:
        request: Incoming HTTP request.

    Returns:
        Response: Forgot-password page response.
    """
    root_path = settings.app_root_path
    if not getattr(settings, "email_auth_enabled", False):
        return RedirectResponse(url=f"{root_path}/admin/login", status_code=303)
    response = request.app.state.templates.TemplateResponse(
        request,
        "forgot-password.html",
        {
            "request": request,
            "root_path": root_path,
            "password_reset_enabled": getattr(settings, "password_reset_enabled", True),
            "ui_airgapped": settings.mcpgateway_ui_airgapped,
            "sri_hashes": load_sri_hashes(),
        },
    )
    _set_admin_csrf_cookie(request, response)
    return response


@admin_router.post("/forgot-password")
async def admin_forgot_password_handler(request: Request, db: Session = Depends(get_db)) -> RedirectResponse:
    """Handle forgot-password form submission.

    Args:
        request: Incoming HTTP request with form data.
        db: Database session dependency.

    Returns:
        RedirectResponse: Redirect to login or forgot-password page with status.
    """
    root_path = _resolve_root_path(request)
    if not getattr(settings, "email_auth_enabled", False):
        return RedirectResponse(url=f"{root_path}/admin/login", status_code=303)
    if not getattr(settings, "password_reset_enabled", True):
        return RedirectResponse(url=f"{root_path}/admin/forgot-password?error=password_reset_disabled", status_code=303)

    try:
        form = await request.form()
        email_val = form.get("email")
        email = str(email_val).strip() if email_val else ""
        if not email:
            return RedirectResponse(url=f"{root_path}/admin/forgot-password?error=missing_email", status_code=303)

        auth_service = EmailAuthService(db)
        result = await auth_service.request_password_reset(email=email, ip_address=get_client_ip(request), user_agent=get_user_agent(request))
        if result.rate_limited:
            return RedirectResponse(url=f"{root_path}/admin/forgot-password?error=rate_limited", status_code=303)
        return RedirectResponse(url=f"{root_path}/admin/login?notice=reset_email_sent", status_code=303)
    except Exception as exc:
        LOGGER.warning("Forgot-password request failed: %s", exc)
        return RedirectResponse(url=f"{root_path}/admin/forgot-password?error=server_error", status_code=303)


@admin_router.get("/reset-password/{token}")
async def admin_reset_password_page(token: str, request: Request, db: Session = Depends(get_db)) -> Response:
    """Render password reset form for a token.

    Args:
        token: One-time reset token.
        request: Incoming HTTP request.
        db: Database session dependency.

    Returns:
        Response: Reset-password page response.
    """
    root_path = settings.app_root_path
    if not getattr(settings, "email_auth_enabled", False):
        return RedirectResponse(url=f"{root_path}/admin/login", status_code=303)
    if not getattr(settings, "password_reset_enabled", True):
        return RedirectResponse(url=f"{root_path}/admin/forgot-password?error=password_reset_disabled", status_code=303)

    auth_service = EmailAuthService(db)
    token_valid = False
    token_error = None
    try:
        await auth_service.validate_password_reset_token(token=token, ip_address=get_client_ip(request), user_agent=get_user_agent(request))
        token_valid = True
    except AuthenticationError as exc:
        token_error = str(exc)

    response = request.app.state.templates.TemplateResponse(
        request,
        "reset-password.html",
        {
            "request": request,
            "root_path": root_path,
            "token": token,
            "token_valid": token_valid,
            "token_error": token_error,
            "password_min_length": settings.password_min_length,
            "ui_airgapped": settings.mcpgateway_ui_airgapped,
            "sri_hashes": load_sri_hashes(),
        },
    )
    _set_admin_csrf_cookie(request, response)
    return response


@admin_router.post("/reset-password/{token}")
async def admin_reset_password_handler(token: str, request: Request, db: Session = Depends(get_db)) -> RedirectResponse:
    """Handle password reset form submission.

    Args:
        token: One-time reset token.
        request: Incoming HTTP request with reset form data.
        db: Database session dependency.

    Returns:
        RedirectResponse: Redirect to login or reset page with status.
    """
    root_path = _resolve_root_path(request)
    if not getattr(settings, "email_auth_enabled", False):
        return RedirectResponse(url=f"{root_path}/admin/login", status_code=303)
    if not getattr(settings, "password_reset_enabled", True):
        return RedirectResponse(url=f"{root_path}/admin/forgot-password?error=password_reset_disabled", status_code=303)

    try:
        form = await request.form()
        password = str(form.get("password", ""))
        confirm_password = str(form.get("confirm_password", ""))
        if not password or not confirm_password:
            return RedirectResponse(url=f"{root_path}/admin/reset-password/{urllib.parse.quote(token)}?error=missing_fields", status_code=303)
        if password != confirm_password:
            return RedirectResponse(url=f"{root_path}/admin/reset-password/{urllib.parse.quote(token)}?error=password_mismatch", status_code=303)

        auth_service = EmailAuthService(db)
        await auth_service.reset_password_with_token(token=token, new_password=password, ip_address=get_client_ip(request), user_agent=get_user_agent(request))
        return RedirectResponse(url=f"{root_path}/admin/login?notice=password_reset_success", status_code=303)
    except PasswordValidationError as exc:
        return RedirectResponse(url=f"{root_path}/admin/reset-password/{urllib.parse.quote(token)}?error={urllib.parse.quote(str(exc))}", status_code=303)
    except AuthenticationError as exc:
        msg = str(exc).lower()
        if "expired" in msg:
            return RedirectResponse(url=f"{root_path}/admin/forgot-password?error=reset_link_expired", status_code=303)
        if "used" in msg:
            return RedirectResponse(url=f"{root_path}/admin/forgot-password?error=reset_link_used", status_code=303)
        return RedirectResponse(url=f"{root_path}/admin/forgot-password?error=reset_link_invalid", status_code=303)
    except Exception as exc:
        LOGGER.warning("Password reset failed: %s", exc)
        return RedirectResponse(url=f"{root_path}/admin/reset-password/{urllib.parse.quote(token)}?error=server_error", status_code=303)


async def _admin_logout(request: Request) -> Response:
    """
    Handle admin logout by clearing authentication cookies.

    Supports three logout scenarios:
    - POST: User-initiated logout from the UI (redirects to login page or Keycloak logout)
    - GET with browser headers: Browser navigation to /admin/logout (redirects to login page)
    - GET without browser headers: OIDC front-channel logout callback from IdP (returns 200 OK)

    For OIDC front-channel logout (per OpenID Connect Front-Channel Logout 1.0 spec),
    identity providers like Microsoft Entra ID send GET requests to notify the application
    that the user has logged out from the IdP. The application should clear the session
    and return HTTP 200.

    Args:
        request (Request): FastAPI request object.

    Returns:
        Response: RedirectResponse for POST, or Response with 200 for GET (front-channel logout).

    Examples:
        >>> from fastapi import Request
        >>> from fastapi.responses import RedirectResponse, Response
        >>> from unittest.mock import MagicMock
        >>>
        >>> # Mock POST request (user-initiated)
        >>> mock_request = MagicMock(spec=Request)
        >>> mock_request.scope = {"root_path": "/test"}
        >>> mock_request.method = "POST"
        >>>
        >>> import asyncio
        >>> async def test_logout_post():
        ...     response = await _admin_logout(mock_request)
        ...     return isinstance(response, RedirectResponse) and response.status_code == 303
        >>>
        >>> asyncio.run(test_logout_post())
        True

        >>> # Mock GET request (front-channel logout)
        >>> mock_request.method = "GET"
        >>> async def test_logout_get():
        ...     response = await _admin_logout(mock_request)
        ...     return response.status_code == 200
        >>>
        >>> asyncio.run(test_logout_get())
        True
    """

    async def _extract_auth_provider_from_jwt_cookie() -> Optional[str]:
        """Best-effort auth provider resolution from the current JWT cookie.

        Returns:
            Optional[str]: Auth provider from JWT payload, if available.
        """
        cookies = getattr(request, "cookies", None)
        if not cookies or not hasattr(cookies, "get"):
            return None
        token = cookies.get("jwt_token")
        if not isinstance(token, str) or not token:
            return None
        try:
            payload = await verify_jwt_token_cached(token, request)
        except Exception as exc:  # nosec B110 - best-effort provider detection during logout
            LOGGER.warning("Failed to verify JWT during logout - SSO session may not be cleared: %s", exc)
            if settings.sso_keycloak_enabled:
                return "keycloak"
            return None

        user_payload = payload.get("user")
        if isinstance(user_payload, dict):
            user_provider = user_payload.get("auth_provider")
            if isinstance(user_provider, str) and user_provider:
                return user_provider

        auth_provider = payload.get("auth_provider")
        if isinstance(auth_provider, str) and auth_provider:
            return auth_provider
        return None

    def _build_absolute_login_url(root_path: str) -> Optional[str]:
        """Build an absolute login URL using request URL, with app_domain fallback.

        Args:
            root_path (str): Application root path from request scope.

        Returns:
            Optional[str]: Absolute login URL when resolvable, otherwise ``None``.
        """
        login_path = f"{root_path}/admin/login"
        request_url = getattr(request, "url", None)
        scheme = getattr(request_url, "scheme", None) if request_url is not None else None
        netloc = getattr(request_url, "netloc", None) if request_url is not None else None
        if isinstance(scheme, str) and scheme and isinstance(netloc, str) and netloc:
            return f"{scheme}://{netloc}{login_path}"

        app_domain = str(getattr(settings, "app_domain", "") or "").rstrip("/")
        if app_domain:
            return f"{app_domain}{login_path}"
        return None

    def _build_keycloak_logout_url(root_path: str) -> Optional[str]:
        """Build Keycloak RP-initiated logout URL when all required config is available.

        Args:
            root_path (str): Application root path from request scope.

        Returns:
            Optional[str]: Keycloak logout URL when all inputs are valid, otherwise ``None``.
        """
        if not settings.sso_keycloak_enabled or not settings.sso_keycloak_base_url:
            return None

        login_url = _build_absolute_login_url(root_path)
        if not login_url:
            LOGGER.warning("Cannot build Keycloak logout URL: unable to resolve absolute login URL")
            return None

        keycloak_base = (settings.sso_keycloak_public_base_url or settings.sso_keycloak_base_url or "").rstrip("/")
        realm = str(settings.sso_keycloak_realm or "").strip()
        if not keycloak_base or not realm:
            LOGGER.warning("Cannot build Keycloak logout URL: missing keycloak_base or realm configuration")
            return None

        logout_endpoint = f"{keycloak_base}/realms/{urllib.parse.quote(realm, safe='')}/protocol/openid-connect/logout"
        query_params: Dict[str, str] = {
            "post_logout_redirect_uri": login_url,
            # Legacy Keycloak compatibility
            "redirect_uri": login_url,
        }
        if settings.sso_keycloak_client_id:
            query_params["client_id"] = settings.sso_keycloak_client_id

        cookies = getattr(request, "cookies", None)
        if cookies and hasattr(cookies, "get"):
            id_token_hint = cookies.get("sso_id_token_hint")
            if isinstance(id_token_hint, str) and id_token_hint:
                # Only include the hint if the id_token has not expired.
                # Keycloak rejects expired id_token_hint with an error page.
                try:
                    payload_b64 = id_token_hint.split(".")[1]
                    payload_b64 += "=" * (-len(payload_b64) % 4)  # pad base64
                    claims = orjson.loads(binascii.a2b_base64(payload_b64))
                    if claims.get("exp", 0) > time.time():
                        query_params["id_token_hint"] = id_token_hint
                    else:
                        LOGGER.info("Omitting expired id_token_hint from Keycloak logout URL")
                except Exception:
                    LOGGER.debug("Could not decode id_token_hint; omitting from logout URL")

        return f"{logout_endpoint}?{urllib.parse.urlencode(query_params)}"

    LOGGER.info(f"Admin user logging out (method: {request.method})")
    root_path = _resolve_root_path(request)

    # Revoke JWT token in blocklist for immediate invalidation
    cookies = getattr(request, "cookies", None)
    if cookies and hasattr(cookies, "get"):
        token = cookies.get("jwt_token")
        if isinstance(token, str) and token:
            try:
                # First-Party
                from mcpgateway.services.token_blocklist_service import get_token_blocklist_service  # pylint: disable=import-outside-toplevel

                payload = await verify_jwt_token_cached(token, request)
                jti = payload.get("jti")
                user_id = payload.get("sub") or payload.get("email", "admin")

                if jti:
                    blocklist_service = get_token_blocklist_service()

                    # Get token expiry from payload
                    exp_ts = payload.get("exp")
                    token_expiry = None
                    if exp_ts:
                        token_expiry = datetime.fromtimestamp(exp_ts, tz=timezone.utc)

                    # Get last activity if present
                    last_activity = None
                    last_activity_ts = payload.get("last_activity")
                    if last_activity_ts:
                        last_activity = datetime.fromtimestamp(last_activity_ts, tz=timezone.utc)

                    blocklist_service.revoke_token(jti=jti, revoked_by=user_id, reason="admin_logout", token_expiry=token_expiry, last_activity=last_activity)
                    LOGGER.info(f"Token revoked during admin logout: jti={jti}", extra={"security_event": "admin_logout_token_revoked", "security_severity": "low", "jti": jti, "user_id": user_id})
            except Exception as revoke_error:
                # Log but don't fail logout if token revocation fails
                LOGGER.warning(f"Failed to revoke token during admin logout: {revoke_error}")

    # For GET requests, distinguish between browser navigation and OIDC front-channel logout
    if request.method == "GET":
        # Check if request is from a browser (Accept: text/html, HX-Request header, or same-origin admin/oauth referer)
        # Detection must match auth_middleware.py and rbac.py patterns to ensure consistent behavior
        # Browser navigation should redirect to login, OIDC callbacks should return 200 OK
        accept_header = request.headers.get("accept", "")
        is_htmx = request.headers.get("hx-request") == "true"
        referer = request.headers.get("referer", "")

        # Check if referer is from same origin (for admin UI and OAuth callback pages)
        is_same_origin_referer = False
        if referer:
            try:
                # Standard
                from urllib.parse import urlparse

                referer_parsed = urlparse(referer)
                request_host = request.headers.get("host", "")
                # Match if referer host matches request host and path contains /admin or /oauth/callback
                if referer_parsed.netloc == request_host and ("/admin" in referer_parsed.path or "/oauth/callback" in referer_parsed.path):
                    is_same_origin_referer = True
            except Exception:  # nosec B110
                pass  # Invalid referer URL, treat as not same-origin

        is_browser_request = "text/html" in accept_header or is_htmx or is_same_origin_referer

        if is_browser_request:
            # Browser navigation - redirect to login (cookies cleared below)
            response = RedirectResponse(url=f"{root_path}/admin/login", status_code=303)
        else:
            # OIDC front-channel logout from IdP - return 200 OK per OIDC spec
            # Reference: OpenID Connect Front-Channel Logout 1.0
            # https://openid.net/specs/openid-connect-frontchannel-1_0.html
            # The RP must clear the session and return HTTP 200 to acknowledge logout
            response = Response(content="Logged out", status_code=200)
    else:
        # POST requests (user-initiated) - redirect to login (cookies cleared below)
        response = RedirectResponse(url=f"{root_path}/admin/login", status_code=303)

        auth_provider = await _extract_auth_provider_from_jwt_cookie()
        if auth_provider == "keycloak":
            keycloak_logout_url = _build_keycloak_logout_url(root_path)
            if keycloak_logout_url:
                LOGGER.info("Redirecting to Keycloak RP-initiated logout endpoint")
                response = RedirectResponse(url=keycloak_logout_url, status_code=303)

    # Always clear local JWT session cookie.
    clear_auth_cookie(response)

    # Clear CSRF token cookie
    # First-Party
    from mcpgateway.services.csrf_service import clear_csrf_cookie

    clear_csrf_cookie(response, settings)

    use_secure = (settings.environment == "production") or settings.secure_cookies
    response.delete_cookie(
        key="sso_id_token_hint",
        path=settings.app_root_path or "/",
        secure=use_secure,
        httponly=True,
        samesite=settings.cookie_samesite,
    )
    _clear_admin_csrf_cookie(request, response)
    return response


@admin_router.get("/logout", operation_id="admin_logout_get")
async def admin_logout_get(request: Request) -> Response:
    """GET logout endpoint for OIDC front-channel logout.

    Args:
        request (Request): FastAPI request object.

    Returns:
        Response: Logout response for front-channel requests.
    """
    return await _admin_logout(request)


@admin_router.post("/logout", operation_id="admin_logout_post")
async def admin_logout_post(request: Request) -> Response:
    """POST logout endpoint for user-initiated UI logout.

    Args:
        request (Request): FastAPI request object.

    Returns:
        Response: Logout response for UI-initiated requests.
    """
    return await _admin_logout(request)


@admin_router.get("/change-password-required", response_class=HTMLResponse)
async def change_password_required_page(request: Request) -> HTMLResponse:
    """
    Render the password change required page.

    This page is shown when a user's password has expired and must be changed
    to continue accessing the system.

    Args:
        request (Request): FastAPI request object.

    Returns:
        HTMLResponse: The password change required page.

    Examples:
        >>> from unittest.mock import MagicMock
        >>> from fastapi import Request
        >>> from fastapi.responses import HTMLResponse
        >>>
        >>> # Mock request
        >>> mock_request = MagicMock(spec=Request)
        >>> mock_request.scope = {"root_path": "/test"}
        >>> mock_request.app.state.templates = MagicMock()
        >>> mock_response = HTMLResponse("<html>Change Password</html>")
        >>> mock_request.app.state.templates.TemplateResponse.return_value = mock_response
        >>>
        >>> import asyncio
        >>> async def test_change_password_page():
        ...     # Note: This requires email_auth_enabled=True in settings
        ...     return True  # Simplified test due to settings dependency
        >>>
        >>> asyncio.run(test_change_password_page())
        True
    """
    if not getattr(settings, "email_auth_enabled", False):
        root_path = _resolve_root_path(request)
        return RedirectResponse(url=f"{root_path}/admin", status_code=303)

    # Get root path for template
    root_path = _resolve_root_path(request)

    # Determine if this is a privileged account for password requirements
    is_privileged = False
    try:
        jwt_token = request.cookies.get("jwt_token")
        if jwt_token:
            credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=jwt_token)
            current_user = await get_current_user(credentials, request=request)
            if current_user:
                is_privileged = getattr(current_user, "is_admin", False)
    except Exception as e:
        LOGGER.warning(f"Failed to determine user admin status for password requirements: {e}")

    # Get actual password requirements from PasswordPolicyService
    password_requirements = PasswordPolicyService.get_password_requirements(is_privileged=is_privileged)

    response = request.app.state.templates.TemplateResponse(
        request,
        "change-password-required.html",
        {
            "request": request,
            "root_path": root_path,
            "ui_airgapped": settings.mcpgateway_ui_airgapped,
            "password_policy_enabled": getattr(settings, "password_policy_enabled", True),
            "password_requirements": password_requirements,
            "sri_hashes": load_sri_hashes(),
            "bundle_css": get_bundle_css_files(),
        },
    )
    _set_admin_csrf_cookie(request, response)
    return response


@admin_router.post("/change-password-required")
async def change_password_required_handler(request: Request, db: Session = Depends(get_db)) -> RedirectResponse:
    """
    Handle password change requirement form submission.

    This endpoint processes the forced password change form, validates the credentials,
    changes the password, clears the password_change_required flag, and redirects to admin panel.

    Args:
        request (Request): FastAPI request object.
        db (Session): Database session dependency.

    Returns:
        RedirectResponse: Redirect to admin panel on success or back to form with error.

    Examples:
        >>> from unittest.mock import MagicMock, AsyncMock
        >>> from fastapi import Request
        >>> from fastapi.responses import RedirectResponse
        >>>
        >>> # Mock request with form data
        >>> mock_request = MagicMock(spec=Request)
        >>> mock_request.scope = {"root_path": "/test"}
        >>> mock_form = {
        ...     "current_password": "oldpass",  # pragma: allowlist secret
        ...     "new_password": "newpass123",  # pragma: allowlist secret
        ...     "confirm_password": "newpass123"  # pragma: allowlist secret
        ... }
        >>> mock_request.form = AsyncMock(return_value=mock_form)
        >>> mock_request.cookies = {"jwt_token": "test_token"}
        >>> mock_request.headers = {"User-Agent": "TestAgent"}
        >>>
        >>> mock_db = MagicMock()
        >>>
        >>> import asyncio
        >>> async def test_password_change_handler():
        ...     # Note: Full test requires email_auth_enabled and valid JWT
        ...     return True  # Simplified test due to settings/auth dependencies
        >>>
        >>> asyncio.run(test_password_change_handler())
        True
    """
    root_path = _resolve_root_path(request)

    if not getattr(settings, "email_auth_enabled", False):
        return RedirectResponse(url=f"{root_path}/admin", status_code=303)

    try:
        form = await request.form()
        current_password_val = form.get("current_password")
        new_password_val = form.get("new_password")
        confirm_password_val = form.get("confirm_password")

        current_password = current_password_val if isinstance(current_password_val, str) else None
        new_password = new_password_val if isinstance(new_password_val, str) else None
        confirm_password = confirm_password_val if isinstance(confirm_password_val, str) else None

        if not all([current_password, new_password, confirm_password]):
            return RedirectResponse(url=f"{root_path}/admin/change-password-required?error=missing_fields", status_code=303)

        if new_password != confirm_password:
            return RedirectResponse(url=f"{root_path}/admin/change-password-required?error=mismatch", status_code=303)

        # Get user from JWT token in cookie
        try:
            jwt_token = request.cookies.get("jwt_token")
            current_user = None
            if jwt_token:
                credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=jwt_token)
                current_user = await get_current_user(credentials, request=request)
        except Exception as e:
            LOGGER.error(f"Authentication error: {e}")
            current_user = None

        if not current_user:
            return RedirectResponse(url=f"{root_path}/admin/login?error=session_expired", status_code=303)

        # Authenticate using the email auth service
        auth_service = EmailAuthService(db)
        ip_address = get_client_ip(request)
        user_agent = get_user_agent(request)

        try:
            # Change password
            success = await auth_service.change_password(email=current_user.email, old_password=current_password, new_password=new_password, ip_address=ip_address, user_agent=user_agent)

            if success:
                # Re-attach current_user to session for downstream use (e.g., get_teams() in token creation)
                # Note: password_change_required is already cleared by auth_service.change_password()
                # We must re-attach to ensure team claims are populated in the new JWT token.
                user_email = current_user.email  # Save before potential re-query
                try:
                    # pylint: disable=import-outside-toplevel
                    # Third-Party
                    from sqlalchemy import inspect as sa_inspect

                    insp = sa_inspect(current_user)
                    if insp.transient or insp.detached:
                        current_user = db.query(EmailUser).filter(EmailUser.email == user_email).first()
                        if current_user is None:
                            LOGGER.error(f"User {user_email} not found after successful password change - possible race condition")
                            return RedirectResponse(url=f"{root_path}/admin/change-password-required?error=server_error", status_code=303)
                except Exception as e:
                    # Return early to avoid creating token with empty team claims
                    LOGGER.error(f"Failed to re-attach user {user_email} to session: {e} - password changed but token creation skipped")
                    return RedirectResponse(url=f"{root_path}/admin/login?message=password_changed", status_code=303)

                # Bind the CSRF cookie to the replacement session. The password change
                # mints a new jti, which invalidates the HMAC bound to the login-time
                # jti in admin_login_handler's password-change branch.
                session_jti = str(uuid.uuid4())

                # Create new JWT token
                token, _ = await create_access_token(current_user, jti=session_jti)

                # Create redirect response to admin panel
                response = RedirectResponse(url=f"{root_path}/admin", status_code=303)

                # Update JWT token cookie
                try:
                    set_auth_cookie(response, token, remember_me=False)
                except CookieTooLargeError:
                    return RedirectResponse(
                        url=f"{root_path}/admin/login?error=token_too_large",
                        status_code=303,
                    )

                _set_admin_csrf_cookie(request, response, user_id=current_user.email, session_id=session_jti)

                LOGGER.info(f"User {current_user.email} successfully changed their expired password")
                return response

            return RedirectResponse(url=f"{root_path}/admin/change-password-required?error=change_failed", status_code=303)

        except AuthenticationError:
            return RedirectResponse(url=f"{root_path}/admin/change-password-required?error=invalid_password", status_code=303)
        except PasswordValidationError as e:
            LOGGER.warning(f"Password validation failed for {current_user.email}: {e}", exc_info=True)
            # Encode error message in URL for display to user (truncate to prevent URL length issues)
            error_msg = str(e)
            max_length = settings.password_error_message_max_length
            if len(error_msg) > max_length:
                error_msg = error_msg[: max_length - 3] + "..."
            error_msg_encoded = urllib.parse.quote(error_msg)
            return RedirectResponse(url=f"{root_path}/admin/change-password-required?error=weak_password&details={error_msg_encoded}", status_code=303)
        except Exception as e:
            LOGGER.error(f"Password change failed for {current_user.email}: {e}", exc_info=True)
            return RedirectResponse(url=f"{root_path}/admin/change-password-required?error=server_error", status_code=303)

    except Exception as e:
        LOGGER.error(f"Password change handler error: {e}")
        return RedirectResponse(url=f"{root_path}/admin/change-password-required?error=server_error", status_code=303)


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


@admin_router.get("/teams/ids", response_class=JSONResponse)
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


@admin_router.get("/teams/search", response_class=JSONResponse)
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


@admin_router.get("/teams/partial")
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


@admin_router.get("/teams")
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


@admin_router.post("/teams")
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


@admin_router.get("/teams/{team_id}/members")
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


@admin_router.get("/teams/{team_id}/members/add")
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


@admin_router.get("/teams/{team_id}/edit")
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


@admin_router.post("/teams/{team_id}/update")
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


@admin_router.delete("/teams/{team_id}")
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


@admin_router.post("/teams/{team_id}/add-member")
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


@admin_router.post("/teams/{team_id}/update-member-role")
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


@admin_router.post("/teams/{team_id}/remove-member")
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


@admin_router.post("/teams/{team_id}/leave")
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


@admin_router.get("/users")
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


@admin_router.get("/users/partial", response_class=HTMLResponse)
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


@admin_router.get("/teams/{team_id}/members/partial", response_class=HTMLResponse)
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


@admin_router.get("/teams/{team_id}/non-members/partial", response_class=HTMLResponse)
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


@admin_router.get("/users/search", response_class=JSONResponse)
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


@admin_router.post("/users")
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


@admin_router.get("/users/{user_email}/edit")
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


@admin_router.post("/users/{user_email}/update")
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


@admin_router.post("/users/{user_email}/activate")
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


@admin_router.post("/users/{user_email}/deactivate")
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


@admin_router.delete("/users/{user_email}")
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


@admin_router.post("/users/{user_email}/unlock")
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


@admin_router.post("/users/{user_email}/force-password-change")
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


@admin_router.get("/tools", response_model=PaginatedResponse)
@require_permission("tools.read", allow_admin_bypass=False)
async def admin_list_tools(
    request: Request,
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    per_page: int = Query(settings.pagination_default_page_size, ge=1, le=settings.pagination_max_page_size, description="Items per page"),
    include_inactive: bool = False,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> Dict[str, Any]:
    """
    List tools for the admin UI with pagination support.

    This endpoint retrieves a paginated list of tools from the database, optionally
    including those that are inactive. Uses offset-based (page/per_page) pagination.

    Args:
        request (Request): FastAPI request object (required for token team extraction via request.state.token_teams).
        page (int): Page number (1-indexed). Default: 1.
        per_page (int): Items per page. Default: 50.
        include_inactive (bool): Whether to include inactive tools in the results.
        db (Session): Database session dependency.
        user (str): Authenticated user dependency.

    Returns:
        Dict with 'data', 'pagination', and 'links' keys containing paginated tools.

    """
    user_email = get_user_email(user)
    token_teams = get_token_teams_from_request(request)
    LOGGER.debug(f"User {user_email} requested tool list (page={page}, per_page={per_page})")
    _is_admin = bool(user.get("is_admin", False) if isinstance(user, dict) else getattr(user, "is_admin", False))
    _team_roles = _get_user_team_roles(db, user_email) if not _is_admin else {}

    # Call tool_service.list_tools with page-based pagination
    paginated_result = await tool_service.list_tools(
        db=db,
        include_inactive=include_inactive,
        page=page,
        per_page=per_page,
        user_email=user_email,
        token_teams=token_teams,
        requesting_user_email=user_email,
        requesting_user_is_admin=_is_admin,
        requesting_user_team_roles=_team_roles,
    )

    # End the read-only transaction early to avoid idle-in-transaction under load.
    db.commit()

    # Return standardized paginated response
    return {
        "data": [tool.model_dump(by_alias=True) for tool in paginated_result["data"]],
        "pagination": paginated_result["pagination"].model_dump(),
        "links": paginated_result["links"].model_dump() if paginated_result["links"] else None,
    }


@admin_router.get("/tools/partial", response_class=HTMLResponse)
@require_permission("tools.read", allow_admin_bypass=False)
async def admin_tools_partial_html(
    request: Request,
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    per_page: int = Query(settings.pagination_default_page_size, ge=1, le=settings.pagination_max_page_size, description="Items per page"),
    q: str = Query("", max_length=500, description="Search query"),
    tags: QueryTagsFilter = None,
    include_inactive: bool = False,
    render: QueryRenderModeControls = None,
    gateway_id: QueryGatewayIdList = None,
    team_id: Optional[str] = Depends(_validated_team_id_param),
    include_public: bool = False,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    """
    Return HTML partial for paginated tools list (HTMX endpoint).

    This endpoint returns only the table body rows and pagination controls
    for HTMX-based pagination in the admin UI.

    Args:
        request (Request): FastAPI request object.
        page (int): Page number (1-indexed). Default: 1.
        per_page (int): Items per page. Default: 50.
        q (str): Free-text query string.
        tags (Optional[str]): Tag filter expression (comma=OR, plus=AND).
        include_inactive (bool): Whether to include inactive tools in the results.
        gateway_id (Optional[str]): Filter by gateway ID(s), comma-separated.
        team_id (Optional[str]): Filter by team ID.
        include_public (bool): Whether to include all public tools in the results.
        render (str): Render mode - 'controls' returns only pagination controls.
        db (Session): Database session dependency.
        user (str): Authenticated user dependency.

    Returns:
        HTMLResponse with tools table rows and pagination controls.
    """
    user_email = get_user_email(user)
    search_query = _normalize_search_query(q)
    normalized_tags = _normalize_tags_query(tags)
    tag_groups = _parse_tag_filter_groups(normalized_tags)
    LOGGER.debug(f"🔧 TOOLS PARTIAL REQUEST - User: {user_email}, team_id: {team_id}, page: {page}, render: {render}, referer: {request.headers.get('referer', 'none')}")

    # Build base query using tool_service's team filtering logic
    team_ids = await _get_user_team_ids(user, db)

    # Build query with eager loading for email_team to avoid N+1 queries
    query = select(DbTool).options(joinedload(DbTool.email_team))

    # Apply gateway filter if provided. Support special sentinel 'null' to
    # request tools with NULL gateway_id (e.g., RestTool/no gateway).
    if gateway_id:
        gateway_ids = [gid.strip() for gid in gateway_id.split(",") if gid.strip()]
        if gateway_ids:
            # Treat literal 'null' (case-insensitive) as a request for NULL gateway_id
            null_requested = any(gid.lower() == "null" for gid in gateway_ids)
            non_null_ids = [gid for gid in gateway_ids if gid.lower() != "null"]
            if non_null_ids and null_requested:
                query = query.where(or_(DbTool.gateway_id.in_(non_null_ids), DbTool.gateway_id.is_(None)))
                LOGGER.debug(f"Filtering tools by gateway IDs (including NULL): {non_null_ids} + NULL")
            elif null_requested:
                query = query.where(DbTool.gateway_id.is_(None))
                LOGGER.debug("Filtering tools by NULL gateway_id (RestTool)")
            else:
                query = query.where(DbTool.gateway_id.in_(non_null_ids))
                LOGGER.debug(f"Filtering tools by gateway IDs: {non_null_ids}")

    # Apply active/inactive filter
    if not include_inactive:
        query = query.where(DbTool.enabled.is_(True))

    # Build access conditions
    # When team_id is specified, show ONLY items from that team (simpler, team-scoped view)
    # When team_id + include_public, show team items PLUS public items from all teams
    # When team_id is NOT specified, show all accessible items (owned + team + public)
    if team_id:
        # Team-specific view: only show tools from the specified team if user is a member
        if team_id in team_ids:
            # Apply visibility check: team/public resources + user's own resources (including private)
            team_access = [
                and_(DbTool.team_id == team_id, DbTool.visibility.in_(["team", "public"])),
                and_(DbTool.team_id == team_id, DbTool.owner_email == user_email),
            ]
            if include_public:
                # Include all globally public items from any team.
                # Items with visibility='team' or 'private' from other teams are
                # blocked by the other conditions (which require team_id == selected team).
                team_access.append(DbTool.visibility == "public")
            query = query.where(or_(*team_access))
            LOGGER.debug(f"Filtering tools by team_id: {team_id}{' (include_public)' if include_public else ''}")
        else:
            # User is not a member of this team, return no results
            LOGGER.warning(f"User {user_email} attempted to filter by team {team_id} but is not a member")
            query = query.where(false())
    else:
        # All Teams view: apply standard access conditions
        access_conditions = []

        # 1. User's personal tools (owner_email matches)
        access_conditions.append(_owner_access_condition(DbTool.owner_email, DbTool.team_id, user_email=user_email, team_ids=team_ids, user=user))

        # 2. Team tools where user is member
        if team_ids:
            access_conditions.append(and_(DbTool.team_id.in_(team_ids), DbTool.visibility.in_(["team", "public"])))

        # 3. Public tools
        access_conditions.append(DbTool.visibility == "public")

        query = query.where(or_(*access_conditions))

    if search_query:
        query = query.where(
            or_(
                _like_contains(func.lower(DbTool.id), search_query),
                _like_contains(func.lower(DbTool.original_name), search_query),
                _like_contains(func.lower(coalesce(DbTool.display_name, "")), search_query),
                _like_contains(func.lower(coalesce(DbTool.custom_name, "")), search_query),
                _like_contains(func.lower(coalesce(DbTool.description, "")), search_query),
                _like_contains(func.lower(coalesce(DbTool.url, "")), search_query),
            )
        )

    query = _apply_tag_filter_groups(query, db, DbTool.tags, tag_groups)

    # Apply sorting: alphabetical by URL, then name, then ID (for UI display)
    # Different from JSON endpoint which uses created_at DESC
    query = query.order_by(DbTool.url, DbTool.original_name, DbTool.id)

    # Use unified pagination function (offset-based for UI compatibility)
    root_path = _resolve_root_path(request)
    base_url = f"{root_path}/admin/tools/partial"
    query_params_dict = {}
    if include_inactive:
        query_params_dict["include_inactive"] = "true"
    if gateway_id:
        query_params_dict["gateway_id"] = gateway_id
    if team_id:
        query_params_dict["team_id"] = team_id
    if search_query:
        query_params_dict["q"] = search_query
    if normalized_tags:
        query_params_dict["tags"] = normalized_tags

    paginated_result = await paginate_query(
        db=db,
        query=query,
        page=page,
        per_page=per_page,
        cursor=None,  # UI uses offset pagination only
        base_url=base_url,
        query_params=query_params_dict,
        use_cursor_threshold=False,  # Disable auto-cursor switching for UI
    )

    # Extract paginated tools (DbTool objects)
    tools_db = paginated_result["data"]
    pagination = paginated_result["pagination"]
    links = paginated_result["links"]

    # Team names are loaded via joinedload(DbTool.email_team) in the query
    # Batch convert to Pydantic models using tool service
    # This eliminates the N+1 query problem from calling get_tool() in a loop
    _is_admin = bool(user.get("is_admin", False) if isinstance(user, dict) else getattr(user, "is_admin", False))
    _team_roles = _get_user_team_roles(db, user_email) if not _is_admin else {}
    tools_pydantic = []
    failed_count = 0
    for t in tools_db:
        try:
            tools_pydantic.append(
                tool_service.convert_tool_to_read(
                    t,
                    include_metrics=False,
                    include_auth=False,
                    requesting_user_email=user_email,
                    requesting_user_is_admin=_is_admin,
                    requesting_user_team_roles=_team_roles,
                )
            )
        except (ValidationError, ValueError, KeyError, TypeError, binascii.Error) as e:
            failed_count += 1
            LOGGER.exception(f"Failed to convert tool {getattr(t, 'id', 'unknown')} ({getattr(t, 'name', 'unknown')}): {e}")
    _adjust_pagination_for_conversion_failures(pagination, failed_count, len(tools_pydantic))

    # Serialize tools
    data = jsonable_encoder(tools_pydantic)

    # End the read-only transaction before template rendering to avoid idle-in-transaction timeouts.
    db.commit()

    # If render=controls, return only pagination controls
    if render == "controls":
        # NOTE: hx_target/hx_swap must match what tools_partial.html sets when
        # rendering the inline pagination_controls include — currently
        # `#tools-table` with swap=outerHTML. Diverging here would cause
        # subsequent pagination clicks (after a controls-only re-render) to
        # swap into a target that the success-path doesn't own and trigger
        # the same `o.querySelector` null-fragment crash that caused the
        # `_loading` deadlock the rest of this PR fixes.
        return request.app.state.templates.TemplateResponse(
            request,
            "pagination_controls.html",
            {
                "request": request,
                "pagination": pagination.model_dump(),
                "base_url": base_url,
                "hx_target": "#tools-table",
                "hx_swap": "outerHTML",
                "hx_indicator": "#tools-loading",
                "table_name": "tools",
                "query_params": query_params_dict,
                "root_path": _resolve_root_path(request),
            },
        )

    # If render=selector, return tool selector items for infinite scroll
    if render == "selector":
        return request.app.state.templates.TemplateResponse(
            request,
            "tools_selector_items.html",
            {
                "request": request,
                "data": data,
                "pagination": pagination.model_dump(),
                "root_path": _resolve_root_path(request),
                "gateway_id": gateway_id,
                "team_id": team_id,
                "include_public": include_public,
            },
        )

    # Render template with paginated data
    return request.app.state.templates.TemplateResponse(
        request,
        "tools_partial.html",
        {
            "request": request,
            "data": data,
            "pagination": pagination.model_dump(),
            "links": links.model_dump() if links else None,
            "root_path": _resolve_root_path(request),
            "include_inactive": include_inactive,
            "query_params": query_params_dict,
            "current_user_email": user_email,
            "is_admin": _is_admin,
            "user_team_roles": _team_roles,
        },
    )


@admin_router.get("/tool-ops/partial", response_class=HTMLResponse)
@require_permission("tools.read", allow_admin_bypass=False)
async def admin_tool_ops_partial(
    request: Request,
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(settings.pagination_default_page_size, ge=1, le=settings.pagination_max_page_size, description="Items per page"),
    include_inactive: bool = False,
    gateway_id: QueryGatewayIdList = None,
    team_id: Optional[str] = Depends(_validated_team_id_param),
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    """
    Return HTML partial for tool operations table.

    Args:
        request (Request): The request object.
        page (int): The page number. Defaults to 1.
        per_page (int): The number of items per page. Defaults to settings.pagination_default_page_size.
        include_inactive (bool): Whether to include inactive items. Defaults to False.
        gateway_id (Optional[str]): The gateway ID to filter by. Defaults to None.
        team_id (Optional[str]): The team ID to filter by. Defaults to None.
        db (Session): The database session. Defaults to Depends(get_db).
        user (Any): The current user. Defaults to Depends(get_current_user_with_permissions).

    Returns:
        HTMLResponse: The HTML partial for the tool operations table.
    """
    user_email = get_user_email(user)
    LOGGER.debug(f"Tool ops partial request - team_id: {team_id}, page: {page}")
    team_ids = await _get_user_team_ids(user, db)

    query = select(DbTool).options(joinedload(DbTool.email_team))

    if gateway_id:
        gateway_ids = [gid.strip() for gid in gateway_id.split(",") if gid.strip()]
        if gateway_ids:
            null_requested = any(gid.lower() == "null" for gid in gateway_ids)
            non_null_ids = [gid for gid in gateway_ids if gid.lower() != "null"]
            if non_null_ids and null_requested:
                query = query.where(or_(DbTool.gateway_id.in_(non_null_ids), DbTool.gateway_id.is_(None)))
                LOGGER.debug(f"Filtering tools by gateway IDs (including NULL): {non_null_ids} + NULL")
            elif null_requested:
                query = query.where(DbTool.gateway_id.is_(None))
                LOGGER.debug("Filtering tools by NULL gateway_id (RestTool)")
            else:
                query = query.where(DbTool.gateway_id.in_(non_null_ids))
                LOGGER.debug(f"Filtering tools by gateway IDs: {non_null_ids}")

    if not include_inactive:
        query = query.where(DbTool.enabled.is_(True))

    if team_id:
        if team_id in team_ids:
            team_access = [
                and_(DbTool.team_id == team_id, DbTool.visibility.in_(["team", "public"])),
                and_(DbTool.team_id == team_id, DbTool.owner_email == user_email),
            ]
            query = query.where(or_(*team_access))
            LOGGER.debug(f"Filtering tools by team_id: {team_id}")
        else:
            LOGGER.warning(f"User {user_email} attempted to filter by team {team_id} but is not a member")
            query = query.where(false())
    else:
        access_conditions = []
        access_conditions.append(_owner_access_condition(DbTool.owner_email, DbTool.team_id, user_email=user_email, team_ids=team_ids, user=user))
        if team_ids:
            access_conditions.append(and_(DbTool.team_id.in_(team_ids), DbTool.visibility.in_(["team", "public"])))
        access_conditions.append(DbTool.visibility == "public")
        query = query.where(or_(*access_conditions))

    query = query.order_by(DbTool.url, DbTool.original_name, DbTool.id)

    paginated_result = await paginate_query(
        db=db,
        query=query,
        page=page,
        per_page=per_page,
        cursor=None,
        base_url=f"{_resolve_root_path(request)}/admin/tool-ops/partial",
        query_params={
            "include_inactive": "true" if include_inactive else "false",
            "gateway_id": gateway_id or "",
            "team_id": team_id or "",
        },
        use_cursor_threshold=False,
    )

    tools_db = paginated_result["data"]
    _is_admin = bool(user.get("is_admin", False) if isinstance(user, dict) else getattr(user, "is_admin", False))
    _team_roles = _get_user_team_roles(db, user_email) if not _is_admin else {}
    tools_pydantic = [
        tool_service.convert_tool_to_read(
            t,
            include_metrics=False,
            include_auth=False,
            requesting_user_email=user_email,
            requesting_user_is_admin=_is_admin,
            requesting_user_team_roles=_team_roles,
        )
        for t in tools_db
    ]
    db.commit()

    return request.app.state.templates.TemplateResponse(
        request,
        "toolops_partial.html",
        {
            "request": request,
            "tools": tools_pydantic,
            "root_path": _resolve_root_path(request),
            "current_user_email": user_email,
            "is_admin": _is_admin,
            "user_team_roles": _team_roles,
        },
    )


@admin_router.get("/tools/ids", response_class=JSONResponse)
@require_permission("tools.read", allow_admin_bypass=False)
async def admin_get_all_tool_ids(
    q: str = Query("", max_length=500, description="Search query"),
    include_inactive: bool = False,
    gateway_id: QueryGatewayIdList = None,
    team_id: Optional[str] = Depends(_validated_team_id_param),
    include_public: bool = False,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    """
    Return all tool IDs accessible to the current user.

    This is used by "Select All" to get all tool IDs without loading full data.

    Args:
        q (str): Search query to filter tools by name, ID, or description
        include_inactive (bool): Whether to include inactive tools in the results
        gateway_id (Optional[str]): Filter by gateway ID(s), comma-separated. Accepts the literal value 'null' to indicate NULL gateway_id (local tools).
        team_id (Optional[str]): Filter by team ID.
        include_public (bool): Whether to include all platform-public tools when filtering by team.
        db (Session): Database session dependency
        user: Current user making the request

    Returns:
        JSONResponse: List of tool IDs accessible to the user
    """
    user_email = get_user_email(user)

    # Build base query
    team_ids = await _get_user_team_ids(user, db)

    query = select(DbTool.id)

    if not include_inactive:
        query = query.where(DbTool.enabled.is_(True))

    # Apply search filter if provided
    if q:
        search_query = _normalize_search_query(q)
        if search_query:
            search_conditions = [
                _like_contains(func.lower(DbTool.id), search_query),
                _like_contains(func.lower(DbTool.original_name), search_query),
                _like_contains(func.lower(coalesce(DbTool.display_name, "")), search_query),
                _like_contains(func.lower(coalesce(DbTool.custom_name, "")), search_query),
                _like_contains(func.lower(coalesce(DbTool.description, "")), search_query),
                _like_contains(func.lower(coalesce(DbTool.url, "")), search_query),
            ]
            query = query.where(or_(*search_conditions))
            LOGGER.debug(f"Filtering tool IDs by search query: {search_query}")

    # Apply optional gateway/server scoping (comma-separated ids). Accepts the
    # literal value 'null' to indicate NULL gateway_id (local tools).
    if gateway_id:
        gateway_ids = [gid.strip() for gid in gateway_id.split(",") if gid.strip()]
        if gateway_ids:
            null_requested = any(gid.lower() == "null" for gid in gateway_ids)
            non_null_ids = [gid for gid in gateway_ids if gid.lower() != "null"]
            if non_null_ids and null_requested:
                query = query.where(or_(DbTool.gateway_id.in_(non_null_ids), DbTool.gateway_id.is_(None)))
                LOGGER.debug(f"Filtering tools by gateway IDs (including NULL): {non_null_ids} + NULL")
            elif null_requested:
                query = query.where(DbTool.gateway_id.is_(None))
                LOGGER.debug("Filtering tools by NULL gateway_id (local tools)")
            else:
                query = query.where(DbTool.gateway_id.in_(non_null_ids))
                LOGGER.debug(f"Filtering tools by gateway IDs: {non_null_ids}")

    # Build access conditions
    # When team_id is specified, show items from that team; optionally include
    # platform-public items when include_public is set (mirrors the partial endpoint).
    # Otherwise, show all accessible items (All Teams view).
    if team_id:
        if team_id in team_ids:
            team_access = [
                and_(DbTool.team_id == team_id, DbTool.visibility.in_(["team", "public"])),
                and_(DbTool.team_id == team_id, DbTool.owner_email == user_email),
            ]
            if include_public:
                team_access.append(DbTool.visibility == "public")
            query = query.where(or_(*team_access))
            LOGGER.debug(f"Filtering tool IDs by team_id: {team_id}{' (include_public)' if include_public else ''}")
        else:
            LOGGER.warning(f"User {user_email} attempted to filter tool IDs by team {team_id} but is not a member")
            query = query.where(false())
    else:
        # All Teams view: apply standard access conditions (owner, team, public)
        access_conditions = []
        access_conditions.append(_owner_access_condition(DbTool.owner_email, DbTool.team_id, user_email=user_email, team_ids=team_ids, user=user))
        access_conditions.append(DbTool.visibility == "public")
        if team_ids:
            access_conditions.append(and_(DbTool.team_id.in_(team_ids), DbTool.visibility.in_(["team", "public"])))
        query = query.where(or_(*access_conditions))

    # Get all IDs
    tool_ids = [row[0] for row in db.execute(query).all()]

    return {"tool_ids": tool_ids, "count": len(tool_ids)}


@admin_router.get("/tools/search", response_class=JSONResponse)
@require_permission("tools.read", allow_admin_bypass=False)
async def admin_search_tools(
    q: str = Query("", max_length=500, description="Search query"),
    tags: QueryTagsFilter = None,
    include_inactive: bool = False,
    limit: int = Query(settings.pagination_default_page_size, ge=1, le=settings.pagination_max_page_size, description="Maximum number of results to return"),
    gateway_id: QueryGatewayIdList = None,
    team_id: Optional[str] = Depends(_validated_team_id_param),
    include_public: bool = False,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    """
    Search tools by name, ID, or description.

    This endpoint searches tools across all accessible tools for the current user,
    returning both IDs and names for use in search functionality like the Add Server page.

    Args:
        q (str): Search query string to match against tool names, IDs, or descriptions.
        tags (Optional[str]): Tag filter expression (comma=OR, plus=AND).
        include_inactive (bool): Whether to include inactive tools in the search results.
        limit (int): Maximum number of results to return.
        gateway_id (Optional[str]): Filter by gateway ID(s), comma-separated.
        team_id (Optional[str]): Filter by team ID.
        include_public (bool): Whether to include all public tools in the results.
        db (Session): Database session.
        user: Current user with permissions.

    Returns:
        JSONResponse: A JSON response containing a list of matching tools.
    """
    user_email = get_user_email(user)
    search_query = _normalize_search_query(q)
    normalized_tags = _normalize_tags_query(tags)
    tag_groups = _parse_tag_filter_groups(normalized_tags)

    if not search_query and not tag_groups:
        return _build_search_response(entity_key="tools", entity_type="tools", items=[], query=search_query, tags=normalized_tags, tag_groups=tag_groups)

    # Build base query
    team_ids = await _get_user_team_ids(user, db)

    query = select(DbTool.id, DbTool.original_name, DbTool.custom_name, DbTool.display_name, DbTool.description)

    # Apply gateway filter if provided. Support special sentinel 'null' to
    # request tools with NULL gateway_id (e.g., RestTool/no gateway).
    if gateway_id:
        gateway_ids = [gid.strip() for gid in gateway_id.split(",") if gid.strip()]
        if gateway_ids:
            # Treat literal 'null' (case-insensitive) as a request for NULL gateway_id
            null_requested = any(gid.lower() == "null" for gid in gateway_ids)
            non_null_ids = [gid for gid in gateway_ids if gid.lower() != "null"]
            if non_null_ids and null_requested:
                query = query.where(or_(DbTool.gateway_id.in_(non_null_ids), DbTool.gateway_id.is_(None)))
                LOGGER.debug(f"Filtering tool search by gateway IDs (including NULL): {non_null_ids} + NULL")
            elif null_requested:
                query = query.where(DbTool.gateway_id.is_(None))
                LOGGER.debug("Filtering tool search by NULL gateway_id (RestTool)")
            else:
                query = query.where(DbTool.gateway_id.in_(non_null_ids))
                LOGGER.debug(f"Filtering tool search by gateway IDs: {non_null_ids}")

    if not include_inactive:
        query = query.where(DbTool.enabled.is_(True))

    # Build access conditions
    # When team_id is specified, show ONLY items from that team (team-scoped view)
    # When team_id + include_public, show team items PLUS public items from all teams
    # Otherwise, show all accessible items (All Teams view)
    if team_id:
        if team_id in team_ids:
            # Apply visibility check: team/public resources + user's own resources (including private)
            team_access = [
                and_(DbTool.team_id == team_id, DbTool.visibility.in_(["team", "public"])),
                and_(DbTool.team_id == team_id, DbTool.owner_email == user_email),
            ]
            if include_public:
                team_access.append(DbTool.visibility == "public")
            query = query.where(or_(*team_access))
            LOGGER.debug(f"Filtering tool search by team_id: {team_id}{' (include_public)' if include_public else ''}")
        else:
            LOGGER.warning(f"User {user_email} attempted to filter tool search by team {team_id} but is not a member")
            query = query.where(false())
    else:
        # All Teams view: apply standard access conditions (owner, team, public)
        access_conditions = []
        access_conditions.append(_owner_access_condition(DbTool.owner_email, DbTool.team_id, user_email=user_email, team_ids=team_ids, user=user))
        access_conditions.append(DbTool.visibility == "public")
        if team_ids:
            access_conditions.append(and_(DbTool.team_id.in_(team_ids), DbTool.visibility.in_(["team", "public"])))
        query = query.where(or_(*access_conditions))

    # Add search conditions - search in display fields and description
    # Using the same priority as display: displayName -> customName -> original_name
    if search_query:
        search_conditions = [
            _like_contains(func.lower(DbTool.id), search_query),
            _like_contains(func.lower(DbTool.original_name), search_query),
            _like_contains(func.lower(coalesce(DbTool.display_name, "")), search_query),
            _like_contains(func.lower(coalesce(DbTool.custom_name, "")), search_query),
            _like_contains(func.lower(coalesce(DbTool.description, "")), search_query),
            _like_contains(func.lower(coalesce(DbTool.url, "")), search_query),
        ]
        query = query.where(or_(*search_conditions))

    query = _apply_tag_filter_groups(query, db, DbTool.tags, tag_groups)

    # Order by relevance - prioritize matches at start of names
    if search_query:
        query = query.order_by(
            case(
                (func.lower(DbTool.original_name).startswith(search_query), 1),
                (func.lower(coalesce(DbTool.custom_name, "")).startswith(search_query), 1),
                (func.lower(coalesce(DbTool.display_name, "")).startswith(search_query), 1),
                else_=2,
            ),
            func.lower(DbTool.original_name),
        )
    else:
        query = query.order_by(func.lower(DbTool.original_name))
    query = query.limit(limit)

    # Execute query
    results = db.execute(query).all()

    # Format results
    tools = []
    for row in results:
        tools.append({"id": row.id, "name": row.original_name, "display_name": row.display_name, "custom_name": row.custom_name})  # original_name for search matching

    return _build_search_response(entity_key="tools", entity_type="tools", items=tools, query=search_query, tags=normalized_tags, tag_groups=tag_groups)


@admin_router.get("/prompts/partial", response_class=HTMLResponse)
@require_permission("prompts.read", allow_admin_bypass=False)
async def admin_prompts_partial_html(
    request: Request,
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    per_page: int = Query(settings.pagination_default_page_size, ge=1, le=settings.pagination_max_page_size, description="Items per page"),
    q: str = Query("", max_length=500, description="Search query"),
    tags: QueryTagsFilter = None,
    include_inactive: bool = False,
    render: QueryRenderMode = None,
    gateway_id: QueryGatewayIdList = None,
    team_id: Optional[str] = Depends(_validated_team_id_param),
    include_public: bool = False,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    """Return paginated prompts HTML partials for the admin UI.

    This HTMX endpoint returns only the partial HTML used by the admin UI for
    prompts. It supports three render modes:

    - default: full table partial (rows + controls)
    - ``render="controls"``: return only pagination controls
    - ``render="selector"``: return selector items for infinite scroll

    Args:
        request (Request): FastAPI request object used by the template engine.
        page (int): Page number (1-indexed).
        per_page (int): Number of items per page (bounded by settings).
        q (str): Free-text query string.
        tags (Optional[str]): Tag filter expression (comma=OR, plus=AND).
        include_inactive (bool): If True, include inactive prompts in results.
        render (Optional[str]): Render mode; one of None, "controls", "selector".
        gateway_id (Optional[str]): Filter by gateway ID(s), comma-separated.
        team_id (Optional[str]): Filter by team ID.
        include_public (bool): Whether to include all public prompts in the results.
        db (Session): Database session (dependency-injected).
        user: Authenticated user object from dependency injection.

    Returns:
        Union[HTMLResponse, TemplateResponse]: A rendered template response
        containing either the table partial, pagination controls, or selector
        items depending on ``render``. The response contains JSON-serializable
        encoded prompt data when templates expect it.
    """
    LOGGER.debug(
        f"User {get_user_email(user)} requested prompts HTML partial (page={page}, per_page={per_page}, include_inactive={include_inactive}, render={render}, gateway_id={gateway_id}, team_id={team_id})"
    )
    search_query = _normalize_search_query(q)
    normalized_tags = _normalize_tags_query(tags)
    tag_groups = _parse_tag_filter_groups(normalized_tags)
    # Normalize per_page within configured bounds
    per_page = max(settings.pagination_min_page_size, min(per_page, settings.pagination_max_page_size))

    user_email = get_user_email(user)

    # Team scoping
    team_ids = await _get_user_team_ids(user, db)

    # Build base query
    query = select(DbPrompt)

    # Apply gateway filter if provided
    if gateway_id:
        gateway_ids = [gid.strip() for gid in gateway_id.split(",") if gid.strip()]
        if gateway_ids:
            null_requested = any(gid.lower() == "null" for gid in gateway_ids)
            non_null_ids = [gid for gid in gateway_ids if gid.lower() != "null"]
            if non_null_ids and null_requested:
                query = query.where(or_(DbPrompt.gateway_id.in_(non_null_ids), DbPrompt.gateway_id.is_(None)))
                LOGGER.debug(f"Filtering prompts by gateway IDs (including NULL): {non_null_ids} + NULL")
            elif null_requested:
                query = query.where(DbPrompt.gateway_id.is_(None))
                LOGGER.debug("Filtering prompts by NULL gateway_id (RestTool)")
            else:
                query = query.where(DbPrompt.gateway_id.in_(non_null_ids))
                LOGGER.debug(f"Filtering prompts by gateway IDs: {non_null_ids}")

    if not include_inactive:
        query = query.where(DbPrompt.enabled.is_(True))

    # Build access conditions
    # When team_id is specified, show ONLY items from that team (team-scoped view)
    # When team_id + include_public, show team items PLUS public items from all teams
    # Otherwise, show all accessible items (All Teams view)
    if team_id:
        # Team-specific view: only show prompts from the specified team
        if team_id in team_ids:
            # Apply visibility check: team/public resources + user's own resources (including private)
            team_access = [
                and_(DbPrompt.team_id == team_id, DbPrompt.visibility.in_(["team", "public"])),
                and_(DbPrompt.team_id == team_id, DbPrompt.owner_email == user_email),
            ]
            if include_public:
                # Include all globally public items from any team.
                # Items with visibility='team' or 'private' from other teams are
                # blocked by the other conditions (which require team_id == selected team).
                team_access.append(DbPrompt.visibility == "public")
            query = query.where(or_(*team_access))
            LOGGER.debug(f"Filtering prompts by team_id: {team_id}{' (include_public)' if include_public else ''}")
        else:
            # User is not a member of this team, return no results using SQLAlchemy's false()
            LOGGER.warning(f"User {user_email} attempted to filter by team {team_id} but is not a member")
            query = query.where(false())
    else:
        # All Teams view: apply standard access conditions (owner, team, public)
        access_conditions = []
        access_conditions.append(_owner_access_condition(DbPrompt.owner_email, DbPrompt.team_id, user_email=user_email, team_ids=team_ids, user=user))
        if team_ids:
            access_conditions.append(and_(DbPrompt.team_id.in_(team_ids), DbPrompt.visibility.in_(["team", "public"])))
        access_conditions.append(DbPrompt.visibility == "public")
        query = query.where(or_(*access_conditions))

    if search_query:
        query = query.where(
            or_(
                _like_contains(func.lower(DbPrompt.id), search_query),
                _like_contains(func.lower(DbPrompt.original_name), search_query),
                _like_contains(func.lower(coalesce(DbPrompt.display_name, "")), search_query),
                _like_contains(func.lower(coalesce(DbPrompt.description, "")), search_query),
            )
        )

    query = _apply_tag_filter_groups(query, db, DbPrompt.tags, tag_groups)

    # Apply pagination ordering for cursor support
    query = query.order_by(desc(DbPrompt.created_at), desc(DbPrompt.id))

    # Build query params for pagination links
    query_params = {}
    if include_inactive:
        query_params["include_inactive"] = "true"
    if gateway_id:
        query_params["gateway_id"] = gateway_id
    if team_id:
        query_params["team_id"] = team_id
    if search_query:
        query_params["q"] = search_query
    if normalized_tags:
        query_params["tags"] = normalized_tags

    # Use unified pagination function
    root_path = _resolve_root_path(request)
    base_url = f"{root_path}/admin/prompts/partial"
    paginated_result = await paginate_query(
        db=db,
        query=query,
        page=page,
        per_page=per_page,
        cursor=None,  # HTMX partials use page-based navigation
        base_url=base_url,
        query_params=query_params,
        use_cursor_threshold=False,  # Disable auto-cursor switching for UI
    )

    # Extract paginated prompts (DbPrompt objects)
    prompts_db = paginated_result["data"]
    pagination = paginated_result["pagination"]
    links = paginated_result["links"]

    # Batch fetch team names for the prompts to avoid N+1 queries
    team_ids_set = {p.team_id for p in prompts_db if p.team_id}
    team_map = {}
    if team_ids_set:
        teams = db.execute(select(EmailTeam.id, EmailTeam.name).where(EmailTeam.id.in_(team_ids_set), EmailTeam.is_active.is_(True))).all()
        team_map = {team.id: team.name for team in teams}

    # Apply team names to DB objects before conversion
    for p in prompts_db:
        p.team = team_map.get(p.team_id) if p.team_id else None

    # Batch convert to Pydantic models using prompt service
    # This eliminates the N+1 query problem from calling get_prompt_details() in a loop
    prompts_pydantic = []
    failed_count = 0
    for p in prompts_db:
        try:
            prompts_pydantic.append(prompt_service.convert_prompt_to_read(p, include_metrics=False))
        except (ValidationError, ValueError, KeyError, TypeError, binascii.Error) as e:
            failed_count += 1
            LOGGER.exception(f"Failed to convert prompt {getattr(p, 'id', 'unknown')} ({getattr(p, 'name', 'unknown')}): {e}")
    _adjust_pagination_for_conversion_failures(pagination, failed_count, len(prompts_pydantic))

    data = jsonable_encoder(prompts_pydantic)

    # End the read-only transaction before template rendering to avoid idle-in-transaction timeouts.
    db.commit()

    if render == "controls":
        return request.app.state.templates.TemplateResponse(
            request,
            "pagination_controls.html",
            {
                "request": request,
                "pagination": pagination.model_dump(),
                "base_url": base_url,
                "hx_target": "#prompts-table-body",
                "hx_indicator": "#prompts-loading",
                "query_params": query_params,
                "root_path": _resolve_root_path(request),
            },
        )

    if render == "selector":
        return request.app.state.templates.TemplateResponse(
            request,
            "prompts_selector_items.html",
            {
                "request": request,
                "data": data,
                "pagination": pagination.model_dump(),
                "root_path": _resolve_root_path(request),
                "gateway_id": gateway_id,
                "team_id": team_id,
                "include_public": include_public,
            },
        )

    _is_admin = bool(user.get("is_admin", False) if isinstance(user, dict) else getattr(user, "is_admin", False))
    _team_roles = _get_user_team_roles(db, user_email) if not _is_admin else {}
    return request.app.state.templates.TemplateResponse(
        request,
        "prompts_partial.html",
        {
            "request": request,
            "data": data,
            "pagination": pagination.model_dump(),
            "links": links.model_dump() if links else None,
            "root_path": _resolve_root_path(request),
            "include_inactive": include_inactive,
            "query_params": query_params,
            "current_user_email": user_email,
            "is_admin": _is_admin,
            "user_team_roles": _team_roles,
        },
    )


@admin_router.get("/gateways/partial", response_class=HTMLResponse)
@require_permission("gateways.read", allow_admin_bypass=False)
async def admin_gateways_partial_html(
    request: Request,
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    per_page: int = Query(settings.pagination_default_page_size, ge=1, le=settings.pagination_max_page_size, description="Items per page"),
    q: str = Query("", max_length=500, description="Search query"),
    tags: QueryTagsFilter = None,
    include_inactive: bool = True,
    render: QueryRenderMode = None,
    team_id: Optional[str] = Depends(_validated_team_id_param),
    include_public: bool = False,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    """Return paginated gateways HTML partials for the admin UI.

    This HTMX endpoint returns only the partial HTML used by the admin UI for
    gateways. It supports three render modes:

    - default: full table partial (rows + controls)
    - ``render="controls"``: return only pagination controls
    - ``render="selector"``: return selector items for infinite scroll

    Args:
        request (Request): FastAPI request object used by the template engine.
        page (int): Page number (1-indexed).
        per_page (int): Number of items per page (bounded by settings).
        q (str): Free-text query string.
        tags (Optional[str]): Tag filter expression (comma=OR, plus=AND).
        include_inactive (bool): If True, include inactive gateways in results.
        render (Optional[str]): Render mode; one of None, "controls", "selector".
        team_id (Optional[str]): Filter by team ID.
        include_public (bool): Whether to include all public gateways in the results.
        db (Session): Database session (dependency-injected).
        user: Authenticated user object from dependency injection.

    Returns:
        Union[HTMLResponse, TemplateResponse]: A rendered template response
        containing either the table partial, pagination controls, or selector
        items depending on ``render``. The response contains JSON-serializable
        encoded gateway data when templates expect it.
    """
    user_email = get_user_email(user)
    search_query = _normalize_search_query(q)
    normalized_tags = _normalize_tags_query(tags)
    tag_groups = _parse_tag_filter_groups(normalized_tags)
    LOGGER.debug(f"🔷 GATEWAYS PARTIAL REQUEST - User: {user_email}, team_id: {team_id}, page: {page}, render: {render}, referer: {request.headers.get('referer', 'none')}")
    # Normalize per_page within configured bounds
    per_page = max(settings.pagination_min_page_size, min(per_page, settings.pagination_max_page_size))

    # Team scoping
    team_ids = await _get_user_team_ids(user, db)

    # Build base query
    query = select(DbGateway).options(joinedload(DbGateway.email_team), *gateway_capability_loaders())

    if not include_inactive:
        query = query.where(DbGateway.enabled.is_(True))

    # Build access conditions
    # When team_id is specified, show ONLY items from that team (simpler, team-scoped view)
    # When team_id + include_public, show team items PLUS public items from all teams
    # When team_id is NOT specified, show all accessible items (owned + team + public)
    if team_id:
        # Team-specific view: only show gateways from the specified team if user is a member
        if team_id in team_ids:
            # Apply visibility check: team/public resources + user's own resources (including private)
            team_access = [
                and_(DbGateway.team_id == team_id, DbGateway.visibility.in_(["team", "public"])),
                and_(DbGateway.team_id == team_id, DbGateway.owner_email == user_email),
            ]
            if include_public:
                # Include all globally public items from any team.
                # Items with visibility='team' or 'private' from other teams are
                # blocked by the other conditions (which require team_id == selected team).
                team_access.append(DbGateway.visibility == "public")
            query = query.where(or_(*team_access))
            LOGGER.debug(f"Filtering gateways by team_id: {team_id}{' (include_public)' if include_public else ''}")
        else:
            # User is not a member of this team, return no results
            LOGGER.warning(f"User {user_email} attempted to filter by team {team_id} but is not a member")
            query = query.where(false())
    else:
        # All Teams view: apply standard access conditions
        access_conditions = []
        access_conditions.append(_owner_access_condition(DbGateway.owner_email, DbGateway.team_id, user_email=user_email, team_ids=team_ids, user=user))
        if team_ids:
            access_conditions.append(and_(DbGateway.team_id.in_(team_ids), DbGateway.visibility.in_(["team", "public"])))
        access_conditions.append(DbGateway.visibility == "public")

        query = query.where(or_(*access_conditions))

    if search_query:
        query = query.where(
            or_(
                _like_contains(func.lower(DbGateway.id), search_query),
                _like_contains(func.lower(DbGateway.name), search_query),
                _like_contains(func.lower(coalesce(DbGateway.url, "")), search_query),
                _like_contains(func.lower(coalesce(DbGateway.description, "")), search_query),
            )
        )

    query = _apply_tag_filter_groups(query, db, DbGateway.tags, tag_groups)

    # Apply pagination ordering for cursor support
    query = query.order_by(desc(DbGateway.created_at), desc(DbGateway.id))

    # Build query params for pagination links
    query_params = {}
    if include_inactive:
        query_params["include_inactive"] = "true"
    if team_id:
        query_params["team_id"] = team_id
    if search_query:
        query_params["q"] = search_query
    if normalized_tags:
        query_params["tags"] = normalized_tags

    # Use unified pagination function
    root_path = _resolve_root_path(request)
    base_url = f"{root_path}/admin/gateways/partial"
    paginated_result = await paginate_query(
        db=db,
        query=query,
        page=page,
        per_page=per_page,
        cursor=None,  # HTMX partials use page-based navigation
        base_url=base_url,
        query_params=query_params,
        use_cursor_threshold=False,  # Disable auto-cursor switching for UI
    )

    # Extract paginated gateways (DbGateway objects)
    gateways_db = paginated_result["data"]
    pagination = paginated_result["pagination"]
    links = paginated_result["links"]

    # Batch convert to Pydantic models using gateway service
    # This eliminates the N+1 query problem from calling get_gateway_details() in a loop
    gateways_pydantic = []
    failed_count = 0
    for g in gateways_db:
        try:
            gateways_pydantic.append(gateway_service.convert_gateway_to_read(g))
        except (ValidationError, ValueError, KeyError, TypeError, binascii.Error) as e:
            failed_count += 1
            LOGGER.exception(f"Failed to convert gateway {getattr(g, 'id', 'unknown')} ({getattr(g, 'name', 'unknown')}): {e}")
    _adjust_pagination_for_conversion_failures(pagination, failed_count, len(gateways_pydantic))
    data = jsonable_encoder(gateways_pydantic)

    # End the read-only transaction before template rendering to avoid idle-in-transaction timeouts.
    db.commit()

    LOGGER.info(f"🔷 GATEWAYS PARTIAL RESPONSE - Returning {len(data)} gateways, render mode: {render or 'default'}, team_id used in query: {team_id}")

    if render == "controls":
        return request.app.state.templates.TemplateResponse(
            request,
            "pagination_controls.html",
            {
                "request": request,
                "pagination": pagination.model_dump(),
                "base_url": base_url,
                "hx_target": "#gateways-table-body",
                "hx_indicator": "#gateways-loading",
                "query_params": query_params,
                "root_path": _resolve_root_path(request),
            },
        )

    if render == "selector":
        return request.app.state.templates.TemplateResponse(
            request,
            "gateways_selector_items.html",
            {"request": request, "data": data, "pagination": pagination.model_dump(), "root_path": _resolve_root_path(request), "team_id": team_id, "include_public": include_public},
        )

    _is_admin = bool(user.get("is_admin", False) if isinstance(user, dict) else getattr(user, "is_admin", False))
    _team_roles = _get_user_team_roles(db, user_email) if not _is_admin else {}
    return request.app.state.templates.TemplateResponse(
        request,
        "gateways_partial.html",
        {
            "request": request,
            "data": data,
            "pagination": pagination.model_dump(),
            "links": links.model_dump() if links else None,
            "root_path": _resolve_root_path(request),
            "include_inactive": include_inactive,
            "query_params": query_params,
            "current_user_email": user_email,
            "is_admin": _is_admin,
            "user_team_roles": _team_roles,
        },
    )


@admin_router.get("/gateways/ids", response_class=JSONResponse)
@require_permission("gateways.read", allow_admin_bypass=False)
async def admin_get_all_gateways_ids(
    include_inactive: bool = False,
    team_id: Optional[str] = Depends(_validated_team_id_param),
    include_public: bool = False,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    """Return all gateway IDs accessible to the current user (select-all helper).

    This endpoint is used by UI "Select All" helpers to fetch only the IDs
    of gateways the requesting user can access (owner, team, or public).

    Args:
        include_inactive (bool): When True include prompts that are inactive.
        team_id (Optional[str]): Filter by team ID.
        include_public (bool): Whether to include all public gateways in the results.
        db (Session): Database session (injected dependency).
        user: Authenticated user object from dependency injection.

    Returns:
        dict: A dictionary containing two keys:
            - "prompt_ids": List[str] of accessible prompt IDs.
            - "count": int number of IDs returned.
    """
    user_email = get_user_email(user)
    team_ids = await _get_user_team_ids(user, db)

    query = select(DbGateway.id)

    if not include_inactive:
        query = query.where(DbGateway.enabled.is_(True))

    # Build access conditions
    # When team_id is specified, show ONLY items from that team (team-scoped view)
    # When team_id + include_public, show team items PLUS public items from all teams
    # Otherwise, show all accessible items (All Teams view)
    if team_id:
        if team_id in team_ids:
            # Apply visibility check: team/public resources + user's own resources (including private)
            team_access = [
                and_(DbGateway.team_id == team_id, DbGateway.visibility.in_(["team", "public"])),
                and_(DbGateway.team_id == team_id, DbGateway.owner_email == user_email),
            ]
            if include_public:
                team_access.append(DbGateway.visibility == "public")
            query = query.where(or_(*team_access))
            LOGGER.debug(f"Filtering gateway IDs by team_id: {team_id}{' (include_public)' if include_public else ''}")
        else:
            LOGGER.warning(f"User {user_email} attempted to filter gateway IDs by team {team_id} but is not a member")
            query = query.where(false())
    else:
        # All Teams view: apply standard access conditions (owner, team, public)
        access_conditions = []
        access_conditions.append(_owner_access_condition(DbGateway.owner_email, DbGateway.team_id, user_email=user_email, team_ids=team_ids, user=user))
        access_conditions.append(DbGateway.visibility == "public")
        if team_ids:
            access_conditions.append(and_(DbGateway.team_id.in_(team_ids), DbGateway.visibility.in_(["team", "public"])))
        query = query.where(or_(*access_conditions))

    gateway_ids = [row[0] for row in db.execute(query).all()]
    return {"gateway_ids": gateway_ids, "count": len(gateway_ids)}


@admin_router.get("/gateways/search", response_class=JSONResponse)
@require_permission("gateways.read", allow_admin_bypass=False)
async def admin_search_gateways(
    q: str = Query("", max_length=500, description="Search query"),
    tags: QueryTagsFilter = None,
    include_inactive: bool = False,
    limit: int = Query(settings.pagination_default_page_size, ge=1, le=settings.pagination_max_page_size),
    team_id: Optional[str] = Depends(_validated_team_id_param),
    include_public: bool = False,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    """Search gateways by name or description for selector search.

    Performs a case-insensitive search over prompt names and descriptions
    and returns a limited list of matching gateways suitable for selector
    UIs (id, name, description).

    Args:
        q (str): Search query string.
        tags (Optional[str]): Tag filter expression (comma=OR, plus=AND).
        include_inactive (bool): When True include gateways that are inactive.
        limit (int): Maximum number of results to return (bounded by the query parameter).
        team_id (Optional[str]): Filter by team ID.
        include_public (bool): Whether to include all public gateways in the results.
        db (Session): Database session (injected dependency).
        user: Authenticated user object from dependency injection.

    Returns:
        dict: A dictionary containing:
            - "gateways": List[dict] where each dict has keys "id", "name", "description".
            - "count": int number of matched gateways returned.
    """
    user_email = get_user_email(user)
    search_query = _normalize_search_query(q)
    normalized_tags = _normalize_tags_query(tags)
    tag_groups = _parse_tag_filter_groups(normalized_tags)
    if not search_query and not tag_groups:
        return _build_search_response(entity_key="gateways", entity_type="gateways", items=[], query=search_query, tags=normalized_tags, tag_groups=tag_groups)

    team_ids = await _get_user_team_ids(user, db)

    query = select(DbGateway.id, DbGateway.name, DbGateway.url, DbGateway.description)

    if not include_inactive:
        query = query.where(DbGateway.enabled.is_(True))

    # Build access conditions
    # When team_id is specified, show ONLY items from that team (team-scoped view)
    # When team_id + include_public, show team items PLUS public items from all teams
    # Otherwise, show all accessible items (All Teams view)
    if team_id:
        if team_id in team_ids:
            # Apply visibility check: team/public resources + user's own resources (including private)
            team_access = [
                and_(DbGateway.team_id == team_id, DbGateway.visibility.in_(["team", "public"])),
                and_(DbGateway.team_id == team_id, DbGateway.owner_email == user_email),
            ]
            if include_public:
                team_access.append(DbGateway.visibility == "public")
            query = query.where(or_(*team_access))
            LOGGER.debug(f"Filtering gateway search by team_id: {team_id}{' (include_public)' if include_public else ''}")
        else:
            LOGGER.warning(f"User {user_email} attempted to filter gateway search by team {team_id} but is not a member")
            query = query.where(false())
    else:
        # All Teams view: apply standard access conditions (owner, team, public)
        access_conditions = []
        access_conditions.append(_owner_access_condition(DbGateway.owner_email, DbGateway.team_id, user_email=user_email, team_ids=team_ids, user=user))
        access_conditions.append(DbGateway.visibility == "public")
        if team_ids:
            access_conditions.append(and_(DbGateway.team_id.in_(team_ids), DbGateway.visibility.in_(["team", "public"])))
        query = query.where(or_(*access_conditions))

    if search_query:
        search_conditions = [
            _like_contains(func.lower(DbGateway.id), search_query),
            _like_contains(func.lower(DbGateway.name), search_query),
            _like_contains(func.lower(coalesce(DbGateway.url, "")), search_query),
            _like_contains(func.lower(coalesce(DbGateway.description, "")), search_query),
        ]
        query = query.where(or_(*search_conditions))

    query = _apply_tag_filter_groups(query, db, DbGateway.tags, tag_groups)

    if search_query:
        query = query.order_by(
            case(
                (func.lower(DbGateway.name).startswith(search_query), 1),
                (func.lower(coalesce(DbGateway.url, "")).startswith(search_query), 1),
                else_=2,
            ),
            func.lower(DbGateway.name),
        )
    else:
        query = query.order_by(func.lower(DbGateway.name))
    query = query.limit(limit)

    results = db.execute(query).all()
    gateways = []
    for row in results:
        gateways.append(
            {
                "id": row.id,
                "name": row.name,
                "url": row.url,
                "description": row.description,
            }
        )

    return _build_search_response(entity_key="gateways", entity_type="gateways", items=gateways, query=search_query, tags=normalized_tags, tag_groups=tag_groups)


@admin_router.get("/servers/ids", response_class=JSONResponse)
@require_permission("servers.read", allow_admin_bypass=False)
async def admin_get_all_server_ids(
    include_inactive: bool = False,
    team_id: Optional[str] = Depends(_validated_team_id_param),
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    """Return all server IDs accessible to the current user (select-all helper).

    This endpoint is used by UI "Select All" helpers to fetch only the IDs
    of servers the requesting user can access (owner, team, or public).

    Args:
        include_inactive (bool): When True include servers that are inactive.
        team_id (Optional[str]): Filter by team ID.
        db (Session): Database session (injected dependency).
        user: Authenticated user object from dependency injection.

    Returns:
        dict: A dictionary containing two keys:
            - "server_ids": List[str] of accessible server IDs.
            - "count": int number of IDs returned.
    """
    user_email = get_user_email(user)
    team_ids = await _get_user_team_ids(user, db)

    query = select(DbServer.id)

    if not include_inactive:
        query = query.where(DbServer.enabled.is_(True))

    # Build access conditions
    # When team_id is specified, show ONLY items from that team (team-scoped view)
    # Otherwise, show all accessible items (All Teams view)
    if team_id:
        # Team-specific view: only show servers from the specified team
        if team_id in team_ids:
            # Apply visibility check: team/public resources + user's own resources (including private)
            team_access = [
                and_(DbServer.team_id == team_id, DbServer.visibility.in_(["team", "public"])),
                and_(DbServer.team_id == team_id, DbServer.owner_email == user_email),
            ]
            query = query.where(or_(*team_access))
            LOGGER.debug(f"Filtering server IDs by team_id: {team_id}")
        else:
            # User is not a member of this team, return no results using SQLAlchemy's false()
            LOGGER.warning(f"User {user_email} attempted to filter server IDs by team {team_id} but is not a member")
            query = query.where(false())
    else:
        # All Teams view: apply standard access conditions (owner, team, public)
        access_conditions = []
        access_conditions.append(_owner_access_condition(DbServer.owner_email, DbServer.team_id, user_email=user_email, team_ids=team_ids, user=user))
        if team_ids:
            access_conditions.append(and_(DbServer.team_id.in_(team_ids), DbServer.visibility.in_(["team", "public"])))
        access_conditions.append(DbServer.visibility == "public")
        query = query.where(or_(*access_conditions))

    server_ids = [row[0] for row in db.execute(query).all()]
    return {"server_ids": server_ids, "count": len(server_ids)}


@admin_router.get("/servers/search", response_class=JSONResponse)
@require_permission("servers.read", allow_admin_bypass=False)
async def admin_search_servers(
    q: str = Query("", max_length=500, description="Search query"),
    tags: QueryTagsFilter = None,
    include_inactive: bool = False,
    limit: int = Query(settings.pagination_default_page_size, ge=1, le=settings.pagination_max_page_size),
    team_id: Optional[str] = Depends(_validated_team_id_param),
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    """Search servers by name or description for selector search.

    Performs a case-insensitive search over prompt names and descriptions
    and returns a limited list of matching servers suitable for selector
    UIs (id, name, description).

    Args:
        q (str): Search query string.
        tags (Optional[str]): Tag filter expression (comma=OR, plus=AND).
        include_inactive (bool): When True include servers that are inactive.
        limit (int): Maximum number of results to return (bounded by the query parameter).
        team_id (Optional[str]): Filter by team ID.
        db (Session): Database session (injected dependency).
        user: Authenticated user object from dependency injection.

    Returns:
        dict: A dictionary containing:
            - "servers": List[dict] where each dict has keys "id", "name", "description".
            - "count": int number of matched servers returned.
    """
    user_email = get_user_email(user)
    search_query = _normalize_search_query(q)
    normalized_tags = _normalize_tags_query(tags)
    tag_groups = _parse_tag_filter_groups(normalized_tags)
    if not search_query and not tag_groups:
        return _build_search_response(entity_key="servers", entity_type="servers", items=[], query=search_query, tags=normalized_tags, tag_groups=tag_groups)

    team_ids = await _get_user_team_ids(user, db)

    query = select(DbServer.id, DbServer.name, DbServer.description)

    if not include_inactive:
        query = query.where(DbServer.enabled.is_(True))

    # Build access conditions
    # When team_id is specified, show ONLY items from that team (team-scoped view)
    # Otherwise, show all accessible items (All Teams view)
    if team_id:
        # Team-specific view: only show servers from the specified team
        if team_id in team_ids:
            # Apply visibility check: team/public resources + user's own resources (including private)
            team_access = [
                and_(DbServer.team_id == team_id, DbServer.visibility.in_(["team", "public"])),
                and_(DbServer.team_id == team_id, DbServer.owner_email == user_email),
            ]
            query = query.where(or_(*team_access))
            LOGGER.debug(f"Filtering server search by team_id: {team_id}")
        else:
            # User is not a member of this team, return no results using SQLAlchemy's false()
            LOGGER.warning(f"User {user_email} attempted to filter server search by team {team_id} but is not a member")
            query = query.where(false())
    else:
        # All Teams view: apply standard access conditions (owner, team, public)
        access_conditions = []
        access_conditions.append(_owner_access_condition(DbServer.owner_email, DbServer.team_id, user_email=user_email, team_ids=team_ids, user=user))
        if team_ids:
            access_conditions.append(and_(DbServer.team_id.in_(team_ids), DbServer.visibility.in_(["team", "public"])))
        access_conditions.append(DbServer.visibility == "public")
        query = query.where(or_(*access_conditions))

    if search_query:
        search_conditions = [
            _like_contains(func.lower(DbServer.id), search_query),
            _like_contains(func.lower(DbServer.name), search_query),
            _like_contains(func.lower(coalesce(DbServer.description, "")), search_query),
        ]
        query = query.where(or_(*search_conditions))

    query = _apply_tag_filter_groups(query, db, DbServer.tags, tag_groups)

    if search_query:
        query = query.order_by(
            case(
                (func.lower(DbServer.name).startswith(search_query), 1),
                else_=2,
            ),
            func.lower(DbServer.name),
        )
    else:
        query = query.order_by(func.lower(DbServer.name))
    query = query.limit(limit)

    results = db.execute(query).all()
    servers = []
    for row in results:
        servers.append(
            {
                "id": row.id,
                "name": row.name,
                "description": row.description,
            }
        )

    return _build_search_response(entity_key="servers", entity_type="servers", items=servers, query=search_query, tags=normalized_tags, tag_groups=tag_groups)


@admin_router.get("/resources/partial", response_class=HTMLResponse)
@require_permission("resources.read", allow_admin_bypass=False)
async def admin_resources_partial_html(
    request: Request,
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    per_page: int = Query(settings.pagination_default_page_size, ge=1, le=settings.pagination_max_page_size, description="Items per page"),
    q: str = Query("", max_length=500, description="Search query"),
    tags: QueryTagsFilter = None,
    include_inactive: bool = False,
    render: QueryRenderModeControls = None,
    gateway_id: QueryGatewayIdList = None,
    team_id: Optional[str] = Depends(_validated_team_id_param),
    include_public: bool = False,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    """Return HTML partial for paginated resources list (HTMX endpoint).

    This endpoint mirrors the behavior of the tools and prompts partial
    endpoints. It returns a template fragment suitable for HTMX-based
    pagination/infinite-scroll within the admin UI.

    Args:
        request (Request): FastAPI request object used by the template engine.
        page (int): Page number (1-indexed).
        per_page (int): Number of items per page (bounded by settings).
        q (str): Free-text query string.
        tags (Optional[str]): Tag filter expression (comma=OR, plus=AND).
        include_inactive (bool): If True, include inactive resources in results.
        render (Optional[str]): Render mode; when set to "controls" returns only
            pagination controls. Other supported value: "selector" for selector
            items used by infinite scroll selectors.
        gateway_id (Optional[str]): Filter by gateway ID(s), comma-separated.
        team_id (Optional[str]): Filter by team ID.
        include_public (bool): Whether to include all public resources in the results.
        db (Session): Database session (dependency-injected).
        user: Authenticated user object from dependency injection.

    Returns:
        Union[HTMLResponse, TemplateResponse]: Rendered template response with the
        resources partial (rows + controls), pagination controls only, or selector
        items depending on the ``render`` parameter.
    """

    LOGGER.debug(
        f"[RESOURCES FILTER DEBUG] User {get_user_email(user)} requested resources HTML partial (page={page}, per_page={per_page}, render={render}, gateway_id={gateway_id}, team_id={team_id})"
    )
    search_query = _normalize_search_query(q)
    normalized_tags = _normalize_tags_query(tags)
    tag_groups = _parse_tag_filter_groups(normalized_tags)

    # Normalize per_page
    per_page = max(settings.pagination_min_page_size, min(per_page, settings.pagination_max_page_size))

    user_email = get_user_email(user)

    # Team scoping
    team_ids = await _get_user_team_ids(user, db)

    # Build base query
    query = select(DbResource)

    # Apply gateway filter if provided
    if gateway_id:
        gateway_ids = [gid.strip() for gid in gateway_id.split(",") if gid.strip()]
        if gateway_ids:
            null_requested = any(gid.lower() == "null" for gid in gateway_ids)
            non_null_ids = [gid for gid in gateway_ids if gid.lower() != "null"]
            if non_null_ids and null_requested:
                query = query.where(or_(DbResource.gateway_id.in_(non_null_ids), DbResource.gateway_id.is_(None)))
                LOGGER.debug(f"[RESOURCES FILTER DEBUG] Filtering resources by gateway IDs (including NULL): {non_null_ids} + NULL")
            elif null_requested:
                query = query.where(DbResource.gateway_id.is_(None))
                LOGGER.debug("[RESOURCES FILTER DEBUG] Filtering resources by NULL gateway_id (RestTool)")
            else:
                query = query.where(DbResource.gateway_id.in_(non_null_ids))
                LOGGER.debug(f"[RESOURCES FILTER DEBUG] Filtering resources by gateway IDs: {non_null_ids}")
    else:
        LOGGER.debug("[RESOURCES FILTER DEBUG] No gateway_id filter provided, showing all resources")

    # Apply active/inactive filter
    if not include_inactive:
        query = query.where(DbResource.enabled.is_(True))

    # Build access conditions
    # When team_id is specified, show ONLY items from that team (team-scoped view)
    # When team_id + include_public, show team items PLUS public items from all teams
    # Otherwise, show all accessible items (All Teams view)
    if team_id:
        # Team-specific view: only show resources from the specified team
        if team_id in team_ids:
            # Apply visibility check: team/public resources + user's own resources (including private)
            team_access = [
                and_(DbResource.team_id == team_id, DbResource.visibility.in_(["team", "public"])),
                and_(DbResource.team_id == team_id, DbResource.owner_email == user_email),
            ]
            if include_public:
                # Include all globally public items from any team.
                # Items with visibility='team' or 'private' from other teams are
                # blocked by the other conditions (which require team_id == selected team).
                team_access.append(DbResource.visibility == "public")
            query = query.where(or_(*team_access))
            LOGGER.debug(f"Filtering resources by team_id: {team_id}{' (include_public)' if include_public else ''}")
        else:
            # User is not a member of this team, return no results using SQLAlchemy's false()
            LOGGER.warning(f"User {user_email} attempted to filter by team {team_id} but is not a member")
            query = query.where(false())
    else:
        # All Teams view: apply standard access conditions (owner, team, public)
        access_conditions = []
        access_conditions.append(_owner_access_condition(DbResource.owner_email, DbResource.team_id, user_email=user_email, team_ids=team_ids, user=user))
        if team_ids:
            access_conditions.append(and_(DbResource.team_id.in_(team_ids), DbResource.visibility.in_(["team", "public"])))
        access_conditions.append(DbResource.visibility == "public")
        query = query.where(or_(*access_conditions))

    if search_query:
        query = query.where(
            or_(
                _like_contains(func.lower(DbResource.id), search_query),
                _like_contains(func.lower(DbResource.name), search_query),
                _like_contains(func.lower(coalesce(DbResource.uri, "")), search_query),
                _like_contains(func.lower(coalesce(DbResource.description, "")), search_query),
            )
        )

    query = _apply_tag_filter_groups(query, db, DbResource.tags, tag_groups)

    # Add sorting for consistent pagination
    query = query.order_by(desc(DbResource.created_at), desc(DbResource.id))

    # Build query params for pagination links
    query_params = {}
    if include_inactive:
        query_params["include_inactive"] = "true"
    if gateway_id:
        query_params["gateway_id"] = gateway_id
    if team_id:
        query_params["team_id"] = team_id
    if search_query:
        query_params["q"] = search_query
    if normalized_tags:
        query_params["tags"] = normalized_tags

    # Use unified pagination function
    root_path = _resolve_root_path(request)
    base_url = f"{root_path}/admin/resources/partial"
    paginated_result = await paginate_query(
        db=db,
        query=query,
        page=page,
        per_page=per_page,
        cursor=None,  # HTMX partials use page-based navigation
        base_url=base_url,
        query_params=query_params,
        use_cursor_threshold=False,  # Disable auto-cursor switching for UI
    )

    # Extract paginated resources (DbResource objects)
    resources_db = paginated_result["data"]
    pagination = paginated_result["pagination"]
    links = paginated_result["links"]

    # Batch fetch team names for the resources to avoid N+1 queries
    team_ids_set = {r.team_id for r in resources_db if r.team_id}
    team_map = {}
    if team_ids_set:
        teams = db.execute(select(EmailTeam.id, EmailTeam.name).where(EmailTeam.id.in_(team_ids_set), EmailTeam.is_active.is_(True))).all()
        team_map = {team.id: team.name for team in teams}

    # Apply team names to DB objects before conversion
    for r in resources_db:
        r.team = team_map.get(r.team_id) if r.team_id else None

    # Batch convert to Pydantic models using resource service
    resources_pydantic = []
    failed_count = 0
    for r in resources_db:
        try:
            resources_pydantic.append(resource_service.convert_resource_to_read(r, include_metrics=False))
        except (ValidationError, ValueError, KeyError, TypeError, binascii.Error) as e:
            failed_count += 1
            LOGGER.exception(f"Failed to convert resource {getattr(r, 'id', 'unknown')} ({getattr(r, 'name', 'unknown')}): {e}")
    _adjust_pagination_for_conversion_failures(pagination, failed_count, len(resources_pydantic))

    data = jsonable_encoder(resources_pydantic)

    # End the read-only transaction before template rendering to avoid idle-in-transaction timeouts.
    db.commit()

    if render == "controls":
        return request.app.state.templates.TemplateResponse(
            request,
            "pagination_controls.html",
            {
                "request": request,
                "pagination": pagination.model_dump(),
                "base_url": base_url,
                "hx_target": "#resources-table-body",
                "hx_indicator": "#resources-loading",
                "query_params": query_params,
                "root_path": _resolve_root_path(request),
            },
        )

    if render == "selector":
        return request.app.state.templates.TemplateResponse(
            request,
            "resources_selector_items.html",
            {
                "request": request,
                "data": data,
                "pagination": pagination.model_dump(),
                "root_path": _resolve_root_path(request),
                "gateway_id": gateway_id,
                "team_id": team_id,
                "include_public": include_public,
            },
        )

    _is_admin = bool(user.get("is_admin", False) if isinstance(user, dict) else getattr(user, "is_admin", False))
    _team_roles = _get_user_team_roles(db, user_email) if not _is_admin else {}
    return request.app.state.templates.TemplateResponse(
        request,
        "resources_partial.html",
        {
            "request": request,
            "data": data,
            "pagination": pagination.model_dump(),
            "links": links.model_dump() if links else None,
            "root_path": _resolve_root_path(request),
            "include_inactive": include_inactive,
            "query_params": query_params,
            "current_user_email": user_email,
            "is_admin": _is_admin,
            "user_team_roles": _team_roles,
        },
    )


@admin_router.get("/prompts/ids", response_class=JSONResponse)
@require_permission("prompts.read", allow_admin_bypass=False)
async def admin_get_all_prompt_ids(
    q: str = Query("", max_length=500, description="Search query"),
    include_inactive: bool = False,
    gateway_id: QueryGatewayIdList = None,
    team_id: Optional[str] = Depends(_validated_team_id_param),
    include_public: bool = False,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    """Return all prompt IDs accessible to the current user (select-all helper).

    This endpoint is used by UI "Select All" helpers to fetch only the IDs
    of prompts the requesting user can access (owner, team, or public).

    Args:
        q (str): Search query to filter prompts by name or description.
        include_inactive (bool): When True include prompts that are inactive.
        gateway_id (Optional[str]): Filter by gateway ID(s), comma-separated. Accepts the literal value 'null' to indicate NULL gateway_id (local prompts).
        team_id (Optional[str]): Filter by team ID.
        include_public (bool): Whether to include all platform-public prompts when filtering by team.
        db (Session): Database session (injected dependency).
        user: Authenticated user object from dependency injection.

    Returns:
        dict: A dictionary containing two keys:
            - "prompt_ids": List[str] of accessible prompt IDs.
            - "count": int number of IDs returned.
    """
    user_email = get_user_email(user)
    team_ids = await _get_user_team_ids(user, db)

    query = select(DbPrompt.id)

    if not include_inactive:
        query = query.where(DbPrompt.enabled.is_(True))

    # Apply search filter if provided
    if q:
        search_query = _normalize_search_query(q)
        if search_query:
            search_conditions = [
                _like_contains(func.lower(DbPrompt.id), search_query),
                _like_contains(func.lower(DbPrompt.original_name), search_query),
                _like_contains(func.lower(coalesce(DbPrompt.display_name, "")), search_query),
                _like_contains(func.lower(coalesce(DbPrompt.description, "")), search_query),
            ]
            query = query.where(or_(*search_conditions))
            LOGGER.debug(f"Filtering prompt IDs by search query: {search_query}")

    # Apply optional gateway/server scoping
    if gateway_id:
        gateway_ids = [gid.strip() for gid in gateway_id.split(",") if gid.strip()]
        if gateway_ids:
            null_requested = any(gid.lower() == "null" for gid in gateway_ids)
            non_null_ids = [gid for gid in gateway_ids if gid.lower() != "null"]
            if non_null_ids and null_requested:
                query = query.where(or_(DbPrompt.gateway_id.in_(non_null_ids), DbPrompt.gateway_id.is_(None)))
                LOGGER.debug(f"Filtering prompts by gateway IDs (including NULL): {non_null_ids} + NULL")
            elif null_requested:
                query = query.where(DbPrompt.gateway_id.is_(None))
                LOGGER.debug("Filtering prompts by NULL gateway_id (RestTool)")
            else:
                query = query.where(DbPrompt.gateway_id.in_(non_null_ids))
                LOGGER.debug(f"Filtering prompts by gateway IDs: {non_null_ids}")

    # Build access conditions
    # When team_id is specified, show items from that team; optionally include
    # platform-public items when include_public is set (mirrors the partial endpoint).
    # Otherwise, show all accessible items (All Teams view).
    if team_id:
        if team_id in team_ids:
            team_access = [
                and_(DbPrompt.team_id == team_id, DbPrompt.visibility.in_(["team", "public"])),
                and_(DbPrompt.team_id == team_id, DbPrompt.owner_email == user_email),
            ]
            if include_public:
                team_access.append(DbPrompt.visibility == "public")
            query = query.where(or_(*team_access))
            LOGGER.debug(f"Filtering prompt IDs by team_id: {team_id}{' (include_public)' if include_public else ''}")
        else:
            # User is not a member of this team, return no results using SQLAlchemy's false()
            LOGGER.warning(f"User {user_email} attempted to filter prompt IDs by team {team_id} but is not a member")
            query = query.where(false())
    else:
        # All Teams view: apply standard access conditions (owner, team, public)
        access_conditions = []
        access_conditions.append(_owner_access_condition(DbPrompt.owner_email, DbPrompt.team_id, user_email=user_email, team_ids=team_ids, user=user))
        if team_ids:
            access_conditions.append(and_(DbPrompt.team_id.in_(team_ids), DbPrompt.visibility.in_(["team", "public"])))
        access_conditions.append(DbPrompt.visibility == "public")
        query = query.where(or_(*access_conditions))

    prompt_ids = [row[0] for row in db.execute(query).all()]
    return {"prompt_ids": prompt_ids, "count": len(prompt_ids)}


@admin_router.get("/resources/ids", response_class=JSONResponse)
@require_permission("resources.read", allow_admin_bypass=False)
async def admin_get_all_resource_ids(
    q: str = Query("", max_length=500, description="Search query"),
    include_inactive: bool = False,
    gateway_id: QueryGatewayIdList = None,
    team_id: Optional[str] = Depends(_validated_team_id_param),
    include_public: bool = False,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    """Return all resource IDs accessible to the current user (select-all helper).

    This endpoint is used by UI "Select All" helpers to fetch only the IDs
    of resources the requesting user can access (owner, team, or public).

    Args:
        q (str): Search query to filter resources by name, URI, or description.
        include_inactive (bool): Whether to include inactive resources in the results.
        gateway_id (Optional[str]): Filter by gateway ID(s), comma-separated. Accepts the literal value 'null' to indicate NULL gateway_id (local resources).
        team_id (Optional[str]): Filter by team ID.
        include_public (bool): Whether to include all platform-public resources when filtering by team.
        db (Session): Database session dependency.
        user: Authenticated user object from dependency injection.

    Returns:
        dict: A dictionary containing two keys:
            - "resource_ids": List[str] of accessible resource IDs.
            - "count": int number of IDs returned.
    """
    user_email = get_user_email(user)
    team_ids = await _get_user_team_ids(user, db)

    query = select(DbResource.id)

    if not include_inactive:
        query = query.where(DbResource.enabled.is_(True))

    # Apply search filter if provided
    if q:
        search_query = _normalize_search_query(q)
        if search_query:
            search_conditions = [
                _like_contains(func.lower(DbResource.id), search_query),
                _like_contains(func.lower(DbResource.name), search_query),
                _like_contains(func.lower(coalesce(DbResource.uri, "")), search_query),
                _like_contains(func.lower(coalesce(DbResource.description, "")), search_query),
            ]
            query = query.where(or_(*search_conditions))
            LOGGER.debug(f"Filtering resource IDs by search query: {search_query}")

    # Apply optional gateway/server scoping
    if gateway_id:
        gateway_ids = [gid.strip() for gid in gateway_id.split(",") if gid.strip()]
        if gateway_ids:
            null_requested = any(gid.lower() == "null" for gid in gateway_ids)
            non_null_ids = [gid for gid in gateway_ids if gid.lower() != "null"]
            if non_null_ids and null_requested:
                query = query.where(or_(DbResource.gateway_id.in_(non_null_ids), DbResource.gateway_id.is_(None)))
                LOGGER.debug(f"Filtering resources by gateway IDs (including NULL): {non_null_ids} + NULL")
            elif null_requested:
                query = query.where(DbResource.gateway_id.is_(None))
                LOGGER.debug("Filtering resources by NULL gateway_id (RestTool)")
            else:
                query = query.where(DbResource.gateway_id.in_(non_null_ids))
                LOGGER.debug(f"Filtering resources by gateway IDs: {non_null_ids}")

    # Build access conditions
    # When team_id is specified, show items from that team; optionally include
    # platform-public items when include_public is set (mirrors the partial endpoint).
    # Otherwise, show all accessible items (All Teams view).
    if team_id:
        if team_id in team_ids:
            team_access = [
                and_(DbResource.team_id == team_id, DbResource.visibility.in_(["team", "public"])),
                and_(DbResource.team_id == team_id, DbResource.owner_email == user_email),
            ]
            if include_public:
                team_access.append(DbResource.visibility == "public")
            query = query.where(or_(*team_access))
            LOGGER.debug(f"Filtering resource IDs by team_id: {team_id}{' (include_public)' if include_public else ''}")
        else:
            # User is not a member of this team, return no results using SQLAlchemy's false()
            LOGGER.warning(f"User {user_email} attempted to filter resource IDs by team {team_id} but is not a member")
            query = query.where(false())
    else:
        # All Teams view: apply standard access conditions (owner, team, public)
        access_conditions = []
        access_conditions.append(_owner_access_condition(DbResource.owner_email, DbResource.team_id, user_email=user_email, team_ids=team_ids, user=user))
        if team_ids:
            access_conditions.append(and_(DbResource.team_id.in_(team_ids), DbResource.visibility.in_(["team", "public"])))
        access_conditions.append(DbResource.visibility == "public")
        query = query.where(or_(*access_conditions))

    resource_ids = [row[0] for row in db.execute(query).all()]
    return {"resource_ids": resource_ids, "count": len(resource_ids)}


@admin_router.get("/resources/search", response_class=JSONResponse)
@require_permission("resources.read", allow_admin_bypass=False)
async def admin_search_resources(
    q: str = Query("", max_length=500, description="Search query"),
    tags: QueryTagsFilter = None,
    include_inactive: bool = False,
    limit: int = Query(settings.pagination_default_page_size, ge=1, le=settings.pagination_max_page_size),
    gateway_id: QueryGatewayIdList = None,
    team_id: Optional[str] = Depends(_validated_team_id_param),
    include_public: bool = False,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    """Search resources by name or description for selector search.

    Performs a case-insensitive search over resource names and descriptions
    and returns a limited list of matching resources suitable for selector
    UIs (id, name, description).

    Args:
        q (str): Search query string.
        tags (Optional[str]): Tag filter expression (comma=OR, plus=AND).
        include_inactive (bool): When True include resources that are inactive.
        limit (int): Maximum number of results to return (bounded by the query parameter).
        gateway_id (Optional[str]): Filter by gateway ID(s), comma-separated.
        team_id (Optional[str]): Filter by team ID.
        include_public (bool): Whether to include all public resources in the results.
        db (Session): Database session (injected dependency).
        user: Authenticated user object from dependency injection.

    Returns:
        dict: A dictionary containing:
            - "resources": List[dict] where each dict has keys "id", "name", "description".
            - "count": int number of matched resources returned.
    """
    user_email = get_user_email(user)
    search_query = _normalize_search_query(q)
    normalized_tags = _normalize_tags_query(tags)
    tag_groups = _parse_tag_filter_groups(normalized_tags)
    if not search_query and not tag_groups:
        return _build_search_response(entity_key="resources", entity_type="resources", items=[], query=search_query, tags=normalized_tags, tag_groups=tag_groups)

    team_ids = await _get_user_team_ids(user, db)

    query = select(DbResource.id, DbResource.name, DbResource.description)

    # Apply gateway filter if provided
    if gateway_id:
        gateway_ids = [gid.strip() for gid in gateway_id.split(",") if gid.strip()]
        if gateway_ids:
            null_requested = any(gid.lower() == "null" for gid in gateway_ids)
            non_null_ids = [gid for gid in gateway_ids if gid.lower() != "null"]
            if non_null_ids and null_requested:
                query = query.where(or_(DbResource.gateway_id.in_(non_null_ids), DbResource.gateway_id.is_(None)))
                LOGGER.debug(f"Filtering resource search by gateway IDs (including NULL): {non_null_ids} + NULL")
            elif null_requested:
                query = query.where(DbResource.gateway_id.is_(None))
                LOGGER.debug("Filtering resource search by NULL gateway_id")
            else:
                query = query.where(DbResource.gateway_id.in_(non_null_ids))
                LOGGER.debug(f"Filtering resource search by gateway IDs: {non_null_ids}")

    if not include_inactive:
        query = query.where(DbResource.enabled.is_(True))

    # Build access conditions
    # When team_id is specified, show ONLY items from that team (team-scoped view)
    # When team_id + include_public, show team items PLUS public items from all teams
    # Otherwise, show all accessible items (All Teams view)
    if team_id:
        # Team-specific view: only show resources from the specified team
        if team_id in team_ids:
            # Apply visibility check: team/public resources + user's own resources (including private)
            team_access = [
                and_(DbResource.team_id == team_id, DbResource.visibility.in_(["team", "public"])),
                and_(DbResource.team_id == team_id, DbResource.owner_email == user_email),
            ]
            if include_public:
                team_access.append(DbResource.visibility == "public")
            query = query.where(or_(*team_access))
            LOGGER.debug(f"Filtering resource search by team_id: {team_id}{' (include_public)' if include_public else ''}")
        else:
            # User is not a member of this team, return no results using SQLAlchemy's false()
            LOGGER.warning(f"User {user_email} attempted to filter resource search by team {team_id} but is not a member")
            query = query.where(false())
    else:
        # All Teams view: apply standard access conditions (owner, team, public)
        access_conditions = []
        access_conditions.append(_owner_access_condition(DbResource.owner_email, DbResource.team_id, user_email=user_email, team_ids=team_ids, user=user))
        if team_ids:
            access_conditions.append(and_(DbResource.team_id.in_(team_ids), DbResource.visibility.in_(["team", "public"])))
        access_conditions.append(DbResource.visibility == "public")
        query = query.where(or_(*access_conditions))

    if search_query:
        search_conditions = [
            _like_contains(func.lower(DbResource.id), search_query),
            _like_contains(func.lower(DbResource.name), search_query),
            _like_contains(func.lower(coalesce(DbResource.uri, "")), search_query),
            _like_contains(func.lower(coalesce(DbResource.description, "")), search_query),
        ]
        query = query.where(or_(*search_conditions))

    query = _apply_tag_filter_groups(query, db, DbResource.tags, tag_groups)

    if search_query:
        query = query.order_by(
            case(
                (func.lower(DbResource.name).startswith(search_query), 1),
                else_=2,
            ),
            func.lower(DbResource.name),
        )
    else:
        query = query.order_by(func.lower(DbResource.name))
    query = query.limit(limit)

    results = db.execute(query).all()
    resources = []
    for row in results:
        resources.append({"id": row.id, "name": row.name, "description": row.description})

    return _build_search_response(entity_key="resources", entity_type="resources", items=resources, query=search_query, tags=normalized_tags, tag_groups=tag_groups)


@admin_router.get("/prompts/search", response_class=JSONResponse)
@require_permission("prompts.read", allow_admin_bypass=False)
async def admin_search_prompts(
    q: str = Query("", max_length=500, description="Search query"),
    tags: QueryTagsFilter = None,
    include_inactive: bool = False,
    limit: int = Query(settings.pagination_default_page_size, ge=1, le=settings.pagination_max_page_size),
    gateway_id: QueryGatewayIdList = None,
    team_id: Optional[str] = Depends(_validated_team_id_param),
    include_public: bool = False,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    """Search prompts by name or description for selector search.

    Performs a case-insensitive search over prompt names and descriptions
    and returns a limited list of matching prompts suitable for selector
    UIs (id, name, description).

    Args:
        q (str): Search query string.
        tags (Optional[str]): Tag filter expression (comma=OR, plus=AND).
        include_inactive (bool): When True include prompts that are inactive.
        limit (int): Maximum number of results to return (bounded by the query parameter).
        gateway_id (Optional[str]): Filter by gateway ID(s), comma-separated.
        team_id (Optional[str]): Filter by team ID.
        include_public (bool): Whether to include all public prompts in the results.
        db (Session): Database session (injected dependency).
        user: Authenticated user object from dependency injection.

    Returns:
        dict: A dictionary containing:
            - "prompts": List[dict] where each dict has keys "id", "name", "description".
            - "count": int number of matched prompts returned.
    """
    user_email = get_user_email(user)
    search_query = _normalize_search_query(q)
    normalized_tags = _normalize_tags_query(tags)
    tag_groups = _parse_tag_filter_groups(normalized_tags)
    if not search_query and not tag_groups:
        return _build_search_response(entity_key="prompts", entity_type="prompts", items=[], query=search_query, tags=normalized_tags, tag_groups=tag_groups)

    team_ids = await _get_user_team_ids(user, db)

    query = select(DbPrompt.id, DbPrompt.original_name, DbPrompt.display_name, DbPrompt.description)

    # Apply gateway filter if provided
    if gateway_id:
        gateway_ids = [gid.strip() for gid in gateway_id.split(",") if gid.strip()]
        if gateway_ids:
            null_requested = any(gid.lower() == "null" for gid in gateway_ids)
            non_null_ids = [gid for gid in gateway_ids if gid.lower() != "null"]
            if non_null_ids and null_requested:
                query = query.where(or_(DbPrompt.gateway_id.in_(non_null_ids), DbPrompt.gateway_id.is_(None)))
                LOGGER.debug(f"Filtering prompt search by gateway IDs (including NULL): {non_null_ids} + NULL")
            elif null_requested:
                query = query.where(DbPrompt.gateway_id.is_(None))
                LOGGER.debug("Filtering prompt search by NULL gateway_id")
            else:
                query = query.where(DbPrompt.gateway_id.in_(non_null_ids))
                LOGGER.debug(f"Filtering prompt search by gateway IDs: {non_null_ids}")

    if not include_inactive:
        query = query.where(DbPrompt.enabled.is_(True))

    # Build access conditions
    # When team_id is specified, show ONLY items from that team (team-scoped view)
    # When team_id + include_public, show team items PLUS public items from all teams
    # Otherwise, show all accessible items (All Teams view)
    if team_id:
        # Team-specific view: only show prompts from the specified team
        if team_id in team_ids:
            # Apply visibility check: team/public resources + user's own resources (including private)
            team_access = [
                and_(DbPrompt.team_id == team_id, DbPrompt.visibility.in_(["team", "public"])),
                and_(DbPrompt.team_id == team_id, DbPrompt.owner_email == user_email),
            ]
            if include_public:
                team_access.append(DbPrompt.visibility == "public")
            query = query.where(or_(*team_access))
            LOGGER.debug(f"Filtering prompt search by team_id: {team_id}{' (include_public)' if include_public else ''}")
        else:
            # User is not a member of this team, return no results using SQLAlchemy's false()
            LOGGER.warning(f"User {user_email} attempted to filter prompt search by team {team_id} but is not a member")
            query = query.where(false())
    else:
        # All Teams view: apply standard access conditions (owner, team, public)
        access_conditions = []
        access_conditions.append(_owner_access_condition(DbPrompt.owner_email, DbPrompt.team_id, user_email=user_email, team_ids=team_ids, user=user))
        if team_ids:
            access_conditions.append(and_(DbPrompt.team_id.in_(team_ids), DbPrompt.visibility.in_(["team", "public"])))
        access_conditions.append(DbPrompt.visibility == "public")
        query = query.where(or_(*access_conditions))

    if search_query:
        search_conditions = [
            _like_contains(func.lower(DbPrompt.id), search_query),
            _like_contains(func.lower(DbPrompt.original_name), search_query),
            _like_contains(func.lower(coalesce(DbPrompt.display_name, "")), search_query),
            _like_contains(func.lower(coalesce(DbPrompt.description, "")), search_query),
        ]
        query = query.where(or_(*search_conditions))

    query = _apply_tag_filter_groups(query, db, DbPrompt.tags, tag_groups)

    if search_query:
        query = query.order_by(
            case(
                (func.lower(DbPrompt.original_name).startswith(search_query), 1),
                (func.lower(coalesce(DbPrompt.display_name, "")).startswith(search_query), 1),
                else_=2,
            ),
            func.lower(DbPrompt.original_name),
        )
    else:
        query = query.order_by(func.lower(DbPrompt.original_name))
    query = query.limit(limit)

    results = db.execute(query).all()
    prompts = []
    for row in results:
        prompts.append(
            {
                "id": row.id,
                "name": row.original_name,
                "original_name": row.original_name,
                "display_name": row.display_name,
                "description": row.description,
            }
        )

    return _build_search_response(entity_key="prompts", entity_type="prompts", items=prompts, query=search_query, tags=normalized_tags, tag_groups=tag_groups)


@admin_router.get("/tokens/partial", response_class=HTMLResponse)
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
        },
    )


@admin_router.get("/tokens/search", response_class=JSONResponse)
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


@admin_router.delete("/tokens/{token_id}", status_code=204)
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


@require_permission("servers.read", allow_admin_bypass=False)
async def admin_search_catalog(
    q: str,
    limit: int,
    db: Session,
    user: Any,
    request: Request,
) -> dict[str, Any]:
    """Search visible open-auth catalog servers by name or description."""
    search_query = _normalize_search_query(q)
    if not search_query or not settings.mcpgateway_catalog_enabled:
        return _build_search_response(entity_key="catalog", entity_type="catalog", items=[], query=search_query, tags="", tag_groups=[])

    user_email, token_teams = get_scoped_resource_access_context(request, user)
    catalog_request = CatalogListRequest(search=search_query, auth_type="Open", limit=limit)
    catalog_response = await catalog_service.get_catalog_servers(
        catalog_request,
        db,
        user_email=user_email,
        token_teams=token_teams,
    )
    items = [{"id": server.id, "name": server.name, "description": server.description} for server in catalog_response.servers]
    return _build_search_response(entity_key="catalog", entity_type="catalog", items=items, query=search_query, tags="", tag_groups=[])


async def perform_unified_search(
    *,
    request: Optional[Request] = None,
    q: str,
    tags: Optional[str],
    entity_types: Optional[str],
    include_inactive: bool,
    limit: int,
    limit_per_type: Optional[int],
    gateway_id: Optional[str],
    team_id: Optional[str],
    db: Session,
    user: Any,
) -> dict[str, Any]:
    """Unified search across primary entities (shared, permission-agnostic core).

    Single source of truth for unified search. Performs no top-level permission
    check — callers own the outer gate (``admin.dashboard`` for the admin route,
    auth-only for ``/v1/search``). Per-entity RBAC and token scoping are still
    enforced inside each ``admin_search_*`` call.

    Searches servers, gateways, tools, resources, prompts, agents, teams, roots,
    and optionally catalog entries or users (when explicitly requested and permitted).

    Args:
        request: Current request object.
        q (str): Free-text search query.
        tags (Optional[str]): Tag filter expression (comma=OR, plus=AND).
        entity_types (Optional[str]): Optional comma-separated entity type list.
            Supported values: servers, gateways, tools, resources, prompts,
            agents, teams, users, roots, catalog.
        include_inactive (bool): Whether to include inactive entities.
        limit (int): Default per-entity limit for returned items.
        limit_per_type (Optional[int]): Optional alias overriding ``limit``.
        gateway_id (Optional[str]): Gateway filter for tools/resources/prompts.
        team_id (Optional[str]): Team scope filter.
        db (Session): Database session.
        user: Authenticated user context.

    Returns:
        dict[str, Any]: Grouped and flattened search results with metadata.

    Raises:
        HTTPException: If ``entity_types`` is provided but contains no supported values.
    """
    search_query = _normalize_search_query(q)
    normalized_tags = _normalize_tags_query(tags)
    normalized_entity_types = _normalize_tags_query(entity_types)
    tag_groups = _parse_tag_filter_groups(normalized_tags)

    supported_entity_types = ["servers", "gateways", "tools", "resources", "prompts", "agents", "teams", "users", "roots", "catalog"]
    default_entity_types = ["servers", "gateways", "tools", "resources", "prompts", "agents", "teams", "roots"]
    selected_entity_types: list[str] = []
    if normalized_entity_types:
        for raw_entity_type in normalized_entity_types.split(","):
            candidate = raw_entity_type.strip().lower()
            if not candidate:
                continue
            if candidate == "a2a":
                candidate = "agents"
            if candidate in supported_entity_types and candidate not in selected_entity_types:
                selected_entity_types.append(candidate)
    else:
        selected_entity_types = default_entity_types.copy()

    users_explicitly_requested = bool(normalized_entity_types and "users" in selected_entity_types)
    if "users" in selected_entity_types:
        can_search_users = await _has_permission(db=db, user=user, permission="admin.user_management")
        if not can_search_users:
            selected_entity_types = [entity_type for entity_type in selected_entity_types if entity_type != "users"]
            if users_explicitly_requested and not selected_entity_types:
                raise HTTPException(status_code=403, detail=_ACCESS_DENIED_MSG)

    if not selected_entity_types:
        raise HTTPException(status_code=400, detail="No valid entity_types requested")

    resolved_limit = _normalize_int_query(limit, 8)
    effective_limit = _normalize_int_query(limit_per_type, resolved_limit)
    effective_limit = max(1, min(effective_limit, settings.pagination_max_page_size))

    if not search_query and not tag_groups:
        return {
            "query": search_query,
            "tags": normalized_tags,
            "entity_types": selected_entity_types,
            "limit_per_type": effective_limit,
            "filters_applied": {"q": search_query, "tags": normalized_tags, "tag_groups": tag_groups},
            "results": {key: [] for key in selected_entity_types},
            "groups": [],
            "items": [],
            "count": 0,
        }

    async def _safe_entity_search(search_callable, empty_key: str, **kwargs: Any) -> dict[str, Any]:
        """Execute entity search and return empty results on auth denials.

        Intentional silent 401/403 suppression: unified search spans entity types
        with heterogeneous permission gates (e.g. roots require admin.system_config
        with no admin bypass), and a single denial must not fail the whole search
        or leak existence of restricted entities to unprivileged callers.

        Args:
            search_callable: Async entity search function to execute.
            empty_key: Entity collection key used for fallback empty payloads.
            **kwargs: Parameters forwarded to ``search_callable``.

        Returns:
            Search result payload or an empty payload for auth-denied entities.

        Raises:
            HTTPException: Re-raised when the failure is not an auth-denied status.
        """
        try:
            return await search_callable(**kwargs)
        except HTTPException as exc:
            if exc.status_code in {401, 403}:
                return {empty_key: [], "items": [], "count": 0}
            raise

    # Pre-fetch team IDs once and inject into the user context so that
    # individual search functions reuse them via _get_user_team_ids().
    _team_ids = await _get_user_team_ids(user, db)
    user = dict(user)  # shallow copy to avoid mutating the caller's dict
    user["_cached_team_ids"] = _team_ids

    grouped_results: dict[str, list[dict[str, Any]]] = {entity_type: [] for entity_type in selected_entity_types}

    if "servers" in selected_entity_types:
        servers_result = await _safe_entity_search(
            admin_search_servers,
            "servers",
            q=search_query,
            tags=normalized_tags,
            include_inactive=include_inactive,
            limit=effective_limit,
            team_id=team_id,
            db=db,
            user=user,
        )
        grouped_results["servers"] = typing_cast(list[dict[str, Any]], servers_result.get("servers", servers_result.get("items", [])))

    if "gateways" in selected_entity_types:
        gateways_result = await _safe_entity_search(
            admin_search_gateways,
            "gateways",
            q=search_query,
            tags=normalized_tags,
            include_inactive=include_inactive,
            limit=effective_limit,
            team_id=team_id,
            db=db,
            user=user,
        )
        grouped_results["gateways"] = typing_cast(list[dict[str, Any]], gateways_result.get("gateways", gateways_result.get("items", [])))

    if "tools" in selected_entity_types:
        tools_result = await _safe_entity_search(
            admin_search_tools,
            "tools",
            q=search_query,
            tags=normalized_tags,
            include_inactive=include_inactive,
            limit=effective_limit,
            gateway_id=gateway_id,
            team_id=team_id,
            db=db,
            user=user,
        )
        grouped_results["tools"] = typing_cast(list[dict[str, Any]], tools_result.get("tools", tools_result.get("items", [])))

    if "resources" in selected_entity_types:
        resources_result = await _safe_entity_search(
            admin_search_resources,
            "resources",
            q=search_query,
            tags=normalized_tags,
            include_inactive=include_inactive,
            limit=effective_limit,
            gateway_id=gateway_id,
            team_id=team_id,
            db=db,
            user=user,
        )
        grouped_results["resources"] = typing_cast(list[dict[str, Any]], resources_result.get("resources", resources_result.get("items", [])))

    if "prompts" in selected_entity_types:
        prompts_result = await _safe_entity_search(
            admin_search_prompts,
            "prompts",
            q=search_query,
            tags=normalized_tags,
            include_inactive=include_inactive,
            limit=effective_limit,
            gateway_id=gateway_id,
            team_id=team_id,
            db=db,
            user=user,
        )
        grouped_results["prompts"] = typing_cast(list[dict[str, Any]], prompts_result.get("prompts", prompts_result.get("items", [])))

    if "agents" in selected_entity_types:
        agents_result = await _safe_entity_search(
            admin_search_a2a_agents,
            "agents",
            q=search_query,
            tags=normalized_tags,
            include_inactive=include_inactive,
            limit=effective_limit,
            team_id=team_id,
            db=db,
            user=user,
        )
        grouped_results["agents"] = typing_cast(list[dict[str, Any]], agents_result.get("agents", agents_result.get("items", [])))

    # Teams and users do not support tag filtering; only include when a text query exists.
    if "teams" in selected_entity_types and search_query:
        teams_result = await _safe_entity_search(
            admin_search_teams,
            "teams",
            q=search_query,
            include_inactive=include_inactive,
            limit=effective_limit,
            visibility=None,
            db=db,
            user=user,
        )
        if isinstance(teams_result, list):
            grouped_results["teams"] = typing_cast(list[dict[str, Any]], teams_result)
        else:
            grouped_results["teams"] = typing_cast(list[dict[str, Any]], teams_result.get("teams", teams_result.get("items", [])))

    if "users" in selected_entity_types and search_query:
        users_result = await _safe_entity_search(
            admin_search_users,
            "users",
            q=search_query,
            limit=effective_limit,
            db=db,
            user=user,
        )
        grouped_results["users"] = typing_cast(list[dict[str, Any]], users_result.get("users", users_result.get("items", [])))

    # Roots do not support tag filtering; only include when a text query exists.
    if "roots" in selected_entity_types and search_query:
        roots_result = await _safe_entity_search(
            admin_search_roots,
            "roots",
            request=request,
            q=search_query,
            limit=effective_limit,
            db=db,
            user=user,
        )
        grouped_results["roots"] = typing_cast(list[dict[str, Any]], roots_result.get("roots", roots_result.get("items", [])))

    # Catalog does not support tag filtering and remains opt-in for unified search.
    if "catalog" in selected_entity_types and search_query:
        catalog_result = await _safe_entity_search(
            admin_search_catalog,
            "catalog",
            request=request,
            q=search_query,
            limit=effective_limit,
            db=db,
            user=user,
        )
        grouped_results["catalog"] = typing_cast(list[dict[str, Any]], catalog_result.get("catalog", catalog_result.get("items", [])))

    groups = []
    flat_items: list[dict[str, Any]] = []
    for entity_type in selected_entity_types:
        items = grouped_results.get(entity_type, [])
        groups.append({"entity_type": entity_type, "count": len(items), "items": items})
        for item in items:
            enriched_item = dict(item)
            enriched_item["entity_type"] = entity_type
            flat_items.append(enriched_item)

    return {
        "query": search_query,
        "tags": normalized_tags,
        "entity_types": selected_entity_types,
        "limit_per_type": effective_limit,
        "filters_applied": {"q": search_query, "tags": normalized_tags, "tag_groups": tag_groups},
        "results": grouped_results,
        "groups": groups,
        "items": flat_items,
        "count": len(flat_items),
    }


@admin_router.get("/search", response_class=JSONResponse)
@require_permission("admin.dashboard", allow_admin_bypass=False)
async def admin_unified_search(
    request: Request = None,
    q: str = Query("", max_length=500, description="Search query"),
    tags: QueryTagsFilter = None,
    entity_types: QueryEntityTypes = None,
    include_inactive: bool = False,
    limit: int = Query(8, ge=1, le=settings.pagination_max_page_size, description="Per-entity result limit"),
    limit_per_type: Optional[int] = Query(
        None,
        ge=1,
        le=settings.pagination_max_page_size,
        description="Optional alias for per-entity result limit",
    ),
    gateway_id: QueryGatewayIdList = None,
    team_id: Optional[str] = Depends(_validated_team_id_param),
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    """Unified search across primary admin entities (admin-gated wrapper).

    Thin wrapper that enforces the ``admin.dashboard`` permission and delegates
    to :func:`perform_unified_search`.

    Args:
        request: Current request object.
        q (str): Free-text search query.
        tags (Optional[str]): Tag filter expression (comma=OR, plus=AND).
        entity_types (Optional[str]): Optional comma-separated entity type list.
            Supported values: servers, gateways, tools, resources, prompts,
            agents, teams, users, roots.
        include_inactive (bool): Whether to include inactive entities.
        limit (int): Default per-entity limit for returned items.
        limit_per_type (Optional[int]): Optional alias overriding ``limit``.
        gateway_id (Optional[str]): Gateway filter for tools/resources/prompts.
        team_id (Optional[str]): Team scope filter.
        db (Session): Database session.
        user: Authenticated user context.

    Returns:
        dict[str, Any]: Grouped and flattened search results with metadata.
    """
    return await perform_unified_search(
        request=request,
        q=q,
        tags=tags,
        entity_types=entity_types,
        include_inactive=include_inactive,
        limit=limit,
        limit_per_type=limit_per_type,
        gateway_id=gateway_id,
        team_id=team_id,
        db=db,
        user=user,
    )


@admin_router.get("/tools/{tool_id}", response_model=ToolRead)
@require_permission("tools.read", allow_admin_bypass=False)
async def admin_get_tool(tool_id: str, request: Request, db: Session = Depends(get_db), user=Depends(get_current_user_with_permissions)) -> Dict[str, Any]:
    """
    Retrieve specific tool details for the admin UI.

    This endpoint fetches the details of a specific tool from the database
    by its ID. It provides access to all information about the tool for
    viewing and management purposes.

    Args:
        tool_id (str): The ID of the tool to retrieve.
        request (Request): Incoming FastAPI request (for visibility scope resolution).
        db (Session): Database session dependency.
        user (str): Authenticated user dependency.

    Returns:
        ToolRead: The tool details formatted with by_alias=True.

    Raises:
        HTTPException: If the tool is not found.
        Exception: For any other unexpected errors.

    Examples:
        >>> callable(admin_get_tool)
        True
        >>> admin_get_tool.__name__
        'admin_get_tool'
    """
    LOGGER.debug(f"User {get_user_email(user)} requested details for tool ID {tool_id}")
    auth_user_email, auth_token_teams = get_scoped_resource_access_context(request, user)
    _user_email = get_user_email(user)
    _is_admin = bool(user.get("is_admin", False) if isinstance(user, dict) else getattr(user, "is_admin", False))
    _team_roles = _get_user_team_roles(db, _user_email) if not _is_admin else {}
    try:
        tool = await tool_service.get_tool(
            db,
            tool_id,
            requesting_user_email=auth_user_email,
            requesting_user_is_admin=_is_admin,
            requesting_user_team_roles=_team_roles,
            token_teams=auth_token_teams,
        )
        return tool.model_dump(by_alias=True)
    except ToolNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        # Catch any other unexpected errors and re-raise or log as needed
        LOGGER.error(f"Error getting tool {tool_id}: {e}")
        raise e  # Re-raise for now, or return a 500 JSONResponse if preferred for API consistency


def _build_auth_obj_from_form(form: Any) -> Optional[dict[str, Any]]:
    """Parse auth fields from a form and return a serialized auth object, or None.

    Custom headers are validated by the same ``_encode_auth_headers_list`` helper the JSON
    tool/gateway schemas use, so malformed header keys and oversized header sets are rejected
    here with a 422 instead of being persisted and failing later at tool-invocation time.
    Rows with a blank key are dropped first: the admin form submits empty rows for headers the
    user never filled in, and those must keep meaning "no headers" rather than 422.

    Args:
        form: Multipart form data containing auth_type and credential fields.

    Returns:
        A dict with auth_type and encrypted auth_value, or None if no valid auth provided.

    Raises:
        HTTPException: 422 if auth_type is 'oauth' (unsupported on tools) or if the supplied
            custom headers fail validation.
    """
    auth_headers_json = form.get("auth_headers") or ""
    auth_headers: list[dict[str, Any]] = []
    if auth_headers_json:
        try:
            parsed_headers = orjson.loads(auth_headers_json)
        except (orjson.JSONDecodeError, ValueError):
            parsed_headers = []
        # orjson.loads accepts any JSON scalar (e.g. "5", "null", "true"), so guard against a
        # non-list value here rather than letting it reach the list comprehension below and raise
        # an uncaught TypeError (500). A non-list body simply means "no custom headers".
        auth_headers = parsed_headers if isinstance(parsed_headers, list) else []

    auth_type = form.get("auth_type", "")
    if auth_type and auth_type.lower() == "oauth":
        raise HTTPException(status_code=422, detail="auth_type 'oauth' is not supported on tools; configure OAuth on the gateway instead")
    auth_obj: Optional[dict[str, Any]] = None
    if auth_type:
        if auth_type == "basic":
            username = form.get("auth_username", "")
            password = form.get("auth_password", "")
            if username and password:
                creds = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode()
                auth_value = encode_auth({"Authorization": f"Basic {creds}"})
                auth_obj = {"auth_type": auth_type, "auth_value": auth_value}
        elif auth_type == "bearer":
            token = form.get("auth_token", "")
            if token:
                auth_value = encode_auth({"Authorization": f"Bearer {token}"})
                auth_obj = {"auth_type": auth_type, "auth_value": auth_value}
        elif auth_type == "authheaders":
            populated_headers = [h for h in auth_headers if isinstance(h, dict) and h.get("key")]
            if populated_headers:
                try:
                    auth_value = _encode_auth_headers_list(populated_headers)
                except ValueError as exc:
                    raise HTTPException(status_code=422, detail=str(exc)) from exc
                auth_obj = {"auth_type": auth_type, "auth_value": auth_value}
            elif not auth_headers:
                header_key = form.get("auth_header_key", "")
                header_value = form.get("auth_header_value", "")
                if header_key and header_value:
                    auth_value = encode_auth({header_key: header_value})
                    auth_obj = {"auth_type": auth_type, "auth_value": auth_value}
    return auth_obj


@admin_router.post("/tools/")
@admin_router.post("/tools")
@require_permission("tools.create", allow_admin_bypass=False)
async def admin_add_tool(
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> JSONResponse:
    """
    Add a tool via the admin UI with error handling.

    Expects form fields:
      - name
      - url
      - description (optional)
      - requestType (mapped to request_type; defaults to "SSE")
      - integrationType (mapped to integration_type; defaults to "MCP")
      - headers (JSON string)
      - input_schema (JSON string)
      - output_schema (JSON string, optional)
      - jsonpath_filter (optional)
      - auth_type (optional)
      - auth_username (optional)
      - auth_password (optional)
      - auth_token (optional)
      - auth_header_key (optional)
      - auth_header_value (optional)

    Logs the raw form data and assembled tool_data for debugging.

    Args:
        request (Request): the FastAPI request object containing the form data.
        db (Session): the SQLAlchemy database session.
        user (str): identifier of the authenticated user.

    Returns:
        JSONResponse: a JSON response with `{"message": ..., "success": ...}` and an appropriate HTTP status code.

    Raises:
        HTTPException: 422 when public visibility is disabled and request is team-scoped.

    Examples:
        >>> callable(admin_add_tool)
        True
        >>> admin_add_tool.__name__
        'admin_add_tool'
    """
    LOGGER.debug(f"User {get_user_email(user)} is adding a new tool")
    form = await request.form()
    LOGGER.debug(f"Received form data: {dict(form)}")
    team_id = _form_team_id(form)
    integration_type = form.get("integrationType", "REST")
    request_type = form.get("requestType")
    visibility = str(form.get("visibility", "private"))
    _check_public_visibility_allowed(visibility, team_id=team_id)

    if request_type is None:
        if integration_type == "REST":
            request_type = "GET"  # or any valid REST method default
        elif integration_type == "MCP":
            request_type = "SSE"
        else:
            request_type = "GET"

    user_email = get_user_email(user)
    team_service = TeamManagementService(db)
    team_id = await team_service.verify_team_for_user(user_email, team_id)
    # Parse tags from comma-separated string
    tags_str = str(form.get("tags", ""))
    tags: list[str] = [tag.strip() for tag in tags_str.split(",") if tag.strip()] if tags_str else []

    # Build auth object from form fields
    auth_obj = _build_auth_obj_from_form(form)

    # Safely parse potential JSON strings from form
    headers_raw = form.get("headers")
    input_schema_raw = form.get("input_schema")
    output_schema_raw = form.get("output_schema")
    annotations_raw = form.get("annotations")

    # Parse JSON fields with validation
    try:
        headers = orjson.loads(headers_raw if isinstance(headers_raw, str) and headers_raw else "{}")
        input_schema = orjson.loads(input_schema_raw if isinstance(input_schema_raw, str) and input_schema_raw else "{}")
        output_schema = orjson.loads(output_schema_raw) if isinstance(output_schema_raw, str) and output_schema_raw else None
        annotations = orjson.loads(annotations_raw if isinstance(annotations_raw, str) and annotations_raw else "{}")
        query_mapping = orjson.loads(form.get("query_mapping") or "{}")
        header_mapping = orjson.loads(form.get("header_mapping") or "{}")
        allowlist = orjson.loads(form.get("allowlist") or "[]")
        plugin_chain_pre = orjson.loads(form.get("plugin_chain_pre") or "[]")
        plugin_chain_post = orjson.loads(form.get("plugin_chain_post") or "[]")
    except orjson.JSONDecodeError as ex:
        LOGGER.error(f"Invalid JSON in form field: {str(ex)}")
        return ORJSONResponse(
            content={"message": f"Invalid JSON in form field: {str(ex)}", "success": False},
            status_code=422,
        )

    tool_data: dict[str, Any] = {
        "name": form.get("name"),
        "displayName": form.get("displayName"),
        "url": form.get("url"),
        "description": form.get("description"),
        "request_type": request_type,
        "integration_type": integration_type,
        "headers": headers,
        "input_schema": input_schema,
        "output_schema": output_schema,
        "annotations": annotations,
        "jsonpath_filter": form.get("jsonpath_filter", ""),
        "auth": auth_obj,
        "tags": tags,
        "visibility": visibility,
        "team_id": team_id,
        "owner_email": user_email,
        "query_mapping": query_mapping,
        "header_mapping": header_mapping,
        "timeout_ms": int(form.get("timeout_ms")) if form.get("timeout_ms") and form.get("timeout_ms").strip() else None,
        "expose_passthrough": form.get("expose_passthrough", "true"),
        "allowlist": allowlist,
        "plugin_chain_pre": plugin_chain_pre,
        "plugin_chain_post": plugin_chain_post,
    }
    LOGGER.debug(f"Tool data built: {tool_data}")
    try:
        tool = ToolCreate(**tool_data)
        LOGGER.debug(f"Validated tool data: {tool.model_dump(by_alias=True)}")

        # Extract creation metadata
        metadata = MetadataCapture.extract_creation_metadata(request, user)

        await tool_service.register_tool(
            db,
            tool,
            created_by=metadata["created_by"],
            created_from_ip=metadata["created_from_ip"],
            created_via=metadata["created_via"],
            created_user_agent=metadata["created_user_agent"],
            import_batch_id=metadata["import_batch_id"],
            federation_source=metadata["federation_source"],
        )
        return ORJSONResponse(
            content={"message": "Tool registered successfully!", "success": True},
            status_code=200,
        )
    except IntegrityError as ex:
        error_message = ErrorFormatter.format_database_error(ex)
        LOGGER.error(f"IntegrityError in admin_add_tool: {error_message}")
        return ORJSONResponse(status_code=409, content=error_message)
    except ToolNameConflictError as ex:
        LOGGER.error(f"ToolNameConflictError in admin_add_tool: {str(ex)}")
        return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=409)
    except ToolError as ex:
        return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=500)
    except ValidationError as ex:  # This block should catch ValidationError
        LOGGER.error(f"ValidationError in admin_add_tool: {str(ex)}")
        return ORJSONResponse(content=ErrorFormatter.format_validation_error(ex), status_code=422)
    except Exception as ex:
        LOGGER.error(f"Unexpected error in admin_add_tool: {str(ex)}")
        return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=500)


@admin_router.post("/tools/{tool_id}/edit/", response_model=None)
@admin_router.post("/tools/{tool_id}/edit", response_model=None)
@require_permission("tools.update", allow_admin_bypass=False)
async def admin_edit_tool(
    tool_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> Response:
    """
    Edit a tool via the admin UI.

    Expects form fields:
      - name
      - displayName (optional)
      - url
      - description (optional)
      - requestType (to be mapped to request_type)
      - integrationType (to be mapped to integration_type)
      - headers (as a JSON string)
      - input_schema (as a JSON string)
      - output_schema (as a JSON string, optional)
      - jsonpathFilter (optional)
      - auth_type (optional, string: "basic", "bearer", or empty)
      - auth_username (optional, for basic auth)
      - auth_password (optional, for basic auth)
      - auth_token (optional, for bearer auth)
      - auth_header_key (optional, for headers auth)
      - auth_header_value (optional, for headers auth)

    Assembles the tool_data dictionary by remapping form keys into the
    snake-case keys expected by the schemas.

    Args:
        tool_id (str): The ID of the tool to edit.
        request (Request): FastAPI request containing form data.
        db (Session): Database session dependency.
        user (str): Authenticated user dependency.

    Returns:
        Response: A redirect response to the tools section of the admin
            dashboard with a status code of 303 (See Other), or a JSON response with
            an error message if the update fails.

    Raises:
        HTTPException: 422 when public visibility is disabled and request is team-scoped.

    Examples:
        >>> callable(admin_edit_tool)
        True
        >>> admin_edit_tool.__name__
        'admin_edit_tool'
    """
    LOGGER.debug(f"User {get_user_email(user)} is editing tool ID {tool_id}")
    form = await request.form()
    team_id = _form_team_id(form)
    # Parse tags from comma-separated string
    tags_str = str(form.get("tags", ""))
    tags: list[str] = [tag.strip() for tag in tags_str.split(",") if tag.strip()] if tags_str else []

    # Build auth object from form fields
    auth_obj = _build_auth_obj_from_form(form)

    visibility = str(form.get("visibility", "private"))
    _check_public_visibility_allowed(visibility, team_id=team_id)

    user_email = get_user_email(user)
    LOGGER.info(f"before Verifying team for user {user_email} with team_id {team_id}")
    team_service = TeamManagementService(db)
    team_id = await team_service.verify_team_for_user(user_email, team_id)

    headers_raw2 = form.get("headers")
    input_schema_raw2 = form.get("input_schema")
    output_schema_raw2 = form.get("output_schema")
    annotations_raw2 = form.get("annotations")

    # Parse JSON fields with validation
    try:
        headers = orjson.loads(headers_raw2 if isinstance(headers_raw2, str) and headers_raw2 else "{}")
        input_schema = orjson.loads(input_schema_raw2 if isinstance(input_schema_raw2, str) and input_schema_raw2 else "{}")
        output_schema = orjson.loads(output_schema_raw2) if isinstance(output_schema_raw2, str) and output_schema_raw2 else None
        annotations = orjson.loads(annotations_raw2 if isinstance(annotations_raw2, str) and annotations_raw2 else "{}")
    except orjson.JSONDecodeError as ex:
        LOGGER.error(f"Invalid JSON in form field: {str(ex)}")
        return ORJSONResponse(
            content={"message": f"Invalid JSON in form field: {str(ex)}", "success": False},
            status_code=422,
        )

    tool_data: dict[str, Any] = {
        "name": form.get("name"),
        "displayName": form.get("displayName"),
        "custom_name": form.get("customName"),
        "url": form.get("url"),
        "description": form.get("description"),
        "headers": headers,
        "input_schema": input_schema,
        "output_schema": output_schema,
        "annotations": annotations,
        "jsonpath_filter": form.get("jsonpathFilter", ""),
        "auth": auth_obj,
        "tags": tags,
        "visibility": visibility,
        "owner_email": user_email,
        "team_id": team_id,
    }
    # Only include integration_type if it's provided (not disabled in form)
    if "integrationType" in form:
        tool_data["integration_type"] = form.get("integrationType")
    # Only include request_type if it's provided (not disabled in form)
    if "requestType" in form:
        tool_data["request_type"] = form.get("requestType")
    LOGGER.debug(f"Tool update data built: {tool_data}")
    try:
        tool = ToolUpdate(**tool_data)  # Pydantic validation happens here

        # Get current tool to extract current version
        current_tool = db.get(DbTool, tool_id)
        current_version = getattr(current_tool, "version", 0) if current_tool else 0

        # Extract modification metadata
        mod_metadata = MetadataCapture.extract_modification_metadata(request, user, current_version)

        await tool_service.update_tool(
            db,
            tool_id,
            tool,
            modified_by=mod_metadata["modified_by"],
            modified_from_ip=mod_metadata["modified_from_ip"],
            modified_via=mod_metadata["modified_via"],
            modified_user_agent=mod_metadata["modified_user_agent"],
            user_email=user_email,
        )
        return ORJSONResponse(content={"message": "Edit tool successfully", "success": True}, status_code=200)
    except PermissionError as e:
        LOGGER.info(f"Permission denied for user {get_user_email(user)}: {e}")
        return ORJSONResponse(
            content={"message": str(e), "success": False},
            status_code=403,
        )
    except IntegrityError as ex:
        error_message = ErrorFormatter.format_database_error(ex)
        LOGGER.error(f"IntegrityError in admin_tool_resource: {error_message}")
        return ORJSONResponse(status_code=409, content=error_message)
    except ToolNameConflictError as ex:
        LOGGER.error(f"ToolNameConflictError in admin_edit_tool: {str(ex)}")
        return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=409)
    except ToolError as ex:
        LOGGER.error(f"ToolError in admin_edit_tool: {str(ex)}")
        return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=500)
    except ValidationError as ex:  # Catch Pydantic validation errors
        LOGGER.error(f"ValidationError in admin_edit_tool: {str(ex)}")
        return ORJSONResponse(content=ErrorFormatter.format_validation_error(ex), status_code=422)
    except Exception as ex:  # Generic catch-all for unexpected errors
        LOGGER.exception(f"Unexpected error in admin_edit_tool: {ex}")
        return ORJSONResponse(content={"message": "An unexpected error occurred. Please try again or contact support.", "success": False}, status_code=500)


@admin_router.post("/tools/generate-schemas-from-openapi")
# tools.create — this endpoint makes outbound HTTP requests to user-supplied
# URLs to fetch OpenAPI specs.  tools.read would let viewers probe internal
# services; tools.create scopes it to users who can already register tools.
@require_permission("tools.create", allow_admin_bypass=False)
async def generate_schemas_from_openapi(
    request: Request,
    _user=Depends(get_current_user_with_permissions),
) -> JSONResponse:
    """
    Generate input_schema and output_schema from OpenAPI specification URL.

    Expects JSON body with:
      - url: The tool URL (e.g., http://localhost:8100/calculate)
      - request_type: HTTP method (GET, POST, etc.)
      - openapi_url: (optional) Direct OpenAPI spec URL

    Args:
        request: FastAPI Request object containing JSON body

    Returns:
        JSONResponse with generated schemas or error message.
    """
    try:
        body = await _read_request_json(request)
    except Exception:
        return ORJSONResponse(
            content={"message": "Invalid JSON in request body", "success": False},
            status_code=400,
        )

    if not isinstance(body, dict):
        return ORJSONResponse(
            content={"message": "Request body must be a JSON object", "success": False},
            status_code=400,
        )

    tool_url = body.get("url", "")
    request_type = body.get("request_type", "GET")
    openapi_url = body.get("openapi_url", "")

    if not isinstance(tool_url, str) or not isinstance(request_type, str) or not isinstance(openapi_url, str):
        return ORJSONResponse(
            content={"message": "'url', 'request_type', and 'openapi_url' must be strings", "success": False},
            status_code=400,
        )

    tool_url = tool_url.strip()
    request_type = request_type.strip()
    openapi_url = openapi_url.strip()

    if not tool_url:
        return ORJSONResponse(
            content={"message": "'url' is required to identify the API path and base URL", "success": False},
            status_code=400,
        )

    try:
        SecurityValidator.validate_url(tool_url, "Tool URL")
    except ValueError as e:
        return ORJSONResponse(
            content={"message": str(e), "success": False},
            status_code=400,
        )

    parsed = urllib.parse.urlparse(tool_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    tool_path = parsed.path

    try:
        input_schema, output_schema, spec_url = await fetch_and_extract_schemas(
            base_url=base_url,
            path=tool_path,
            method=request_type,
            openapi_url=openapi_url,
            timeout=10.0,
        )
    except ValueError as e:
        return ORJSONResponse(
            content={"message": f"Security validation failed: {str(e)}", "success": False},
            status_code=400,
        )
    except KeyError as e:
        return ORJSONResponse(
            content={"message": str(e), "success": False},
            status_code=404,
        )
    except httpx.HTTPStatusError as e:
        LOGGER.warning("OpenAPI spec server returned HTTP %s", e.response.status_code, exc_info=True)
        return ORJSONResponse(
            content={"message": f"OpenAPI spec server returned HTTP {e.response.status_code}", "success": False},
            status_code=502,
        )
    except httpx.HTTPError:
        LOGGER.warning("Failed to fetch OpenAPI spec", exc_info=True)
        return ORJSONResponse(
            content={"message": "Failed to fetch OpenAPI spec from the provided URL", "success": False},
            status_code=502,
        )
    except Exception:
        LOGGER.error("Error fetching OpenAPI spec", exc_info=True)
        return ORJSONResponse(
            content={"message": "An unexpected error occurred while processing the OpenAPI spec", "success": False},
            status_code=500,
        )

    return ORJSONResponse(
        content={
            "message": "Schemas generated successfully from OpenAPI spec",
            "success": True,
            "input_schema": input_schema,
            "output_schema": output_schema,
            "spec_url": spec_url,
        },
        status_code=200,
    )


@admin_router.post("/tools/{tool_id}/delete")
@require_permission("tools.delete", allow_admin_bypass=False)
async def admin_delete_tool(tool_id: str, request: Request, db: Session = Depends(get_db), user=Depends(get_current_user_with_permissions)) -> RedirectResponse:
    """
    Delete a tool via the admin UI.

    This endpoint permanently removes a tool from the database using its ID.
    It is irreversible and should be used with caution. The operation is logged,
    and the user must be authenticated to access this route.

    Args:
        tool_id (str): The ID of the tool to delete.
        request (Request): FastAPI request object (not used directly, but required by route signature).
        db (Session): Database session dependency.
        user (str): Authenticated user dependency.

    Returns:
        RedirectResponse: A redirect response to the tools section of the admin
        dashboard with a status code of 303 (See Other).

    Examples:
        >>> callable(admin_delete_tool)
        True
        >>> admin_delete_tool.__name__
        'admin_delete_tool'
    """
    form = await request.form()
    is_inactive_checked = str(form.get("is_inactive_checked", "false"))
    purge_metrics = str(form.get("purge_metrics", "false")).lower() == "true"
    user_email = get_user_email(user)
    LOGGER.debug(f"User {user_email} is deleting tool ID {tool_id}")
    error_message = None
    try:
        await tool_service.delete_tool(db, tool_id, user_email=user_email, purge_metrics=purge_metrics)
    except PermissionError as e:
        LOGGER.warning(f"Permission denied for user {user_email} deleting tool {tool_id}: {e}")
        error_message = str(e)
    except Exception as e:
        LOGGER.error(f"Error deleting tool: {e}")
        error_message = "Failed to delete tool. Please try again."

    root_path = _resolve_root_path(request)
    team_id = str(form.get("team_id", "") or "")
    redirect_url = _build_admin_redirect(root_path, "tools", error=error_message, include_inactive=is_inactive_checked.lower() == "true", team_id=team_id)
    return RedirectResponse(redirect_url, status_code=303)


@admin_router.post("/tools/{tool_id}/state")
@require_permission("tools.update", allow_admin_bypass=False)
async def admin_set_tool_state(
    tool_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> RedirectResponse:
    """
    Toggle a tool's active status via the admin UI.

    This endpoint processes a form request to activate or deactivate a tool.
    It expects a form field 'activate' with value "true" to activate the tool
    or "false" to deactivate it. The endpoint handles exceptions gracefully and
    logs any errors that might occur during the status toggle operation.

    Args:
        tool_id (str): The ID of the tool whose status to toggle.
        request (Request): FastAPI request containing form data with the 'activate' field.
        db (Session): Database session dependency.
        user (str): Authenticated user dependency.

    Returns:
        RedirectResponse: A redirect to the admin dashboard tools section with a
        status code of 303 (See Other).

    Examples:
        >>> callable(admin_set_tool_state)
        True
        >>> admin_set_tool_state.__name__
        'admin_set_tool_state'
    """
    error_message = None
    user_email = get_user_email(user)
    LOGGER.debug(f"User {user_email} is toggling tool ID {tool_id}")
    form = await request.form()
    activate = str(form.get("activate", "true")).lower() == "true"
    is_inactive_checked = str(form.get("is_inactive_checked", "false"))
    try:
        await tool_service.set_tool_state(db, tool_id, activate, reachable=activate, user_email=user_email)
    except PermissionError as e:
        LOGGER.warning(f"Permission denied for user {user_email} setting tool state {tool_id}: {e}")
        error_message = str(e)
    except ToolLockConflictError as e:
        LOGGER.warning(f"Lock conflict for user {user_email} setting tool {tool_id} state: {e}")
        error_message = "Tool is being modified by another request. Please try again."
    except Exception as e:
        LOGGER.error(f"Error setting tool state: {e}")
        error_message = "Failed to set tool state. Please try again."

    root_path = _resolve_root_path(request)
    team_id = str(form.get("team_id", "") or "")
    redirect_url = _build_admin_redirect(root_path, "tools", error=error_message, include_inactive=is_inactive_checked.lower() == "true", team_id=team_id)
    return RedirectResponse(redirect_url, status_code=303)


@admin_router.get("/gateways/{gateway_id}", response_model=GatewayRead)
@require_permission("gateways.read", allow_admin_bypass=False)
async def admin_get_gateway(gateway_id: str, request: Request, db: Session = Depends(get_db), user=Depends(get_current_user_with_permissions)) -> Dict[str, Any]:
    """Get gateway details for the admin UI.

    Args:
        gateway_id: Gateway ID.
        request: Incoming FastAPI request (for visibility scope resolution).
        db: Database session.
        user: Authenticated user.

    Returns:
        Gateway details.

    Raises:
        HTTPException: If the gateway is not found.
        Exception: For any other unexpected errors.

    Examples:
        >>> callable(admin_get_gateway)
        True
        >>> admin_get_gateway.__name__
        'admin_get_gateway'
    """
    LOGGER.debug(f"User {get_user_email(user)} requested details for gateway ID {gateway_id}")
    try:
        auth_user_email, auth_token_teams = get_scoped_resource_access_context(request, user)
        gateway = await gateway_service.get_gateway(db, gateway_id, user_email=auth_user_email, token_teams=auth_token_teams)
        return gateway.model_dump(by_alias=True)
    except GatewayLookupConflictError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except GatewayNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        LOGGER.error(f"Error getting gateway {gateway_id}: {e}")
        raise e


@admin_router.post("/gateways/discover-oauth")
@require_permission("gateways.create", allow_admin_bypass=False)
async def admin_discover_oauth(
    request: Request,
    user: dict[str, Any] = Depends(get_current_user_with_permissions),  # pylint: disable=unused-argument
) -> JSONResponse:
    """Discover OAuth/OIDC endpoints from an issuer URL (RFC 8414 / OIDC discovery).

    Args:
        request: FastAPI request containing JSON body with 'issuer' field.
        user: Authenticated user.

    Returns:
        JSONResponse with discovered endpoints or error message.

    Examples:
        >>> callable(admin_discover_oauth)
        True
    """
    # First-Party
    from mcpgateway.services.dcr_service import DcrService  # pylint: disable=import-outside-toplevel
    from mcpgateway.utils.url_auth import sanitize_exception_message  # pylint: disable=import-outside-toplevel

    try:
        body = await request.json()
    except Exception:
        LOGGER.warning("OAuth discovery failed: invalid JSON body")
        return JSONResponse(
            {"success": False, "error": "Invalid JSON body"},
            status_code=400,
        )

    if not isinstance(body, dict):
        return JSONResponse(
            {"success": False, "error": "Request body must be a JSON object"},
            status_code=400,
        )

    issuer = body.get("issuer", "").strip()
    if not issuer:
        return JSONResponse(
            {"success": False, "error": "issuer is required"},
            status_code=400,
        )

    try:
        SecurityValidator.validate_url(issuer, "OAuth issuer URL")
    except ValueError as _e:
        return JSONResponse(
            {"success": False, "error": f"Invalid issuer URL: {_e}"},
            status_code=400,
        )

    try:
        dcr = DcrService()
        metadata = await dcr.discover_as_metadata(issuer)

        def _safe_endpoint(raw: str | None, name: str) -> str | None:
            """Validate and return an OAuth endpoint URL, or None if invalid.

            Args:
                raw: The raw endpoint URL string or None.
                name: The name of the endpoint for validation error messages.

            Returns:
                The validated URL string if valid, None otherwise.
            """
            if not raw:
                return None
            try:
                SecurityValidator.validate_url(raw, name)
                return raw
            except ValueError:
                return None

        return JSONResponse(
            {
                "success": True,
                "token_endpoint": _safe_endpoint(metadata.get("token_endpoint"), "token_endpoint"),
                "authorization_endpoint": _safe_endpoint(metadata.get("authorization_endpoint"), "authorization_endpoint"),
                "jwks_uri": _safe_endpoint(metadata.get("jwks_uri"), "jwks_uri"),
                "registration_endpoint": _safe_endpoint(metadata.get("registration_endpoint"), "registration_endpoint"),
                "dcr_available": bool(metadata.get("registration_endpoint")),
                "scopes_supported": metadata.get("scopes_supported", []),
                "grant_types_supported": metadata.get("grant_types_supported", []),
            }
        )
    except Exception as e:
        LOGGER.warning("OAuth discovery failed: %s", e)
        sanitized = sanitize_exception_message(str(e))
        return JSONResponse(
            {
                "success": False,
                "error": sanitized,
                "message": "Discovery failed. Please configure token and authorization endpoints manually.",
            },
            status_code=502,
        )


@admin_router.post("/gateways", response_model=None)
@require_permission("gateways.create", allow_admin_bypass=False)
async def admin_add_gateway(
    request: Request,
    db: Session = Depends(get_db),
    user: dict[str, Any] = Depends(get_current_user_with_permissions),
) -> JSONResponse:
    """Add a gateway via Admin API.

    Accepts both JSON (application/json) and form data (multipart/form-data).

    **JSON Example:**
    ```json
    {
      "name": "my-gateway",
      "url": "http://localhost:9000/sse",
      "transport": "SSE",
      "description": "My gateway",
      "tags": ["tag1", "tag2"],
      "visibility": "private"
    }
    ```

    **Form Data Example:**
    ```
    name=my-gateway
    url=http://localhost:9000/sse
    transport=SSE
    tags=tag1,tag2
    ```

    Args:
        request: FastAPI request containing JSON or form data.
        gateway_data: Optional pre-parsed Pydantic model (for JSON requests).
        db: Database session.
        user: Authenticated user.

    Returns:
        JSON response with success status and message.

    Raises:
        HTTPException: 422 when public visibility is disabled and request is team-scoped.
    """
    LOGGER.debug(f"User {get_user_email(user)} is adding a new gateway")

    # Parse request data (supports both JSON and form-data)
    try:
        data = await _parse_gateway_data_from_request(request)
    except HTTPException:
        raise
    except Exception as e:
        return ORJSONResponse(content={"message": f"Invalid request data: {e}", "success": False}, status_code=400)

    team_id = data.get("team_id")
    if team_id and isinstance(team_id, str):
        team_id = team_id.strip() or None
    visibility = str(data.get("visibility", "private"))

    _check_public_visibility_allowed(visibility, team_id=team_id)

    try:
        # Handle OAuth client secret encryption if present
        oauth_config = data.get("oauth_config")
        if oauth_config and isinstance(oauth_config, dict) and "client_secret" in oauth_config:
            client_secret = oauth_config.get("client_secret")
            if client_secret and isinstance(client_secret, str):
                encryption = get_encryption_service(settings.auth_encryption_secret)
                oauth_config["client_secret"] = await encryption.encrypt_secret_async(client_secret)
                data["oauth_config"] = oauth_config

        # Handle CA certificate signing
        ca_certificate = data.get("ca_certificate")
        sig: Optional[str] = None
        if ca_certificate and isinstance(ca_certificate, str) and ca_certificate.strip():
            ca_certificate = ca_certificate.strip()
            if settings.enable_ed25519_signing:
                try:
                    private_key_pem = settings.ed25519_private_key.get_secret_value()
                    sig = sign_data(ca_certificate.encode(), private_key_pem)
                    data["ca_certificate_sig"] = sig
                    data["signing_algorithm"] = "ed25519"
                except Exception as e:
                    LOGGER.error(f"Error signing CA certificate: {e}")
                    raise RuntimeError("Failed to sign CA certificate") from e
            else:
                # Explicitly set to None when signing is disabled
                data["ca_certificate_sig"] = None
                data["signing_algorithm"] = None

        # Auto-detect OAuth auth_type
        if oauth_config and not data.get("auth_type"):
            data["auth_type"] = "oauth"
            LOGGER.info("✅ Auto-detected OAuth configuration, setting auth_type='oauth'")

        # Create GatewayCreate model from data
        gateway = GatewayCreate(**data)

    except ValidationError as ex:
        # --- Getting only the custom message from the ValueError ---
        error_ctx = [str(err.get("ctx", {}).get("error", err.get("msg", str(err)))) for err in ex.errors()]
        return ORJSONResponse(content={"success": False, "message": "; ".join(error_ctx)}, status_code=422)

    except RuntimeError as err:
        # --- Getting only the custom message from the RuntimeError ---
        error_ctx = [str(err)]
        return ORJSONResponse(content={"success": False, "message": "; ".join(error_ctx)}, status_code=422)

    user_email = get_user_email(user)

    team_service = TeamManagementService(db)
    team_id = await team_service.verify_team_for_user(user_email, team_id)

    try:
        # Extract creation metadata
        metadata = MetadataCapture.extract_creation_metadata(request, user)

        team_id_cast = typing_cast(Optional[str], team_id)
        result = await gateway_service.register_gateway(
            db,
            gateway,
            created_by=metadata["created_by"],
            created_from_ip=metadata["created_from_ip"],
            created_via=metadata["created_via"],
            created_user_agent=metadata["created_user_agent"],
            visibility=visibility,
            team_id=team_id_cast,
            owner_email=user_email,
            initialize_timeout=settings.httpx_admin_read_timeout,
        )

        # Provide specific guidance for OAuth Authorization Code flow
        is_pending = _gateway_result_status(result) == "pending"
        message = "Gateway registration accepted and pending initialization." if is_pending else "Gateway registered successfully!"
        if oauth_config and isinstance(oauth_config, dict) and oauth_config.get("grant_type") == "authorization_code":
            message = (
                "Gateway registered successfully! 🎉\n\n"
                "⚠️  IMPORTANT: This gateway uses OAuth Authorization Code flow.\n"
                "You must complete the OAuth authorization before tools will work:\n\n"
                "1. Go to the Gateways list\n"
                "2. Click the '🔐 Authorize' button for this gateway\n"
                "3. Complete the OAuth consent flow\n"
                "4. Return to the admin panel\n\n"
                "Tools will not work until OAuth authorization is completed."
            )
        skipped_tools = result.skipped_tools if isinstance(getattr(result, "skipped_tools", None), list) else []
        # `message` is for accepted/success lifecycle state. Failure responses use
        # `error` so admin UI can style async progress separately from errors.
        content: dict[str, Any] = {"message": message, "success": True, "skipped_tools": skipped_tools}
        gateway_payload = _gateway_result_payload(result)
        if gateway_payload is not None:
            content["gateway"] = gateway_payload
        return ORJSONResponse(content=content, status_code=202 if is_pending else 200)

    except PermissionError as ex:
        return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=403)
    except GatewayCredentialError as ex:
        return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=422)
    except GatewayConnectionError as ex:
        return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=502)
    except GatewayDuplicateConflictError as ex:
        return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=409)
    except GatewayNameConflictError as ex:
        return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=409)
    except GatewayToolNameConflictError as ex:
        return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=409)
    except RuntimeError as ex:
        return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=500)
    except ValidationError as ex:
        return ORJSONResponse(content=ErrorFormatter.format_validation_error(ex), status_code=422)
    # NOTE: Pydantic's ValidationError subclasses ValueError, so ValidationError must be handled first.
    except ValueError as ex:
        return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=400)
    except IntegrityError as ex:
        return ORJSONResponse(content=ErrorFormatter.format_database_error(ex), status_code=409)
    except DataError as ex:
        return ORJSONResponse(content=ErrorFormatter.format_database_error(ex), status_code=400)
    except Exception as ex:
        LOGGER.exception(f"Unexpected error in admin_add_gateway: {ex}")
        return ORJSONResponse(content={"message": "An unexpected error occurred. Please try again or contact support.", "success": False}, status_code=500)


# RESTful PUT endpoint for gateway updates (JSON/form-data support)
@admin_router.put("/gateways/{gateway_id}", response_model=None)
@require_permission("gateways.update", allow_admin_bypass=False)
async def admin_update_gateway_rest(
    gateway_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: dict[str, Any] = Depends(get_current_user_with_permissions),
) -> JSONResponse:
    """Update a gateway via REST API (PUT).

    Accepts both JSON (application/json) and form data (multipart/form-data).

    **JSON Example:**
    ```json
    {
      "name": "updated-gateway",
      "url": "http://localhost:9001/sse",
      "description": "Updated description"
    }
    ```

    Args:
        gateway_id: Gateway ID to update.
        request: FastAPI request containing JSON or form data.
        gateway_data: Optional pre-parsed Pydantic model (for JSON requests).
        db: Database session.
        user: Authenticated user.

    Returns:
        JSON response with success status and message.
    """
    LOGGER.debug(f"User {get_user_email(user)} is updating gateway ID {gateway_id}")

    # Parse request data (supports both JSON and form-data)
    try:
        data = await _parse_gateway_data_from_request(request)
    except HTTPException:
        raise
    except Exception as e:
        return ORJSONResponse(content={"message": f"Invalid request data: {e}", "success": False}, status_code=400)

    team_id = data.get("team_id")
    if team_id and isinstance(team_id, str):
        team_id = team_id.strip() or None
    visibility = str(data.get("visibility", "private"))

    _check_public_visibility_allowed(visibility, team_id=team_id)

    try:
        # Handle OAuth client secret encryption if present
        oauth_config = data.get("oauth_config")
        if oauth_config and isinstance(oauth_config, dict) and "client_secret" in oauth_config:
            client_secret = oauth_config.get("client_secret")
            if client_secret and isinstance(client_secret, str):
                encryption = get_encryption_service(settings.auth_encryption_secret)
                oauth_config["client_secret"] = await encryption.encrypt_secret_async(client_secret)
                data["oauth_config"] = oauth_config

        # Auto-detect OAuth auth_type
        if oauth_config and not data.get("auth_type"):
            data["auth_type"] = "oauth"

        user_email = get_user_email(user)

        # Fetch existing gateway to preserve owner_email and team_id
        existing_gateway = db.get(DbGateway, gateway_id)
        if not existing_gateway:
            return ORJSONResponse(content={"message": "Gateway not found", "success": False}, status_code=404)

        # Preserve existing owner_email (don't transfer ownership)
        existing_owner = getattr(existing_gateway, "owner_email", None)
        if existing_owner:
            data["owner_email"] = existing_owner

        # Preserve existing gateway's team_id when no explicit team_id is provided
        if not team_id:
            existing_team = getattr(existing_gateway, "team_id", None)
            if isinstance(existing_team, str) and existing_team:
                team_id = existing_team

        team_service = TeamManagementService(db)
        team_id = await team_service.verify_team_for_user(user_email, team_id)

        # Set team_id (but not owner_email, which was preserved above)
        data["team_id"] = team_id

        # Create GatewayUpdate model from data
        gateway = GatewayUpdate(**data)

        mod_metadata = MetadataCapture.extract_modification_metadata(request, user, 0)
        result = await gateway_service.update_gateway(
            db,
            gateway_id,
            gateway,
            modified_by=mod_metadata["modified_by"],
            modified_from_ip=mod_metadata["modified_from_ip"],
            modified_via=mod_metadata["modified_via"],
            modified_user_agent=mod_metadata["modified_user_agent"],
            user_email=user_email,
        )
        is_pending = _gateway_result_status(result) == "pending"
        # Keep accepted/success text in `message`; reserve `error` for failures.
        content: dict[str, Any] = {
            "message": "Gateway update accepted and pending initialization." if is_pending else "Gateway updated successfully!",
            "success": True,
        }
        gateway_payload = _gateway_result_payload(result)
        if gateway_payload is not None:
            content["gateway"] = gateway_payload
        return ORJSONResponse(content=content, status_code=202 if is_pending else 200)
    except PermissionError as e:
        LOGGER.info(f"Permission denied for user {get_user_email(user)}: {e}")
        return ORJSONResponse(content={"message": str(e), "success": False}, status_code=403)
    except HTTPException:
        raise
    except GatewayNotFoundError as e:
        return ORJSONResponse(content={"message": str(e), "success": False}, status_code=404)
    except Exception as ex:
        if isinstance(ex, GatewayToolNameConflictError):
            return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=409)
        if isinstance(ex, GatewayCredentialError):
            return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=422)
        if isinstance(ex, GatewayConnectionError):
            return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=502)
        if isinstance(ex, RuntimeError):
            return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=500)
        if isinstance(ex, ValidationError):
            return ORJSONResponse(content=ErrorFormatter.format_validation_error(ex), status_code=422)
        if isinstance(ex, IntegrityError):
            return ORJSONResponse(status_code=409, content=ErrorFormatter.format_database_error(ex))
        if isinstance(ex, ValueError):
            return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=400)
        LOGGER.exception(f"Unexpected error in admin_update_gateway_rest: {ex}")
        return ORJSONResponse(content={"message": "An unexpected error occurred. Please try again or contact support.", "success": False}, status_code=500)


# RESTful DELETE endpoint for gateway deletion
@admin_router.delete("/gateways/{gateway_id}", response_model=None, status_code=204)
@require_permission("gateways.delete", allow_admin_bypass=False)
async def admin_delete_gateway_rest(
    gateway_id: str,
    db: Session = Depends(get_db),
    user: dict[str, Any] = Depends(get_current_user_with_permissions),
) -> Response:
    """Delete a gateway via REST API (DELETE).

    **Example Request:**
    ```bash
    curl -X DELETE http://localhost:4444/admin/gateways/gw-123 \
         -H "Authorization: Bearer $TOKEN"
    ```

    **Example Response (204):**
    ```
    (No content - empty response body)
    ```

    Args:
        gateway_id: The ID of the gateway to delete.
        db: Database session.
        user: Authenticated user.

    Returns:
        204 No Content on success, or error response with appropriate status code.
    """
    user_email = get_user_email(user)
    LOGGER.debug(f"User {user_email} is deleting gateway ID {gateway_id}")

    try:
        result = await gateway_service.delete_gateway(db, gateway_id, user_email=user_email)
        if getattr(result, "status", None) == "deleting":
            return ORJSONResponse(
                content={
                    "message": "Gateway deletion accepted and pending cleanup.",
                    "success": True,
                    "gateway": result.model_dump(mode="json", by_alias=True),
                },
                status_code=202,
            )
        return Response(status_code=204)
    except PermissionError as e:
        LOGGER.warning("Permission denied for user %s deleting gateway %s: %s", SecurityValidator.sanitize_log_message(user_email), SecurityValidator.sanitize_log_message(gateway_id), e)
        return ORJSONResponse(content={"message": str(e), "success": False}, status_code=403)
    except GatewayNotFoundError as e:
        return ORJSONResponse(content={"message": str(e), "success": False}, status_code=404)
    except Exception as e:
        LOGGER.error(f"Error deleting gateway: {e}")
        return ORJSONResponse(
            content={"message": "Failed to delete gateway. Please try again.", "success": False},
            status_code=500,
        )


# Ownership transfer endpoint for gateways
@admin_router.post("/gateways/{gateway_id}/transfer-ownership", response_model=GatewayRead)
@require_admin_permission()
async def transfer_gateway_ownership(
    gateway_id: str,
    transfer: GatewayOwnershipTransferRequest,
    db: Session = Depends(get_db),
    _user=Depends(get_current_user_with_permissions),
) -> GatewayRead:
    """Transfer ownership of a gateway to another user.

    Args:
        gateway_id: The ID of the gateway to transfer.
        transfer: Transfer request with target owner email and optional team.
        db: Database session.
        _user: Authenticated admin user.

    Returns:
        Updated GatewayRead with new ownership.
    """
    actor_email = get_user_email(_user)
    token_teams = extract_token_team_ids(_user)
    try:
        result = await gateway_service.transfer_gateway_ownership(
            db=db,
            gateway_id=gateway_id,
            target_owner_email=transfer.target_owner_email,
            actor_email=actor_email,
            target_team_id=transfer.target_team_id,
            token_teams=token_teams,
        )
        return result
    except GatewayNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# Legacy POST endpoint for backward compatibility with HTMX UI
# OAuth callback is now handled by the dedicated OAuth router at /oauth/callback
# This route has been removed to avoid conflicts with the complete implementation
@admin_router.post("/gateways/{gateway_id}/edit")
@require_permission("gateways.update", allow_admin_bypass=False)
async def admin_edit_gateway(
    gateway_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> JSONResponse:
    """Edit a gateway via the admin UI.

    Expects form fields:
      - name
      - url
      - description (optional)
      - tags (optional, comma-separated)

    Args:
        gateway_id: Gateway ID.
        request: FastAPI request containing form data.
        db: Database session.
        user: Authenticated user.

    Returns:
        A redirect response to the admin dashboard.

    Raises:
        HTTPException: 422 when public visibility is disabled and request is team-scoped.

    Examples:
        >>> callable(admin_edit_gateway)
        True
        >>> admin_edit_gateway.__name__
        'admin_edit_gateway'
    """
    LOGGER.debug(f"User {get_user_email(user)} is editing gateway ID {gateway_id}")
    form = await request.form()
    team_id = _form_team_id(form)
    try:
        # Parse tags from comma-separated string
        tags_str = str(form.get("tags", ""))
        tags: List[str] = [tag.strip() for tag in tags_str.split(",") if tag.strip()] if tags_str else []

        visibility = str(form.get("visibility", "private"))
        _check_public_visibility_allowed(visibility, team_id=team_id)

        # Parse auth_headers JSON if present
        auth_headers_json = form.get("auth_headers") or ""
        auth_headers = []
        if auth_headers_json:
            try:
                auth_headers = orjson.loads(auth_headers_json)
            except (orjson.JSONDecodeError, ValueError):
                auth_headers = []

        # Handle passthrough_headers
        passthrough_headers = str(form.get("passthrough_headers"))
        if passthrough_headers and passthrough_headers.strip():
            try:
                passthrough_headers = orjson.loads(passthrough_headers)
            except (orjson.JSONDecodeError, ValueError):
                # Fallback to comma-separated parsing
                passthrough_headers = [h.strip() for h in passthrough_headers.split(",") if h.strip()]
        else:
            passthrough_headers = None

        # Parse OAuth configuration - support both JSON string and individual form fields
        oauth_config_json = str(form.get("oauth_config"))
        oauth_config: Optional[dict[str, Any]] = None

        # Option 1: Pre-assembled oauth_config JSON (from API calls)
        if oauth_config_json and oauth_config_json != "None":
            try:
                oauth_config = orjson.loads(oauth_config_json)
                # Encrypt the client secret if present and not empty
                if oauth_config and "client_secret" in oauth_config and oauth_config["client_secret"]:
                    encryption = get_encryption_service(settings.auth_encryption_secret)
                    oauth_config["client_secret"] = await encryption.encrypt_secret_async(oauth_config["client_secret"])
            except (orjson.JSONDecodeError, ValueError) as e:
                LOGGER.error(f"Failed to parse OAuth config: {e}")
                oauth_config = None

        # Option 2: Assemble from individual UI form fields
        if not oauth_config:
            oauth_config = await _assemble_oauth_config_from_fields(form, encrypt_secret=True)
            if oauth_config:
                LOGGER.info(f"✅ Assembled OAuth config from UI form fields (edit): grant_type={oauth_config.get('grant_type')}, issuer={oauth_config.get('issuer')}")

        user_email = get_user_email(user)
        # Fetch existing gateway once to preserve team_id and any oauth_config fields that
        # the UI edit form does not expose (e.g. redirect_uri_after_oauth).
        existing_gateway = db.get(DbGateway, gateway_id)

        # Preserve existing gateway's team_id when no explicit team_id is provided.
        # Without this guard, verify_team_for_user() falls back to the user's
        # personal team, silently reassigning the gateway on every edit.
        if not team_id:
            existing_team = getattr(existing_gateway, "team_id", None) if existing_gateway else None
            if isinstance(existing_team, str) and existing_team:
                team_id = existing_team

        # Preserve redirect_uri_after_oauth when this deployment does not render the
        # field. A rendered but blank field explicitly disables the redirect.
        if oauth_config is not None and existing_gateway is not None:
            existing_oauth: dict = existing_gateway.oauth_config or {}
            if "redirect_uri_after_success" not in form and "redirect_uri_after_oauth" not in oauth_config and "redirect_uri_after_oauth" in existing_oauth:
                oauth_config["redirect_uri_after_oauth"] = existing_oauth["redirect_uri_after_oauth"]

        team_service = TeamManagementService(db)
        team_id = await team_service.verify_team_for_user(user_email, team_id)

        # Auto-detect OAuth: if oauth_config is present and auth_type not explicitly set, use "oauth"
        auth_type_from_form = str(form.get("auth_type", ""))
        if oauth_config and not auth_type_from_form:
            auth_type_from_form = "oauth"
            LOGGER.info("Auto-detected OAuth configuration in edit, setting auth_type='oauth'")

        gateway = GatewayUpdate(  # Pydantic validation happens here
            name=str(form.get("name")),
            url=str(form["url"]),
            description=str(form.get("description")),
            transport=str(form.get("transport", "SSE")),
            tags=tags,
            auth_type=auth_type_from_form,
            auth_username=str(form.get("auth_username", "")),
            auth_password=str(form.get("auth_password", "")),
            auth_token=str(form.get("auth_token", "")),
            auth_header_key=str(form.get("auth_header_key", "")),
            auth_header_value=str(form.get("auth_header_value", "")),
            auth_value=str(form.get("auth_value", "")),
            auth_headers=auth_headers if auth_headers else None,
            auth_query_param_key=str(form.get("auth_query_param_key", "")) or None,
            auth_query_param_value=str(form.get("auth_query_param_value", "")) or None,
            one_time_auth=form.get("one_time_auth", False),
            passthrough_headers=passthrough_headers,
            oauth_config=oauth_config,
            visibility=visibility,
            owner_email=user_email,
            team_id=team_id,
        )

        mod_metadata = MetadataCapture.extract_modification_metadata(request, user, 0)
        result = await gateway_service.update_gateway(
            db,
            gateway_id,
            gateway,
            modified_by=mod_metadata["modified_by"],
            modified_from_ip=mod_metadata["modified_from_ip"],
            modified_via=mod_metadata["modified_via"],
            modified_user_agent=mod_metadata["modified_user_agent"],
            user_email=user_email,
        )
        is_pending = _gateway_result_status(result) == "pending"
        # Keep accepted/success text in `message`; reserve `error` for failures.
        content: dict[str, Any] = {
            "message": "Gateway update accepted and pending initialization." if is_pending else "Gateway updated successfully!",
            "success": True,
        }
        gateway_payload = _gateway_result_payload(result)
        if gateway_payload is not None:
            content["gateway"] = gateway_payload
        return ORJSONResponse(content=content, status_code=202 if is_pending else 200)
    except PermissionError as e:
        LOGGER.info(f"Permission denied for user {get_user_email(user)}: {e}")
        return ORJSONResponse(
            content={"message": str(e), "success": False},
            status_code=403,
        )
    except HTTPException:
        raise
    except Exception as ex:
        if isinstance(ex, GatewayToolNameConflictError):
            return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=409)
        if isinstance(ex, GatewayCredentialError):
            return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=422)
        if isinstance(ex, GatewayConnectionError):
            return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=502)
        if isinstance(ex, RuntimeError):
            return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=500)
        if isinstance(ex, ValidationError):
            return ORJSONResponse(content=ErrorFormatter.format_validation_error(ex), status_code=422)
        if isinstance(ex, IntegrityError):
            return ORJSONResponse(status_code=409, content=ErrorFormatter.format_database_error(ex))
        # NOTE: Pydantic's ValidationError subclasses ValueError, so ValidationError must be handled first.
        if isinstance(ex, ValueError):
            return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=400)
        LOGGER.exception(f"Unexpected error in admin_edit_gateway: {ex}")
        return ORJSONResponse(content={"message": "An unexpected error occurred. Please try again or contact support.", "success": False}, status_code=500)


@admin_router.post("/gateways/{gateway_id}/delete")
@require_permission("gateways.delete", allow_admin_bypass=False)
async def admin_delete_gateway(gateway_id: str, request: Request, db: Session = Depends(get_db), user=Depends(get_current_user_with_permissions)) -> RedirectResponse:
    """
    Delete a gateway via the admin UI.

    This endpoint removes a gateway from the database by its ID. The deletion is
    permanent and cannot be undone. It requires authentication and logs the
    operation for auditing purposes.

    Args:
        gateway_id (str): The ID of the gateway to delete.
        request (Request): FastAPI request object (not used directly but required by the route signature).
        db (Session): Database session dependency.
        user (str): Authenticated user dependency.

    Returns:
        RedirectResponse: A redirect response to the gateways section of the admin
        dashboard with a status code of 303 (See Other).

    Examples:
        >>> callable(admin_delete_gateway)
        True
        >>> admin_delete_gateway.__name__
        'admin_delete_gateway'
    """
    user_email = get_user_email(user)
    LOGGER.debug(f"User {user_email} is deleting gateway ID {gateway_id}")
    error_message = None
    accepted_message = None
    try:
        result = await gateway_service.delete_gateway(db, gateway_id, user_email=user_email)
        if getattr(result, "status", None) == "deleting":
            accepted_message = "Gateway deletion accepted and pending cleanup."
    except PermissionError as e:
        LOGGER.warning("Permission denied for user %s deleting gateway %s: %s", SecurityValidator.sanitize_log_message(user_email), SecurityValidator.sanitize_log_message(gateway_id), e)
        error_message = str(e)
    except Exception as e:
        LOGGER.error(f"Error deleting gateway: {e}")
        error_message = "Failed to delete gateway. Please try again."

    form = await request.form()
    is_inactive_checked = str(form.get("is_inactive_checked", "false"))
    root_path = _resolve_root_path(request)
    team_id = str(form.get("team_id", "") or "")
    redirect_url = _build_admin_redirect(
        root_path,
        "gateways",
        error=error_message,
        message=accepted_message,
        include_inactive=is_inactive_checked.lower() == "true",
        team_id=team_id,
    )
    return RedirectResponse(redirect_url, status_code=303)


@admin_router.get("/resources/test/{resource_uri:path}")
@require_permission("resources.read", allow_admin_bypass=False)
async def admin_test_resource(resource_uri: str, db: Session = Depends(get_db), user=Depends(get_current_user_with_permissions)) -> Dict[str, Any]:
    """
    Test reading a resource by its URI for the admin UI.

    Args:
        resource_uri: The full resource URI (may include encoded characters).
        db: Database session dependency.
        user: Authenticated user with proper permissions.

    Returns:
        A dictionary containing the resolved resource content.

    Raises:
        HTTPException: If the resource is not found.
        Exception: For unexpected errors.

    Examples:
        >>> callable(admin_test_resource)
        True
        >>> admin_test_resource.__name__
        'admin_test_resource'
    """
    user_email = get_user_email(user)
    LOGGER.debug(f"User {user_email} requested details for resource ID {resource_uri}")

    # For admin UI, pass user email and token_teams=None
    # Since admin UI requires admin permissions, the user should have full access
    # via the admin bypass (is_admin + token_teams=None)
    is_admin = user.get("is_admin", False) if isinstance(user, dict) else False

    try:
        # Admin users get unrestricted access (user_email=None, token_teams=None)
        # Non-admin users get team-based access (user_email=email, token_teams=None for lookup)
        resource_content = await resource_service.read_resource(
            db,
            resource_uri=resource_uri,
            user=None if is_admin else user_email,
            token_teams=None,
        )
        return {"content": resource_content}
    except ResourceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ResourceError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        LOGGER.error(f"Error getting resource for {resource_uri}: {e}")
        raise e


@admin_router.get("/resources/{resource_id}")
@require_permission("resources.read", allow_admin_bypass=False)
async def admin_get_resource(resource_id: str, request: Request, db: Session = Depends(get_db), user=Depends(get_current_user_with_permissions)) -> Dict[str, Any]:
    """Get resource details for the admin UI.

    Args:
        resource_id: Resource ID.
        request: Incoming FastAPI request (for visibility scope resolution).
        db: Database session.
        user: Authenticated user.

    Returns:
        A dictionary containing resource details.

    Raises:
        HTTPException: If the resource is not found.
        Exception: For any other unexpected errors.

    Examples:
        >>> callable(admin_get_resource)
        True
        >>> admin_get_resource.__name__
        'admin_get_resource'
    """
    LOGGER.debug(f"User {get_user_email(user)} requested details for resource ID {resource_id}")
    try:
        auth_user_email, auth_token_teams = get_scoped_resource_access_context(request, user)
        resource = await resource_service.get_resource_by_id(
            db,
            resource_id,
            include_inactive=True,
            user_email=auth_user_email,
            token_teams=auth_token_teams,
        )
        return {"resource": resource.model_dump(by_alias=True)}
    except ResourceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        LOGGER.error(f"Error getting resource {resource_id}: {e}")
        raise e


@admin_router.post("/resources")
@require_permission("resources.create", allow_admin_bypass=False)
async def admin_add_resource(request: Request, db: Session = Depends(get_db), user=Depends(get_current_user_with_permissions)) -> Response:
    """
    Add a resource via the admin UI.

    Expects form fields:
      - uri
      - name
      - description (optional)
      - mime_type (optional)
      - content

    Args:
        request: FastAPI request containing form data.
        db: Database session.
        user: Authenticated user.

    Returns:
        A redirect response to the admin dashboard.

    Raises:
        HTTPException: 422 when public visibility is disabled and request is team-scoped.

    Examples:
        >>> callable(admin_add_resource)
        True
        >>> admin_add_resource.__name__
        'admin_add_resource'
    """
    LOGGER.debug(f"User {get_user_email(user)} is adding a new resource")
    form = await request.form()
    team_id = _form_team_id(form)

    # Parse tags from comma-separated string
    tags_str = str(form.get("tags", ""))
    tags: List[str] = [tag.strip() for tag in tags_str.split(",") if tag.strip()] if tags_str else []
    visibility = str(form.get("visibility", "public"))
    _check_public_visibility_allowed(visibility, team_id=team_id)
    user_email = get_user_email(user)
    team_service = TeamManagementService(db)
    team_id = await team_service.verify_team_for_user(user_email, team_id)

    try:
        # Handle template field: convert empty string to None for optional field
        template = None
        template_value = form.get("uri_template")
        template = template_value if template_value else None
        template_value = form.get("uri_template")
        uri_value = form.get("uri")

        # Ensure uri_value is a string
        if isinstance(uri_value, str) and "{" in uri_value and "}" in uri_value:
            template = uri_value

        resource = ResourceCreate(
            uri=str(form["uri"]),
            name=str(form["name"]),
            description=str(form.get("description", "")),
            mime_type=str(form.get("mimeType", "")),
            uri_template=template,
            content=str(form["content"]),
            tags=tags,
            visibility=visibility,
            team_id=team_id,
            owner_email=user_email,
        )

        metadata = MetadataCapture.extract_creation_metadata(request, user)

        await resource_service.register_resource(
            db,
            resource,
            created_by=metadata["created_by"],
            created_from_ip=metadata["created_from_ip"],
            created_via=metadata["created_via"],
            created_user_agent=metadata["created_user_agent"],
            import_batch_id=metadata["import_batch_id"],
            federation_source=metadata["federation_source"],
            team_id=team_id,
            owner_email=user_email,
            visibility=visibility,
        )
        return ORJSONResponse(
            content={"message": "Add resource registered successfully!", "success": True},
            status_code=200,
        )
    except Exception as ex:
        # Roll back only when a transaction is active to avoid sqlite3 "no transaction" errors.
        try:
            active_transaction = db.get_transaction() if hasattr(db, "get_transaction") else None
            if db.is_active and active_transaction is not None:
                db.rollback()
        except (InvalidRequestError, OperationalError) as rollback_error:
            LOGGER.warning(
                "Rollback failed (ignoring for SQLite compatibility): %s",
                rollback_error,
            )

        if isinstance(ex, ValidationError):
            LOGGER.error("ValidationError in admin_add_resource: %s", sanitize_validation_error_for_log(ex))
            return ORJSONResponse(content=ErrorFormatter.format_validation_error(ex), status_code=422)
        if isinstance(ex, IntegrityError):
            error_message = ErrorFormatter.format_database_error(ex)
            LOGGER.error(f"IntegrityError in admin_add_resource: {error_message}")
            return ORJSONResponse(status_code=409, content=error_message)
        if isinstance(ex, ResourceValidationError):
            LOGGER.error(f"ResourceValidationError in admin_add_resource: {ex}")
            return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=422)
        if isinstance(ex, ResourceURIConflictError):
            LOGGER.error(f"ResourceURIConflictError in admin_add_resource: {ex}")
            return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=409)
        if isinstance(ex, ContentSizeError):
            LOGGER.error(f"ContentSizeError in admin_add_resource: {ex}")
            return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=413)
        if isinstance(ex, ContentTypeError):
            LOGGER.error(f"ContentTypeError in admin_add_resource: {ex}")
            return ORJSONResponse(
                content={
                    "message": str(ex),
                    "success": False,
                    "mime_type": ex.mime_type,
                    "allowed_types": ex.allowed_types,
                },
                status_code=415,
            )
        LOGGER.exception(f"Unexpected error in admin_add_resource: {ex}")
        return ORJSONResponse(content={"message": "An unexpected error occurred. Please try again or contact support.", "success": False}, status_code=500)


@admin_router.post("/resources/{resource_id}/edit")
@require_permission("resources.update", allow_admin_bypass=False)
async def admin_edit_resource(
    resource_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> JSONResponse:
    """
    Edit a resource via the admin UI.

    Expects form fields:
      - name
      - description (optional)
      - mime_type (optional)
      - content

    Args:
        resource_id: Resource ID.
        request: FastAPI request containing form data.
        db: Database session.
        user: Authenticated user.

    Returns:
        JSONResponse: A JSON response indicating success or failure of the resource update operation.

    Raises:
        HTTPException: 422 when public visibility is disabled and request is team-scoped.

    Examples:
        >>> callable(admin_edit_resource)
        True
        >>> admin_edit_resource.__name__
        'admin_edit_resource'
    """
    LOGGER.debug(f"User {get_user_email(user)} is editing resource ID {resource_id}")
    form = await request.form()
    LOGGER.info(f"Form data received for resource edit: {form}")
    team_id = _form_team_id(form)
    visibility = str(form.get("visibility", "private"))
    _check_public_visibility_allowed(visibility, team_id=team_id)

    user_email = get_user_email(user)

    # Preserve existing resource's team_id when no explicit team_id is provided.
    # Without this guard, verify_team_for_user() falls back to the user's
    # personal team, silently reassigning the resource on every edit.
    if not team_id:
        existing_resource = db.get(DbResource, resource_id)
        existing_team = getattr(existing_resource, "team_id", None) if existing_resource else None
        if isinstance(existing_team, str) and existing_team:
            team_id = existing_team

    team_service = TeamManagementService(db)
    team_id = await team_service.verify_team_for_user(user_email, team_id)

    # Parse tags from comma-separated string
    tags_str = str(form.get("tags", ""))
    tags: List[str] = [tag.strip() for tag in tags_str.split(",") if tag.strip()] if tags_str else []

    try:
        mod_metadata = MetadataCapture.extract_modification_metadata(request, user, 0)
        resource = ResourceUpdate(
            uri=str(form.get("uri", "")),
            **({"name": str(form["name"])} if "name" in form else {}),
            custom_name=str(form["customName"]) if "customName" in form else None,
            description=str(form.get("description")),
            mime_type=str(form.get("mimeType")),
            content=str(form.get("content", "")),
            template=str(form.get("template")),
            tags=tags,
            visibility=visibility,
            team_id=team_id,
            owner_email=user_email,
        )
        LOGGER.info(f"ResourceUpdate object created: {resource}")
        await resource_service.update_resource(
            db,
            resource_id,
            resource,
            modified_by=mod_metadata["modified_by"],
            modified_from_ip=mod_metadata["modified_from_ip"],
            modified_via=mod_metadata["modified_via"],
            modified_user_agent=mod_metadata["modified_user_agent"],
            user_email=get_user_email(user),
        )
        return ORJSONResponse(
            content={"message": "Resource updated successfully!", "success": True},
            status_code=200,
        )
    except PermissionError as e:
        LOGGER.info(f"Permission denied for user {get_user_email(user)}: {e}")
        return ORJSONResponse(content={"message": str(e), "success": False}, status_code=403)
    except Exception as ex:
        # Roll back to discard any dirty tracked state from the failed update.
        try:
            active_transaction = db.get_transaction() if hasattr(db, "get_transaction") else None
            if db.is_active and active_transaction is not None:
                db.rollback()
        except (InvalidRequestError, OperationalError) as rollback_error:
            LOGGER.warning("Rollback failed (ignoring for SQLite compatibility): %s", rollback_error)

        if isinstance(ex, ValidationError):
            LOGGER.error("ValidationError in admin_edit_resource: %s", sanitize_validation_error_for_log(ex))
            return ORJSONResponse(content=ErrorFormatter.format_validation_error(ex), status_code=422)
        if isinstance(ex, IntegrityError):
            error_message = ErrorFormatter.format_database_error(ex)
            LOGGER.error(f"IntegrityError in admin_edit_resource: {error_message}")
            return ORJSONResponse(status_code=409, content=error_message)
        if isinstance(ex, ResourceValidationError):
            LOGGER.error(f"ResourceValidationError in admin_edit_resource: {ex}")
            return ORJSONResponse(content={"message": str(ex), "success": False}, status_code=422)
        if isinstance(ex, ResourceURIConflictError):
            LOGGER.error(f"ResourceURIConflictError in admin_edit_resource: {ex}")
            return ORJSONResponse(status_code=409, content={"message": str(ex), "success": False})
        if isinstance(ex, ContentSizeError):
            LOGGER.error(f"ContentSizeError in admin_edit_resource: {ex}")
            return ORJSONResponse(status_code=413, content={"message": str(ex), "success": False})
        if isinstance(ex, ContentTypeError):
            LOGGER.error(f"ContentTypeError in admin_edit_resource: {ex}")
            return ORJSONResponse(
                status_code=415,
                content={
                    "message": str(ex),
                    "success": False,
                    "mime_type": ex.mime_type,
                    "allowed_types": ex.allowed_types,
                },
            )
        LOGGER.exception(f"Unexpected error in admin_edit_resource: {ex}")
        return ORJSONResponse(content={"message": "An unexpected error occurred. Please try again or contact support.", "success": False}, status_code=500)


@admin_router.post("/resources/{resource_id}/delete")
@require_permission("resources.delete", allow_admin_bypass=False)
async def admin_delete_resource(resource_id: str, request: Request, db: Session = Depends(get_db), user=Depends(get_current_user_with_permissions)) -> RedirectResponse:
    """
    Delete a resource via the admin UI.

    This endpoint permanently removes a resource from the database using its resource ID.
    The operation is irreversible and should be used with caution. It requires
    user authentication and logs the deletion attempt.

    Args:
        resource_id (str): The ID of the resource to delete.
        request (Request): FastAPI request object (not used directly but required by the route signature).
        db (Session): Database session dependency.
        user (str): Authenticated user dependency.

    Returns:
        RedirectResponse: A redirect response to the resources section of the admin
        dashboard with a status code of 303 (See Other).

    Examples:
        >>> callable(admin_delete_resource)
        True
        >>> admin_delete_resource.__name__
        'admin_delete_resource'
    """

    form = await request.form()
    is_inactive_checked: str = str(form.get("is_inactive_checked", "false"))
    purge_metrics = str(form.get("purge_metrics", "false")).lower() == "true"
    user_email = get_user_email(user)
    LOGGER.debug(f"User {get_user_email(user)} is deleting resource ID {resource_id}")
    error_message = None
    try:
        await resource_service.delete_resource(
            db,  # Use endpoint's db session (user["db"] is now closed early)
            resource_id,
            user_email=user_email,
            purge_metrics=purge_metrics,
        )
    except PermissionError as e:
        LOGGER.warning(f"Permission denied for user {user_email} deleting resource {resource_id}: {e}")
        error_message = str(e)
    except Exception as e:
        LOGGER.error(f"Error deleting resource: {e}")
        error_message = "Failed to delete resource. Please try again."
    root_path = _resolve_root_path(request)
    team_id = str(form.get("team_id", "") or "")
    redirect_url = _build_admin_redirect(root_path, "resources", error=error_message, include_inactive=is_inactive_checked.lower() == "true", team_id=team_id)
    return RedirectResponse(redirect_url, status_code=303)


@admin_router.post("/resources/{resource_id}/state")
@require_permission("resources.update", allow_admin_bypass=False)
async def admin_set_resource_state(
    resource_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> RedirectResponse:
    """
    Toggle a resource's active status via the admin UI.

    This endpoint processes a form request to activate or deactivate a resource.
    It expects a form field 'activate' with value "true" to activate the resource
    or "false" to deactivate it. The endpoint handles exceptions gracefully and
    logs any errors that might occur during the status toggle operation.

    Args:
        resource_id (str): The ID of the resource whose status to toggle.
        request (Request): FastAPI request containing form data with the 'activate' field.
        db (Session): Database session dependency.
        user (str): Authenticated user dependency.

    Returns:
        RedirectResponse: A redirect to the admin dashboard resources section with a
        status code of 303 (See Other).

    Examples:
        >>> callable(admin_set_resource_state)
        True
        >>> admin_set_resource_state.__name__
        'admin_set_resource_state'
    """
    user_email = get_user_email(user)
    LOGGER.debug(f"User {user_email} is toggling resource ID {resource_id}")
    form = await request.form()
    error_message = None
    activate = str(form.get("activate", "true")).lower() == "true"
    is_inactive_checked = str(form.get("is_inactive_checked", "false"))
    try:
        await resource_service.set_resource_state(db, resource_id, activate, user_email=user_email)
    except PermissionError as e:
        LOGGER.warning(f"Permission denied for user {user_email} setting resource state {resource_id}: {e}")
        error_message = str(e)
    except Exception as e:
        LOGGER.error(f"Error setting resource state: {e}")
        error_message = "Failed to set resource state. Please try again."

    root_path = _resolve_root_path(request)
    team_id = str(form.get("team_id", "") or "")
    redirect_url = _build_admin_redirect(root_path, "resources", error=error_message, include_inactive=is_inactive_checked.lower() == "true", team_id=team_id)
    return RedirectResponse(redirect_url, status_code=303)


@admin_router.get("/prompts/{prompt_id}")
@require_permission("prompts.read", allow_admin_bypass=False)
async def admin_get_prompt(prompt_id: str, request: Request, db: Session = Depends(get_db), user=Depends(get_current_user_with_permissions)) -> Dict[str, Any]:
    """Get prompt details for the admin UI.

    Args:
        prompt_id: Prompt ID.
        request: Incoming FastAPI request (for visibility scope resolution).
        db: Database session.
        user: Authenticated user.

    Returns:
        A dictionary with prompt details.

    Raises:
        HTTPException: If the prompt is not found.
        Exception: For any other unexpected errors.

    Examples:
        >>> callable(admin_get_prompt)
        True
        >>> admin_get_prompt.__name__
        'admin_get_prompt'
    """
    LOGGER.info(f"User {get_user_email(user)} requested details for prompt ID {prompt_id}")
    try:
        auth_user_email, auth_token_teams = get_scoped_resource_access_context(request, user)
        prompt_details = await prompt_service.get_prompt_details(
            db,
            prompt_id,
            user_email=auth_user_email,
            token_teams=auth_token_teams,
        )
        prompt = PromptRead.model_validate(prompt_details)
        return prompt.model_dump(by_alias=True)
    except PromptNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        LOGGER.error(f"Error getting prompt {prompt_id}: {e}")
        raise


@admin_router.post("/prompts")
@require_permission("prompts.create", allow_admin_bypass=False)
async def admin_add_prompt(request: Request, db: Session = Depends(get_db), user=Depends(get_current_user_with_permissions)) -> JSONResponse:
    """Add a prompt via the admin UI.

    Expects form fields:
      - name
      - description (optional)
      - template
      - arguments (as a JSON string representing a list)

    Args:
        request: FastAPI request containing form data.
        db: Database session.
        user: Authenticated user.

    Returns:
        A redirect response to the admin dashboard.

    Raises:
        HTTPException: 422 when public visibility is disabled and request is team-scoped.

    Examples:
        >>> callable(admin_add_prompt)
        True
        >>> admin_add_prompt.__name__
        'admin_add_prompt'
    """
    LOGGER.debug(f"User {get_user_email(user)} is adding a new prompt")
    form = await request.form()
    team_id = _form_team_id(form)
    visibility = str(form.get("visibility", "private"))
    _check_public_visibility_allowed(visibility, team_id=team_id)
    user_email = get_user_email(user)
    team_service = TeamManagementService(db)
    team_id = await team_service.verify_team_for_user(user_email, team_id)

    # Parse tags from comma-separated string
    tags_str = str(form.get("tags", ""))
    tags: List[str] = [tag.strip() for tag in tags_str.split(",") if tag.strip()] if tags_str else []

    try:
        # Validate arguments JSON using prompt service
        arguments: List[Dict[str, Any]] = prompt_service.validate_arguments_json(args_value=form.get("arguments"), context="new prompt")
        prompt = PromptCreate(
            name=str(form["name"]),
            display_name=str(form.get("display_name") or form["name"]),
            description=str(form.get("description")),
            template=str(form["template"]),
            arguments=arguments,
            tags=tags,
            visibility=visibility,
            team_id=team_id,
            owner_email=user_email,
        )
        # Extract creation metadata
        metadata = MetadataCapture.extract_creation_metadata(request, user)

        await prompt_service.register_prompt(
            db,
            prompt,
            created_by=metadata["created_by"],
            created_from_ip=metadata["created_from_ip"],
            created_via=metadata["created_via"],
            created_user_agent=metadata["created_user_agent"],
            import_batch_id=metadata["import_batch_id"],
            federation_source=metadata["federation_source"],
            team_id=team_id,
            owner_email=user_email,
            visibility=visibility,
        )
        return ORJSONResponse(
            content={"message": "Prompt registered successfully!", "success": True},
            status_code=200,
        )
    except Exception as ex:
        if isinstance(ex, ValidationError):
            LOGGER.error("ValidationError in admin_add_prompt: %s", sanitize_validation_error_for_log(ex))
            return ORJSONResponse(content=ErrorFormatter.format_validation_error(ex), status_code=422)
        if isinstance(ex, IntegrityError):
            error_message = ErrorFormatter.format_database_error(ex)
            LOGGER.error(f"IntegrityError in admin_add_prompt: {error_message}")
            return ORJSONResponse(status_code=409, content=error_message)
        if isinstance(ex, PromptNameConflictError):
            LOGGER.error(f"PromptNameConflictError in admin_add_prompt: {ex}")
            return ORJSONResponse(status_code=409, content={"message": str(ex), "success": False})
        if isinstance(ex, PromptArgumentsJSONError):
            LOGGER.error(f"PromptArgumentsJSONError in admin_add_prompt: {ex}")
            return ORJSONResponse(
                status_code=422,
                content={
                    "message": f"Invalid JSON in {ex.field_name}: {ex.json_error}",
                    "field": ex.field_name,
                    "success": False,
                },
            )
        if isinstance(ex, ContentSizeError):
            LOGGER.error(f"ContentSizeError in admin_add_prompt: {ex}")
            return ORJSONResponse(status_code=413, content={"message": str(ex), "success": False})
        if isinstance(ex, TemplateValidationError):
            LOGGER.error(f"TemplateValidationError in admin_add_prompt: {ex}")
            return ORJSONResponse(
                status_code=400,
                content={
                    "message": f"Template validation failed: {ex.reason}",
                    "template_name": ex.template_name,
                    "reason": ex.reason,
                    "pattern": ex.pattern,
                    "success": False,
                },
            )

        LOGGER.exception(f"Unexpected error in admin_add_prompt: {ex}")
        return ORJSONResponse(content={"message": "An unexpected error occurred. Please try again or contact support.", "success": False}, status_code=500)


@admin_router.post("/prompts/{prompt_id}/edit")
@require_permission("prompts.update", allow_admin_bypass=False)
async def admin_edit_prompt(
    prompt_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> JSONResponse:
    """Edit a prompt via the admin UI.

    Expects form fields:
        - name
        - description (optional)
        - template
        - arguments (as a JSON string representing a list)

    Args:
        prompt_id: Prompt ID.
        request: FastAPI request containing form data.
        db: Database session.
        user: Authenticated user.

    Returns:
        JSONResponse: A JSON response indicating success or failure of the server update operation.

    Raises:
        HTTPException: 422 when public visibility is disabled and request is team-scoped.

    Examples:
        >>> callable(admin_edit_prompt)
        True
        >>> admin_edit_prompt.__name__
        'admin_edit_prompt'
    """
    LOGGER.debug(f"User {get_user_email(user)} is editing prompt {prompt_id}")
    form = await request.form()
    team_id = _form_team_id(form)

    visibility = str(form.get("visibility", "private"))
    _check_public_visibility_allowed(visibility, team_id=team_id)
    user_email = get_user_email(user)

    # Preserve existing prompt's team_id when no explicit team_id is provided.
    # Without this guard, verify_team_for_user() falls back to the user's
    # personal team, silently reassigning the prompt on every edit.
    if not team_id:
        existing_prompt = db.get(DbPrompt, prompt_id)
        existing_team = getattr(existing_prompt, "team_id", None) if existing_prompt else None
        if isinstance(existing_team, str) and existing_team:
            team_id = existing_team

    team_service = TeamManagementService(db)
    team_id = await team_service.verify_team_for_user(user_email, team_id)

    # Parse tags from comma-separated string
    tags_str = str(form.get("tags", ""))
    tags: List[str] = [tag.strip() for tag in tags_str.split(",") if tag.strip()] if tags_str else []
    try:
        # Validate arguments JSON using prompt service; preserve existing when field absent
        args_value = form.get("arguments")
        arguments = prompt_service.validate_arguments_json(args_value, context="prompt update") if args_value is not None else None
        mod_metadata = MetadataCapture.extract_modification_metadata(request, user, 0)
        prompt = PromptUpdate(
            custom_name=str(form.get("customName") or form.get("name")),
            display_name=str(form.get("displayName") or form.get("display_name") or form.get("name")),
            description=str(form.get("description")),
            template=str(form["template"]),
            arguments=arguments,
            tags=tags,
            visibility=visibility,
            team_id=team_id,
            owner_email=user_email,
        )
        await prompt_service.update_prompt(
            db,
            prompt_id,
            prompt,
            modified_by=mod_metadata["modified_by"],
            modified_from_ip=mod_metadata["modified_from_ip"],
            modified_via=mod_metadata["modified_via"],
            modified_user_agent=mod_metadata["modified_user_agent"],
            user_email=user_email,
        )
        return ORJSONResponse(
            content={"message": "Prompt updated successfully!", "success": True},
            status_code=200,
        )
    except PermissionError as e:
        LOGGER.info(f"Permission denied for user {get_user_email(user)}: {e}")
        return ORJSONResponse(content={"message": str(e), "success": False}, status_code=403)
    except Exception as ex:
        if isinstance(ex, ValidationError):
            LOGGER.error("ValidationError in admin_edit_prompt: %s", sanitize_validation_error_for_log(ex))
            return ORJSONResponse(content=ErrorFormatter.format_validation_error(ex), status_code=422)
        if isinstance(ex, IntegrityError):
            error_message = ErrorFormatter.format_database_error(ex)
            LOGGER.error(f"IntegrityError in admin_edit_prompt: {error_message}")
            return ORJSONResponse(status_code=409, content=error_message)
        if isinstance(ex, PromptNameConflictError):
            LOGGER.error(f"PromptNameConflictError in admin_edit_prompt: {ex}")
            return ORJSONResponse(status_code=409, content={"message": str(ex), "success": False})
        if isinstance(ex, PromptArgumentsJSONError):
            LOGGER.error(f"PromptArgumentsJSONError in admin_edit_prompt: {ex}")
            return ORJSONResponse(
                status_code=422,
                content={
                    "message": f"Invalid JSON in {ex.field_name}: {ex.json_error}",
                    "field": ex.field_name,
                    "success": False,
                },
            )
        if isinstance(ex, ContentSizeError):
            LOGGER.error(f"ContentSizeError in admin_edit_prompt: {ex}")
            return ORJSONResponse(status_code=413, content={"message": str(ex), "success": False})
        if isinstance(ex, TemplateValidationError):
            LOGGER.error(f"TemplateValidationError in admin_edit_prompt: {ex}")
            return ORJSONResponse(
                status_code=400,
                content={
                    "message": f"Template validation failed: {ex.reason}",
                    "template_name": ex.template_name,
                    "reason": ex.reason,
                    "pattern": ex.pattern,
                    "success": False,
                },
            )
        LOGGER.exception(f"Unexpected error in admin_edit_prompt: {ex}")
        return ORJSONResponse(content={"message": "An unexpected error occurred. Please try again or contact support.", "success": False}, status_code=500)


@admin_router.post("/prompts/{prompt_id}/delete")
@require_permission("prompts.delete", allow_admin_bypass=False)
async def admin_delete_prompt(prompt_id: str, request: Request, db: Session = Depends(get_db), user=Depends(get_current_user_with_permissions)) -> RedirectResponse:
    """
    Delete a prompt via the admin UI.

    This endpoint permanently deletes a prompt from the database using its ID.
    Deletion is irreversible and requires authentication. All actions are logged
    for administrative auditing.

    Args:
        prompt_id (str): The ID of the prompt to delete.
        request (Request): FastAPI request object (not used directly but required by the route signature).
        db (Session): Database session dependency.
        user (str): Authenticated user dependency.

    Returns:
        RedirectResponse: A redirect response to the prompts section of the admin
        dashboard with a status code of 303 (See Other).

    Examples:
        >>> callable(admin_delete_prompt)
        True
        >>> admin_delete_prompt.__name__
        'admin_delete_prompt'
    """
    form = await request.form()
    is_inactive_checked: str = str(form.get("is_inactive_checked", "false"))
    purge_metrics = str(form.get("purge_metrics", "false")).lower() == "true"
    user_email = get_user_email(user)
    LOGGER.info(f"User {get_user_email(user)} is deleting prompt id {prompt_id}")
    error_message = None
    try:
        await prompt_service.delete_prompt(db, prompt_id, user_email=user_email, purge_metrics=purge_metrics)
    except PermissionError as e:
        LOGGER.warning(f"Permission denied for user {user_email} deleting prompt {prompt_id}: {e}")
        error_message = str(e)
    except Exception as e:
        LOGGER.error(f"Error deleting prompt: {e}")
        error_message = "Failed to delete prompt. Please try again."
    root_path = _resolve_root_path(request)
    team_id = str(form.get("team_id", "") or "")
    redirect_url = _build_admin_redirect(root_path, "prompts", error=error_message, include_inactive=is_inactive_checked.lower() == "true", team_id=team_id)
    return RedirectResponse(redirect_url, status_code=303)


@admin_router.post("/prompts/{prompt_id}/state")
@require_permission("prompts.update", allow_admin_bypass=False)
async def admin_set_prompt_state(
    prompt_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> RedirectResponse:
    """
    Toggle a prompt's active status via the admin UI.

    This endpoint processes a form request to activate or deactivate a prompt.
    It expects a form field 'activate' with value "true" to activate the prompt
    or "false" to deactivate it. The endpoint handles exceptions gracefully and
    logs any errors that might occur during the status toggle operation.

    Args:
        prompt_id (str): The ID of the prompt whose status to toggle.
        request (Request): FastAPI request containing form data with the 'activate' field.
        db (Session): Database session dependency.
        user (str): Authenticated user dependency.

    Returns:
        RedirectResponse: A redirect to the admin dashboard prompts section with a
        status code of 303 (See Other).

    Examples:
        >>> callable(admin_set_prompt_state)
        True
        >>> admin_set_prompt_state.__name__
        'admin_set_prompt_state'
    """
    user_email = get_user_email(user)
    LOGGER.debug(f"User {user_email} is toggling prompt ID {prompt_id}")
    error_message = None
    form = await request.form()
    activate: bool = str(form.get("activate", "true")).lower() == "true"
    is_inactive_checked: str = str(form.get("is_inactive_checked", "false"))
    try:
        await prompt_service.set_prompt_state(db, prompt_id, activate, user_email=user_email)
    except PermissionError as e:
        LOGGER.warning(f"Permission denied for user {user_email} setting prompt state {prompt_id}: {e}")
        error_message = str(e)
    except Exception as e:
        LOGGER.error(f"Error setting prompt state: {e}")
        error_message = "Failed to set prompt state. Please try again."

    root_path = _resolve_root_path(request)
    team_id = str(form.get("team_id", "") or "")
    redirect_url = _build_admin_redirect(root_path, "prompts", error=error_message, include_inactive=is_inactive_checked.lower() == "true", team_id=team_id)
    return RedirectResponse(redirect_url, status_code=303)


async def _require_unrestricted_root_admin(request: Optional[Request], user: Any, db: Session) -> None:
    """Require unrestricted platform-admin authority for global roots."""
    if not await is_unrestricted_platform_admin(request, user, db):
        raise HTTPException(status_code=403, detail=_ACCESS_DENIED_MSG)


@admin_router.get("/roots/search", response_class=JSONResponse)
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


@admin_router.get("/roots/export")
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


@admin_router.get("/roots/{uri:path}")
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


@admin_router.post("/roots")
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


@admin_router.post("/roots/{uri:path}/update")
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


@admin_router.post("/roots/{uri:path}/delete")
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


@admin_router.post("/gateways/test", response_model=GatewayTestResponse)
@require_permission("gateways.read", allow_admin_bypass=False)
async def admin_test_gateway(
    request: GatewayTestRequest, team_id: Optional[str] = Depends(_validated_team_id_param), user=Depends(get_current_user_with_permissions), db: Session = Depends(get_db)
) -> GatewayTestResponse:
    """
    Test a gateway by sending a request to its URL.
    This endpoint allows administrators to test the connectivity and response

    Args:
        request (GatewayTestRequest): The request object containing the gateway URL and request details.
        team_id (Optional[str]): Optional team ID for team-specific gateways.
        user (str): Authenticated user dependency.
        db (Session): Database session dependency.

    Returns:
        GatewayTestResponse: The response from the gateway, including status code, latency, and body

    Examples:
        >>> callable(admin_test_gateway)
        True
        >>> admin_test_gateway.__name__
        'admin_test_gateway'
    """
    # Reject cross-team access: token_teams=None means admin bypass; a list means the
    # caller is scoped to those teams only. A caller-supplied team_id outside that list
    # would allow enumerating other teams' registered gateway hostnames (SSRF allowlist).
    if team_id is not None:
        token_teams = user.get("token_teams") if isinstance(user, dict) else None
        if token_teams is not None and team_id not in token_teams:
            raise HTTPException(status_code=403, detail="Access to requested team is not permitted")
    return await test_gateway_connectivity(request, team_id, user, db)


@admin_router.get("/sections/resources")
@require_permission("resources.read", allow_admin_bypass=False)
async def get_resources_section(
    request: Request,
    team_id: Optional[str] = None,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    """Get resources data filtered by team.

    Args:
        request: FastAPI request object
        team_id: Optional team ID to filter by
        db: Database session
        user: Current authenticated user context

    Returns:
        JSONResponse: Resources data with team filtering applied
    """
    try:
        local_resource_service = ResourceService()
        user_email, token_teams = get_scoped_resource_access_context(request, user)
        LOGGER.debug(f"User {user_email} requesting resources section with team_id={team_id}, token_teams={token_teams}")

        # Filter in the service, not here: a strict team_id comparison would drop
        # globally-public rows owned by other teams.
        resources_result = await local_resource_service.list_resources(db, include_inactive=True, user_email=user_email, token_teams=token_teams, team_id=team_id)
        if isinstance(resources_result, tuple):
            resources_list = resources_result[0]
        else:
            resources_list = resources_result

        # Convert to JSON-serializable format
        resources = []
        for resource in resources_list:
            resource_dict = (
                resource.model_dump(by_alias=True)
                if hasattr(resource, "model_dump")
                else {
                    "id": resource.id,
                    "name": resource.name,
                    "description": resource.description,
                    "uri": resource.uri,
                    "tags": resource.tags or [],
                    "isActive": resource.enabled,
                    "team_id": getattr(resource, "team_id", None),
                    "visibility": getattr(resource, "visibility", "private"),
                }
            )
            resources.append(resource_dict)

        return ORJSONResponse(content={"resources": resources, "team_id": team_id})

    except Exception as e:
        LOGGER.error(f"Error loading resources section: {e}")
        return ORJSONResponse(content={"error": str(e)}, status_code=500)


@admin_router.get("/sections/prompts")
@require_permission("prompts.read", allow_admin_bypass=False)
async def get_prompts_section(
    request: Request,
    team_id: Optional[str] = None,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    """Get prompts data filtered by team.

    Args:
        request: FastAPI request object
        team_id: Optional team ID to filter by
        db: Database session
        user: Current authenticated user context

    Returns:
        JSONResponse: Prompts data with team filtering applied
    """
    try:
        local_prompt_service = PromptService()
        user_email, token_teams = get_scoped_resource_access_context(request, user)
        LOGGER.debug(f"User {user_email} requesting prompts section with team_id={team_id}, token_teams={token_teams}")

        # Filter in the service, not here: a strict team_id comparison would drop
        # globally-public rows owned by other teams.
        prompts_result = await local_prompt_service.list_prompts(db, include_inactive=True, user_email=user_email, token_teams=token_teams, team_id=team_id)
        if isinstance(prompts_result, tuple):
            prompts_list = prompts_result[0]
        else:
            prompts_list = prompts_result

        # Convert to JSON-serializable format
        prompts = []
        for prompt in prompts_list:
            prompt_dict = (
                prompt.model_dump(by_alias=True)
                if hasattr(prompt, "model_dump")
                else {
                    "id": prompt.id,
                    "name": prompt.name,
                    "description": prompt.description,
                    "arguments": prompt.arguments or [],
                    "tags": prompt.tags or [],
                    # Prompt enabled/disabled state is stored on the prompt as `enabled`.
                    "isActive": getattr(prompt, "enabled", False),
                    "team_id": getattr(prompt, "team_id", None),
                    "visibility": getattr(prompt, "visibility", "private"),
                }
            )
            prompts.append(prompt_dict)

        return ORJSONResponse(content={"prompts": prompts, "team_id": team_id})

    except Exception as e:
        LOGGER.error(f"Error loading prompts section: {e}")
        return ORJSONResponse(content={"error": str(e)}, status_code=500)


@admin_router.get("/sections/servers")
@require_permission("servers.read", allow_admin_bypass=False)
async def get_servers_section(
    request: Request,
    team_id: Optional[str] = None,
    include_inactive: bool = False,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    """Get servers data filtered by team.

    Args:
        request: FastAPI request, used to derive the caller's Layer-1 visibility scope
        team_id: Optional team ID to filter by
        include_inactive: Whether to include inactive servers
        db: Database session
        user: Current authenticated user context

    Returns:
        JSONResponse: Servers data with team filtering applied
    """
    try:
        local_server_service = ServerService()
        user_email, token_teams = get_scoped_resource_access_context(request, user)
        LOGGER.debug(f"User {user_email} requesting servers section with team_id={team_id}, include_inactive={include_inactive}, token_teams={token_teams}")

        # Filter in the service, not here: a strict team_id comparison would drop
        # globally-public rows owned by other teams.
        servers_result = await local_server_service.list_servers(db, include_inactive=include_inactive, user_email=user_email, token_teams=token_teams, team_id=team_id)
        if isinstance(servers_result, tuple):
            servers_list = servers_result[0]
        else:
            servers_list = servers_result

        # Convert to JSON-serializable format
        servers = []
        for server in servers_list:
            server_dict = (
                server.model_dump(by_alias=True)
                if hasattr(server, "model_dump")
                else {
                    "id": server.id,
                    "name": server.name,
                    "description": server.description,
                    "tags": server.tags or [],
                    "isActive": server.enabled,
                    "team_id": getattr(server, "team_id", None),
                    "visibility": getattr(server, "visibility", "private"),
                }
            )
            servers.append(server_dict)

        return ORJSONResponse(content={"servers": servers, "team_id": team_id})

    except Exception as e:
        LOGGER.error(f"Error loading servers section: {e}")
        return ORJSONResponse(content={"error": str(e)}, status_code=500)


@admin_router.get("/sections/gateways")
@require_permission("gateways.read", allow_admin_bypass=False)
async def get_gateways_section(
    request: Request,
    team_id: Optional[str] = None,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
):
    """Get gateways data filtered by team.

    Args:
        request: FastAPI request, used to derive the caller's Layer-1 visibility scope
        team_id: Optional team ID to filter by
        db: Database session
        user: Current authenticated user context

    Returns:
        JSONResponse: Gateways data with team filtering applied
    """
    try:
        local_gateway_service = GatewayService()
        user_email, token_teams = get_scoped_resource_access_context(request, user)

        # Filter in the service, not here: a strict team_id comparison would drop
        # globally-public rows owned by other teams.
        gateways_list, _ = await local_gateway_service.list_gateways(db, include_inactive=True, user_email=user_email, token_teams=token_teams, team_id=team_id)

        # Convert to JSON-serializable format
        gateways = []
        for gateway in gateways_list:
            if hasattr(gateway, "model_dump"):
                # Get dict and serialize datetime objects
                gateway_dict = gateway.model_dump(by_alias=True)
                # Convert datetime objects to strings
                for key, value in gateway_dict.items():
                    gateway_dict[key] = serialize_datetime(value)
            else:
                # Parse URL to extract host and port
                parsed_url = urllib.parse.urlparse(gateway.url) if gateway.url else None
                gateway_dict = {
                    "id": gateway.id,
                    "name": gateway.name,
                    "host": parsed_url.hostname if parsed_url else "",
                    "port": parsed_url.port if parsed_url else 80,
                    "tags": gateway.tags or [],
                    "isActive": getattr(gateway, "enabled", False),
                    "team_id": getattr(gateway, "team_id", None),
                    "visibility": getattr(gateway, "visibility", "private"),
                    "created_at": serialize_datetime(getattr(gateway, "created_at", None)),
                    "updated_at": serialize_datetime(getattr(gateway, "updated_at", None)),
                }
            gateways.append(gateway_dict)

        return ORJSONResponse(content={"gateways": gateways, "team_id": team_id})

    except Exception as e:
        LOGGER.error(f"Error loading gateways section: {e}")
        return ORJSONResponse(content={"error": str(e)}, status_code=500)


# FastAPI >= 0.141 include_router() mounts a lazy _IncludedRouter, which would
# break the flat route list on admin_router; the observability router mirrors
# admin_router's prefix, tags, and CSRF dependency, so extending is equivalent.
admin_router.routes.extend(_observability_router.routes)
admin_router.routes.extend(_mcp_registry_router.routes)
admin_router.routes.extend(_plugins_router.routes)
admin_router.routes.extend(_performance_router.routes)
admin_router.routes.extend(_system_router.routes)
admin_router.routes.extend(_events_router.routes)
admin_router.routes.extend(_metrics_router.routes)
admin_router.routes.extend(_team_join_router.routes)
admin_router.routes.extend(_tags_router.routes)
admin_router.routes.extend(_tools_import_router.routes)
admin_router.routes.extend(_logs_router.routes)
admin_router.routes.extend(_export_import_router.routes)
admin_router.routes.extend(_a2a_router.routes)
admin_router.routes.extend(_grpc_router.routes)
