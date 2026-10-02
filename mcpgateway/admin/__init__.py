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
from datetime import datetime, timedelta, timezone
import html
import logging
import time
from typing import Any
from typing import cast as typing_cast
from typing import Dict, Optional
import uuid

# Third-Party
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import SecretStr, ValidationError
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

# First-Party
from mcpgateway import __version__
from mcpgateway import version as version_module

# Authentication and password-related imports
from mcpgateway.auth import get_current_user as get_current_user
from mcpgateway.auth_user_helpers import is_passwordless_user as is_passwordless_user

# Re-export canonical get_user_email from auth_context for backward compatibility.
from mcpgateway.auth_context import (
    configuration_export_includes_roots as configuration_export_includes_roots,
    extract_token_team_ids as extract_token_team_ids,
    get_scoped_resource_access_context,
    get_token_teams_from_request as get_token_teams_from_request,
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
    QueryRelationship as QueryRelationship,
    QueryRenderMode as QueryRenderMode,
    QueryRenderModeControls as QueryRenderModeControls,
    QueryRenderModeUserSelector as QueryRenderModeUserSelector,
    QueryTagsFilter,
    QueryVisibility as QueryVisibility,
    QueryVisibilityCompact as QueryVisibilityCompact,
)
from mcpgateway.common.validators import SecurityValidator as SecurityValidator
from mcpgateway.config import settings, UI_HIDABLE_HEADER_ITEMS as UI_HIDABLE_HEADER_ITEMS, UI_HIDABLE_SECTIONS as UI_HIDABLE_SECTIONS, UI_HIDE_SECTION_ALIASES as UI_HIDE_SECTION_ALIASES
from mcpgateway.db import A2AAgent as DbA2AAgent
from mcpgateway.db import EmailApiToken as EmailApiToken, EmailTeam as EmailTeam, EmailUser
from mcpgateway.db import Gateway as DbGateway
from mcpgateway.db import get_db, GlobalConfig
from mcpgateway.db import Prompt as DbPrompt
from mcpgateway.db import Resource as DbResource
from mcpgateway.db import Server as DbServer
from mcpgateway.db import SessionLocal as SessionLocal
from mcpgateway.db import Tool as DbTool
from mcpgateway.db import utc_now as utc_now
from mcpgateway.middleware.rbac import (
    _ACCESS_DENIED_MSG,
    get_current_user_with_permissions,
    require_admin_permission as require_admin_permission,
    require_any_permission as require_any_permission,
    require_permission,
)
from mcpgateway.routers.email_auth import create_access_token as create_access_token
from mcpgateway.schemas import (
    _encode_auth_headers_list as _encode_auth_headers_list,
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
    GatewayCreate as GatewayCreate,
    GatewayOwnershipTransferRequest as GatewayOwnershipTransferRequest,
    GatewayRead as GatewayRead,
    GatewayTestRequest as GatewayTestRequest,
    GatewayTestResponse as GatewayTestResponse,
    GatewayUpdate as GatewayUpdate,
    GlobalConfigRead,
    GlobalConfigUpdate,
    PaginatedResponse as PaginatedResponse,
    PaginationMeta as PaginationMeta,
    PluginDetail as PluginDetail,
    PluginListResponse as PluginListResponse,
    PluginModeUpdateRequest as PluginModeUpdateRequest,
    PluginModeUpdateResponse as PluginModeUpdateResponse,
    PluginStatsResponse as PluginStatsResponse,
    PluginToggleRequest as PluginToggleRequest,
    PluginToggleResponse as PluginToggleResponse,
    PromptCreate as PromptCreate,
    PromptMetrics as PromptMetrics,
    PromptRead as PromptRead,
    PromptUpdate as PromptUpdate,
    ResourceCreate as ResourceCreate,
    ResourceMetrics as ResourceMetrics,
    ResourceUpdate as ResourceUpdate,
    ServerCreate as ServerCreate,
    ServerMetrics as ServerMetrics,
    ServerRead as ServerRead,
    ServerUpdate as ServerUpdate,
    ToolCreate as ToolCreate,
    ToolMetrics as ToolMetrics,
    ToolRead as ToolRead,
    ToolUpdate as ToolUpdate,
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
from mcpgateway.services.argon2_service import Argon2PasswordService as Argon2PasswordService
from mcpgateway.services.audit_trail_service import get_audit_trail_service as get_audit_trail_service
from mcpgateway.services.catalog_service import catalog_service, CatalogRegistrationPermissionError as CatalogRegistrationPermissionError
from mcpgateway.services.content_security import ContentSizeError as ContentSizeError, ContentTypeError as ContentTypeError, TemplateValidationError as TemplateValidationError
from mcpgateway.services.csrf_service import get_csrf_service as get_csrf_service
from mcpgateway.services.email_auth_service import AuthenticationError as AuthenticationError, EmailAuthService as EmailAuthService, PasswordValidationError as PasswordValidationError
from mcpgateway.services.encryption_service import get_encryption_service as get_encryption_service
from mcpgateway.services.export_service import ExportError as ExportError, ExportService as ExportService
from mcpgateway.services.gateway_service import (
    gateway_capability_loaders as gateway_capability_loaders,
    GatewayConnectionError as GatewayConnectionError,
    GatewayCredentialError as GatewayCredentialError,
    GatewayDuplicateConflictError as GatewayDuplicateConflictError,
    GatewayLookupConflictError as GatewayLookupConflictError,
    GatewayNameConflictError as GatewayNameConflictError,
    GatewayNotFoundError as GatewayNotFoundError,
    GatewayToolNameConflictError as GatewayToolNameConflictError,
    GatewayService as GatewayService,
    test_gateway_connectivity as test_gateway_connectivity,
)
from mcpgateway.services.import_service import ConflictStrategy as ConflictStrategy
from mcpgateway.services.import_service import ImportService as ImportService, ImportValidationError as ImportValidationError
from mcpgateway.services.logging_service import LoggingService
from mcpgateway.services.openapi_service import fetch_and_extract_schemas as fetch_and_extract_schemas
from mcpgateway.services.password_policy_service import PasswordPolicyService
from mcpgateway.services.performance_service import get_performance_service as get_performance_service
from mcpgateway.services.permission_service import PermissionService
from mcpgateway.services.plugin_service import get_plugin_service, sync_plugin_service_from_runtime
from mcpgateway.services.prompt_service import (
    PromptArgumentsJSONError as PromptArgumentsJSONError,
    PromptNameConflictError as PromptNameConflictError,
    PromptNotFoundError as PromptNotFoundError,
    PromptService,
)
from mcpgateway.services.resource_service import (
    ResourceError as ResourceError,
    ResourceNotFoundError as ResourceNotFoundError,
    ResourceService,
    ResourceURIConflictError as ResourceURIConflictError,
    ResourceValidationError as ResourceValidationError,
)
from mcpgateway.services.root_service import (
    RootService as RootService,
    RootServiceError as RootServiceError,
    RootServiceNotFoundError as RootServiceNotFoundError,
    RootServiceValidationError as RootServiceValidationError,
)
from mcpgateway.services.server_service import (
    ServerError as ServerError,
    ServerLockConflictError as ServerLockConflictError,
    ServerNameConflictError as ServerNameConflictError,
    ServerNotFoundError as ServerNotFoundError,
    ServerService,
)
from mcpgateway.services.structured_logger import get_structured_logger as get_structured_logger
from mcpgateway.services.tag_service import TagService as TagService
from mcpgateway.services.team_management_service import JoinRequestNotFoundError as JoinRequestNotFoundError, TeamManagementService, UNSET as UNSET
from mcpgateway.services.token_catalog_service import TokenCatalogService as TokenCatalogService
from mcpgateway.services.tool_service import (
    ToolError as ToolError,
    ToolLockConflictError as ToolLockConflictError,
    ToolNameConflictError as ToolNameConflictError,
    ToolNotFoundError as ToolNotFoundError,
    ToolService,
)
from mcpgateway.utils.create_jwt_token import create_jwt_token, get_jwt_token
from mcpgateway.utils.error_formatter import ErrorFormatter as ErrorFormatter, sanitize_validation_error_for_log as sanitize_validation_error_for_log
from mcpgateway.utils.log_sanitizer import sanitize_for_log as sanitize_for_log
from mcpgateway.utils.metadata_capture import MetadataCapture as MetadataCapture
from mcpgateway.utils.oauth_resource import parse_oauth_resource_form as parse_oauth_resource_form
from mcpgateway.utils.orjson_response import ORJSONResponse as ORJSONResponse
from mcpgateway.utils.pagination import paginate_query as paginate_query
from mcpgateway.utils.passthrough_headers import PassthroughHeadersError
from mcpgateway.utils.paths import is_path_within as is_path_within, open_confined as open_confined
from mcpgateway.utils.paths import resolve_root_path as _resolve_root_path
from mcpgateway.utils.security_cookies import clear_auth_cookie as clear_auth_cookie, CookieTooLargeError as CookieTooLargeError, set_auth_cookie
from mcpgateway.utils.services_auth import encode_auth as encode_auth
from mcpgateway.utils.sqlalchemy_modifier import json_contains_tag_expr as json_contains_tag_expr
from mcpgateway.utils.validate_signature import sign_data as sign_data
from mcpgateway.utils.origin import is_allowed_redirect as is_allowed_redirect, normalize_origin_parts as normalize_origin_parts, origin_from_url as origin_from_url
from mcpgateway.utils.verify_credentials import verify_jwt_token_cached

# Re-export cross-cutting helpers from the focused submodules extracted out of
# this package so existing ``from mcpgateway.admin import X`` sites (and test
# patch targets) keep working unchanged.
from mcpgateway.admin.assets import _bundle_css_cache as _bundle_css_cache, _bundle_js_cache as _bundle_js_cache, get_bundle_css_files, get_bundle_js_filename, load_sri_hashes  # noqa: PLC2701
from mcpgateway.admin.common import (  # noqa: PLC2701
    _adjust_pagination_for_conversion_failures as _adjust_pagination_for_conversion_failures,
    _apply_tag_filter_groups as _apply_tag_filter_groups,
    _assemble_oauth_config_from_fields as _assemble_oauth_config_from_fields,
    _build_admin_redirect as _build_admin_redirect,
    _build_search_response,
    _check_public_visibility_allowed as _check_public_visibility_allowed,
    _escape_like as _escape_like,
    _form_team_id as _form_team_id,
    _get_user_team_ids,
    _get_user_team_roles as _get_user_team_roles,
    _is_explicit_token_team_scope as _is_explicit_token_team_scope,
    _like_contains as _like_contains,
    _merge_select_all_ids as _merge_select_all_ids,
    _normalize_int_query,
    _normalize_search_query,
    _normalize_tags_query,
    _normalize_team_id as _normalize_team_id,
    _owner_access_condition as _owner_access_condition,
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
    serialize_datetime as serialize_datetime,
    server_service,
    tool_service,
)
from mcpgateway.admin.security import (  # noqa: PLC2701
    _admin_cookie_path as _admin_cookie_path,
    _clear_admin_csrf_cookie as _clear_admin_csrf_cookie,
    _request_origin_matches as _request_origin_matches,
    _set_admin_csrf_cookie,
    ADMIN_CSRF_COOKIE_NAME as ADMIN_CSRF_COOKIE_NAME,
    ADMIN_CSRF_FORM_FIELD as ADMIN_CSRF_FORM_FIELD,
    ADMIN_CSRF_HEADER_NAME as ADMIN_CSRF_HEADER_NAME,
    enforce_admin_csrf,
    get_client_ip as get_client_ip,
    get_user_agent as get_user_agent,
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
from mcpgateway.admin.tools import (  # noqa: PLC2701
    admin_list_tools as admin_list_tools,
    admin_tools_partial_html as admin_tools_partial_html,
    admin_tool_ops_partial as admin_tool_ops_partial,
    admin_get_all_tool_ids as admin_get_all_tool_ids,
    admin_search_tools as admin_search_tools,
    admin_get_tool as admin_get_tool,
    _build_auth_obj_from_form as _build_auth_obj_from_form,
    admin_add_tool as admin_add_tool,
    admin_edit_tool as admin_edit_tool,
    generate_schemas_from_openapi as generate_schemas_from_openapi,
    admin_delete_tool as admin_delete_tool,
    admin_set_tool_state as admin_set_tool_state,
    router as _tools_router,
)
from mcpgateway.admin.servers import (  # noqa: PLC2701
    admin_list_servers as admin_list_servers,
    admin_servers_partial_html as admin_servers_partial_html,
    admin_get_server as admin_get_server,
    admin_add_server as admin_add_server,
    admin_edit_server as admin_edit_server,
    admin_set_server_state as admin_set_server_state,
    admin_delete_server as admin_delete_server,
    admin_get_all_server_ids as admin_get_all_server_ids,
    admin_search_servers as admin_search_servers,
    router as _servers_router,
)
from mcpgateway.admin.resources import (  # noqa: PLC2701
    admin_list_resources as admin_list_resources,
    admin_resources_partial_html as admin_resources_partial_html,
    admin_get_all_resource_ids as admin_get_all_resource_ids,
    admin_search_resources as admin_search_resources,
    admin_test_resource as admin_test_resource,
    admin_get_resource as admin_get_resource,
    admin_add_resource as admin_add_resource,
    admin_edit_resource as admin_edit_resource,
    admin_delete_resource as admin_delete_resource,
    admin_set_resource_state as admin_set_resource_state,
    router as _resources_router,
)
from mcpgateway.admin.prompts import (  # noqa: PLC2701
    admin_list_prompts as admin_list_prompts,
    admin_prompts_partial_html as admin_prompts_partial_html,
    admin_get_all_prompt_ids as admin_get_all_prompt_ids,
    admin_search_prompts as admin_search_prompts,
    admin_get_prompt as admin_get_prompt,
    admin_add_prompt as admin_add_prompt,
    admin_edit_prompt as admin_edit_prompt,
    admin_delete_prompt as admin_delete_prompt,
    admin_set_prompt_state as admin_set_prompt_state,
    router as _prompts_router,
)
from mcpgateway.admin.gateways import (  # noqa: PLC2701
    admin_list_gateways as admin_list_gateways,
    admin_set_gateway_state as admin_set_gateway_state,
    admin_gateways_partial_html as admin_gateways_partial_html,
    admin_get_all_gateways_ids as admin_get_all_gateways_ids,
    admin_search_gateways as admin_search_gateways,
    admin_get_gateway as admin_get_gateway,
    admin_discover_oauth as admin_discover_oauth,
    admin_add_gateway as admin_add_gateway,
    admin_update_gateway_rest as admin_update_gateway_rest,
    admin_delete_gateway_rest as admin_delete_gateway_rest,
    transfer_gateway_ownership as transfer_gateway_ownership,
    admin_edit_gateway as admin_edit_gateway,
    admin_delete_gateway as admin_delete_gateway,
    admin_test_gateway as admin_test_gateway,
    _parse_gateway_data_from_request as _parse_gateway_data_from_request,
    _gateway_result_status as _gateway_result_status,
    _gateway_result_payload as _gateway_result_payload,
    router as _gateways_router,
)
from mcpgateway.admin.auth import (  # noqa: PLC2701
    _admin_logout as _admin_logout,
    admin_login_page as admin_login_page,
    admin_login_handler as admin_login_handler,
    admin_forgot_password_page as admin_forgot_password_page,
    admin_forgot_password_handler as admin_forgot_password_handler,
    admin_reset_password_page as admin_reset_password_page,
    admin_reset_password_handler as admin_reset_password_handler,
    admin_logout_get as admin_logout_get,
    admin_logout_post as admin_logout_post,
    change_password_required_page as change_password_required_page,
    change_password_required_handler as change_password_required_handler,
    router as _auth_router,
)
from mcpgateway.admin.tokens import (  # noqa: PLC2701
    admin_tokens_partial_html as admin_tokens_partial_html,
    admin_search_tokens as admin_search_tokens,
    admin_revoke_token as admin_revoke_token,
    router as _tokens_router,
)
from mcpgateway.admin.roots import (  # noqa: PLC2701
    admin_search_roots as admin_search_roots,
    admin_export_root as admin_export_root,
    admin_get_root as admin_get_root,
    admin_add_root as admin_add_root,
    admin_update_root as admin_update_root,
    admin_delete_root as admin_delete_root,
    router as _roots_router,
)
from mcpgateway.admin.sections import (  # noqa: PLC2701
    get_resources_section as get_resources_section,
    get_prompts_section as get_prompts_section,
    get_servers_section as get_servers_section,
    get_gateways_section as get_gateways_section,
    router as _sections_router,
)
from mcpgateway.admin.users import (  # noqa: PLC2701
    _render_user_card_html as _render_user_card_html,
    admin_list_users as admin_list_users,
    admin_users_partial_html as admin_users_partial_html,
    admin_team_members_partial_html as admin_team_members_partial_html,
    admin_team_non_members_partial_html as admin_team_non_members_partial_html,
    admin_search_users as admin_search_users,
    admin_create_user as admin_create_user,
    admin_get_user_edit as admin_get_user_edit,
    admin_update_user as admin_update_user,
    admin_activate_user as admin_activate_user,
    admin_deactivate_user as admin_deactivate_user,
    admin_delete_user as admin_delete_user,
    admin_unlock_user as admin_unlock_user,
    admin_force_password_change as admin_force_password_change,
    validate_password_strength as validate_password_strength,
    router as _users_router,
)
from mcpgateway.admin.teams import (  # noqa: PLC2701
    _generate_unified_teams_view as _generate_unified_teams_view,
    _parse_form_max_members as _parse_form_max_members,
    admin_get_all_team_ids as admin_get_all_team_ids,
    admin_search_teams as admin_search_teams,
    admin_teams_partial_html as admin_teams_partial_html,
    admin_list_teams as admin_list_teams,
    admin_create_team as admin_create_team,
    admin_view_team_members as admin_view_team_members,
    admin_add_team_members_view as admin_add_team_members_view,
    admin_get_team_edit as admin_get_team_edit,
    admin_update_team as admin_update_team,
    admin_delete_team as admin_delete_team,
    admin_add_team_members as admin_add_team_members,
    admin_update_team_member_role as admin_update_team_member_role,
    admin_remove_team_member as admin_remove_team_member,
    admin_leave_team as admin_leave_team,
    router as _teams_router,
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
admin_router.routes.extend(_teams_router.routes)
admin_router.routes.extend(_users_router.routes)
admin_router.routes.extend(_sections_router.routes)
admin_router.routes.extend(_roots_router.routes)
admin_router.routes.extend(_tokens_router.routes)
admin_router.routes.extend(_auth_router.routes)
admin_router.routes.extend(_gateways_router.routes)
admin_router.routes.extend(_prompts_router.routes)
admin_router.routes.extend(_resources_router.routes)
admin_router.routes.extend(_servers_router.routes)
admin_router.routes.extend(_tools_router.routes)
