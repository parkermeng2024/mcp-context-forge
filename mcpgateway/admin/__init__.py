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
import logging
from typing import Optional

# Third-Party
from fastapi import APIRouter, Depends, HTTPException as HTTPException  # noqa: F401 — re-exported for tests

# First-Party
from mcpgateway import __version__ as __version__  # noqa: F401
from mcpgateway import version as version_module  # noqa: F401 — re-exported for tests

# Authentication and password-related imports
from mcpgateway.auth import get_current_user as get_current_user
from mcpgateway.auth_user_helpers import is_passwordless_user as is_passwordless_user

# Re-export canonical get_user_email from auth_context for backward compatibility.
from mcpgateway.auth_context import (
    configuration_export_includes_roots as configuration_export_includes_roots,
    extract_token_team_ids as extract_token_team_ids,
    get_scoped_resource_access_context as get_scoped_resource_access_context,
    get_token_teams_from_request as get_token_teams_from_request,
    get_user_email as get_user_email,
    import_envelope_includes_roots as import_envelope_includes_roots,
    is_unrestricted_platform_admin as is_unrestricted_platform_admin,
    selective_selection_includes_roots as selective_selection_includes_roots,
)
from mcpgateway.cache.a2a_stats_cache import a2a_stats_cache as a2a_stats_cache
from mcpgateway.cache.global_config_cache import global_config_cache as global_config_cache
from mcpgateway.common.models import LogLevel as LogLevel
from mcpgateway.common.query_params import (
    QueryEntityType as QueryEntityType,
    QueryEntityTypes as QueryEntityTypes,
    QueryExportFormatAliased as QueryExportFormatAliased,
    QueryGatewayIdList as QueryGatewayIdList,
    QueryPeriodType as QueryPeriodType,
    QueryRelationship as QueryRelationship,
    QueryRenderMode as QueryRenderMode,
    QueryRenderModeControls as QueryRenderModeControls,
    QueryRenderModeUserSelector as QueryRenderModeUserSelector,
    QueryTagsFilter as QueryTagsFilter,
    QueryVisibility as QueryVisibility,
    QueryVisibilityCompact as QueryVisibilityCompact,
)
from mcpgateway.common.validators import SecurityValidator as SecurityValidator
from mcpgateway.config import settings as settings, UI_HIDABLE_HEADER_ITEMS as UI_HIDABLE_HEADER_ITEMS, UI_HIDABLE_SECTIONS as UI_HIDABLE_SECTIONS, UI_HIDE_SECTION_ALIASES as UI_HIDE_SECTION_ALIASES
from mcpgateway.db import EmailApiToken as EmailApiToken, EmailTeam as EmailTeam, EmailUser as EmailUser
from mcpgateway.db import get_db as get_db, GlobalConfig as GlobalConfig
from mcpgateway.db import SessionLocal as SessionLocal
from mcpgateway.db import utc_now as utc_now
from mcpgateway.middleware.rbac import (
    _ACCESS_DENIED_MSG as _ACCESS_DENIED_MSG,
    get_current_user_with_permissions as get_current_user_with_permissions,
    require_admin_permission as require_admin_permission,
    require_any_permission as require_any_permission,
    require_permission as require_permission,
)
from mcpgateway.routers.email_auth import create_access_token as create_access_token
from mcpgateway.schemas import (
    _encode_auth_headers_list as _encode_auth_headers_list,
    A2AAgentCreate as A2AAgentCreate,
    A2AAgentRead as A2AAgentRead,
    A2AAgentUpdate as A2AAgentUpdate,
    CatalogBulkRegisterRequest as CatalogBulkRegisterRequest,
    CatalogBulkRegisterResponse as CatalogBulkRegisterResponse,
    CatalogListRequest as CatalogListRequest,
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
    GlobalConfigRead as GlobalConfigRead,
    GlobalConfigUpdate as GlobalConfigUpdate,
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
from mcpgateway.services.catalog_service import catalog_service as catalog_service, CatalogRegistrationPermissionError as CatalogRegistrationPermissionError
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
from mcpgateway.services.password_policy_service import PasswordPolicyService as PasswordPolicyService
from mcpgateway.services.performance_service import get_performance_service as get_performance_service
from mcpgateway.services.permission_service import PermissionService as PermissionService
from mcpgateway.services.plugin_service import get_plugin_service as get_plugin_service, sync_plugin_service_from_runtime as sync_plugin_service_from_runtime
from mcpgateway.services.prompt_service import (
    PromptArgumentsJSONError as PromptArgumentsJSONError,
    PromptNameConflictError as PromptNameConflictError,
    PromptNotFoundError as PromptNotFoundError,
    PromptService as PromptService,
)
from mcpgateway.services.resource_service import (
    ResourceError as ResourceError,
    ResourceNotFoundError as ResourceNotFoundError,
    ResourceService as ResourceService,
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
    ServerService as ServerService,
)
from mcpgateway.services.structured_logger import get_structured_logger as get_structured_logger
from mcpgateway.services.tag_service import TagService as TagService
from mcpgateway.services.team_management_service import JoinRequestNotFoundError as JoinRequestNotFoundError, TeamManagementService as TeamManagementService, UNSET as UNSET
from mcpgateway.services.token_catalog_service import TokenCatalogService as TokenCatalogService
from mcpgateway.services.tool_service import (
    ToolError as ToolError,
    ToolLockConflictError as ToolLockConflictError,
    ToolNameConflictError as ToolNameConflictError,
    ToolNotFoundError as ToolNotFoundError,
    ToolService as ToolService,
)
from mcpgateway.utils.create_jwt_token import create_jwt_token as create_jwt_token, get_jwt_token as get_jwt_token
from mcpgateway.utils.error_formatter import ErrorFormatter as ErrorFormatter, sanitize_validation_error_for_log as sanitize_validation_error_for_log
from mcpgateway.utils.log_sanitizer import sanitize_for_log as sanitize_for_log
from mcpgateway.utils.metadata_capture import MetadataCapture as MetadataCapture
from mcpgateway.utils.oauth_resource import parse_oauth_resource_form as parse_oauth_resource_form
from mcpgateway.utils.orjson_response import ORJSONResponse as ORJSONResponse
from mcpgateway.utils.pagination import paginate_query as paginate_query
from mcpgateway.utils.passthrough_headers import PassthroughHeadersError as PassthroughHeadersError
from mcpgateway.utils.paths import is_path_within as is_path_within, open_confined as open_confined
from mcpgateway.utils.paths import resolve_root_path as _resolve_root_path  # noqa: F401 — re-exported for tests
from mcpgateway.utils.security_cookies import clear_auth_cookie as clear_auth_cookie, CookieTooLargeError as CookieTooLargeError, set_auth_cookie as set_auth_cookie
from mcpgateway.utils.services_auth import encode_auth as encode_auth
from mcpgateway.utils.sqlalchemy_modifier import json_contains_tag_expr as json_contains_tag_expr
from mcpgateway.utils.validate_signature import sign_data as sign_data
from mcpgateway.utils.origin import is_allowed_redirect as is_allowed_redirect, normalize_origin_parts as normalize_origin_parts, origin_from_url as origin_from_url
from mcpgateway.utils.verify_credentials import verify_jwt_token_cached as verify_jwt_token_cached

# Re-export cross-cutting helpers from the focused submodules extracted out of
# this package so existing ``from mcpgateway.admin import X`` sites (and test
# patch targets) keep working unchanged.
from mcpgateway.admin.assets import (
    _bundle_css_cache as _bundle_css_cache,
    _bundle_js_cache as _bundle_js_cache,
    get_bundle_css_files as get_bundle_css_files,
    get_bundle_js_filename as get_bundle_js_filename,
    load_sri_hashes as load_sri_hashes,
)  # noqa: PLC2701
from mcpgateway.admin.common import (  # noqa: PLC2701
    _adjust_pagination_for_conversion_failures as _adjust_pagination_for_conversion_failures,
    _has_permission as _has_permission,
    _apply_tag_filter_groups as _apply_tag_filter_groups,
    _assemble_oauth_config_from_fields as _assemble_oauth_config_from_fields,
    _build_admin_redirect as _build_admin_redirect,
    _build_search_response as _build_search_response,
    _check_public_visibility_allowed as _check_public_visibility_allowed,
    _escape_like as _escape_like,
    _form_team_id as _form_team_id,
    _get_user_team_ids as _get_user_team_ids,
    _get_user_team_roles as _get_user_team_roles,
    _is_explicit_token_team_scope as _is_explicit_token_team_scope,
    _like_contains as _like_contains,
    _merge_select_all_ids as _merge_select_all_ids,
    _normalize_int_query as _normalize_int_query,
    _normalize_search_query as _normalize_search_query,
    _normalize_tags_query as _normalize_tags_query,
    _normalize_team_id as _normalize_team_id,
    _owner_access_condition as _owner_access_condition,
    _parse_tag_filter_groups as _parse_tag_filter_groups,
    _read_request_json as _read_request_json,
    _TAG_MAX_GROUPS as _TAG_MAX_GROUPS,
    _TAG_MAX_TERMS_PER_GROUP as _TAG_MAX_TERMS_PER_GROUP,
    _validated_team_id_param as _validated_team_id_param,
    a2a_service as a2a_service,
    export_service as export_service,
    gateway_service as gateway_service,
    get_user_id as get_user_id,
    import_service as import_service,
    prompt_service as prompt_service,
    resource_service as resource_service,
    root_service as root_service,
    serialize_datetime as serialize_datetime,
    server_service as server_service,
    tool_service as tool_service,
)
from mcpgateway.admin.security import (  # noqa: PLC2701
    _admin_cookie_path as _admin_cookie_path,
    _clear_admin_csrf_cookie as _clear_admin_csrf_cookie,
    _request_origin_matches as _request_origin_matches,
    _set_admin_csrf_cookie as _set_admin_csrf_cookie,
    ADMIN_CSRF_COOKIE_NAME as ADMIN_CSRF_COOKIE_NAME,
    ADMIN_CSRF_FORM_FIELD as ADMIN_CSRF_FORM_FIELD,
    ADMIN_CSRF_HEADER_NAME as ADMIN_CSRF_HEADER_NAME,
    enforce_admin_csrf,
    get_client_ip as get_client_ip,
    get_user_agent as get_user_agent,
    rate_limit as rate_limit,
    rate_limit_storage as rate_limit_storage,
)
from mcpgateway.admin.visibility import (  # noqa: PLC2701
    _extract_permission_from_route as _extract_permission_from_route,
    _normalize_ui_hide_values as _normalize_ui_hide_values,
    _SECTION_TO_ROUTE_PATH as _SECTION_TO_ROUTE_PATH,
    get_hidden_sections_for_user as get_hidden_sections_for_user,
    get_ui_visibility_config as get_ui_visibility_config,
    get_user_action_permissions as get_user_action_permissions,
    SECTION_PERMISSIONS as SECTION_PERMISSIONS,
    UI_ACTION_PERMISSIONS as UI_ACTION_PERMISSIONS,
    UI_EMBEDDED_DEFAULT_HIDDEN_HEADER_ITEMS as UI_EMBEDDED_DEFAULT_HIDDEN_HEADER_ITEMS,
    UI_HIDE_SECTIONS_COOKIE_MAX_AGE as UI_HIDE_SECTIONS_COOKIE_MAX_AGE,
    UI_HIDE_SECTIONS_COOKIE_NAME as UI_HIDE_SECTIONS_COOKIE_NAME,
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
from mcpgateway.admin.dashboard import (  # noqa: PLC2701
    admin_ui as admin_ui,
    router as _dashboard_router,
)
from mcpgateway.admin.search import (  # noqa: PLC2701
    admin_search_catalog as admin_search_catalog,
    admin_unified_search as admin_unified_search,
    perform_unified_search as perform_unified_search,
    router as _search_router,
)
from mcpgateway.admin.overview import (  # noqa: PLC2701
    get_overview_partial as get_overview_partial,
    get_global_passthrough_headers as get_global_passthrough_headers,
    update_global_passthrough_headers as update_global_passthrough_headers,
    invalidate_passthrough_headers_cache as invalidate_passthrough_headers_cache,
    get_passthrough_headers_cache_stats as get_passthrough_headers_cache_stats,
    invalidate_a2a_stats_cache as invalidate_a2a_stats_cache,
    get_a2a_stats_cache_stats as get_a2a_stats_cache_stats,
    get_configuration_settings as get_configuration_settings,
    router as _overview_router,
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
admin_router.routes.extend(_overview_router.routes)
admin_router.routes.extend(_dashboard_router.routes)
admin_router.routes.extend(_search_router.routes)
