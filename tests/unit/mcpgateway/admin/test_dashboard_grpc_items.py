# -*- coding: utf-8 -*-
"""Location: ./tests/unit/mcpgateway/admin/test_dashboard_grpc_items.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Regression tests for the admin dashboard's gRPC service list unwrapping.

``GrpcService.list_services`` returns ``(items, next_cursor)`` when no page is
requested and a dict when page pagination is requested. The dashboard iterated
the raw result, hit AttributeError on the tuple, and silently rendered an empty
gRPC panel.
"""

# First-Party
from mcpgateway.admin.dashboard import _grpc_service_items


def test_unwraps_the_cursor_tuple():
    """A tuple result yields its first element."""
    assert _grpc_service_items((["service-a"], None)) == ["service-a"]


def test_unwraps_the_page_dict():
    """A page-based dict result yields its ``data`` list."""
    assert _grpc_service_items({"data": ["service-a"], "pagination": {}}) == ["service-a"]


def test_passes_through_a_plain_list():
    """A plain list is returned unchanged."""
    assert _grpc_service_items(["service-a"]) == ["service-a"]


def test_normalises_empty_shapes():
    """Every empty shape maps to an empty list, never None."""
    assert _grpc_service_items(None) == []
    assert _grpc_service_items(([], None)) == []
    assert _grpc_service_items({"data": None}) == []
    assert _grpc_service_items([]) == []
