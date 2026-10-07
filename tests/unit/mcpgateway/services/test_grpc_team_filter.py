# -*- coding: utf-8 -*-
"""Location: ./tests/unit/mcpgateway/services/test_grpc_team_filter.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Regression tests for gRPC team/visibility filtering.

``GrpcService.list_services`` and ``GrpcService.get_service`` call
``TeamManagementService.build_team_filter_clause``. That method did not exist,
so every authenticated gRPC read raised AttributeError and answered HTTP 500.
"""

# Standard
from unittest.mock import AsyncMock, MagicMock

# Third-Party
import pytest
from sqlalchemy import select

# First-Party
from mcpgateway.db import GrpcService as DbGrpcService
from mcpgateway.services.team_management_service import TeamManagementService


def _team(team_id):
    """Build a stand-in EmailTeam exposing ``id``."""
    team = MagicMock()
    team.id = team_id
    return team


def _sql(clause):
    """Render a clause as literal SQL so tests can assert on it."""
    return str(select(DbGrpcService).where(clause).compile(compile_kwargs={"literal_binds": True}))


def test_build_team_filter_clause_is_defined():
    """The method must exist; its absence broke every gRPC read path."""
    assert hasattr(TeamManagementService, "build_team_filter_clause")


@pytest.mark.asyncio
async def test_build_team_filter_clause_returns_none_without_user():
    """No identity means no filter, so callers keep their unfiltered query."""
    service = TeamManagementService(db=MagicMock())

    assert await service.build_team_filter_clause(DbGrpcService, None) is None


@pytest.mark.asyncio
async def test_build_team_filter_clause_scopes_public_team_and_own_rows():
    """Public rows, the caller's teams and the caller's own rows stay visible."""
    service = TeamManagementService(db=MagicMock())
    service.get_user_teams = AsyncMock(return_value=[_team("team-1")])

    sql = _sql(await service.build_team_filter_clause(DbGrpcService, "user@example.com"))

    assert "visibility" in sql
    assert "team-1" in sql
    assert "user@example.com" in sql


@pytest.mark.asyncio
async def test_build_team_filter_clause_drops_team_the_user_is_not_in():
    """A team scope outside the caller's membership must not broaden access."""
    service = TeamManagementService(db=MagicMock())
    service.get_user_teams = AsyncMock(return_value=[_team("team-1")])

    sql = _sql(await service.build_team_filter_clause(DbGrpcService, "user@example.com", "team-9"))

    assert "team-9" not in sql
