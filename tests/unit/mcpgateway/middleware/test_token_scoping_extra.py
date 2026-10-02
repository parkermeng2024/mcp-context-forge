# -*- coding: utf-8 -*-
"""Location: ./tests/unit/mcpgateway/middleware/test_token_scoping_extra.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Additional tests for token scoping middleware helpers.
"""

# Standard
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

# Third-Party
import pytest
from fastapi import HTTPException

# First-Party
from mcpgateway.middleware.token_scoping import ResourceOwnershipResult, TokenScopingMiddleware

# Hex-only IDs that match the regex pattern [a-f0-9\-]+
_SRV_ID = "aabbccdd-1122-3344-5566-778899aabbcc"
_TOOL_ID = "11223344-aabb-ccdd-eeff-001122334455"
_RES_ID = "aabbccdd-eeff-0011-2233-445566778899"
_PROMPT_ID = "00112233-4455-6677-8899-aabbccddeeff"
_GW_ID = "ffeeddcc-bbaa-9988-7766-554433221100"


def test_normalize_teams_and_client_ip():
    middleware = TokenScopingMiddleware()
    assert middleware._normalize_teams(None) == []
    assert middleware._normalize_teams([{"id": "t1"}, "t2", {"name": "x"}]) == ["t1", "t2"]

    # _get_client_ip now uses request.client.host directly (proxy headers are
    # handled by ProxyHeadersMiddleware which rewrites client.host).
    req = SimpleNamespace(headers={"X-Forwarded-For": "1.2.3.4"}, client=SimpleNamespace(host="9.9.9.9"))
    assert middleware._get_client_ip(req) == "9.9.9.9"

    req = SimpleNamespace(headers={"X-Real-IP": "5.6.7.8"}, client=SimpleNamespace(host="9.9.9.9"))
    assert middleware._get_client_ip(req) == "9.9.9.9"


def test_check_ip_restrictions_invalid():
    middleware = TokenScopingMiddleware()
    assert middleware._check_ip_restrictions("invalid", ["10.0.0.0/24"]) is False


def test_check_ip_restrictions_exact_and_cidr():
    middleware = TokenScopingMiddleware()
    assert middleware._check_ip_restrictions("192.168.1.10", ["192.168.1.10"]) is True
    assert middleware._check_ip_restrictions("10.0.0.5", ["10.0.0.0/24"]) is True
    assert middleware._check_ip_restrictions("10.0.0.5", ["bad-cidr"]) is False


def test_check_time_restrictions(monkeypatch: pytest.MonkeyPatch):
    middleware = TokenScopingMiddleware()

    class FakeDateTime:
        @classmethod
        def now(cls, tz=None):
            return datetime(2025, 1, 6, 10, 0, tzinfo=timezone.utc)

    monkeypatch.setattr("mcpgateway.middleware.token_scoping.datetime", FakeDateTime)

    assert middleware._check_time_restrictions({"business_hours_only": True, "weekdays_only": True}) is True


def test_check_time_restrictions_weekend(monkeypatch: pytest.MonkeyPatch):
    middleware = TokenScopingMiddleware()

    class FakeDateTime:
        @classmethod
        def now(cls, tz=None):
            return datetime(2025, 1, 5, 10, 0, tzinfo=timezone.utc)  # Sunday

    monkeypatch.setattr("mcpgateway.middleware.token_scoping.datetime", FakeDateTime)

    assert middleware._check_time_restrictions({"weekdays_only": True}) is False


def test_check_usage_limits_hourly_exceeded():
    middleware = TokenScopingMiddleware()
    mock_db = MagicMock()
    hourly_count_result = MagicMock()
    hourly_count_result.scalar.return_value = 3
    mock_db.execute.return_value = hourly_count_result

    with patch("mcpgateway.db.get_db", return_value=iter([mock_db])):
        allowed, reason = middleware._check_usage_limits("jti-123", {"requests_per_hour": 3})

    assert allowed is False
    assert reason == "Hourly request limit exceeded"
    mock_db.rollback.assert_called_once()
    mock_db.close.assert_called_once()


def test_check_usage_limits_daily_exceeded():
    middleware = TokenScopingMiddleware()
    mock_db = MagicMock()
    daily_count_result = MagicMock()
    daily_count_result.scalar.return_value = 7
    mock_db.execute.return_value = daily_count_result

    with patch("mcpgateway.db.get_db", return_value=iter([mock_db])):
        allowed, reason = middleware._check_usage_limits("jti-123", {"requests_per_day": 7})

    assert allowed is False
    assert reason == "Daily request limit exceeded"


def test_check_usage_limits_allows_when_under_limits():
    middleware = TokenScopingMiddleware()
    mock_db = MagicMock()
    hourly_count_result = MagicMock()
    hourly_count_result.scalar.return_value = 2
    daily_count_result = MagicMock()
    daily_count_result.scalar.return_value = 5
    mock_db.execute.side_effect = [hourly_count_result, daily_count_result]

    with patch("mcpgateway.db.get_db", return_value=iter([mock_db])):
        allowed, reason = middleware._check_usage_limits(
            "jti-123",
            {"requests_per_hour": 3, "requests_per_day": 10},
        )

    assert allowed is True
    assert reason is None


def test_check_usage_limits_ignores_non_positive_limits_without_db_call():
    middleware = TokenScopingMiddleware()
    mock_db = MagicMock()

    with patch("mcpgateway.db.get_db", return_value=iter([mock_db])):
        allowed, reason = middleware._check_usage_limits("jti-123", {"requests_per_hour": "bad", "requests_per_day": 0})

    assert allowed is True
    assert reason is None
    mock_db.execute.assert_not_called()


def test_check_usage_limits_db_failure_fails_open():
    middleware = TokenScopingMiddleware()
    mock_db = MagicMock()
    mock_db.execute.side_effect = RuntimeError("db-error")

    with patch("mcpgateway.db.get_db", return_value=iter([mock_db])):
        allowed, reason = middleware._check_usage_limits("jti-123", {"requests_per_day": 3})

    assert allowed is True
    assert reason is None
    mock_db.rollback.assert_called_once()
    mock_db.close.assert_called_once()


def _freeze_now(monkeypatch: pytest.MonkeyPatch, frozen: datetime) -> None:
    """Patch the middleware module clock to return a fixed datetime.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
        frozen: Timezone-aware datetime returned by the patched clock.
    """

    class FakeDateTime:
        @classmethod
        def now(cls, tz=None):
            return frozen

    monkeypatch.setattr("mcpgateway.middleware.token_scoping.datetime", FakeDateTime)


# 2025-01-06 is a Monday; 2025-01-05 is a Sunday; 2025-01-07 is a Tuesday.
_MONDAY_10AM_UTC = datetime(2025, 1, 6, 10, 0, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    "hour,expected",
    [
        (10, True),  # Within the window
        (9, True),  # Inclusive start boundary
        (17, True),  # Inclusive end boundary
        (8, False),  # Before the window
        (18, False),  # After the window
    ],
)
def test_check_time_restrictions_start_end_window(monkeypatch: pytest.MonkeyPatch, hour: int, expected: bool):
    middleware = TokenScopingMiddleware()
    _freeze_now(monkeypatch, datetime(2025, 1, 6, hour, 0, tzinfo=timezone.utc))

    assert middleware._check_time_restrictions({"start_time": "09:00", "end_time": "17:00"}) is expected


@pytest.mark.parametrize(
    "hour,expected",
    [
        (23, True),  # After the overnight start
        (3, True),  # Before the overnight end
        (22, True),  # Inclusive overnight start boundary
        (6, True),  # Inclusive overnight end boundary
        (12, False),  # Outside the overnight window
    ],
)
def test_check_time_restrictions_overnight_window(monkeypatch: pytest.MonkeyPatch, hour: int, expected: bool):
    middleware = TokenScopingMiddleware()
    _freeze_now(monkeypatch, datetime(2025, 1, 6, hour, 0, tzinfo=timezone.utc))

    assert middleware._check_time_restrictions({"start_time": "22:00", "end_time": "06:00"}) is expected


def test_check_time_restrictions_open_ended_start(monkeypatch: pytest.MonkeyPatch):
    middleware = TokenScopingMiddleware()
    _freeze_now(monkeypatch, _MONDAY_10AM_UTC)

    assert middleware._check_time_restrictions({"start_time": "09:00"}) is True
    assert middleware._check_time_restrictions({"start_time": "11:00"}) is False


def test_check_time_restrictions_open_ended_end(monkeypatch: pytest.MonkeyPatch):
    middleware = TokenScopingMiddleware()
    _freeze_now(monkeypatch, _MONDAY_10AM_UTC)

    assert middleware._check_time_restrictions({"end_time": "17:00"}) is True
    assert middleware._check_time_restrictions({"end_time": "08:00"}) is False


def test_check_time_restrictions_equal_bounds_allow_whole_day(monkeypatch: pytest.MonkeyPatch):
    middleware = TokenScopingMiddleware()
    _freeze_now(monkeypatch, _MONDAY_10AM_UTC)

    assert middleware._check_time_restrictions({"start_time": "09:00", "end_time": "09:00"}) is True


def test_check_time_restrictions_timezone_window(monkeypatch: pytest.MonkeyPatch):
    middleware = TokenScopingMiddleware()
    # 15:00 UTC is 10:00 in America/New_York (EST, January)
    _freeze_now(monkeypatch, datetime(2025, 1, 6, 15, 0, tzinfo=timezone.utc))

    restrictions = {"start_time": "09:00", "end_time": "17:00", "timezone": "America/New_York"}
    assert middleware._check_time_restrictions(restrictions) is True

    # 12:00 UTC is 07:00 in America/New_York — outside the window
    _freeze_now(monkeypatch, datetime(2025, 1, 6, 12, 0, tzinfo=timezone.utc))
    assert middleware._check_time_restrictions(restrictions) is False


def test_check_time_restrictions_invalid_timezone_fails_closed(monkeypatch: pytest.MonkeyPatch):
    middleware = TokenScopingMiddleware()
    _freeze_now(monkeypatch, _MONDAY_10AM_UTC)

    assert middleware._check_time_restrictions({"start_time": "09:00", "timezone": "Not/AZone"}) is False
    assert middleware._check_time_restrictions({"days": ["Monday"], "timezone": "Mars/Olympus_Mons"}) is False
    assert middleware._check_time_restrictions({"start_time": "09:00", "timezone": 120}) is False


@pytest.mark.parametrize("bad_time", ["9am", "25:00", "09:60", "09:00:00", ":", 900, 9.5])
def test_check_time_restrictions_invalid_time_format_fails_closed(monkeypatch: pytest.MonkeyPatch, bad_time):
    middleware = TokenScopingMiddleware()
    _freeze_now(monkeypatch, _MONDAY_10AM_UTC)

    assert middleware._check_time_restrictions({"start_time": bad_time}) is False


def test_check_time_restrictions_days_allow_and_deny(monkeypatch: pytest.MonkeyPatch):
    middleware = TokenScopingMiddleware()
    _freeze_now(monkeypatch, _MONDAY_10AM_UTC)

    assert middleware._check_time_restrictions({"days": ["Monday", "Tuesday"]}) is True
    assert middleware._check_time_restrictions({"days": ["Saturday", "Sunday"]}) is False


def test_check_time_restrictions_days_evaluated_in_effective_timezone(monkeypatch: pytest.MonkeyPatch):
    middleware = TokenScopingMiddleware()
    # 2025-01-06 02:00 UTC is Sunday 21:00 in America/New_York
    _freeze_now(monkeypatch, datetime(2025, 1, 6, 2, 0, tzinfo=timezone.utc))

    assert middleware._check_time_restrictions({"days": ["Sunday"], "timezone": "America/New_York"}) is True
    assert middleware._check_time_restrictions({"days": ["Monday"], "timezone": "America/New_York"}) is False


def test_check_time_restrictions_invalid_days_fail_closed(monkeypatch: pytest.MonkeyPatch):
    middleware = TokenScopingMiddleware()
    _freeze_now(monkeypatch, _MONDAY_10AM_UTC)

    assert middleware._check_time_restrictions({"days": ["Funday"]}) is False
    assert middleware._check_time_restrictions({"days": "Monday"}) is False
    assert middleware._check_time_restrictions({"days": ["Monday", 3]}) is False


def test_check_time_restrictions_empty_days_is_no_restriction(monkeypatch: pytest.MonkeyPatch):
    middleware = TokenScopingMiddleware()
    _freeze_now(monkeypatch, _MONDAY_10AM_UTC)

    assert middleware._check_time_restrictions({"days": []}) is True


def test_check_time_restrictions_combined_restrictions_are_anded(monkeypatch: pytest.MonkeyPatch):
    middleware = TokenScopingMiddleware()
    restrictions = {"start_time": "09:00", "end_time": "17:00", "days": ["Tuesday"]}

    # Within the window but the wrong weekday denies
    _freeze_now(monkeypatch, _MONDAY_10AM_UTC)
    assert middleware._check_time_restrictions(restrictions) is False

    # Within the window and the right weekday allows
    _freeze_now(monkeypatch, datetime(2025, 1, 7, 10, 0, tzinfo=timezone.utc))
    assert middleware._check_time_restrictions(restrictions) is True


def test_check_time_restrictions_legacy_keys_still_apply_with_new_keys(monkeypatch: pytest.MonkeyPatch):
    middleware = TokenScopingMiddleware()
    restrictions = {"business_hours_only": True, "start_time": "09:00"}

    # Inside both UTC business hours and the window allows
    _freeze_now(monkeypatch, _MONDAY_10AM_UTC)
    assert middleware._check_time_restrictions(restrictions) is True

    # Outside UTC business hours denies even though the window is open-ended
    _freeze_now(monkeypatch, datetime(2025, 1, 6, 18, 0, tzinfo=timezone.utc))
    assert middleware._check_time_restrictions(restrictions) is False


def test_check_server_and_permission_restrictions():
    middleware = TokenScopingMiddleware()
    assert middleware._check_server_restriction("/servers/abc/tools", "abc") is True
    assert middleware._check_server_restriction("/health", "abc") is True
    assert middleware._check_permission_restrictions("/tools", "GET", ["*"]) is True
    assert middleware._check_permission_restrictions("/tools", "POST", ["tools.read"]) is False


def test_check_restrictions_normalize_app_root_path(monkeypatch):
    middleware = TokenScopingMiddleware()
    monkeypatch.setattr("mcpgateway.middleware.token_scoping.settings.app_root_path", "/forge")
    assert middleware._check_server_restriction("/forge/servers/abc/tools", "abc") is True
    assert middleware._check_permission_restrictions("/forge/tools", "GET", ["tools.read"]) is True


@pytest.mark.asyncio
async def test_extract_token_scopes_handles_exceptions(monkeypatch):
    middleware = TokenScopingMiddleware()
    request = SimpleNamespace(headers={"Authorization": "Bearer bad-token"})

    async def _raise_http(*_args, **_kwargs):
        raise HTTPException(status_code=401, detail="invalid")

    monkeypatch.setattr("mcpgateway.middleware.token_scoping.verify_jwt_token_cached", _raise_http)
    assert await middleware._extract_token_scopes(request) is None

    async def _raise_other(*_args, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr("mcpgateway.middleware.token_scoping.verify_jwt_token_cached", _raise_other)
    assert await middleware._extract_token_scopes(request) is None


def test_check_team_membership_public_token():
    middleware = TokenScopingMiddleware()
    payload = {"teams": [], "sub": "user@example.com"}
    assert middleware._check_team_membership(payload) is True


def test_check_resource_team_ownership_no_resource():
    middleware = TokenScopingMiddleware()
    assert middleware._check_resource_team_ownership("/health", [], db=None, _user_email=None) is ResourceOwnershipResult.ALLOWED


# --------------------------------------------------------------------------- #
# Coverage: _normalize_teams edge cases                                        #
# --------------------------------------------------------------------------- #
def test_normalize_teams_empty_list():
    middleware = TokenScopingMiddleware()
    assert middleware._normalize_teams([]) == []


def test_normalize_teams_dict_without_id():
    """Dict without 'id' key is skipped."""
    middleware = TokenScopingMiddleware()
    assert middleware._normalize_teams([{"name": "t1"}, {"id": "t2"}]) == ["t2"]


def test_normalize_teams_mixed_types():
    """Non-dict, non-string items are skipped."""
    middleware = TokenScopingMiddleware()
    assert middleware._normalize_teams([123, "team-1", None]) == ["team-1"]


# --------------------------------------------------------------------------- #
# Coverage: _get_client_ip fallback                                            #
# --------------------------------------------------------------------------- #
def test_get_client_ip_direct():
    middleware = TokenScopingMiddleware()
    req = SimpleNamespace(headers={}, client=SimpleNamespace(host="10.0.0.1"))
    assert middleware._get_client_ip(req) == "10.0.0.1"


def test_get_client_ip_no_client():
    middleware = TokenScopingMiddleware()
    req = SimpleNamespace(headers={}, client=None)
    assert middleware._get_client_ip(req) == "unknown"


# --------------------------------------------------------------------------- #
# Coverage: _check_resource_team_ownership - server visibility branches        #
# --------------------------------------------------------------------------- #
class TestResourceTeamOwnershipServers:
    """Tests for server visibility checks in _check_resource_team_ownership."""

    def _make_db_with_entity(self, entity):
        """Create mock DB that returns entity for select().where() queries."""
        mock_db = MagicMock()
        mock_db.execute.return_value.scalar_one_or_none.return_value = entity
        return mock_db

    def test_server_not_found(self):
        middleware = TokenScopingMiddleware()
        db = self._make_db_with_entity(None)
        result = middleware._check_resource_team_ownership(f"/servers/{_SRV_ID}", ["team-1"], db=db, _user_email="u@t.com")
        assert result is ResourceOwnershipResult.NOT_FOUND

    def test_server_public_allowed(self):
        middleware = TokenScopingMiddleware()
        server = SimpleNamespace(visibility="public", team_id=None, owner_email=None)
        db = self._make_db_with_entity(server)
        result = middleware._check_resource_team_ownership(f"/servers/{_SRV_ID}", ["team-1"], db=db, _user_email="u@t.com")
        assert result is ResourceOwnershipResult.ALLOWED

    def test_server_public_token_denied_team_server(self):
        middleware = TokenScopingMiddleware()
        server = SimpleNamespace(visibility="team", team_id="team-2", owner_email=None)
        db = self._make_db_with_entity(server)
        result = middleware._check_resource_team_ownership(f"/servers/{_SRV_ID}", [], db=db, _user_email="u@t.com")
        assert result is ResourceOwnershipResult.DENIED

    def test_server_team_access_granted(self):
        middleware = TokenScopingMiddleware()
        server = SimpleNamespace(visibility="team", team_id="team-1", owner_email=None)
        db = self._make_db_with_entity(server)
        result = middleware._check_resource_team_ownership(f"/servers/{_SRV_ID}", ["team-1"], db=db, _user_email="u@t.com")
        assert result is ResourceOwnershipResult.ALLOWED

    def test_server_team_access_denied(self):
        middleware = TokenScopingMiddleware()
        server = SimpleNamespace(visibility="team", team_id="team-2", owner_email=None)
        db = self._make_db_with_entity(server)
        result = middleware._check_resource_team_ownership(f"/servers/{_SRV_ID}", ["team-1"], db=db, _user_email="u@t.com")
        assert result is ResourceOwnershipResult.DENIED

    def test_server_private_owner_access(self):
        middleware = TokenScopingMiddleware()
        server = SimpleNamespace(visibility="private", team_id=None, owner_email="u@t.com")
        db = self._make_db_with_entity(server)
        result = middleware._check_resource_team_ownership(f"/servers/{_SRV_ID}", ["team-1"], db=db, _user_email="u@t.com")
        assert result is ResourceOwnershipResult.ALLOWED

    def test_server_private_non_owner_denied(self):
        middleware = TokenScopingMiddleware()
        server = SimpleNamespace(visibility="private", team_id=None, owner_email="other@t.com")
        db = self._make_db_with_entity(server)
        result = middleware._check_resource_team_ownership(f"/servers/{_SRV_ID}", ["team-1"], db=db, _user_email="u@t.com")
        assert result is ResourceOwnershipResult.DENIED

    def test_server_unknown_visibility_denied(self):
        middleware = TokenScopingMiddleware()
        server = SimpleNamespace(visibility="unknown_vis", team_id=None, owner_email=None)
        db = self._make_db_with_entity(server)
        result = middleware._check_resource_team_ownership(f"/servers/{_SRV_ID}", ["team-1"], db=db, _user_email="u@t.com")
        assert result is ResourceOwnershipResult.DENIED


# --------------------------------------------------------------------------- #
# Coverage: _check_resource_team_ownership - tool visibility branches          #
# --------------------------------------------------------------------------- #
class TestResourceTeamOwnershipTools:
    """Tests for tool visibility checks."""

    def _make_db_with_entity(self, entity):
        mock_db = MagicMock()
        mock_db.execute.return_value.scalar_one_or_none.return_value = entity
        return mock_db

    def test_tool_not_found(self):
        middleware = TokenScopingMiddleware()
        db = self._make_db_with_entity(None)
        result = middleware._check_resource_team_ownership(f"/tools/{_TOOL_ID}", ["team-1"], db=db, _user_email="u@t.com")
        assert result is ResourceOwnershipResult.DENIED

    def test_tool_public_allowed(self):
        middleware = TokenScopingMiddleware()
        tool = SimpleNamespace(visibility="public", team_id=None, owner_email=None)
        db = self._make_db_with_entity(tool)
        result = middleware._check_resource_team_ownership(f"/tools/{_TOOL_ID}", ["team-1"], db=db, _user_email="u@t.com")
        assert result is ResourceOwnershipResult.ALLOWED

    def test_tool_team_access_denied(self):
        middleware = TokenScopingMiddleware()
        tool = SimpleNamespace(visibility="team", team_id="team-2", owner_email=None)
        db = self._make_db_with_entity(tool)
        result = middleware._check_resource_team_ownership(f"/tools/{_TOOL_ID}", ["team-1"], db=db, _user_email="u@t.com")
        assert result is ResourceOwnershipResult.DENIED

    def test_tool_public_token_denied(self):
        middleware = TokenScopingMiddleware()
        tool = SimpleNamespace(visibility="team", team_id="team-1", owner_email=None)
        db = self._make_db_with_entity(tool)
        result = middleware._check_resource_team_ownership(f"/tools/{_TOOL_ID}", [], db=db, _user_email="u@t.com")
        assert result is ResourceOwnershipResult.DENIED


# --------------------------------------------------------------------------- #
# Coverage: _check_resource_team_ownership - resource visibility               #
# --------------------------------------------------------------------------- #
class TestResourceTeamOwnershipResources:
    """Tests for resource visibility checks."""

    def _make_db_with_entity(self, entity):
        mock_db = MagicMock()
        mock_db.execute.return_value.scalar_one_or_none.return_value = entity
        return mock_db

    def test_resource_not_found(self):
        middleware = TokenScopingMiddleware()
        db = self._make_db_with_entity(None)
        result = middleware._check_resource_team_ownership(f"/resources/{_RES_ID}", ["team-1"], db=db, _user_email="u@t.com")
        assert result is ResourceOwnershipResult.DENIED

    def test_resource_team_denied(self):
        middleware = TokenScopingMiddleware()
        resource = SimpleNamespace(visibility="team", team_id="team-2", owner_email=None)
        db = self._make_db_with_entity(resource)
        result = middleware._check_resource_team_ownership(f"/resources/{_RES_ID}", ["team-1"], db=db, _user_email="u@t.com")
        assert result is ResourceOwnershipResult.DENIED


# --------------------------------------------------------------------------- #
# Coverage: _check_resource_team_ownership - prompt visibility                 #
# --------------------------------------------------------------------------- #
class TestResourceTeamOwnershipPrompts:
    """Tests for prompt visibility checks."""

    def _make_db_with_entity(self, entity):
        mock_db = MagicMock()
        mock_db.execute.return_value.scalar_one_or_none.return_value = entity
        return mock_db

    def test_prompt_not_found(self):
        middleware = TokenScopingMiddleware()
        db = self._make_db_with_entity(None)
        result = middleware._check_resource_team_ownership(f"/prompts/{_PROMPT_ID}", ["team-1"], db=db, _user_email="u@t.com")
        assert result is ResourceOwnershipResult.DENIED

    def test_prompt_public_allowed(self):
        middleware = TokenScopingMiddleware()
        prompt = SimpleNamespace(visibility="public", team_id=None, owner_email=None)
        db = self._make_db_with_entity(prompt)
        result = middleware._check_resource_team_ownership(f"/prompts/{_PROMPT_ID}", ["team-1"], db=db, _user_email="u@t.com")
        assert result is ResourceOwnershipResult.ALLOWED

    def test_prompt_team_denied(self):
        middleware = TokenScopingMiddleware()
        prompt = SimpleNamespace(visibility="team", team_id="team-2", owner_email=None)
        db = self._make_db_with_entity(prompt)
        result = middleware._check_resource_team_ownership(f"/prompts/{_PROMPT_ID}", ["team-1"], db=db, _user_email="u@t.com")
        assert result is ResourceOwnershipResult.DENIED

    def test_prompt_private_owner_access(self):
        middleware = TokenScopingMiddleware()
        prompt = SimpleNamespace(visibility="private", team_id=None, owner_email="u@t.com")
        db = self._make_db_with_entity(prompt)
        result = middleware._check_resource_team_ownership(f"/prompts/{_PROMPT_ID}", ["team-1"], db=db, _user_email="u@t.com")
        assert result is ResourceOwnershipResult.ALLOWED

    def test_prompt_private_non_owner_denied(self):
        middleware = TokenScopingMiddleware()
        prompt = SimpleNamespace(visibility="private", team_id=None, owner_email="other@t.com")
        db = self._make_db_with_entity(prompt)
        result = middleware._check_resource_team_ownership(f"/prompts/{_PROMPT_ID}", ["team-1"], db=db, _user_email="u@t.com")
        assert result is ResourceOwnershipResult.DENIED


# --------------------------------------------------------------------------- #
# Coverage: _check_resource_team_ownership - gateway visibility                #
# --------------------------------------------------------------------------- #
class TestResourceTeamOwnershipGateways:
    """Tests for gateway visibility checks."""

    def _make_db_with_entity(self, entity):
        mock_db = MagicMock()
        mock_db.execute.return_value.scalar_one_or_none.return_value = entity
        return mock_db

    def test_gateway_not_found(self):
        middleware = TokenScopingMiddleware()
        db = self._make_db_with_entity(None)
        result = middleware._check_resource_team_ownership(f"/gateways/{_GW_ID}", ["team-1"], db=db, _user_email="u@t.com")
        assert result is ResourceOwnershipResult.NOT_FOUND

    def test_gateway_public_allowed(self):
        middleware = TokenScopingMiddleware()
        gw = SimpleNamespace(visibility="public", team_id=None, owner_email=None)
        db = self._make_db_with_entity(gw)
        result = middleware._check_resource_team_ownership(f"/gateways/{_GW_ID}", ["team-1"], db=db, _user_email="u@t.com")
        assert result is ResourceOwnershipResult.ALLOWED

    def test_gateway_public_token_denied(self):
        middleware = TokenScopingMiddleware()
        gw = SimpleNamespace(visibility="team", team_id="team-1", owner_email=None)
        db = self._make_db_with_entity(gw)
        result = middleware._check_resource_team_ownership(f"/gateways/{_GW_ID}", [], db=db, _user_email="u@t.com")
        assert result is ResourceOwnershipResult.DENIED

    def test_gateway_team_denied(self):
        middleware = TokenScopingMiddleware()
        gw = SimpleNamespace(visibility="team", team_id="team-2", owner_email=None)
        db = self._make_db_with_entity(gw)
        result = middleware._check_resource_team_ownership(f"/gateways/{_GW_ID}", ["team-1"], db=db, _user_email="u@t.com")
        assert result is ResourceOwnershipResult.DENIED

    def test_gateway_private_owner(self):
        middleware = TokenScopingMiddleware()
        gw = SimpleNamespace(visibility="private", team_id=None, owner_email="u@t.com")
        db = self._make_db_with_entity(gw)
        result = middleware._check_resource_team_ownership(f"/gateways/{_GW_ID}", ["team-1"], db=db, _user_email="u@t.com")
        assert result is ResourceOwnershipResult.ALLOWED

    def test_gateway_unknown_visibility(self):
        middleware = TokenScopingMiddleware()
        gw = SimpleNamespace(visibility="weird", team_id=None, owner_email=None)
        db = self._make_db_with_entity(gw)
        result = middleware._check_resource_team_ownership(f"/gateways/{_GW_ID}", ["team-1"], db=db, _user_email="u@t.com")
        assert result is ResourceOwnershipResult.DENIED


# --------------------------------------------------------------------------- #
# Coverage: _check_time_restrictions - business hours                          #
# --------------------------------------------------------------------------- #
def test_check_time_restrictions_outside_business_hours(monkeypatch):
    middleware = TokenScopingMiddleware()

    class FakeDateTime:
        @classmethod
        def now(cls, tz=None):
            return datetime(2025, 1, 6, 22, 0, tzinfo=timezone.utc)  # Monday 10pm

    monkeypatch.setattr("mcpgateway.middleware.token_scoping.datetime", FakeDateTime)
    assert middleware._check_time_restrictions({"business_hours_only": True}) is False
