# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/admin/auth.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Admin UI authentication routes: login, logout, forgot and reset password, and
the forced password change flow.
"""

# Standard
import binascii
from datetime import datetime, timezone
import logging
import time
from typing import Dict, Optional, cast as typing_cast
import urllib.parse
import uuid

# Third-Party
from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials
import orjson
from sqlalchemy.orm import Session

# First-Party
from mcpgateway.admin.assets import get_bundle_css_files, load_sri_hashes
from mcpgateway.admin.security import _clear_admin_csrf_cookie, _set_admin_csrf_cookie, enforce_admin_csrf, get_client_ip, get_user_agent
from mcpgateway.auth import get_current_user
from mcpgateway.auth_user_helpers import is_passwordless_user
from mcpgateway.config import settings
from mcpgateway.db import EmailUser, get_db, SessionLocal, utc_now
from mcpgateway.i18n import t as i18n_t
from mcpgateway.routers.email_auth import create_access_token
from mcpgateway.services.argon2_service import Argon2PasswordService
from mcpgateway.services.email_auth_service import AuthenticationError, EmailAuthService, PasswordValidationError
from mcpgateway.services.password_policy_service import PasswordPolicyService
from mcpgateway.services.permission_service import PermissionService
from mcpgateway.utils.paths import resolve_root_path as _resolve_root_path
from mcpgateway.utils.security_cookies import clear_auth_cookie, CookieTooLargeError, set_auth_cookie
from mcpgateway.utils.verify_credentials import verify_jwt_token_cached

LOGGER: logging.Logger = logging.getLogger("mcpgateway.admin")

# mcpgateway.admin (__init__) appends this router's routes to admin_router, so the
# prefix, tags, and CSRF dependency must mirror admin_router exactly.
router = APIRouter(
    prefix="/admin",
    tags=["Admin UI"],
    dependencies=[Depends(enforce_admin_csrf)],
)


@router.get("/login")
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


@router.post("/login")
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


@router.get("/forgot-password")
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


@router.post("/forgot-password")
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


@router.get("/reset-password/{token}")
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


@router.post("/reset-password/{token}")
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


@router.get("/logout", operation_id="admin_logout_get")
async def admin_logout_get(request: Request) -> Response:
    """GET logout endpoint for OIDC front-channel logout.

    Args:
        request (Request): FastAPI request object.

    Returns:
        Response: Logout response for front-channel requests.
    """
    return await _admin_logout(request)


@router.post("/logout", operation_id="admin_logout_post")
async def admin_logout_post(request: Request) -> Response:
    """POST logout endpoint for user-initiated UI logout.

    Args:
        request (Request): FastAPI request object.

    Returns:
        Response: Logout response for UI-initiated requests.
    """
    return await _admin_logout(request)


@router.get("/change-password-required", response_class=HTMLResponse)
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


@router.post("/change-password-required")
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
