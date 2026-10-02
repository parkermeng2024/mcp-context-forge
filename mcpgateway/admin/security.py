# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/admin/security.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Admin UI security helpers: CSRF double-submit cookie handling, rate limiting, and client request metadata extraction.
"""

# Standard
from collections import defaultdict
from functools import wraps
import inspect
import logging
import secrets
import time
from typing import Optional
import urllib.parse

# Third-Party
from fastapi import HTTPException, Request, Response

# First-Party
from mcpgateway.config import settings
from mcpgateway.services.csrf_service import get_csrf_service
from mcpgateway.utils.origin import normalize_origin_parts
from mcpgateway.utils.paths import resolve_root_path as _resolve_root_path

LOGGER: logging.Logger = logging.getLogger("mcpgateway.admin")


# Rate limiting storage
rate_limit_storage = defaultdict(list)


def get_client_ip(request: Request) -> str:
    """Extract client IP address from request.

    Args:
        request: FastAPI request object

    Returns:
        str: Client IP address

    Examples:
        >>> from unittest.mock import MagicMock
        >>>
        >>> # Test with X-Forwarded-For header
        >>> mock_request = MagicMock()
        >>> mock_request.headers = {"X-Forwarded-For": "192.168.1.1, 10.0.0.1"}
        >>> get_client_ip(mock_request)
        '192.168.1.1'
        >>>
        >>> # Test with X-Real-IP header
        >>> mock_request.headers = {"X-Real-IP": "10.0.0.5"}
        >>> get_client_ip(mock_request)
        '10.0.0.5'
        >>>
        >>> # Test with direct client IP
        >>> mock_request.headers = {}
        >>> mock_request.client.host = "127.0.0.1"
        >>> get_client_ip(mock_request)
        '127.0.0.1'
        >>>
        >>> # Test with no client info
        >>> mock_request.client = None
        >>> get_client_ip(mock_request)
        'unknown'
    """
    # Check for X-Forwarded-For header (proxy/load balancer)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()

    # Check for X-Real-IP header
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip

    # Fall back to direct client IP
    return request.client.host if request.client else "unknown"


def get_user_agent(request: Request) -> str:
    """Extract user agent from request.

    Args:
        request: FastAPI request object

    Returns:
        str: User agent string

    Examples:
        >>> from unittest.mock import MagicMock
        >>>
        >>> # Test with User-Agent header
        >>> mock_request = MagicMock()
        >>> mock_request.headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0)"}
        >>> get_user_agent(mock_request)
        'Mozilla/5.0 (Windows NT 10.0)'
        >>>
        >>> # Test without User-Agent header
        >>> mock_request.headers = {}
        >>> get_user_agent(mock_request)
        'unknown'
    """
    return request.headers.get("User-Agent", "unknown")


def rate_limit(requests_per_minute: Optional[int] = None):
    """Apply rate limiting to admin endpoints.

    Args:
        requests_per_minute: Maximum requests per minute (uses config default if None)

    Returns:
        Decorator function that enforces rate limiting

    Examples:
        Test basic decorator creation:
        >>> from mcpgateway import admin
        >>> decorator = admin.rate_limit(10)
        >>> callable(decorator)
        True

        Test with None parameter (uses default):
        >>> default_decorator = admin.rate_limit(None)
        >>> callable(default_decorator)
        True

        Test with specific limit:
        >>> limited_decorator = admin.rate_limit(5)
        >>> callable(limited_decorator)
        True

        Test decorator returns wrapper:
        >>> async def dummy_func():
        ...     return "success"
        >>> decorated_func = decorator(dummy_func)
        >>> callable(decorated_func)
        True

        Test rate limit storage structure:
        >>> isinstance(admin.rate_limit_storage, dict)
        True
        >>> from collections import defaultdict
        >>> isinstance(admin.rate_limit_storage, defaultdict)
        True

        Test decorator with zero limit:
        >>> zero_limit_decorator = admin.rate_limit(0)
        >>> callable(zero_limit_decorator)
        True

        Test decorator with high limit:
        >>> high_limit_decorator = admin.rate_limit(1000)
        >>> callable(high_limit_decorator)
        True
    """

    def decorator(func_to_wrap):
        """Decorator that wraps the function with rate limiting logic.

        Args:
            func_to_wrap: The function to be wrapped with rate limiting

        Returns:
            The wrapped function with rate limiting applied
        """
        signature_params = inspect.signature(func_to_wrap).parameters.values()
        accepts_request = any(param.name == "request" or param.kind == inspect.Parameter.VAR_KEYWORD for param in signature_params)

        @wraps(func_to_wrap)
        async def wrapper(*args, request: Optional[Request] = None, **kwargs):
            """Execute the wrapped function with rate limiting enforcement.

            Args:
                *args: Positional arguments to pass to the wrapped function
                request: FastAPI Request object for extracting client IP
                **kwargs: Keyword arguments to pass to the wrapped function

            Returns:
                The result of the wrapped function call

            Raises:
                HTTPException: When rate limit is exceeded (429 status)
            """
            # use configured limit if none provided
            limit = requests_per_minute or settings.validation_max_requests_per_minute

            # request can be None in some edge cases (e.g., tests)
            client_ip = request.client.host if request and request.client else "unknown"
            current_time = time.time()
            minute_ago = current_time - 60

            # prune old timestamps
            rate_limit_storage[client_ip] = [ts for ts in rate_limit_storage[client_ip] if ts > minute_ago]

            # enforce
            if len(rate_limit_storage[client_ip]) >= limit:
                LOGGER.warning(f"Rate limit exceeded for IP {client_ip} on endpoint {func_to_wrap.__name__}")
                raise HTTPException(
                    status_code=429,
                    detail=f"Rate limit exceeded. Maximum {limit} requests per minute.",
                )
            rate_limit_storage[client_ip].append(current_time)
            if accepts_request:
                return await func_to_wrap(*args, request=request, **kwargs)
            return await func_to_wrap(*args, **kwargs)

        return wrapper

    return decorator


ADMIN_CSRF_COOKIE_NAME = "mcpgateway_csrf_token"
ADMIN_CSRF_HEADER_NAME = "x-csrf-token"
ADMIN_CSRF_FORM_FIELD = "csrf_token"


def _admin_cookie_path(request: Request) -> str:
    """Build admin cookie path honoring ASGI root_path.

    Args:
        request: Incoming request used to read ASGI ``root_path``.

    Returns:
        Cookie path scoped to the deployed app root so admin-originated
        non-/admin mutations can carry the same double-submit token.
    """
    root_path = _resolve_root_path(request)
    return root_path or "/"


def _request_origin_matches(request: Request) -> bool:
    """Return ``True`` when Origin/Referer matches this request origin.

    The function first performs an exact same-origin comparison using the
    request's forwarded headers (``X-Forwarded-Proto`` / ``X-Forwarded-Host``).
    When that fails — common behind layered reverse proxies where forwarded
    headers reflect internal hops rather than the external scheme — it falls
    back to checking whether the candidate origin is explicitly listed in
    ``settings.allowed_origins``.  Wildcard entries (``*``, ``null``, ``""``)
    are excluded from the fallback to preserve fail-closed behavior.

    Args:
        request: Incoming request carrying Origin/Referer and host headers.

    Returns:
        ``True`` when candidate origin matches either the request origin or an
        entry in ``settings.allowed_origins``; otherwise ``False``.
    """
    origin = request.headers.get("origin")
    referer = request.headers.get("referer")

    candidate_origin = origin
    if not candidate_origin and referer:
        try:
            parsed_referer = urllib.parse.urlparse(referer)
            if parsed_referer.scheme and parsed_referer.netloc:
                candidate_origin = f"{parsed_referer.scheme}://{parsed_referer.netloc}"
        except Exception:  # nosec B110 - invalid Referer should fail closed below
            candidate_origin = None

    if not candidate_origin:
        return False

    parsed_candidate = urllib.parse.urlparse(candidate_origin)
    if not parsed_candidate.scheme or not parsed_candidate.netloc:
        return False

    forwarded_proto = request.headers.get("x-forwarded-proto")
    forwarded_host = request.headers.get("x-forwarded-host")
    request_scheme = (forwarded_proto.split(",")[0].strip() if forwarded_proto else request.url.scheme) or "http"
    request_netloc = (forwarded_host.split(",")[0].strip() if forwarded_host else request.headers.get("host")) or request.url.netloc

    candidate_parts = normalize_origin_parts(parsed_candidate.scheme, parsed_candidate.netloc)
    request_parts = normalize_origin_parts(request_scheme, request_netloc)
    if candidate_parts == request_parts:
        return True

    # Fallback: accept origins explicitly listed in settings.allowed_origins.
    # Handles reverse-proxy deployments where forwarded headers may not
    # accurately reflect the external scheme/host.
    for allowed in settings.allowed_origins:
        # Normalize each allowed origin to avoid config surprises such as
        # ["https://a.com "] or [" null "], which could otherwise be
        # mis-parsed or skipped.
        allowed_normalized = str(allowed).strip()
        if not allowed_normalized or allowed_normalized == "*" or allowed_normalized.casefold() == "null":
            continue
        try:
            allowed_parsed = urllib.parse.urlparse(allowed_normalized if "://" in allowed_normalized else f"https://{allowed_normalized}")
            if not allowed_parsed.scheme or not allowed_parsed.netloc:
                continue
            if candidate_parts == normalize_origin_parts(allowed_parsed.scheme, allowed_parsed.netloc):
                return True
        except Exception:  # nosec B112 - malformed allowed_origins entry should not crash
            continue

    return False


def _set_admin_csrf_cookie(request: Request, response: Response, *, user_id: str | None = None, session_id: str | None = None) -> str:
    """Set or refresh admin CSRF cookie and return token value.

    Args:
        request: Incoming request used for existing token and path scoping.
        response: Outgoing response where the cookie will be written.
        user_id: Optional authenticated user binding for HMAC CSRF tokens.
        session_id: Optional JWT session binding for HMAC CSRF tokens.

    Returns:
        CSRF token value stored in the response cookie.
    """
    if user_id and session_id:
        csrf_token = get_csrf_service().generate_csrf_token(user_id=user_id, session_id=session_id)
    else:
        existing_token = request.cookies.get(ADMIN_CSRF_COOKIE_NAME)
        csrf_token = existing_token if isinstance(existing_token, str) and len(existing_token) >= 32 else secrets.token_urlsafe(32)

    use_secure = (settings.environment == "production") or settings.secure_cookies
    max_age = max(300, int(getattr(settings, "token_expiry", 60)) * 60)
    response.set_cookie(
        key=ADMIN_CSRF_COOKIE_NAME,
        value=csrf_token,
        max_age=max_age,
        path=_admin_cookie_path(request),
        httponly=False,
        secure=use_secure,
        samesite="strict",
    )
    return csrf_token


def _clear_admin_csrf_cookie(request: Request, response: Response) -> None:
    """Clear admin CSRF cookie.

    Args:
        request: Incoming request used to compute cookie path.
        response: Outgoing response where cookie deletion is applied.
    """
    use_secure = (settings.environment == "production") or settings.secure_cookies
    response.delete_cookie(
        key=ADMIN_CSRF_COOKIE_NAME,
        path=_admin_cookie_path(request),
        secure=use_secure,
        httponly=False,
        samesite="strict",
    )


async def enforce_admin_csrf(request: Request) -> None:
    """Enforce CSRF protections for cookie-authenticated admin mutations.

    Args:
        request: Incoming admin request to validate.

    Returns:
        ``None`` when validation passes.

    Raises:
        HTTPException: If origin validation fails or CSRF token validation fails.
    """
    if request.method.upper() in {"GET", "HEAD", "OPTIONS", "TRACE"}:
        return

    session_cookie = request.cookies.get("jwt_token") or request.cookies.get("access_token")
    request_path = getattr(request.url, "path", "") or ""
    is_login_post = request_path.rstrip("/").endswith("/admin/login")
    if not session_cookie and not is_login_post:
        # CSRF is relevant only for browser cookie auth. Token-auth API calls
        # without session cookies are not subject to browser CSRF. The login
        # POST is the one exception: it is pre-auth (no session cookie exists
        # yet) but still a state-changing browser action, so it is validated
        # against the pre-auth nonce minted by admin_login_page's GET.
        return

    if not _request_origin_matches(request):
        raise HTTPException(status_code=403, detail="CSRF origin validation failed")

    csrf_cookie = request.cookies.get(ADMIN_CSRF_COOKIE_NAME)
    if not isinstance(csrf_cookie, str) or not csrf_cookie:
        raise HTTPException(status_code=403, detail="CSRF token cookie missing")

    submitted_token = request.headers.get(ADMIN_CSRF_HEADER_NAME)
    if not submitted_token:
        content_type = (request.headers.get("content-type") or "").lower()
        if "application/x-www-form-urlencoded" in content_type:
            try:
                form = await request.form()
                form_token = form.get(ADMIN_CSRF_FORM_FIELD)
                if isinstance(form_token, str):
                    submitted_token = form_token
            except Exception:
                submitted_token = None

    if not isinstance(submitted_token, str) or not submitted_token or not secrets.compare_digest(submitted_token, csrf_cookie):
        raise HTTPException(status_code=403, detail="CSRF token validation failed")
