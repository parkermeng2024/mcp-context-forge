# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/middleware/locale_middleware.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Locale resolution middleware.

Resolves the request locale and stores it in the i18n context variable, so that
:func:`mcpgateway.i18n.t` returns text in the right language from any template or
service reached during the request.

Resolution order:

1. The ``mcpgateway_locale`` cookie -- the visitor's explicit choice.
2. The ``Accept-Language`` header -- first supported language wins.
3. English -- the default, so this middleware never rejects a request.

The middleware only sets a display preference. It does not read or write
credentials, and it does not influence authentication or authorization.
"""

# Standard
import logging
from typing import Callable

# Third-Party
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

# First-Party
from mcpgateway.i18n import LOCALE_COOKIE_NAME, reset_locale, resolve_locale, set_locale

logger = logging.getLogger(__name__)


class LocaleMiddleware(BaseHTTPMiddleware):
    """Attach the resolved locale to the i18n context for each request.

    The locale is read from the request and stored in a context variable for the
    duration of the request. Concurrent requests keep their own locale because
    context variables are isolated per async task.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Resolve the locale, then run the request.

        Args:
            request: The incoming HTTP request.
            call_next: Callable that runs the next middleware or the route.

        Returns:
            The response produced downstream.
        """
        locale = resolve_locale(
            cookie_value=request.cookies.get(LOCALE_COOKIE_NAME),
            accept_language=request.headers.get("accept-language"),
        )
        set_locale(locale)
        try:
            return await call_next(request)
        finally:
            reset_locale()
