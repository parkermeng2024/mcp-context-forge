# -*- coding: utf-8 -*-
"""Location: ./tests/unit/mcpgateway/middleware/test_locale_middleware.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

LocaleMiddleware behaviour tests.

The middleware only sets a display preference, so these tests check that the
request language reaches handlers and that a request without a usable language
still succeeds in English.
"""

# Third-Party
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

# First-Party
from mcpgateway.i18n import DEFAULT_LOCALE, get_locale, LOCALE_COOKIE_NAME, t
from mcpgateway.middleware.locale_middleware import LocaleMiddleware


async def _locale_endpoint(request):
    """Return the locale the middleware resolved for this request."""
    return PlainTextResponse(get_locale())


async def _translated_endpoint(request):
    """Return a translated string, proving ``t`` sees the middleware locale."""
    return PlainTextResponse(t("nav.overview"))


def _client() -> TestClient:
    """Build a minimal app wrapped in LocaleMiddleware."""
    app = Starlette(
        routes=[Route("/locale", _locale_endpoint), Route("/translated", _translated_endpoint)],
        middleware=[Middleware(LocaleMiddleware)],
    )
    return TestClient(app)


def test_cookie_locale_is_used():
    """An explicit cookie choice wins."""
    response = _client().get("/locale", cookies={LOCALE_COOKIE_NAME: "zh-CN"})
    assert response.status_code == 200
    assert response.text == "zh-CN"


def test_accept_language_is_used_without_a_cookie():
    """The header is the fallback when no cookie is present."""
    response = _client().get("/locale", headers={"accept-language": "zh-CN,zh;q=0.9,en;q=0.8"})
    assert response.status_code == 200
    assert response.text == "zh-CN"


def test_cookie_overrides_accept_language():
    """The cookie outranks the header."""
    response = _client().get("/locale", cookies={LOCALE_COOKIE_NAME: "en"}, headers={"accept-language": "zh-CN"})
    assert response.status_code == 200
    assert response.text == "en"


def test_unsupported_language_falls_back_to_default():
    """An unsupported language must not fail the request."""
    response = _client().get("/locale", cookies={LOCALE_COOKIE_NAME: "fr"}, headers={"accept-language": "de-DE"})
    assert response.status_code == 200
    assert response.text == DEFAULT_LOCALE


def test_translation_uses_the_request_locale():
    """``t`` reads the locale the middleware stored."""
    response = _client().get("/translated", cookies={LOCALE_COOKIE_NAME: "zh-CN"})
    assert response.text == "概览"


def test_locale_does_not_leak_between_requests():
    """Each request resolves its own locale."""
    client = _client()
    assert client.get("/locale", cookies={LOCALE_COOKIE_NAME: "zh-CN"}).text == "zh-CN"
    assert client.get("/locale").text == DEFAULT_LOCALE
