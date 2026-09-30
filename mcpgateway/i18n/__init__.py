# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/i18n/__init__.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Internationalization (i18n) support for ContextForge.

Templates and Python code call :func:`t` with a catalog key. The active locale
comes from a :class:`contextvars.ContextVar` that ``LocaleMiddleware`` sets once
per request, so no call site has to pass a locale around.

    Jinja:  ``{{ t("common.actions.save") }}``
    Python: ``t("tools.toast.exportFailed", error=str(exc))``

The admin UI JavaScript runtime reads the same catalogs through
:func:`mcpgateway.i18n.catalog.catalog_for`, which the page embeds at render
time. See ``docs/docs/architecture/adr/`` for the design decision.
"""

# Standard
from contextvars import ContextVar
import logging
from typing import Dict, Optional

# First-Party
from mcpgateway.i18n.catalog import (  # noqa: F401  (re-exported public names)
    DEFAULT_LOCALE,
    LOCALE_COOKIE_NAME,
    SUPPORTED_LOCALES,
    catalog_for,
    clear_catalog_cache,
    load_catalog,
    normalize_locale,
    parse_accept_language,
    report_missing_key,
    resolve_locale,
)
from mcpgateway.i18n.catalog import lookup as _lookup

logger = logging.getLogger(__name__)

__all__ = [
    "DEFAULT_LOCALE",
    "LOCALE_COOKIE_NAME",
    "SUPPORTED_LOCALES",
    "catalog_for",
    "clear_catalog_cache",
    "get_locale",
    "load_catalog",
    "namespace_catalog",
    "normalize_locale",
    "parse_accept_language",
    "reset_locale",
    "resolve_locale",
    "set_locale",
    "t",
    "translated_catalog",
]

#: Active locale for the current request. Async-safe, so concurrent requests
#: in different languages do not interfere.
_locale_context: ContextVar[Optional[str]] = ContextVar("mcpgateway_locale", default=None)


def get_locale() -> str:
    """Return the active locale, defaulting to English outside a request.

    Returns:
        A key of ``SUPPORTED_LOCALES``.

    Examples:
        >>> reset_locale()
        >>> get_locale()
        'en'
        >>> set_locale("zh-CN")
        >>> get_locale()
        'zh-CN'
        >>> reset_locale()
    """
    return _locale_context.get() or DEFAULT_LOCALE


def set_locale(locale: str) -> None:
    """Set the active locale for the current context.

    Args:
        locale: A key of ``SUPPORTED_LOCALES``, or any value ``normalize_locale`` maps to one.

    Examples:
        >>> set_locale("zh-CN")
        >>> get_locale()
        'zh-CN'
        >>> set_locale("zh")
        >>> get_locale()
        'zh-CN'
        >>> reset_locale()
    """
    _locale_context.set(normalize_locale(locale) or DEFAULT_LOCALE)


def reset_locale() -> None:
    """Clear the active locale, restoring the English default.

    Examples:
        >>> set_locale("zh-CN")
        >>> reset_locale()
        >>> get_locale()
        'en'
    """
    _locale_context.set(None)


def t(key: str, **params: object) -> str:
    """Translate a catalog key into the active locale.

    Falls back to English, then to the key itself, so a missing translation
    shows the key rather than raising. ``{name}`` placeholders in the catalog
    value are filled from ``params``.

    Args:
        key: Dot-separated catalog key, for example ``common.actions.save``.
        **params: Values for ``{name}`` placeholders in the catalog value.

    Returns:
        The translated text, or ``key`` when no catalog defines it.

    Examples:
        >>> reset_locale()
        >>> t("common.actions.save")
        'Save'
        >>> set_locale("zh-CN")
        >>> t("common.actions.save")
        '保存'
        >>> t("common.toast.requestFailed", error="timeout")
        '请求失败：timeout'
        >>> reset_locale()
        >>> t("no.such.key")
        'no.such.key'
    """
    locale = get_locale()
    text = _lookup(locale, key)
    if text is None:
        report_missing_key(locale, key)
        return key

    if params:
        try:
            return text.format(**params)
        except (KeyError, IndexError, ValueError) as exc:
            # A malformed placeholder must not break page rendering.
            logger.warning("i18n value for %r has a bad placeholder (%s); using raw value", key, exc)

    return text


def translated_catalog(locale: Optional[str] = None) -> Dict[str, str]:
    """Return the full catalog for a locale, ready to embed for the browser.

    Args:
        locale: Locale to build the catalog for. Defaults to the active locale.

    Returns:
        Mapping of key to text, with English filling any untranslated key.

    Examples:
        >>> reset_locale()
        >>> translated_catalog()["common.actions.save"]
        'Save'
        >>> translated_catalog("zh-CN")["common.actions.cancel"]
        '取消'
    """
    return catalog_for(locale or get_locale())


def locale_display_names() -> Dict[str, str]:
    """Return the supported locales mapped to their display names.

    Returns:
        Mapping usable by a language switcher.

    Examples:
        >>> sorted(locale_display_names())
        ['en', 'zh-CN']
    """
    return dict(SUPPORTED_LOCALES)


def namespace_catalog(prefix: str) -> Dict[str, str]:
    """Return the catalog entries under a prefix, with the prefix removed.

    Pages that carry their own inline script -- the login page, for example --
    embed only the keys they need instead of the whole catalog.

    Args:
        prefix: Key prefix to select, for example ``login.``.

    Returns:
        Mapping of remaining key part to text for the active locale.

    Examples:
        >>> reset_locale()
        >>> namespace_catalog("login.")["submit"]
        'Sign In'
        >>> set_locale("zh-CN")
        >>> namespace_catalog("login.")["submit"]
        '登录'
        >>> reset_locale()
        >>> namespace_catalog("no.such.prefix")
        {}
    """
    return {key[len(prefix) :]: value for key, value in translated_catalog().items() if key.startswith(prefix)}
