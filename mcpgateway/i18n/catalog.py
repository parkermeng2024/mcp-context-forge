# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/i18n/catalog.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Locale catalog loading and lookup.

Each locale is a flat JSON file mapping a dot-separated key to its text::

    {
      "common.actions.save": "Save",
      "tools.toast.exportFailed": "Export failed: {error}"
    }

The same catalog serves Jinja templates and the admin UI JavaScript runtime, so
a key is translated once for both.

Keys use ``<domain>.<component>.<element>`` naming. Values may carry ``{name}``
placeholders, filled by the caller with ``t("key", name=value)``.
"""

# Standard
import json
import logging
from pathlib import Path
from types import MappingProxyType
from typing import Dict, Mapping, Optional

logger = logging.getLogger(__name__)

#: Directory holding ``<locale>.json`` catalogs.
LOCALES_DIR = Path(__file__).resolve().parent / "locales"

#: Locale used when nothing else resolves, and the fallback for missing keys.
DEFAULT_LOCALE = "en"

#: Supported locales mapped to their display name.
SUPPORTED_LOCALES: Dict[str, str] = {
    "en": "English",
    "zh-CN": "简体中文",
}

#: Cookie holding the visitor's explicit locale choice.
LOCALE_COOKIE_NAME = "mcpgateway_locale"

#: Aliases accepted for a supported locale. Keys are lower-cased inputs.
_LOCALE_ALIASES: Dict[str, str] = {
    "en": "en",
    "en-us": "en",
    "en-gb": "en",
    "en-ca": "en",
    "en-au": "en",
    "zh": "zh-CN",
    "zh-cn": "zh-CN",
    "zh-hans": "zh-CN",
    "zh-sg": "zh-CN",
    "zh-chs": "zh-CN",
    "zh-hant": "zh-CN",
    "zh-tw": "zh-CN",
    "zh-hk": "zh-CN",
}


def normalize_locale(value: Optional[str]) -> Optional[str]:
    """Map a raw locale string to a supported locale.

    Accepts the exact tags plus common aliases such as ``zh``, ``zh-Hans`` and
    ``en-US``. Tags that carry a region resolve to the base language.

    Args:
        value: Raw locale from a cookie or an ``Accept-Language`` entry.

    Returns:
        A key of ``SUPPORTED_LOCALES``, or ``None`` when the value is not supported.

    Examples:
        >>> normalize_locale("zh-CN")
        'zh-CN'
        >>> normalize_locale("zh")
        'zh-CN'
        >>> normalize_locale("zh-Hans")
        'zh-CN'
        >>> normalize_locale("en-US")
        'en'
        >>> normalize_locale("fr") is None
        True
        >>> normalize_locale("") is None
        True
        >>> normalize_locale(None) is None
        True
    """
    if not value:
        return None

    candidate = value.strip().split(";")[0].strip()
    if not candidate:
        return None

    lowered = candidate.lower()

    # Exact match first, so a future region-specific catalog wins over its alias.
    for supported in SUPPORTED_LOCALES:
        if supported.lower() == lowered:
            return supported

    if lowered in _LOCALE_ALIASES:
        return _LOCALE_ALIASES[lowered]

    # Fall back to the base language (for example "zh-Hans-CN" -> "zh").
    base = lowered.split("-")[0].split("_")[0]
    if base in _LOCALE_ALIASES:
        return _LOCALE_ALIASES[base]

    return None


def parse_accept_language(header: Optional[str]) -> Optional[str]:
    """Return the best supported locale in an ``Accept-Language`` header.

    Entries are honoured in quality order. A missing or unparsable quality value
    counts as ``q=1.0``.

    Args:
        header: Raw ``Accept-Language`` header value.

    Returns:
        A key of ``SUPPORTED_LOCALES``, or ``None`` when nothing matches.

    Examples:
        >>> parse_accept_language("zh-CN,zh;q=0.9,en;q=0.8")
        'zh-CN'
        >>> parse_accept_language("fr-FR,fr;q=0.9,en;q=0.5")
        'en'
        >>> parse_accept_language("fr-FR") is None
        True
        >>> parse_accept_language(None) is None
        True
    """
    if not header:
        return None

    ranked = []
    for index, entry in enumerate(header.split(",")):
        entry = entry.strip()
        if not entry:
            continue
        parts = entry.split(";")
        tag = parts[0].strip()
        quality = 1.0
        for param in parts[1:]:
            param = param.strip()
            if param.startswith("q="):
                try:
                    quality = float(param[2:])
                except ValueError:
                    quality = 0.0
        # ``index`` keeps the original order for equal quality values.
        ranked.append((-quality, index, tag))

    for _, _, tag in sorted(ranked):
        locale = normalize_locale(tag)
        if locale:
            return locale

    return None


def resolve_locale(cookie_value: Optional[str] = None, accept_language: Optional[str] = None) -> str:
    """Resolve the locale for a request from its cookie, then its header.

    The explicit cookie choice wins. ``Accept-Language`` is the fallback, and
    ``DEFAULT_LOCALE`` the final answer, so this function never fails.

    Args:
        cookie_value: Value of the ``LOCALE_COOKIE_NAME`` cookie, if present.
        accept_language: Raw ``Accept-Language`` header, if present.

    Returns:
        A key of ``SUPPORTED_LOCALES``.

    Examples:
        >>> resolve_locale("zh-CN", "en-US")
        'zh-CN'
        >>> resolve_locale(None, "zh-CN,zh;q=0.9")
        'zh-CN'
        >>> resolve_locale(None, None)
        'en'
        >>> resolve_locale("fr", "de")
        'en'
    """
    return normalize_locale(cookie_value) or parse_accept_language(accept_language) or DEFAULT_LOCALE


def load_catalog(locale: str) -> Mapping[str, str]:
    """Load the catalog for one locale.

    Results are cached for the process lifetime. A missing or malformed file
    yields an empty mapping rather than an error, so a bad catalog degrades to
    the fallback locale instead of breaking the request.

    Args:
        locale: A key of ``SUPPORTED_LOCALES``.

    Returns:
        Read-only mapping of key to text.

    Examples:
        >>> "common.actions.save" in load_catalog("en")
        True
        >>> dict(load_catalog("no-such-locale"))
        {}
    """
    cached = _CATALOG_CACHE.get(locale)
    if cached is not None:
        return cached

    path = LOCALES_DIR / f"{locale}.json"
    data: Dict[str, str] = {}
    try:
        with path.open(encoding="utf-8") as handle:
            raw = json.load(handle)
        if isinstance(raw, dict):
            data = {str(key): str(value) for key, value in raw.items()}
        else:
            logger.warning("Locale catalog %s is not a JSON object; ignoring", path)
    except FileNotFoundError:
        logger.warning("Locale catalog not found: %s", path)
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to load locale catalog %s: %s", path, exc)

    frozen = MappingProxyType(data)
    _CATALOG_CACHE[locale] = frozen
    return frozen


#: Process-lifetime catalog cache, keyed by locale.
_CATALOG_CACHE: Dict[str, Mapping[str, str]] = {}

#: Keys already reported as missing, so each one logs at most once.
_MISSING_KEYS_REPORTED: set = set()


def clear_catalog_cache() -> None:
    """Drop the cached catalogs and the missing-key log memory.

    Call this after editing a catalog file, or between tests.

    Examples:
        >>> _ = load_catalog("en")
        >>> clear_catalog_cache()
        >>> "common.actions.save" in load_catalog("en")
        True
    """
    _CATALOG_CACHE.clear()
    _MISSING_KEYS_REPORTED.clear()


def lookup(locale: str, key: str) -> Optional[str]:
    """Look up one key, falling back to ``DEFAULT_LOCALE``.

    Args:
        locale: Preferred locale.
        key: Dot-separated catalog key.

    Returns:
        The translated text, or ``None`` when no catalog defines the key.

    Examples:
        >>> lookup("zh-CN", "common.actions.cancel")
        '取消'
        >>> lookup("zh-CN", "no.such.key") is None
        True
    """
    text = load_catalog(locale).get(key)
    if text is None and locale != DEFAULT_LOCALE:
        text = load_catalog(DEFAULT_LOCALE).get(key)
    return text


def report_missing_key(locale: str, key: str) -> None:
    """Log a missing key once per process.

    Args:
        locale: Locale that was asked for the key.
        key: The key that no catalog defines.
    """
    marker = f"{locale}:{key}"
    if marker in _MISSING_KEYS_REPORTED:
        return
    _MISSING_KEYS_REPORTED.add(marker)
    logger.warning("Missing i18n key %r for locale %r", key, locale)


def catalog_for(locale: str) -> Dict[str, str]:
    """Return the complete key set for a locale, with English filling any gaps.

    The admin UI JavaScript runtime receives this mapping, so a partially
    translated locale still renders every string.

    Args:
        locale: Preferred locale.

    Returns:
        Mutable mapping of key to text.

    Examples:
        >>> catalog = catalog_for("zh-CN")
        >>> catalog["common.actions.save"]
        '保存'
        >>> catalog["common.actions.cancel"]
        '取消'
    """
    merged = dict(load_catalog(DEFAULT_LOCALE))
    if locale != DEFAULT_LOCALE:
        merged.update(load_catalog(locale))
    return merged
