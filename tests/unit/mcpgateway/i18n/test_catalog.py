# -*- coding: utf-8 -*-
"""Location: ./tests/unit/mcpgateway/i18n/test_catalog.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Locale catalog integrity tests.

The English catalog is the baseline. Every other locale must define the same
keys and the same ``{placeholder}`` names. A missing key falls back to English at
runtime, so without these tests a translation gap would only show up as an
untranslated string in the UI.
"""

# Standard
import re
from types import MappingProxyType

# Third-Party
import pytest

# First-Party
from mcpgateway.i18n import catalog as catalog_module
from mcpgateway.i18n import DEFAULT_LOCALE, LOCALE_COOKIE_NAME, SUPPORTED_LOCALES, clear_catalog_cache, load_catalog, normalize_locale, parse_accept_language, resolve_locale, set_locale, t, translated_catalog

PLACEHOLDER = re.compile(r"\{(\w+)\}")


@pytest.fixture(autouse=True)
def _reset_catalog_cache():
    """Reload catalogs from disk around each test."""
    clear_catalog_cache()
    yield
    clear_catalog_cache()


def _baseline_keys() -> set:
    """Return the key set of the English baseline catalog."""
    return set(load_catalog(DEFAULT_LOCALE))


def test_baseline_catalog_is_not_empty():
    """The English baseline must exist; every other check depends on it."""
    assert len(_baseline_keys()) > 0


@pytest.mark.parametrize("locale", sorted(SUPPORTED_LOCALES))
def test_every_supported_locale_has_a_catalog(locale):
    """Each advertised locale must ship a catalog file."""
    assert load_catalog(locale), f"locale {locale!r} has no catalog entries"


@pytest.mark.parametrize("locale", sorted(set(SUPPORTED_LOCALES) - {DEFAULT_LOCALE}))
def test_locales_define_the_same_keys_as_the_baseline(locale):
    """A locale must not add or drop keys relative to the English baseline."""
    baseline = _baseline_keys()
    other = set(load_catalog(locale))

    missing = sorted(baseline - other)
    extra = sorted(other - baseline)

    assert not missing, f"{locale} is missing keys present in {DEFAULT_LOCALE}: {missing[:10]}"
    assert not extra, f"{locale} defines keys absent from {DEFAULT_LOCALE}: {extra[:10]}"


@pytest.mark.parametrize("locale", sorted(SUPPORTED_LOCALES))
def test_catalog_values_are_non_empty_strings(locale):
    """A blank value would render as an empty label, so reject it."""
    blank = sorted(key for key, value in load_catalog(locale).items() if not isinstance(value, str) or not value.strip())
    assert not blank, f"{locale} has blank values: {blank[:10]}"


@pytest.mark.parametrize("locale", sorted(set(SUPPORTED_LOCALES) - {DEFAULT_LOCALE}))
def test_translated_values_keep_the_baseline_placeholders(locale):
    """Placeholder names must survive translation, or interpolation silently drops data."""
    baseline = load_catalog(DEFAULT_LOCALE)
    translated = load_catalog(locale)

    mismatched = {key: (sorted(PLACEHOLDER.findall(baseline[key])), sorted(PLACEHOLDER.findall(value))) for key, value in translated.items() if key in baseline and sorted(PLACEHOLDER.findall(baseline[key])) != sorted(PLACEHOLDER.findall(value))}

    assert not mismatched, f"{locale} changed placeholder names: {mismatched}"


def test_translated_catalog_covers_every_baseline_key():
    """The catalog embedded for the browser must be complete for any locale."""
    baseline = _baseline_keys()
    for locale in sorted(SUPPORTED_LOCALES):
        assert baseline <= set(translated_catalog(locale)), f"{locale} catalog is incomplete after merging {DEFAULT_LOCALE}"


def test_missing_key_returns_the_key_and_does_not_raise():
    """An unknown key must be visible rather than fatal."""
    assert t("no.such.key.exists") == "no.such.key.exists"


def test_missing_key_falls_back_to_the_baseline_locale(monkeypatch):
    """A key that a locale has not translated yet still resolves from English.

    Key parity is enforced by another test, so a partial catalog is simulated
    here: it is the state a translator ships mid-way through a language.
    """
    baseline = load_catalog(DEFAULT_LOCALE)
    key = sorted(baseline)[0]

    real_load = catalog_module.load_catalog

    def partial_catalog(locale):
        if locale == "zh-CN":
            return MappingProxyType({})
        return real_load(locale)

    monkeypatch.setattr(catalog_module, "load_catalog", partial_catalog)
    set_locale("zh-CN")
    try:
        assert t(key) == baseline[key]
    finally:
        set_locale(DEFAULT_LOCALE)


def test_placeholder_rendering_substitutes_values():
    """Values pass straight into ``str.format``."""
    set_locale(DEFAULT_LOCALE)
    try:
        assert t("common.toast.requestFailed", error="timeout") == "Request failed: timeout"
    finally:
        set_locale(DEFAULT_LOCALE)


def test_placeholder_rendering_survives_a_missing_argument():
    """A caller that omits an argument must not break page rendering."""
    set_locale(DEFAULT_LOCALE)
    try:
        assert t("common.toast.requestFailed") == "Request failed: {error}"
    finally:
        set_locale(DEFAULT_LOCALE)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("en", "en"),
        ("en-US", "en"),
        ("zh", "zh-CN"),
        ("zh-CN", "zh-CN"),
        ("zh-Hans", "zh-CN"),
        ("zh-Hans-CN", "zh-CN"),
        ("ZH-cn", "zh-CN"),
        ("fr", None),
        ("", None),
        (None, None),
    ],
)
def test_normalize_locale(raw, expected):
    """Locale tags and common aliases map to a supported locale."""
    assert normalize_locale(raw) == expected


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ("zh-CN,zh;q=0.9,en;q=0.8", "zh-CN"),
        ("en-US,en;q=0.9", "en"),
        ("fr-FR,fr;q=1.0,zh;q=0.2", "zh-CN"),
        ("fr-FR", None),
        ("", None),
        (None, None),
    ],
)
def test_parse_accept_language(header, expected):
    """The best supported language in the header wins."""
    assert parse_accept_language(header) == expected


def test_resolve_locale_cookie_wins_over_header():
    """The cookie is the authoritative source when both are present."""
    assert resolve_locale(cookie_value="zh-CN", accept_language="en-US") == "zh-CN"
    assert resolve_locale(cookie_value="en", accept_language="zh-CN") == "en"


def test_resolve_locale_falls_back_to_default():
    """Nothing usable resolves to the default locale, never to an error."""
    assert resolve_locale() == DEFAULT_LOCALE
    assert resolve_locale(cookie_value="fr", accept_language="de-DE") == DEFAULT_LOCALE


def test_locale_cookie_name_is_stable():
    """The cookie name is a persisted contract; changing it would discard user choices."""
    assert LOCALE_COOKIE_NAME == "mcpgateway_locale"
