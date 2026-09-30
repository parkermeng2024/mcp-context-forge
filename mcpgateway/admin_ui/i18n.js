/**
 * Client-side i18n runtime for the ContextForge admin UI.
 *
 * The server renders the catalog for the active locale into `window.__I18N__`
 * (see `templates/_i18n_config.html`). Because Jinja templates and this runtime
 * read the same JSON catalogs, a key is translated once for both.
 *
 * Usage:
 *   import { t } from "./i18n.js";
 *   showToast(t("common.toast.saveFailed", { error: message }), "error");
 *
 * Switching the language is owned by `templates/_locale_switcher.html`, which
 * works on pages that never load this bundle (the login page).
 */

let catalog = {};
let locale = "en";
let supported = {};

/**
 * Load the catalog the server embedded in the page.
 *
 * Called automatically on import when `window.__I18N__` is present.
 *
 * @param {{locale?: string, catalog?: Object, supported?: Object}} config - Embedded configuration.
 * @returns {{locale: string, catalog: Object}} The active configuration.
 */
export function initI18n(config = {}) {
  if (config && typeof config === "object") {
    locale = config.locale || "en";
    catalog = config.catalog || {};
    supported = config.supported || {};
  }
  return { locale, catalog };
}

/**
 * Return the active locale.
 *
 * @returns {string} Active locale tag, for example `"zh-CN"`.
 */
export function getLocale() {
  return locale;
}

/**
 * Return the supported locales mapped to their display names.
 *
 * @returns {Object} For example `{ en: "English", "zh-CN": "简体中文" }`.
 */
export function getSupportedLocales() {
  return supported;
}

/**
 * Translate a catalog key.
 *
 * Returns the key itself when the catalog has no entry, so a missing
 * translation is visible instead of breaking the call.
 *
 * @param {string} key - Dot-separated catalog key, for example `"nav.tools"`.
 * @param {Object} [params] - Values for `{name}` placeholders in the value.
 * @returns {string} Translated text.
 */
export function t(key, params) {
  const text = catalog[key];
  if (typeof text !== "string") {
    return key;
  }
  if (!params) {
    return text;
  }
  return text.replace(/\{(\w+)\}/g, (match, name) => (Object.prototype.hasOwnProperty.call(params, name) ? String(params[name]) : match));
}

// The embedded configuration is available before this module runs, because the
// template emits it ahead of the bundle script tag.
if (typeof window !== "undefined" && window.__I18N__) {
  initI18n(window.__I18N__);
}
