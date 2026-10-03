/**
 * HTMX Client Configuration
 *
 * Registers the HTMX request and response hooks, and wraps `window.fetch` so
 * that same-origin mutations carry the JWT and CSRF headers. Extracted from an
 * inline script in admin.html; `initHtmxClient()` is called by admin.js.
 */

import { getCookie } from "./utils.js";

/**
 * Read the configured bearer-token header name from the server-injected config.
 * @returns {string} Header name, defaulting to `Authorization`.
 */
const getAuthHeaderName = function () {
  return (window.__ADMIN_CONFIG__ && window.__ADMIN_CONFIG__.authHeaderName) || "Authorization";
};

/**
 * Report whether an HTTP method changes state.
 * @param {string} method - HTTP method.
 * @returns {boolean} True for methods other than GET, HEAD, OPTIONS, and TRACE.
 */
const isUnsafeHttpMethod = function (method) {
  const normalized = (method || "GET").toUpperCase();
  return normalized !== "GET" && normalized !== "HEAD" && normalized !== "OPTIONS" && normalized !== "TRACE";
};

/**
 * Report whether a request targets the current origin.
 * @param {string|Request} resource - Fetch resource.
 * @returns {boolean} True when the resolved origin matches `window.location.origin`.
 */
const isSameOriginRequest = function (resource) {
  try {
    if (resource instanceof Request) {
      return new URL(resource.url, window.location.origin).origin === window.location.origin;
    }
    return new URL(String(resource), window.location.origin).origin === window.location.origin;
  } catch (e) {
    return false;
  }
};

/**
 * Allow HTMX to swap rejected responses that ask for a retarget, so the server
 * can render an inline error into the page.
 */
const initErrorSwap = function () {
  document.addEventListener("htmx:beforeSwap", function (evt) {
    const xhr = evt.detail.xhr;
    if (!xhr || xhr.status < 400 || xhr.status >= 500) {
      return;
    }
    const triggerEl = evt.detail.elt;
    const requestEl = evt.detail.requestConfig?.elt;
    const isTeamForm =
      (triggerEl && triggerEl.closest('[data-team-validation="true"]')) ||
      (requestEl && requestEl.closest('[data-team-validation="true"]'));
    const hasRetarget = !!xhr.getResponseHeader("HX-Retarget");
    if (isTeamForm || hasRetarget) {
      evt.detail.shouldSwap = true;
      evt.detail.isError = false;
    }
  });
};

/**
 * Add the same-origin credentials, the JWT, and the CSRF token to every HTMX
 * request.
 */
const initRequestHeaders = function () {
  document.addEventListener("htmx:configRequest", function (evt) {
    evt.detail.credentials = "same-origin"; // pragma: allowlist secret
    evt.detail.headers = evt.detail.headers || {};

    const jwtToken = getCookie("jwt_token");
    if (jwtToken) {
      evt.detail.headers[getAuthHeaderName()] = "Bearer " + jwtToken;
    }

    const csrfToken = getCookie("mcpgateway_csrf_token");
    if (csrfToken) {
      evt.detail.headers["X-CSRF-Token"] = csrfToken;
    }
  });
};

/**
 * Ensure all same-origin fetch mutations carry the CSRF header.
 */
const wrapFetchWithCsrf = function () {
  if (window.__mcpgatewayCsrfFetchWrapped || typeof window.fetch !== "function") {
    return;
  }
  const originalFetch = window.fetch.bind(window);
  window.fetch = function (resource, init = {}) {
    const requestInit = init ? { ...init } : {};
    const methodFromRequest = resource instanceof Request ? resource.method : null;
    const method = (requestInit.method || methodFromRequest || "GET").toUpperCase();
    if (isUnsafeHttpMethod(method) && isSameOriginRequest(resource)) {
      const csrfToken = getCookie("mcpgateway_csrf_token");
      const jwtToken = getCookie("jwt_token");
      if (csrfToken || jwtToken) {
        const nextHeaders = new Headers(requestInit.headers || (resource instanceof Request ? resource.headers : undefined));
        const authHeaderName = getAuthHeaderName();
        if (jwtToken && !nextHeaders.has(authHeaderName)) {
          nextHeaders.set(authHeaderName, "Bearer " + jwtToken);
        }
        if (csrfToken) {
          nextHeaders.set("X-CSRF-Token", csrfToken);
        }
        requestInit.headers = nextHeaders;
      }
    }
    return originalFetch(resource, requestInit);
  };
  window.__mcpgatewayCsrfFetchWrapped = true;
};

/**
 * Add the CSRF token to same-origin non-GET forms as a hidden field.
 */
const initFormCsrf = function () {
  document.addEventListener("submit", function (event) {
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) {
      return;
    }
    const method = (form.getAttribute("method") || "GET").toUpperCase();
    if (!isUnsafeHttpMethod(method)) {
      return;
    }
    const action = form.getAttribute("action") || window.location.href;
    if (!isSameOriginRequest(action)) {
      return;
    }
    const csrfToken = getCookie("mcpgateway_csrf_token");
    if (!csrfToken) {
      return;
    }
    let tokenInput = form.querySelector('input[name="csrf_token"]');
    if (!tokenInput) {
      tokenInput = document.createElement("input");
      tokenInput.type = "hidden";
      tokenInput.name = "csrf_token";
      form.appendChild(tokenInput);
    }
    tokenInput.value = csrfToken;
  });
};

/**
 * Register every HTMX request and response hook. Call once from admin.js.
 */
export const initHtmxClient = function () {
  initErrorSwap();
  initRequestHeaders();
  wrapFetchWithCsrf();
  initFormCsrf();
};

export { getAuthHeaderName, isSameOriginRequest, isUnsafeHttpMethod };
