/**
 * Unit tests for htmxClient.js
 * Tests: the HTMX request/response hooks, the CSRF fetch wrapper, and the form
 *        CSRF field injection.
 */

import { describe, test, expect, vi, beforeEach, afterEach } from "vitest";

import {
  getAuthHeaderName,
  initHtmxClient,
  isSameOriginRequest,
  isUnsafeHttpMethod,
} from "../../../mcpgateway/admin_ui/htmxClient.js";

const clearCookies = function () {
  document.cookie.split(";").forEach((cookie) => {
    const name = cookie.split("=")[0].trim();
    document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/`;
  });
};

let fetchStub;

beforeEach(() => {
  clearCookies();
  document.body.innerHTML = "";
  window.__ADMIN_CONFIG__ = { authHeaderName: "X-Auth" };
  window.__mcpgatewayCsrfFetchWrapped = false;
  fetchStub = vi.fn().mockResolvedValue({ ok: true });
  vi.stubGlobal("fetch", fetchStub);
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  delete window.__ADMIN_CONFIG__;
  delete window.__mcpgatewayCsrfFetchWrapped;
  clearCookies();
});

describe("isUnsafeHttpMethod", () => {
  test("treats GET, HEAD, OPTIONS and TRACE as safe", () => {
    for (const method of ["GET", "HEAD", "OPTIONS", "TRACE", "get"]) {
      expect(isUnsafeHttpMethod(method)).toBe(false);
    }
  });

  test("treats mutating methods as unsafe", () => {
    for (const method of ["POST", "PUT", "PATCH", "DELETE"]) {
      expect(isUnsafeHttpMethod(method)).toBe(true);
    }
  });

  test("defaults a missing method to GET", () => {
    expect(isUnsafeHttpMethod(undefined)).toBe(false);
  });
});

describe("isSameOriginRequest", () => {
  test("accepts a same-origin relative path", () => {
    expect(isSameOriginRequest("/admin/tools")).toBe(true);
  });

  test("rejects another origin", () => {
    expect(isSameOriginRequest("https://evil.example/steal")).toBe(false);
  });
});

describe("getAuthHeaderName", () => {
  test("reads the configured header name", () => {
    expect(getAuthHeaderName()).toBe("X-Auth");
  });

  test("defaults to Authorization without config", () => {
    delete window.__ADMIN_CONFIG__;
    expect(getAuthHeaderName()).toBe("Authorization");
  });
});

describe("initHtmxClient", () => {
  test("htmx:configRequest adds credentials, the JWT, and the CSRF token", () => {
    document.cookie = "jwt_token=abc123; path=/";
    document.cookie = "mcpgateway_csrf_token=csrf456; path=/";
    initHtmxClient();

    const detail = { headers: {} };
    document.dispatchEvent(new CustomEvent("htmx:configRequest", { detail }));

    expect(detail.credentials).toBe("same-origin");
    expect(detail.headers["X-Auth"]).toBe("Bearer abc123");
    expect(detail.headers["X-CSRF-Token"]).toBe("csrf456");
  });

  test("htmx:beforeSwap swaps a rejected request that asks for a retarget", () => {
    initHtmxClient();

    const detail = {
      xhr: { status: 403, getResponseHeader: () => "team-members" },
      elt: null,
      requestConfig: null,
      shouldSwap: false,
      isError: true,
    };
    document.dispatchEvent(new CustomEvent("htmx:beforeSwap", { detail }));

    expect(detail.shouldSwap).toBe(true);
    expect(detail.isError).toBe(false);
  });

  test("htmx:beforeSwap leaves a successful response alone", () => {
    initHtmxClient();

    const detail = {
      xhr: { status: 200, getResponseHeader: () => null },
      elt: null,
      requestConfig: null,
      shouldSwap: true,
      isError: false,
    };
    document.dispatchEvent(new CustomEvent("htmx:beforeSwap", { detail }));

    expect(detail.shouldSwap).toBe(true);
    expect(detail.isError).toBe(false);
  });

  test("wraps fetch so same-origin mutations carry the CSRF token", async () => {
    document.cookie = "mcpgateway_csrf_token=csrf456; path=/";
    document.cookie = "jwt_token=abc123; path=/";
    initHtmxClient();

    await window.fetch("/admin/tools", { method: "POST" });

    const [, init] = fetchStub.mock.calls[0];
    expect(init.headers.get("X-CSRF-Token")).toBe("csrf456");
    expect(init.headers.get("X-Auth")).toBe("Bearer abc123");
  });

  test("leaves a safe same-origin request untouched", async () => {
    document.cookie = "mcpgateway_csrf_token=csrf456; path=/";
    initHtmxClient();

    await window.fetch("/admin/tools", { method: "GET" });

    const [, init] = fetchStub.mock.calls[0];
    expect(init.headers).toBeUndefined();
  });

  test("adds a hidden csrf_token field to a same-origin non-GET form", () => {
    document.cookie = "mcpgateway_csrf_token=csrf456; path=/";
    initHtmxClient();
    document.body.innerHTML = '<form method="post" action="/admin/tools"><button>Save</button></form>';
    const form = document.querySelector("form");

    form.dispatchEvent(new Event("submit", { bubbles: true }));

    const tokenInput = form.querySelector('input[name="csrf_token"]');
    expect(tokenInput).not.toBeNull();
    expect(tokenInput.value).toBe("csrf456");
  });
});
