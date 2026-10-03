/**
 * Unit tests for flashMessages.js module
 * Tests: reading the ?error= / ?success= query parameters, rendering the
 *        notification, and keeping URL-supplied text inert.
 */

import { describe, test, expect, vi, beforeEach, afterEach } from "vitest";

import {
  getFlashParams,
  initFlashMessages,
} from "../../../mcpgateway/admin_ui/flashMessages.js";

beforeEach(() => {
  vi.useFakeTimers();
  document.body.innerHTML = `<div id="global-notification" style="display: none"></div>`;
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe("getFlashParams", () => {
  test("returns null when the query string carries no message", () => {
    expect(getFlashParams("?page=2")).toEqual({ error: null, success: null });
  });

  test("decodes the error and success parameters", () => {
    expect(getFlashParams("?error=Save%20failed&success=Done")).toEqual({
      error: "Save failed",
      success: "Done",
    });
  });
});

describe("initFlashMessages", () => {
  const withSearch = (search) => {
    window.history.replaceState({}, "", `/admin/${search}`);
  };

  test("stays hidden when the URL carries no message", () => {
    withSearch("");
    initFlashMessages();
    const el = document.getElementById("global-notification");
    expect(el.style.display).toBe("none");
    expect(el.childElementCount).toBe(0);
  });

  test("renders an error message and hides it again after five seconds", () => {
    withSearch("?error=Save%20failed");
    initFlashMessages();

    const el = document.getElementById("global-notification");
    expect(el.style.display).toBe("block");
    expect(el.textContent).toContain("Save failed");
    expect(el.querySelector("div").className).toContain("bg-red-50");

    vi.advanceTimersByTime(5000);
    expect(el.style.display).toBe("none");
    expect(el.childElementCount).toBe(0);
  });

  test("renders a success message", () => {
    withSearch("?success=Saved");
    initFlashMessages();
    const el = document.getElementById("global-notification");
    expect(el.querySelector("div").className).toContain("bg-green-50");
    expect(el.textContent).toContain("Saved");
  });

  test("keeps HTML in the message inert", () => {
    withSearch("?error=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E");
    initFlashMessages();

    const el = document.getElementById("global-notification");
    expect(el.querySelector("img")).toBeNull();
    expect(el.textContent).toContain("<img src=x onerror=alert(1)>");
  });

  test("drops the message parameters from the URL after auto-dismiss", () => {
    withSearch("?error=Save%20failed");
    const replaceState = vi.spyOn(window.history, "replaceState");
    initFlashMessages();

    vi.advanceTimersByTime(5000);

    expect(replaceState).toHaveBeenCalledTimes(1);
    expect(String(replaceState.mock.calls[0][2])).not.toContain("error=");
  });
});
