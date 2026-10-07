/**
 * Unit tests for components/main-layout.js
 * Tests: mainLayout factory, init resize listener, sidebarCollapsed persistence
 */

import { describe, test, expect, vi, beforeEach, afterEach } from "vitest";
import { mainLayout } from "../../../mcpgateway/admin_ui/components/main-layout.js";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeComponent() {
  const component = mainLayout();
  const watchCallbacks = {};
  component.$watch = vi.fn((prop, cb) => {
    watchCallbacks[prop] = cb;
  });
  return { component, watchCallbacks };
}

function makeLocalStorage() {
  const values = new Map();
  return {
    clear: () => values.clear(),
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, String(value)),
  };
}

// ─── Setup / teardown ─────────────────────────────────────────────────────────

let originalInnerWidth;

beforeEach(() => {
  originalInnerWidth = window.innerWidth;
  vi.stubGlobal("localStorage", makeLocalStorage());
  localStorage.clear();
});

afterEach(() => {
  Object.defineProperty(window, "innerWidth", {
    value: originalInnerWidth,
    writable: true,
    configurable: true,
  });
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  delete window.Admin;
});

// ─── Factory ──────────────────────────────────────────────────────────────────

describe("mainLayout factory", () => {
  test("returns sidebarOpen as true", () => {
    const component = mainLayout();
    expect(component.sidebarOpen).toBe(true);
  });

  test("returns sidebarCollapsed as false", () => {
    const component = mainLayout();
    expect(component.sidebarCollapsed).toBe(false);
  });

  test("returns isDesktop true when innerWidth is 1024", () => {
    Object.defineProperty(window, "innerWidth", { value: 1024, writable: true, configurable: true });
    const component = mainLayout();
    expect(component.isDesktop).toBe(true);
  });

  test("returns isDesktop true when innerWidth is above 1024", () => {
    Object.defineProperty(window, "innerWidth", { value: 1440, writable: true, configurable: true });
    const component = mainLayout();
    expect(component.isDesktop).toBe(true);
  });

  test("returns isDesktop false when innerWidth is below 1024", () => {
    Object.defineProperty(window, "innerWidth", { value: 768, writable: true, configurable: true });
    const component = mainLayout();
    expect(component.isDesktop).toBe(false);
  });

  test("exposes an init method", () => {
    const component = mainLayout();
    expect(typeof component.init).toBe("function");
  });

  test("does not throw on construction", () => {
    expect(() => mainLayout()).not.toThrow();
  });
});

// ─── init — resize listener ───────────────────────────────────────────────────

describe("init — resize listener", () => {
  test("updates isDesktop to true when resized to >= 1024", () => {
    Object.defineProperty(window, "innerWidth", { value: 800, writable: true, configurable: true });
    const { component } = makeComponent();
    component.init();

    Object.defineProperty(window, "innerWidth", { value: 1280, writable: true, configurable: true });
    window.dispatchEvent(new Event("resize"));

    expect(component.isDesktop).toBe(true);
  });

  test("updates isDesktop to false when resized to < 1024", () => {
    Object.defineProperty(window, "innerWidth", { value: 1280, writable: true, configurable: true });
    const { component } = makeComponent();
    component.init();

    Object.defineProperty(window, "innerWidth", { value: 600, writable: true, configurable: true });
    window.dispatchEvent(new Event("resize"));

    expect(component.isDesktop).toBe(false);
  });

  test("sets sidebarOpen to true when resized to >= 1024", () => {
    Object.defineProperty(window, "innerWidth", { value: 800, writable: true, configurable: true });
    const { component } = makeComponent();
    component.sidebarOpen = false;
    component.init();

    Object.defineProperty(window, "innerWidth", { value: 1024, writable: true, configurable: true });
    window.dispatchEvent(new Event("resize"));

    expect(component.sidebarOpen).toBe(true);
  });

  test("does not change sidebarOpen when resized to < 1024", () => {
    Object.defineProperty(window, "innerWidth", { value: 1280, writable: true, configurable: true });
    const { component } = makeComponent();
    component.sidebarOpen = false;
    component.init();

    Object.defineProperty(window, "innerWidth", { value: 768, writable: true, configurable: true });
    window.dispatchEvent(new Event("resize"));

    expect(component.sidebarOpen).toBe(false);
  });

  test("updates isDesktop on exact 1024 boundary", () => {
    Object.defineProperty(window, "innerWidth", { value: 800, writable: true, configurable: true });
    const { component } = makeComponent();
    component.init();

    Object.defineProperty(window, "innerWidth", { value: 1024, writable: true, configurable: true });
    window.dispatchEvent(new Event("resize"));

    expect(component.isDesktop).toBe(true);
  });

  test("updates isDesktop on 1023 boundary (just below desktop)", () => {
    Object.defineProperty(window, "innerWidth", { value: 1280, writable: true, configurable: true });
    const { component } = makeComponent();
    component.init();

    Object.defineProperty(window, "innerWidth", { value: 1023, writable: true, configurable: true });
    window.dispatchEvent(new Event("resize"));

    expect(component.isDesktop).toBe(false);
  });
});

// ─── sidebarCollapsed persistence ─────────────────────────────────────────────

describe("sidebarCollapsed persistence", () => {
  test("reads persisted collapsed state from localStorage on init", () => {
    localStorage.setItem("sidebarCollapsed", "true");
    const { component } = makeComponent();
    component.init();
    expect(component.sidebarCollapsed).toBe(true);
  });

  test("defaults to false when localStorage has no value", () => {
    const { component } = makeComponent();
    component.init();
    expect(component.sidebarCollapsed).toBe(false);
  });

  test("falls back to false when stored value is corrupt", () => {
    localStorage.setItem("sidebarCollapsed", "{not-json");
    window.Admin = { logRestrictedContext: vi.fn() };
    const { component } = makeComponent();
    component.init();
    expect(component.sidebarCollapsed).toBe(false);
    expect(window.Admin.logRestrictedContext).toHaveBeenCalled();
  });

  test("registers a $watch on sidebarCollapsed", () => {
    const { component } = makeComponent();
    component.init();
    expect(component.$watch).toHaveBeenCalledWith("sidebarCollapsed", expect.any(Function));
  });

  test("writes collapsed state to localStorage via $watch callback", () => {
    const { component, watchCallbacks } = makeComponent();
    component.init();
    watchCallbacks.sidebarCollapsed(true);
    expect(localStorage.getItem("sidebarCollapsed")).toBe("true");
    watchCallbacks.sidebarCollapsed(false);
    expect(localStorage.getItem("sidebarCollapsed")).toBe("false");
  });
});

// ─── syncNavLabels — collapsed rail tooltips ──────────────────────────────────

describe("syncNavLabels", () => {
  const NAV_MARKUP = `
    <a class="sidebar-link" href="#overview">
      <span class="sidebar-icon text-lg">📊</span>
      <span x-show="!sidebarCollapsed">  概览  </span>
    </a>
    <a class="sidebar-link" href="#tools">
      <span class="sidebar-icon text-lg">🛠️</span>
      <span x-show="!sidebarCollapsed">工具</span>
    </a>
    <a class="sidebar-link" href="#bare">
      <span class="sidebar-icon text-lg">❔</span>
    </a>
  `;

  const links = () => [...document.querySelectorAll(".sidebar-link")];
  const tooltip = () => document.querySelector(".sidebar-rail-tooltip");

  beforeEach(() => {
    document.body.innerHTML = NAV_MARKUP;
  });

  afterEach(() => {
    document.body.innerHTML = "";
  });

  test("exposes a syncNavLabels method", () => {
    expect(typeof mainLayout().syncNavLabels).toBe("function");
  });

  test("sets aria-label from the trimmed label text when collapsed", () => {
    mainLayout().syncNavLabels(true);
    const [overview, tools] = links();
    expect(overview.getAttribute("aria-label")).toBe("概览");
    expect(tools.getAttribute("aria-label")).toBe("工具");
  });

  test("removes aria-label when expanded", () => {
    const component = mainLayout();
    component.syncNavLabels(true);
    component.syncNavLabels(false);
    expect(links().every((link) => !link.hasAttribute("aria-label"))).toBe(true);
  });

  test("leaves a link without a label untouched", () => {
    mainLayout().syncNavLabels(true);
    expect(
      document.querySelector('a[href="#bare"]').hasAttribute("aria-label"),
    ).toBe(false);
  });

  test("applies labels on init when the persisted state is collapsed", () => {
    localStorage.setItem("sidebarCollapsed", "true");
    const { component } = makeComponent();
    component.init();
    expect(
      links().filter((link) => link.hasAttribute("aria-label")).length,
    ).toBe(2);
  });

  test("applies no labels on init when the persisted state is expanded", () => {
    const { component } = makeComponent();
    component.init();
    expect(links().some((link) => link.hasAttribute("aria-label"))).toBe(false);
  });

  test("updates labels when the watch callback fires", () => {
    const { component, watchCallbacks } = makeComponent();
    component.init();
    watchCallbacks.sidebarCollapsed(true);
    expect(links()[0].getAttribute("aria-label")).toBe("概览");
    watchCallbacks.sidebarCollapsed(false);
    expect(links()[0].hasAttribute("aria-label")).toBe(false);
  });

  test("renders a tooltip on mouseenter while collapsed", () => {
    const { component } = makeComponent();
    localStorage.setItem("sidebarCollapsed", "true");
    component.init();
    links()[0].dispatchEvent(new MouseEvent("mouseenter"));

    const el = tooltip();
    expect(el).not.toBeNull();
    expect(el.textContent).toBe("概览");
    expect(el.getAttribute("role")).toBe("tooltip");
    expect(el.parentElement).toBe(document.body);
    expect(el.style.left).toBe("8px");
  });

  test("keeps a single tooltip while the pointer moves between links", () => {
    const { component } = makeComponent();
    localStorage.setItem("sidebarCollapsed", "true");
    component.init();
    links()[0].dispatchEvent(new MouseEvent("mouseenter"));
    links()[1].dispatchEvent(new MouseEvent("mouseenter"));

    expect(document.querySelectorAll(".sidebar-rail-tooltip").length).toBe(1);
    expect(tooltip().textContent).toBe("工具");
  });

  test("removes the tooltip on mouseleave", () => {
    const { component } = makeComponent();
    localStorage.setItem("sidebarCollapsed", "true");
    component.init();
    links()[0].dispatchEvent(new MouseEvent("mouseenter"));
    links()[0].dispatchEvent(new MouseEvent("mouseleave"));
    expect(tooltip()).toBeNull();
  });

  test("renders no tooltip while expanded", () => {
    const { component } = makeComponent();
    component.init();
    links()[0].dispatchEvent(new MouseEvent("mouseenter"));
    expect(tooltip()).toBeNull();
  });

  test("removes the tooltip when the rail expands", () => {
    const { component, watchCallbacks } = makeComponent();
    localStorage.setItem("sidebarCollapsed", "true");
    component.init();
    links()[0].dispatchEvent(new MouseEvent("mouseenter"));
    expect(tooltip()).not.toBeNull();

    watchCallbacks.sidebarCollapsed(false);
    expect(tooltip()).toBeNull();
  });
});
