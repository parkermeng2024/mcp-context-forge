/**
 * Unit tests for teamActions.js module
 * Tests: teams list loading and its duplicate-request guard, team context
 *        switching, the team/edit/join-request modal helpers, the sample bulk
 *        import download, and OAuth endpoint discovery.
 */

import { describe, test, expect, vi, beforeEach, afterEach } from "vitest";

import {
  SAMPLE_TOOLS_DATA,
  buildTeamsPartialUrl,
  cancelJoinRequest,
  closeCreateTeamModal,
  deleteTeamSafe,
  discoverOAuthEndpoints,
  downloadSampleJSON,
  editTeamSafe,
  initializeTeamManagement,
  initTeamActions,
  leaveTeamSafe,
  loadTeamMembersView,
  manageTeamMembersSafe,
  openCreateTeamModal,
  requestToJoinTeamSafe,
  updateTeamContext,
  viewJoinRequestsSafe,
} from "../../../mcpgateway/admin_ui/teamActions.js";

/**
 * Build the DOM section an OAuth discovery button lives in.
 * @returns {HTMLElement} The section element
 */
const buildDiscoverSection = () => {
  document.body.innerHTML = `
    <form>
      <section>
        <input name="oauth_issuer" value="" />
        <div class="oauth-discover-status hidden"></div>
        <button id="discover">Discover</button>
      </section>
      <input name="oauth_token_url" value="" />
      <input name="oauth_authorization_url" value="" />
    </form>
  `;
  return document.querySelector("section");
};

let ajax;

/**
 * Let the loader's own promise callbacks run, so the in-flight state clears
 * before a test asserts on the duplicate-request window.
 * @returns {Promise<void>} Resolves after several microtask ticks
 */
const flushMicrotasks = async () => {
  for (let i = 0; i < 5; i += 1) {
    await Promise.resolve();
  }
};

beforeEach(() => {
  vi.useFakeTimers();
  window.ROOT_PATH = "";
  window.htmx = { ajax: vi.fn() };
  ajax = window.htmx.ajax;
  ajax.mockReturnValue(Promise.resolve({}));
  document.body.innerHTML = "";
  window.location.hash = "";
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  delete window.htmx;
  delete window.ROOT_PATH;
});

describe("buildTeamsPartialUrl", () => {
  test("always carries page and page size", () => {
    expect(
      buildTeamsPartialUrl("/prefix", { page: 3, perPage: 25 })
    ).toBe("/prefix/admin/teams/partial?page=3&per_page=25");
  });

  test("adds the search term when one is set", () => {
    const url = buildTeamsPartialUrl("", {
      page: 1,
      perPage: 10,
      searchQuery: "core",
    });
    expect(url).toContain("q=core");
  });

  test("adds the relationship filter only when it narrows the list", () => {
    expect(
      buildTeamsPartialUrl("", { page: 1, perPage: 10, relationship: "all" })
    ).not.toContain("relationship");
    expect(
      buildTeamsPartialUrl("", { page: 1, perPage: 10, relationship: "member" })
    ).toContain("relationship=member");
  });
});

describe("updateTeamContext", () => {
  let assign;

  beforeEach(() => {
    window.__teamSwitchingInProgress = false;
    assign = vi.fn();
    Object.defineProperty(window, "location", {
      value: { ...window.location, assign, href: "http://localhost/admin/" },
      writable: true,
      configurable: true,
    });
  });

  afterEach(() => {
    window.__teamSwitchingInProgress = false;
  });

  test("navigates with the team_id query parameter", () => {
    updateTeamContext("team-1");
    expect(assign).toHaveBeenCalledTimes(1);
    expect(assign.mock.calls[0][0]).toContain("team_id=team-1");
  });

  test("navigates without team_id when the selection is cleared", () => {
    updateTeamContext("");
    expect(assign.mock.calls[0][0]).not.toContain("team_id");
  });

  test("ignores a second switch while one is in progress", () => {
    updateTeamContext("team-1");
    updateTeamContext("team-2");
    expect(assign).toHaveBeenCalledTimes(1);
  });
});

describe("create-team modal", () => {
  beforeEach(() => {
    document.body.innerHTML = `
      <div id="create-team-modal" class="hidden">
        <form id="create-team-form"><input id="team-name" /></form>
      </div>
    `;
  });

  test("openCreateTeamModal reveals the modal and focuses the name field", () => {
    openCreateTeamModal();
    expect(document.getElementById("create-team-modal").classList).not.toContain(
      "hidden"
    );
    vi.runAllTimers();
    expect(document.activeElement.id).toBe("team-name");
  });

  test("closeCreateTeamModal hides the modal and resets the form", () => {
    const form = document.getElementById("create-team-form");
    form.reset = vi.fn();
    closeCreateTeamModal();
    expect(document.getElementById("create-team-modal").classList).toContain(
      "hidden"
    );
    expect(form.reset).toHaveBeenCalled();
  });
});

describe("team action helpers", () => {
  beforeEach(() => {
    document.body.innerHTML = `
      <div id="team-edit-modal" class="hidden"><div id="team-edit-modal-content"></div></div>
      <div id="team-join-requests-modal" class="hidden"></div>
      <button id="btn" data-team-id="team-1" data-team-name="Core"></button>
    `;
  });

  test("loadTeamMembersView clears stale content and opens the modal", async () => {
    const content = document.getElementById("team-edit-modal-content");
    content.innerHTML = "stale";
    loadTeamMembersView("team-1");

    expect(content.innerHTML).toBe("");
    expect(ajax).toHaveBeenCalledWith(
      "GET",
      "/admin/teams/team-1/members",
      expect.objectContaining({ target: "#team-edit-modal-content" })
    );

    await vi.waitFor(() =>
      expect(
        document.getElementById("team-edit-modal").classList
      ).not.toContain("hidden")
    );
  });

  test("manageTeamMembersSafe loads the members view for the button's team", () => {
    manageTeamMembersSafe(document.getElementById("btn"));
    expect(ajax.mock.calls[0][1]).toBe("/admin/teams/team-1/members");
  });

  test("editTeamSafe loads the edit form", () => {
    editTeamSafe(document.getElementById("btn"));
    expect(ajax.mock.calls[0][1]).toBe("/admin/teams/team-1/edit");
  });

  test("viewJoinRequestsSafe loads join requests and opens their modal", async () => {
    viewJoinRequestsSafe(document.getElementById("btn"));
    expect(ajax.mock.calls[0][1]).toBe(
      "/admin/teams/team-1/join-requests"
    );
    await vi.waitFor(() =>
      expect(
        document.getElementById("team-join-requests-modal").classList
      ).not.toContain("hidden")
    );
  });

  test("requestToJoinTeamSafe posts after confirmation", () => {
    vi.spyOn(window, "confirm").mockReturnValue(true);
    requestToJoinTeamSafe(document.getElementById("btn"));
    expect(ajax.mock.calls[0][0]).toBe("POST");
    expect(ajax.mock.calls[0][1]).toBe("/admin/teams/team-1/join-request");
  });

  test("leaveTeamSafe does nothing when the user declines", () => {
    vi.spyOn(window, "confirm").mockReturnValue(false);
    leaveTeamSafe(document.getElementById("btn"));
    expect(ajax).not.toHaveBeenCalled();
  });

  test("deleteTeamSafe issues a DELETE after confirmation", () => {
    vi.spyOn(window, "confirm").mockReturnValue(true);
    deleteTeamSafe(document.getElementById("btn"));
    expect(ajax.mock.calls[0][0]).toBe("DELETE");
    expect(ajax.mock.calls[0][1]).toBe("/admin/teams/team-1");
  });

  test("cancelJoinRequest issues a DELETE for the pending request", () => {
    vi.spyOn(window, "confirm").mockReturnValue(true);
    cancelJoinRequest("team-1", "req-9");
    expect(ajax.mock.calls[0][0]).toBe("DELETE");
    expect(ajax.mock.calls[0][1]).toBe(
      "/admin/teams/team-1/join-request/req-9"
    );
  });
});

describe("initializeTeamManagement", () => {
  // The duplicate-request window is module state. Move the clock forward past
  // it before each test so every test starts from a clean slate.
  let clock = Date.now();


  beforeEach(() => {
    document.body.innerHTML = `
      <input id="team-search" value="" />
      <div id="unified-teams-list"></div>
      <div id="teams-loading"></div>
    `;
    Object.defineProperty(window, "location", {
      value: { ...window.location, search: "", href: "http://localhost/admin/" },
      writable: true,
      configurable: true,
    });
    clock += 60_000;
    vi.setSystemTime(clock);
  });

  test("loads the teams partial for the current page", async () => {
    await initializeTeamManagement();
    expect(ajax).toHaveBeenCalledTimes(1);
    expect(ajax.mock.calls[0][1]).toBe(
      "/admin/teams/partial?page=1&per_page=10"
    );
    expect(ajax.mock.calls[0][2]).toMatchObject({
      target: "#unified-teams-list",
      indicator: "#teams-loading",
    });
  });

  test("suppresses an identical second call and allows a later refresh", async () => {
    await initializeTeamManagement();
    await flushMicrotasks();
    expect(ajax).toHaveBeenCalledTimes(1);

    expect(initializeTeamManagement()).toBeNull();
    expect(ajax).toHaveBeenCalledTimes(1);

    vi.advanceTimersByTime(1001);
    await initializeTeamManagement();
    expect(ajax).toHaveBeenCalledTimes(2);
  });

  test("reuses the pending request instead of issuing a second one", () => {
    let resolvePending;
    ajax.mockReturnValue(new Promise((resolve) => (resolvePending = resolve)));

    const first = initializeTeamManagement();
    const second = initializeTeamManagement();

    expect(ajax).toHaveBeenCalledTimes(1);
    expect(second).toBe(first);
    resolvePending({});
  });

  test("a failed load does not block an immediate retry", async () => {
    ajax.mockReturnValue(Promise.reject(new Error("boom")));
    await expect(initializeTeamManagement()).rejects.toThrow("boom");

    ajax.mockReturnValue(Promise.resolve({}));
    initializeTeamManagement();
    await vi.waitFor(() => expect(ajax).toHaveBeenCalledTimes(2));
  });

  test("a different search term loads a fresh list", async () => {
    await initializeTeamManagement();
    expect(ajax).toHaveBeenCalledTimes(1);

    document.getElementById("team-search").value = "core";
    await initializeTeamManagement();
    expect(ajax).toHaveBeenCalledTimes(2);
    expect(ajax.mock.calls[1][1]).toContain("q=core");
  });
});

describe("initTeamActions", () => {
  // The tab handler and tabs.js both load the list on a click; the dedupe guard
  // collapses the pair, and a later click on the active tab refreshes.
  let clock = Date.now();

  beforeEach(() => {
    document.body.innerHTML = `
      <a id="tab-teams" href="#teams">Teams</a>
      <input id="team-search" value="" />
      <div id="unified-teams-list"></div>
      <div id="teams-loading"></div>
      <div id="create-team-modal" class="hidden">
        <form id="create-team-form"></form>
      </div>
    `;
    Object.defineProperty(window, "location", {
      value: { ...window.location, search: "", href: "http://localhost/admin/" },
      writable: true,
      configurable: true,
    });
    clock += 60_000;
    vi.setSystemTime(clock);
    initTeamActions();
  });

  test("collapses a tab click into a single request", () => {
    document.getElementById("tab-teams").click();
    vi.advanceTimersByTime(100);
    document.getElementById("tab-teams").click();
    vi.advanceTimersByTime(100);

    expect(ajax).toHaveBeenCalledTimes(1);
  });

  test("a later click on the active tab refreshes the list", async () => {
    document.getElementById("tab-teams").click();
    vi.advanceTimersByTime(100);
    await flushMicrotasks();

    vi.advanceTimersByTime(1001);
    document.getElementById("tab-teams").click();
    vi.advanceTimersByTime(100);

    expect(ajax).toHaveBeenCalledTimes(2);
  });

  test("reloads the list when the create-team form succeeds", () => {
    document.dispatchEvent(
      new CustomEvent("htmx:afterRequest", {
        detail: { xhr: { status: 201 }, elt: { id: "create-team-form" } },
      })
    );
    expect(ajax).toHaveBeenCalledTimes(1);
  });
});

describe("downloadSampleJSON", () => {
  test("downloads the sample payload as JSON", () => {
    const createObjectURL = vi
      .spyOn(window.URL, "createObjectURL")
      .mockReturnValue("blob:sample");
    const revokeObjectURL = vi
      .spyOn(window.URL, "revokeObjectURL")
      .mockImplementation(() => {});
    const click = vi
      .spyOn(HTMLAnchorElement.prototype, "click")
      .mockImplementation(() => {});

    downloadSampleJSON();

    expect(SAMPLE_TOOLS_DATA.length).toBeGreaterThan(0);
    const blob = createObjectURL.mock.calls[0][0];
    expect(blob.type).toBe("application/json");
    expect(click).toHaveBeenCalled();
    expect(revokeObjectURL).toHaveBeenCalledWith("blob:sample");
  });
});

describe("discoverOAuthEndpoints", () => {
  test("asks for an Issuer URL when the field is empty", async () => {
    const section = buildDiscoverSection();
    const fetchSpy = vi.spyOn(globalThis, "fetch");

    await discoverOAuthEndpoints(document.getElementById("discover"));

    expect(section.querySelector(".oauth-discover-status").textContent).toBe(
      "Please enter an Issuer URL first."
    );
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  test("fills token and authorization URLs from the discovery response", async () => {
    buildDiscoverSection();
    document.querySelector('input[name="oauth_issuer"]').value =
      "https://issuer.example.com";
    vi.spyOn(globalThis, "fetch").mockResolvedValue({
      json: async () => ({
        success: true,
        token_endpoint: "https://issuer.example.com/token",
        authorization_endpoint: "https://issuer.example.com/authorize",
        dcr_available: true,
      }),
    });

    const btn = document.getElementById("discover");
    await discoverOAuthEndpoints(btn);

    expect(
      document.querySelector('input[name="oauth_token_url"]').value
    ).toBe("https://issuer.example.com/token");
    expect(
      document.querySelector('input[name="oauth_authorization_url"]').value
    ).toBe("https://issuer.example.com/authorize");
    expect(btn.disabled).toBe(false);
    expect(btn.textContent).toBe("🔍 Discover");
  });

  test("reports a failed discovery with the server message", async () => {
    buildDiscoverSection();
    document.querySelector('input[name="oauth_issuer"]').value = "https://x.test";
    vi.spyOn(globalThis, "fetch").mockResolvedValue({
      json: async () => ({ success: false, error: "no metadata" }),
    });

    await discoverOAuthEndpoints(document.getElementById("discover"));

    const status = document.querySelector(".oauth-discover-status");
    expect(status.innerHTML).toContain("no metadata");
    expect(status.classList).not.toContain("hidden");
  });

  test("escapes an issuer value before rendering it", async () => {
    buildDiscoverSection();
    document.querySelector('input[name="oauth_issuer"]').value =
      "https://x.test/<img src=x>";
    vi.spyOn(globalThis, "fetch").mockResolvedValue({
      json: async () => ({
        success: true,
        token_endpoint: "https://x.test/token",
        authorization_endpoint: "https://x.test/authorize",
      }),
    });

    await discoverOAuthEndpoints(document.getElementById("discover"));

    const html = document.querySelector(".oauth-discover-status").innerHTML;
    expect(html).toContain("&lt;img src=x&gt;");
    expect(html).not.toContain("<img src=x>");
  });
});
