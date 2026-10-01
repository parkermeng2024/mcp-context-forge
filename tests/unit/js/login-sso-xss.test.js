/**
 * Regression test for issue #5856 (Option A — DOM-sink XSS guard).
 *
 * The SSO login page renders admin-controlled provider names into the DOM.
 * The fix injects the name via `textContent` (never string-interpolated into
 * `innerHTML`), so a stored/malicious `display_name` is inert when another
 * admin loads the login page.
 *
 * This test exercises the *real* template source: it slices the `t()` helper,
 * the `ssoProviders` config, and the `loadSSOProviders()` function straight out
 * of `login.html` and runs them in JSDOM. If someone reverts to
 * `innerHTML = ...Continue with ${config.name}...`, the payload parses into a
 * live <img> node and this test fails.
 */

import fs from "fs";
import path from "path";
import { JSDOM } from "jsdom";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const loginHtml = fs.readFileSync(path.resolve(__dirname, "../../../mcpgateway/templates/login.html"), "utf8");

// Extract the shipped SSO-rendering source: the `ssoProviders` config object
// and the `loadSSOProviders()` function. The DOMContentLoaded bootstrap block
// that sits between them is deliberately skipped (it touches unrelated login
// elements and would just add noise here).
// `loadSSOProviders()` calls `t()`, which the template defines above the
// config. The slice must carry that definition, or the extracted source throws
// a ReferenceError before any XSS assertion runs.
const tStart = loginHtml.indexOf("const LOGIN_STRINGS =");
const tEnd = loginHtml.indexOf("function getCookie(name) {");
const cfgStart = loginHtml.indexOf("const ssoProviders = {");
const cfgEnd = loginHtml.indexOf('document.addEventListener("DOMContentLoaded"');
const fnStart = loginHtml.indexOf("async function loadSSOProviders()");
const fnEnd = loginHtml.indexOf("// Initiate SSO authentication");
if ([tStart, tEnd, cfgStart, cfgEnd, fnStart, fnEnd].some((i) => i === -1) || tEnd <= tStart || cfgEnd <= cfgStart || fnEnd <= fnStart) {
  throw new Error("Could not locate SSO rendering source in login.html — update the extraction anchors.");
}
const ssoSource =
  loginHtml.slice(tStart, tEnd) +
  "\n" +
  loginHtml.slice(cfgStart, cfgEnd) +
  "\n" +
  loginHtml.slice(fnStart, fnEnd);

function renderWith(provider) {
  const dom = new JSDOM(
    `<!DOCTYPE html><html><body>
       <div id="sso-section"></div>
       <div id="divider"></div>
       <div id="sso-providers"></div>
     </body></html>`,
    { url: "http://localhost", runScripts: "outside-only" },
  );
  const win = dom.window;
  win.ROOT_PATH = "";
  win.fetch = async () => ({ ok: true, status: 200, json: async () => [provider] });
  win.eval(ssoSource); // defines ssoProviders + loadSSOProviders on this window
  return win;
}

describe("login.html SSO provider button — DOM-sink XSS guard (issue #5856)", () => {
  test("malicious display_name renders as inert text, never parsed as HTML", async () => {
    const payload = '<img src=x onerror="window.__xss=1"><script>window.__xss=1</script>';
    const win = renderWith({ id: "custom-oidc", name: "ignored", display_name: payload });

    await win.loadSSOProviders();

    const container = win.document.getElementById("sso-providers");
    // The payload must not have been parsed into live nodes.
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("script")).toBeNull();
    expect(win.__xss).toBeUndefined();

    // The name is present verbatim as text in the dedicated span.
    const span = container.querySelector(".sso-provider-name");
    expect(span).not.toBeNull();
    expect(span.textContent).toBe(payload);
  });

  test("falls back to provider.name when display_name is absent (still text)", async () => {
    const payload = '<img src=x onerror="window.__xss=1">';
    const win = renderWith({ id: "custom-oidc", name: payload });

    await win.loadSSOProviders();

    const container = win.document.getElementById("sso-providers");
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector(".sso-provider-name").textContent).toBe(payload);
  });
});
