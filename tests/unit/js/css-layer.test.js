/**
 * Guards the @keyframes namespace shared by admin.css and the Tailwind layer.
 *
 * admin.html loads admin.css after tailwind.min.css, so a name defined in both
 * files always resolves to admin.css. Two animations with different geometry
 * must not share a name: a fade-in collision once displaced the top-right LLM
 * chat notification, because admin.css carried a translate(-50%) meant for a
 * centred tooltip.
 */

import { describe, test, expect } from "vitest";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { createRequire } from "module";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, "../../..");
const ADMIN_CSS_PATH = path.join(REPO_ROOT, "mcpgateway/static/admin.css");

// Tailwind emits these keyframes without a config entry.
const TAILWIND_BUILTIN_KEYFRAMES = ["spin", "ping", "pulse", "bounce"];

const require = createRequire(import.meta.url);
const ADMIN_CSS = fs.readFileSync(ADMIN_CSS_PATH, "utf8");

/** Names declared by `@keyframes <name>` in a CSS string. */
function definedKeyframes(cssText) {
  return new Set(
    [...cssText.matchAll(/@keyframes\s+([A-Za-z0-9_-]+)/g)].map((match) => match[1]),
  );
}

/**
 * Names referenced by `animation:` shorthand.
 *
 * The name is read from the first token, which holds for the shorthand order
 * used throughout admin.css (`animation: <name> <duration> <timing>`).
 */
function referencedAnimations(cssText) {
  const referenced = new Set();
  for (const match of cssText.matchAll(/animation:\s*([^;]+);/g)) {
    const [first] = match[1].trim().split(/\s+/);
    if (/^[A-Za-z_-][A-Za-z0-9_-]*$/.test(first)) {
      referenced.add(first);
    }
  }
  return referenced;
}

/** Names the Tailwind layer emits: built-ins plus `theme.extend.keyframes`. */
function tailwindKeyframes() {
  const config = require(path.join(REPO_ROOT, "tailwind.config.js"));
  const configured = Object.keys(config?.theme?.extend?.keyframes ?? {});
  return new Set([...TAILWIND_BUILTIN_KEYFRAMES, ...configured]);
}

describe("CSS layer hygiene", () => {
  test("admin.css defines the keyframes it animates with", () => {
    const defined = definedKeyframes(ADMIN_CSS);
    const referenced = referencedAnimations(ADMIN_CSS);

    expect(referenced.size).toBeGreaterThan(0);
    expect([...referenced].filter((name) => !defined.has(name))).toEqual([]);
  });

  test("admin.css shares no @keyframes name with Tailwind", () => {
    const own = definedKeyframes(ADMIN_CSS);
    const tailwind = tailwindKeyframes();

    expect(own.size).toBeGreaterThan(0);
    expect([...own].filter((name) => tailwind.has(name))).toEqual([]);
  });
});
