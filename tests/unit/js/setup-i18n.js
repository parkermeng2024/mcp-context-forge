/**
 * Seeds the frontend i18n catalog for the jsdom test environment.
 *
 * In the browser `templates/_i18n_config.html` assigns `window.__I18N__` before
 * the admin UI bundle runs, and `admin_ui/i18n.js` reads that global at import
 * time. A lookup that misses returns the raw key, so without this setup every
 * assertion on a user-visible string sees a key such as
 * "common.tooltip.copyId" instead of "Copy ID to clipboard".
 */

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const LOCALES_DIR = path.resolve(HERE, "../../../mcpgateway/i18n/locales");

// Mirrors SUPPORTED_LOCALES in mcpgateway/i18n/catalog.py.
const SUPPORTED_LOCALES = { en: "English", "zh-CN": "简体中文" };

window.__I18N__ = {
  locale: "en",
  catalog: JSON.parse(fs.readFileSync(path.join(LOCALES_DIR, "en.json"), "utf8")),
  supported: SUPPORTED_LOCALES,
};
