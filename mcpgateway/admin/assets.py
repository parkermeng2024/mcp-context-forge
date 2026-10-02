# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/admin/assets.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Admin UI static asset resolution: Vite bundle filenames, bundled CSS assets, and SRI hashes.
"""

# Standard
from functools import lru_cache
import json
import logging
from pathlib import Path
from typing import Dict, Optional

# Third-Party
import orjson

LOGGER: logging.Logger = logging.getLogger("mcpgateway.admin")


# Cache for the bundle filename to avoid reading manifest on every request
# Using a mutable dict to avoid the need for a global statement in the accessor function
_bundle_js_cache: dict[str, Optional[str]] = {"filename": None}

# Cache for the bundle's CSS asset paths (e.g. Font Awesome, CodeMirror) emitted by Vite
_bundle_css_cache: dict[str, Optional[list]] = {"files": None}


def get_bundle_js_filename() -> str:
    """Get the hashed bundle.js filename from Vite manifest.

    Reads the Vite manifest file to get the current hashed bundle filename.
    Falls back to scanning for bundle-*.js on disk if the manifest is unreadable.
    Invalidates the cache when the cached bundle file no longer exists on disk.

    Returns:
        str: The bundle filename (e.g., 'bundle-abc123.js')
    """
    # admin is a package (__init__.py), so static assets sit one directory up at the mcpgateway package root
    static_dir = Path(__file__).parent.parent / "static"

    # Use cache if the bundle file still exists on disk
    cached = _bundle_js_cache["filename"]
    if cached is not None and (static_dir / cached).exists():
        return cached

    manifest_path = static_dir / ".vite" / "manifest.json"
    try:
        if manifest_path.exists():
            with open(manifest_path, "r", encoding="utf-8") as f:
                manifest = orjson.loads(f.read())
                # The key is the input path relative to the project root
                entry_key = "mcpgateway/admin_ui/index.js"
                if entry_key in manifest and manifest[entry_key].get("file"):
                    _bundle_js_cache["filename"] = manifest[entry_key]["file"]
                    return _bundle_js_cache["filename"]  # type: ignore[return-value]
    except Exception as e:
        LOGGER.warning(f"Failed to read Vite manifest: {e}")

    # Manifest unreadable or missing entry — find bundle file directly on disk
    bundles = sorted(static_dir.glob("bundle-*.js"), key=lambda p: p.stat().st_mtime, reverse=True)
    if bundles:
        _bundle_js_cache["filename"] = bundles[0].name
        return _bundle_js_cache["filename"]  # type: ignore[return-value]

    LOGGER.error("No bundle-*.js found in %s — admin UI will not load", static_dir)
    return ""


def get_bundle_css_files() -> list:
    """Get the hashed CSS asset paths bundled with the admin entry from the Vite manifest.

    Vite emits CSS pulled in via JS imports (Font Awesome, CodeMirror, etc.) as separate
    files rather than inlining them into the JS bundle or the HTML automatically, so callers
    must link them explicitly. CSS for a statically-imported chunk (e.g. the CodeMirror/
    Font Awesome vendor chunk) is listed under that *chunk's own* manifest entry, not the
    top-level entry, so the entry's "imports" graph must be walked to collect all of it.

    Falls back to scanning ``assets/*.css`` on disk if the manifest is unreadable or has
    no CSS for the entry, mirroring :func:`get_bundle_js_filename`'s disk fallback. Since a
    single build can emit more than one CSS file (e.g. the CodeMirror/Font Awesome vendor
    chunk plus the entry's own CSS), the fallback keeps every file whose mtime is within a
    few seconds of the newest one, rather than just the single newest file, so it doesn't
    pick only half of the current build's assets.

    Returns:
        list[str]: Paths relative to the static dir (e.g. ['assets/index-abc123.css']),
            or an empty list if neither the manifest nor the assets directory has any CSS.
    """
    # admin is a package (__init__.py), so static assets sit one directory up at the mcpgateway package root
    static_dir = Path(__file__).parent.parent / "static"

    cached = _bundle_css_cache.get("files")
    if cached is not None and all((static_dir / f).exists() for f in cached):
        return cached

    manifest_path = static_dir / ".vite" / "manifest.json"
    try:
        if manifest_path.exists():
            with open(manifest_path, "r", encoding="utf-8") as f:
                manifest = orjson.loads(f.read())
                entry_key = "mcpgateway/admin_ui/index.js"
                if entry_key in manifest:
                    css_files: list = []
                    seen_chunks: set = set()
                    queue = [entry_key]
                    while queue:
                        chunk_key = queue.pop()
                        if chunk_key in seen_chunks or chunk_key not in manifest:
                            continue
                        seen_chunks.add(chunk_key)
                        chunk = manifest[chunk_key]
                        for css_path in chunk.get("css") or []:
                            if css_path not in css_files:
                                css_files.append(css_path)
                        queue.extend(chunk.get("imports") or [])
                    if css_files:
                        _bundle_css_cache["files"] = css_files
                        return css_files
    except Exception as e:
        LOGGER.warning(f"Failed to read Vite manifest for CSS assets: {e}")

    # Manifest unreadable, missing, or missing the entry — find CSS assets directly on disk.
    assets_dir = static_dir / "assets"
    if assets_dir.exists():
        css_paths = sorted(assets_dir.glob("*.css"), key=lambda p: p.stat().st_mtime, reverse=True)
        if css_paths:
            newest_mtime = css_paths[0].stat().st_mtime
            recent_paths = [p for p in css_paths if newest_mtime - p.stat().st_mtime < 5]
            css_files = [f"assets/{p.name}" for p in recent_paths]
            _bundle_css_cache["files"] = css_files
            return css_files

    return []


@lru_cache(maxsize=1)
def load_sri_hashes() -> Dict[str, str]:
    """Load SRI hashes from sri_hashes.json file.

    Uses lru_cache to ensure the file is only read once per process.

    Returns:
        Dict[str, str]: Dictionary mapping resource names to SRI hash strings.
                       Returns empty dict if file not found or invalid.
    """
    try:
        # admin is a package (__init__.py), so sri_hashes.json sits one directory up at the mcpgateway package root
        sri_file = Path(__file__).parent.parent / "sri_hashes.json"
        if sri_file.exists():
            with sri_file.open("r") as f:
                return json.load(f)
    except Exception as e:
        LOGGER.warning("Failed to load SRI hashes: %s", e)

    return {}
