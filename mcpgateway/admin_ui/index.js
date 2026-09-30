/**
 * Admin Entry Point
 * Imports admin.js which sets up the Admin namespace and loads all modules
 * Also imports lazy-loader for on-demand feature loading
 * Also imports i18n.js, which loads the embedded catalog and wires the language switcher
 */
import './i18n.js';
import './lazy-loader.js';
import './admin.js';
