/** @type {import('tailwindcss').Config} */
const daisyThemes = require("daisyui/src/theming/themes");

module.exports = {
    content: [
        "./mcpgateway/templates/**/*.html",
        "./mcpgateway/static/**/*.js",
    ],
    darkMode: "class",
    theme: {
        extend: {
            animation: {
                float: "float 6s ease-in-out infinite",
                "pulse-soft": "pulse-soft 2s ease-in-out infinite",
                "slide-up": "slide-up 0.8s ease-out",
                "fade-in": "fade-in 1s ease-out",
            },
            keyframes: {
                float: {
                    "0%, 100%": { transform: "translateY(0px)" },
                    "50%": { transform: "translateY(-20px)" },
                },
                "pulse-soft": {
                    "0%, 100%": { opacity: "1" },
                    "50%": { opacity: "0.8" },
                },
                "slide-up": {
                    "0%": { transform: "translateY(30px)", opacity: "0" },
                    "100%": { transform: "translateY(0)", opacity: "1" },
                },
                "fade-in": {
                    "0%": { opacity: "0" },
                    "100%": { opacity: "1" },
                },
            },
        },
    },
    plugins: [require("daisyui")],
    daisyui: {
        // base:false keeps daisyUI out of global element resets; component styles
        // apply only where daisyUI classes are used.
        base: false,
        logs: false,
        // The app toggles a .dark class on <html> (Alpine darkMode); use it for the dark theme.
        darkTheme: "dark",
        themes: [
            {
                light: {
                    ...daisyThemes.light,
                    // Match the existing indigo-600 brand color.
                    primary: "#4f46e5",
                },
            },
            {
                dark: {
                    ...daisyThemes.dark,
                    primary: "#4f46e5",
                },
            },
        ],
    },
};
