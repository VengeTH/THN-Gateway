import type { Config } from "tailwindcss";

/**
 * The theme is built around one idea: a gateway console is mostly a list of
 * states, and the states are what need to be readable at a glance from across
 * a room.
 *
 * Severity is therefore the only place colour is used with any force, and it is
 * used consistently. A colour that means "critical" on one page and "selected"
 * on another is worse than no colour at all, because an operator learns the
 * palette once and then misreads it.
 */
const config: Config = {
  content: [
    "./app/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
    "./lib/**/*.{ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // A neutral ramp rather than pure greys. The slight blue cast matters
        // on the severity colours below: a warm grey behind a red reads as
        // alarming even when it is not.
        // The Heedful Official Corporate Palette:
        // Dark-first, minimal, technical, data-focused.
        // Primary bg #0F0F0F, Surface #1A1A1A, Secondary surface #2B2B2B,
        // Primary gray #424242, Text secondary #BDBDBD, Text primary #FFFFFF.
        ink: {
          50: "#FFFFFF",
          100: "#F5F5F5",
          200: "#EEEEEE",
          300: "#E0E0E0",
          400: "#BDBDBD",
          500: "#9E9E9E",
          600: "#616161",
          700: "#424242",
          800: "#2B2B2B",
          850: "#222222",
          900: "#1A1A1A",
          950: "#0F0F0F",
        },
        // Severity. Each is paired with a text colour that meets contrast on
        // its own background, because a status pill is often the only text on
        // a row.
        /*
         * Severity.
         *
         * Each family carries three roles, and the third one exists because
         * the first two are wrong for a dark theme:
         *
         *   DEFAULT — the saturated colour. Correct as a *fill* with white or
         *             near-black text on top, wrong as text on a dark page.
         *   muted   — a light tint. Correct as a fill with `text` on top.
         *   text    — a dark shade of the hue, legible ON `muted`.
         *   edge    — the light tint again, for borders on the dark page.
         *   fg      — the light tint, for TEXT on the dark page.
         *
         * `fg` and `edge` are the same value because the page is dark and a
         * border and a label need the same luminance to read. They are named
         * separately because `text-critical-edge` is confusing to read and
         * `border-critical-fg` is not, and a reader picking the wrong one
         * gets an invisible label.
         *
         * Getting this wrong is not cosmetic: `text-critical` on the page
         * background is #7a271a on #0b0d13, which is a contrast ratio near
         * 1.9:1. Every status label written that way is unreadable.
         */
        critical: {
          DEFAULT: "#b42318",
          muted: "#fee4e2",
          text: "#7a271a",
          edge: "#fda29b",
          fg: "#fda29b",
        },
        warning: {
          DEFAULT: "#b54708",
          muted: "#fef0c7",
          text: "#7a3d0a",
          edge: "#fec84b",
          fg: "#fec84b",
        },
        ok: {
          DEFAULT: "#067647",
          muted: "#d1fadf",
          text: "#085c3a",
          edge: "#6ce9a6",
          fg: "#6ce9a6",
        },
        info: {
          DEFAULT: "#175cd3",
          muted: "#d1e9ff",
          text: "#194185",
          edge: "#84caff",
          fg: "#84caff",
        },
        unknown: {
          DEFAULT: "#5f6780",
          muted: "#eceef2",
          text: "#464d63",
          edge: "#aeb5c4",
          fg: "#aeb5c4",
        },
        /*
         * The interactive colour — the TH yellow. Reserved for controls a
         * person can act on, and deliberately distinct from every severity
         * above, because "this control is selected" and "this thing is broken"
         * must never read as the same kind of statement.
         *
         * WARNING is orange and this is yellow, which is a close call on a bad
         * display. It is acceptable because they never appear in the same
         * role: a warning is a status about the network, an accent is an
         * affordance about the page.
         */
        accent: {
          DEFAULT: "#ffc107",
          hover: "#e6b400",
          soft: "#4a3d00",
          text: "#3d2f00",
        },
      },
      fontFamily: {
        sans: [
          "Inter",
          "ui-sans-serif",
          "system-ui",
          "-apple-system",
          "BlinkMacSystemFont",
          "Segoe UI",
          "Roboto",
          "sans-serif",
        ],
        display: [
          "Space Grotesk",
          "Inter",
          "system-ui",
          "-apple-system",
          "sans-serif",
        ],
        mono: [
          "ui-monospace",
          "SFMono-Regular",
          "Menlo",
          "Consolas",
          "monospace",
        ],
      },
      fontSize: {
        // One extra-small step. THN's output is dense — rule names, signal
        // names, command lines — and the default scale jumps too far for a
        // three-line policy explanation to sit on one row.
        "2xs": ["0.6875rem", { lineHeight: "1rem" }],
      },
      spacing: {
        // A gutter step that keeps touch targets legal on a phone without
        // wasting a tablet's width.
        gutter: "1rem",
      },
      maxWidth: {
        console: "80rem",
      },
      screens: {
        // The default Tailwind breakpoints are tuned for a desktop-first
        // layout. A console that is read on a phone needs the two-column
        // step to arrive later and the table-to-cards step to arrive earlier.
        sm: "480px",
        md: "768px",
        lg: "1024px",
        xl: "1280px",
      },
      boxShadow: {
        panel: "0 1px 2px 0 rgb(0 0 0 / 0.4)",
        pop: "0 12px 32px -8px rgb(0 0 0 / 0.7)",
      },
      keyframes: {
        "fade-in": {
          from: { opacity: "0" },
          to: { opacity: "1" },
        },
        "slide-down": {
          from: { opacity: "0", transform: "translateY(-6px)" },
          to: { opacity: "1", transform: "translateY(0)" },
        },
      },
      animation: {
        "fade-in": "fade-in 160ms ease-out",
        "slide-down": "slide-down 160ms ease-out",
      },
    },
  },
  plugins: [],
};

export default config;
