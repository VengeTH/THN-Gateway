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
        ink: {
          50: "#f6f7f9",
          100: "#eceef2",
          200: "#d4d8e0",
          300: "#aeb5c4",
          400: "#8189a0",
          500: "#5f6780",
          600: "#464d63",
          700: "#333849",
          800: "#1f2331",
          // Row dividers need to sit between the panel and the page, and
          // neither 800 nor 900 does: 800 is the panel edge and reads as a
          // border, 900 is the page and reads as nothing at all.
          850: "#191d28",
          900: "#13161f",
          950: "#0b0d13",
        },
        // Severity. Each is paired with a text colour that meets contrast on
        // its own background, because a status pill is often the only text on
        // a row.
        critical: {
          DEFAULT: "#b42318",
          muted: "#fee4e2",
          text: "#7a271a",
        },
        warning: {
          DEFAULT: "#b54708",
          muted: "#fef0c7",
          text: "#7a3d0a",
        },
        ok: {
          DEFAULT: "#067647",
          muted: "#d1fadf",
          text: "#085c3a",
        },
        info: {
          DEFAULT: "#175cd3",
          muted: "#d1e9ff",
          text: "#194185",
        },
        unknown: {
          DEFAULT: "#5f6780",
          muted: "#eceef2",
          text: "#464d63",
        },
      },
      fontFamily: {
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
    },
  },
  plugins: [],
};

export default config;
