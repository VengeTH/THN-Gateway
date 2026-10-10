/**
 * The only place in this application that runs a process.
 *
 * # Why the console shells out rather than reimplementing
 *
 * THN is a Go binary with one hard property: it can read the host and it cannot
 * change it. Every correctness argument in that project — the guard package, the
 * render-not-apply discipline, the safety-invariant tests — is an argument about
 * what the Go side does and does not do.
 *
 * If the console reimplemented any of it, that argument would stop applying to
 * the console, and the operator would be looking at two tools that claim to
 * describe the same gateway and can disagree. So this file invokes `thn` and
 * renders what it says. The console can do exactly what `thn` can do, which is
 * the property that makes it safe to point at a device nobody can reach.
 *
 * # Why there is an allowlist
 *
 * Shelling out to a binary makes the console's capabilities equal to the
 * binary's, which is the right direction — but the binary also has one
 * destructive command, `activate`, which refuses to do anything in this build
 * and is expected never to do anything.
 *
 * An allowlist means the console cannot reach it even if a future contributor
 * adds a route handler for it by mistake. The refusal lives in the Go binary
 * too, so this is a second, independent barrier rather than the only one — which
 * is how a safety property should be arranged when the cost is four lines.
 *
 * The consequence is that this console has no write path. There is no Apply
 * button, and adding one is not a change to this file: it is a change to THN's
 * own safety posture, and it should be argued for there rather than here.
 */

import { execFile } from "node:child_process";
import { access, constants } from "node:fs/promises";
import path from "node:path";

/**
 * The subcommands this console may invoke.
 *
 * Each names a command and the subcommands permitted beneath it. `activate` is
 * absent, and its absence is the point: it is the only TierDestructive command
 * in the binary, and this list is where a reader looks to confirm that.
 */
const ALLOWED: Readonly<Record<string, readonly string[]>> = {
  config: [],
  diagnostics: [],
  firewall: ["render", "validate"],
  net: ["render", "validate", "simulate"],
  simulate: [],
  dhcp: ["render", "leases"],
  dns: ["render"],
  qos: ["render", "validate", "available"],
  rules: ["list", "test"],
  incidents: ["list"],
  policy: ["list", "resolve"],
  status: [],
  validate: [],
  plan: [],
  schema: [],
  clients: [],
  interfaces: [],
  networks: [],
  monitoring: [],
  events: [],
  management: ["status", "check", "auth"],
};

export type ThnCommand = keyof typeof ALLOWED;

/** A result from the binary, or the reason there isn't one. */
export type ThnResult<T> =
  | { ok: true; data: T; exitCode: number }
  | { ok: false; error: ThnError };

export type ThnErrorKind =
  /** The allowlist refused the command. */
  | "not-permitted"
  /** The binary is not where we were told to look. */
  | "binary-missing"
  /** The binary ran and refused, or failed to run. */
  | "execution-failed"
  /** The binary ran and printed something that is not the JSON we expected. */
  | "unparseable"
  /** The binary took too long, which on a live read means the host is busy. */
  | "timeout";

export interface ThnError {
  kind: ThnErrorKind;
  /** A sentence for the operator. Never empty. */
  message: string;
  /** The binary's own words, when it produced any. */
  detail?: string;
  /** The command line, for a bug report. */
  command: string;
}

/** How long a single invocation may take. */
const TIMEOUT_MS = 15_000;

/**
 * The path to the Go binary.
 *
 * `THN_BINARY` overrides it. On the gateway it is the installed binary; on a
 * laptop it is a local build, because the console is useless without one and
 * saying so plainly is better than failing to spawn.
 */
async function resolveBinary(): Promise<string | null> {
  const override = process.env.THN_BINARY;
  if (override && override.length > 0) {
    try {
      await access(override, constants.X_OK);
      return override;
    } catch {
      return null;
    }
  }

  const ext = process.platform === "win32" ? ".exe" : "";
  const candidates = [
    path.join(process.cwd(), "..", `thn${ext}`),
    path.join(process.cwd(), "..", "bin", `thn${ext}`),
    path.join(process.cwd(), `thn${ext}`),
    path.join(process.cwd(), "bin", `thn${ext}`),
  ];

  for (const c of candidates) {
    try {
      await access(c, constants.X_OK);
      return c;
    } catch {
      continue;
    }
  }
  return null;
}

function isAllowed(command: string, sub: string | undefined): boolean {
  if (!Object.prototype.hasOwnProperty.call(ALLOWED, command)) {
    return false;
  }
  if (sub === undefined || sub.length === 0) {
    return true;
  }
  return ALLOWED[command]!.includes(sub);
}

/**
 * Runs a permitted `thn` subcommand and parses its JSON.
 *
 * The command line is passed as an array and never interpolated into a shell
 * string. That is not a style preference: a `--config` value containing a space
 * or a semicolon would otherwise be a command injection into a process that can
 * read a network configuration.
 *
 * `argv[0]` is the command and `argv[1]`, if it is not a flag, is the
 * subcommand. Taking it by position rather than by scanning for the first
 * non-flag argument is deliberate: the scan could not tell a subcommand from a
 * flag's value, so `thn diagnostics --interface eth0` would have been refused
 * for looking as though `eth0` were a subcommand. Refusing wrongly is at least
 * the safe direction, but a safety check that rejects valid calls gets turned
 * off by whoever it annoys, and then it protects nothing.
 */
export async function thn<T>(argv: readonly string[]): Promise<ThnResult<T>> {
  const command = argv[0] ?? "";
  const first = argv[1];
  const sub = first !== undefined && !first.startsWith("-") ? first : undefined;
  const printable = [...argv, "--json"].join(" ");

  if (!isAllowed(command, sub)) {
    return {
      ok: false,
      error: {
        kind: "not-permitted",
        message: sub
          ? `\`thn ${command} ${sub}\` is not something this console may run.`
          : `\`thn ${command}\` is not something this console may run.`,
        command: printable,
      },
    };
  }

  const bin = await resolveBinary();
  if (!bin) {
    return {
      ok: false,
      error: {
        kind: "binary-missing",
        message: "The thn binary was not found in workspace.",
        detail:
          "Build it with `go build -o bin/thn ./cmd/thn`, or set THN_BINARY to its path. " +
          "The console reads through the binary and has no other source of truth.",
        command: printable,
      },
    };
  }

  // --json is always passed. The console never parses the human-readable
  // output, because its shape is a presentation choice and the JSON is the
  // contract.
  const fullArgv = [...argv, "--json"];

  return new Promise<ThnResult<T>>((resolve) => {
    execFile(
      bin,
      fullArgv,
      {
        timeout: TIMEOUT_MS,
        maxBuffer: 8 * 1024 * 1024,
        windowsHide: true,
        // A minimal environment. The binary reads THN_ROOT and similar, and an
        // inherited environment full of unrelated variables is a way for a
        // development shell to change what the console reports.
        env: {
          PATH: process.env.PATH ?? "",
          // Next.js's own types declare NODE_ENV as required. It is a harmless
          // variable for a Go binary to inherit; everything else is dropped.
          NODE_ENV: process.env.NODE_ENV ?? "production",
          ...(process.env.THN_ROOT ? { THN_ROOT: process.env.THN_ROOT } : {}),
          ...(process.env.THN_CONFIG ? { THN_CONFIG: process.env.THN_CONFIG } : {}),
        },
      },
      (error, stdout, stderr) => {
        const trimmedErr = stderr.trim();

        if (error) {
          const timedOut =
            "killed" in error && Boolean((error as { killed?: boolean }).killed);

          resolve({
            ok: false,
            error: {
              kind: timedOut ? "timeout" : "execution-failed",
              message: timedOut
                ? `\`thn ${command}\` did not finish within ${TIMEOUT_MS / 1000}s.`
                : `\`thn ${command}\` failed.`,
              detail: trimmedErr.length > 0 ? trimmedErr : error.message,
              command: printable,
            },
          });
          return;
        }

        try {
          resolve({
            ok: true,
            data: JSON.parse(stdout) as T,
            exitCode: 0,
          });
        } catch (parseError) {
          resolve({
            ok: false,
            error: {
              kind: "unparseable",
              message: `\`thn ${command}\` did not return JSON.`,
              detail:
                `${(parseError as Error).message}\n\n` +
                (trimmedErr.length > 0
                  ? trimmedErr
                  : stdout.slice(0, 400) || "(no output)"),
              command: printable,
            },
          });
        }
      },
    );
  });
}

/** The commands this console can show, for the navigation. */
export const availableCommands = Object.keys(ALLOWED).sort() as ThnCommand[];

/** Reports whether a command is permitted, for display in the about page. */
export function isPermitted(command: string): boolean {
  return Object.prototype.hasOwnProperty.call(ALLOWED, command);
}

/** The commands deliberately not permitted, and why. */
export const withheldCommands: ReadonlyArray<{ command: string; why: string }> = [
  {
    command: "activate",
    why: "The only destructive command in the binary. It refuses in this build and " +
      "is expected to keep refusing; a console that could reach it would be a " +
      "control surface for a device nobody can physically reach.",
  },
];
