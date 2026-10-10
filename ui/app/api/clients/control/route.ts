import { NextRequest, NextResponse } from "next/server";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { ip, action, mbps, direction } = body;

    if (!ip || typeof ip !== "string") {
      return NextResponse.json({ error: "Invalid or missing IP address" }, { status: 400 });
    }

    if (!["limit", "unlimit", "block", "unblock"].includes(action)) {
      return NextResponse.json({ error: "Invalid action" }, { status: 400 });
    }

    const scriptPath = "/usr/local/bin/thn-client-control";
    const args: string[] = [action, ip];

    if (action === "limit") {
      const rate = Number(mbps);
      // The engine clamps to the real link ceiling and reports what it did.
      // Rejecting 95+ here was wrong: it hard-coded Fast Ethernet into the
      // API, so a gigabit uplink could never be given more than 95 Mbps.
      if (!Number.isFinite(rate) || rate <= 0 || rate > 10000) {
        return NextResponse.json(
          { error: "Rate must be a whole number of Mbps between 1 and 10000" },
          { status: 400 }
        );
      }

      // "both" is the default so an older client that does not send a
      // direction still gets the previous, symmetric behaviour.
      const dir = ["both", "upload", "download"].includes(direction) ? direction : "both";

      args.push(String(Math.round(rate)), dir);
    }

    try {
      const { stdout } = await execFileAsync("sudo", [scriptPath, ...args]);
      return NextResponse.json({ ok: true, output: stdout.trim() });
    } catch {
      // Fallback: try executing without sudo
      const { stdout } = await execFileAsync(scriptPath, args);
      return NextResponse.json({ ok: true, output: stdout.trim() });
    }
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
