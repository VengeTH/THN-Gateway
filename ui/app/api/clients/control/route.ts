import { NextRequest, NextResponse } from "next/server";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { ip, action, mbps } = body;

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
      if (!rate || rate <= 0 || rate > 95) {
        return NextResponse.json(
          { error: "Rate must be between 1 and 95 Mbps (due to Fast Ethernet limit)" },
          { status: 400 }
        );
      }
      args.push(String(Math.round(rate)));
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
