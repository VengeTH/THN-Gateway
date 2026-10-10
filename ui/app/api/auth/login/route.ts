import { NextRequest, NextResponse } from "next/server";
import { thn } from "@/lib/thn";
import { SESSION_COOKIE_NAME, type SessionData } from "@/lib/auth";
import type { AuthLoginResponse } from "@/lib/types";

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { username, password } = body;

    if (!username || typeof username !== "string" || !password || typeof password !== "string") {
      return NextResponse.json(
        { error: "Username and password are required" },
        { status: 400 }
      );
    }

    const res = await thn<AuthLoginResponse>([
      "management",
      "auth",
      "--username",
      username,
      "--password",
      password,
    ]);

    if (!res.ok) {
      if (res.error.kind === "execution-failed" && res.error.detail) {
        try {
          const parsed = JSON.parse(res.error.detail) as AuthLoginResponse;
          if (parsed && !parsed.authenticated) {
            return NextResponse.json(
              { error: parsed.error || "Authentication failed", detail: parsed.detail },
              { status: parsed.error?.includes("not configured") ? 503 : 401 }
            );
          }
        } catch {
          // not json detail
        }
      }

      return NextResponse.json(
        { error: res.error.message || "Invalid credentials" },
        { status: 401 }
      );
    }

    const data = res.data;
    if (!data.authenticated) {
      return NextResponse.json(
        { error: data.error || "Invalid username or password", detail: data.detail },
        { status: data.error?.includes("not configured") ? 503 : 401 }
      );
    }

    const session: SessionData = {
      authenticated: true,
      username: data.username || username,
      role: data.role || "admin",
      token: data.token,
      createdAt: new Date().toISOString(),
    };

    const cookieValue = Buffer.from(JSON.stringify(session)).toString("base64url");
    const response = NextResponse.json({
      ok: true,
      username: session.username,
      role: session.role,
    });

    response.cookies.set(SESSION_COOKIE_NAME, cookieValue, {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      path: "/",
      maxAge: 60 * 60 * 24, // 24 hours
    });

    return response;
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
