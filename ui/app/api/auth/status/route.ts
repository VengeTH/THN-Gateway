import { NextResponse } from "next/server";
import { getAuthStatus, getSession } from "@/lib/auth";

export async function GET() {
  const [status, session] = await Promise.all([getAuthStatus(), getSession()]);
  return NextResponse.json({
    configured: status.configured,
    operatorUsername: status.username,
    session: session
      ? {
          authenticated: true,
          username: session.username,
          role: session.role,
        }
      : null,
  });
}
