import { cookies } from "next/headers";
import { thn } from "./thn";
import type { AuthStatusResponse } from "./types";

export const SESSION_COOKIE_NAME = "thn_session";

export interface SessionData {
  authenticated: boolean;
  username: string;
  role: string;
  token?: string;
  createdAt: string;
}

/**
 * Returns current authenticated session from the encrypted/signed session cookie.
 */
export async function getSession(): Promise<SessionData | null> {
  const cookieStore = await cookies();
  const sessionCookie = cookieStore.get(SESSION_COOKIE_NAME);

  if (!sessionCookie || !sessionCookie.value) {
    return null;
  }

  try {
    const raw = Buffer.from(sessionCookie.value, "base64url").toString("utf-8");
    const parsed = JSON.parse(raw) as SessionData;
    if (parsed && parsed.authenticated && parsed.username) {
      return parsed;
    }
  } catch {
    // Malformed session cookie
    return null;
  }

  return null;
}

/**
 * Checks whether operator credentials have been configured on the gateway.
 */
export async function getAuthStatus(): Promise<AuthStatusResponse> {
  const res = await thn<AuthStatusResponse>(["management", "auth", "--status"]);
  if (res.ok && res.data) {
    return res.data;
  }
  return { configured: false };
}
