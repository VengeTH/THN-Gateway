"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

interface UserBadgeProps {
  username: string;
}

export function UserBadge({ username }: UserBadgeProps) {
  const router = useRouter();
  const [loggingOut, setLoggingOut] = useState(false);

  async function handleLogout() {
    setLoggingOut(true);
    try {
      await fetch("/api/auth/logout", { method: "POST" });
      router.refresh();
      window.location.reload();
    } catch {
      setLoggingOut(false);
    }
  }

  return (
    <div className="flex items-center gap-3">
      <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-ink-850 border border-ink-750 text-2xs text-ink-200">
        <span className="h-1.5 w-1.5 rounded-full bg-ok" />
        <span className="font-medium text-ink-300">operator:</span>
        <span className="font-semibold text-ink-100">{username}</span>
      </div>
      <button
        type="button"
        onClick={handleLogout}
        disabled={loggingOut}
        className="text-2xs text-ink-400 hover:text-ink-200 underline underline-offset-2 transition-colors disabled:opacity-50"
      >
        {loggingOut ? "Signing out..." : "Sign out"}
      </button>
    </div>
  );
}
