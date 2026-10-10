"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { HexagonalEyeLogo } from "@/components/logo";

interface LoginViewProps {
  configured: boolean;
  operatorUsername?: string;
}

export function LoginView({ configured, operatorUsername }: LoginViewProps) {
  const router = useRouter();
  const [username, setUsername] = useState(operatorUsername || "");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });

      const data = await res.json();

      if (!res.ok) {
        if (res.status === 503) {
          setError(
            data.detail ||
              "Gateway management is unconfigured. Set operator credentials in /etc/thn/config.yaml."
          );
        } else {
          setError(data.error || "Invalid username or password");
        }
        setLoading(false);
        return;
      }

      // Success: reload or refresh route
      router.refresh();
      window.location.reload();
    } catch {
      setError("Network error communicating with gateway console");
      setLoading(false);
    }
  }

  return (
    <div className="flex min-h-[80vh] flex-col items-center justify-center px-4 py-12">
      <div className="w-full max-w-md space-y-6">
        {/* Branding header */}
        <div className="text-center space-y-3">
          <div className="inline-flex items-center justify-center p-3 rounded-2xl bg-ink-900 border border-ink-800 shadow-xl">
            <HexagonalEyeLogo className="h-12 w-12" />
          </div>
          <div>
            <h1 className="text-2xl font-bold font-display tracking-tight text-ink-50">
              THN Gateway
            </h1>
            <p className="text-xs text-ink-400 mt-1">
              The Heedful Network Appliance · Local Administration
            </p>
          </div>
        </div>

        {/* Card */}
        <div className="rounded-2xl border border-ink-800 bg-ink-900/90 p-6 sm:p-8 backdrop-blur shadow-2xl space-y-6">
          <div className="border-b border-ink-800/80 pb-4">
            <h2 className="text-base font-semibold text-ink-100">
              Gateway Operator Login
            </h2>
            <p className="text-xs text-ink-400 mt-0.5">
              Enter operator credentials to access network controls and diagnostics.
            </p>
          </div>

          {!configured && (
            <div className="rounded-lg border border-warning/40 bg-warning/10 p-3.5 text-xs text-warning-fg space-y-1">
              <div className="font-semibold flex items-center gap-1.5">
                <span className="inline-block h-2 w-2 rounded-full bg-warning" />
                Management Unconfigured
              </div>
              <p className="text-2xs text-ink-300 leading-relaxed">
                No operator credentials are set on this gateway. To enable login, configure{" "}
                <code className="text-accent font-mono text-2xs">management.operator_username</code> and{" "}
                <code className="text-accent font-mono text-2xs">management.operator_password</code> in{" "}
                <code className="text-ink-200 font-mono text-2xs">/etc/thn/config.yaml</code>.
              </p>
            </div>
          )}

          {error && (
            <div className="rounded-lg border border-critical/40 bg-critical/10 p-3 text-xs text-critical-fg">
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-1.5">
              <label
                htmlFor="username"
                className="block text-xs font-medium text-ink-300"
              >
                Operator Username
              </label>
              <input
                id="username"
                type="text"
                required
                autoComplete="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="e.g. admin"
                className="w-full rounded-lg border border-ink-750 bg-ink-950 px-3.5 py-2.5 text-sm text-ink-100 placeholder:text-ink-600 focus:border-accent focus:outline-none focus:ring-1 focus:ring-accent transition-colors"
              />
            </div>

            <div className="space-y-1.5">
              <label
                htmlFor="password"
                className="block text-xs font-medium text-ink-300"
              >
                Operator Password
              </label>
              <input
                id="password"
                type="password"
                required
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full rounded-lg border border-ink-750 bg-ink-950 px-3.5 py-2.5 text-sm text-ink-100 placeholder:text-ink-600 focus:border-accent focus:outline-none focus:ring-1 focus:ring-accent transition-colors"
              />
            </div>

            <button
              type="submit"
              disabled={loading || !configured}
              className="w-full mt-2 inline-flex items-center justify-center rounded-lg bg-accent px-4 py-2.5 text-sm font-semibold text-ink-950 shadow-md hover:bg-amber-400 focus:outline-none focus:ring-2 focus:ring-accent focus:ring-offset-2 focus:ring-offset-ink-900 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
            >
              {loading ? (
                <span className="flex items-center gap-2">
                  <svg className="animate-spin h-4 w-4 text-ink-950" viewBox="0 0 24 24" fill="none">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                  </svg>
                  Authenticating...
                </span>
              ) : (
                "Sign In to Gateway"
              )}
            </button>
          </form>

          <div className="pt-2 border-t border-ink-850/80 text-center">
            <span className="text-2xs text-ink-500">
              Connected via 10.77.0.1 · Direct LAN Administration
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
