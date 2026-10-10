import type { Metadata } from "next";
import Link from "next/link";
import { Nav, type NavItem } from "@/components/nav";
import { thn } from "@/lib/thn";
import type { MonitoringResponse } from "@/lib/types";
import "./globals.css";

export const metadata: Metadata = {
  title: {
    default: "THN Gateway",
    template: "%s · THN Gateway",
  },
  description:
    "Management console for the THN Gateway. See what your network is doing, and why.",
};

const NAV: ReadonlyArray<NavItem> = [
  { href: "/", label: "Dashboard", note: "Is everything working right now?" },
  { href: "/devices", label: "Devices", note: "Computers and phones on your network" },
  { href: "/networks", label: "Networks", note: "Separate groups and who can see whom" },
  { href: "/monitoring", label: "Monitoring", note: "Cables, ports and hardware health" },
  { href: "/incidents", label: "Problems", note: "What is wrong, and what to do" },
  { href: "/rules", label: "Rules", note: "The checks the gateway runs for you" },
  { href: "/policies", label: "Policies", note: "Speed limits and settings per device" },
  { href: "/schedules", label: "Schedules", note: "When a setting applies" },
  { href: "/render", label: "Preview", note: "The configuration, before it is used" },
  { href: "/about", label: "About", note: "What this console can and cannot do" },
];

export const dynamic = "force-dynamic";

/**
 * A one-line answer to "is my network okay?", shown in the chrome on every
 * page.
 *
 * It reads the gateway's own health state rather than counting anything
 * itself. The distinction matters: a console that computes its own verdict
 * from a partial view is a second opinion, and a second opinion that
 * disagrees with the gateway is worse than none.
 *
 * The states come from the binary's own vocabulary. An unrecognised value is
 * reported as unknown rather than guessed at — a made-up "everything is
 * working" from a state the console does not know is exactly the failure this
 * whole design is trying to prevent.
 */
async function gatewayStatus(): Promise<{
  tone: "ok" | "warning" | "critical";
  label: string;
} | null> {
  const res = await thn<MonitoringResponse>(["monitoring"]);
  if (!res.ok) return null;

  const { gateway } = res.data;

  switch (gateway.health_state.toLowerCase()) {
    case "critical":
    case "failed":
    case "down":
      return { tone: "critical", label: "Needs attention" };

    case "healthy":
    case "ok":
      return {
        tone: gateway.internet_status === "online" ? "ok" : "warning",
        label:
          gateway.internet_status === "online"
            ? "Everything is working"
            : "Local network working, internet not",
      };

    case "degraded":
    case "warning":
      return { tone: "warning", label: "Partly working" };

    default:
      return { tone: "warning", label: "Status unknown" };
  }
}

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const status = await gatewayStatus();

  return (
    <html lang="en">
      <body className="min-h-screen">
        {/* ---- Desktop header ---------------------------------------- */}
        <header className="sticky top-0 z-30 hidden border-b border-ink-800 bg-ink-900/90 backdrop-blur lg:block">
          <div className="shell flex h-16 items-center justify-between gap-4">
            <Link href="/" className="flex min-w-0 items-center gap-2.5">
              <span
                aria-hidden="true"
                className="grid h-8 w-8 shrink-0 place-items-center rounded bg-accent text-xs font-bold text-accent-text"
              >
                TH
              </span>
              <span className="min-w-0">
                <span className="block truncate text-sm font-semibold leading-tight text-ink-50">
                  THN Gateway
                </span>
                <span className="block truncate text-2xs leading-tight text-ink-400">
                  Your network&apos;s control panel
                </span>
              </span>
            </Link>

            {status ? (
              <span className="flex items-center gap-2 text-xs text-ink-300">
                <span
                  aria-hidden="true"
                  className={`h-2 w-2 rounded-full ${
                    status.tone === "ok"
                      ? "bg-ok"
                      : status.tone === "warning"
                        ? "bg-warning"
                        : "bg-critical"
                  }`}
                />
                {status.label}
              </span>
            ) : (
              <span className="text-xs text-ink-500">Status unavailable</span>
            )}
          </div>
        </header>

        {/*
          The mobile chrome sits OUTSIDE the content row. It used to be inside
          it, which made the mobile bar and the status strip flex siblings of
          <main>: at 874px the row had three children competing for the width
          and <main> was squeezed to zero, so the page rendered as a sidebar
          and nothing else.
        */}
        <div className="lg:hidden">
          <Nav items={NAV} status={status} variant="mobile" />
        </div>

        <div className="shell flex gap-8 pb-16 pt-4 lg:pt-6">
          <Nav items={NAV} status={status} variant="desktop" />

          <main className="min-w-0 flex-1">{children}</main>
        </div>

        <footer className="border-t border-ink-850 py-6">
          <div className="shell flex flex-col gap-1 text-2xs text-ink-500 sm:flex-row sm:items-center sm:justify-between">
            <span>THN Gateway · The Heedful</span>
            <span>Manageable only from inside your own network</span>
          </div>
        </footer>
      </body>
    </html>
  );
}
