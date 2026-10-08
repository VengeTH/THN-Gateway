import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";

export const metadata: Metadata = {
  title: "THN Gateway",
  description:
    "Read-only console for the THN gateway. Renders what the Go binary reports; applies nothing.",
};

const NAV: ReadonlyArray<{ href: string; label: string; note: string }> = [
  { href: "/", label: "Dashboard", note: "live mobile-first gateway overview" },
  { href: "/devices", label: "Devices", note: "connected clients, limits & policies" },
  { href: "/networks", label: "Networks", note: "zones, subnets & VLAN isolation" },
  { href: "/monitoring", label: "Monitoring", note: "interfaces, WAN & host vitals" },
  { href: "/rules", label: "Rules", note: "the conditions THN evaluates" },
  { href: "/incidents", label: "Incidents", note: "what those conditions concluded" },
  { href: "/policies", label: "Policies", note: "per-device and per-time settings" },
  { href: "/schedules", label: "Schedules", note: "when a policy applies" },
  { href: "/render", label: "Rendered", note: "the artefacts THN would hand a kernel" },
  { href: "/about", label: "About", note: "what this console can and cannot do" },
];

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <div className="min-h-screen">
          <header className="border-b border-ink-800 bg-ink-900 sticky top-0 z-20">
            <div className="mx-auto flex max-w-6xl items-center justify-between px-4 sm:px-6 py-3">
              <div className="flex items-baseline gap-3">
                <Link href="/" className="text-sm font-semibold tracking-tight text-ink-50 hover:text-white">
                  THN Gateway
                </Link>
                <span className="rounded border border-ok/30 bg-ok/10 px-1.5 py-0.5 text-2xs font-medium text-ok">
                  appliance mode
                </span>
              </div>
              <span className="text-2xs text-ink-400 hidden sm:inline">
                local management &middot; fail-closed control
              </span>
            </div>
          </header>

          <div className="mx-auto flex max-w-6xl flex-col md:flex-row gap-6 px-4 sm:px-6 py-6">
            <nav className="w-full md:w-56 shrink-0">
              <ul className="flex md:flex-col overflow-x-auto md:overflow-visible gap-1 md:space-y-0.5 pb-2 md:pb-0 md:sticky md:top-16">
                {NAV.map((item) => (
                  <li key={item.href} className="shrink-0 md:shrink">
                    <Link
                      href={item.href}
                      className="block rounded px-2.5 py-1.5 transition-colors hover:bg-ink-850 whitespace-nowrap md:whitespace-normal"
                    >
                      <span className="block text-xs font-medium text-ink-200">
                        {item.label}
                      </span>
                      <span className="block text-2xs text-ink-500 hidden md:block">{item.note}</span>
                    </Link>
                  </li>
                ))}
              </ul>
            </nav>

            <main className="min-w-0 flex-1 pb-16">{children}</main>
          </div>
        </div>
      </body>
    </html>
  );
}
