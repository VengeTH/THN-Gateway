import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";

export const metadata: Metadata = {
  title: "THN Gateway",
  description:
    "Read-only console for the THN gateway. Renders what the Go binary reports; applies nothing.",
};

const NAV: ReadonlyArray<{ href: string; label: string; note: string }> = [
  { href: "/", label: "Overview", note: "what the gateway reports about itself" },
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
          <header className="border-b border-ink-800 bg-ink-900">
            <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-3">
              <div className="flex items-baseline gap-3">
                <span className="text-sm font-semibold tracking-tight text-ink-50">
                  THN Gateway
                </span>
                {/* A standing reminder, not a page. An operator who has this
                    open on a screen in the corner of a room should be able to
                    see that nothing here is a control. */}
                <span className="rounded border border-ok/30 bg-ok/10 px-1.5 py-0.5 text-2xs font-medium text-ok">
                  read-only
                </span>
              </div>
              <span className="text-2xs text-ink-400">
                renders what thn reports &middot; applies nothing
              </span>
            </div>
          </header>

          <div className="mx-auto flex max-w-6xl gap-8 px-6 py-6">
            <nav className="w-56 shrink-0">
              <ul className="sticky top-6 space-y-0.5">
                {NAV.map((item) => (
                  <li key={item.href}>
                    <Link
                      href={item.href}
                      className="block rounded px-2 py-1.5 transition-colors hover:bg-ink-850"
                    >
                      <span className="block text-xs font-medium text-ink-200">
                        {item.label}
                      </span>
                      <span className="block text-2xs text-ink-500">{item.note}</span>
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
