"use client";

/**
 * Navigation that works on a phone.
 *
 * # Why this is a client component
 *
 * The sidebar needs three things a server component cannot do: know which
 * route is current, open and close, and lock the page behind the drawer while
 * it is open. All three are interaction, so the nav is the one interactive
 * island in an otherwise server-rendered application.
 *
 * # Why a drawer rather than a scroll strip
 *
 * The previous version collapsed the nav into a horizontal scroller on
 * narrow screens. Ten items scrolled sideways, off the edge of a phone, with
 * no menu button and no indication that there were more. A person opening
 * this on a phone could reach six of the ten pages and would have no way to
 * know what the other four were.
 *
 * A drawer lists all ten, names the current one, and closes on selection.
 */

import { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { HexagonalEyeLogo } from "./logo";

export interface NavItem {
  href: string;
  label: string;
  note: string;
}

export function Nav({
  items,
  status,
  variant,
}: {
  items: ReadonlyArray<NavItem>;
  status: { tone: "ok" | "warning" | "critical"; label: string } | null;
  /**
   * Which half to render.
   *
   * Split rather than one component that hides halves with CSS, because the
   * two live in different places in the document: the mobile bar belongs
   * above the content row, and the rail belongs inside it as a flex child.
   * Rendering both and hiding one collapses the content at the widths where
   * the hidden one is still a flex item.
   */
  variant: "mobile" | "desktop";
}) {
  const pathname = usePathname();
  const [open, setOpen] = useState(false);

  // Close the drawer on navigation. Without this the drawer stays open over
  // the page the person just asked for, which is disorienting and hides the
  // thing they navigated to read.
  useEffect(() => {
    setOpen(false);
  }, [pathname]);

  // Escape closes it, and the page behind it stops scrolling. A drawer over a
  // scrollable page is unusable on a phone otherwise — the background scrolls
  // under the finger and the drawer appears to have detached.
  useEffect(() => {
    if (!open) return;

    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    window.addEventListener("keydown", onKey);

    return () => {
      document.body.style.overflow = previousOverflow;
      window.removeEventListener("keydown", onKey);
    };
  }, [open]);

  // Close the drawer if the viewport grows past the breakpoint, otherwise a
  // resize from phone to desktop leaves an invisible drawer holding the page
  // scroll hostage.
  useEffect(() => {
    const mq = window.matchMedia("(min-width: 1024px)");
    const onChange = () => {
      if (mq.matches) setOpen(false);
    };
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, []);

  const isActive = (href: string) =>
    href === "/" ? pathname === "/" : pathname.startsWith(href);

  const current = items.find((i) => isActive(i.href));

  if (variant === "desktop") {
    return (
      <nav aria-label="Main" className="hidden w-60 shrink-0 lg:block">
        <ul className="sticky top-24 space-y-0.5">
          {items.map((item) => {
            const active = isActive(item.href);
            return (
              <li key={item.href}>
                <Link
                  href={item.href}
                  aria-current={active ? "page" : undefined}
                  className={[
                    "flex items-start gap-2.5 rounded-md px-2.5 py-2 transition-colors",
                    active
                      ? "bg-ink-800 text-ink-50 shadow-[inset_2px_0_0_0_#ffc107]"
                      : "text-ink-300 hover:bg-ink-850 hover:text-ink-100",
                  ].join(" ")}
                >
                  <span className="min-w-0">
                    <span className="block text-sm font-medium">{item.label}</span>
                    <span className="block text-2xs leading-snug text-ink-500">{item.note}</span>
                  </span>
                </Link>
              </li>
            );
          })}
        </ul>
      </nav>
    );
  }

  return (
    <>
      {/* ---- Mobile bar ---------------------------------------------- */}
      <div className="sticky top-0 z-30 border-b border-ink-800 bg-ink-900/95 backdrop-blur">
        <div className="shell flex h-14 items-center justify-between gap-3">
          <Link
            href="/"
            className="flex min-w-0 items-center gap-2.5"
            aria-label="THN Gateway, go to dashboard"
          >
            <HexagonalEyeLogo className="h-7 w-7" />
            <span className="min-w-0">
              <span className="block truncate text-sm font-bold font-display leading-tight text-ink-50">
                THN Gateway
              </span>
              <span className="block truncate text-2xs leading-tight text-ink-400">
                {current?.label ?? "Dashboard"}
              </span>
            </span>
          </Link>

          <button
            type="button"
            onClick={() => setOpen(true)}
            aria-expanded={open}
            aria-controls="thn-nav-drawer"
            className="btn tap shrink-0 gap-2"
          >
            <svg
              aria-hidden="true"
              viewBox="0 0 20 20"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.75"
              strokeLinecap="round"
              className="h-4 w-4"
            >
              <path d="M3 5h14M3 10h14M3 15h14" />
            </svg>
            Menu
          </button>
        </div>
      </div>

      {/*
        The status is on the mobile bar because it is the single most
        important fact on the page and the drawer is closed by default. On a
        phone the alternative is that it is one tap away.
      */}
      {status ? (
        <div className="shell pt-3">
          <Link
            href="/incidents"
            className={`flex items-center justify-between gap-3 rounded-md border px-3 py-2 ${
              status.tone === "ok"
                ? "border-ok-edge/40 bg-ok-muted/10"
                : status.tone === "warning"
                  ? "border-warning-edge/40 bg-warning-muted/10"
                  : "border-critical-edge/50 bg-critical-muted/10"
            }`}
          >
            <span className="flex min-w-0 items-center gap-2">
              <span
                aria-hidden="true"
                className={`h-2 w-2 shrink-0 rounded-full ${
                  status.tone === "ok"
                    ? "bg-ok"
                    : status.tone === "warning"
                      ? "bg-warning"
                      : "bg-critical"
                }`}
              />
              <span className="truncate text-xs font-medium text-ink-100">{status.label}</span>
            </span>
            <span className="shrink-0 text-2xs text-ink-400">Details →</span>
          </Link>
        </div>
      ) : null}

      {/* ---- Drawer ---------------------------------------------------- */}
      {open ? (
        <div className="fixed inset-0 z-40">
          <button
            type="button"
            aria-label="Close menu"
            onClick={() => setOpen(false)}
            className="absolute inset-0 animate-fade-in bg-ink-950/80 backdrop-blur-sm"
          />

          <div
            id="thn-nav-drawer"
            role="dialog"
            aria-modal="true"
            aria-label="Main menu"
            className="absolute inset-y-0 left-0 flex w-[min(20rem,85vw)] animate-slide-down flex-col border-r border-ink-800 bg-ink-900 shadow-pop"
          >
            <div className="flex h-14 shrink-0 items-center justify-between border-b border-ink-800 px-3">
              <div className="flex items-center gap-2">
                <HexagonalEyeLogo className="h-6 w-6" />
                <span className="text-sm font-bold font-display text-ink-50">Navigation</span>
              </div>
              <button
                type="button"
                onClick={() => setOpen(false)}
                aria-label="Close menu"
                className="btn h-9 w-9 !px-0"
              >
                <svg
                  aria-hidden="true"
                  viewBox="0 0 20 20"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="1.75"
                  strokeLinecap="round"
                  className="h-4 w-4"
                >
                  <path d="M5 5l10 10M15 5L5 15" />
                </svg>
              </button>
            </div>

            <nav className="flex-1 overflow-y-auto p-2">
              <ul className="space-y-0.5">
                {items.map((item) => {
                  const active = isActive(item.href);
                  return (
                    <li key={item.href}>
                      <Link
                        href={item.href}
                        aria-current={active ? "page" : undefined}
                        className={[
                          "flex items-start gap-2.5 rounded-md px-2.5 py-2 transition-colors",
                          active
                            ? "bg-ink-800 text-ink-50 shadow-[inset_2px_0_0_0_#ffc107]"
                            : "text-ink-300 hover:bg-ink-850 hover:text-ink-100",
                        ].join(" ")}
                      >
                        <span className="min-w-0">
                          <span className="block text-sm font-medium">{item.label}</span>
                          <span className="block text-2xs leading-snug text-ink-500">
                            {item.note}
                          </span>
                        </span>
                      </Link>
                    </li>
                  );
                })}
              </ul>
            </nav>

            <div className="shrink-0 border-t border-ink-800 px-3 py-3 text-2xs text-ink-500">
              Manageable only from inside your own network
            </div>
          </div>
        </div>
      ) : null}
    </>
  );
}