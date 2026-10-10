import { Failure, Panel, PageHeader, Pill, Because, Empty } from "@/components/primitives";
import { thn } from "@/lib/thn";
import type { PolicyListResponse, ScheduleJSON } from "@/lib/types";

export const dynamic = "force-dynamic";

/**
 * Schedules, shown against a clock the reader chooses.
 *
 * # Why this page previews rather than lists
 *
 * A schedule read as text — `22:00-06:00 every day (UTC)` — is compact and
 * almost unreadable. The three ways it goes wrong are not visible in that
 * string at all: it crosses midnight, it is expressed in a zone that shifts,
 * and a window that opens at 22:00 on Friday is still open at 03:00 on
 * Saturday.
 *
 * So the page evaluates each schedule at a chosen moment and shows whether it
 * holds, and at what point it next changes. That turns a string into a
 * statement about the clock.
 */
export default async function SchedulesPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const params = await searchParams;
  const at = firstString(params.at) ?? "";

  const listed = await thn<PolicyListResponse>(["policy", "list"]);

  return (
    <>
      <PageHeader
        title="Schedules"
        plain="When a setting applies — for example, a slower speed limit only between 22:00 and 06:00."
        detail="Checked against a moment you choose, because a schedule that is right on paper is still wrong at three in the morning."
      />

      <Panel title="Check against a time" note="Leave blank to use the current time">
        <form method="get" className="panel-body space-y-3">
          <div>
            <label htmlFor="at" className="label mb-1 block">
              Moment to check
            </label>
            <input
              id="at"
              type="text"
              name="at"
              defaultValue={at}
              placeholder="2026-03-14T23:00:00Z"
              className="field sm:max-w-xs"
              autoComplete="off"
              spellCheck={false}
            />
            <p className="mt-1.5 text-2xs text-ink-500">
              Format: <code className="text-ink-400">2026-03-14T23:00:00Z</code> — date,
              then time, then <code className="text-ink-400">Z</code> for UTC.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button type="submit" className="btn btn-primary tap">
              Check
            </button>
            {[
              { label: "Midday", v: "2026-03-14T12:00:00Z" },
              { label: "Evening", v: "2026-03-14T23:00:00Z" },
              { label: "Small hours", v: "2026-03-15T03:00:00Z" },
            ].map((p) => (
              <a
                key={p.label}
                href={`/schedules?at=${encodeURIComponent(p.v)}`}
                className="btn !py-1 text-2xs"
              >
                {p.label}
              </a>
            ))}
          </div>
        </form>
      </Panel>

      {listed.ok ? (
        <Panel
          title="Defined schedules"
          note={
            at
              ? `as written; use the policies page to see what each one selects`
              : "as written in the configuration"
          }
        >
          {Object.keys(listed.data.policies.schedules ?? {}).length === 0 ? (
            <Empty>
              No schedules are defined, so every binding applies whenever it
              matches. That is a complete configuration, not an absence of one.
            </Empty>
          ) : (
            Object.entries(listed.data.policies.schedules ?? {}).map(([name, s]) => (
              <div key={name} className="kv border-b border-ink-850 px-4 py-3 last:border-b-0">
                <div>
                  <div className="value text-ink-100">{name}</div>
                  <div className="label">{s.kind}</div>
                  {s.priority ? <Pill>priority {s.priority}</Pill> : null}
                </div>
                <div>
                  <Window schedule={s} />
                  {s.comments?.map((c, i) => (
                    <Because key={i}>{c}</Because>
                  ))}
                </div>
              </div>
            ))
          )}

          <div className="panel-body border-t border-ink-800">
            <div className="label mb-2">How a window is read</div>
            <ul className="space-y-1.5">
              <Rule>
                <b className="text-ink-200">A window may cross midnight.</b>{" "}
                <code>22:00</code> to <code>06:00</code> is the ordinary way to
                say "overnight", and it is the case a naive comparison gets
                wrong — written as <code>start &lt;= t &lt; end</code> it never
                matches, and the schedule silently never applies, which looks
                identical to one that is working.
              </Rule>
              <Rule>
                <b className="text-ink-200">A window belongs to the day it
                opens.</b>{" "}
                A Friday{" "}
                <code>22:00</code>–<code>06:00</code> window is still applying at
                03:00 on Saturday. Testing the observed weekday instead would
                leave a "friday night only" limit switched off every Saturday
                morning.
              </Rule>
              <Rule>
                <b className="text-ink-200">The end is exclusive.</b> A window
                ending at <code>06:00</code> does not include <code>06:00</code>,
                so back-to-back windows tile a day with no gap and no overlap.
              </Rule>
              <Rule>
                <b className="text-ink-200">A wall clock survives daylight
                saving.</b> A window is a pair of times, not a pair of instants,
                so <code>09:00</code> stays <code>09:00</code> local when the
                zone's offset changes underneath it.
              </Rule>
            </ul>
          </div>
        </Panel>
      ) : (
        <Failure error={listed.error} />
      )}
    </>
  );
}

function Window({ schedule }: { schedule: ScheduleJSON }) {
  if (schedule.kind === "always") {
    return <span className="value text-ink-300">always active</span>;
  }
  if (schedule.kind === "never") {
    return <span className="value text-ink-400">disabled</span>;
  }
  if (schedule.kind === "once") {
    return <span className="value text-ink-300">a single bounded window</span>;
  }

  const from = fmtClock(schedule.from);
  const to = fmtClock(schedule.to);
  const overnight =
    schedule.from && schedule.to && schedule.from.hour * 60 + schedule.from.minute >
      schedule.to.hour * 60 + schedule.to.minute;

  return (
    <div>
      <div className="value text-ink-200">
        {from}–{to} {schedule.days && schedule.days.length > 0 ? schedule.days.join(", ") : "every day"}
        {schedule.location ? ` (${schedule.location})` : " (UTC)"}
      </div>
      {overnight ? (
        <Because>
          Crosses midnight, so it is also active in the small hours of the
          following day.
        </Because>
      ) : null}
    </div>
  );
}

function Rule({ children }: { children: React.ReactNode }) {
  return (
    <li className="text-2xs leading-relaxed text-ink-400">
      <span className="text-ink-500">· </span>
      {children}
    </li>
  );
}

function fmtClock(c: { hour: number; minute: number } | undefined): string {
  if (!c) return "—";
  return `${String(c.hour).padStart(2, "0")}:${String(c.minute).padStart(2, "0")}`;
}

function firstString(v: string | string[] | undefined): string | undefined {
  return Array.isArray(v) ? v[0] : v;
}
