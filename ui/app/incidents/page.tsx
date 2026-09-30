import { Failure, Panel, SeverityPill, Pill, Because, Empty } from "@/components/primitives";
import { thn } from "@/lib/thn";
import type { ThnResult } from "@/lib/thn";
import type { IncidentsResponse } from "@/lib/types";

export const dynamic = "force-dynamic";

/**
 * Incidents, evaluated rather than remembered.
 *
 * # Why this page leads with what it does not have
 *
 * There is no daemon in this build, so there is no incident history. The
 * console could load the page, find no incidents and render an empty list —
 * and that empty list would be read as "the gateway is fine", which is the
 * single most expensive misreading a monitoring tool can produce.
 *
 * So the page states the limitation first, before any data. An operator should
 * never have to notice a caveat at the bottom of a screen.
 *
 * A user-supplied observation is accepted so the pipeline can be exercised, and
 * the resulting incidents are labelled as computed from that observation rather
 * than as a record of anything.
 */
export default async function IncidentsPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const params = await searchParams;
  const observe = firstString(params.observe);

  // The binary refuses to be asked for incidents with nothing to evaluate, and
  // it is right to: an empty result computed from no observations is not the
  // same as a gateway with nothing wrong, and the command declines to
  // manufacture the appearance of the former. So the page does not ask. With
  // no observation it says that nothing was evaluated, which is the truth and is
  // a different statement from either "no incidents" or "the query failed".
  const listed: ThnResult<IncidentsResponse> | null = observe
    ? await thn<IncidentsResponse>(["incidents", "list", "--observe", observe])
    : null;

  return (
    <>
      <h1 className="mb-1 text-lg font-semibold tracking-tight text-ink-50">Incidents</h1>

      {/* The limitation, above everything. */}
      <div className="panel mb-4 border-ink-700 bg-ink-900">
        <div className="panel-body">
          <div className="flex items-center gap-2">
            <span className="text-2xs font-semibold uppercase tracking-wide text-ink-200">
              no retained history
            </span>
            <Pill>no daemon in this build</Pill>
          </div>
          <p className="mt-2 text-xs text-ink-300">
            Nothing on this page is a record of what has happened. The state
            database and the daemon that would write to it are not part of this
            build, so there is nothing to read back and nothing is remembered
            between requests.
          </p>
          <p className="mt-1 text-2xs text-ink-400">
            Supply an observation below to run the rules and see what they would
            conclude. The result is computed from what you typed, not observed
            from the gateway.
          </p>
        </div>
      </div>

      <Panel
        title="Observe"
        note="space-separated name=value pairs; ? means the value could not be read"
      >
        <form method="get" className="panel-body">
          <div className="flex flex-wrap gap-2">
            <input
              type="text"
              name="observe"
              defaultValue={observe ?? ""}
              placeholder="network.inspect.supported=true network.wan.present=true network.wan.up=false"
              className="min-w-[24rem] flex-1 rounded border border-ink-700 bg-ink-950 px-3 py-2 font-mono text-xs text-ink-100 outline-none focus:border-ink-500"
            />
            <button
              type="submit"
              className="rounded border border-ink-600 bg-ink-800 px-3 py-1.5 text-xs font-medium text-ink-100 hover:bg-ink-700"
            >
              Evaluate
            </button>
          </div>
          {observe ? (
            <a
              href="/incidents"
              className="mt-2 inline-block text-2xs text-ink-400 underline decoration-ink-700 hover:text-ink-200"
            >
              clear
            </a>
          ) : null}
        </form>
      </Panel>

      {listed === null ? (
        <Panel title="Incidents" note="nothing was evaluated">
          <Empty>
            No observation was supplied, so no rule ran and there is nothing to
            report. That is not the same as a gateway with no incidents — it is
            the absence of a question. Supply observations above, or open the{" "}
            <a href="/rules" className="underline decoration-ink-700">
              rules page
            </a>{" "}
            to see each rule&apos;s conclusion individually.
          </Empty>
        </Panel>
      ) : listed.ok ? (
        <Panel
          title="Implied by your observation"
          note="computed from the observation above; not observed from the gateway"
          action={
            <span className="flex gap-1.5">
              <Pill>{listed.data.summary.active} active</Pill>
              <Pill>{listed.data.summary.resolved} resolved</Pill>
              {listed.data.summary.flapping > 0 ? (
                <Pill>{listed.data.summary.flapping} flapping</Pill>
              ) : null}
            </span>
          }
        >
          {listed.data.incidents.length === 0 ? (
            <Empty>
              No incidents. If that surprises you, check the{" "}
              <a href="/rules" className="underline decoration-ink-700">
                rules page
              </a>{" "}
              with the same observations: every rule has a duration threshold, so
              a condition that is genuinely true is reported as pending rather
              than firing, and a rule that could not read its input is reported
              as undecidable rather than as fine.
            </Empty>
          ) : (
            listed.data.incidents.map((inc) => (
              <article key={inc.id} className="border-b border-ink-850 py-3 last:border-b-0">
                <div className="mb-1 flex flex-wrap items-center gap-2">
                  <SeverityPill severity={inc.severity} />
                  <span className="text-xs font-medium text-ink-100">{inc.title}</span>
                  {inc.status === "resolved" ? <Pill>resolved</Pill> : null}
                  {inc.flaps > 0 ? <Pill>flapped {inc.flaps}×</Pill> : null}
                </div>

                <div className="mb-2 grid grid-cols-4 gap-3">
                  <div>
                    <div className="label">opened</div>
                    <div className="value text-ink-300">{shortTime(inc.opened_at)}</div>
                  </div>
                  <div>
                    <div className="label">duration</div>
                    <div className="value text-ink-300">{inc.duration}</div>
                  </div>
                  <div>
                    <div className="label">causes</div>
                    <div className="value text-ink-300">{inc.causes.length}</div>
                  </div>
                  <div>
                    <div className="label">consequences</div>
                    <div className="value text-ink-300">
                      {inc.consequences?.length ?? 0}
                    </div>
                  </div>
                </div>

                <div className="label mb-1">Causes</div>
                {inc.causes.map((c) => (
                  <div key={c.rule} className="flex items-baseline gap-2 py-0.5">
                    <span className="value w-56 shrink-0 text-ink-200">{c.rule}</span>
                    <span className="text-2xs text-ink-400">{c.title}</span>
                  </div>
                ))}

                {inc.consequences && inc.consequences.length > 0 ? (
                  <>
                    <div className="label mb-1 mt-2">Suppressed as consequences</div>
                    {inc.consequences.map((c) => (
                      <div key={c.rule} className="flex items-baseline gap-2 py-0.5">
                        <span className="value w-56 shrink-0 text-ink-400 line-through decoration-ink-700">
                          {c.rule}
                        </span>
                        <span className="text-2xs text-ink-500">
                          suppressed by {c.suppressed_by}
                        </span>
                      </div>
                    ))}
                    <Because>
                      Kept rather than discarded. The consequence is still true,
                      and losing it would mean that resolving the cause also
                      loses everything else that was true at the time.
                    </Because>
                  </>
                ) : null}

                <details className="mt-2">
                  <summary className="cursor-pointer text-2xs text-ink-400 hover:text-ink-200">
                    timeline ({inc.timeline.length})
                  </summary>
                  <ol className="mt-1 space-y-1 border-l border-ink-800 pl-3">
                    {inc.timeline.map((e, i) => (
                      <li key={`${e.at}-${i}`}>
                        <div className="flex items-baseline gap-2">
                          <span className="value text-ink-500">{shortTime(e.at)}</span>
                          <span className="text-2xs text-ink-300">{e.action}</span>
                        </div>
                        <Because>{e.detail}</Because>
                      </li>
                    ))}
                  </ol>
                </details>

                <div className="mt-2 text-2xs text-ink-600">
                  <code>{inc.id}</code> · <code>{inc.fingerprint}</code> ·{" "}
                  <code>{inc.key}</code>
                </div>
              </article>
            ))
          )}
        </Panel>
      ) : (
        <Failure error={listed.error} />
      )}
    </>
  );
}

function firstString(v: string | string[] | undefined): string | undefined {
  return Array.isArray(v) ? v[0] : v;
}

/** Renders a timestamp compactly, without inventing a timezone. */
function shortTime(iso: string): string {
  return iso.replace("T", " ").replace(/\.\d+Z$/, "").replace("Z", "");
}
