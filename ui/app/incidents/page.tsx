import Link from "next/link";
import {
  Failure,
  Panel,
  PageHeader,
  Callout,
  SeverityPill,
  Pill,
  Because,
  Empty,
} from "@/components/primitives";
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
      <PageHeader
        title="Problems"
        plain="What is wrong with your network right now, and what to do about it."
        detail="The gateway runs the checks on the Rules page and reports anything that needs your attention here."
      />

      {/* The limitation, immediately after the page says what the page is. */}
      <div className="mb-4">
        <Callout tone="info" title="This build does not keep a history">
          <p>
            Nothing on this page is a record of something that happened. The
            part of the gateway that would save history is not built yet, so
            problems are not remembered between visits.
          </p>
          <p>
            Describe a situation below and the gateway will run its checks
            against it. What you see is worked out from what you typed — it is
            not something the gateway has observed.
          </p>
        </Callout>
      </div>

      <Panel
        title="Describe a situation"
        note="Write what you observed as name=value pairs, separated by spaces"
      >
        <form method="get" className="panel-body space-y-3">
          <div>
            <label htmlFor="observe" className="label mb-1 block">
              What you are seeing
            </label>
            <input
              id="observe"
              type="text"
              name="observe"
              defaultValue={observe ?? ""}
              placeholder="network.inspect.supported=true network.wan.present=true network.wan.up=false"
              className="field"
              autoComplete="off"
              spellCheck={false}
            />
            <p className="mt-1.5 text-2xs leading-relaxed text-ink-500">
              Use <code className="text-ink-400">?</code> for anything you could
              not find out. The gateway treats &ldquo;could not check&rdquo;
              differently from a genuine <code className="text-ink-400">false</code>.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button type="submit" className="btn btn-primary tap">
              Run the checks
            </button>
            {observe ? (
              <Link href="/incidents" className="link">
                Clear
              </Link>
            ) : null}
          </div>
        </form>
      </Panel>

      {listed === null ? (
        <Panel title="Problems" note="nothing was checked">
          <Empty>
            You have not described a situation, so no check has run and there is
            nothing to report. That is not the same as your network having no
            problems — it means nobody has asked yet. Describe a situation
            above, or open the{" "}
            <Link href="/rules" className="link">
              rules page
            </Link>{" "}
            to see each check&apos;s conclusion on its own.
          </Empty>
        </Panel>
      ) : listed.ok ? (
        <Panel
          title="What your description implies"
          note="worked out from what you typed above; not observed from the gateway"
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
              No problems found. If that surprises you, open the{" "}
              <Link href="/rules" className="link">
                rules page
              </Link>{" "}
              with the same description: every check has a minimum duration, so a
              fault that is genuinely true is reported as &ldquo;waiting&rdquo;
              rather than &ldquo;happening&rdquo;, and a check that could not
              read its input is reported as &ldquo;unknown&rdquo; rather than as
              fine.
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

                <div className="mb-2 grid grid-cols-2 gap-3 sm:grid-cols-4">
                  <div>
                    <div className="label">started</div>
                    <div className="value text-ink-300">{shortTime(inc.opened_at)}</div>
                  </div>
                  <div>
                    <div className="label">lasting</div>
                    <div className="value text-ink-300">{inc.duration}</div>
                  </div>
                  <div>
                    <div className="label">root causes</div>
                    <div className="value text-ink-300">{inc.causes.length}</div>
                  </div>
                  <div>
                    <div className="label">knock-on effects</div>
                    <div className="value text-ink-300">{inc.consequences?.length ?? 0}</div>
                  </div>
                </div>

                <div className="label mb-1">What caused it</div>
                {inc.causes.map((c) => (
                  <div key={c.rule} className="kv py-0.5">
                    <span className="value break-all text-ink-200">{c.rule}</span>
                    <span className="text-2xs text-ink-400">{c.title}</span>
                  </div>
                ))}

                {inc.consequences && inc.consequences.length > 0 ? (
                  <>
                    <div className="label mb-1 mt-2">Also affected, but not reported separately</div>
                    {inc.consequences.map((c) => (
                      <div key={c.rule} className="kv py-0.5">
                        <span className="value break-all text-ink-400 line-through decoration-ink-700">
                          {c.rule}
                        </span>
                        <span className="text-2xs text-ink-500">
                          because of {c.suppressed_by}
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
