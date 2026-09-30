import { Failure, Panel, SeverityPill, StatePill, Pill, Because, Empty } from "@/components/primitives";
import { thn } from "@/lib/thn";
import type { RulesListResponse, RulesTestResponse, Signal } from "@/lib/types";

export const dynamic = "force-dynamic";

/**
 * The rule set, and a way to try a rule against a made-up gateway.
 *
 * The test form is the reason this page exists. A rule set that has never been
 * exercised against an observation is a rule set nobody knows works, and the
 * three-valued logic — true, false, and could-not-tell — is invisible in a
 * list of rule names.
 *
 * The form is a GET, so a test is a shareable URL. There is no POST, no state,
 * and nothing stored: the observation exists only in the address bar.
 */
export default async function RulesPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const params = await searchParams;

  const listed = await thn<RulesListResponse>(["rules", "list"]);

  // An observation arrives as name=value pairs in a single field, because the
  // browser form serialises repeated fields into an array and the observation
  // syntax is a repeated one.
  const raw = firstString(params.observe);
  const observations = parseObservations(raw);

  const tested =
    observations.length > 0
      ? await thn<RulesTestResponse>([
          "rules",
          "test",
          ...observations.flatMap((o) => ["--observe", `${o.name}=${o.value}`]),
        ])
      : null;

  return (
    <>
      <h1 className="mb-1 text-lg font-semibold tracking-tight text-ink-50">Rules</h1>
      <p className="mb-5 text-xs text-ink-400">
        The conditions THN evaluates, and what it concludes. Evaluating a rule
        changes nothing; the binary has no apply path.
      </p>

      <ObservationForm defaultValue={raw ?? ""} />

      {tested ? (
        tested.ok ? (
          <Conclusions tested={tested.data} />
        ) : (
          <Failure error={tested.error} />
        )
      ) : null}

      {listed.ok ? (
        <Panel
          title="Shipped rule set"
          note={`${listed.data.count} rules`}
        >
          <div className="panel-body">
            <table className="w-full table-fixed">
              <thead>
                <tr className="border-b border-ink-800 text-left">
                  <th className="label w-8 pb-2">severity</th>
                  <th className="label w-48 pb-2">rule</th>
                  <th className="label w-24 pb-2">threshold</th>
                  <th className="label pb-2">holds when</th>
                </tr>
              </thead>
              <tbody>
                {listed.data.rules.map((r) => (
                  <tr key={r.name} className="border-b border-ink-850 align-top last:border-b-0">
                    <td className="py-2 pr-3">
                      <SeverityPill severity={r.severity} />
                    </td>
                    <td className="py-2 pr-3">
                      <div className="value">{r.name}</div>
                      <Because>{r.title}</Because>
                      {r.remedy ? (
                        <Because>
                          <span className="text-ink-500">remedy:</span> {r.remedy}
                        </Because>
                      ) : null}
                    </td>
                    <td className="py-2 pr-3">
                      {r.for > 0 ? (
                        <span className="value text-ink-300">{formatFor(r.for)}</span>
                      ) : (
                        <Pill>immediate</Pill>
                      )}
                    </td>
                    <td className="py-2">
                      <code className="value text-ink-300">{r.condition}</code>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      ) : (
        <Failure error={listed.error} />
      )}

      {listed.ok ? (
        <Panel
          title="Suppressions"
          note="which conditions are consequences of which, so one fault is reported once"
        >
          {listed.data.inhibitions.map((i) => (
            <div key={`${i.source}-${i.target}`} className="row grid-cols-[1fr]">
              <div>
                <span className="value">{i.source}</span>
                <span className="muted"> suppresses </span>
                <span className="value">{i.target}</span>
              </div>
              <Because>{i.reason}</Because>
            </div>
          ))}
        </Panel>
      ) : null}
    </>
  );
}

// ------------------------------------------------------------- the form

const EXAMPLES: ReadonlyArray<{ label: string; value: string }> = [
  {
    label: "uplink present, down",
    value: "network.inspect.supported=true network.wan.present=true network.wan.up=false",
  },
  {
    label: "uplink unreadable",
    value: "network.inspect.supported=true network.wan.up=?",
  },
  {
    label: "host unobservable",
    value: "network.inspect.supported=false",
  },
  {
    label: "pool nearly full",
    value: "network.inspect.supported=true dhcp.pool.capacity=150 dhcp.pool.utilisation=0.95",
  },
];

/**
 * The observation form.
 *
 * A plain GET form. That is a deliberate choice over a client component with
 * state: the whole point of the page is that a test can be reproduced by
 * sending someone the URL, and a form that holds its state in JavaScript
 * cannot be.
 */
function ObservationForm({ defaultValue }: { defaultValue: string }) {
  return (
    <Panel
      title="Try the rules against an observation"
      note="pairs of name=value; use ? for a value that could not be read"
    >
      <form method="get" className="panel-body space-y-3">
        <input
          type="text"
          name="observe"
          defaultValue={defaultValue}
          placeholder="network.inspect.supported=true network.wan.up=false"
          className="w-full rounded border border-ink-700 bg-ink-950 px-3 py-2 font-mono text-xs text-ink-100 outline-none focus:border-ink-500"
        />
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="submit"
            className="rounded border border-ink-600 bg-ink-800 px-3 py-1.5 text-xs font-medium text-ink-100 hover:bg-ink-700"
          >
            Evaluate
          </button>
          {EXAMPLES.map((ex) => (
            <a
              key={ex.label}
              href={`/rules?observe=${encodeURIComponent(ex.value)}`}
              className="rounded border border-ink-800 px-2 py-1 text-2xs text-ink-400 hover:border-ink-600 hover:text-ink-200"
            >
              {ex.label}
            </a>
          ))}
        </div>
      </form>
    </Panel>
  );
}

// ------------------------------------------------------- the conclusions

function Conclusions({ tested }: { tested: RulesTestResponse }) {
  const undecidable = new Set(tested.undecidable.map((i) => i.rule));

  return (
    <Panel
      title="What the rules concluded"
      note={`evaluated at ${tested.at}`}
      action={
        <span className="flex gap-1.5">
          <Pill>{tested.firing.length} firing</Pill>
          <Pill>{tested.pending.length} pending</Pill>
          <Pill>{tested.undecidable.length} undecidable</Pill>
        </span>
      }
    >
      {tested.observations.length === 0 ? (
        <Empty>No observations were supplied.</Empty>
      ) : (
        <div className="panel-body pb-2">
          <div className="label mb-1">Observations</div>
          <div className="flex flex-wrap gap-1.5">
            {tested.observations.map((s) => (
              <ObservationChip key={s.name} signal={s} />
            ))}
          </div>
        </div>
      )}

      {/* The undecidable list comes first and unprompted. On a degraded gateway
          it is usually the whole story, and burying it under a list of rules
          that correctly did not fire would hide exactly the thing an operator
          needs. */}
      {undecidable.size > 0 ? (
        <div className="row grid-cols-1 bg-warning-muted/20">
          <div className="flex items-center gap-2">
            <span className="text-2xs font-semibold uppercase tracking-wide text-warning-text">
              could not be determined
            </span>
            <span className="muted">{undecidable.size} rule(s)</span>
          </div>
          <Because>
            These rules did not fire and did not clear. THN could not read what
            they depend on, which is not the same as their condition being
            false. A rule that was firing and lost sight of its input stays
            firing, because losing visibility is not evidence of recovery.
          </Because>
        </div>
      ) : null}

      {tested.firing.length === 0 && tested.pending.length === 0 ? (
        <Empty>
          Nothing fired and nothing is pending. Every rule needs a condition
          that holds for its threshold, so a single observation never shows a
          firing rule — the clock has to advance.
        </Empty>
      ) : (
        [...tested.firing, ...tested.pending].map((inst) => (
          <div key={`${inst.rule}-${inst.group ?? ""}`} className="row grid-cols-[7rem_1fr]">
            <div className="flex items-start gap-2">
              <StatePill state={inst.state} />
              <SeverityPill severity={inst.severity} />
            </div>
            <div className="min-w-0">
              <div className="value">{inst.rule}</div>
              <Because>{inst.title}</Because>
              <code className="value mt-1 block text-ink-400">{inst.condition}</code>
            </div>
          </div>
        ))
      )}
    </Panel>
  );
}

function ObservationChip({ signal }: { signal: Signal }) {
  const value = signal.value.known
    ? signal.value.kind === "bool"
      ? String(signal.value.bool)
      : signal.value.kind === "number"
        ? String(signal.value.number)
        : signal.value.str
    : "unknown";

  const tone = signal.value.known
    ? "border-ink-700 bg-ink-850 text-ink-200"
    : "border-warning/40 bg-warning-muted text-warning-text";

  return (
    <span className={`inline-flex items-center gap-1.5 rounded border px-2 py-1 font-mono text-2xs ${tone}`}>
      <span>{signal.name}</span>
      <span className="text-ink-500">=</span>
      <span className="font-semibold">{value}</span>
    </span>
  );
}

// ------------------------------------------------------------- utilities

/**
 * Renders a `for` threshold for a human.
 *
 * The binary sends nanoseconds, because a number is easier to compare than a
 * duration string and the comparison is what the threshold is for. A reader
 * wants "60s" or "15m", and "60000000000" is not that.
 *
 * A threshold is always a whole number of seconds in practice — they are
 * written as durations in the rule set — so anything finer is shown with an
 * "ms" rather than rounded away.
 */
function formatFor(nanoseconds: number): string {
  const ms = nanoseconds / 1_000_000;
  if (ms < 1000) {
    return `${Math.round(ms)}ms`;
  }
  const seconds = ms / 1000;
  if (seconds < 60) {
    return `${Number.isInteger(seconds) ? seconds : seconds.toFixed(1)}s`;
  }
  if (seconds < 3600) {
    const minutes = seconds / 60;
    return `${Number.isInteger(minutes) ? minutes : minutes.toFixed(1)}m`;
  }
  const hours = seconds / 3600;
  return `${Number.isInteger(hours) ? hours : hours.toFixed(1)}h`;
}

function firstString(v: string | string[] | undefined): string | undefined {
  if (Array.isArray(v)) {
    return v[0];
  }
  return v;
}

/**
 * Splits an observation string into pairs.
 *
 * Only spaces and newlines separate, and a `?` is preserved verbatim: it is
 * the operator's way of saying "this could not be read", and normalising it
 * away here would turn the most important input into a boolean.
 */
function parseObservations(raw: string | undefined): Array<{ name: string; value: string }> {
  if (!raw) {
    return [];
  }
  return raw
    .split(/[\s]+/)
    .map((pair) => pair.trim())
    .filter((pair) => pair.includes("="))
    .map((pair) => {
      const eq = pair.indexOf("=");
      return { name: pair.slice(0, eq), value: pair.slice(eq + 1) };
    })
    .filter((o) => o.name.length > 0);
}
