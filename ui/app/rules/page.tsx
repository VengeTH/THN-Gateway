import {
  Failure,
  Panel,
  PageHeader,
  SeverityPill,
  StatePill,
  Pill,
  Because,
  Empty,
} from "@/components/primitives";
import { DataTable } from "@/components/data-table";
import { thn } from "@/lib/thn";
import type { RulesListResponse, RulesTestResponse, Signal, Severity } from "@/lib/types";

export const dynamic = "force-dynamic";

/*
 * Most serious first. The binary returns rules in whatever order the rule
 * file declares, and the order that is convenient for the author of a YAML
 * file is not the order a person triaging a fault wants to read them in.
 */
const SEVERITY_ORDER: Record<Severity, number> = { critical: 0, warning: 1, info: 2 };

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

  const sorted =
    listed.ok
      ? [...listed.data.rules].sort(
          (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity],
        )
      : [];

  return (
    <>
      <PageHeader
        title="Rules"
        plain="The automatic checks your gateway runs to spot problems before you notice them."
        detail="Each check has a name, a level of seriousness, and how long the problem must last before it is reported. Looking at these changes nothing."
      />

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
          title={`The ${listed.data.count} checks your gateway runs`}
          note="Sorted by how serious each one is. “Reports after” is how long a fault must persist before you are told about it."
        >
          <div className="panel-body">
            <DataTable
              caption="The checks the gateway runs"
              rows={sorted}
              rowKey={(r) => r.name}
              columns={[
                {
                  key: "name",
                  label: "check",
                  render: (r) => (
                    <>
                      <div className="flex flex-wrap items-center gap-2">
                        <SeverityPill severity={r.severity} />
                        <span className="value text-ink-100">{r.name}</span>
                      </div>
                      <Because>{r.title}</Because>
                      {r.remedy ? (
                        <Because>
                          <span className="text-ink-500">what to do:</span> {r.remedy}
                        </Because>
                      ) : null}
                    </>
                  ),
                },
                {
                  key: "for",
                  label: "reports after",
                  render: (r) =>
                    r.for > 0 ? (
                      <span className="value text-ink-300">{formatFor(r.for)}</span>
                    ) : (
                      <Pill>straight away</Pill>
                    ),
                },
                {
                  key: "condition",
                  label: "checks whether",
                  render: (r) =>
                    r.condition ? (
                      <code className="value break-words text-ink-300">{r.condition}</code>
                    ) : (
                      <span className="text-2xs text-ink-500">not shown here</span>
                    ),
                },
              ]}
            />
          </div>
        </Panel>
      ) : (
        <Failure error={listed.error} />
      )}

      {listed.ok && listed.data.inhibitions.length > 0 ? (
        <Panel
          title="Avoiding duplicate alarms"
          note="When one fault causes another, only the root cause is reported"
        >
          <div className="panel-body">
            <DataTable
              caption="Which problems suppress which"
              rows={listed.data.inhibitions}
              rowKey={(i) => `${i.source}-${i.target}`}
              columns={[
                {
                  key: "pair",
                  label: "instead of",
                  render: (i) => (
                    <span className="min-w-0 break-words">
                      <span className="value text-ink-200">{i.source}</span>
                      <span className="muted"> is reported, not </span>
                      <span className="value text-ink-400 line-through decoration-ink-600">
                        {i.target}
                      </span>
                    </span>
                  ),
                },
                {
                  key: "reason",
                  label: "because",
                  render: (i) => <Because>{i.reason}</Because>,
                },
              ]}
            />
          </div>
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
      title="Try a check against a made-up situation"
      note="Useful if you want to see what the gateway would do, without waiting for something to go wrong."
    >
      <form method="get" className="panel-body space-y-3">
        <div>
          <label htmlFor="observe" className="label mb-1 block">
            Describe what you are seeing
          </label>
          <input
            id="observe"
            type="text"
            name="observe"
            defaultValue={defaultValue}
            placeholder="network.inspect.supported=true network.wan.up=false"
            className="field"
            autoComplete="off"
            spellCheck={false}
          />
          <p className="mt-1.5 text-2xs leading-relaxed text-ink-500">
            Write what you observed as <code className="text-ink-400">name=value</code> pairs,
            separated by spaces. Use <code className="text-ink-400">?</code> for something you
            could not find out — the gateway treats that differently from a genuine{" "}
            <code className="text-ink-400">false</code>.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button type="submit" className="btn btn-primary tap">
            Run the checks
          </button>
          {EXAMPLES.map((ex) => (
            <a
              key={ex.label}
              href={`/rules?observe=${encodeURIComponent(ex.value)}`}
              className="btn !py-1 text-2xs"
            >
              Try: {ex.label}
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
      title="What the checks concluded"
      note={`Run against your description at ${tested.at}`}
      action={
        <span className="flex flex-wrap gap-1.5">
          <Pill>{tested.firing.length} firing</Pill>
          <Pill>{tested.pending.length} waiting</Pill>
          <Pill>{tested.undecidable.length} unknown</Pill>
        </span>
      }
    >
      {tested.observations.length === 0 ? (
        <Empty>Nothing was described, so there was nothing to check.</Empty>
      ) : (
        <div className="panel-body pb-2">
          <div className="label mb-1">What you described</div>
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
        <div className="border-b border-ink-850 bg-warning-muted/20 px-4 py-3">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs font-semibold uppercase tracking-wide text-warning-fg">
              could not be determined
            </span>
            <span className="muted text-2xs">{undecidable.size} check(s)</span>
          </div>
          <Because>
            These checks neither fired nor cleared. The gateway could not read
            what they depend on, which is not the same as their condition
            being false. A check that was firing and lost sight of its input
            stays firing, because losing visibility is not evidence of
            recovery.
          </Because>
        </div>
      ) : null}

      {tested.firing.length === 0 && tested.pending.length === 0 ? (
        <Empty>
          Nothing fired and nothing is waiting. Every check needs its condition
          to hold for the full threshold, so a single observation never shows a
          firing rule — the clock has to advance.
        </Empty>
      ) : (
        [...tested.firing, ...tested.pending].map((inst) => (
          <div key={`${inst.rule}-${inst.group ?? ""}`} className="kv border-b border-ink-850 px-4 py-2 last:border-b-0">
            <div className="flex flex-wrap items-center gap-2">
              <StatePill state={inst.state} />
              <SeverityPill severity={inst.severity} />
            </div>
            <div className="min-w-0">
              <div className="value">{inst.rule}</div>
              <Because>{inst.title}</Because>
              {inst.condition ? (
                <code className="value mt-1 block break-words text-ink-400">{inst.condition}</code>
              ) : null}
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
    : "border-warning-edge/50 bg-warning-muted text-warning-text";

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
