import type { ThnError } from "@/lib/thn";
import type { Severity } from "@/lib/types";

/**
 * The shared vocabulary of the console: panels, states, and the failure case.
 *
 * Everything here is presentational and server-side. There is no client state
 * in this application, because there is nothing to interact with — the binary
 * is re-invoked on each request and the answer rendered as it comes back.
 */

// ------------------------------------------------------------- severity

const SEVERITY_CLASS: Record<Severity, string> = {
  critical: "bg-critical-muted text-critical-text",
  warning: "bg-warning-muted text-warning-text",
  info: "bg-info-muted text-info-text",
};

/** A severity pill. The only place colour carries meaning on its own. */
export function SeverityPill({ severity }: { severity: Severity }) {
  return (
    <span
      className={`inline-flex shrink-0 items-center rounded px-1.5 py-0.5 text-2xs font-semibold uppercase tracking-wide ${SEVERITY_CLASS[severity]}`}
    >
      {severity}
    </span>
  );
}

/** A state pill for the three-valued rule states. */
export function StatePill({ state }: { state: string }) {
  const tone =
    state === "firing"
      ? "bg-critical-muted text-critical-text"
      : state === "pending"
        ? "bg-warning-muted text-warning-text"
        : "bg-ink-800 text-ink-300";

  return (
    <span
      className={`inline-flex shrink-0 items-center rounded px-1.5 py-0.5 text-2xs font-semibold uppercase tracking-wide ${tone}`}
    >
      {state}
    </span>
  );
}

/** A neutral pill, for the many values that are not a state. */
export function Pill({ children }: { children: React.ReactNode }) {
  return (
    <span className="inline-flex shrink-0 items-center rounded bg-ink-800 px-1.5 py-0.5 text-2xs text-ink-300">
      {children}
    </span>
  );
}

// ---------------------------------------------------------------- panels

export function Panel({
  title,
  note,
  action,
  children,
}: {
  title: string;
  note?: string;
  action?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <section className="panel mb-4">
      <div className="panel-header">
        <div>
          <h2 className="panel-title">{title}</h2>
          {note ? <p className="mt-0.5 text-2xs text-ink-400">{note}</p> : null}
        </div>
        {action}
      </div>
      {children}
    </section>
  );
}

/** A label/value row, the console's basic unit. */
export function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="row grid-cols-[8rem_1fr]">
      <span className="label">{label}</span>
      <div className="min-w-0">{children}</div>
    </div>
  );
}

/** A heading above a group of fields. */
export function Group({ children }: { children: React.ReactNode }) {
  return <div className="mb-2 mt-4 first:mt-0">{children}</div>;
}

// -------------------------------------------------------------- failures

const ERROR_TITLE: Record<ThnError["kind"], string> = {
  "not-permitted": "Not permitted",
  "binary-missing": "The thn binary is not available",
  "execution-failed": "thn reported a problem",
  unparseable: "thn returned something unexpected",
  timeout: "thn did not finish in time",
};

/**
 * The failure case, and the most important component in the application.
 *
 * A console that shows an empty table when the binary is missing has told the
 * operator the gateway has no incidents, when in fact the console cannot see.
 * Those are very different situations and conflating them is how a monitoring
 * tool starts being believed when it has stopped working.
 *
 * So every failure says what failed, what the binary said, and what was run —
 * and nothing renders an empty result from a failed call.
 */
export function Failure({ error }: { error: ThnError }) {
  return (
    <div className="panel border-critical/40">
      <div className="panel-header">
        <h2 className="panel-title text-critical-text">
          {ERROR_TITLE[error.kind]}
        </h2>
        <span className="value text-ink-500">{error.kind}</span>
      </div>
      <div className="panel-body space-y-3">
        <p className="text-xs text-ink-200">{error.message}</p>

        {error.detail ? (
          <div>
            <div className="label mb-1">What thn said</div>
            <pre className="pre-block">{error.detail}</pre>
          </div>
        ) : null}

        <div>
          <div className="label mb-1">What was run</div>
          <code className="value">thn {error.command}</code>
        </div>

        <p className="because">
          This page shows no data because the query did not succeed. An empty
          result and a failed one are not the same thing, and this console does
          not present them as the same thing.
        </p>
      </div>
    </div>
  );
}

/** Nothing to show, which is distinct from something failed. */
export function Empty({ children }: { children: React.ReactNode }) {
  return (
    <p className="panel-body py-6 text-center text-xs text-ink-400">{children}</p>
  );
}

// ------------------------------------------------------------- rendering

/**
 * A preformatted artefact.
 *
 * The rendered rulesets, dnsmasq configuration and tc commands are what an
 * operator actually copies out of this tool, so they are selectable and do not
 * wrap.
 */
export function Pre({ children }: { children: string }) {
  return <pre className="pre-block">{children}</pre>;
}

/**
 * The explanation that accompanies a value.
 *
 * THN's design puts the reasoning in the same output as the conclusion, and
 * this renders it as a second line rather than inlining it. "wan.down" is the
 * conclusion; "eth0 is present but the carrier reports it down" is what an
 * operator three time zones away needs, and the two should not be the same
 * visual weight.
 */
export function Because({ children }: { children: React.ReactNode }) {
  return <p className="because mt-0.5">{children}</p>;
}

/** A monospace value with an optional explanation beneath it. */
export function Detail({
  value,
  why,
}: {
  value: React.ReactNode;
  why?: React.ReactNode;
}) {
  return (
    <div>
      <div className="value">{value}</div>
      {why ? <Because>{why}</Because> : null}
    </div>
  );
}
