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
          <h2 className="panel-title font-display">{title}</h2>
          {note ? <p className="mt-0.5 text-2xs text-ink-400">{note}</p> : null}
        </div>
        {action}
      </div>
      {children}
    </section>
  );
}

/**
 * A label/value row, the console's basic unit.
 *
 * The label sits beside its value on a wide screen and above it on a narrow
 * one. That is the single most load-bearing responsive decision in the
 * application: a fixed 8rem label column leaves a 220px value column on a
 * phone, which turns every sentence into three two-word lines.
 */
export function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="kv border-b border-ink-850 px-4 py-2 last:border-b-0">
      <span className="label">{label}</span>
      <div className="min-w-0">{children}</div>
    </div>
  );
}

/** A heading above a group of fields. */
export function Group({ children }: { children: React.ReactNode }) {
  return <div className="mb-2 mt-4 first:mt-0">{children}</div>;
}

// ----------------------------------------------------------- page header

/**
 * The top of every page.
 *
 * `plain` is the sentence a non-technical reader actually needs, written
 * before the technical one rather than after it. Several pages in this
 * console open with a caveat instead, which is the right instinct and the
 * wrong order: someone who cannot tell what a page is for cannot act on the
 * caveat once they reach it.
 */
export function PageHeader({
  title,
  plain,
  detail,
  action,
}: {
  title: string;
  /** One plain sentence: what this page is for. */
  plain: string;
  /** Optional second sentence, for the mechanism behind it. */
  detail?: string;
  action?: React.ReactNode;
}) {
  return (
    <header className="mb-6 flex flex-wrap items-start justify-between gap-x-6 gap-y-3 border-b border-ink-800 pb-4">
      <div className="min-w-0">
        <h1 className="text-xl font-bold font-display tracking-tight text-ink-50 sm:text-2xl">{title}</h1>
        <p className="mt-1 text-sm text-ink-300">{plain}</p>
        {detail ? <p className="mt-1 text-xs text-ink-400">{detail}</p> : null}
      </div>
      {action ? <div className="shrink-0">{action}</div> : null}
    </header>
  );
}

// -------------------------------------------------------------- key/value

/**
 * A number with a label, for the small multiples on the dashboard.
 *
 * The value is set in the largest weight on the card because it is the thing
 * being read; the label is above it in the muted tone because it is the
 * context. A statistic whose unit is in the label rather than the value is a
 * statistic that gets quoted without its unit.
 */
export function Stat({
  label,
  value,
  hint,
  tone = "neutral",
}: {
  label: string;
  value: React.ReactNode;
  hint?: string;
  tone?: "neutral" | "ok" | "warning" | "critical";
}) {
  const toneClass =
    tone === "ok"
      ? "text-ok-fg"
      : tone === "warning"
        ? "text-warning-fg"
        : tone === "critical"
          ? "text-critical-fg"
          : "text-ink-50";

  return (
    <div className="min-w-0 rounded-lg border border-ink-800 bg-ink-900/80 p-3 shadow-panel">
      <span className="block text-2xs uppercase tracking-wider text-ink-400 font-medium">{label}</span>
      <span className={`mt-1 block truncate text-lg font-bold font-display ${toneClass}`}>{value}</span>
      {hint ? <span className="mt-0.5 block text-2xs text-ink-400">{hint}</span> : null}
    </div>
  );
}

// ------------------------------------------------------------- callouts

/**
 * A note that changes how the rest of the page should be read.
 *
 * `tone` is about the reader's situation, not about severity: `info` is a
 * limitation to understand, `warning` is something to check, `critical` is
 * something that failed. Using it for anything else would dilute the one
 * thing colour means in this application.
 */
export function Callout({
  tone = "info",
  title,
  children,
}: {
  tone?: "info" | "warning" | "critical";
  title?: string;
  children: React.ReactNode;
}) {
  const toneClass =
    tone === "critical"
      ? "border-critical-edge/50 bg-critical-muted/10"
      : tone === "warning"
        ? "border-warning-edge/50 bg-warning-muted/10"
        : "border-accent/30 bg-accent/5";

  const titleClass =
    tone === "critical"
      ? "text-critical-fg"
      : tone === "warning"
        ? "text-warning-fg"
        : "text-accent";

  return (
    <div className={`rounded-lg border px-3.5 py-3 ${toneClass}`}>
      {title ? (
        <div className={`text-2xs font-semibold uppercase tracking-wide ${titleClass}`}>
          {title}
        </div>
      ) : null}
      <div className="mt-1 space-y-1.5 text-xs leading-relaxed text-ink-300">{children}</div>
    </div>
  );
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
    <div className="panel border-critical-edge/40">
      <div className="panel-header">
        <h2 className="panel-title text-critical-fg">
          {ERROR_TITLE[error.kind]}
        </h2>
        <span className="value text-ink-400">{error.kind}</span>
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
