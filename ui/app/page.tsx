import { Failure, Panel, Field, Pill, SeverityPill, Empty, Because } from "@/components/primitives";
import { thn } from "@/lib/thn";
import type { DiagnosticsResponse, RulesListResponse, StatusResponse } from "@/lib/types";

/**
 * The overview answers one question: what does the gateway say about itself?
 *
 * Three sources, deliberately. `status` is the gateway's own summary,
 * `diagnostics` is the same binary reading the host, and `rules` is what it
 * would evaluate. Rendering all three side by side is the point — a console
 * showing only the summary hides the case where the summary is stale.
 *
 * Every request is independent. A failure in one does not blank the page,
 * because "the firewall is readable but the host is not" is a more useful
 * screen than either half of that with an error page over it.
 */
export const dynamic = "force-dynamic";

export default async function OverviewPage() {
  const [status, diagnostics, rules] = await Promise.all([
    thn<StatusResponse>(["status", "--local"]),
    thn<DiagnosticsResponse>(["diagnostics", "--local"]),
    thn<RulesListResponse>(["rules", "list"]),
  ]);

  const ruleCounts = rules.ok
    ? {
        critical: rules.data.rules.filter((r) => r.severity === "critical").length,
        warning: rules.data.rules.filter((r) => r.severity === "warning").length,
        info: rules.data.rules.filter((r) => r.severity === "info").length,
        inhibitions: rules.data.inhibitions.length,
      }
    : null;

  return (
    <>
      <h1 className="mb-1 text-lg font-semibold tracking-tight text-ink-50">Overview</h1>
      <p className="mb-5 text-xs text-ink-400">
        Everything here is what the <code>thn</code> binary reported at the
        moment this page was requested. Nothing is cached and nothing is applied.
      </p>

      {status.ok ? (
        <Panel
          title="Gateway"
          note="the binary's own summary of its state"
          action={<Pill>{status.data.state ?? "unknown"}</Pill>}
        >
          <Field label="name">{status.data.gateway ?? <span className="muted">not set</span>}</Field>
          <Field label="WAN">
            {status.data.wan ?? <span className="muted">not configured</span>}
          </Field>
          <Field label="LAN">
            {status.data.lan ?? <span className="muted">not configured</span>}
          </Field>
          <Field label="firewall">
            {status.data.firewall ?? <span className="muted">unknown</span>}
          </Field>
          <Field label="can apply">
            {/* Rendered prominently because it is the single most important
                fact on the page: a reader should not have to infer from the
                absence of a button. */}
            <span className="text-ok">
              no — this build has no apply path
            </span>
            <Because>
              The binary has no code that can modify host networking. There is
              nothing for this console to offer, and nothing for it to do.
            </Because>
          </Field>
          {status.data.pending && Object.keys(status.data.pending).length > 0 ? (
            <Field label="pending">
              <ul className="space-y-1">
                {Object.entries(status.data.pending).map(([k, v]) => (
                  <li key={k}>
                    <span className="value text-ink-300">{k}</span>
                    <Because>{v}</Because>
                  </li>
                ))}
              </ul>
            </Field>
          ) : null}
        </Panel>
      ) : (
        <Failure error={status.error} />
      )}

      {diagnostics.ok ? (
        <Panel
          title="Host inspection"
          note="the same binary reading the host it runs on"
          action={
            diagnostics.data.supported ? (
              <Pill>supported</Pill>
            ) : (
              <Pill>unsupported</Pill>
            )
          }
        >
          <Field label="host">{diagnostics.data.host ?? <span className="muted">unknown</span>}</Field>
          <Field label="interfaces">{diagnostics.data.interfaces ?? 0}</Field>
          <Field label="addresses">{diagnostics.data.addresses ?? 0}</Field>
          <Field label="routes">{diagnostics.data.routes ?? 0}</Field>
          <Field label="config valid">
            {diagnostics.data.valid ? (
              <span className="text-ok">yes</span>
            ) : (
              <span className="text-critical-text">no</span>
            )}
          </Field>
          {!diagnostics.data.supported ? (
            <Field label="note">
              <Because>
                Host inspection is unavailable on this platform, so every
                observation derived from it is unknown. That is reported as
                unknown rather than as fine, and the rules layer is built so it
                never fires on a value it could not read.
              </Because>
            </Field>
          ) : null}
        </Panel>
      ) : (
        <Failure error={diagnostics.error} />
      )}

      {rules.ok && ruleCounts ? (
        <Panel
          title="Rule set"
          note="the conditions THN would evaluate, and the suppressions between them"
        >
          <Field label="critical">
            <SeverityPill severity="critical" />{" "}
            <span className="muted">{ruleCounts.critical}</span>
          </Field>
          <Field label="warning">
            <SeverityPill severity="warning" />{" "}
            <span className="muted">{ruleCounts.warning}</span>
          </Field>
          <Field label="info">
            <SeverityPill severity="info" /> <span className="muted">{ruleCounts.info}</span>
          </Field>
          <Field label="suppressions">
            {ruleCounts.inhibitions}
            <Because>
              Each one names a cause and its consequences, so that one fault is
              reported once rather than as several.
            </Because>
          </Field>
        </Panel>
      ) : rules.ok ? null : (
        <Failure error={rules.error} />
      )}

      {status.ok && diagnostics.ok ? (
        <Panel title="Reading this page">
          <p className="text-xs text-ink-300">
            The two panels above come from separate invocations of the same
            binary and are not a consistent snapshot. A change between them is
            possible, and this console does not pretend otherwise — it reports
            each answer as it was given rather than merging them into a single
            moment that never existed.
          </p>
        </Panel>
      ) : null}
    </>
  );
}
