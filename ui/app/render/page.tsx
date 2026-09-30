import { Failure, Panel, Pre, Because } from "@/components/primitives";
import { thn } from "@/lib/thn";
import type { RenderResponse } from "@/lib/types";

export const dynamic = "force-dynamic";

/**
 * The artefacts THN would hand a kernel.
 *
 * Nothing here has been applied. These are the rulesets, the dnsmasq
 * configuration and the tc commands that a future activation would install — the
 * text an operator reads to check that the intent is what they meant before
 * anything changes.
 *
 * The page says so once, at the top, rather than repeating it on every panel.
 * A caveat repeated five times is a caveat nobody reads.
 */

const ARTEFACTS = [
  {
    key: "firewall",
    title: "nftables ruleset",
    note: "the host firewall, as text",
    args: ["firewall", "render"],
  },
  {
    key: "dnsmasq",
    title: "dnsmasq configuration",
    note: "DHCP and DNS for the configured networks",
    args: ["dhcp", "render"],
  },
  {
    key: "qos",
    title: "traffic shaping",
    note: "the tc command and its verification",
    args: ["qos", "render"],
  },
  {
    key: "net",
    title: "network configuration",
    note: "routes, NAT and forwarding",
    args: ["net", "render"],
  },
  {
    key: "dns",
    title: "DNS configuration",
    note: "upstreams and local records",
    args: ["dns", "render"],
  },
] as const;

export default async function RenderPage() {
  const results = await Promise.all(
    ARTEFACTS.map(async (a) => {
      const r = await thn<RenderResponse>(a.args);
      return { artefact: a, result: r };
    }),
  );

  return (
    <>
      <h1 className="mb-1 text-lg font-semibold tracking-tight text-ink-50">Rendered artefacts</h1>
      <p className="mb-2 text-xs text-ink-400">
        The configurations THN would install, as text.
      </p>
      <p className="mb-5 text-xs text-ink-500">
        None of it has been applied, and this build has no code path that could
        apply it. The value of these panels is that the intent is reviewable
        before anything is applied — which is the only stage at which reviewing
        it is free.
      </p>

      {results.map(({ artefact, result }) => (
        <Panel key={artefact.key} title={artefact.title} note={artefact.note}>
          <div className="panel-body">
            {result.ok ? (
              typeof result.data.content === "string" && result.data.content.length > 0 ? (
                <Pre>{result.data.content}</Pre>
              ) : (
                <p className="text-xs text-ink-400">
                  The binary produced no output. That usually means the
                  subsystem is disabled in the configuration rather than that
                  something went wrong — the validation output for the same
                  subsystem will say which.
                </p>
              )
            ) : (
              <Failure error={result.error} />
            )}
          </div>
        </Panel>
      ))}
    </>
  );
}
