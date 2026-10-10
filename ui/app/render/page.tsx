import { Failure, Panel, PageHeader, Pre, Because } from "@/components/primitives";
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
      <PageHeader
        title="Configuration preview"
        plain="Exactly what the gateway is set up to do, written out in plain text."
        detail="Useful if you want to check a setting is really doing what you think — or to show it to someone else. Nothing here has been applied, and this build has no way to apply it."
      />

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
