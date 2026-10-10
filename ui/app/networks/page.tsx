import { Failure, PageHeader, Panel, Field, Callout } from "@/components/primitives";
import { thn } from "@/lib/thn";
import type { NetworkZone } from "@/lib/types";

export const dynamic = "force-dynamic";

export default async function NetworksPage() {
  const networksRes = await thn<NetworkZone[]>(["networks"]);

  if (!networksRes.ok) {
    return <Failure error={networksRes.error} />;
  }

  const zones = networksRes.data;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Networks"
        plain="Your devices are split into separate groups, so a guest device cannot see your private ones."
        detail="Each group has its own address range and its own rules about who can talk to whom."
      />

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        {zones.map((z) => (
          <Panel key={z.id} title={z.name} note={describeZone(z.name, z.role)}>
            <div className="panel-body space-y-0.5">
              <Field label="Address range">
                <span className="value break-all text-ink-200">{z.subnet}</span>
              </Field>
              <Field label="Gateway">
                <span className="value break-all text-ink-200">{z.gateway}</span>
              </Field>
              <Field label="Internet">
                <span className={z.internet_access ? "font-medium text-ok-fg" : "font-medium text-critical-fg"}>
                  {z.internet_access ? "Allowed" : "Blocked"}
                </span>
              </Field>
              <Field label="Can devices see each other?">
                <span className={z.client_isolation ? "font-medium text-ok-fg" : "font-medium text-ink-300"}>
                  {z.client_isolation ? "No — they are kept apart" : "Yes — they can talk freely"}
                </span>
              </Field>
              <Field label="Reach other groups">
                <span className="text-xs uppercase text-ink-300">{z.inter_network_policy}</span>
              </Field>
            </div>
          </Panel>
        ))}
      </div>

      <Callout tone="info" title="What these words mean">
        <p>
          <strong className="text-ink-200">Separate groups (VLAN).</strong>{" "}
          Putting devices on different groups keeps their traffic apart entirely,
          like having separate networks wired into one box. A guest device on a
          different group cannot reach your main devices at all.
        </p>
        <p>
          <strong className="text-ink-200">Can&apos;t see each other (isolation).</strong>{" "}
          Stops devices within the <em>same</em> group from talking directly to
          each other — useful for a guest network, where guests should reach the
          internet but not each other&apos;s phones. They keep their own internet
          access.
        </p>
      </Callout>
    </div>
  );
}

/**
 * What a zone is for, in words.
 *
 * Keyed on the zone *name*, not `role`. The binary sets `role: LAN` for both
 * the family network and the neighbour network — the role says which
 * interface a zone sits behind, not who is meant to be on it. Describing the
 * neighbour network by its role therefore labelled guests' neighbours as
 * "your own trusted devices", which is the opposite of the truth.
 *
 * An unrecognised name falls back to the raw value rather than a guess: a
 * wrong description of who is on a network is worse than an abbreviation.
 */
function describeZone(name: string, role: string): string {
  const n = name.toLowerCase();

  if (n.includes("mgmt") || n.includes("management")) {
    return "Reserved for managing the gateway itself";
  }
  if (n.includes("guest")) return "Visitors and guest devices";
  if (n.includes("neighbour") || n.includes("neighbor")) {
    return "Neighbouring devices, kept apart from your own";
  }
  if (n.includes("family") || n.includes("trusted") || n.includes("lan")) {
    return "Your own trusted devices";
  }
  if (n.includes("iot")) return "Smart home devices";

  return `${role} group`;
}
