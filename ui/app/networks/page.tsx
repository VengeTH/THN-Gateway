import { Failure } from "@/components/primitives";
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
      <div className="border-b border-ink-800 pb-4">
        <h1 className="text-xl font-bold tracking-tight text-ink-50">
          Network Zones &amp; Client Isolation
        </h1>
        <p className="text-xs text-ink-400">
          Logical network segmentation models, future VLAN boundaries, and inter-client isolation policies.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {zones.map((z) => (
          <section
            key={z.id}
            className="rounded-lg border border-ink-800 bg-ink-900/60 p-4 shadow-sm space-y-3"
          >
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-sm font-semibold text-ink-100">{z.name}</h2>
                <span className="text-2xs text-ink-500 font-mono">ID: {z.id} &middot; Role: {z.role}</span>
              </div>
              <span className="text-2xs font-semibold px-2 py-0.5 rounded bg-ink-800 text-ink-300">
                {z.vlan_id > 0 ? `VLAN ${z.vlan_id}` : "Native"}
              </span>
            </div>

            <div className="space-y-1.5 text-xs border-t border-ink-800/80 pt-2">
              <div className="flex justify-between">
                <span className="text-ink-400">Subnet CIDR:</span>
                <span className="font-mono text-ink-200">{z.subnet}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-ink-400">Gateway IP:</span>
                <span className="font-mono text-ink-200">{z.gateway}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-ink-400">Internet Access:</span>
                <span className="text-ok font-medium">{z.internet_access ? "Allowed" : "Blocked"}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-ink-400">Client Isolation:</span>
                <span className={`font-medium ${z.client_isolation ? "text-ok" : "text-ink-400"}`}>
                  {z.client_isolation ? "Enforced (A ↮ B)" : "Shared"}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-ink-400">Inter-Network Policy:</span>
                <span className="text-ink-300 uppercase text-2xs">{z.inter_network_policy}</span>
              </div>
            </div>
          </section>
        ))}
      </div>

      <div className="rounded-lg border border-ink-800/80 bg-ink-850/40 p-4 text-xs text-ink-400 space-y-2">
        <h3 className="font-semibold text-ink-200">About Client Isolation Semantics</h3>
        <p>
          <strong>VLAN separation:</strong> Separates network traffic by 802.1Q tags across broadcast domains.
        </p>
        <p>
          <strong>Client isolation:</strong> Prevents devices within the same network segment from contacting one another (e.g. Neighbor A ↮ Neighbor B), while preserving independent uplink connectivity to the Internet.
        </p>
        <p className="text-2xs text-ink-500">
          Note: This milestone establishes and validates the data model foundation. Real host switch/VLAN activation remains guarded until physical cutover.
        </p>
      </div>
    </div>
  );
}
