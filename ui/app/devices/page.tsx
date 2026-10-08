import { Failure, Panel, Pill } from "@/components/primitives";
import { thn } from "@/lib/thn";
import type { ClientDevice } from "@/lib/types";

export const dynamic = "force-dynamic";

export default async function DevicesPage() {
  const clientsRes = await thn<ClientDevice[]>(["clients"]);

  if (!clientsRes.ok) {
    return <Failure error={clientsRes.error} />;
  }

  const clients = clientsRes.data;

  return (
    <div className="space-y-6">
      <div className="border-b border-ink-800 pb-4">
        <h1 className="text-xl font-bold tracking-tight text-ink-50">
          Connected Devices ({clients.length})
        </h1>
        <p className="text-xs text-ink-400">
          Inventory of devices discovered on the network, their assigned zone, and active bandwidth policies.
        </p>
      </div>

      <div className="grid grid-cols-1 gap-4">
        {clients.map((c) => (
          <div
            key={c.id}
            className="rounded-lg border border-ink-800 bg-ink-900/60 p-4 shadow-sm flex flex-col sm:flex-row sm:items-center justify-between gap-4"
          >
            <div className="space-y-1 min-w-0">
              <div className="flex items-center gap-2">
                <span className="font-semibold text-sm text-ink-100 truncate">
                  {c.hostname}
                </span>
                <span
                  className={`text-2xs font-semibold px-2 py-0.5 rounded ${
                    c.blocked
                      ? "bg-critical-muted text-critical-text"
                      : "bg-ok/10 text-ok"
                  }`}
                >
                  {c.blocked ? "BLOCKED" : "ONLINE"}
                </span>
                <span className="bg-ink-800 text-ink-400 text-2xs px-2 py-0.5 rounded uppercase">
                  {c.logical_group}
                </span>
              </div>

              <div className="text-xs text-ink-400 flex flex-wrap gap-x-4 gap-y-1">
                <span>IP: <strong className="text-ink-200 font-mono">{c.ipv4}</strong></span>
                <span>MAC: <span className="font-mono">{c.mac}</span></span>
                <span>Zone: <span className="text-ink-300">{c.network_id}</span></span>
                <span>Isolation: <span className="text-ink-300">{c.isolation_status}</span></span>
              </div>
            </div>

            <div className="flex sm:flex-col items-center sm:items-end justify-between border-t sm:border-t-0 pt-2 sm:pt-0 border-ink-800/80 gap-1 text-xs shrink-0">
              <span className="text-2xs uppercase text-ink-400">QoS Allocation</span>
              <span className="font-medium text-ink-200">
                {c.qos_policy || "Default (Uncapped)"}
              </span>
              <span className="text-2xs text-ink-500">
                Throughput: {(c.current_rx_bps / 1000000).toFixed(1)} Mbps &darr;
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
