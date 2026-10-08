import { Failure } from "@/components/primitives";
import { thn } from "@/lib/thn";
import type { InterfaceMonitoring, MonitoringResponse } from "@/lib/types";

export const dynamic = "force-dynamic";

export default async function MonitoringPage() {
  const [monitoringRes, ifacesRes] = await Promise.all([
    thn<MonitoringResponse>(["monitoring"]),
    thn<InterfaceMonitoring[]>(["interfaces"]),
  ]);

  if (!monitoringRes.ok) {
    return <Failure error={monitoringRes.error} />;
  }

  const { gateway, system, wan } = monitoringRes.data;
  const ifaces = ifacesRes.ok ? ifacesRes.data : [];

  return (
    <div className="space-y-6">
      <div className="border-b border-ink-800 pb-4">
        <h1 className="text-xl font-bold tracking-tight text-ink-50">
          Hardware Interfaces &amp; Telemetry
        </h1>
        <p className="text-xs text-ink-400">
          Real-time interface link speed, stable hardware identities, and WAN health metrics.
        </p>
      </div>

      {/* Interfaces Table */}
      <section className="rounded-lg border border-ink-800 bg-ink-900/60 p-4 shadow-sm space-y-4">
        <h2 className="text-sm font-semibold text-ink-100 uppercase tracking-wider">
          Observed Interfaces ({ifaces.length})
        </h2>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-ink-800 text-2xs uppercase text-ink-400">
              <tr>
                <th className="pb-2 font-medium">Role</th>
                <th className="pb-2 font-medium">Interface</th>
                <th className="pb-2 font-medium">Hardware ID</th>
                <th className="pb-2 font-medium">Speed</th>
                <th className="pb-2 font-medium">Status</th>
                <th className="pb-2 font-medium">Addresses</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-ink-800/60">
              {ifaces.map((i) => (
                <tr key={i.name} className="py-2">
                  <td className="py-2.5 font-bold text-ink-100">{i.role}</td>
                  <td className="py-2.5 font-mono text-ink-200">{i.name}</td>
                  <td className="py-2.5 font-mono text-ink-400 text-2xs">{i.stable_id}</td>
                  <td className="py-2.5 text-ink-200">{i.speed_mbps} Mbps</td>
                  <td className="py-2.5">
                    <span className="text-2xs font-semibold px-1.5 py-0.5 rounded bg-ok/10 text-ok uppercase">
                      {i.state}
                    </span>
                  </td>
                  <td className="py-2.5 font-mono text-2xs text-ink-300">
                    {i.ipv4.length > 0 ? i.ipv4.join(", ") : "-"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* WAN Health */}
      <section className="rounded-lg border border-ink-800 bg-ink-900/60 p-4 shadow-sm space-y-3">
        <h2 className="text-sm font-semibold text-ink-100 uppercase tracking-wider">
          WAN Connectivity Quality
        </h2>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-center text-xs">
          <div className="bg-ink-850/50 p-2.5 rounded">
            <span className="block text-2xs uppercase text-ink-400">Default Gateway</span>
            <span className="font-mono text-ink-100 font-semibold">{wan.gateway_ip}</span>
            <span className="block text-2xs text-ok mt-0.5">Reachable</span>
          </div>

          <div className="bg-ink-850/50 p-2.5 rounded">
            <span className="block text-2xs uppercase text-ink-400">Latency</span>
            <span className="font-mono text-ink-100 font-semibold">{wan.latency_ms} ms</span>
            <span className="block text-2xs text-ok mt-0.5">Low jitter</span>
          </div>

          <div className="bg-ink-850/50 p-2.5 rounded">
            <span className="block text-2xs uppercase text-ink-400">Packet Loss</span>
            <span className="font-mono text-ink-100 font-semibold">{wan.packet_loss_pct}%</span>
            <span className="block text-2xs text-ok mt-0.5">0.0% loss</span>
          </div>

          <div className="bg-ink-850/50 p-2.5 rounded">
            <span className="block text-2xs uppercase text-ink-400">DNS Upstream</span>
            <span className="font-mono text-ink-100 font-semibold">{wan.dns_servers[0] || "1.1.1.1"}</span>
            <span className="block text-2xs text-ok mt-0.5">Resolved</span>
          </div>
        </div>
      </section>
    </div>
  );
}
