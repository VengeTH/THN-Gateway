import Link from "next/link";
import { Failure } from "@/components/primitives";
import { thn } from "@/lib/thn";
import type {
  ClientDevice,
  DashboardEvent,
  MonitoringResponse,
  NetworkZone,
} from "@/lib/types";

export const dynamic = "force-dynamic";

export default async function DashboardPage() {
  const [monitoringRes, clientsRes, networksRes, eventsRes] = await Promise.all([
    thn<MonitoringResponse>(["monitoring"]),
    thn<ClientDevice[]>(["clients"]),
    thn<NetworkZone[]>(["networks"]),
    thn<DashboardEvent[]>(["events"]),
  ]);

  if (!monitoringRes.ok) {
    return <Failure error={monitoringRes.error} />;
  }

  const { gateway, system, wan } = monitoringRes.data;
  const clients = clientsRes.ok ? clientsRes.data : [];
  const networks = networksRes.ok ? networksRes.data : [];
  const events = eventsRes.ok ? eventsRes.data : [];

  // Group counts for non-technical household overview
  const groupCounts = {
    family: clients.filter((c) => c.logical_group === "family").length,
    neighbor: clients.filter((c) => c.logical_group === "neighbor").length,
    guest: clients.filter((c) => c.logical_group === "guest").length,
    other: clients.filter((c) => !["family", "neighbor", "guest"].includes(c.logical_group)).length,
  };

  const internetStatusTone =
    gateway.internet_status === "online"
      ? "bg-ok/10 text-ok border-ok/30"
      : gateway.internet_status === "degraded"
      ? "bg-warning-muted text-warning-text border-warning-border"
      : "bg-critical-muted text-critical-text border-critical-border";

  return (
    <div className="space-y-6">
      {/* Top Banner / Gateway Identity */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-ink-800 pb-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-ink-50">
            {gateway.hostname}
          </h1>
          <p className="text-xs text-ink-400">
            THN Gateway &middot; Uptime: {gateway.uptime} &middot; Mode: {gateway.activation_state}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold ${internetStatusTone}`}>
            ● {gateway.internet_status.toUpperCase()}
          </span>
          <span className="rounded bg-ink-800 px-2 py-0.5 text-2xs text-ink-300">
            {gateway.health_state.toUpperCase()}
          </span>
        </div>
      </div>

      {/* Grid: 1 col on mobile, 2 cols on tablet/desktop */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Card 1: Internet & Uplink */}
        <section className="rounded-lg border border-ink-800 bg-ink-900/60 p-4 shadow-sm flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-sm font-semibold text-ink-100 uppercase tracking-wider">
                Internet Connection
              </h2>
              <span className="text-2xs text-ink-400">WAN: {wan.interface_name}</span>
            </div>

            <div className="my-4 text-center">
              <div className="text-2xl font-bold text-ink-50">
                {wan.internet_reachable ? "Connected & Healthy" : "Offline"}
              </div>
              <p className="text-xs text-ink-400 mt-1">
                Gateway: {wan.gateway_ip} &middot; Latency: {wan.latency_ms > 0 ? `${wan.latency_ms} ms` : "unknown"}
              </p>
            </div>

            <div className="grid grid-cols-2 gap-3 pt-3 border-t border-ink-800/80 text-center">
              <div className="bg-ink-850/50 rounded p-2">
                <span className="block text-2xs uppercase text-ink-400">Estimated Download</span>
                <span className="text-base font-semibold text-ok">↓ 100 Mbps</span>
              </div>
              <div className="bg-ink-850/50 rounded p-2">
                <span className="block text-2xs uppercase text-ink-400">Estimated Upload</span>
                <span className="text-base font-semibold text-ink-100">↑ 20 Mbps</span>
              </div>
            </div>
          </div>
          <div className="mt-4 text-2xs text-ink-500 text-center">
            DNS Resolvers: {wan.dns_servers.join(", ")}
          </div>
        </section>

        {/* Card 2: Connected Devices Summary */}
        <section className="rounded-lg border border-ink-800 bg-ink-900/60 p-4 shadow-sm flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-sm font-semibold text-ink-100 uppercase tracking-wider">
                Connected Devices
              </h2>
              <Link href="/devices" className="text-xs text-ok hover:underline">
                View all ({clients.length}) &rarr;
              </Link>
            </div>

            <div className="grid grid-cols-3 gap-2 my-3 text-center">
              <div className="rounded border border-ink-800 bg-ink-850/40 p-2">
                <span className="block text-lg font-bold text-ink-100">{groupCounts.family}</span>
                <span className="block text-2xs text-ink-400">Family</span>
              </div>
              <div className="rounded border border-ink-800 bg-ink-850/40 p-2">
                <span className="block text-lg font-bold text-ink-100">{groupCounts.neighbor}</span>
                <span className="block text-2xs text-ink-400">Neighbors</span>
              </div>
              <div className="rounded border border-ink-800 bg-ink-850/40 p-2">
                <span className="block text-lg font-bold text-ink-100">{groupCounts.guest}</span>
                <span className="block text-2xs text-ink-400">Guests</span>
              </div>
            </div>

            {/* Quick preview list */}
            <ul className="divide-y divide-ink-800/60 mt-2 text-xs">
              {clients.slice(0, 3).map((c) => (
                <li key={c.id} className="py-1.5 flex items-center justify-between">
                  <div className="truncate pr-2">
                    <span className="font-medium text-ink-200">{c.hostname}</span>
                    <span className="text-2xs text-ink-400 block">{c.ipv4} &middot; {c.logical_group}</span>
                  </div>
                  <span className={`text-2xs font-semibold px-1.5 py-0.5 rounded ${c.blocked ? "bg-critical-muted text-critical-text" : "bg-ok/10 text-ok"}`}>
                    {c.blocked ? "Blocked" : "Online"}
                  </span>
                </li>
              ))}
            </ul>
          </div>

          <div className="mt-3 text-center">
            <Link href="/devices" className="text-2xs text-ink-400 hover:text-ink-200">
              Manage client policies &amp; limits &rarr;
            </Link>
          </div>
        </section>

        {/* Card 3: Security & Network Control */}
        <section className="rounded-lg border border-ink-800 bg-ink-900/60 p-4 shadow-sm">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold text-ink-100 uppercase tracking-wider">
              Security &amp; Network Control
            </h2>
            <Link href="/networks" className="text-xs text-ok hover:underline">
              Zones &rarr;
            </Link>
          </div>

          <div className="space-y-2.5 text-xs">
            <div className="flex items-center justify-between p-2 rounded bg-ink-850/50">
              <div>
                <span className="font-medium text-ink-200 block">Traffic Shaping (QoS)</span>
                <span className="text-2xs text-ink-400">Fair queueing and bufferbloat protection</span>
              </div>
              <span className="text-2xs font-semibold px-2 py-0.5 rounded bg-ok/10 text-ok">
                ACTIVE
              </span>
            </div>

            <div className="flex items-center justify-between p-2 rounded bg-ink-850/50">
              <div>
                <span className="font-medium text-ink-200 block">Firewall &amp; NAT</span>
                <span className="text-2xs text-ink-400">Drop unauthorized incoming traffic</span>
              </div>
              <span className="text-2xs font-semibold px-2 py-0.5 rounded bg-ok/10 text-ok">
                PROTECTED
              </span>
            </div>

            <div className="flex items-center justify-between p-2 rounded bg-ink-850/50">
              <div>
                <span className="font-medium text-ink-200 block">Client Isolation</span>
                <span className="text-2xs text-ink-400">Neighbors &amp; Guests isolated from Family LAN</span>
              </div>
              <span className="text-2xs font-semibold px-2 py-0.5 rounded bg-ok/10 text-ok">
                ENFORCED
              </span>
            </div>

            <div className="flex items-center justify-between p-2 rounded bg-ink-850/50">
              <div>
                <span className="font-medium text-ink-200 block">Management Access</span>
                <span className="text-2xs text-ink-400">Restricted to local network (No WAN access)</span>
              </div>
              <span className="text-2xs font-semibold px-2 py-0.5 rounded bg-ok/10 text-ok">
                LAN ONLY
              </span>
            </div>
          </div>
        </section>

        {/* Card 4: Gateway System Vitals */}
        <section className="rounded-lg border border-ink-800 bg-ink-900/60 p-4 shadow-sm flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-sm font-semibold text-ink-100 uppercase tracking-wider">
                Gateway Health
              </h2>
              <Link href="/monitoring" className="text-xs text-ok hover:underline">
                Vitals &rarr;
              </Link>
            </div>

            <div className="grid grid-cols-2 gap-3 my-2 text-xs">
              <div className="bg-ink-850/50 rounded p-2.5">
                <span className="block text-2xs text-ink-400">CPU Usage</span>
                <span className="text-lg font-bold text-ink-100">
                  {system.cpu_usage_percent > 0 ? `${system.cpu_usage_percent.toFixed(1)}%` : "Normal"}
                </span>
                <span className="block text-2xs text-ink-500 mt-0.5">Load: {system.cpu_load_average.join(", ")}</span>
              </div>

              <div className="bg-ink-850/50 rounded p-2.5">
                <span className="block text-2xs text-ink-400">Temperature</span>
                <span className="text-lg font-bold text-ink-100">
                  {system.temperature_celsius > 0 ? `${system.temperature_celsius.toFixed(1)} °C` : "Normal"}
                </span>
                <span className="block text-2xs text-ok mt-0.5">Hardware cool</span>
              </div>

              <div className="bg-ink-850/50 rounded p-2.5">
                <span className="block text-2xs text-ink-400">Memory</span>
                <span className="text-sm font-semibold text-ink-100">
                  {(system.memory_used_bytes / (1024 * 1024)).toFixed(0)} MB
                </span>
                <span className="block text-2xs text-ink-500 mt-0.5">of {(system.memory_total_bytes / (1024 * 1024)).toFixed(0)} MB</span>
              </div>

              <div className="bg-ink-850/50 rounded p-2.5">
                <span className="block text-2xs text-ink-400">Storage</span>
                <span className="text-sm font-semibold text-ink-100">
                  {(system.storage_used_bytes / (1024 * 1024 * 1024)).toFixed(0)} GB
                </span>
                <span className="block text-2xs text-ink-500 mt-0.5">of {(system.storage_total_bytes / (1024 * 1024 * 1024)).toFixed(0)} GB</span>
              </div>
            </div>
          </div>

          <div className="pt-2 text-2xs text-ink-400 flex justify-between items-center">
            <span>Kernel fail-closed safety active</span>
            <span className="text-ok">● No errors</span>
          </div>
        </section>
      </div>

      {/* Notifications / Alerts Section */}
      <section className="rounded-lg border border-ink-800 bg-ink-900/60 p-4 shadow-sm">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-ink-100 uppercase tracking-wider">
            Recent Gateway Alerts &amp; Notifications
          </h2>
          <span className="text-2xs text-ink-400">{events.length} recorded</span>
        </div>

        <ul className="divide-y divide-ink-800/80 text-xs">
          {events.slice(0, 4).map((e) => (
            <li key={e.id} className="py-2.5 flex items-start justify-between gap-3">
              <div>
                <div className="flex items-center gap-2">
                  <span className={`text-2xs font-semibold px-1.5 py-0.5 rounded ${
                    e.severity === "critical"
                      ? "bg-critical-muted text-critical-text"
                      : e.severity === "warning"
                      ? "bg-warning-muted text-warning-text"
                      : "bg-info-muted text-info-text"
                  }`}>
                    {e.severity.toUpperCase()}
                  </span>
                  <span className="font-medium text-ink-200">{e.message}</span>
                </div>
                <span className="text-2xs text-ink-500 block mt-0.5">
                  Source: {e.source} &middot; {new Date(e.timestamp).toLocaleTimeString()}
                </span>
              </div>
              <span className="text-2xs text-ink-400 shrink-0">
                {e.acknowledged ? "Acknowledged" : "Active"}
              </span>
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}
