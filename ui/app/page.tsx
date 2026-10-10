import Link from "next/link";
import { Failure, PageHeader, Stat } from "@/components/primitives";
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
      ? "bg-ok-muted/20 text-ok-fg border-ok-edge/40"
      : gateway.internet_status === "degraded"
      ? "bg-warning-muted text-warning-text border-warning-edge"
      : "bg-critical-muted text-critical-text border-critical-edge";

  return (
    <div className="space-y-6">
      {/* Top Banner / Gateway Identity */}
      <PageHeader
        title={gateway.hostname}
        plain={
          gateway.internet_status === "online"
            ? "Your network and internet are working."
            : gateway.internet_status === "degraded"
              ? "Your local network works, but the internet connection is unstable."
              : "Your local network is up, but the internet is not reachable."
        }
        detail={`Up for ${gateway.uptime} · ${describeActivation(gateway.activation_state)}`}
        action={
          <span
            className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-semibold ${internetStatusTone}`}
          >
            <span aria-hidden="true" className="h-2 w-2 rounded-full bg-current" />
            {describeStatus(gateway.internet_status)}
          </span>
        }
      />

      {/* Grid: 1 col on mobile, 2 cols on tablet/desktop */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Card 1: Internet & Uplink */}
        <section className="rounded-lg border border-ink-800 bg-ink-900 p-4 shadow-panel flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-sm font-semibold font-display text-ink-100 tracking-tight">
                Internet Connection
              </h2>
              <span className="text-2xs text-ink-400">WAN: {wan.interface_name}</span>
            </div>

            <div className="my-4 text-center">
              <div className="text-xl font-bold font-display text-ink-50 sm:text-2xl">
                {wan.internet_reachable ? "Internet is working" : "No internet"}
              </div>
              <p className="mt-1 text-xs text-ink-400">
                Reply time {wan.latency_ms > 0 ? `${wan.latency_ms} ms` : "unknown"} &middot;{" "}
                lost packets {wan.packet_loss_pct}%
              </p>
            </div>

            <div className="grid grid-cols-2 gap-3 border-t border-ink-800/80 pt-3 text-center">
              <div className="rounded bg-ink-850 p-2.5">
                <span className="block text-2xs uppercase tracking-wider text-ink-400">Downloading now</span>
                <span className="text-base font-semibold font-display text-ink-100">
                  {formatSpeed(wan.rx_throughput_bps)}
                </span>
              </div>
              <div className="rounded bg-ink-850 p-2.5">
                <span className="block text-2xs uppercase tracking-wider text-ink-400">Uploading now</span>
                <span className="text-base font-semibold font-display text-ink-100">
                  {formatSpeed(wan.tx_throughput_bps)}
                </span>
              </div>
            </div>
          </div>
          <div className="mt-4 text-2xs text-ink-400 text-center">
            DNS Resolvers: {wan.dns_servers.join(", ")}
          </div>
        </section>

        {/* Card 2: Connected Devices Summary */}
        <section className="rounded-lg border border-ink-800 bg-ink-900 p-4 shadow-panel flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-sm font-semibold font-display text-ink-100 tracking-tight">
                Connected Devices
              </h2>
              <Link href="/devices" className="text-xs text-accent hover:underline">
                View all ({clients.length}) &rarr;
              </Link>
            </div>

            <div className="grid grid-cols-3 gap-2 my-3 text-center">
              <div className="rounded border border-ink-800 bg-ink-850 p-2">
                <span className="block text-lg font-bold font-display text-ink-100">{groupCounts.family}</span>
                <span className="block text-2xs text-ink-400">Family</span>
              </div>
              <div className="rounded border border-ink-800 bg-ink-850 p-2">
                <span className="block text-lg font-bold font-display text-ink-100">{groupCounts.neighbor}</span>
                <span className="block text-2xs text-ink-400">Neighbors</span>
              </div>
              <div className="rounded border border-ink-800 bg-ink-850 p-2">
                <span className="block text-lg font-bold font-display text-ink-100">{groupCounts.guest}</span>
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
                  <span
                    className={`text-2xs font-semibold px-1.5 py-0.5 rounded ${
                      c.blocked
                        ? "bg-critical-muted text-critical-fg"
                        : c.online
                          ? "bg-ok-muted/20 text-ok-fg"
                          : "bg-ink-800 text-ink-400"
                    }`}
                  >
                    {c.blocked ? "Blocked" : c.online ? "Online" : "Offline"}
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
        <section className="rounded-lg border border-ink-800 bg-ink-900 p-4 shadow-panel">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold font-display text-ink-100 tracking-tight">
              Security &amp; Network Control
            </h2>
            <Link href="/networks" className="text-xs text-accent hover:underline">
              Zones &rarr;
            </Link>
          </div>

          <div className="space-y-2 text-xs">
            {[
              {
                title: "Speed shaping",
                note: "Devices with a speed limit get one, so one device cannot use up everyone else's",
                href: "/policies",
              },
              {
                title: "Firewall",
                note: "Incoming connections from outside your network are refused",
                href: "/render",
              },
              {
                title: "Device separation",
                note: "Guest and neighbour devices cannot see each other or your main devices",
                href: "/networks",
              },
              {
                title: "Management access",
                note: "This console can only be reached from inside your network",
                href: "/about",
              },
            ].map((item) => (
              <Link
                key={item.title}
                href={item.href}
                className="flex items-center justify-between gap-3 rounded bg-ink-850 p-2.5 transition-colors hover:bg-ink-800"
              >
                <span className="min-w-0">
                  <span className="block font-medium text-ink-200">{item.title}</span>
                  <span className="block text-2xs text-ink-400">{item.note}</span>
                </span>
                <span aria-hidden="true" className="shrink-0 text-2xs text-accent">
                  →
                </span>
              </Link>
            ))}
          </div>
        </section>

        {/* Card 4: Gateway System Vitals */}
        <section className="rounded-lg border border-ink-800 bg-ink-900 p-4 shadow-panel flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-sm font-semibold font-display text-ink-100 tracking-tight">
                Gateway Health
              </h2>
              <Link href="/monitoring" className="text-xs text-accent hover:underline">
                Vitals &rarr;
              </Link>
            </div>

            <div className="my-2 grid grid-cols-2 gap-3 text-xs">
              <Stat
                label="Processor"
                value={
                  system.cpu_usage_percent > 0
                    ? `${system.cpu_usage_percent.toFixed(0)}%`
                    : "—"
                }
                hint={`Load ${system.cpu_load_average.join(", ")}`}
                tone={system.cpu_usage_percent > 85 ? "warning" : "neutral"}
              />
              <Stat
                label="Temperature"
                value={
                  system.temperature_celsius > 0 ? `${system.temperature_celsius.toFixed(0)}°C` : "—"
                }
                tone={
                  system.temperature_celsius >= 80
                    ? "warning"
                    : system.temperature_celsius > 0
                      ? "ok"
                      : "neutral"
                }
              />

              <Stat
                label="Memory used"
                value={`${(system.memory_used_bytes / (1024 * 1024)).toFixed(0)} MB`}
                hint={`of ${(system.memory_total_bytes / (1024 * 1024)).toFixed(0)} MB`}
              />
              <Stat
                label="Storage used"
                value={`${(system.storage_used_bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`}
                hint={`of ${(system.storage_total_bytes / (1024 * 1024 * 1024)).toFixed(0)} GB`}
              />
            </div>
          </div>

          <p className="mt-2 border-t border-ink-800/80 pt-2 text-2xs text-ink-400">
            Safety behaviour: if the gateway cannot read the state of the
            network, it stops rather than letting traffic through unchecked.
          </p>
        </section>
      </div>

      {/* Recent activity */}
      <section className="rounded-lg border border-ink-800 bg-ink-900 p-4 shadow-panel">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-sm font-semibold font-display text-ink-100 tracking-tight">Recent activity</h2>
          <Link href="/incidents" className="link text-xs">
            See all problems →
          </Link>
        </div>

        {events.length === 0 ? (
          <p className="py-4 text-center text-xs text-ink-400">
            Nothing has been recorded yet.
          </p>
        ) : (
          <ul className="divide-y divide-ink-800/80 text-xs">
            {events.slice(0, 4).map((e) => (
              <li key={e.id} className="flex flex-wrap items-start justify-between gap-x-3 gap-y-1 py-2.5">
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span
                      className={`rounded px-1.5 py-0.5 text-2xs font-semibold ${
                        e.severity === "critical"
                          ? "bg-critical-muted text-critical-text"
                          : e.severity === "warning"
                            ? "bg-warning-muted text-warning-text"
                            : "bg-info-muted text-info-text"
                      }`}
                    >
                      {e.severity}
                    </span>
                    <span className="font-medium text-ink-200">{e.message}</span>
                  </div>
                  <span className="mt-0.5 block text-2xs text-ink-500">
                    {e.source} &middot; {formatTime(e.timestamp)}
                  </span>
                </div>
                <span className="shrink-0 text-2xs text-ink-400">
                  {e.acknowledged ? "Seen" : "New"}
                </span>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}

// ------------------------------------------------------------- helpers

/**
 * Renders a bit rate for a person.
 *
 * The unit is inside the value rather than in the label, because a speed is
 * quoted without its label and "1.4" means nothing on its own.
 */
function formatSpeed(bps: number): string {
  if (!Number.isFinite(bps) || bps <= 0) return "idle";
  if (bps >= 1_000_000_000) return `${(bps / 1_000_000_000).toFixed(1)} Gbit/s`;
  if (bps >= 1_000_000) return `${(bps / 1_000_000).toFixed(1)} Mbit/s`;
  if (bps >= 1_000) return `${(bps / 1_000).toFixed(0)} kbit/s`;
  return `${Math.round(bps)} bit/s`;
}

function formatTime(timestamp: string): string {
  const d = new Date(timestamp);
  return Number.isNaN(d.getTime()) ? timestamp : d.toLocaleTimeString();
}

/**
 * The binary speaks in states; a person does not. These two renderings exist
 * so the vocabulary of the machine never reaches the top of a page.
 */
function describeStatus(status: string): string {
  switch (status) {
    case "online":
      return "Internet working";
    case "degraded":
      return "Internet unstable";
    case "offline":
      return "No internet";
    default:
      return "Status unknown";
  }
}

function describeActivation(state: string): string {
  switch (state) {
    case "active":
      return "running normally";
    case "dryrun":
      return "in test mode — nothing is being applied";
    default:
      return `mode: ${state}`;
  }
}
