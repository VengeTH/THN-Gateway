import { Failure, PageHeader, Panel, Stat, Field, Empty } from "@/components/primitives";
import { DataTable } from "@/components/data-table";
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
      <PageHeader
        title="Monitoring"
        plain="The cables, ports and hardware behind your network."
        detail="If a cable is loose or a port has failed, it shows up here before it causes a problem for you."
      />

      {/* Interfaces */}
      <Panel title={`Cables and ports (${ifaces.length})`} note="Every network port the gateway can see">
        <div className="panel-body">
          <DataTable
            caption="Network interfaces"
            rows={ifaces}
            rowKey={(i) => i.name}
            empty={<Empty>No interfaces were reported.</Empty>}
            columns={[
              {
                key: "role",
                label: "purpose",
                render: (i) => <span className="text-xs font-semibold text-ink-100">{i.role}</span>,
              },
              {
                key: "name",
                label: "port",
                render: (i) => <span className="value">{i.name}</span>,
              },
              {
                key: "state",
                label: "status",
                render: (i) => (
                  <span
                    className={`inline-flex rounded px-1.5 py-0.5 text-2xs font-semibold uppercase ${
                      i.state === "up"
                        ? "bg-ok-muted/20 text-ok-fg"
                        : "bg-critical-muted text-critical-text"
                    }`}
                  >
                    {i.state}
                  </span>
                ),
              },
              {
                key: "speed",
                label: "max speed",
                render: (i) => (
                  <span className="text-xs text-ink-300">
                    {i.speed_mbps > 0 ? `${i.speed_mbps} Mbps` : "—"}
                    {i.duplex ? ` · ${i.duplex}` : ""}
                  </span>
                ),
              },
              {
                key: "ipv4",
                label: "addresses",
                render: (i) =>
                  i.ipv4.length > 0 ? (
                    <span className="value break-all text-ink-300">{i.ipv4.join(", ")}</span>
                  ) : (
                    <span className="text-2xs text-ink-500">none</span>
                  ),
              },
              {
                key: "errors",
                label: "errors",
                render: (i) => {
                  const errs = i.rx_errors + i.tx_errors + i.rx_drops + i.tx_drops;
                  return errs > 0 ? (
                    <span className="text-2xs font-medium text-warning-fg">{errs.toLocaleString()}</span>
                  ) : (
                    <span className="text-2xs text-ok-fg">none</span>
                  );
                },
              },
            ]}
          />
        </div>
      </Panel>

      {/* WAN Health */}
      <Panel title="Internet connection quality" note="How well the link to your provider is behaving">
        <div className="panel-body grid grid-cols-2 gap-3 sm:grid-cols-4">
          <Stat
            label="Reply time"
            value={wan.latency_ms > 0 ? `${wan.latency_ms} ms` : "—"}
            hint={wan.latency_ms <= 0 ? "not measured" : wan.latency_ms < 50 ? "fast" : "slow"}
            tone={wan.latency_ms <= 0 ? "neutral" : wan.latency_ms < 50 ? "ok" : "warning"}
          />
          <Stat
            label="Packets lost"
            value={`${wan.packet_loss_pct}%`}
            hint={wan.packet_loss_pct === 0 ? "none" : "connection is unstable"}
            tone={wan.packet_loss_pct === 0 ? "ok" : "warning"}
          />
          <Stat
            label="Router reachable"
            value={wan.gateway_reachable ? "Yes" : "No"}
            tone={wan.gateway_reachable ? "ok" : "critical"}
          />
          <Stat
            label="DNS working"
            value={wan.dns_reachable ? "Yes" : "No"}
            tone={wan.dns_reachable ? "ok" : "critical"}
          />
        </div>
      </Panel>

      {/*
        The remaining metrics used to render a fixed verdict under each
        reading — "Low jitter", "0.0% loss", "Reachable" — regardless of what
        the reading actually was. A page that says "low jitter" next to a 900ms
        latency is worse than one that shows only the number, because it tells
        the reader the gateway checked something it never checked.
      */}
      <Panel title="Connection details" note="The technical readings behind the summary above">
        <div className="panel-body grid gap-x-6 gap-y-2 sm:grid-cols-2">
          <Field label="Internet port">{wan.interface_name}</Field>
          <Field label="Router address">{wan.gateway_ip}</Field>
          <Field label="Downloading">{formatBps(wan.rx_throughput_bps)}</Field>
          <Field label="Uploading">{formatBps(wan.tx_throughput_bps)}</Field>
          <Field label="Name servers">{wan.dns_servers.join(", ") || "—"}</Field>
          <Field label="Reported status">{wan.status}</Field>
        </div>
      </Panel>
    </div>
  );
}

function formatBps(bps: number): string {
  if (!Number.isFinite(bps) || bps <= 0) return "idle";
  if (bps >= 1_000_000_000) return `${(bps / 1_000_000_000).toFixed(2)} Gbit/s`;
  if (bps >= 1_000_000) return `${(bps / 1_000_000).toFixed(1)} Mbit/s`;
  if (bps >= 1_000) return `${(bps / 1_000).toFixed(0)} kbit/s`;
  return `${Math.round(bps)} bit/s`;
}
