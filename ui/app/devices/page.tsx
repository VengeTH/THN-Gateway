import { Failure, PageHeader, Pill } from "@/components/primitives";
import { DeviceControls } from "@/components/device-controls";
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
      <PageHeader
        title={`Devices (${clients.length})`}
        plain="Every computer, phone and smart device currently on your network."
        detail="You can set a speed limit or block internet access for any of them."
      />

      {clients.length === 0 ? (
        <div className="panel">
          <div className="panel-body py-10 text-center">
            <p className="text-sm font-medium text-ink-200">No devices seen yet</p>
            <p className="mx-auto mt-1 max-w-md text-xs leading-relaxed text-ink-400">
              Devices appear here as they join the network. If you expected to
              see some, they may be on the internet connection rather than
              your own network, or they may not have connected since the
              gateway last looked.
            </p>
          </div>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-4">
          {clients.map((c) => (
            <div
              key={c.id}
              className="flex flex-col justify-between gap-3 rounded-lg border border-ink-800 bg-ink-900/60 p-4 shadow-panel"
            >
            <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-start sm:gap-4">
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="truncate text-sm font-semibold text-ink-100">
                    {c.hostname}
                  </span>
                  <span
                    className={`rounded px-2 py-0.5 text-2xs font-semibold ${
                      c.blocked
                        ? "bg-critical-muted text-critical-text"
                        : "bg-ok-muted/20 text-ok-fg"
                    }`}
                  >
                    {c.blocked ? "Blocked" : "Online"}
                  </span>
                  <span className="rounded bg-ink-800 px-2 py-0.5 text-2xs uppercase text-ink-400">
                    {c.logical_group}
                  </span>
                </div>

                <dl className="mt-2 grid grid-cols-[5rem_minmax(0,1fr)] gap-x-3 gap-y-0.5 text-2xs">
                  <dt className="text-ink-500">Address</dt>
                  <dd className="truncate font-mono text-ink-200">{c.ipv4}</dd>
                  <dt className="text-ink-500">Group</dt>
                  <dd className="truncate font-mono text-ink-200">{c.network_id}</dd>
                  <dt className="text-ink-500">Visibility</dt>
                  <dd className="truncate text-ink-300">{c.isolation_status}</dd>
                </dl>
              </div>

              <div className="shrink-0 border-t border-ink-800/80 pt-2 text-xs sm:border-l sm:border-t-0 sm:pl-4 sm:pt-0 sm:text-right">
                <span className="block text-2xs uppercase text-ink-400">Speed limit</span>
                <span className="block font-medium text-ink-200">
                  {c.qos_policy || "No limit"}
                </span>
                <span className="mt-0.5 block text-2xs text-ink-500">
                  Using {(c.current_rx_bps / 1_000_000).toFixed(1)} Mbit/s now
                </span>
              </div>
            </div>

            {/* Live Interactive Bandwidth & Access Controls */}
              <DeviceControls client={c} />
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
