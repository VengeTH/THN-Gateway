import { Failure, Panel, Pill, Because, Empty, Pre } from "@/components/primitives";
import { thn } from "@/lib/thn";
import type { PolicyListResponse, PolicyResolveResponse } from "@/lib/types";

export const dynamic = "force-dynamic";

/**
 * Per-device policies, and the resolution that decides them.
 *
 * # Why resolution gets a form of its own
 *
 * A per-device policy layer is the only part of THN whose output is a choice
 * rather than a rendering. Given a device and a moment, several bindings match,
 * and one wins. The wrong one applying produces no error at all — the guest
 * simply gets the whole link, and nothing says so.
 *
 * So the page is built around showing the decision, not just the answer. Every
 * binding that was considered is listed, the winner is marked, and the losers
 * say why they lost. A policy layer whose selection is invisible is one nobody
 * leaves enabled.
 */
export default async function PoliciesPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const params = await searchParams;
  const mac = firstString(params.mac);
  const at = firstString(params.at);

  const listed = await thn<PolicyListResponse>(["policy", "list"]);

  const resolveArgs = ["resolve"];
  if (mac) resolveArgs.push("--mac", mac);
  if (at) resolveArgs.push("--at", at);
  const resolved =
    mac || at ? await thn<PolicyResolveResponse>(["policy", ...resolveArgs]) : null;

  return (
    <>
      <h1 className="mb-1 text-lg font-semibold tracking-tight text-ink-50">Policies</h1>
      <p className="mb-5 text-xs text-ink-400">
        Named settings selected per device and per time. A device with no
        profile gets the host defaults, which is a complete configuration.
      </p>

      <ResolveForm mac={mac ?? ""} at={at ?? ""} />

      {resolved ? (
        resolved.ok ? (
          <Resolution result={resolved.data} mac={mac ?? ""} />
        ) : (
          <Failure error={resolved.error} />
        )
      ) : null}

      {listed.ok ? (
        <>
          <Panel
            title="Profiles"
            note="the settings a binding can select"
          >
            {listed.data.counts.total === 0 ? (
              <Empty>
                No per-device policies are configured. Every device gets the
                host defaults from the qos, dns and firewall blocks.
              </Empty>
            ) : (
              <>
                <ProfileGroup
                  title="bandwidth"
                  count={listed.data.counts.bandwidth ?? 0}
                  entries={Object.entries(listed.data.policies.bandwidth ?? {}).map(
                    ([name, p]) => ({
                      name,
                      summary: p.shaped
                        ? `${p.rate.download_kbps}/${p.rate.upload_kbps} kbit/s` +
                          (p.rate.overhead_percent
                            ? ` (overhead ${p.rate.overhead_percent}%)`
                            : "")
                        : "unconstrained",
                    }),
                  )}
                />
                <ProfileGroup
                  title="dns"
                  count={listed.data.counts.dns ?? 0}
                  entries={Object.entries(listed.data.policies.dns ?? {}).map(
                    ([name, p]) => ({
                      name,
                      summary:
                        (p.upstreams && p.upstreams.length > 0
                          ? `via ${p.upstreams.join(", ")}`
                          : "host default resolvers") +
                        (p.blocked && p.blocked.length > 0
                          ? ` · blocking ${p.blocked.length}`
                          : ""),
                    }),
                  )}
                />
                <ProfileGroup
                  title="firewall"
                  count={listed.data.counts.firewall ?? 0}
                  entries={Object.entries(listed.data.policies.firewall ?? {}).map(
                    ([name, p]) => ({
                      name,
                      summary:
                        `default ${p.default}` + (p.isolate ? " · isolated" : "") +
                        (p.rules && p.rules.length > 0 ? ` · ${p.rules.length} rules` : ""),
                    }),
                  )}
                />
                <ProfileGroup
                  title="device"
                  count={listed.data.counts.device ?? 0}
                  entries={Object.entries(listed.data.policies.devices ?? {}).map(
                    ([name, p]) => ({
                      name,
                      summary: [
                        p.bandwidth ? `bandwidth=${p.bandwidth}` : null,
                        p.dns ? `dns=${p.dns}` : null,
                        p.firewall ? `firewall=${p.firewall}` : null,
                        p.expect_strong_identity ? "expects strong identity" : null,
                      ]
                        .filter(Boolean)
                        .join(" · ") || "no overrides",
                    }),
                  )}
                />
              </>
            )}
          </Panel>

          <Panel
            title="Bindings"
            note="which subject gets which profile, and when"
          >
            {(listed.data.policies.bindings ?? []).length === 0 ? (
              <Empty>No bindings. Nothing overrides the host defaults.</Empty>
            ) : (
              <div className="panel-body">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-ink-800 text-left">
                      <th className="label w-24 pb-2">kind</th>
                      <th className="label w-56 pb-2">subject</th>
                      <th className="label w-40 pb-2">profile</th>
                      <th className="label pb-2">when</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(listed.data.policies.bindings ?? []).map((b, i) => (
                      <tr key={`${b.kind}-${i}`} className="border-b border-ink-850 last:border-b-0">
                        <td className="py-1.5 pr-3">
                          <span className="value text-ink-300">{b.kind}</span>
                        </td>
                        <td className="py-1.5 pr-3">
                          <span className="value text-ink-200">
                            {b.subject.mac ?? b.subject.device_id ?? b.subject.hostname ?? "(any device)"}
                          </span>
                        </td>
                        <td className="py-1.5 pr-3">
                          <span className="value text-ink-200">{b.profile}</span>
                        </td>
                        <td className="py-1.5">
                          {b.schedule ? (
                            <span className="value text-ink-300">{b.schedule}</span>
                          ) : (
                            <Pill>always</Pill>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Panel>
        </>
      ) : (
        <Failure error={listed.error} />
      )}
    </>
  );
}

function ProfileGroup({
  title,
  count,
  entries,
}: {
  title: string;
  count: number;
  entries: Array<{ name: string; summary: string }>;
}) {
  if (count === 0) return null;
  return (
    <div className="mb-3 last:mb-0">
      <div className="label mb-1">{title}</div>
      {entries.map((e) => (
        <div key={e.name} className="flex items-baseline gap-3 py-0.5">
          <span className="value w-40 shrink-0 text-ink-200">{e.name}</span>
          <span className="text-2xs text-ink-400">{e.summary}</span>
        </div>
      ))}
    </div>
  );
}

function Resolution({
  result,
  mac,
}: {
  result: PolicyResolveResponse;
  mac: string;
}) {
  const r = result.resolution;
  const reasons = r.reasons ?? [];
  const unresolved = r.unresolved ?? [];

  return (
    <Panel
      title="Resolution"
      note={`${mac || "every device"} at ${r.at}`}
      action={unresolved.length > 0 ? <Pill>{unresolved.length} unresolved</Pill> : null}
    >
      <div className="panel-body grid grid-cols-2 gap-4 border-b border-ink-800">
        <Effective label="device" value={r.device?.name} note={describeDevice(r.device?.name)} />
        <Effective
          label="bandwidth"
          value={
            r.bandwidth
              ? `${r.bandwidth.rate.download_kbps}/${r.bandwidth.rate.upload_kbps} kbit/s`
              : undefined
          }
          note={r.bandwidth?.name}
        />
        <Effective
          label="dns"
          value={
            r.dns
              ? r.dns.upstreams && r.dns.upstreams.length > 0
                ? r.dns.upstreams.join(", ")
                : "host default"
              : undefined
          }
          note={r.dns?.name}
        />
        <Effective
          label="firewall"
          value={r.firewall ? `default ${r.firewall.default}` : undefined}
          note={r.firewall?.isolate ? `${r.firewall.name} · isolated` : r.firewall?.name}
        />
      </div>

      {/* The decision, spelled out. This is the part of the page that exists
          for the operator debugging why a limit did or did not apply. */}
      <div className="panel-body">
        <div className="label mb-2">Why</div>
        {reasons.length === 0 ? (
          <Empty>No bindings matched. The host defaults are in force.</Empty>
        ) : (
          <ol className="space-y-2">
            {reasons.map((reason, i) => (
              <li
                key={`${reason.binding.kind}-${i}`}
                className={`rounded border px-3 py-2 ${
                  reason.selected
                    ? "border-ok/40 bg-ok-muted/20"
                    : "border-ink-800 bg-ink-950"
                }`}
              >
                <div className="flex items-baseline gap-2">
                  <span className="value text-ink-100">
                    {reason.binding.subject.mac ??
                      reason.binding.subject.device_id ??
                      reason.binding.subject.hostname ??
                      "(any device)"}
                  </span>
                  <span className="muted">→</span>
                  <span className="value text-ink-100">{reason.binding.profile}</span>
                  {reason.selected ? <Pill>selected</Pill> : null}
                  {reason.binding.schedule ? (
                    <span className="text-2xs text-ink-500">
                      ({reason.binding.schedule})
                    </span>
                  ) : null}
                </div>
                <Because>{reason.explanation}</Because>
              </li>
            ))}
          </ol>
        )}
      </div>

      {unresolved.length > 0 ? (
        <div className="panel-body border-t border-critical/30">
          <div className="label mb-1 text-critical-text">Configuration problems</div>
          <ul className="space-y-1">
            {unresolved.map((u) => (
              <li key={u} className="text-2xs text-critical-text">
                {u}
              </li>
            ))}
          </ul>
          <Because>
            These are errors in the document, not faults on the device. The
            resolution above is what the rest of the document produces.
          </Because>
        </div>
      ) : null}
    </Panel>
  );
}

function Effective({
  label,
  value,
  note,
}: {
  label: string;
  value: string | undefined;
  note?: string | undefined;
}) {
  return (
    <div>
      <div className="label">{label}</div>
      {value ? (
        <div>
          <div className="value">{value}</div>
          {note ? <Because>{note}</Because> : null}
        </div>
      ) : (
        <div className="value muted">not selected</div>
      )}
    </div>
  );
}

function describeDevice(name: string | undefined): string | undefined {
  return name;
}

function ResolveForm({ mac, at }: { mac: string; at: string }) {
  return (
    <Panel title="Resolve" note="what a given device gets at a given moment">
      <form method="get" className="panel-body space-y-2">
        <div className="flex flex-wrap gap-2">
          <label className="flex items-center gap-2">
            <span className="label">mac</span>
            <input
              type="text"
              name="mac"
              defaultValue={mac}
              placeholder="aa:bb:cc:dd:ee:01"
              className="w-56 rounded border border-ink-700 bg-ink-950 px-3 py-2 font-mono text-xs text-ink-100 outline-none focus:border-ink-500"
            />
          </label>
          <label className="flex items-center gap-2">
            <span className="label">at</span>
            <input
              type="text"
              name="at"
              defaultValue={at}
              placeholder="2026-03-14T23:00:00Z"
              className="w-56 rounded border border-ink-700 bg-ink-950 px-3 py-2 font-mono text-xs text-ink-100 outline-none focus:border-ink-500"
            />
          </label>
          <button
            type="submit"
            className="rounded border border-ink-600 bg-ink-800 px-3 py-1.5 text-xs font-medium text-ink-100 hover:bg-ink-700"
          >
            Resolve
          </button>
        </div>
        <Because>
          The time is an RFC 3339 instant. It matters: a policy gated by an
          overnight window resolves differently at 23:00 and at 03:00, and
          that difference is the whole reason the layer has a time model.
        </Because>
      </form>
    </Panel>
  );
}

function firstString(v: string | string[] | undefined): string | undefined {
  return Array.isArray(v) ? v[0] : v;
}
