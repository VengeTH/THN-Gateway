"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import type { ClientDevice } from "@/lib/types";

export function DeviceControls({ client }: { client: ClientDevice }) {
  const router = useRouter();
  const [isPending, startTransition] = useTransition();
  const [customMbps, setCustomMbps] = useState("");
  const [currentPolicy, setCurrentPolicy] = useState(client.qos_policy || "Default (Uncapped)");
  const [isBlocked, setIsBlocked] = useState(client.blocked);
  const [feedback, setFeedback] = useState<string | null>(null);

  const presets = [
    { label: "Uncapped", value: 0 },
    { label: "10M", value: 10 },
    { label: "20M", value: 20 },
    { label: "30M", value: 30 },
    { label: "50M", value: 50 },
  ];

  async function handleApplyLimit(mbps: number) {
    setFeedback(null);
    startTransition(async () => {
      try {
        const action = mbps === 0 ? "unlimit" : "limit";
        const res = await fetch("/api/clients/control", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            ip: client.ipv4,
            action,
            mbps: mbps > 0 ? mbps : undefined,
          }),
        });
        const data = await res.json();
        if (!res.ok) {
          setFeedback(`Error: ${data.error || "Failed to set limit"}`);
          return;
        }
        const newPolicy = mbps === 0 ? "Default (Uncapped)" : `${mbps} Mbps (Limited)`;
        setCurrentPolicy(newPolicy);
        setFeedback(mbps === 0 ? "Bandwidth uncapped" : `Limit set to ${mbps} Mbps`);
        router.refresh();
      } catch (err: unknown) {
        setFeedback(`Network error: ${String(err)}`);
      }
    });
  }

  async function handleToggleBlock() {
    setFeedback(null);
    startTransition(async () => {
      try {
        const action = isBlocked ? "unblock" : "block";
        const res = await fetch("/api/clients/control", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            ip: client.ipv4,
            action,
          }),
        });
        const data = await res.json();
        if (!res.ok) {
          setFeedback(`Error: ${data.error || "Failed to change block status"}`);
          return;
        }
        setIsBlocked(!isBlocked);
        setFeedback(!isBlocked ? "Device blocked" : "Device unblocked");
        router.refresh();
      } catch (err: unknown) {
        setFeedback(`Network error: ${String(err)}`);
      }
    });
  }

  return (
    <div className="mt-3 pt-3 border-t border-ink-800/80 flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs">
      {/* Current Policy badge and Feedback message */}
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-2xs uppercase tracking-wide text-ink-400">Bandwidth:</span>
        <span className="font-semibold text-ink-200 bg-ink-800 px-2 py-0.5 rounded text-2xs">
          {currentPolicy}
        </span>
        {feedback && (
          <span className="text-2xs text-ok font-medium animate-pulse">
            ✓ {feedback}
          </span>
        )}
      </div>

      {/* Interactive Controls: Presets, Custom Input, Block/Unblock */}
      <div className="flex items-center gap-2 flex-wrap">
        {/* Preset Limit Buttons */}
        <div className="inline-flex rounded-md shadow-sm border border-ink-700/60 overflow-hidden" role="group">
          {presets.map((p) => {
            const isActive =
              (p.value === 0 && currentPolicy.includes("Uncapped")) ||
              (p.value > 0 && currentPolicy.includes(`${p.value} Mbps`));

            return (
              <button
                key={p.label}
                type="button"
                disabled={isPending}
                onClick={() => handleApplyLimit(p.value)}
                className={`px-2 py-1 text-2xs font-medium transition-colors ${
                  isActive
                    ? "bg-accent text-ink-950 font-bold"
                    : "bg-ink-800 text-ink-300 hover:bg-ink-700 hover:text-ink-100"
                } disabled:opacity-50 border-r border-ink-700/60 last:border-r-0`}
              >
                {p.label}
              </button>
            );
          })}
        </div>

        {/* Custom Limit Input */}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            const val = parseInt(customMbps, 10);
            if (val > 0) {
              handleApplyLimit(val);
              setCustomMbps("");
            }
          }}
          className="flex items-center gap-1"
        >
          <input
            type="number"
            min="1"
            max="95"
            placeholder="Mbps"
            value={customMbps}
            onChange={(e) => setCustomMbps(e.target.value)}
            disabled={isPending}
            className="w-16 px-1.5 py-0.5 text-2xs rounded bg-ink-800 border border-ink-700 text-ink-100 focus:outline-none focus:border-accent"
          />
          <button
            type="submit"
            disabled={isPending || !customMbps}
            className="px-2 py-0.5 text-2xs bg-ink-700 text-ink-200 rounded hover:bg-ink-600 disabled:opacity-50"
          >
            Set
          </button>
        </form>

        {/* Block / Unblock Toggle */}
        <button
          type="button"
          disabled={isPending}
          onClick={handleToggleBlock}
          className={`px-2.5 py-1 text-2xs font-semibold rounded transition-colors ${
            isBlocked
              ? "bg-ok/20 text-ok border border-ok/40 hover:bg-ok/30"
              : "bg-critical-muted text-critical-text border border-critical-border hover:bg-critical-muted/80"
          } disabled:opacity-50`}
        >
          {isBlocked ? "Unblock" : "Block"}
        </button>
      </div>
    </div>
  );
}
