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
    <div className="mt-3 flex flex-col gap-3 border-t border-ink-800/80 pt-3 text-xs">
      {/* Current policy and the result of the last action. */}
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-2xs uppercase tracking-wide text-ink-400">Speed limit</span>
        <span className="rounded bg-ink-800 px-2 py-0.5 text-2xs font-semibold text-ink-200">
          {currentPolicy}
        </span>
        {feedback ? (
          <span
            role="status"
            aria-live="polite"
            className={`text-2xs font-medium ${
              feedback.startsWith("Error") || feedback.startsWith("Network")
                ? "text-critical-fg"
                : "text-ok-fg"
            }`}
          >
            {feedback.startsWith("Error") || feedback.startsWith("Network") ? "✕" : "✓"}{" "}
            {feedback}
          </span>
        ) : null}
      </div>

      <div className="flex flex-wrap items-center gap-2">
        {/* Preset limits. The group is labelled so a screen reader announces
            what the row of buttons is for rather than five unlabelled numbers. */}
        <div
          role="group"
          aria-label={`Speed limit presets for ${client.hostname}`}
          className="inline-flex overflow-hidden rounded-md border border-ink-700"
        >
          {presets.map((p) => {
            const isActive =
              (p.value === 0 && currentPolicy.includes("Uncapped")) ||
              (p.value > 0 && currentPolicy.includes(`${p.value} Mbps`));

            return (
              <button
                key={p.label}
                type="button"
                disabled={isPending}
                aria-pressed={isActive}
                onClick={() => handleApplyLimit(p.value)}
                className={`tap border-r border-ink-700 px-2.5 py-1 text-2xs font-medium transition-colors last:border-r-0 disabled:opacity-50 sm:min-h-0 ${
                  isActive
                    ? "bg-accent font-bold text-accent-text"
                    : "bg-ink-800 text-ink-300 hover:bg-ink-700 hover:text-ink-100"
                }`}
              >
                {p.label}
              </button>
            );
          })}
        </div>

        {/* Custom limit. */}
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
          <label htmlFor={`limit-${client.id}`} className="sr-only">
            Custom speed limit in Mbit/s for {client.hostname}
          </label>
          <input
            id={`limit-${client.id}`}
            type="number"
            min="1"
            max="1000"
            inputMode="numeric"
            placeholder="Other"
            value={customMbps}
            onChange={(e) => setCustomMbps(e.target.value)}
            disabled={isPending}
            className="tap w-20 rounded border border-ink-700 bg-ink-950 px-2 py-1 text-2xs text-ink-100 outline-none focus:border-accent sm:min-h-0"
          />
          <button
            type="submit"
            disabled={isPending || !customMbps}
            className="btn tap !py-1 text-2xs sm:min-h-0"
          >
            Set
          </button>
        </form>

        {/* Block / Unblock Toggle. The label says what the button will do, not what
           is currently true — "Unblock" next to a blocked device is an action,
           and reading it as a status is the more common mistake. */}
        <button
          type="button"
          disabled={isPending}
          onClick={handleToggleBlock}
          className={`btn tap !py-1 text-2xs font-semibold sm:min-h-0 ${
            isBlocked
              ? "border-ok-edge/50 text-ok-fg hover:bg-ok-muted/20"
              : "border-critical-edge/50 text-critical-fg hover:bg-critical-muted/20"
          }`}
        >
          {isBlocked ? "Allow internet" : "Block internet"}
        </button>
      </div>
    </div>
  );
}
