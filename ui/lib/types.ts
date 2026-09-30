/**
 * Types mirroring what the Go binary prints under `--json`.
 *
 * # Why these are hand-written rather than generated
 *
 * The binary is the contract. Generating types from it would mean a build step
 * that runs the binary, which would make `next build` depend on a Go toolchain
 * and a compiled binary being present — and a type check that silently passes
 * because it could not run is worse than no type check.
 *
 * So these are written by hand, and the drift risk is handled where it belongs:
 * `ui/lib/schema-check.ts` holds a test that compares the fields this file
 * declares against the fields a real invocation actually returns, and a
 * mismatch fails the build.
 *
 * Optional fields are marked optional for a reason: THN reports different
 * shapes depending on what it could observe, and a type that claimed otherwise
 * would force the console to invent a value rather than say "not known".
 */

import type { ThnError } from "./thn";

// ---------------------------------------------------------------- signals

export type SignalKind = "bool" | "number" | "string";

export interface Signal {
  name: string;
  source: string;
  value: {
    kind: SignalKind;
    /** False means the value could not be read. Never treat it as a zero. */
    known: boolean;
    number: number;
    bool: boolean;
    str: string;
  };
  at: string;
  labels?: Record<string, string>;
  detail?: string;
}

// ------------------------------------------------------------------- rules

export type Severity = "critical" | "warning" | "info";

export interface RuleCondition {
  name: string;
  title: string;
  severity: Severity;
  /**
   * The duration threshold in nanoseconds. A number rather than "1m0s"
   * because every use of it here is a comparison, and parsing a Go duration
   * string back into a number in the browser to do that is a step that can
   * fail for no good reason.
   */
  for: number;
  remedy?: string;
  comments?: string[];
  /**
   * The condition in prose. Present on an evaluated instance, absent from the
   * catalogue entry, so it is not safe to require.
   */
  condition?: string;
  labels?: Record<string, string>;
}

export interface InhibitRule {
  source: string;
  target: string;
  reason: string;
  equal?: string[];
}

export interface RulesListResponse {
  rules: RuleCondition[];
  inhibitions: InhibitRule[];
  count: number;
}

export type RuleState = "inactive" | "pending" | "firing";
export type Truth = "true" | "false" | "unknown";

export interface RuleInstance {
  rule: string;
  group?: string;
  state: RuleState;
  since: string;
  severity: Severity;
  title?: string;
  condition?: string;
  /**
   * The signals this conclusion rests on, in full. An incident that says a
   * thing is broken should say what it saw, so this is rendered rather than
   * merely counted.
   */
  evidence?: Signal;
  last_truth: Truth;
  conditions?: string[];
}

export interface RulesTestResponse {
  at: string;
  observations: Signal[];
  firing: RuleInstance[];
  pending: RuleInstance[];
  undecidable: RuleInstance[];
}

// --------------------------------------------------------------- incidents

export type IncidentStatus = "active" | "resolved";

export interface IncidentContribution {
  rule: string;
  title?: string;
  condition?: string;
  evidence?: string;
  severity: Severity;
  suppressed?: boolean;
  suppressed_by?: string;
  suppressed_reason?: string;
}

export interface IncidentEntry {
  at: string;
  action: "opened" | "updated" | "escalated" | "resolved" | "reopened";
  detail: string;
  severity: Severity;
  conditions: number;
}

export interface Incident {
  id: string;
  fingerprint: string;
  key: string;
  title: string;
  severity: Severity;
  status: IncidentStatus;
  opened_at: string;
  updated_at: string;
  resolved_at?: string;
  /** Go duration string, e.g. "4m0s". */
  duration: string;
  flaps: number;
  causes: IncidentContribution[];
  consequences?: IncidentContribution[];
  timeline: IncidentEntry[];
}

export interface IncidentCounts {
  active: number;
  resolved: number;
  critical: number;
  warning: number;
  flapping: number;
}

export interface IncidentsResponse {
  source: string;
  recorded: boolean;
  incidents: Incident[];
  summary: IncidentCounts;
}

// ---------------------------------------------------------------- policies

export type PolicyKind = "device" | "bandwidth" | "dns" | "firewall";

export interface BandwidthProfile {
  name: string;
  rate: {
    download_kbps: number;
    upload_kbps: number;
    overhead_percent?: number;
  };
  /**
   * The tc parameters the rate would be applied with. Carried alongside the
   * rate because a rate without them is not a specification — 5000kbps means
   * different things at different `target_ms`.
   */
  limits?: {
    target_ms: number;
    interval_ms: number;
    quantum: number;
  };
  shaped?: boolean;
  comments?: string[];
}

export interface DNSProfile {
  name: string;
  upstreams?: string[];
  blocked?: string[];
  log_queries?: boolean;
  comments?: string[];
}

export type FirewallAction = "allow" | "deny";

export interface FirewallProfile {
  name: string;
  default: FirewallAction;
  isolate?: boolean;
  rules?: Array<{
    action: FirewallAction;
    to?: string;
    ports?: string;
    protocol?: string;
    comment?: string;
  }>;
  comments?: string[];
}

export interface DeviceProfile {
  name: string;
  bandwidth?: string;
  dns?: string;
  firewall?: string;
  /** The DHCP range reserved for this device. */
  pool?: unknown;
  fixed_address?: string;
  expect_strong_identity?: boolean;
  tags?: string[];
  comments?: string[];
}

export interface Binding {
  kind: PolicyKind;
  subject: { kind: string; mac?: string; device_id?: string; hostname?: string };
  profile: string;
  schedule?: string;
  comments?: string[];
}

export interface WallClockJSON {
  hour: number;
  minute: number;
}

export interface ScheduleJSON {
  name: string;
  kind: "always" | "never" | "once" | "daily" | "weekly";
  location?: string;
  priority?: number;
  from?: WallClockJSON;
  to?: WallClockJSON;
  days?: string[];
  comments?: string[];
}

export interface PolicyReason {
  binding: Binding;
  selected: boolean;
  explanation: string;
  schedule?: ScheduleJSON;
  schedule_result?: {
    active: boolean;
    reason: string;
    next_change?: string;
  };
}

export interface PolicyResolution {
  subject: { kind: string; mac?: string; device_id?: string; hostname?: string };
  at: string;
  device?: DeviceProfile;
  bandwidth?: BandwidthProfile;
  dns?: DNSProfile;
  firewall?: FirewallProfile;
  reasons?: PolicyReason[];
  unresolved?: string[];
}

export interface PolicyListResponse {
  config: string;
  policies: {
    bandwidth?: Record<string, BandwidthProfile>;
    dns?: Record<string, DNSProfile>;
    firewall?: Record<string, FirewallProfile>;
    devices?: Record<string, DeviceProfile>;
    bindings?: Binding[];
    schedules?: Record<string, ScheduleJSON>;
  };
  counts: Record<string, number>;
}

export interface PolicyResolveResponse {
  config: string;
  resolution: PolicyResolution;
}

// ------------------------------------------------------------------ others

export interface StatusResponse {
  source: string;
  gateway?: string;
  state?: string;
  canApply: boolean;
  wan?: string;
  lan?: string;
  firewall?: string;
  pending?: Record<string, string>;
}

export interface DiagnosticsResponse {
  source: string;
  host?: string;
  supported: boolean;
  interfaces?: number;
  addresses?: number;
  routes?: number;
  firewall?: string;
  valid?: boolean;
  canApply: boolean;
}

export interface PlanStep {
  id: string;
  phase: number;
  summary: string;
  reason: string;
  subsystem?: string;
  disruptive: boolean;
}

export interface PlanResponse {
  id: string;
  status?: string;
  steps: PlanStep[];
  blocking?: Array<{ step?: string; severity: string; message: string }>;
}

export interface RenderResponse {
  content: string;
  path?: string;
  valid?: boolean;
}

/** A page that failed, carrying enough to explain itself. */
export interface PageError {
  error: ThnError;
}
