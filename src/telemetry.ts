/**
 * Telemetry for the guard contract's events.
 *
 * The listener consumes **two** streams (plus an opt-in third, added in #58),
 * and this is the part that is easy to get wrong: a blocked decision never
 * reaches the ledger. The guard returns `Err`, which rolls the event back, so
 * a listener that only tails committed ledger events sees a contract that
 * appears to approve everything. The streams are:
 *
 *   1. **ledger events** — `server.getEvents`, filtered to the guard contract.
 *      Carries allowed decisions, heartbeats, and the admin lifecycle events.
 *   2. **simulation diagnostics** — attached to a failed *enforced simulation*.
 *      Carries blocked decisions, which by construction have no transaction.
 *   3. **failed-transaction diagnostics** (opt-in, `failedTx` option) —
 *      attached to a transaction that *was* broadcast, included in a ledger,
 *      and then failed on-chain. Its events roll back exactly like a blocked
 *      simulation's, but the RPC preserves them on the `getTransaction` /
 *      `getTransactions` response (`diagnosticEventsXdr`, public and typed in
 *      the pinned stellar-sdk 17.0.1 — see docs/event-schema.md for the spike
 *      evidence).
 *
 * The topic vocabulary is the one verified against the live chain in
 * `docs/event-schema.md`, not the one the contracts documentation describes.
 *
 * ## Stable ids (issue #33)
 *
 * Every decoded `GuardEvent` carries a non-null, stable `id`, because the two
 * streams fail identity in opposite ways: a committed event is anchored on a
 * transaction hash, while a blocked one has no ledger anchor at all (it was
 * rolled back before broadcast) and needs a synthetic id derived from its own
 * content. The format and the collision notes are documented in
 * `docs/event-schema.md` and implemented by `guardEventId` below.
 */
import { createHash } from "node:crypto";
import { rpc, scValToNative, StrKey, xdr } from "@stellar/stellar-sdk";
import { GUARD_AUTH_RESULTS, GUARD_EVENT_TOPICS, decodeAuthDecision, normalizeEventData, type GuardAuthDecision } from "./events.ts";
import { topicSymbols } from "./invoke.ts";
import { resolveLogger, type GuardLogger, type GuardLoggerInput } from "./logger.ts";

/** The event name topics this SDK knows how to interpret. */
const KNOWN_TOPICS = new Set<string>(Object.values(GUARD_EVENT_TOPICS));

export type GuardEventKind =
  | "auth_checked"
  | "heartbeat"
  | "initialized"
  | "frozen"
  | "unfrozen"
  | "policy_set"
  | "policy_revoked"
  | "unknown";

const KIND_BY_TOPIC: Record<string, GuardEventKind> = {
  [GUARD_EVENT_TOPICS.authChecked]: "auth_checked",
  [GUARD_EVENT_TOPICS.heartbeat]: "heartbeat",
  [GUARD_EVENT_TOPICS.initialized]: "initialized",
  [GUARD_EVENT_TOPICS.frozen]: "frozen",
  [GUARD_EVENT_TOPICS.unfrozen]: "unfrozen",
  [GUARD_EVENT_TOPICS.policySet]: "policy_set",
  [GUARD_EVENT_TOPICS.policyRevoked]: "policy_revoked",
};

/** Where an event was observed. A blocked decision can only be `diagnostic`. */
export type GuardEventSource = "ledger" | "diagnostic";

/**
 * The stream discriminator on a `GuardEvent` (issue #67).
 *
 * `source` records the observation channel (`ledger` vs `diagnostic`); this
 * field states the same fact in the vocabulary a consumer of the **unified**
 * stream reads, so one `for await (const event of listener.watchAll())` loop can
 * tell a committed event from a pre-broadcast one without knowing the SDK's
 * two-channel model.
 */
export type GuardEventStream = "committed" | "diagnostic" | "failed_tx";

export interface GuardEvent {
  /**
   * Stable identity for this event, non-null on both streams.
   *
   * `ledger:<txHash>:<topic>` for a committed event; `diag:<sha256>` for a
   * diagnostic one, which has no transaction to anchor on. Derived by
   * `guardEventId`; see `docs/event-schema.md` for the format and collisions.
   */
  id: string;
  kind: GuardEventKind;
  /** The event's name topic, e.g. `event_auth_checked`. */
  topic: string;
  source: GuardEventSource;
  /**
   * Which of the listener's two streams produced this event, derived from
   * `source`: `ledger` → `committed`, `diagnostic` → `diagnostic`. Present on
   * every `GuardEvent` the SDK emits, including from `watch()`. Additive
   * (issue #67).
   */
  stream: GuardEventStream;
  /** The contract that emitted it, when the stream identifies one. */
  contractId: string | null;
  /** Ledger sequence, when the event was committed. */
  ledger: number | null;
  ledgerClosedAt: string | null;
  /**
   * When a diagnostic event was observed, ISO-8601. `null` on the committed
   * stream (which carries `ledgerClosedAt` instead) and on diagnostics read
   * straight off `diagnosticsToEvents`; `watchAll()` stamps it at the moment
   * the batch is merged in. Additive (issue #67).
   */
  observedAt: string | null;
  transactionHash: string | null;
  /** Present only for `auth_checked`. */
  decision: GuardAuthDecision | null;
  /** Decoded event data: `{ at }` for a heartbeat, `{ by }` for admin events. */
  data: unknown;
  /**
   * The undecoded source event, present only when the decode was asked for it
   * with `includeRaw: true` (issue #94). Absent — not merely `null` — otherwise,
   * so a runtime that does not want the payload does not retain it.
   *
   * The value is what was available at the decode site, which differs per
   * stream: a **diagnostic** keeps the host-shaped event object the RPC
   * returned (`{ event: { contractId, body: { v0: { topics: ScVal[], data } } }
   * }`), and a **ledger** event keeps the `rpc.Api.EventResponse` object from
   * `getEvents` (`topic: ScVal[]`, `value: ScVal`, `txHash`, …). Neither is a
   * base64 blob — the SDK never re-serialises it, so what a consumer files in a
   * bug report is the object the SDK actually saw.
   *
   * **Memory:** this holds a reference to the source payload (including its
   * `xdr.ScVal`s) for as long as the `GuardEvent` lives, and, when the listener's
   * ring buffer is enabled, for as long as that buffer retains the event. That is
   * why it is opt-in and off by default; turn it on for the debugging session or
   * the bug-report window, not for a long-running fleet.
   */
  raw?: unknown;
}

/**
 * Decode-time options shared by every entry point that produces `GuardEvent`s.
 */
export interface GuardEventDecodeOptions {
  /**
   * Opt-in retention of the undecoded source event on each decoded event's
   * `raw` field (issue #94). Default `false`: the raw payload is discarded as
   * soon as it has been decoded, which is the memory discipline the default
   * path has always had. When `false`, `raw` is absent (undefined) rather than
   * a copy of anything.
   *
   * Intended as a debugging affordance: when a decoded verdict looks wrong, the
   * raw event is what you attach to an SDK bug report. Pair it with
   * `guardEventsFromDiagnostics(events, guard, { includeRaw: true })` for offline
   * analysis of a captured simulation.
   */
  includeRaw?: boolean;
}

function decodeData(value: unknown): unknown {
  if (value === undefined || value === null) return null;
  try {
    return scValToNative(value as xdr.ScVal) as unknown;
  } catch {
    return String(value);
  }
}

/** The stream facts an event's `id` is derived from. */
export interface GuardEventIdentityInput {
  source: GuardEventSource;
  /** Name topics in order, as decoded from the event. */
  topics: readonly string[];
  /** Decoded event data, exactly as it lands in `GuardEvent.data`. */
  data: unknown;
  /** The emitting guard, when the stream identifies one. */
  contractId: string | null;
  /** Ledger sequence, when committed; null on the diagnostic stream. */
  ledger: number | null;
  transactionHash: string | null;
  /**
   * Position of this event within the diagnostic batch it arrived in, or null
   * on the ledger stream. This is the component that keeps two *distinct*
   * blocks within one simulation from colliding.
   */
  simulationIndex: number | null;
}

/**
 * Stable identity for a guard event, usable as a delivery / de-duplication key.
 *
 * One format per stream, because the two fail identity in opposite ways:
 *
 * - `ledger:<txHash>:<topic>` — a committed event is anchored on the
 *   transaction that emitted it, plus its name topic. The topic is part of the
 *   id because a single transaction emits several guard events: a `heartbeat`
 *   call commits both `event_auth_checked` and `event_heartbeat` (see the live
 *   capture in `docs/event-schema.md`), so `ledger:<txHash>` alone is not
 *   unique. If an RPC response ever omits the hash, the ledger sequence
 *   anchors instead — an id is always produced.
 *
 * - `diag:<sha256>` — a blocked decision never reaches a ledger (the guard
 *   returns `Err`, the host rolls the event back), so there is nothing to
 *   anchor on and the id is derived from the event's own content: a SHA-256
 *   over the stream name, the guard address, the event's position within its
 *   diagnostic batch, the decoded topics and the decoded data. Re-parsing the
 *   same simulation therefore yields the same id, while two different blocks in
 *   one simulation get different ids because their positions differ.
 *
 * Collision notes: two *separate* simulations that produce an identical
 * diagnostic event for the same guard share an id. That is deliberate — the
 * content is the same decision — so a consumer needing per-attempt identity
 * should combine `id` with its own attempt counter instead of expecting a
 * unique key per refusal. Within one batch, SHA-256 plus the position makes
 * accidental collisions impossible in practice.
 */
export function guardEventId(event: GuardEventIdentityInput): string {
  if (event.source === "ledger") {
    const anchor =
      event.transactionHash ?? (event.ledger !== null ? String(event.ledger) : "unknown");
    return `ledger:${anchor}:${event.topics[0] ?? ""}`;
  }
  return `diag:${createHash("sha256").update(diagnosticIdMaterial(event)).digest("hex")}`;
}

/**
 * The exact string hashed into a diagnostic id, in a fixed order: stream, guard
 * address, position in batch, topics, data.
 *
 * Parts are length-prefixed rather than merely separated: a topic or a decoded
 * value that itself contains the separator must not be able to shift the field
 * boundaries and alias two different events onto one id. With framing, the
 * rendering is unambiguous for any input.
 */
function diagnosticIdMaterial(event: GuardEventIdentityInput): string {
  const parts = [
    "diagnostic",
    event.contractId ?? "",
    String(event.simulationIndex ?? -1),
    ...event.topics,
    stableStringify(event.data),
  ];
  return parts
    .map((part) => `${Buffer.byteLength(part, "utf8")}:${part}`)
    .join("");
}

/**
 * A canonical rendering of decoded event data for hashing: object keys sorted
 * so key order cannot change an id, `bigint` and byte arrays rendered
 * explicitly (`scValToNative` yields `bigint` for u64, which `JSON.stringify`
 * throws on), and a depth cap so a pathological payload cannot build an
 * unbounded string.
 */
function stableStringify(value: unknown, depth = 0): string {
  if (value === null || value === undefined) return "null";
  if (typeof value === "bigint") return `${value.toString()}n`;
  if (typeof value === "boolean" || typeof value === "number" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (value instanceof Uint8Array) return `bytes:${Buffer.from(value).toString("hex")}`;
  if (depth >= 8) return "depth";
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item, depth + 1)).join(",")}]`;
  }
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, item]) => item !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries
    .map(([key, item]) => `${JSON.stringify(key)}:${stableStringify(item, depth + 1)}`)
    .join(",")}}`;
}

/**
 * The stream facts known at decode time, before the event's `id` is derived
 * from them.
 */
export type GuardEventContext = Omit<
  GuardEvent,
  "kind" | "topic" | "id" | "decision" | "data" | "observedAt"
> & {
  /** Position within the diagnostic batch; null on the ledger stream. */
  simulationIndex: number | null;
  /**
   * Observation time for a diagnostic event; omitted (→ `null`) on the
   * committed stream, which anchors on `ledgerClosedAt` instead.
   */
  observedAt?: string | null;
};

/** Interpret an already-decoded topic list plus data as a `GuardEvent`. */
function interpret(
  topics: string[],
  data: unknown,
  context: GuardEventContext,
): GuardEvent | null {
  const topic = topics[0];
  if (!topic || !KNOWN_TOPICS.has(topic)) return null;
  const { simulationIndex, observedAt, ...streamFacts } = context;
  return {
    kind: KIND_BY_TOPIC[topic] ?? "unknown",
    topic,
    id: guardEventId({
      source: streamFacts.source,
      contractId: streamFacts.contractId,
      ledger: streamFacts.ledger,
      transactionHash: streamFacts.transactionHash,
      topics,
      data,
      simulationIndex,
    }),
    ...streamFacts,
    stream: streamFacts.stream,
    observedAt: observedAt ?? null,
    decision: decodeAuthDecision(topics, context.source),
    data: normalizeEventData(data),
  };
}

/**
 * Canonical converter from raw simulation diagnostic events to GuardEvents.
 *
 * Both `guardEventsFromDiagnostics` and `telemetryFromDecision` delegate to this
 * canonical decode engine to ensure unified field extraction and prevent divergence.
 */
export function diagnosticsToEvents(
  diagnosticEvents: readonly unknown[],
  guard?: string,
  options?: GuardEventDecodeOptions,
): GuardEvent[] {
  const includeRaw = options?.includeRaw === true;
  const out: GuardEvent[] = [];
  for (const [index, raw] of diagnosticEvents.entries()) {
    const bare = (raw as { event?: unknown }).event ?? raw;
    const topics = topicSymbols(bare);
    if (topics.length === 0) continue;
    const decoded = interpret(topics, decodeData(dataOf(bare)), {
      source: "diagnostic",
      stream: "diagnostic",
      contractId: guard ?? null,
      ledger: null,
      ledgerClosedAt: null,
      transactionHash: null,
      // The position within this batch is what keeps two blocked decisions from
      // one simulation apart once both are rolled back and neither has a hash.
      simulationIndex: index,
      // The host-shaped wrapper is the source object here, not `bare`: it is
      // exactly what the RPC returned and what a bug report needs to include.
      ...(includeRaw ? { raw } : {}),
    });
    if (decoded) out.push(decoded);
  }
  return out;
}

/**
 * Normalise the contract events attached to a failed enforced simulation.
 *
 * This accepts raw diagnostic events (e.g. from an RPC simulation failure) and
 * converts them to GuardEvents via canonical `diagnosticsToEvents`.
 *
 * This is the only place a *blocked* decision is observable, and it is reached
 * by passing a `PreFlightDecision`'s or an `invoke()` block's diagnostic events
 * through: no ledger query can return them.
 */
export function guardEventsFromDiagnostics(
  diagnosticEvents: readonly unknown[],
  guard?: string,
  options?: GuardEventDecodeOptions,
): GuardEvent[] {
  return diagnosticsToEvents(diagnosticEvents, guard, options);
}

/**
 * Decode the guard events carried by a failed on-chain transaction.
 *
 * A transaction can pass enforced pre-flight and still fail after inclusion
 * (stale resource pricing, a race the simulation could not see). Its Soroban
 * auth events roll back exactly like a blocked simulation's — but unlike the
 * simulation path, the RPC preserves the diagnostics: `getTransaction` and
 * `getTransactions` attach `diagnosticEventsXdr` to a FAILED response. That is
 * a public, typed field of the pinned stellar-sdk 17.0.1
 * (`Api.GetFailedTransactionResponse` — spike evidence in
 * `docs/event-schema.md`); nothing here reaches into SDK internals.
 *
 * The `auth_checked` decoding is deliberately the *same* one the simulation
 * path uses (this delegates to the canonical `interpret` engine): the contract
 * emits the identical event schema in both contexts. Only the markers differ —
 * the event keeps `source: "diagnostic"` (it rolled back; it is not a
 * committed contract event) and gains `stream: "failed_tx"` plus the failed
 * transaction's hash and ledger. `ledgerClosedAt` stays null: the RPC returns
 * `createdAt` as unix seconds here, not the ISO close time this field carries
 * elsewhere, and re-formatting it is this module's business only once there is
 * a consumer that needs it.
 *
 * Accepts the structural subset of either response type (`GetFailedTransactionResponse`
 * from `getTransaction`, `TransactionInfo` from `getTransactions`), so the
 * listener and direct callers share one decoder.
 */
export function guardEventsFromFailedTransaction(
  tx: Pick<
    rpc.Api.GetFailedTransactionResponse,
    "txHash" | "ledger" | "createdAt" | "diagnosticEventsXdr"
  >,
  guard?: string,
): GuardEvent[] {
  const out: GuardEvent[] = [];
  for (const [index, raw] of (tx.diagnosticEventsXdr ?? []).entries()) {
    const bare = (raw as { event?: unknown }).event ?? raw;
    const topics = topicSymbols(bare);
    if (topics.length === 0) continue;
    const decoded = interpret(topics, decodeData(dataOf(bare)), {
      source: "diagnostic",
      stream: "failed_tx",
      contractId: guard ?? null,
      ledger: tx.ledger,
      ledgerClosedAt: null,
      transactionHash: tx.txHash,
      // Position within this transaction's diagnostic batch, so two identical
      // events in one failed transaction cannot share a content-derived id.
      simulationIndex: index,
    });
    if (decoded) out.push(decoded);
  }
  return out;
}

function dataOf(raw: unknown): unknown {
  const candidate = raw as {
    body?: unknown;
    event?: { body?: unknown };
  };
  const body = (candidate.event?.body ?? candidate.body) as
    | { v0?: { data?: unknown }; value?: { v0?: { data?: unknown } } }
    | undefined;
  return body?.v0?.data ?? body?.value?.v0?.data;
}

/** True only when the diagnostic's emitting contract is this guard. */
function emittedByGuard(raw: unknown, guard: string): boolean {
  const bare = (raw as { event?: unknown }).event ?? raw;
  const contractId = (bare as { contractId?: xdr.ContractId | null }).contractId;
  if (!contractId) return false;
  try {
    return StrKey.encodeContract(contractId.toBytes()) === guard;
  } catch {
    return false;
  }
}

/**
 * Opt-in retention of the most recent events, so a consumer can answer "what
 * did the guard decide just now?" without standing up its own store (issue #68).
 *
 * Off by default: an embedded agent runtime should not pay for a buffer it never
 * reads. Non-durable by construction — the buffer lives in process memory, so a
 * restart empties it. Persistence, if needed, is a cursor store (its own issue),
 * not something this buffer pretends to provide.
 */
export interface GuardEventBufferOptions {
  /** How many of the most recent events to keep. Must be a positive integer. */
  max: number;
}

/**
 * The filter surface of `recent()`, deliberately small.
 *
 * `stream` and `reason` are the useful selectors ("show me blocked decisions",
 * "show me refusals for this reason"); `fromLedger`/`toLedger` narrow to a
 * ledger range. Kept to these four so the accessor stays a snapshot, not a
 * query engine: a consumer that needs more should keep its own store with the
 * full event stream.
 */
export interface RecentEventFilter {
  /** Only events observed on this stream. */
  stream?: GuardEventStream;
  /** Only events whose decoded decision reason equals this code. */
  reason?: string;
  /** Only events at or after this ledger (committed events only). */
  fromLedger?: number;
  /** Only events at or before this ledger (committed events only). */
  toLedger?: number;
}

/** True when an event satisfies every field set in `filter`. */
function matchesRecentFilter(event: GuardEvent, filter: RecentEventFilter): boolean {
  if (filter.stream !== undefined && event.stream !== filter.stream) return false;
  if (filter.reason !== undefined && event.decision?.reason !== filter.reason) return false;
  // A diagnostic event has no ledger; a ledger bound therefore excludes it,
  // rather than silently treating `null` as "inside the range".
  if (filter.fromLedger !== undefined && (event.ledger === null || event.ledger < filter.fromLedger)) {
    return false;
  }
  if (filter.toLedger !== undefined && (event.ledger === null || event.ledger > filter.toLedger)) {
    return false;
  }
  return true;
}

/**
 * A fixed-capacity FIFO ring of the most recent `GuardEvent`s (issue #68).
 *
 * O(1) push with no allocation after construction: the backing array is
 * allocated once at `max` and reused, so a long-running agent does not grow the
 * heap with telemetry it already decided to keep only a window of. Once full,
 * each push overwrites the oldest slot; `recent()` always returns events in
 * observation order (oldest first).
 */
export class GuardEventRingBuffer {
  readonly max: number;
  private readonly slots: GuardEvent[];
  /** Index of the oldest retained event. */
  private start = 0;
  /** Number of live slots, `0..max`. */
  private count = 0;

  constructor(max: number) {
    if (!Number.isInteger(max) || max < 1) {
      throw new RangeError(`buffer.max must be a positive integer, received ${max}`);
    }
    this.max = max;
    this.slots = new Array<GuardEvent>(max);
  }

  /** Append an event, evicting the oldest once `max` is reached. */
  push(event: GuardEvent): void {
    const index = (this.start + this.count) % this.max;
    this.slots[index] = event;
    if (this.count < this.max) {
      this.count += 1;
    } else {
      // Full: the write above landed on the oldest slot, so advance past it.
      this.start = (this.start + 1) % this.max;
    }
  }

  /** True when no events are retained (e.g. nothing observed yet). */
  get size(): number {
    return this.count;
  }

  /**
   * The retained events in observation order, optionally narrowed by `filter`.
   *
   * Returns a copy, so a caller cannot mutate the ring by holding the result.
   */
  recent(filter?: RecentEventFilter): GuardEvent[] {
    const out: GuardEvent[] = [];
    for (let i = 0; i < this.count; i += 1) {
      const event = this.slots[(this.start + i) % this.max]!;
      if (!filter || matchesRecentFilter(event, filter)) out.push(event);
    }
    return out;
  }
}

export interface GuardTelemetryConfig {
  /** Pre-built RPC server. Mutually exclusive with `url`. */
  server?: rpc.Server;
  /** The guard contract to follow. */
  guard: string;
  /** Opt in to scanning failed transaction diagnostics as a third stream. */
  failedTx?: boolean;
  /** RPC URL, only used for error messages. */
  rpcUrl?: string;
  /**
   * RPC URL to construct a `rpc.Server` from when no pre-built `server` is
   * supplied. Mutually exclusive with `server`. Proxy/auth/mTLS setup must
   * happen before constructing the `Server` — pass `server` for that.
   */
  url?: string;
  /**
   * Optional log sink for this listener's diagnostics: a summary of every page
   * received (with how many events were dropped as unrecognised), a coverage
   * gap, and a poll that failed or was aborted.
   *
   * Omitted — the default — the listener says nothing at all.
   */
  logger?: GuardLoggerInput | undefined;
  /**
   * Opt-in sliding-window counters over allowed/blocked decisions (issue #68).
   * Omitted → no counter state is allocated and `stats()` returns `null`.
   */
  counters?: GuardTelemetryCountersOptions;
  /**
   * Clock the counters consult for `windowMs` eviction. Defaults to
   * `Date.now`; injectable so tests need no wall-clock waits.
   */
  clock?: (() => number) | undefined;
  /**
   * Opt-in: retain the most recent events for `recent()` snapshots (issue #68).
   * Omitted → no buffer is allocated and `recent()` always returns `[]`.
   */
  buffer?: GuardEventBufferOptions;
  /**
   * Opt-in: attach the raw `rpc.Api.EventResponse` to every committed event
   * decoded by `poll()`/`watch()`/`watchAll()` (issue #94). Default `false`.
   *
   * Diagnostic events decoded by the caller (`guardEventsFromDiagnostics` /
   * `telemetryFromDecision`) take their own `includeRaw` option, so the two
   * halves of the unified stream are independent: a consumer can retain the raw
   * payload for the committed feed, the diagnostic feed, or both.
   *
   * Memory: see `GuardEvent.raw`.
   */
  includeRaw?: boolean;
  /**
   * Opt-in: a cursor store adapter that persists the watch cursor across
   * listener restarts. Without one, a restart resumes from the head (skipping
   * events emitted while the process was dead) or replays history (if
   * `startLedger` is used).
   */
  cursorStore?: CursorStore;
}

/**
 * Resolve the shared `{ server? | url? }` transport config into a concrete
 * `rpc.Server`, validating mutual exclusion.
 *
 * Exactly one of `server` / `url` must be supplied: both is ambiguous (which
 * wins?), neither leaves the listener with no transport. Both cases throw a
 * typed error so a misconfiguration fails loudly at construction time rather
 * than as an opaque RPC failure on the first poll.
 */
export function resolveTelemetryServer(config: {
  server?: rpc.Server | undefined;
  url?: string | undefined;
}): rpc.Server {
  const hasServer = config.server !== undefined && config.server !== null;
  const hasUrl = config.url !== undefined && config.url !== null && config.url !== "";
  if (hasServer && hasUrl) {
    throw new TypeError(
      "telemetry: specify either `server` or `url`, not both",
    );
  }
  if (!hasServer && !hasUrl) {
    throw new TypeError(
      "telemetry: one of `server` or `url` is required",
    );
  }
  if (hasServer) return config.server as rpc.Server;
  return new rpc.Server(config.url as string);
}

export interface PollResult {
  events: GuardEvent[];
  /** Cursor to resume from, as returned by the RPC. */
  cursor: string;
  latestLedger: number;
  /**
   * Oldest ledger the RPC still retains, from the same response
   * (`Api.RetentionState.oldestLedger`).
   *
   * `null` when the host did not report it. Gap detection is skipped in that
   * case rather than guessed at: a proof needs the boundary.
   */
  oldestLedger: number | null;
}

/**
 * Why event coverage is known to have broken.
 *
 * Only one reason is produced today, and it is deliberately the *provable* one:
 * the RPC's own retention window moved past the listener, so the missing ledgers
 * can no longer be retrieved from it. See `docs/event-schema.md` for the rule.
 */
export type GuardTelemetryGapReason = "history_pruned";

/**
 * A provable gap in event coverage: a ledger range whose events are gone.
 *
 * `fromLedger..toLedger` (inclusive) is unrecoverable from the RPC that reported
 * it. The listener never fabricates events for the range — it announces the hole
 * and keeps streaming real events, because a silent gap in a security monitor is
 * worse than an announced one.
 */
export interface GuardTelemetryGap {
  /** First ledger that can no longer be retrieved (inclusive). */
  fromLedger: number;
  /** Last ledger that can no longer be retrieved (inclusive). */
  toLedger: number;
  reason: GuardTelemetryGapReason;
  /** `oldestLedger` of the response that detected the gap. */
  retainedFromLedger: number;
  /** `latestLedger` of that same response. */
  retainedToLedger: number;
}

/**
 * One page of the failed-transaction scan. Shape-matched to `PollResult` but
 * without `latestLedger`: the scan's only cursor obligation is to round-trip
 * the value the caller handed back, and the two streams' cursors are never
 * exchanged (see `pollFailedTransactions`).
 */
export interface FailedTxPollResult {
  events: GuardEvent[];
  /** Cursor to resume the failed-transaction scan from. */
  cursor: string;
}

/**
 * Cap on failed-transaction hashes tracked for per-process dedup, trimmed
 * oldest-first past the cap (`docs/event-schema.md`, "Deduplication"). A page
 * only ever re-reads one page back after an error, so the cap just has to
 * cover what a retention window can still resurface.
 */
const MAX_TRACKED_FAILED_TX = 1_000;

export type TelemetryJitter = "none" | "full";

export const DEFAULT_JITTER_FRACTION = 0.2;

/**
 * Compute the sleep delay for telemetry polling with optional uniform jitter.
 *
 * When `jitter` is `'full'` (the good-citizen default), delays are uniformly
 * distributed in `[intervalMs * (1 - j), intervalMs]` with `j = 0.2`. This
 * prevents fleet-level thundering herds against public RPCs when multiple agents
 * start at the same time.
 */
export function computePollDelay(
  intervalMs: number,
  jitter: TelemetryJitter = "full",
  rng: () => number = Math.random,
  jitterFraction: number = DEFAULT_JITTER_FRACTION,
): number {
  if (jitter === "none") return intervalMs;
  const j = Math.max(0, Math.min(1, jitterFraction));
  const factor = 1 - j + rng() * j;
  return Math.round(intervalMs * factor);
}

/**
 * The sleep used between polls: waits `ms`, or until `signal` aborts.
 *
 * The signal argument is optional, so a caller can inject a plain
 * `(ms) => Promise<void>` exactly as before; the watch loop cuts that short
 * itself (`raceAbort`) rather than requiring the hook to be abort-aware.
 */
export type PollSleep = (ms: number, signal?: AbortSignal) => Promise<void>;

/**
 * The default poll delay: a `setTimeout` an abort cancels outright.
 *
 * Clearing the timer rather than merely abandoning it is what makes abort
 * usable during teardown: a listener stopped mid-interval must not leave an
 * open handle behind, or a Node process — a test suite most visibly — stays
 * alive until the timer would have fired.
 */
function defaultPollSleep(ms: number, signal?: AbortSignal): Promise<void> {
  if (!signal) return new Promise((resolve) => setTimeout(resolve, ms));
  if (signal.aborted) return Promise.resolve();
  return new Promise((resolve) => {
    const onAbort = () => {
      clearTimeout(timer);
      resolve();
    };
    const timer = setTimeout(() => {
      signal.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    signal.addEventListener("abort", onAbort, { once: true });
  });
}

/**
 * Wait out a poll delay, ending as soon as `signal` aborts.
 *
 * A caller-supplied sleep cannot be cancelled from the outside, so the wait is
 * *raced* against the abort event instead: aborting resolves this promise
 * immediately and whatever the abandoned sleep does later is ignored. A sleep
 * that rejects after the abort is likewise swallowed — a stop request is
 * teardown, not a telemetry failure — while a sleep that rejects without an
 * abort still surfaces to the caller exactly as it did before.
 */
function raceAbort(signal: AbortSignal | undefined, wait: () => Promise<void>): Promise<void> {
  if (!signal) return wait();
  if (signal.aborted) return Promise.resolve();
  return new Promise<void>((resolve, reject) => {
    const onAbort = () => {
      signal.removeEventListener("abort", onAbort);
      resolve();
    };
    signal.addEventListener("abort", onAbort, { once: true });
    wait().then(
      () => {
        signal.removeEventListener("abort", onAbort);
        resolve();
      },
      (error: unknown) => {
        signal.removeEventListener("abort", onAbort);
        if (signal.aborted) resolve();
        else reject(error);
      },
    );
  });
}

export interface GuardTelemetryWatchParams {
  startLedger?: number;
  pollIntervalMs?: number;
  limit?: number;
  /**
   * Stop the stream. Abort is honoured at **loop boundaries**: before the first
   * request, before each poll, and during the delay between polls (the default
   * delay's timer is cleared, so no handle is left open). It is deliberately
   * *not* honoured inside a request that is already in flight — see the
   * cancellation note in the README for why, and for the one-request bound that
   * implies.
   */
  signal?: AbortSignal;
  /**
   * Jitter mode for poll interval delays.
   * - `'full'` (default): uniformly randomizes each delay in `[interval*(1-j), interval]` (j=0.2)
   *   to avoid synchronized polling thundering herds across agent fleets.
   * - `'none'`: exact fixed interval cadence.
   */
  jitter?: TelemetryJitter;
  /** Optional RNG injector for deterministic unit testing (defaults to Math.random). */
  rng?: () => number;
  /**
   * Optional sleep handler, for testing without wall-clock delays.
   *
   * It receives the watch signal as a second argument so it can end early on
   * abort; one that ignores the argument is still cut short by the loop.
   */
  sleep?: PollSleep;
  /**
   * Resume from a previously stored RPC cursor instead of a ledger range.
   * Cursors are opaque, so pair this with `resumeLedger` — the last ledger the
   * stored cursor had already consumed — to make a gap that opened while the
   * listener was offline detectable.
   */
  cursor?: string;
  /**
   * The ledger a supplied `cursor` points at. Without it the resume point cannot
   * be reconstructed from the cursor, so no gap can be proven and none is
   * reported (an announced unknown is not better than a silent guess).
   */
  resumeLedger?: number;
  /**
   * Called when coverage provably broke: the RPC's retention window now starts
   * after the earliest ledger the listener still needed.
   *
   * Fires at most once per discontinuity — never once per poll — and is never
   * called with a fabricated event. A throwing callback is isolated (it cannot
   * break the watch loop), matching `invoke()`'s `onStep` contract.
   */
  onGap?: (gap: GuardTelemetryGap) => void;
  /**
   * Called once when the committed stream ends because of a terminal RPC
   * failure — after the bounded retry envelope is exhausted. Fail-visible
   * telemetry: a silent stream death is an incident blind spot.
   *
   * The callback receives the final error. A callback that throws propagates
   * out of the `for await` loop: the consumer asked for it. When omitted, the
   * stream still retries-then-ends, and the terminal error is retrievable via
   * `lastError` on the listener.
   */
  onStreamError?: (error: unknown) => void;
}

/**
 * Sliding-window counters for allowed/blocked decisions (issue #68).
 *
 * Opt-in via `GuardTelemetryListenerOptions.counters`. When absent, no counter
 * state is allocated at all and `stats()` returns `null` — memory discipline
 * matters for a listener that may run for the lifetime of an agent.
 *
 * Exactly one of `windowEvents` / `windowMs` selects the eviction rule:
 *
 * - `windowEvents` (preferred): the window holds the last N decisions. No
 *   clock is consulted, so the counters are deterministic under test and
 *   unaffected by wall-clock skew.
 * - `windowMs`: time-based eviction, using the injected `clock`. Time-based
 *   windows are a follow-up to the count-based form; the count form is the
 *   one the acceptance criteria exercise.
 */
export interface GuardTelemetryCountersOptions {
  /** Keep the last N decisions. Mutually exclusive with `windowMs`. */
  windowEvents?: number;
  /** Keep decisions observed within the last `windowMs` milliseconds. */
  windowMs?: number;
  /**
   * Clock used for `windowMs` eviction and for `windowStart`. Defaults to
   * `Date.now`. Injected so tests need no wall-clock waits.
   */
  clock?: () => number;
}

/** A snapshot of the sliding-window counters. Never mutated by callers. */
export interface GuardTelemetryStats {
  /** Decisions observed in the window whose verdict was `allowed`. */
  allowed: number;
  /** Decisions observed in the window whose verdict was `blocked`. */
  blocked: number;
  /** Blocked decisions in the window, keyed by reason. */
  byReason: Record<string, number>;
  /** Timestamp (per the injected clock) of the oldest decision in the window. */
  windowStart: number;
}

/** One decision recorded in the window, retained for eviction. */
interface CounterEntry {
  verdict: "allowed" | "blocked";
  reason: string | null;
  at: number;
}

/**
 * Sliding-window counters over guard decisions.
 *
 * Fed one event at a time by the listener; `stats()` returns a fresh snapshot
 * object each call so a caller cannot mutate internal state by holding onto it.
 */
export class GuardDecisionCounters {
  private readonly windowEvents: number | null;
  private readonly windowMs: number | null;
  private readonly clock: () => number;
  private readonly entries: CounterEntry[] = [];
  private allowed = 0;
  private blocked = 0;
  private readonly byReason = new Map<string, number>();

  constructor(options: GuardTelemetryCountersOptions) {
    const { windowEvents, windowMs } = options;
    if (windowEvents !== undefined && windowMs !== undefined) {
      throw new Error("counters: specify windowEvents or windowMs, not both");
    }
    if (windowEvents === undefined && windowMs === undefined) {
      throw new Error("counters: windowEvents or windowMs is required");
    }
    if (windowEvents !== undefined && (!Number.isInteger(windowEvents) || windowEvents <= 0)) {
      throw new Error("counters: windowEvents must be a positive integer");
    }
    if (windowMs !== undefined && (!Number.isFinite(windowMs) || windowMs <= 0)) {
      throw new Error("counters: windowMs must be a positive number");
    }
    this.windowEvents = windowEvents ?? null;
    this.windowMs = windowMs ?? null;
    this.clock = options.clock ?? Date.now;
  }

  /** Record one decision. Non-decision events are ignored by the caller. */
  record(event: GuardEvent): void {
    if (event.kind !== "auth_checked" || event.decision === null) return;
    const verdict = isAllowedDecision(event.decision) ? "allowed" : "blocked";
    const reason = event.decision.reason ?? null;
    const at = this.clock();
    this.entries.push({ verdict, reason, at });
    if (verdict === "allowed") this.allowed += 1;
    else {
      this.blocked += 1;
      if (reason !== null) this.byReason.set(reason, (this.byReason.get(reason) ?? 0) + 1);
    }
    this.evict();
  }

  /** Drop entries that have aged out of the window. */
  private evict(): void {
    if (this.windowEvents !== null) {
      while (this.entries.length > this.windowEvents) {
        this.remove(this.entries.shift()!);
      }
      return;
    }
    const cutoff = this.clock() - (this.windowMs ?? 0);
    while (this.entries.length > 0 && this.entries[0]!.at < cutoff) {
      this.remove(this.entries.shift()!);
    }
  }

  private remove(entry: CounterEntry): void {
    if (entry.verdict === "allowed") {
      this.allowed -= 1;
      return;
    }
    this.blocked -= 1;
    if (entry.reason !== null) {
      const next = (this.byReason.get(entry.reason) ?? 0) - 1;
      if (next <= 0) this.byReason.delete(entry.reason);
      else this.byReason.set(entry.reason, next);
    }
  }

  /** A fresh snapshot; callers may mutate it freely. */
  stats(): GuardTelemetryStats {
    this.evict();
    return {
      allowed: this.allowed,
      blocked: this.blocked,
      byReason: Object.fromEntries(this.byReason),
      windowStart: this.entries.length > 0 ? this.entries[0]!.at : this.clock(),
    };
  }
}

/**
 * A batch of already-decoded diagnostic events, with the time they were
 * observed. This is the second source the unified stream (`watchAll()`) merges
 * with the committed ledger feed — see `docs/event-schema.md`.
 */
export interface GuardDiagnosticBatch {
  /** Decoded guard events, in the order they were observed. */
  events: readonly GuardEvent[];
  /**
   * ISO-8601 time the batch was observed. Defaults to `new Date().toISOString()`
   * when omitted, so a merged diagnostic always carries an `observedAt`.
   */
  observedAt?: string;
}

/**
 * `watchAll()` parameters: the committed-stream options plus the diagnostic
 * source to interleave with them.
 */
export interface GuardTelemetryUnifiedParams extends GuardTelemetryWatchParams {
  /**
   * The diagnostic half of the unified stream: batches of decoded events from
   * `guardEventsFromDiagnostics()` / `telemetryFromDecision()`, in observation
   * order. Absent → `watchAll()` degenerates cleanly to the committed stream.
   */
  diagnostics?: AsyncIterable<GuardDiagnosticBatch> | Iterable<GuardDiagnosticBatch>;
}

/** Committed events sort by ledger ascending; a missing ledger sorts last. */
function compareEventsByLedger(a: GuardEvent, b: GuardEvent): number {
  return (a.ledger ?? Number.MAX_SAFE_INTEGER) - (b.ledger ?? Number.MAX_SAFE_INTEGER);
}

/** Adapt a sync or async iterable to an async iterator, so both arms can be armed. */
function asAsyncIterator<T>(source: AsyncIterable<T> | Iterable<T>): AsyncIterator<T> {
  const asyncSource = source as AsyncIterable<T>;
  if (typeof asyncSource[Symbol.asyncIterator] === "function") {
    return asyncSource[Symbol.asyncIterator]();
  }
  const syncIterator = (source as Iterable<T>)[Symbol.iterator]();
  return {
    next: () => Promise.resolve(syncIterator.next()),
    return: (value?: unknown) =>
      Promise.resolve(
        syncIterator.return ? syncIterator.return(value) : { value: value as T, done: true },
      ),
  };
}

/** One settled arm of the merge: a committed page, a diagnostic batch, or abort. */
type MergePull =
  | { source: "committed"; result: IteratorResult<GuardEvent[]> }
  | { source: "diagnostic"; result: IteratorResult<GuardDiagnosticBatch> }
  | { source: "abort" };

/**
 * Merge the committed and diagnostic streams into one ordered, de-duplicated
 * stream of `GuardEvent`s (issue #67).
 *
 * ## Ordering rule
 *
 * - **Committed events are emitted in ledger order.** Each page is sorted by
 *   `ledger` ascending before it is yielded, and pages arrive in cursor order,
 *   so no committed event overtakes an earlier-ledger one.
 * - **Diagnostic events are emitted when the batch carrying them is observed**,
 *   tagged with `observedAt`. A refusal was rolled back before broadcast, so it
 *   has no ledger to sort on; its position is the point of observation relative
 *   to the committed frontier already drained, not a ledger. That is the rule a
 *   consumer relies on: a decision observed at time T appears after the
 *   committed events drained at or before T.
 *
 * ## De-duplication rule
 *
 * `GuardEvent.id` is the SDK's delivery key, and the merge emits each id **at
 * most once** — first observation wins. A guard decision is single-homed (a
 * blocked decision is rolled back and never committed; an allowed decision has
 * no diagnostic), so the same decision cannot arrive under two ids. The
 * duplicate the merge actually guards against is the *same id* delivered twice
 * — a re-fed diagnostic batch, or an overlapping committed page — which the
 * emitted-id set suppresses.
 */
export async function* mergeGuardEventStreams(
  committedSource: AsyncIterable<GuardEvent[]> | Iterable<GuardEvent[]>,
  diagnosticSource?: AsyncIterable<GuardDiagnosticBatch> | Iterable<GuardDiagnosticBatch>,
  signal?: AbortSignal,
): AsyncGenerator<GuardEvent, void, undefined> {
  const committed = asAsyncIterator(committedSource);
  const diagnostics = diagnosticSource ? asAsyncIterator(diagnosticSource) : null;
  const emitted = new Set<string>();

  let onAbort: (() => void) | null = null;
  const abortArm = signal
    ? new Promise<MergePull>((resolve) => {
        onAbort = () => resolve({ source: "abort" });
        if (signal.aborted) onAbort();
        else signal.addEventListener("abort", onAbort);
      })
    : null;

  let committedPull: Promise<MergePull> | null = committed
    .next()
    .then((result) => ({ source: "committed" as const, result }));
  let diagnosticPull: Promise<MergePull> | null = diagnostics
    ? diagnostics.next().then((result) => ({ source: "diagnostic" as const, result }))
    : null;

  try {
    while (committedPull !== null || diagnosticPull !== null) {
      const pending = [committedPull, diagnosticPull].filter(
        (pull): pull is Promise<MergePull> => pull !== null,
      );
      if (abortArm) pending.push(abortArm);
      const settled = await (pending.length === 1 ? pending[0]! : Promise.race(pending));

      if (settled.source === "abort") return;

      if (settled.source === "committed") {
        committedPull = null;
        if (settled.result.done) continue;
        for (const event of [...settled.result.value].sort(compareEventsByLedger)) {
          if (emitted.has(event.id)) continue;
          emitted.add(event.id);
          yield event;
        }
        committedPull = committed
          .next()
          .then((result) => ({ source: "committed" as const, result }));
      } else {
        diagnosticPull = null;
        if (settled.result.done) continue;
        const observedAt = settled.result.value.observedAt ?? new Date().toISOString();
        for (const event of settled.result.value.events) {
          const tagged: GuardEvent = { ...event, stream: "diagnostic", observedAt };
          if (emitted.has(tagged.id)) continue;
          emitted.add(tagged.id);
          yield tagged;
        }
        diagnosticPull = diagnostics!
          .next()
          .then((result) => ({ source: "diagnostic" as const, result }));
      }
    }
  } finally {
    if (signal && onAbort) signal.removeEventListener("abort", onAbort);
    await committed.return?.();
    if (diagnostics) await diagnostics.return?.();
  }
}

export interface CursorStore {
  save(cursor: string): Promise<void>;
  load(): Promise<string | null>;
}

export class InMemoryCursorStore implements CursorStore {
  private cursor: string | null = null;
  async save(cursor: string): Promise<void> {
    this.cursor = cursor;
  }
  async load(): Promise<string | null> {
    return this.cursor;
  }
}

/**
 * Config for a listener used purely for local state (counters, `recent()`),
 * with no RPC transport. A host that only wants `observe()`/`stats()` does not
 * need a `server` and should not have to fabricate one.
 */
export interface GuardTelemetryLocalConfig {
  /** Opt-in sliding-window counters over allowed/blocked decisions. */
  counters?: GuardTelemetryCountersOptions;
  /** Clock the counters consult for `windowMs` eviction. */
  clock?: (() => number) | undefined;
  /** Optional log sink. */
  logger?: GuardLoggerInput | undefined;
}

export class GuardTelemetryListener {
  private readonly config: GuardTelemetryConfig;
  private readonly logger: GuardLogger;
  /** The resolved RPC server: either the injected instance or one built from `url`. */
  private readonly server: rpc.Server;

  /** The persistence adapter this listener is using (defaults to in-memory). */
  readonly activeCursorStore: CursorStore;

  /**
   * Null unless `config.buffer` is set: with no buffer requested, there is no
   * structure to allocate and every `recent()` call short-circuits (issue #68).
   */
  private readonly buffer: GuardEventRingBuffer | null;

  /**
   * The terminal error that ended the most recent `watch()` stream, or `null`
   * when the stream ended normally (abort or completion). Set when the bounded
   * retry envelope is exhausted; cleared at the start of each `watch()`.
   */
  private lastError: unknown = null;

  /** The terminal error that ended the most recent `watch()` stream, if any. */
  getLastError(): unknown {
    return this.lastError;
  }

  /**
   * Failed-transaction hashes already surfaced, so a re-encountered page (the
   * `getTransactions` cursor is not advanced on a mid-page error) or a retry
   * never emits the same failed_tx event twice.
   *
   * This is process-local checkpoint state, not a substitute for the cursors:
   * across a listener restart the streams resume from their cursors and this
   * set starts empty, so a failed transaction still inside the retention
   * window may be re-surfaced once — the same at-least-once behavior the
   * committed stream has when no cursor was persisted.
   */
  private readonly processedFailedTx = new Set<string>();

  /**
   * Null unless `config.counters` is set: with no counters requested, no
   * sliding-window state is allocated and `stats()` returns `null`.
   */
  private readonly counters: GuardDecisionCounters | null;

  constructor(config: GuardTelemetryConfig | GuardTelemetryLocalConfig = {}) {
    const resolved = config as GuardTelemetryConfig;
    this.config = resolved;
    this.logger = resolveLogger(resolved.logger);
    this.server = resolveTelemetryServer({
      server: resolved.server,
      url: resolved.url,
    });
    this.buffer = resolved.buffer ? new GuardEventRingBuffer(resolved.buffer.max) : null;
    this.activeCursorStore = resolved.cursorStore ?? new InMemoryCursorStore();
    this.counters = resolved.counters
      ? new GuardDecisionCounters({
          ...resolved.counters,
          ...(resolved.clock ? { clock: resolved.clock } : {}),
        })
      : null;
  }

  /**
   * Feed one decoded event through the listener's opt-in state (currently the
   * sliding-window decision counters). Public so a host that decodes events
   * itself — e.g. from its own simulation diagnostics — can include them in
   * `stats()` without standing up a `watchAll()` stream.
   */
  observe(event: GuardEvent): void {
    this.counters?.record(event);
  }

  /**
   * Snapshot of the sliding-window decision counters, or `null` when counters
   * were not opted into. The returned object is a copy: mutating it does not
   * affect the listener.
   */
  stats(): GuardTelemetryStats | null {
    return this.counters ? this.counters.stats() : null;
  }

  /**
   * The most recent events the listener has observed, oldest first, optionally
   * narrowed by `filter` (issue #68). Empty when no `buffer` was configured.
   *
   * Only events this listener decoded are retained: committed events from
   * `poll()`/`watch()`, and diagnostic events merged in by `watchAll()`. A
   * consumer that never calls `watchAll()` sees no diagnostic half — the same
   * two-stream distinction the rest of the telemetry API makes.
   *
   * The buffer is in-process and non-durable; a restart empties it.
   */
  recent(filter?: RecentEventFilter): GuardEvent[] {
    return this.buffer ? this.buffer.recent(filter) : [];
  }

  /** Record decoded events into the opt-in buffer, if one is configured. */
  private record(events: readonly GuardEvent[]): void {
    if (!this.buffer) return;
    for (const event of events) this.buffer.push(event);
  }

  /** Record a hash as processed, trimming the oldest entry past the cap. */
  private rememberFailedTx(hash: string): void {
    this.processedFailedTx.add(hash);
    if (this.processedFailedTx.size > MAX_TRACKED_FAILED_TX) {
      const oldest = this.processedFailedTx.values().next().value;
      if (oldest !== undefined) this.processedFailedTx.delete(oldest);
    }
  }

  /**
   * Decode one failed transaction's diagnostics into GuardEvents.
   *
   * Diagnostics attributed to the guard contract go through the canonical
   * `interpret` engine — the same topic filter and decision decoder every
   * other stream uses — so an unknown topic (host noise, another contract's
   * event) is dropped, never guessed at, and a malformed event that throws
   * while decoding is skipped rather than crashing the poll.
   */
  private decodeFailedTransaction(tx: rpc.Api.TransactionInfo): GuardEvent[] {
    const out: GuardEvent[] = [];
    for (const [index, raw] of (tx.diagnosticEventsXdr ?? []).entries()) {
      try {
        const bare = (raw as { event?: unknown }).event ?? raw;
        const topics = topicSymbols(bare);
        if (topics.length === 0) continue;
        if (!emittedByGuard(raw, this.config.guard)) continue;
        const decoded = interpret(topics, decodeData(dataOf(bare)), {
          source: "diagnostic",
          stream: "failed_tx",
          contractId: this.config.guard,
          ledger: tx.ledger,
          ledgerClosedAt: null,
          transactionHash: tx.txHash,
          // Position within this transaction's diagnostic batch, so two identical
          // events in one failed transaction cannot share a content-derived id.
          simulationIndex: index,
        });
        if (decoded) out.push(decoded);
      } catch {
        // A single malformed diagnostic must not take down the poll; the
        // transaction's other events, and the page, continue.
      }
    }
    return out;
  }

  /**
   * Read one page of failed transactions independently from the event cursor.
   * Without a cursor, start at the current head so existing failures are not
   * replayed retroactively.
   */
  async pollFailedTransactions(
    params: { cursor?: string; startLedger?: number; limit?: number } = {},
  ): Promise<FailedTxPollResult> {
    if (params.cursor === undefined && params.startLedger === undefined) {
      const latest = await this.server.getLatestLedger();
      return { events: [], cursor: String(latest.sequence) };
    }

    const request: rpc.Api.GetTransactionsRequest = params.cursor !== undefined
      ? {
          pagination: {
            cursor: params.cursor,
            ...(params.limit !== undefined ? { limit: params.limit } : {}),
          },
        }
      : {
          startLedger: params.startLedger!,
          ...(params.limit !== undefined ? { pagination: { limit: params.limit } } : {}),
        };

    try {
      const response = await this.server.getTransactions(request);
      const events: GuardEvent[] = [];
      for (const tx of response.transactions) {
        if (tx.status !== rpc.Api.GetTransactionStatus.FAILED) continue;
        if (this.processedFailedTx.has(tx.txHash)) continue;
        this.rememberFailedTx(tx.txHash);
        events.push(...this.decodeFailedTransaction(tx));
      }
      this.record(events);
      return { events, cursor: response.cursor };
    } catch {
      return { events: [], cursor: params.cursor ?? String(params.startLedger) };
    }
  }

  /**
   * One page of committed guard events at or after `startLedger`.
   *
   * Filters server-side by contract id, so the listener only ever sees this
   * guard's own events — the topic vocabulary then narrows further, and an
   * unrecognised topic is dropped rather than guessed at.
   */
  async poll(params: { startLedger?: number; cursor?: string; limit?: number } = {}): Promise<PollResult> {
    const request = (
      params.cursor
        ? { filters: [{ type: "contract" as const, contractIds: [this.config.guard] }], cursor: params.cursor, limit: params.limit }
        : {
            filters: [{ type: "contract" as const, contractIds: [this.config.guard] }],
            startLedger: params.startLedger,
            limit: params.limit,
          }
    ) as rpc.Api.GetEventsRequest;

    if (!params.cursor && params.startLedger === undefined) {
      // Default to the current head: replaying a year of history by accident is
      // a mean surprise, and callers that want history pass `startLedger`.
      const latest = await this.server.getLatestLedger();
      (request as { startLedger: number }).startLedger = latest.sequence;
    }

    const response = await this.server.getEvents(request);
    const events: GuardEvent[] = [];
    // Kept rather than merely skipped: an event this listener cannot interpret
    // is a coverage fact a host may need to see, and counting it is the only
    // way to tell "the guard was quiet" from "the guard spoke in a vocabulary
    // this SDK version does not know".
    let dropped = 0;
    for (const event of response.events) {
      const contractId = event.contractId ? String(event.contractId) : null;
      const decoded = interpret(
        event.topic.map((topic) => String(scValToNative(topic))),
        decodeData(event.value),
        {
          source: "ledger",
          stream: "committed",
          contractId,
          ledger: event.ledger,
          ledgerClosedAt: event.ledgerClosedAt ?? null,
          transactionHash: event.txHash ?? null,
          // Committed events anchor on the transaction hash, not on a position
          // within a page: a page boundary would otherwise change an event's id.
          simulationIndex: null,
          // `includeRaw` is off unless the listener was constructed with it, so
          // the default path keeps discarding the RPC object (issue #94).
          ...(this.config.includeRaw ? { raw: event } : {}),
        },
      );
      if (decoded) events.push(decoded);
      else dropped += 1;
    }
    const oldestLedger = typeof response.oldestLedger === "number" ? response.oldestLedger : null;
    this.logger.debug("telemetry page received", {
      guard: this.config.guard,
      events: events.length,
      dropped,
      latestLedger: response.latestLedger,
      oldestLedger,
    });
    this.record(events);
    return {
      events,
      cursor: response.cursor,
      latestLedger: response.latestLedger,
      // Best-effort: a host that omits the retention boundary gets no gap
      // detection, rather than a boundary invented from `latestLedger`.
      oldestLedger,
    };
  }

  /**
   * Follow the guard from `startLedger` (default: one page back) or from a
   * stored `cursor` until aborted. Yields batches so a caller controls
   * backpressure; the cursor is advanced internally so no event is delivered
   * twice.
   *
   * When `onGap` is supplied, the listener also checks each response's retention
   * window and reports a provable hole (see `GuardTelemetryGap`) instead of
   * silently skipping it. Omitting `onGap` changes nothing about the stream.
   *
   * ## Aborting
   *
   * `signal` ending the stream is a normal exit, never a throw: an abort before
   * the first request issues no RPC call at all, an abort between pages prevents
   * the next poll and does not serve out the remaining interval, and an abort
   * that lands while a request is in flight lets that request's rejection go
   * quietly as teardown rather than surfacing as an unhandled rejection. The
   * one bound on promptness is the request already in flight: `getEvents` takes
   * no `AbortSignal` (see the README's cancellation note), so the listener can
   * stop *issuing* requests immediately but cannot cancel one already sent.
   */
  async *watch(
    params: GuardTelemetryWatchParams = {},
  ): AsyncGenerator<GuardEvent[], void, undefined> {
    const interval = params.pollIntervalMs ?? 5_000;
    const jitter = params.jitter ?? "full";
    const rng = params.rng ?? Math.random;
    const signal = params.signal;
    const sleep: PollSleep = params.sleep ?? defaultPollSleep;
    let cursor = params.cursor;
    let startLedger = params.startLedger;
    let failedTxCursor: string | undefined;
    this.lastError = null;

    // An abort that landed before the iterator was first pulled must not probe
    // the RPC — not even the `getLatestLedger` call that resolves the default
    // start ledger. Teardown gets no requests at all, not one.
    if (signal?.aborted) return;

    if (cursor === undefined && startLedger === undefined) {
      cursor = (await this.activeCursorStore.load()) ?? undefined;
    }

    // `expectedFrom` is the earliest ledger the listener has not yet confirmed
    // coverage through: `startLedger` for a fresh range request, or the ledger
    // *after* a resumed cursor. `null` means "cannot be known", in which case gap
    // detection is skipped rather than guessed at.
    let expectedFrom: number | null;
    if (cursor !== undefined) {
      expectedFrom = params.resumeLedger === undefined ? null : params.resumeLedger + 1;
    } else {
      if (startLedger === undefined) {
        const latest = await this.server.getLatestLedger();
        startLedger = Math.max(1, latest.sequence - 1);
      }
      expectedFrom = startLedger;
    }

    while (!signal?.aborted) {
      let page: PollResult;
      let attempts = 0;
      try {
        page = await this.poll({
          ...(startLedger !== undefined ? { startLedger } : {}),
          ...(cursor !== undefined ? { cursor } : {}),
          ...(params.limit !== undefined ? { limit: params.limit } : {}),
        });
      } catch (error) {
        // Abort landed while this request was in flight. The request itself
        // cannot be cancelled — `@stellar/stellar-sdk`'s `getEvents` accepts no
        // signal — so the caller's stop request usually shows up here, as the
        // rejection of the request it arrived during. That is teardown, not a
        // telemetry failure: end the stream quietly instead of throwing at the
        // `for await` consumer or leaving an unhandled rejection behind.
        if (signal?.aborted) {
          this.logger.debug("telemetry watch aborted with a request in flight", {
            guard: this.config.guard,
          });
          return;
        }
        // Bounded retry with backoff, then a fail-visible end: call
        // `onStreamError` once with the terminal error and complete the
        // iterator normally. A callback that throws propagates (the consumer
        // asked for it); without a callback the error is retrievable via
        // `getLastError()`.
        const maxAttempts = 5;
        let terminal: unknown = error;
        let recovered: PollResult | null = null;
        while (attempts < maxAttempts) {
          attempts += 1;
          const backoff = Math.min(interval, 100 * 2 ** (attempts - 1));
          await raceAbort(signal, () => sleep(backoff, signal));
          if (signal?.aborted) return;
          try {
            recovered = await this.poll({
              ...(startLedger !== undefined ? { startLedger } : {}),
              ...(cursor !== undefined ? { cursor } : {}),
              ...(params.limit !== undefined ? { limit: params.limit } : {}),
            });
            break;
          } catch (retryError) {
            if (signal?.aborted) return;
            terminal = retryError;
          }
        }
        if (recovered === null) {
          this.logger.warn(
            `telemetry poll failed: ${terminal instanceof Error ? terminal.message : String(terminal)}`,
            { guard: this.config.guard },
          );
          this.lastError = terminal;
          if (params.onStreamError) params.onStreamError(terminal);
          return;
        }
        page = recovered;
      }
      cursor = page.cursor;
      // Once a cursor is held, the ledger range must not be sent again — the RPC
      // rejects a request that mixes the two modes.
      startLedger = undefined;

      let failedTxEvents: GuardEvent[] = [];
      if (this.config.failedTx) {
        try {
          const failedTxPage = await this.pollFailedTransactions({
            ...(failedTxCursor !== undefined ? { cursor: failedTxCursor } : {}),
            ...(params.limit !== undefined ? { limit: params.limit } : {}),
          });
          failedTxCursor = failedTxPage.cursor;
          failedTxEvents = failedTxPage.events;
        } catch {
          // This optional stream must not interrupt committed event polling.
        }
      }

      // ── Gap detection ────────────────────────────────────────────────────
      // The retention window is reported on every response, so the rule is
      // exact rather than heuristic: coverage is broken precisely when the
      // earliest ledger the listener still needs is older than the oldest ledger
      // the RPC retains. Event *density* plays no part — an empty page inside the
      // window is silence, not loss — so a sparse but fully-retained history
      // cannot raise a false notice. No events are fabricated for the hole.
      if (
        params.onGap &&
        expectedFrom !== null &&
        page.oldestLedger !== null &&
        expectedFrom < page.oldestLedger
      ) {
        const gap: GuardTelemetryGap = {
          fromLedger: expectedFrom,
          toLedger: page.oldestLedger - 1,
          reason: "history_pruned",
          retainedFromLedger: page.oldestLedger,
          retainedToLedger: page.latestLedger,
        };
        // Also reported through the logger, because `onGap` is only wired when a
        // caller supplies it and a pruned range is worth seeing in a log even
        // for a listener that did not ask for a callback.
        this.logger.warn(
          `telemetry coverage gap: ledgers ${gap.fromLedger}-${gap.toLedger} are no longer retained by the RPC`,
          { ...gap, guard: this.config.guard },
        );
        try {
          params.onGap(gap);
        } catch {
          // A consumer's alerting failure must not stop the stream: the notice
          // is advisory, and swallowing it mirrors `onStep`'s isolation.
        }
      }

      const events = [...page.events, ...failedTxEvents];

      await this.activeCursorStore.save(page.cursor);
      
      if (events.length > 0) yield events;

      // Advance confirmed coverage. A page that reached the RPC's head confirms
      // everything up to `latestLedger`; a full page (a partial window, more to
      // come) confirms only through its last event, leaving the boundary check
      // active for the next poll.
      const ledgers = page.events
        .map((event) => event.ledger)
        .filter((ledger): ledger is number => ledger !== null);
      const fullPage = params.limit !== undefined && page.events.length >= params.limit;
      expectedFrom =
        fullPage && ledgers.length > 0
          ? Math.max(...ledgers) + 1
          : page.latestLedger + 1;

      if (signal?.aborted) return;
      const delay = computePollDelay(interval, jitter, rng);
      // Abort-aware: otherwise a caller that aborts mid-interval waits out the
      // whole poll delay (5s by default, jittered) before the iterator ends.
      await raceAbort(signal, () => sleep(delay, signal));
    }
  }

  /**
   * Follow **both** of the listener's streams as one ordered stream of
   * `GuardEvent`s (issue #67).
   *
   * `watch()` tails committed ledger events only, so a consumer that reads just
   * it watches a guard that never blocks — a refusal is rolled back before
   * broadcast and exists only as a simulation diagnostic. `watchAll()` merges
   * the committed stream with the `diagnostics` the caller feeds in, tags every
   * event with `stream` (`committed` | `diagnostic`) and `observedAt`, and
   * de-duplicates by `id`. The ordering and de-duplication rules are documented
   * on `mergeGuardEventStreams()` and in `docs/event-schema.md`.
   *
   * `watch()` is untouched: this is additive, and the default path still yields
   * committed events only. `signal` ends this stream too (it is forwarded to
   * both `watch()` and the merge, so a pending diagnostic source cannot hold it
   * open past teardown).
   */
  async *watchAll(
    params: GuardTelemetryUnifiedParams = {},
  ): AsyncGenerator<GuardEvent, void, undefined> {
    if (params.signal?.aborted) return;
    for await (const event of mergeGuardEventStreams(
      this.watch(params),
      params.diagnostics,
      params.signal,
    )) {
      this.counters?.record(event);
      // Committed events were already recorded when their page was decoded in
      // `poll()`, so only the diagnostic half is recorded here — recording the
      // merged stream wholesale would double every committed event.
      if (event.stream === "diagnostic") this.record([event]);
      yield event;
    }
  }
}

/** Options accepted by `GuardTelemetryListener`. */
export interface GuardTelemetryListenerOptions {
  /**
   * Opt-in sliding-window counters over allowed/blocked decisions. Absent →
   * no counter state is allocated and `stats()` returns `null`.
   */
  counters?: GuardTelemetryCountersOptions;
}

/**
 * Convenience: interpret one `PreFlightDecision`'s diagnostics into events.
 *
 * Accepts a preflight or simulation decision object, and extracts GuardEvents
 * from its `diagnosticEvents` array if the decision outcome was `blocked`.
 * Distinct from `guardEventsFromDiagnostics` which operates on raw diagnostic
 * event arrays directly; both delegate to canonical `diagnosticsToEvents`.
 */
export function telemetryFromDecision(
  decision: { kind: string; diagnosticEvents?: unknown[]; reason?: string },
  guard: string,
  options?: GuardEventDecodeOptions,
): GuardEvent[] {
  if (decision.kind !== "blocked" || !decision.diagnosticEvents) return [];
  return diagnosticsToEvents(decision.diagnosticEvents, guard, options);
}

/** True when a decoded decision means the guard permitted the action. */
export function isAllowedDecision(decision: GuardAuthDecision | null): boolean {
  return decision?.result === GUARD_AUTH_RESULTS.allowed;
}

/**
 * The top-level key order `serializeEvent()` emits, pinned to the `GuardEvent`
 * field reference in `docs/event-schema.md`: the identity fields first, then the
 * stream facts, then the decoded decision and data.
 *
 * This is an explicit, frozen projection rather than an object spread, so adding
 * a field to `GuardEvent` cannot silently change the serialized shape (or its
 * key order) — a new field must be added here deliberately, and its addition is
 * a visible golden-string diff in `tests/unit/serialize-event.test.ts`.
 */
const EVENT_KEY_ORDER = [
  "id",
  "kind",
  "topic",
  "source",
  "stream",
  "contractId",
  "ledger",
  "ledgerClosedAt",
  "observedAt",
  "transactionHash",
  "decision",
  "data",
] as const;

/** The nested key order `serializeEvent()` emits for `decision`. */
const DECISION_KEY_ORDER = ["result", "reason", "source"] as const;

/**
 * Recursively project a decoded value into the JSON-safe shape `serializeEvent()`
 * ships, matching the repo's normalization policy (`normalizeEventData` +
 * `stableStringify`):
 *
 * - `undefined` is **dropped** from objects (the documented empty-field policy)
 *   and rendered as `null` inside arrays, so indices stay stable;
 * - `null` is kept — it is a real value on stream-dependent fields, not absence;
 * - `bigint` becomes a decimal **string** (no `n` suffix), because `JSON.stringify`
 *   throws on a bigint and a logger needs a value `JSON.parse` can read back;
 * - a `Uint8Array`/`Buffer` becomes `bytes:<hex>`, the rendering `stableStringify`
 *   already uses for hashing.
 */
function toJsonSafe(value: unknown): unknown {
  if (value === undefined) return undefined;
  if (value === null) return null;
  if (typeof value === "bigint") return value.toString();
  if (
    typeof value === "boolean" ||
    typeof value === "number" ||
    typeof value === "string"
  ) {
    return value;
  }
  if (value instanceof Uint8Array) return `bytes:${Buffer.from(value).toString("hex")}`;
  if (Array.isArray(value)) {
    return value.map((item) => {
      const normalized = toJsonSafe(item);
      return normalized === undefined ? null : normalized;
    });
  }
  const out: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    const normalized = toJsonSafe(item);
    if (normalized !== undefined) out[key] = normalized;
  }
  return out;
}

/**
 * Canonical one-line JSON for a `GuardEvent`, for deterministic JSON-lines log
 * shipping (issue #130).
 *
 * The output is a stable serialization, not a debugging convenience:
 *
 * - **Key order is fixed** (see `EVENT_KEY_ORDER`), so the same event always
 *   renders byte-for-byte identically and a log line can be diffed.
 * - **`undefined` fields are dropped; `null` is kept.** Absence is expressed by
 *   the key not being present, while `null` remains a real value on the
 *   stream-dependent fields (`ledger`, `transactionHash`, …).
 * - **`bigint` is rendered as a decimal string.** `JSON.stringify` throws on a
 *   bigint, so the decoded `data.at` (a u64 `bigint`) must be converted; decimal
 *   is used over the hashing form `…n` so `JSON.parse` reads a normal string.
 * - **Round-trip:** `JSON.parse(serializeEvent(e))` is shape-equal to `e` modulo
 *   those normalizations (`bigint` → decimal string, `Uint8Array` → `bytes:…`,
 *   `undefined` → absent).
 *
 * The exact contract — order and policies — is documented in
 * `docs/event-schema.md` under "Canonical JSON serialization".
 */
export function serializeEvent(event: GuardEvent): string {
  const projected: Record<string, unknown> = {};
  for (const key of EVENT_KEY_ORDER) {
    const value = event[key];
    if (value === undefined) continue;
    projected[key] = value;
  }
  if (event.decision !== undefined && event.decision !== null) {
    const decision: Record<string, unknown> = {};
    for (const key of DECISION_KEY_ORDER) {
      const value = event.decision[key];
      if (value === undefined) continue;
      decision[key] = value;
    }
    projected.decision = decision;
  }
  return JSON.stringify(toJsonSafe(projected));
}

/** A compact one-line rendering of a guard event, for logs. */
export function describeGuardEvent(event: GuardEvent): string {
  const where =
    event.stream === "committed"
      ? `ledger ${event.ledger ?? "?"}`
      : event.stream === "failed_tx"
        ? `failed tx ${event.transactionHash?.slice(0, 8) ?? "?"}`
        : "pre-broadcast";
  const what =
    event.kind === "auth_checked"
      ? `${event.decision?.result ?? "?"}${event.decision?.reason ? ` (${event.decision.reason})` : ""}`
      : event.kind;
  return `${where}: ${event.topic} → ${what}`;
}