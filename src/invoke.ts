import { rpc as _rpc } from "@stellar/stellar-sdk";
/**
 * The full invocation pipeline for a guarded account, in the order the Stellar
 * host actually requires:
 *
 *  1. simulate with no authorization  → RPC reports which authorizations the
 *     call needs (and the footprint that call touches);
 *  2. sign each reported authorization — a classic keypair for admin calls, or
 *     an agent-signed `SorobanAuthorizationEntry` for the guard contract;
 *  3. simulate again with the signed entries → this second simulation runs the
 *     *real* `__check_auth` against live ledger state, so a policy violation is
 *     reported here, **before** anything is broadcast;
 *  4. only if step 3 succeeds, assemble the real resources, sign the envelope
 *     and broadcast.
 *
 * Steps 1–3 never mutate the ledger. A blocked action therefore costs nothing,
 * which is the property the pre-flight interceptor is built to expose.
 */
import { Account, Address, Keypair, Operation, rpc, scValToNative, xdr } from "@stellar/stellar-sdk";
import type { Server } from "@stellar/stellar-sdk/lib/rpc/server";
import { feeBreakdown, type FeeBreakdown } from "./cost.ts";
import {
  BroadcastError,
  ContractResponseError,
  GuardError,
  SigningError,
  SimulationError,
} from "./errors.ts";
import { GUARD_AUTH_RESULTS, decodeAuthDecision } from "./events.ts";
import {
  SILENT_LOGGER,
  resolveLogger,
  type GuardLogger,
  type GuardLoggerInput,
} from "./logger.ts";
import type { TraceStepName, TraceStepStatus } from "./trace.ts";
import {
  SIG_EXPIRATION_LEDGERS,
  assembleFromSimulation,
  buildGuardAuthEntry,
  buildInitialEnvelope,
  describeSimulationResources,
  describeSubmissionFailure,
  INCLUSION_FEE,
  isMinimumFeeBroadcastFailure,
  isSequenceNumberFailure,
  isStaleLedgerResourceFailure,
  parseSimulationResourceFee,
  signAccountAuthEntry,
  summarizeDiagnosticEvents,
  submitAndPoll,
  type AdminSigner,
  type AgentSigner,
  type ContractCall,
  type SubmissionResult,
} from "./tx.ts";

/**
 * Shared RPC endpoint configuration consumed by every surface (`invoke`,
 * `check`, `cost`).
 *
 * Exactly one of `server` or `url` must be supplied:
 *
 *  - `server` — a pre-built `rpc.Server` instance, used verbatim. This is the
 *    escape hatch for enterprise/agent deployments that route RPC through a
 *    proxy (auth headers, mTLS, latency shielding) or mock it entirely in
 *    tests: the proxy setup happens *before* constructing the `Server`, and the
 *    SDK never rebuilds one from a URL.
 *  - `url` — a Soroban RPC endpoint the SDK constructs a `Server` from.
 *
 * Supplying both, or neither, is a programming error and is rejected with a
 * typed `GuardError` before any RPC call is made.
 *
 * Note on `stellar-sdk` 17: `rpc.Server`'s constructor accepts
 * `{ allowHttp?, headers?, fetch? }` in addition to the URL, so a custom
 * `fetch` can be injected when constructing the `Server` — but the SDK does
 * not expose a separate `transport` option on `invoke`/`check`/`cost`. To use
 * a custom `fetch`, construct the `Server` yourself and pass it as `server`.
 */
export type RpcEndpointConfig =
  | { server: rpc.Server; url?: undefined }
  | { url: string; server?: undefined };

/**
 * Resolve an {@link RpcEndpointConfig} to the `rpc.Server` the pipeline uses.
 *
 * The injected instance is returned verbatim — never wrapped, never rebuilt
 * from a URL — so a caller's proxy configuration, custom `fetch`, or test
 * double is exactly what every RPC call lands on.
 */
export function resolveServer(config: RpcEndpointConfig): rpc.Server {
  const hasServer = config.server !== undefined;
  const hasUrl = config.url !== undefined;
  if (hasServer && hasUrl) {
    throw new GuardError(
      "RPC endpoint config is ambiguous: supply either `server` or `url`, not both",
      { cause: "config" },
    );
  }
  if (!hasServer && !hasUrl) {
    throw new GuardError(
      "RPC endpoint config is missing: supply either `server` or `url`",
      { cause: "config" },
    );
  }
  if (hasServer) return config.server as rpc.Server;
  return new rpc.Server(config.url as string);
}

/** How the guard's authorization is produced for a call that needs it. */
export interface GuardAuthorization {
  guard: string;
  /**
   * The account's registered agent signer: an `AgentSigner` for any signing
   * setup, or a plain Ed25519 `Keypair` for the single-key default. The
   * multi-key shape (contracts v2) arrives behind the same interface — see
   * `docs/concepts/multi-key-agent-signing.md`.
   */
  agent: AgentSigner | Keypair;
}

/**
 * Default RPC timeout applied when a caller supplies neither `timeoutMs` nor
 * its own `signal`. A hung Soroban RPC (network partition, black-holed
 * connection) would otherwise leave `check()`/`invoke()` pending forever, which
 * turns a fail-closed guardrail into an unbounded hang — not a decision. A
 * bounded default is the safer posture: an agent that cannot reach the network
 * gets a typed `RpcTimeoutError` and can fail closed on its own terms.
 *
 * 30s is generous enough for a slow-but-live RPC (a full enforced simulation
 * against a busy ledger) while still bounding the worst case. Callers that
 * need a different budget pass `timeoutMs` explicitly; callers that need no
 * bound at all pass `timeoutMs: 0` (documented below).
 */
export const DEFAULT_RPC_TIMEOUT_MS = 30_000;

/**
 * Raised when an RPC call is aborted or exceeds its timeout.
 *
 * The underlying HTTP request is *not* cancelled at the transport layer:
 * `stellar-sdk` 17's `Server` methods do not accept an `AbortSignal`, so this
 * SDK races the in-flight promise against the signal/timeout. The request
 * therefore continues server-side until it completes or the connection times
 * out; cancellation here is local-only. That is an honest limitation, not a
 * bug — the caller's decision (fail closed) is what matters, and it is made
 * promptly.
 */
export class RpcTimeoutError extends GuardError {
  readonly kind = "timeout" as const;
  /** Which pipeline stage was in flight when the bound fired. */
  readonly stage: string;
  /** True when the caller's own `AbortSignal` fired; false for a timeout. */
  readonly aborted: boolean;
  /** The budget that fired, in milliseconds; absent when the bound was a signal abort. */
  readonly timeoutMs?: number | undefined;

  constructor(params: { stage: string; aborted: boolean; timeoutMs?: number }) {
    const reason = params.aborted
      ? "aborted by caller signal"
      : `exceeded timeout of ${params.timeoutMs}ms`;
    // The classified cause the pipeline surfaces for an abort or a timeout:
    // callers branch on `cause === "timeout"`. The `stage` and `aborted` fields
    // carry the detail, so nothing is lost to the single coarse cause.
    super(`RPC call during '${params.stage}' ${reason}`, { cause: "timeout" });
    this.stage = params.stage;
    this.aborted = params.aborted;
    if (params.timeoutMs !== undefined) this.timeoutMs = params.timeoutMs;
  }
}

/**
 * Shared plumbing for every RPC call the pipeline makes.
 *
 * One implementation, used by `getAccount`, `getLatestLedger`,
 * `simulateTransaction` (both probe and enforced), and `submitAndPoll` — so
 * abort/timeout semantics cannot drift between stages. The rules:
 *
 *  - An already-aborted signal short-circuits *before* `run()` is invoked, so
 *    no RPC call is made at all (the acceptance criterion: "already-aborted
 *    signal returns without RPC call").
 *  - A mid-flight abort or a fired timeout rejects promptly with
 *    `RpcTimeoutError`, even though the underlying request keeps running.
 *  - `timeoutMs: 0` disables the timeout entirely (opt-out for callers that
 *    manage their own bound); `undefined` uses `DEFAULT_RPC_TIMEOUT_MS`.
 *  - The signal/timeout listeners are always removed, so a long-lived signal
 *    shared across many calls does not accumulate listeners.
 */
export async function withRpcAbort<T>(
  params: {
    stage: string;
    signal?: AbortSignal | undefined;
    timeoutMs?: number | undefined;
  },
  run: () => Promise<T>,
): Promise<T> {
  const { stage, signal } = params;
  const timeoutMs = params.timeoutMs ?? DEFAULT_RPC_TIMEOUT_MS;

  if (signal?.aborted) {
    throw new RpcTimeoutError({ stage, aborted: true });
  }

  if (timeoutMs <= 0 && !signal) return run();

  return new Promise<T>((resolve, reject) => {
    let settled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;

    const cleanup = () => {
      if (timer !== undefined) clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
    };
    const onAbort = () => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(new RpcTimeoutError({ stage, aborted: true }));
    };

    if (signal) signal.addEventListener("abort", onAbort, { once: true });
    if (timeoutMs > 0) {
      timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        cleanup();
        reject(new RpcTimeoutError({ stage, aborted: false, timeoutMs }));
      }, timeoutMs);
    }

    run().then(
      (value) => {
        if (settled) return;
        settled = true;
        cleanup();
        resolve(value);
      },
      (error) => {
        if (settled) return;
        settled = true;
        cleanup();
        reject(error);
      },
    );
  });
}

/**
 * Machine-readable causes attached to non-policy `invoke()` failures.
 *
 * `undetermined` deliberately covers errors for which the guard did not make a
 * decision (a bad input, an RPC/host failure, or an unsupported auth shape).
 * It is the same fail-closed category used by pre-flight decisions; it must not
 * be confused with `blocked`, which means the guard actually refused the call.
 */
export const INVOKE_ERROR_CAUSES = {
  undetermined: "undetermined",
  staleLedgerResourceLimit: "stale_ledger_resource_limit",
  sequenceNumberCollision: "sequence_number_collision",
} as const;

export type InvokeErrorCause =
  (typeof INVOKE_ERROR_CAUSES)[keyof typeof INVOKE_ERROR_CAUSES];

/**
 * Failures that a fresh invocation pipeline can fix: a stale-ledger resource
 * declaration (see `isStaleLedgerResourceFailure`) or a sequence-number
 * collision (see `isSequenceNumberFailure`) in `tx.ts`. Both share the single
 * bounded retry policy in `invoke`.
 */
export type RetryableInvokeFailure =
  | "stale_ledger_resource_limit"
  | "sequence_number_collision"
  | "min_fee";

/** The coarse cause each retryable failure reports once the budget is spent. */
const RETRYABLE_CAUSES = {
  stale_ledger_resource_limit: INVOKE_ERROR_CAUSES.staleLedgerResourceLimit,
  sequence_number_collision: INVOKE_ERROR_CAUSES.sequenceNumberCollision,
  min_fee: INVOKE_ERROR_CAUSES.undetermined,
} as const satisfies Record<RetryableInvokeFailure, InvokeErrorCause>;

/** The error arm returned by one invocation attempt. */
export interface InvokeErrorOutcome {
  kind: "error";
  detail: string;
  /** Machine-readable failure; branch on this with `instanceof`. */
  error: GuardError;
  /** Diagnostic events the host bundled with the failure, if any. */
  diagnosticEvents: unknown[];
  /** Coarse cause; absent for a dry run because no failure was classified. */
  cause?: InvokeErrorCause;
  /** Set when a re-simulation against fresh state can fix the failure. */
  retryable?: RetryableInvokeFailure;
  /** Fee of the transaction when broadcast was attempted. */
  lastFee?: bigint | undefined;
  /** Submission result when broadcast was attempted. */
  submission?: SubmissionResult | undefined;
}

/**
 * Raised/returned when the bounded stale-ledger retry budget is exhausted.
 *
 * `invoke()` returns this object as its `kind: "error"` outcome rather than
 * throwing, preserving the result-oriented API. It is still a real `Error`, so
 * callers can use `instanceof`, retain it for diagnostics, or rethrow it.
 */
export class InvokeRetryError extends Error {
  readonly kind = "error" as const;
  readonly attempts: number;
  override readonly cause: InvokeErrorCause;
  readonly lastCause: InvokeErrorCause;
  readonly detail: string;
  readonly lastOutcome: InvokeErrorOutcome;
  /**
   * The last attempt's typed failure. Present so that narrowing an
   * `InvokeOutcome` to `kind: "error"` always yields an `error` to branch on
   * with `instanceof`, whatever exhausted the retry budget.
   */
  readonly error: GuardError;
  /** Diagnostic events from the last attempt, if any. */
  readonly diagnosticEvents: unknown[];
  /** An exhausted attempt is no longer itself retryable. */
  readonly retryable?: undefined;

  constructor(params: { attempts: number; lastOutcome: InvokeErrorOutcome }) {
    const lastCause =
      params.lastOutcome.retryable === undefined
        ? (params.lastOutcome.cause ?? INVOKE_ERROR_CAUSES.undetermined)
        : RETRYABLE_CAUSES[params.lastOutcome.retryable];
    super(
      `stellar-agent-guard invoke retry budget exhausted after ${params.attempts} attempt(s) ` +
        `(last cause: ${lastCause})\n${params.lastOutcome.detail}`,
    );
    this.name = "InvokeRetryError";
    this.attempts = params.attempts;
    this.cause = lastCause;
    this.lastCause = lastCause;
    this.detail = params.lastOutcome.detail;
    this.lastOutcome = params.lastOutcome;
    this.error = params.lastOutcome.error;
    this.diagnosticEvents = params.lastOutcome.diagnosticEvents;
  }
}

export type InvokeDryRunVerdict = "admissible" | "blocked" | "undetermined";

/**
 * Stage names a dry-run trace reports.
 *
 * The first three come from the shared trace vocabulary so a dry run and an
 * `onStep` trace can never name the same stage differently; `verdict` and
 * `fees` are the two stages a dry run adds, which a real invocation has no
 * equivalent of. `broadcast` is excluded on purpose: a dry run must be
 * structurally incapable of reporting it.
 */
export type InvokeDryRunStepName = Exclude<TraceStepName, "broadcast"> | "verdict" | "fees";

/** One completed stage in a dry run. `ok` describes the stage, not policy approval. */
export interface InvokePipelineStep {
  name: InvokeDryRunStepName;
  durationMs: number;
  ok: boolean;
}

/**
 * Full pre-broadcast result from `invoke({ dryRun: true })`.
 *
 * There is intentionally no submission/hash field: dry-run execution cannot
 * enter assembly or `sendTransaction`, so exposing a transaction hash would be
 * false evidence. `fees` is the network estimate when admissible and an
 * explicit zero breakdown when no admissible execution was priced.
 */
export interface InvokeDryRunResult {
  kind: "dry_run";
  admissible: boolean;
  verdict: InvokeDryRunVerdict;
  reason: string | null;
  detail: string | null;
  /** Typed failure for an undetermined verdict; null for admissible/blocked. */
  error: GuardError | null;
  fees: FeeBreakdown;
  diagnostics: unknown[];
  steps: InvokePipelineStep[];
}

/** Configuration for bounded fee bumping when broadcast fails due to minimum fee. */
export interface FeeBumpConfig {
  /**
   * Maximum total broadcast attempts permitted (initial attempt + retries).
   * Default: 3 attempts.
   */
  maxAttempts?: number | undefined;
  /**
   * Multiplier applied to the inclusion fee on each fee-bump retry.
   * Default: 2 (doubles the inclusion fee per attempt).
   */
  feeMultiplier?: number | undefined;
  /**
   * Initial inclusion fee in stroops to use on the first attempt.
   * Default: 100 stroops (`INCLUSION_FEE`).
   */
  initialInclusionFee?: bigint | undefined;
}

export type PipelineOutcome =
  | { kind: "allowed"; submission: SubmissionResult }
  | {
      kind: "blocked";
      /** Reason symbol from the contract's own event/topic vocabulary. */
      reason: string | null;
      detail: string;
      /** Diagnostic events emitted by the contract during enforced simulation. */
      diagnosticEvents: unknown[];
      /** Present only when policy/account state changed and blocked after inclusion. */
      transactionHash?: string;
      /** True only for a post-broadcast refusal; absent for free preflight blocks. */
      charged?: boolean;
    }
  | InvokeErrorOutcome
  | InvokeRetryError;

export type InvokeOutcome =
  | InvokeDryRunResult
  | PipelineOutcome
  | BroadcastError;

/** Defaults for the bounded stale-ledger retry policy. */
export const DEFAULT_INVOKE_RETRY_OPTIONS = {
  /** Total attempts, including the first attempt. */
  maxAttempts: 3,
  /** Upper bound used for the first full-jitter delay. */
  baseDelayMs: 100,
  /** Upper bound for every later full-jitter delay. */
  maxDelayMs: 2_000,
} as const;

export interface InvokeRetryOptions {
  /** Total attempts, including the first attempt. Default: 3. */
  maxAttempts?: number;
  /** Base full-jitter window in milliseconds. Default: 100. */
  baseDelayMs?: number;
  /** Maximum full-jitter window in milliseconds. Default: 2,000. */
  maxDelayMs?: number;
  /** RNG used for full jitter; it must return a value in [0, 1). */
  random?: () => number;
  /** Alias for `random`, useful when describing the jitter strategy. */
  jitter?: () => number;
  /** Sleep implementation, injectable for deterministic tests/custom clocks. */
  sleep?: (delayMs: number) => Promise<void>;
  /** Compatibility alias for `baseDelayMs`. */
  initialDelayMs?: number;
}

export interface InvokePollOptions {
  /** Number of ledger-status polls after a pending broadcast. */
  pollAttempts?: number;
  /** Delay between ledger-status polls. */
  pollIntervalMs?: number;
}

export interface InvokeParams {
  /** Pre-built RPC server instance; mutually exclusive with `url`. */
  server?: rpc.Server | undefined;
  /** Soroban RPC URL; mutually exclusive with `server`. */
  url?: string | undefined;
  /** Classic account that pays the fee and supplies the sequence number. */
  source: Keypair | AdminSigner;
  call: ContractCall;
  networkPassphrase: string;
  /** Present when the call requires the smart account's own authorization. */
  guardAuth?: GuardAuthorization | null | undefined;
  /** Extra classic-account authorizers available to sign (e.g. an admin). */
  accountSigners?: Array<Keypair | AdminSigner> | undefined;
  /** Skip broadcast even if the enforced simulation passes (dry run). */
  dryRun?: boolean | undefined;
  /** Configure bounded full-jitter retries for stale ledger resource limits. */
  retry?: InvokeRetryOptions | undefined;
  pollAttempts?: number | undefined;
  pollIntervalMs?: number | undefined;
  /** Options controlling polling interval and attempts after submission. */
  pollOptions?: { pollAttempts?: number; pollIntervalMs?: number } | undefined;
  /**
   * Optional configuration for fee-bump retry when broadcast hits min-fee.
   * If omitted, defaults to 3 attempts with a 2x fee multiplier.
   */
  feeBump?: FeeBumpConfig | undefined;
  /**
   * Overall maximum retries across retryable classes. If specified, bounds the
   * total attempts across all triggers.
   */
  maxRetries?: number | undefined;
  /** Custom inclusion fee (used internally during fee-bump retries). */
  fee?: bigint | string | undefined;
  /**
   * Caller-owned cancellation. When aborted, the pipeline stops at the next
   * RPC boundary and `invoke()` returns its `error` outcome carrying an
   * `RpcTimeoutError` (see `RpcTimeoutError` for the local-only cancellation
   * caveat). An already-aborted signal short-circuits before any RPC call.
   */
  signal?: AbortSignal | undefined;
  /**
   * Bound on each individual RPC call, in milliseconds. Defaults to
   * `DEFAULT_RPC_TIMEOUT_MS` (30s); pass `0` to disable the timeout and rely
   * solely on `signal`. A fired timeout produces the same `RpcTimeoutError`
   * outcome as an abort.
   */
  timeoutMs?: number | undefined;
  /**
   * Optional, logger-agnostic observability hook: one `InvokeStepEvent` per
   * pipeline-stage attempt, covering probe → sign → simulate → broadcast,
   * including every attempt of the built-in stale-ledger retry. Omitting it
   * leaves `invoke()` exactly as it was before this hook existed; what a
   * consumer does with the events is entirely the consumer's business.
   */
  onStep?: ((step: InvokeStepEvent) => void) | undefined;
  /**
   * Optional log sink. Omitted — the default — `invoke()` writes nothing
   * anywhere: no console output, no stdout or stderr, no implicit
   * process-level logger.
   *
   * Supplying one reports the same decision points `onStep` exposes (each stage
   * attempt), plus the retry loop's attempts and the terminal outcome, at
   * levels a host can filter: stage attempts and retries at `debug`, a guard
   * refusal at `info`, anything that ended without a verdict at `warn`.
   *
   * A logger never changes behaviour — outcomes, retry counts and timings are
   * identical with and without one — and a logger that throws is isolated, so
   * a broken sink cannot decide whether a transaction runs.
   */
  logger?: GuardLoggerInput | undefined;
}

/**
 * One pipeline-stage attempt, as reported to `onStep`.
 *
 * `name` comes from the shared trace vocabulary (`TraceStepName`), the same
 * names a dry-run trace uses, so the two can never drift apart. `attempt` is
 * the retry index, 0-based, and is always present: `0` for the first (and
 * usually only) pass over the pipeline, `1` for the built-in stale-ledger
 * re-run — so a consumer never has to special-case its absence.
 */
export interface InvokeStepEvent {
  name: TraceStepName;
  status: TraceStepStatus;
  /**
   * Elapsed wall-clock time of *this* stage attempt, in milliseconds. On
   * `start` it is always `0` — nothing has been timed yet.
   */
  durationMs: number;
  /** 0-based retry index: `0` normally, `1` on the stale-ledger re-run. */
  attempt: number;
}

/**
 * Emit one step event to the caller's `onStep` callback.
 *
 * The callback is the caller's, and it is not routed anywhere: a `logger` is a
 * separate sink, so a throwing callback is swallowed and the pipeline carries
 * on: observability must never decide whether a transaction runs. Two cases matter. A callback throw on the happy
 * path must not turn a successful stage into a failed one. And when the stage
 * itself failed, the original error must survive untouched: swallowing here
 * means the callback's error simply vanishes, and `invoke()` rethrows the real
 * pipeline error — never a callback error wearing its clothes.
 */
function emitStep(
  hook: ((step: InvokeStepEvent) => void) | undefined,
  event: InvokeStepEvent,
): void {
  if (!hook) return;
  try {
    hook(event);
  } catch {
    /* a broken consumer must not break the pipeline */
  }
}

/**
 * The stage hook the pipeline actually uses: the caller's `onStep` and, when a
 * logger was injected, a `debug` line for the same event.
 *
 * Returns `undefined` when neither sink is supplied, which is what keeps the
 * default path free of timing work: `withStepTiming` runs the stage directly
 * on `undefined`, adding no timers and emitting nothing. The two sinks are
 * independent — a host may supply either, both, or neither — and a logger is
 * compared against `SILENT_LOGGER` by identity so a caller that passed no
 * logger is not taxed for a sink that writes nothing.
 */
function stepHook(
  hook: ((step: InvokeStepEvent) => void) | undefined,
  logger: GuardLogger,
): ((step: InvokeStepEvent) => void) | undefined {
  const logs = logger !== SILENT_LOGGER;
  if (!hook && !logs) return undefined;
  return (step: InvokeStepEvent): void => {
    emitStep(hook, step);
    if (logs) {
      logger.debug(`pipeline step ${step.name} ${step.status}`, {
        step: step.name,
        status: step.status,
        durationMs: step.durationMs,
        attempt: step.attempt,
      });
    }
  };
}

/**
 * Time one stage attempt, emitting `start` before it runs and `ok` or `fail`
 * with the attempt's own elapsed time after it settles. `ok` means the stage
 * passed; `fail` covers both a thrown error and — via the optional `failed`
 * classifier — a response the pipeline treats as that stage failing (a
 * simulation-error response, a submission that never made it into a ledger).
 * Returns the stage's value and rethrows its error untouched; the `fail`
 * callback throwing only loses the callback's error, never the stage's. With
 * no hook, the stage runs directly — no timers, no events, no work added to
 * the default path.
 */
async function withStepTiming<T>(
  hook: ((step: InvokeStepEvent) => void) | undefined,
  params: { name: TraceStepName; attempt: number },
  run: () => Promise<T>,
  failed?: (value: T) => boolean,
): Promise<T> {
  if (!hook) return run();
  emitStep(hook, { name: params.name, status: "start", durationMs: 0, attempt: params.attempt });
  const startedAt = performance.now();
  try {
    const value = await run();
    emitStep(hook, {
      name: params.name,
      status: failed?.(value) ? "fail" : "ok",
      durationMs: performance.now() - startedAt,
      attempt: params.attempt,
    });
    return value;
  } catch (error) {
    emitStep(hook, {
      name: params.name,
      status: "fail",
      durationMs: performance.now() - startedAt,
      attempt: params.attempt,
    });
    throw error;
  }
}

/**
 * Internal signal that the signing stage refused an authorization shape.
 *
 * Carries the exact detail text the pipeline has always reported plus the
 * typed failure the caller should branch on. `enforceCall` converts it back to
 * an `error` outcome so a shape refusal stays a result, while still giving the
 * `sign` stage a real `fail` event on the way through.
 */
class SigningStageError extends Error {
  readonly detail: string;
  readonly guardError: GuardError;

  constructor(detail: string, guardError: GuardError) {
    super(detail);
    this.name = "SigningStageError";
    this.detail = detail;
    this.guardError = guardError;
  }
}

/** Alias matching the terminology used by the README API reference. */
export type InvokeOptions = InvokeParams;

/**
 * Topic symbols of a contract event, tolerating the several shapes RPC and the
 * SDK use for the same event: decoded `xdr.DiagnosticEvent` instances, bare
 * event objects, or base64 XDR strings in a JSON error payload.
 *
 * Exported because a telemetry consumer needs the same tolerance to read a
 * guard decision out of either stream, and duplicating the shape-handling would
 * mean two places to get it wrong.
 */
export function topicSymbols(raw: unknown): string[] {
  const candidate = raw as {
    event?: { body?: unknown };
    body?: unknown;
  };
  const body = (candidate.event?.body ?? candidate.body) as
    | { v0?: { topics?: unknown[] }; value?: { v0?: { topics?: unknown[] } } }
    | undefined;
  const topics = body?.v0?.topics ?? body?.value?.v0?.topics;
  if (!Array.isArray(topics)) return [];
  return topics.flatMap((topic) => {
    try {
      if (typeof topic === "string") {
        return [String(scValToNative(xdr.ScVal.fromXDR(topic, "base64")))];
      }
      return [String(scValToNative(topic as xdr.ScVal))];
    } catch {
      return [];
    }
  });
}

/**
 * Extract the contract's own block reason from a simulation failure.
 *
 * The RPC error string is not the contract's reason vocabulary, but the
 * diagnostic events bundled with the failure are: the guard publishes
 * `topics = [event_auth_checked, blocked, <reason>]` on every decision,
 * including decisions taken inside an enforced simulation. Note the `event_`
 * prefix — see `events.ts` for why the live topic differs from the docs' name.
 *
 * A *blocked* decision is only ever observed here, as a diagnostic: the guard
 * returns `Err`, which rolls the event back, so it never reaches a ledger.
 */
export function reasonFromDiagnosticEvents(events: unknown[]): string | null {
  for (const event of events) {
    const decision = decodeAuthDecision(topicSymbols(event), "diagnostic");
    if (decision?.result === GUARD_AUTH_RESULTS.blocked && decision.reason) {
      return decision.reason;
    }
  }
  return null;
}

/**
 * Diagnostic events attached to a failed simulation, if the RPC supplied any.
 * Both the top-level `events` field and the nested error payload are checked:
 * which one carries them varies by failure kind.
 */
/**
 * Payload of an address-bound credential, for either arm.
 *
 * The two arms name their payload differently (`address` for legacy, `addressV2`
 * for CAP-71's address-bound form), which mirrors the SDK's own internal
 * `getAddressCredentials` switch.
 */
function addressCredentialsOf(
  credentials: xdr.SorobanCredentials,
): xdr.SorobanAddressCredentials | null {
  if (credentials.type === "sorobanCredentialsAddress") {
    return credentials.address;
  }
  if (credentials.type === "sorobanCredentialsAddressV2") {
    return credentials.addressV2;
  }
  return null;
}

function diagnosticEventsOf(response: unknown): unknown[] {
  const candidate = response as {
    events?: unknown;
    error?: { data?: { events?: unknown } };
  };
  for (const value of [candidate.events, candidate.error?.data?.events]) {
    if (Array.isArray(value)) return value;
  }
  return [];
}

/**
 * The authorization entries a recording-mode probe asked for, read strictly.
 *
 * RPC hands these back as decoded objects, but the same payload can arrive from
 * a proxy, a fixture, or a host that reports a different JSON shape. Every
 * downstream step assumes a well-formed entry, so a malformed one is rejected
 * here with a typed `ContractResponseError` naming the exact field rather than
 * surfacing later as a `TypeError` that says nothing about which response was
 * bad. An absent `auth` is legitimate and means "nothing to sign".
 */
function requiredAuthorizationEntries(
  response: unknown,
): xdr.SorobanAuthorizationEntry[] {
  const result = (response as { result?: unknown }).result;
  if (result !== undefined && (result === null || typeof result !== "object")) {
    throw new ContractResponseError("simulation result is not an object", {
      field: "result",
    });
  }
  const auth = (result as { auth?: unknown } | undefined)?.auth;
  if (auth === undefined) return [];
  if (!Array.isArray(auth)) {
    throw new ContractResponseError("simulation result.auth is not an array", {
      field: "result.auth",
    });
  }
  return auth.map((entry, index) => {
    const credentials = (entry as { credentials?: unknown } | null)?.credentials;
    if (
      entry === null ||
      typeof entry !== "object" ||
      credentials === null ||
      typeof credentials !== "object" ||
      typeof (credentials as { type?: unknown }).type !== "string"
    ) {
      throw new ContractResponseError(
        `simulation result.auth[${index}] has no credential payload`,
        { field: `result.auth[${index}].credentials` },
      );
    }
    return entry as xdr.SorobanAuthorizationEntry;
  });
}

interface ResolvedRetryOptions {
  maxAttempts: number;
  baseDelayMs: number;
  maxDelayMs: number;
  random: () => number;
  sleep: (delayMs: number) => Promise<void>;
}

function defaultSleep(delayMs: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, delayMs));
}

function resolveRetryOptions(options: InvokeRetryOptions | undefined): ResolvedRetryOptions {
  const maxAttempts = options?.maxAttempts ?? DEFAULT_INVOKE_RETRY_OPTIONS.maxAttempts;
  const baseDelayMs =
    options?.baseDelayMs ??
    options?.initialDelayMs ??
    DEFAULT_INVOKE_RETRY_OPTIONS.baseDelayMs;
  const maxDelayMs = options?.maxDelayMs ?? DEFAULT_INVOKE_RETRY_OPTIONS.maxDelayMs;

  if (!Number.isInteger(maxAttempts) || maxAttempts < 1) {
    throw new RangeError(`retry.maxAttempts must be an integer >= 1 (received ${maxAttempts})`);
  }
  if (!Number.isFinite(baseDelayMs) || baseDelayMs < 0) {
    throw new RangeError(`retry.baseDelayMs must be finite and >= 0 (received ${baseDelayMs})`);
  }
  if (!Number.isFinite(maxDelayMs) || maxDelayMs < 0) {
    throw new RangeError(`retry.maxDelayMs must be finite and >= 0 (received ${maxDelayMs})`);
  }

  return {
    maxAttempts,
    baseDelayMs,
    maxDelayMs,
    random: options?.random ?? options?.jitter ?? Math.random,
    sleep: options?.sleep ?? defaultSleep,
  };
}

/**
 * Full-jitter delay for the retry after `attempt` has failed.
 *
 * The exponential value is only the window: multiplying it by an independent
 * random sample spreads agents that observed the same ledger pressure instead
 * of releasing them in a synchronized thundering herd.
 */
function fullJitterDelay(attempt: number, options: ResolvedRetryOptions): number {
  const window = Math.min(
    options.maxDelayMs,
    options.baseDelayMs * 2 ** Math.max(0, attempt - 1),
  );
  const sample = options.random();
  // A custom RNG should return [0, 1), but clamp a bad edge value rather than
  // allowing a production retry policy to be disabled by an out-of-range sample.
  const normalized = Number.isFinite(sample) ? Math.min(Math.max(sample, 0), 1) : 0;
  return Math.floor(window * normalized);
}

/**
 * Run one contract call through simulate → sign → enforce, submitting only on a
 * pass. Returns a discriminated result rather than throwing, so callers can
 * decide whether a block is an expected outcome (agents hitting a guardrail) or
 * a failure worth surfacing.
 *
 * The whole invocation, submission included, is serialized per source account
 * so two concurrent calls can never build from the same account sequence.
 *
 * With `dryRun`, the pipeline stops after the enforced simulation and returns a
 * structured {@link InvokeDryRunResult} instead of an `invoke()` outcome: no
 * transaction is ever assembled, signed for broadcast, or submitted, so there is
 * no hash to report and nothing was charged.
 *
 * Stale-ledger resource failures and sequence-number collisions are retried
 * with bounded full-jitter backoff. Every attempt starts a fresh invocation
 * pipeline, including discovery and enforced simulation, so the resource
 * declaration is always priced against current ledger state. Non-retryable
 * outcomes return immediately and never sleep. When the budget is exhausted,
 * the returned `InvokeRetryError` carries the attempt count and the last retry
 * cause.
 */
type AccountState = {
  queue: Promise<void>;
  lastReservedSequence?: bigint;
};

const accountStates = new WeakMap<object, Map<string, AccountState>>();

function accountStateFor(server: rpc.Server, publicKey: string): AccountState {
  let states = accountStates.get(server);
  if (!states) {
    states = new Map<string, AccountState>();
    accountStates.set(server, states);
  }
  let state = states.get(publicKey);
  if (!state) {
    state = { queue: Promise.resolve() };
    states.set(publicKey, state);
  }
  return state;
}

/**
 * Serialize invoke() for one source account, including its submission.
 *
 * The queue is scoped to the RPC server object as well as the account key: the
 * same account can have an unrelated sequence on a different network/server.
 * A rejected task releases the queue in `finally`, so one failed transaction
 * cannot strand all later calls.
 */
async function withAccountQueue<T>(
  server: rpc.Server,
  publicKey: string,
  task: () => Promise<T>,
): Promise<T> {
  const state = accountStateFor(server, publicKey);
  const previous = state.queue;
  let release!: () => void;
  const current = new Promise<void>((resolve) => {
    release = resolve;
  });
  state.queue = current;
  await previous;
  try {
    return await task();
  } finally {
    release();
    if (state.queue === current) state.queue = Promise.resolve();
  }
}

/**
 * Reserve a sequence number for an account.
 *
 * The RPC snapshot can remain one transaction behind immediately after a
 * successful broadcast (and test doubles commonly do). Remember the last
 * reservation and advance past it when the next fetch is not newer. This also
 * makes the reservation safe when `enforceCall` is used directly, while the
 * invoke queue still guarantees fetch → build → submit ordering.
 */
function reserveNextSequence(
  server: rpc.Server,
  publicKey: string,
  fetchedSequence: string,
): string {
  const state = accountStateFor(server, publicKey);
  const fetched = BigInt(fetchedSequence);
  const next =
    state.lastReservedSequence !== undefined && state.lastReservedSequence >= fetched
      ? state.lastReservedSequence + 1n
      : fetched;
  state.lastReservedSequence = next;
  return next.toString();
}

export function invoke(params: InvokeParams & { dryRun: true }): Promise<InvokeDryRunResult>;
export function invoke(
  params: InvokeParams & { dryRun?: false },
): Promise<Exclude<InvokeOutcome, InvokeDryRunResult>>;
export function invoke(params: InvokeParams): Promise<InvokeOutcome>;
export async function invoke(params: InvokeParams): Promise<InvokeOutcome> {
  const server = resolveServer(params);
  // A dry run performs exactly one pass: it never reaches broadcast, so there
  // is no stale-ledger rejection to retry, no sleep to justify, and nothing to
  // serialize against the account queue.
  if (params.dryRun) return invokeDryRun(params);

  try {
    // Every RPC the pipeline makes sits inside this bound: an already-aborted
    // signal short-circuits before the account is looked up, and a mid-flight
    // abort or a fired timeout rejects promptly with `RpcTimeoutError`.
    return await withRpcAbort(
      { stage: "invoke", signal: params.signal, timeoutMs: params.timeoutMs },
      () => invokeWithQueue({ ...params, server }),
    );
  } catch (error) {
    if (error instanceof RpcTimeoutError) {
      // A bound that fired is a fail-closed *decision*, not a crash: the guard
      // never reached a verdict, which is exactly the `error` arm's meaning.
      return timeoutOutcome(error);
    }
    throw error;
  }
}

async function invokeWithQueue(params: InvokeParams): Promise<InvokeOutcome> {
  const sourceKey = await params.source.publicKey();
  return withAccountQueue(resolveServer(params), sourceKey, async () => {
    const retry = resolveRetryOptions(params.retry);
    const logger = resolveLogger(params.logger);

    const configuredFeeMax =
      params.feeBump?.maxAttempts ??
      (params.maxRetries !== undefined ? params.maxRetries + 1 : 3);
    const maxFeeAttempts = Math.max(1, configuredFeeMax);
    const feeMultiplier = params.feeBump?.feeMultiplier ?? 2;
    let currentInclusionFee = params.feeBump?.initialInclusionFee ?? BigInt(INCLUSION_FEE);

    let feeAttempt = 0;
    let generalAttempt = 0;

    while (true) {
      generalAttempt += 1;
      feeAttempt += 1;
      // `attempt` is the 0-based index `onStep` reports; `attempts` is the count.
      const outcome = await invokePipeline(params, generalAttempt - 1, {
        inclusionFee: currentInclusionFee,
      });

      if (outcome.kind !== "error" || outcome.retryable === undefined) {
        logTerminalOutcome(logger, outcome);
        return outcome;
      }

      if (outcome.retryable === "min_fee") {
        if (feeAttempt < maxFeeAttempts) {
          const bumped = BigInt(Math.ceil(Number(currentInclusionFee) * feeMultiplier));
          currentInclusionFee = bumped > currentInclusionFee ? bumped : currentInclusionFee + 100n;
          continue;
        }

        const broadcastError = new BroadcastError({
          attempts: feeAttempt,
          lastFee: outcome.lastFee ?? currentInclusionFee,
          failure: outcome.submission?.failure ?? {
            resultXdr: null,
            resultCode: "result=txInsufficientFee",
            message: outcome.detail,
            diagnosticEvents: [],
          },
          detail: outcome.detail,
        });
        return broadcastError;
      }

      if (generalAttempt >= retry.maxAttempts) {
        logger.warn(`invoke retry budget exhausted after ${generalAttempt} attempt(s)`, {
          attempts: generalAttempt,
          maxAttempts: retry.maxAttempts,
          retryable: outcome.retryable,
        });
        return new InvokeRetryError({ attempts: generalAttempt, lastOutcome: outcome });
      }

      logger.debug(
        `retrying invoke after a retryable failure (attempt ${generalAttempt} of ${retry.maxAttempts})`,
        { attempt: generalAttempt, maxAttempts: retry.maxAttempts, retryable: outcome.retryable },
      );
      await retry.sleep(fullJitterDelay(generalAttempt, retry));
    }
  });
}

/**
 * Report a terminal pipeline outcome at the level its severity deserves.
 *
 * Terminal means "this is the answer the caller is about to receive". A failure
 * the retry loop is still going to retry is announced by the loop's own retry
 * line instead, so one failure is never reported twice and a retry that
 * eventually succeeds does not leave a warning behind.
 */
function logTerminalOutcome(logger: GuardLogger, outcome: InvokeOutcome): void {
  // Unreachable from `invoke()` — a dry run returns before the retry loop — but
  // the outcome union is shared, and a dry run is not a submission to report.
  if (outcome.kind === "dry_run") return;
  if (outcome.kind === "blocked") {
    logger.info(`guard refused the call (${outcome.reason ?? "unstated"})`, {
      reason: outcome.reason,
      // A post-broadcast refusal was charged; a pre-broadcast one was free, and
      // that distinction is the whole point of the pipeline order.
      charged: outcome.charged === true,
      transactionHash: outcome.transactionHash ?? null,
    });
    return;
  }
  if (outcome.kind === "error") {
    logger.warn(`invoke ended without a verdict: ${outcome.detail}`, {
      cause: outcome.cause ?? null,
    });
    return;
  }
  logger.debug("call admitted and submitted", {
    transactionHash: outcome.submission?.hash ?? null,
  });
}

/**
 * `probe → sign → simulate → verdict → fees`, then stop before assembly.
 *
 * The first three stages are the real pipeline, instrumented through the same
 * `onStep` hook an ordinary invocation uses, so a dry run's trace and a live
 * invocation's trace are the same measurement of the same code. The last two
 * are local to this function: classifying the guard's answer, and pricing it.
 */
async function invokeDryRun(params: InvokeParams): Promise<InvokeDryRunResult> {
  const steps: InvokePipelineStep[] = [];
  const observer = params.onStep;
  const enforced = await enforceCall(
    {
      ...params,
      onStep: (event) => {
        // A dry run can never reach broadcast, so a broadcast stage is a bug
        // rather than a stage to report. Dropping it here keeps that guarantee
        // in the trace itself, not just in the control flow.
        if (event.status !== "start" && event.name !== "broadcast") {
          steps.push({
            name: event.name,
            durationMs: event.durationMs,
            ok: event.status === "ok",
          });
        }
        observer?.(event);
      },
    },
    0,
  );
  const verdictStartedAt = performance.now();

  let verdict: InvokeDryRunVerdict =
    enforced.kind === "admissible" ? "admissible" : enforced.kind === "blocked" ? "blocked" : "undetermined";
  const reason: string | null = enforced.kind === "blocked" ? enforced.reason : null;
  let detail: string | null =
    enforced.kind === "error" || enforced.kind === "blocked" ? enforced.detail : null;
  let error: GuardError | null = enforced.kind === "error" ? enforced.error : null;
  const diagnostics: unknown[] =
    enforced.kind === "blocked" || enforced.kind === "error"
      ? enforced.diagnosticEvents
      : diagnosticEventsOf(enforced.simulation);
  let resourceFee = 0n;
  let feesOk = true;

  if (enforced.kind === "admissible") {
    try {
      resourceFee = parseSimulationResourceFee(enforced.simulation.minResourceFee);
    } catch (cause) {
      // The guard approved, but the network's own price for it is unusable.
      // Reporting `admissible` here would hand the caller a fee figure that
      // never came from the host, so the verdict degrades to undetermined.
      verdict = "undetermined";
      detail = `enforced simulation succeeded but returned an invalid resource fee: ${
        cause instanceof Error ? cause.message : String(cause)
      }`;
      error =
        cause instanceof GuardError
          ? cause
          : new SimulationError("enforced simulation returned an invalid resource fee", {
              stage: "simulate",
              cause,
            });
      feesOk = false;
    }
  }
  const verdictDurationMs = Math.max(0, performance.now() - verdictStartedAt);

  const feesStartedAt = performance.now();
  const fees: FeeBreakdown =
    verdict === "admissible"
      ? feeBreakdown(resourceFee)
      : {
          resourceFeeStroops: 0n,
          inclusionFeeStroops: 0n,
          totalFeeStroops: 0n,
        };
  const feesDurationMs = Math.max(0, performance.now() - feesStartedAt);
  // The pipeline stages above are the three `enforceCall` produced; append the
  // two local ones so all five stages are in one ordered trace.
  steps.push(
    { name: "verdict", durationMs: verdictDurationMs, ok: enforced.kind !== "error" },
    { name: "fees", durationMs: feesDurationMs, ok: feesOk },
  );

  return {
    kind: "dry_run",
    admissible: verdict === "admissible",
    verdict,
    reason,
    detail,
    error,
    fees,
    diagnostics,
    steps,
  };
}

/**
 * The outcome of steps 1–3: the guard has been asked, and answered.
 *
 * `admissible` means the enforced simulation ran the real `__check_auth` against
 * live ledger state and it passed. It is separated from submission so the
 * pre-flight interceptor can ask the same question without broadcasting
 * anything — one implementation of the enforcement question, two callers.
 */
export type EnforcementOutcome =
  | {
      kind: "admissible";
      /** The successful enforced simulation, carrying real resource pricing. */
      simulation: rpc.Api.SimulateTransactionSuccessResponse;
      /** The operation with signed authorizations attached, ready to assemble. */
      operation: xdr.Operation;
      /** Base sequence number for building the submitting envelope. */
      nextSeq: string;
    }
  | {
      kind: "blocked";
      reason: string;
      detail: string;
      diagnosticEvents: unknown[];
    }
  | {
      kind: "error";
      detail: string;
      error: GuardError;
      diagnosticEvents: unknown[];
    };

/** One attempt: simulate → sign → enforce → submit. No retry logic lives here. */
async function invokePipeline(
  params: InvokeParams,
  attempt: number,
  options?: { inclusionFee?: bigint | undefined },
): Promise<PipelineOutcome> {
  const server = resolveServer(params);
  const onStep = stepHook(params.onStep, resolveLogger(params.logger));
  const enforced = await enforceCall(
    {
      ...params,
      ...(options?.inclusionFee !== undefined ? { fee: options.inclusionFee } : {}),
    },
    attempt,
  );
  if (enforced.kind === "error") {
    // The guard never made a decision, so this is `undetermined` and not
    // `blocked`. Classify it here, at the point the failure is produced, so
    // every consumer sees a cause without having to re-derive it.
    return {
      ...enforced,
      cause: INVOKE_ERROR_CAUSES.undetermined,
    };
  }
  if (enforced.kind !== "admissible") return enforced;

  // ── Step 4: assemble real resources, sign the envelope, broadcast ─────
  const sourcePubKey = await params.source.publicKey();
  let assembled: ReturnType<typeof assembleFromSimulation>;
  try {
    assembled = assembleFromSimulation({
      simulation: enforced.simulation,
      // A fresh `Account` per build: `TransactionBuilder` advances the sequence of
      // the instance it is handed, so sharing one across builds silently produces
      // `tx_bad_seq`.
      source: new Account(sourcePubKey, enforced.nextSeq),
      operation: enforced.operation,
      networkPassphrase: params.networkPassphrase,
      guard: params.guardAuth?.guard ?? null,
      ...(options?.inclusionFee !== undefined ? { inclusionFee: options.inclusionFee } : {}),
    });
  } catch (cause) {
    // The enforced simulation passed, so a failure to turn its result into a
    // transaction is a defect in construction — never a guardrail deciding.
    const detail = `transaction assembly failed: ${cause instanceof Error ? cause.message : String(cause)}`;
    return {
      kind: "error",
      detail,
      error: new SimulationError("could not assemble transaction from enforced simulation", {
        stage: "simulate",
        cause,
      }),
      diagnosticEvents: [],
    };
  }

  let submission: SubmissionResult;
  const pollAttempts = params.pollOptions?.pollAttempts ?? params.pollAttempts;
  const pollIntervalMs = params.pollOptions?.pollIntervalMs ?? params.pollIntervalMs;
  const signers: Array<Keypair | AdminSigner> = [
    params.source,
    ...(params.accountSigners ?? []),
  ];

  try {
    submission = await withStepTiming(
      onStep,
      { name: "broadcast", attempt },
      () =>
        submitAndPoll(server, assembled.transaction, signers, {
          pollAttempts,
          pollIntervalMs,
        }),
      (result) => result.failure !== null,
    );
  } catch (error) {
    const typed =
      error instanceof GuardError ? error : new BroadcastError(String(error), { cause: error });
    return {
      kind: "error",
      detail: typed.message,
      error: typed,
      diagnosticEvents: [],
    };
  }
  if (submission.failure) {
    // A post-broadcast rejection is a hard error, not a policy block: the
    // enforced simulation already passed, so anything here is a defect in
    // construction (sequence, fee, footprint) or a contract trap — never a
    // guardrail doing its job.
    const detail = `tx ${submission.hash} ${describeSubmissionFailure(submission.failure)}`;
    const events = submission.failure.diagnosticEvents;
    // One exception, and it is a real one: the guard can refuse *after*
    // inclusion, when policy or account state has already moved. That is
    // still the guard refusing, so it stays a `blocked` outcome — carrying the
    // real hash and `charged`, because the caller did pay for the attempt.
    const reason = reasonFromDiagnosticEvents(events);
    if (reason !== null) {
      return {
        kind: "blocked",
        reason,
        detail,
        diagnosticEvents: events,
        transactionHash: submission.hash,
        charged: true,
      };
    }
    const isMinFee = isMinimumFeeBroadcastFailure(submission.failure);
    const staleLedger = !isMinFee && isStaleLedgerResourceFailure(submission.failure);
    // A sequence collision is only expected when something outside this queue
    // broadcasts for the same account; inside the queue it means the RPC
    // snapshot lagged further than the per-account reservation assumed.
    const sequenceCollision = !isMinFee && !staleLedger && isSequenceNumberFailure(submission.failure);
    return {
      kind: "error",
      detail,
      error: new BroadcastError(detail, { transactionHash: submission.hash }),
      diagnosticEvents: events,
      cause: staleLedger
        ? INVOKE_ERROR_CAUSES.staleLedgerResourceLimit
        : sequenceCollision
          ? INVOKE_ERROR_CAUSES.sequenceNumberCollision
          : INVOKE_ERROR_CAUSES.undetermined,
      ...(staleLedger
        ? { retryable: "stale_ledger_resource_limit" as const }
        : sequenceCollision
          ? { retryable: "sequence_number_collision" as const }
          : isMinFee
            ? { retryable: "min_fee" as const }
            : {}),
      lastFee: BigInt(assembled.transaction.fee),
      submission,
    };
  }
  return { kind: "allowed", submission };
}

/**
 * Steps 1–3 of the pipeline, with no submission: discover what the call needs,
 * sign it, then run the *enforced* simulation that actually exercises the
 * guard's `__check_auth` against live ledger state.
 *
 * Nothing here mutates the ledger, which is what makes a refusal free.
 */
export async function enforceCall(
  params: InvokeParams,
  attempt: number = 0,
): Promise<EnforcementOutcome> {
  const { source, call, networkPassphrase } = params;
  const server = resolveServer(params);
  const logger = resolveLogger(params.logger);
  const onStep = stepHook(params.onStep, logger);

  let operation: xdr.Operation;
  let expiration: number;
  let nextSeq: string;
  let freshAccount: () => Account;
  let first: rpc.Api.SimulateTransactionResponse;

  try {
    operation = Operation.invokeContractFunction({
      contract: call.contract,
      function: call.fn,
      args: call.args,
    });
    // `publicKey()` may be async: an `AdminSigner` is allowed to resolve its
    // identity late (a remote or threshold signer).
    const sourcePubKey = await source.publicKey();
    const sourceAccount = await server.getAccount(sourcePubKey);
    const latest = await server.getLatestLedger();
    expiration = latest.sequence + SIG_EXPIRATION_LEDGERS;
    // `TransactionBuilder` advances the sequence of the `Account` it is handed,
    // so every build in this function gets its own instance built from the same
    // base sequence. Sharing one would silently build the second transaction on
    // sequence N+2 and the network would reject it with `tx_bad_seq`. The
    // per-account reservation also advances past an RPC snapshot that has not
    // yet observed the preceding submission.
    nextSeq = reserveNextSequence(server, sourcePubKey, sourceAccount.sequenceNumber());
    freshAccount = () => new Account(sourcePubKey, nextSeq);

    // ── Step 1: discover required authorizations ──────────────────────────
    const probe = buildInitialEnvelope({
      source: freshAccount(),
      operation,
      networkPassphrase,
      guard: params.guardAuth?.guard ?? null,
      fee: params.fee,
    });
    first = await withStepTiming(
      onStep,
      { name: "probe", attempt },
      () => server.simulateTransaction(probe),
      (response) => rpc.Api.isSimulationError(response),
    );
  } catch (error) {
    // Ledger lookup or transport failure: the guard was never asked, so this is
    // `undetermined` rather than a refusal. The original error is kept as the
    // typed cause — it is the only thing that explains *why* the probe failed.
    return {
      kind: "error",
      detail: `probe failed: ${error instanceof Error ? error.message : String(error)}`,
      error: new SimulationError("authorization probe failed", {
        stage: "probe",
        cause: error,
      }),
      diagnosticEvents: [],
    };
  }

  if (rpc.Api.isSimulationError(first)) {
    // The discovery simulation runs in recording mode, so it can fail for
    // reasons that have nothing to do with policy (a contract trap, a missing
    // trustline). Report it as an error with the host's own diagnostics rather
    // than pretending the guard made a decision.
    const error = first as rpc.Api.SimulateTransactionErrorResponse;
    const events = diagnosticEventsOf(error);
    return {
      kind: "error",
      detail: [
        typeof error.error === "string" ? error.error : JSON.stringify(error.error),
        ...summarizeDiagnosticEvents(events),
      ].join("\n  "),
      error: new SimulationError("authorization probe simulation failed", {
        stage: "probe",
        diagnosticEvents: events,
      }),
      diagnosticEvents: events,
    };
  }
  const success = first as rpc.Api.SimulateTransactionSuccessResponse;

  // ── Step 2: sign every authorization the call requires ────────────────
  // One `sign` stage per attempt, spanning every entry the discovery probe
  // reported: a caller tracing the pipeline cares that signing happened and
  // how long it took, not how the loop over entries is shaped inside. A shape
  // this SDK cannot sign raises the internal `SigningStageError` so the stage
  // reports a real `fail`; `enforceCall` converts it straight back into the
  // error outcome the pipeline has always returned, detail text unchanged.
  const signRequiredAuth = async (): Promise<xdr.SorobanAuthorizationEntry[]> => {
    let requiredAuth: xdr.SorobanAuthorizationEntry[];
    try {
      requiredAuth = requiredAuthorizationEntries(success);
    } catch (cause) {
      const detail = cause instanceof Error ? cause.message : String(cause);
      throw new SigningStageError(
        detail,
        cause instanceof ContractResponseError
          ? cause
          : new SimulationError("could not read required authorization entries", {
              stage: "probe",
              cause,
            }),
      );
    }

    const signedAuth: xdr.SorobanAuthorizationEntry[] = [];
    for (const entry of requiredAuth) {
      const creds = entry.credentials;
      if (creds.type === "sorobanCredentialsSourceAccount") {
        // Nothing to sign: the transaction source's authorization is carried by
        // the envelope signature. The entry itself is NOT droppable, though — an
        // operation whose auth list is empty is treated as a recording-mode
        // request by the RPC (so `__check_auth` never runs and policy is never
        // enforced), and core then rejects the submitted transaction because no
        // authorization was actually provided.
        signedAuth.push(entry);
        continue;
      }
      if (
        creds.type !== "sorobanCredentialsAddress" &&
        creds.type !== "sorobanCredentialsAddressV2"
      ) {
        // ADDRESS_WITH_DELEGATES (CAP-71 delegation) is out of v1 scope; the
        // contract's SPEC records the same boundary.
        const detail = `unsupported credential type in required authorization: ${creds.type}`;
        throw new SigningStageError(detail, new SigningError(detail));
      }
      const addressCredentials = addressCredentialsOf(creds);
      if (!addressCredentials) {
        const detail = `credential kind has no address payload: ${creds.type}`;
        throw new SigningStageError(detail, new SigningError(detail));
      }
      // Works for both account (G…) and contract (C…) authorizers; the guard's
      // address is a contract, which is exactly why the agent key — not the
      // transaction source — has to produce this signature.
      let address: string;
      try {
        address = Address.fromScAddress(addressCredentials.address).toString();
      } catch (cause) {
        const detail = `required authorization has an invalid address payload: ${
          cause instanceof Error ? cause.message : String(cause)
        }`;
        throw new SigningStageError(detail, new SigningError(detail, { cause }));
      }

      if (params.guardAuth && address === params.guardAuth.guard) {
        // The smart account authorizes: sign with the registered agent key over
        // the guard's own preimage (fresh nonce per transaction).
        try {
          signedAuth.push(
            await buildGuardAuthEntry({
              guard: params.guardAuth.guard,
              call,
              signer: params.guardAuth.agent,
              // The transaction's own sequence number doubles as the nonce: unique
              // per transaction and never reused, so the host can never see a
              // replay for this guard address.
              nonce: BigInt(nextSeq),
              signatureExpirationLedger: expiration,
              networkPassphrase,
              // Answer in the same credential kind the host asked for: the signed
              // preimage differs between legacy ADDRESS and ADDRESS_V2, so using
              // the wrong one produces a signature the account cannot verify.
              credentialType: creds.type,
            }),
          );
        } catch (error) {
          const detail = `could not sign guard authorization for ${address}: ${
            error instanceof Error ? error.message : String(error)
          }`;
          throw new SigningStageError(
            detail,
            new SigningError(detail, { address, cause: error }),
          );
        }
        continue;
      }

      let signer: Keypair | AdminSigner | undefined;
      const suppliedPubkeys: string[] = [];
      for (const s of params.accountSigners ?? []) {
        const pubkey = await s.publicKey();
        suppliedPubkeys.push(pubkey);
        if (pubkey === address) {
          signer = s;
        }
      }
      if (!signer) {
        const detail =
          `call requires authorization from ${address}, but no matching key was provided ` +
          `(supplied: ${suppliedPubkeys.join(", ") || "none"})`;
        throw new SigningStageError(detail, new SigningError(detail, { address }));
      }
      try {
        signedAuth.push(
          await signAccountAuthEntry({
            entry,
            signer,
            signatureExpirationLedger: expiration,
            networkPassphrase,
          }),
        );
      } catch (error) {
        const detail = `could not sign authorization for ${address}: ${
          error instanceof Error ? error.message : String(error)
        }`;
        throw new SigningStageError(detail, new SigningError(detail, { address, cause: error }));
      }
    }
    return signedAuth;
  };

  let signedAuth: xdr.SorobanAuthorizationEntry[];
  try {
    signedAuth = await withStepTiming(onStep, { name: "sign", attempt }, signRequiredAuth);
  } catch (error) {
    // A signing-stage shape refusal is a result, not an exception: keep
    // reporting it exactly as the pipeline always has, word for word, with the
    // typed failure attached so a caller never has to match on the text.
    if (error instanceof SigningStageError) {
      return {
        kind: "error",
        detail: error.detail,
        error: error.guardError,
        diagnosticEvents: [],
      };
    }
    throw error;
  }

  // ── Step 3: enforced simulation — this is where policy is applied ─────
  // Building the signed envelope and running the enforced simulation are one
  // timed stage: from a tracer's point of view they are the same question
  // ("did the guard approve?"), and a build failure is a stage failure exactly
  // like a transport failure.
  let signedOperation: xdr.Operation;
  let enforced: rpc.Api.SimulateTransactionResponse;
  try {
    const simulated = await withStepTiming(
      onStep,
      { name: "simulate", attempt },
      async () => {
        const authorized = Operation.invokeContractFunction({
          contract: call.contract,
          function: call.fn,
          args: call.args,
          auth: signedAuth,
        });
        const enforcingTx = buildInitialEnvelope({
          source: freshAccount(),
          operation: authorized,
          networkPassphrase,
          guard: params.guardAuth?.guard ?? null,
          fee: params.fee,
        });
        return { operation: authorized, response: await server.simulateTransaction(enforcingTx) };
      },
      (value) => rpc.Api.isSimulationError(value.response),
    );
    signedOperation = simulated.operation;
    enforced = simulated.response;
  } catch (cause) {
    return {
      kind: "error",
      detail: `enforced simulation could not be prepared or run: ${
        cause instanceof Error ? cause.message : String(cause)
      }`,
      error: new SimulationError("enforced simulation could not be prepared or run", {
        stage: "simulate",
        cause,
      }),
      diagnosticEvents: [],
    };
  }
  // This used to be an env-gated write straight to the host's stdout
  // (`SAG_DEBUG_RESOURCES=1`). The description is the same; it now reaches an
  // injected logger and otherwise goes nowhere, because a library does not get
  // to decide where an application's output goes. The README's logging section
  // shows the one-liner that deliberately restores the old behaviour.
  //
  // Two guards around it. The description is only rendered when a logger is
  // attached, so the default path pays nothing for output nobody will read — and
  // it is isolated, because rendering parses the simulation's XDR and a
  // description that cannot be produced is not a reason to fail a call whose
  // simulation just succeeded.
  if (logger !== SILENT_LOGGER) {
    try {
      logger.debug(describeSimulationResources(enforced, params.guardAuth?.guard ?? null), {
        guard: params.guardAuth?.guard ?? null,
        stage: "simulate",
      });
    } catch {
      logger.debug("enforced simulation succeeded (resource description unavailable)", {
        guard: params.guardAuth?.guard ?? null,
        stage: "simulate",
      });
    }
  }
  if (rpc.Api.isSimulationError(enforced)) {
    // NOTE: a simulation failure here is not automatically a block — see the
    // discriminator below. Returning `error` rather than `blocked` in that case
    // is deliberate: an adapter must be able to tell "the guard refused this"
    // from "we could not determine".
    const error = enforced as rpc.Api.SimulateTransactionErrorResponse;
    const events = diagnosticEventsOf(error);
    const reason = reasonFromDiagnosticEvents(events);
    // A guard decision is identifiable: the contract publishes its own
    // `event_auth_checked/blocked/<reason>` event. Any other simulation failure
    // — a contract trap, an absent trustline, a host misuse — is an error, not
    // a block, and must not be reported as the guard refusing anything.
    if (reason === null) {
      return {
        kind: "error",
        detail: [
          typeof error.error === "string" ? error.error : JSON.stringify(error.error),
          ...summarizeDiagnosticEvents(events),
        ].join("\n  "),
        error: new SimulationError("enforced simulation failed without a guard verdict", {
          stage: "simulate",
          diagnosticEvents: events,
        }),
        diagnosticEvents: events,
      };
    }
    return {
      kind: "blocked",
      reason,
      detail: typeof error.error === "string" ? error.error : JSON.stringify(error.error),
      diagnosticEvents: events,
    };
  }

  return {
    kind: "admissible",
    simulation: enforced as rpc.Api.SimulateTransactionSuccessResponse,
    operation: signedOperation,
    nextSeq,
  };
}

/**
 * Convert a fired cancel/timeout into the pipeline's `error`/`undetermined` arm
 * rather than letting it escape as an exception.
 *
 * The asymmetry with `invoke()` is deliberate and documented in the README:
 * `check()`/`cost()` answer a *verdict* question, so a timeout is reported as
 * `undetermined` carrying the typed `RpcTimeoutError` — the guard made no
 * decision, and the caller's fail-closed policy takes over. `invoke()` drives a
 * *pipeline* that was already committed to broadcasting, so a timeout there
 * surfaces through `invoke()`'s own `error` outcome, which the caller must
 * handle explicitly. Either way the error class is the same one — callers
 * branch on `instanceof RpcTimeoutError`, never on a message.
 *
 * The `RpcTimeoutError` is carried as-is (not re-wrapped) so `instanceof`,
 * `stage` and `aborted` survive the trip to the caller.
 */
export function timeoutOutcome(error: RpcTimeoutError): InvokeErrorOutcome {
  return {
    kind: "error",
    detail: error.message,
    error,
    diagnosticEvents: [],
  };
}
