/**
 * Structured SDK failures.
 *
 * Callers should branch on an error class (or on the class attached to a result-
 * oriented `invoke` error outcome), not by matching human-readable messages that
 * may change as the Stellar SDK evolves. Operational SDK errors extend
 * `GuardError`, so a single `instanceof GuardError` check covers transport,
 * signing, policy and simulation failures. Invalid caller input is the deliberate
 * exception: `InvalidInputError` extends `TypeError` so a malformed argument is
 * distinguishable from an operational failure.
 */
import type { InvokeRetryMetadata } from "./retry.ts";

function causeOptions(cause: unknown): ErrorOptions | undefined {
  return cause === undefined ? undefined : { cause };
}

/** Base class for every error deliberately produced by this SDK. */
export class GuardError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = new.target.name;
  }
}

/**
 * Thrown by `assertAllowed` (or an adapter's pre-execution interceptor) when the guard
 * could not reach a decision (e.g. transport failure, simulation error, missing state).
 *
 * Distinct from `GuardBlockedError`: an action that is undetermined was never ruled on
 * by policy, but must fail closed so an agent is not given an unverified green light.
 */
export class GuardUndeterminedError extends GuardError {
  readonly stage: "preflight" | "submission";
  readonly detail: string;

  constructor(
    detailOrMessage: string,
    options: { stage?: "preflight" | "submission"; detail?: string; cause?: unknown } = {},
  ) {
    const message = detailOrMessage.startsWith("stellar-agent-guard could not determine")
      ? detailOrMessage
      : `stellar-agent-guard could not determine this action's status\n${detailOrMessage}`;
    super(message, causeOptions(options.cause));
    this.name = "GuardUndeterminedError";
    this.stage = options.stage ?? "preflight";
    this.detail = options.detail ?? detailOrMessage;
  }
}

/**
 * A caller-supplied value had the wrong shape or type.
 *
 * This is an `InputError` in the platform sense: it is thrown before the SDK
 * does any work with the value, so a caller can distinguish a programmer error
 * from a policy verdict or a transport failure. Extending `TypeError` keeps the
 * conventional `instanceof TypeError` check working for invalid inputs.
 */
export class InvalidInputError extends TypeError {
  /** The input field that failed validation. */
  readonly field: string;
  /** Stable rule identifier for the failed check. */
  readonly rule: string;
  /** Optional human-readable detail with the offending value. */
  readonly detail?: string | undefined;

  constructor(field: string, rule: string, detail?: string) {
    const message = detail
      ? `Invalid input for '${field}': violates rule '${rule}' (${detail})`
      : `Invalid input for '${field}': violates rule '${rule}'`;
    super(message);
    this.name = new.target.name;
    this.field = field;
    this.rule = rule;
    if (detail !== undefined) {
      this.detail = detail;
    }
  }
}

/**
 * A fee ceiling was not a non-negative `bigint` in stroops.
 *
 * Fee ceilings describe a spend policy, not a signed delta: a negative value
 * would make every real quote appear over budget, and routing a `number` or a
 * string through would hide the precision loss the SDK deliberately refuses.
 * Rejected at the configuration boundary (constructor) and again before a
 * per-call override is used, so neither path can silently become a policy.
 */
export class InvalidFeeCeilingError extends InvalidInputError {
  /** The rejected value, kept for callers that report the bad input. */
  readonly value: unknown;

  constructor(field: string, value: unknown) {
    const received =
      typeof value === "bigint"
        ? `${value}n`
        : typeof value === "string"
          ? JSON.stringify(value)
          : String(value);
    super(field, "non_negative_bigint", `expected a non-negative bigint, got ${received}`);
    this.value = value;
  }
}

/** A simulation could not run, or ran without producing a contract verdict. */
export class SimulationError extends GuardError {
  readonly stage: "probe" | "simulate" | "preflight";
  readonly diagnosticEvents: unknown[];

  constructor(
    message: string,
    options: {
      stage: SimulationError["stage"];
      cause?: unknown;
      diagnosticEvents?: readonly unknown[];
    },
  ) {
    super(message, causeOptions(options.cause));
    this.stage = options.stage;
    this.diagnosticEvents = [...(options.diagnosticEvents ?? [])];
  }
}

/**
 * The RPC kept answering HTTP 429 (rate limited) after the bounded retry, so no
 * simulation ran (issue #40).
 *
 * Still fail-closed: it is the `error` of an `undetermined` pre-flight verdict
 * whose `cause` is `"rate_limited"`, never a refusal and never an approval. The
 * remedy is operational, not a policy change: lower `maxConcurrentSimulations`,
 * or raise the RPC's limit (self-hosted RPC).
 */
export class RateLimitedError extends SimulationError {
  /** Machine-readable discriminant; mirrors the verdict's `cause`. */
  readonly kind = "rate_limited" as const;
  /** The server's `Retry-After`, in milliseconds, when it sent one. */
  readonly retryAfterMs: number | null;
  /** Simulation attempts made, including the first. */
  readonly attempts: number;

  constructor(options: {
    stage: SimulationError["stage"];
    retryAfterMs: number | null;
    attempts: number;
    cause?: unknown;
  }) {
    super(
      `the RPC rate-limited the simulation (HTTP 429) on ${options.attempts} attempt(s)` +
        (options.retryAfterMs !== null ? `; Retry-After ${options.retryAfterMs}ms` : ""),
      { stage: options.stage, cause: options.cause },
    );
    this.retryAfterMs = options.retryAfterMs;
    this.attempts = options.attempts;
  }
}

/** A transaction could not be signed for submission. */
export class SigningError extends GuardError {
  /** Account/contract whose authorization could not be produced, when known. */
  readonly address: string | null;

  constructor(message: string, options: { address?: string | null; cause?: unknown } = {}) {
    super(message, causeOptions(options.cause));
    this.address = options.address ?? null;
  }
}

export interface BroadcastFailurePayload {
  resultXdr: string | null;
  resultCode: string | null;
  message: string;
  diagnosticEvents: unknown[];
}

export interface BroadcastFailureParams {
  attempts: number;
  lastFee: bigint;
  failure: BroadcastFailurePayload;
  detail?: string | undefined;
  /** Structured retry metadata; additive, and safe to log. */
  retry?: InvokeRetryMetadata | undefined;
}

/** Submission failed after assembly, or the RPC rejected the send request. */
export class BroadcastError extends GuardError {
  readonly kind = "error" as const;
  /** Present once the RPC has assigned a hash; absent for pre-send failures. */
  readonly transactionHash: string | null;
  readonly attempts?: number | undefined;
  readonly lastFee?: bigint | undefined;
  readonly failure?: BroadcastFailurePayload | undefined;
  readonly detail?: string | undefined;
  /** Structured retry metadata; present when a retry budget was involved. */
  readonly retry?: InvokeRetryMetadata | undefined;

  constructor(
    message: string,
    options?: {
      transactionHash?: string | null;
      cause?: unknown;
      retry?: InvokeRetryMetadata | undefined;
    },
  );
  constructor(params: BroadcastFailureParams);
  constructor(
    messageOrParams: string | BroadcastFailureParams,
    options: {
      transactionHash?: string | null;
      cause?: unknown;
      retry?: InvokeRetryMetadata | undefined;
    } = {},
  ) {
    if (typeof messageOrParams === "string") {
      super(messageOrParams, causeOptions(options.cause));
      this.name = "BroadcastError";
      this.transactionHash = options.transactionHash ?? null;
      this.attempts = undefined;
      this.lastFee = undefined;
      this.failure = undefined;
      this.detail = undefined;
      this.retry = options.retry;
    } else {
      const detail = messageOrParams.detail ?? messageOrParams.failure.message;
      super(
        `stellar-agent-guard broadcast failed: minimum fee not met after ${messageOrParams.attempts} attempt(s) (last fee: ${messageOrParams.lastFee} stroops)\n${detail}`,
      );
      this.name = "BroadcastError";
      this.transactionHash = null;
      this.attempts = messageOrParams.attempts;
      this.lastFee = messageOrParams.lastFee;
      this.failure = messageOrParams.failure;
      this.detail = detail;
      this.retry = messageOrParams.retry;
    }
  }

  get error(): BroadcastError {
    return this;
  }
}

/** A caller's `maxFeeCap` would be exceeded by the transaction `invoke()` is
 * about to broadcast.
 *
 * Raised as a fail-closed `error` outcome **before** `sendTransaction`, never as
 * a guard refusal: the guard approved the call and the network priced it, the
 * caller's own spend ceiling is what stopped it. The breakdown is carried as
 * exact stroop `bigint`s so an operator can see *which* half grew — a resource
 * fee spike versus a fee-bump retry's inclusion fee — without parsing text.
 */
export class FeeCapExceededError extends GuardError {
  /** Stable code for consumers that branch on the failure. */
  readonly code = "fee_cap_exceeded" as const;
  /** The ceiling supplied as `maxFeeCap`. */
  readonly maxFeeCap: bigint;
  /** Simulated resource fee, in stroops. */
  readonly resourceFeeStroops: bigint;
  /** Inclusion fee the attempt would have declared, in stroops. */
  readonly inclusionFeeStroops: bigint;
  /** `resourceFeeStroops + inclusionFeeStroops`, in stroops. */
  readonly totalFeeStroops: bigint;
  /** 0-based pipeline attempt whose price breached the cap. */
  readonly attempt: number;

  constructor(params: {
    maxFeeCap: bigint;
    resourceFeeStroops: bigint;
    inclusionFeeStroops: bigint;
    attempt: number;
  }) {
    const totalFeeStroops = params.resourceFeeStroops + params.inclusionFeeStroops;
    super(
      `fee cap exceeded: total ${totalFeeStroops} stroops ` +
        `(resource ${params.resourceFeeStroops} + inclusion ${params.inclusionFeeStroops}) ` +
        `exceeds maxFeeCap ${params.maxFeeCap} stroops; nothing was broadcast`,
    );
    this.maxFeeCap = params.maxFeeCap;
    this.resourceFeeStroops = params.resourceFeeStroops;
    this.inclusionFeeStroops = params.inclusionFeeStroops;
    this.totalFeeStroops = totalFeeStroops;
    this.attempt = params.attempt;
  }
}

/** A contract response did not match the API shape the SDK understands. */
export class ContractResponseError extends GuardError {
  /** The exact field of the contract response that did not match. */
  readonly field: string;
  /**
   * The pipeline stage that read the field, when the failure has one
   * (`"probe"`, `"simulate"`, `"preflight"`, `"assemble"`).
   *
   * Additive: a malformed value is reported with the same typed error
   * everywhere, and the stage says *where* the bad value was seen — the
   * distinction a caller needs to tell a bad simulation apart from a bad
   * policy payload.
   */
  readonly stage?: string | undefined;

  constructor(message: string, options: { field: string; stage?: string; cause?: unknown }) {
    super(message, causeOptions(options.cause));
    this.field = options.field;
    if (options.stage !== undefined) this.stage = options.stage;
  }
}

/** A policy ScVal did not match the deployed `PolicyConfig` wire shape. */
export class PolicyDecodeError extends GuardError {
  /** Dotted field path at which decoding failed. */
  readonly path: string;

  constructor(message: string, options: { path: string; cause?: unknown }) {
    super(message, causeOptions(options.cause));
    this.path = options.path;
  }
}

/**
/**
 * Stable identifiers for policy *encoding* failures.
 *
 * Deliberately separate from `POLICY_RULE_IDS` (SPEC §8 semantics): these rules
 * describe whether a draft can be represented as the contract's `PolicyConfig`
 * at all, not whether the resulting policy is sensible. A SPEC rule id would be
 * misleading for an integer that simply does not fit the wire type.
 */
export type PolicyEncodingRuleId =
  | "invalid_type"
  | "missing_field"
  | "invalid_address"
  | "invalid_symbol"
  | "integer_out_of_range";

/** One actionable, field-level reason a policy draft cannot be encoded. */
export interface PolicyEncodingFailure {
  /** Dotted path into the policy object, e.g. `protocols[1].fns[0]`. */
  path: string;
  /** Stable rule identifier for the failed encoding check. */
  rule: PolicyEncodingRuleId;
  /** Human-readable detail naming the offending value. */
  message: string;
}

/**
 * A policy draft could not be encoded as contract `ScVal` because one or more
 * fields violate the wire contract.
 *
 * The policy-editor counterpart to `PolicyDecodeError`: both report a dotted
 * `path`, so the same form can highlight a field whether the bad value came
 * from a draft before submission or from a policy read back off-chain. Every
 * failure is collected before the error is thrown, and no partial `ScVal` is
 * ever produced — `failures` is the complete list a form should render, while
 * `path`/`rule`/`field` describe the first one.
 *
 * This is invalid caller input (it is caught before any RPC or encoding work),
 * so it extends `InvalidInputError` and remains an `instanceof TypeError`.
 */
export class PolicyEncodeError extends InvalidInputError {
  /** Dotted path of the first failure; equal to `failures[0]?.path`. */
  readonly path: string;
  /** Every encoding failure found, in policy field order. */
  readonly failures: readonly PolicyEncodingFailure[];

  constructor(failures: readonly PolicyEncodingFailure[]) {
    const [first, ...rest] = failures;
    if (first === undefined) {
      throw new TypeError("PolicyEncodeError requires at least one failure");
    }
    super(
      first.path,
      first.rule,
      rest.length === 0 ? first.message : `${first.message} (and ${rest.length} more failure(s))`,
    );
    this.path = first.path;
    this.failures = Object.freeze(failures.map((failure) => Object.freeze({ ...failure })));
  }
}

/**
 * A policy file could not be read from disk (issue #105).
 *
 * Distinct from `PolicyDecodeError` on purpose: "the file is not there" is an
 * operational problem with a filesystem path, while "the bytes are not a
 * policy" is a content problem. `code` preserves the platform errno
 * (`ENOENT`, `EACCES`, `EISDIR`, ...) so a shell script can branch on the cause
 * without parsing a message.
 */
export class PolicyFileReadError extends GuardError {
  /** The path the caller asked to load. */
  readonly path: string;
  /** The Node errno code, when the runtime reported one. */
  readonly code: string | null;

  constructor(message: string, options: { path: string; code?: string | null; cause?: unknown }) {
    super(message, causeOptions(options.cause));
    this.path = options.path;
    this.code = options.code ?? null;
  }
}

/**
 * A policy file parsed as JSON but failed SPEC §8 policy validation (issue #105).
 *
 * Every failure is carried, not just the first one: a policy file is edited as
 * a whole, so reporting one violation per run would turn a form fix into a
 * guessing game. The validator's structured `path`/`rule`/`message` shape is
 * reused rather than flattened into a string.
 */
export class PolicyValidationError extends GuardError {
  /** The file that failed validation. */
  readonly path: string;
  /** Every policy failure, in the validator's order. */
  readonly failures: ReadonlyArray<import("./policy.ts").PolicyFailure>;

  constructor(
    message: string,
    options: {
      path: string;
      failures: ReadonlyArray<import("./policy.ts").PolicyFailure>;
      cause?: unknown;
    },
  ) {
    super(message, causeOptions(options.cause));
    this.path = options.path;
    this.failures = [...options.failures];
  }
}

/**
 * An adapter's call mapper could not produce a contract call.
 *
 * `toContractCall`/`toContractCalls` is application code: when it throws, or
 * returns something that is not a contract call, the adapter fails closed and
 * reports an `undetermined` halt rather than letting the action through. The
 * original failure is kept as `cause`, and `field` names the mapper to fix.
 */
export class AdapterMappingError extends GuardError {
  /** The mapper option that failed. */
  readonly field: "toContractCall" | "toContractCalls";

  constructor(
    message: string,
    options: { field: "toContractCall" | "toContractCalls"; cause?: unknown },
  ) {
    super(message, causeOptions(options.cause));
    this.field = options.field;
  }
}

/**
 * An adapter was constructed with misconfigured options.
 *
 * This is a programmer error, not a policy refusal: it is thrown at
 * construction time, before the adapter ever sees an agent action, so a code
 * bug in the integration fails fast instead of killing the first tool call of

 * production. The `field` names the offending option and `expected` describes
 * the shape it must have, so the fix is obvious without reading this SDK's
 * source.
 */
export class AdapterConfigError extends GuardError {
  /** Option key that was missing or had the wrong type. */
  readonly field: string;
  /** Human-readable description of the expected shape. */
  readonly expected: string;
  /** Adapter identifier, e.g. `"langchain"` or `"elizaos"`. */
  readonly adapter: string;

  constructor(
    message: string,
    options: { field: string; expected: string; adapter: string; cause?: unknown },
  ) {
    super(message, causeOptions(options.cause));
    this.field = options.field;
    this.expected = options.expected;
    this.adapter = options.adapter;
  }
}
