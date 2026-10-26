/**
 * Typed preflight support for the contract's `validate_policy` read
 * (contracts issue #35; SDK issue #254).
 *
 * `set_policy` rejects an invalid configuration with the single stable
 * `invalid_config` error code, which is deliberately all the on-chain
 * rejection surface says. That is enough for a transaction, but useless for an
 * operator staring at a form: it names no field and no rule. The contracts repo
 * added a read-only `validate_policy(config) -> ValidationOutcome` entrypoint
 * (no auth, no writes, no events) that names the **first** failing SPEC §8 rule.
 * This module is the SDK's typed bridge to it:
 *
 *   - `buildValidatePolicyCall()` builds the read call from a candidate
 *     `PolicyConfig`, using the same canonical `policyToScVal` encoder as
 *     `set_policy` itself — there is one encoder, so a preflight cannot disagree
 *     with the transaction it is preflighting.
 *   - `validatePolicyOnChain()` simulates that call through the RPC and decodes
 *     the returned `ValidationOutcome`.
 *   - `decodeValidationOutcome()` decodes the externally tagged enum from either
 *     the host's `ScVal` or the JSON form a CLI prints, so an operator can pass
 *     a captured payload straight in.
 *   - `POLICY_RULE_MESSAGES` translates each of the eleven documented
 *     `PolicyRuleId` variants into the human-readable statement of the rule it
 *     enforces (SPEC §8.1).
 */

/** Wire shape
 *
 * `#[contracttype]` enums use the externally tagged representation: a unit
 * variant is a one-element vector of its name symbol, a tuple variant is the
 * variant name followed by its payload. Through `scValToNative` that is
 * `[\"Valid\"]` / `[\"Invalid\", \"AmountSign\"]`; the JSON a CLI prints is `\"Valid\"`
 * / `{ \"Invalid\": \"AmountSign\" }`. Both forms are accepted — `decode...` never
 * guesses, and a malformed payload is a typed `PolicyDecodeError`.
 */

/** Scope
 *
 * This is off-chain advisory validation. The contract re-validates on
 * `set_policy`, and its rejection code is unchanged; a preflight cannot turn an
 * invalid policy into a valid one.
 */

import { Keypair, Operation, rpc, scValToNative, xdr } from "@stellar/stellar-sdk";
import { ContractResponseError, PolicyDecodeError, SimulationError } from "./errors.ts";
import { DEFAULT_RPC_TIMEOUT_MS, RpcTimeoutError, withRpcAbort } from "./invoke.ts";
import { policyToScVal, type ContractAddress, type ReadonlyPolicyConfig } from "./policy.ts";
import { buildInitialEnvelope, type AdminSigner } from "./tx.ts";

/** The default network passphrase used by the administrative helpers.
 *
 * Kept in sync with `admin.DEFAULT_NETWORK_PASSPHRASE`. Duplicated rather than
 * imported because `admin.ts` imports this module for `submitSetPolicy`'s
 * preflight; importing back would create a runtime cycle for one string.
 */
const DEFAULT_NETWORK_PASSPHRASE = "Test SDF Network ; September 2015";

/** The `PolicyRuleId` variants this SDK ships a message for: the eleven rules
 * documented in SPEC §8.1 when `validate_policy` landed (contracts #35).
 *
 * Order matters only for introspection; a policy is reported with the *first*
 * rule the contract found, not the first rule in this list.
 */
export const CONTRACT_POLICY_RULE_IDS = [
  "AmountSign",
  "WindowRequiresWidth",
  "ActiveWindowOrder",
  "SelfAddressInList",
  "DuplicateAddressInList",
  "DuplicateRecipientCap",
  "RecipientListTooLong",
  "RecipientCapSign",
  "RecipientAllowAndBlocked",
  "ProtocolContractDuplicate",
  "ProtocolFnListInvalid",
] as const;

/** A rule id this SDK documents and can explain. */
export type ContractPolicyRuleId = (typeof CONTRACT_POLICY_RULE_IDS)[number];

/** Human-readable descriptions of the eleven documented rules, mirroring
 * SPEC §8.1.
 *
 * The text states the rule, not merely the symptom: an operator who sees
 * `RecipientAllowAndBlocked` should be able to fix the policy without opening
 * the contract source. Variants added by a newer contract decode fine but fall
 * back to a generic message that names the rule and tells the caller the SDK
 * has not translated it yet — never a fabricated explanation.
 */
export const POLICY_RULE_MESSAGES: Readonly<Record<ContractPolicyRuleId, string>> = Object.freeze({
  AmountSign:
    "per_tx_cap, window_cap, or an asset/per-recipient cap is negative; caps must be non-negative.",
  WindowRequiresWidth:
    "a non-zero window_cap (or a positive per-recipient cap) requires a non-zero window_secs.",
  ActiveWindowOrder:
    "active_until is set but is not greater than active_from; it must be 0 (no expiry) or later than active_from.",
  SelfAddressInList:
    "the guard contract's own address appears in assets, protocols, recipients, blocked_recipients, or recipient_window_caps.",
  DuplicateAddressInList:
    "a duplicate address appears in assets, recipients, or blocked_recipients, or a protocol rule repeats a function name.",
  DuplicateRecipientCap: "the same recipient appears more than once in recipient_window_caps.",
  RecipientListTooLong:
    "recipients, recipient_window_caps, or blocked_recipients exceeds the maximum number of entries (256).",
  RecipientCapSign:
    "a recipient_window_caps cap is negative; per-recipient caps must be non-negative.",
  RecipientAllowAndBlocked:
    "a recipient appears in both recipients and blocked_recipients; a destination cannot be allowed and denied at once.",
  ProtocolContractDuplicate: "the same contract appears in more than one protocol rule.",
  ProtocolFnListInvalid:
    "a protocol rule's fns list is empty or contains duplicate names; use null to allow every function.",
});

/** The decoded `ValidationOutcome`.
 *
 * `rule` is `null` exactly when the policy is valid. `knownRule` is `false` for
 * a rule name this SDK version does not document (a newer contract): the result
 * stays usable — the name is preserved verbatim and `message` explains that it
 * is untranslated — instead of failing the whole preflight.
 */
export interface PolicyValidationResult {
  /** True when every SPEC §8 rule passed (`ValidationOutcome::Valid`). */
  valid: boolean;
  /** The contract's rule name, or `null` when valid. */
  rule: string | null;
  /** The SPEC §8.1 message, or `null` when valid. */
  message: string | null;
  /** True when `rule` is one of `CONTRACT_POLICY_RULE_IDS`. */
  knownRule: boolean;
}

/** The valid arm, built in one place so every decoder path agrees. */
function validResult(): PolicyValidationResult {
  return { valid: true, rule: null, message: null, knownRule: false };
}

/** Build the invalid arm, translating a documented rule when possible. */
function invalidResult(rule: string): PolicyValidationResult {
  const known = (CONTRACT_POLICY_RULE_IDS as readonly string[]).includes(rule);
  return {
    valid: false,
    rule,
    message: known
      ? POLICY_RULE_MESSAGES[rule as ContractPolicyRuleId]
      : `the contract rejected the policy with rule "${rule}"; this SDK does not have a description for it yet`,
    knownRule: known,
  };
}

/** Decode `ValidationOutcome::{Valid, Invalid(PolicyRuleId)}`.
 *
 * Accepts the host's `ScVal` (what a simulation returns), the native form
 * `scValToNative` produces (`[\"Valid\"]` / `[\"Invalid\", \"AmountSign\"]`), and the
 * externally tagged JSON a CLI or dashboard may hold (`\"Valid\"` /
 * `{\"Invalid\": \"AmountSign\"}`). Anything else throws a `PolicyDecodeError`
 * naming `ValidationOutcome` — a preflight that cannot decode the answer must
 * not be mistaken for a pass.
 *
 * @throws {PolicyDecodeError} when the payload is not a `ValidationOutcome`.
 */
export function decodeValidationOutcome(raw: unknown): PolicyValidationResult {
  let native: unknown;
  if (raw instanceof xdr.ScVal) {
    try {
      native = scValToNative(raw as xdr.ScVal);
    } catch (cause) {
      throw new PolicyDecodeError("validate_policy returned an undecodable ScVal", {
        path: "ValidationOutcome",
        cause,
      });
    }
  } else if (typeof raw === "object" && raw !== null) {
    try {
      native = scValToNative(xdr.ScVal.fromXDR(JSON.stringify(raw), "base64") as xdr.ScVal);
    } catch (cause) {
      throw new PolicyDecodeError("validate_policy returned an undecodable JSON payload", {
        path: "ValidationOutcome",
        cause,
      });
    }
  } else {
    throw new PolicyDecodeError("validate_policy returned an unexpected payload", {
      path: "ValidationOutcome",
    });
  }

  // Note: describeRaw is a utility for error messages; kept for external consumers
  if (native === "Valid") {
    return validResult();
  }

  if (native === "Invalid" && typeof native === "object" && native !== null && "reason" in native) {
    return invalidResult((native as { reason: string }).reason);
  }

  // `["Invalid", "AmountSign"]` form
  if (Array.isArray(native)) {
    const [tag, reason] = native;
    if (tag === "Invalid" && typeof reason === "string") {
      return invalidResult(reason);
    }
  }

  // Fallback: try to extract a rule name from any other shape
  throw new PolicyDecodeError(`validate_policy returned an unrecognised Invalid form`, {
    path: "ValidationOutcome",
  });
}

/** Parameters for {@link buildValidatePolicyCall}. */
export interface BuildValidatePolicyCallParams {
  /** The guard contract whose `validate_policy` is read. */
  guard: ContractAddress;
  /** The candidate policy to validate. */
  policy: ReadonlyPolicyConfig;
}

/** Result of {@link buildValidatePolicyCall}, ready to be sent to RPC. */
export interface ValidatePolicyCall {
  contract: string;
  fn: string;
  args: xdr.ScVal[];
}

/** Build the validate_policy call from a `PolicyConfig`. */
export function buildValidatePolicyCall(
  guard: ContractAddress,
  policy: ReadonlyPolicyConfig,
): ValidatePolicyCall {
  const args = [policyToScVal(policy)];
  return {
    contract: guard,
    fn: "validate_policy",
    args,
  };
}

/** Parameters for {@link validatePolicyOnChain}. */
export interface ValidatePolicyOnChainParams {
  server: rpc.Server;
  /** The guard contract whose `validate_policy` is read. */
  guard: ContractAddress;
  /** Account that supplies the simulation's sequence number and fee. It pays
   * nothing: the call is a read, simulated and never signed or broadcast. */
  source: Keypair | AdminSigner;
  /** The candidate policy; never installed by this helper. */
  policy: ReadonlyPolicyConfig;
  /** Defaults to the testnet passphrase used by the admin helpers. */
  networkPassphrase?: string | undefined;
  /** Caller-owned cancellation, honoured at the RPC boundary. */
  signal?: AbortSignal | undefined;
  /** Per-call bound; defaults to `DEFAULT_RPC_TIMEOUT_MS` (30s). */
  timeoutMs?: number | undefined;
}

/** Simulate `validate_policy` against a candidate policy and decode the answer.
 *
 * Read-only: no signing, no broadcast, no writes. The only cost is one
 * simulation, paid by the source account's ledger lookup only in the sense of a
 * normal RPC read — nothing is charged to it.
 *
 * A simulation that fails for a non-validation reason (transport, a contract
 * trap, a restored footprint) throws `SimulationError`; only a successful
 * simulation whose return value is not a `ValidationOutcome` throws
 * `PolicyDecodeError`/`ContractResponseError`. An invalid policy is therefore a
 * **successful** result with `valid: false` — it is an answer, not an SDK
 * failure.
 */
export async function validatePolicyOnChain(
  params: ValidatePolicyOnChainParams,
): Promise<PolicyValidationResult> {
  const { server, guard, source, policy } = params;
  const call = buildValidatePolicyCall(guard, policy);
  const timeoutMs = params.timeoutMs ?? DEFAULT_RPC_TIMEOUT_MS;

  // An already-aborted signal must cost zero RPC calls, the same contract
  // `invoke()` keeps. "Already stopped" is not a reason to probe the network.
  if (params.signal?.aborted) {
    throw new RpcTimeoutError({ stage: "validate_policy", aborted: true });
  }

  let account: Awaited<ReturnType<rpc.Server["getAccount"]>>;
  try {
    const sourcePubKey = await source.publicKey();
    account = await withRpcAbort(
      { stage: "validate_policy", signal: params.signal, timeoutMs },
      () => server.getAccount(sourcePubKey),
    );
  } catch (cause) {
    if (cause instanceof RpcTimeoutError) throw cause;
    throw new SimulationError("validate_policy preflight could not read the source account", {
      stage: "preflight",
      cause,
    });
  }

  const operation = Operation.invokeContractFunction({
    contract: call.contract,
    function: call.fn,
    args: call.args,
  });
  const transaction = buildInitialEnvelope({
    source: account,
    operation,
    networkPassphrase: params.networkPassphrase ?? DEFAULT_NETWORK_PASSPHRASE,
    guard: null,
  });

  const response = await withRpcAbort(
    { stage: "validate_policy", signal: params.signal, timeoutMs },
    () => server.simulateTransaction(transaction),
  );

  if (rpc.Api.isSimulationError(response)) {
    throw new SimulationError("validate_policy simulation failed", {
      stage: "preflight",
      diagnosticEvents: response.events,
    });
  }

  const retval = response.result?.retval;
  if (retval === undefined) {
    throw new ContractResponseError("validate_policy simulation returned no result.retval", {
      field: "result.retval",
      stage: "preflight",
    });
  }
  return decodeValidationOutcome(retval);
}
