import { transactInstructionDataCodec } from "@zolana/interface/codecs";
import {
  SHIELDED_POOL_PROGRAM_ID,
  TRANSACTION_SIZE_LIMIT,
  decodeShieldedPoolError,
  type Address,
  type Bytes32,
  type RequestContext,
  type Signature,
  type Transaction,
} from "@zolana/interface";
import type { InputUtxoContext } from "@zolana/transaction";

import { ClientError } from "./error.js";
import { compactU16 } from "./wire.js";
import {
  addressBytes,
  composeSignal,
  compareBytes,
  decodeBase58,
  decodeBase58Bytes,
  decodeBase64,
  encodeBase64,
  requestError,
  signatureBytes,
  sleep,
} from "./internal.js";
import type {
  Commitment,
  GetMerkleProofsResponse,
  GetNonInclusionProofsResponse,
  IndexerRpcConfig,
  Rpc,
  RpcAccount,
  SendTransactionConfig,
  SpendProof,
} from "./rpc.js";

type JsonObject = Record<string, unknown>;

const TRANSACT_TAG = 0;
const DEFAULT_CONFIRMATION_TIMEOUT_MS = 30_000;
const CONFIRMATION_INTERVAL_MS = 250;

/// One instruction with its program and account keys already resolved against
/// the message's account keys plus the transaction's loaded addresses.
export interface ParsedInstruction {
  readonly programId: Address;
  readonly accounts: readonly Address[];
  readonly data: Uint8Array;
  readonly stackHeight?: number;
}

/// An outer instruction and the inner instructions it invoked, in call order.
export interface InstructionGroup {
  readonly outer: ParsedInstruction;
  readonly inner: readonly ParsedInstruction[];
}

export interface ConfirmedInstructionGroups {
  readonly groups: readonly InstructionGroup[];
}

/// Rust serializes the whole config struct, so an unset field arrives as an
/// explicit `null` rather than being omitted. Reproduced literally: the node
/// treats the two alike, but a recorded request is compared as a whole.
function sendConfigParameter(
  config: SendTransactionConfig | undefined,
  absentPreflightCommitment: Commitment,
): JsonObject {
  return {
    encoding: "base64",
    maxRetries: config?.maxRetries === undefined ? null : countField(config.maxRetries),
    minContextSlot: config?.minContextSlot === undefined ? null : slotField(config.minContextSlot),
    preflightCommitment: config?.preflightCommitment ?? absentPreflightCommitment,
    skipPreflight: config?.skipPreflight ?? false,
  };
}

function countField(value: number): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new ClientError("CLIENT_INVALID_INTEGER", {
      details: { field: "maxRetries", value: String(value) },
    });
  }
  return value;
}

function slotField(value: bigint): number {
  if (value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new ClientError("CLIENT_INVALID_INTEGER", {
      details: { field: "minContextSlot", value: value.toString() },
    });
  }
  return Number(value);
}

/// One entry of a `getSignatureStatuses` response. `confirmations` is absent
/// once the transaction is rooted, and `err` is absent when it succeeded.
export interface SignatureStatus {
  readonly slot: bigint;
  readonly confirmations?: number;
  readonly confirmationStatus?: string;
  readonly err?: unknown;
}

/// The plain Solana reads below are deliberately not on the `Rpc` interface.
/// Light Protocol's `Rpc extends Connection implements CompressionApiInterface`
/// keeps the same split: the protocol interface declares only protocol methods,
/// and the plain Solana surface belongs to the concrete transport. Declaring
/// them on `Rpc` would oblige every implementor -- `ZolanaClient`, the indexer,
/// a caller's mock -- to answer chain-state questions it has no transport for,
/// which is the fat-trait shape Rust carries and this port split apart.
export class SolanaRpc implements Rpc {
  readonly #fetch: typeof globalThis.fetch;
  readonly #url: URL;
  readonly #confirmationTimeoutMs: number;
  #requestId = 0;

  constructor(
    input: Readonly<{
      url: URL | string;
      fetch?: typeof globalThis.fetch;
      confirmationTimeoutMs?: number;
    }>,
  ) {
    const candidate: unknown = input;
    if (typeof candidate !== "object" || candidate === null) {
      throw new ClientError("CLIENT_INVALID_CONFIG");
    }
    const timeout = input.confirmationTimeoutMs ?? DEFAULT_CONFIRMATION_TIMEOUT_MS;
    if (!Number.isSafeInteger(timeout) || timeout < 0) {
      throw new ClientError("CLIENT_INVALID_CONFIG", {
        details: { field: "confirmationTimeoutMs" },
      });
    }
    this.#confirmationTimeoutMs = timeout;
    try {
      this.#url = new URL(input.url instanceof URL ? input.url.href : input.url);
    } catch {
      throw new ClientError("CLIENT_INVALID_CONFIG", { details: { field: "url" } });
    }
    if (
      (this.#url.protocol !== "http:" && this.#url.protocol !== "https:") ||
      this.#url.username !== "" ||
      this.#url.password !== "" ||
      this.#url.hash !== ""
    ) {
      throw new ClientError("CLIENT_INVALID_CONFIG", { details: { field: "url" } });
    }
    const fetchImplementation = input.fetch ?? globalThis.fetch;
    if (typeof fetchImplementation !== "function") {
      throw new ClientError("CLIENT_INVALID_CONFIG", { details: { field: "fetch" } });
    }
    this.#fetch = fetchImplementation;
  }

  async getAccount(address: Address, context?: RequestContext): Promise<RpcAccount | undefined> {
    addressBytes(address);
    const result = await this.#call(
      "getAccountInfo",
      [address, { commitment: "confirmed", encoding: "base64" }],
      context,
    );
    const envelope = object(result, "result");
    return envelope["value"] === null
      ? undefined
      : decodeAccount(envelope["value"], "result.value");
  }

  async getProgramAccounts(
    programAddress: Address,
    context?: RequestContext,
  ): Promise<readonly Readonly<{ address: Address; account: RpcAccount }>[]> {
    addressBytes(programAddress);
    const result = await this.#call(
      "getProgramAccounts",
      [programAddress, { commitment: "confirmed", encoding: "base64" }],
      context,
    );
    return Object.freeze(
      array(result, "result").map((value, index) => {
        const entry = object(value, `result[${String(index)}]`);
        const address = string(entry["pubkey"], `result[${String(index)}].pubkey`) as Address;
        addressBytes(address);
        return Object.freeze({
          address,
          account: decodeAccount(entry["account"], `result[${String(index)}].account`),
        });
      }),
    );
  }

  async getMultipleAccounts(
    addresses: readonly Address[],
    context?: RequestContext,
  ): Promise<readonly (RpcAccount | undefined)[]> {
    addresses.forEach(addressBytes);
    const result = await this.#call(
      "getMultipleAccounts",
      [addresses, { commitment: "confirmed", encoding: "base64" }],
      context,
    );
    const values = array(object(result, "result")["value"], "result.value");
    if (values.length !== addresses.length) {
      throw new ClientError("CLIENT_INVALID_RPC_RESPONSE", {
        details: {
          method: "getMultipleAccounts",
          expected: addresses.length,
          actual: values.length,
        },
      });
    }
    return Object.freeze(
      values.map((value, index) =>
        value === null ? undefined : decodeAccount(value, `result.value[${String(index)}]`),
      ),
    );
  }

  async getBalance(address: Address, context?: RequestContext): Promise<bigint> {
    addressBytes(address);
    const result = await this.#call("getBalance", [address, { commitment: "confirmed" }], context);
    return unsignedInteger(object(result, "result")["value"], "result.value");
  }

  async getLatestBlockhash(
    context?: RequestContext,
  ): Promise<Readonly<{ blockhash: string; lastValidBlockHeight: bigint }>> {
    const result = object(
      await this.#call("getLatestBlockhash", [{ commitment: "confirmed" }], context),
      "result",
    );
    const value = object(result["value"], "result.value");
    const blockhash = string(value["blockhash"], "result.value.blockhash");
    decodeBase58(blockhash, 32, "blockhash");
    return Object.freeze({
      blockhash,
      lastValidBlockHeight: unsignedInteger(
        value["lastValidBlockHeight"],
        "result.value.lastValidBlockHeight",
      ),
    });
  }

  async getSlot(context?: RequestContext): Promise<bigint> {
    return unsignedInteger(
      await this.#call("getSlot", [{ commitment: "confirmed" }], context),
      "result",
    );
  }

  async getBlockHeight(context?: RequestContext): Promise<bigint> {
    return unsignedInteger(
      await this.#call("getBlockHeight", [{ commitment: "confirmed" }], context),
      "result",
    );
  }

  /// Rust reaches this through `RpcClient::get_signature_statuses`, which sends
  /// the signatures alone and so leaves `searchTransactionHistory` at the
  /// server's default; `confirmTransaction` is the call that turns it on.
  async getSignatureStatuses(
    signatures: readonly Signature[],
    context?: RequestContext,
  ): Promise<readonly (SignatureStatus | undefined)[]> {
    signatures.forEach(signatureBytes);
    const result = await this.#call("getSignatureStatuses", [signatures], context);
    const values = array(object(result, "result")["value"], "result.value");
    if (values.length !== signatures.length) {
      throw new ClientError("CLIENT_INVALID_RPC_RESPONSE", {
        details: {
          method: "getSignatureStatuses",
          expected: signatures.length,
          actual: values.length,
        },
      });
    }
    return Object.freeze(
      values.map((value, index) =>
        value === null ? undefined : decodeSignatureStatus(value, `result.value[${String(index)}]`),
      ),
    );
  }

  async getMinimumBalanceForRentExemption(
    dataLength: number,
    context?: RequestContext,
  ): Promise<bigint> {
    if (!Number.isSafeInteger(dataLength) || dataLength < 0) {
      throw new ClientError("CLIENT_INVALID_INTEGER", {
        details: { field: "dataLength", value: String(dataLength) },
      });
    }
    return unsignedInteger(
      await this.#call("getMinimumBalanceForRentExemption", [dataLength], context),
      "result",
    );
  }

  /// Resolves when the node reports itself healthy and rejects otherwise, the
  /// way Rust's `health` returns `Result<(), _>`. An unhealthy node answers with
  /// a JSON-RPC error, which `#call` raises as a retryable `CLIENT_RPC_ENVELOPE`.
  async getHealth(context?: RequestContext): Promise<void> {
    // `null` rather than `[]`: `solana_rpc_client` sends no parameter list for a
    // parameterless request, and the recorded oracle pins that.
    const status = string(await this.#call("getHealth", null, context), "result");
    if (status !== "ok") {
      throw new ClientError("CLIENT_RPC", { details: { method: "getHealth", reason: status } });
    }
  }

  /// Sends and confirms, as the Rust `Rpc::send_transaction` does: the returned
  /// signature is confirmed at the `confirmed` commitment, not merely accepted.
  async sendTransaction(transaction: Transaction, context?: RequestContext): Promise<Signature> {
    return this.#sendAndConfirm(transaction, sendConfigParameter(undefined, "confirmed"), context);
  }

  /// `Rpc::send_transaction_with_config`, whose config reaches the node
  /// untouched apart from one fallback.
  ///
  /// An absent `preflightCommitment` resolves to `finalized` here and to
  /// `confirmed` in `sendTransaction`. The two paths fill it from different
  /// places in Rust, the config field's own default against the client's
  /// configured commitment, which is why the difference is preserved rather
  /// than smoothed over.
  async sendTransactionWithConfig(
    transaction: Transaction,
    config: SendTransactionConfig,
    context?: RequestContext,
  ): Promise<Signature> {
    return this.#sendAndConfirm(transaction, sendConfigParameter(config, "finalized"), context);
  }

  async #sendAndConfirm(
    transaction: Transaction,
    config: JsonObject,
    context: RequestContext | undefined,
  ): Promise<Signature> {
    const encoded = encodeBase64(serializeTransaction(transaction));
    const submit = async (): Promise<Signature> => {
      const result = await this.#call("sendTransaction", [encoded, config], context);
      const signature = string(result, "result") as Signature;
      signatureBytes(signature);
      return signature;
    };

    const signature = await submit();
    // `send_and_confirm_transaction` keeps resubmitting while it waits, so a
    // transaction the leader drops still lands. Submitting once and only polling
    // gave up on a transaction Rust confirms. Resubmitting is safe: the bytes
    // are identical, so the signature is too, and the runtime rejects the
    // duplicate once the first copy is in a block.
    await this.#waitForSignature(signature, context, submit);
    return signature;
  }

  /// Requests lamports from the validator faucet and waits for confirmation.
  async airdrop(address: Address, lamports: bigint, context?: RequestContext): Promise<Signature> {
    addressBytes(address);
    // JSON-RPC carries the amount as a Number; refuse values that cannot
    // round-trip through Number without changing magnitude.
    if (
      lamports < 0n ||
      lamports > 0xffff_ffff_ffff_ffffn ||
      lamports > BigInt(Number.MAX_SAFE_INTEGER)
    ) {
      throw new ClientError("CLIENT_INVALID_INTEGER", {
        details: { field: "lamports", value: lamports.toString() },
      });
    }
    const result = await this.#call(
      "requestAirdrop",
      [address, Number(lamports), { commitment: "confirmed" }],
      context,
    );
    const signature = string(result, "result") as Signature;
    signatureBytes(signature);
    await this.#waitForSignature(signature, context);
    return signature;
  }

  async assertExecutable(programAddress: Address, context?: RequestContext): Promise<void> {
    addressBytes(programAddress);
    const result = await this.#call(
      "getAccountInfo",
      [programAddress, { commitment: "confirmed", encoding: "base64" }],
      context,
    );
    const value = object(result, "result")["value"];
    if (value === null || object(value, "result.value")["executable"] !== true) {
      throw new ClientError("CLIENT_RPC", {
        details: { method: "assertExecutable", reason: "program is not executable" },
      });
    }
  }

  /// The confirmed transaction, retried until the confirmation timeout while the
  /// RPC still reports it as unknown or fails to answer.
  async getConfirmedTransaction(
    signature: Signature,
    context?: RequestContext,
  ): Promise<JsonObject> {
    signatureBytes(signature);
    const started = Date.now();
    const expired = (): boolean => Date.now() - started >= this.#confirmationTimeoutMs;
    for (;;) {
      let result: unknown;
      try {
        result = await this.#call(
          "getTransaction",
          [
            signature,
            { commitment: "confirmed", encoding: "json", maxSupportedTransactionVersion: 0 },
          ],
          context,
        );
      } catch (error) {
        // `fetch_confirmed_transaction` retries every failure until the
        // deadline, not only the unknown-transaction answer, so a validator
        // that drops a request mid-confirmation does not fail the fetch. The
        // sleep below ends the wait on an abort.
        if (expired()) throw error;
        await sleep(BigInt(CONFIRMATION_INTERVAL_MS), context);
        continue;
      }
      if (result !== null) return object(result, "result");
      if (expired()) {
        throw new ClientError("CLIENT_RPC_TRANSACTION_NOT_FOUND", { details: { signature } });
      }
      await sleep(BigInt(CONFIRMATION_INTERVAL_MS), context);
    }
  }

  async confirmedInstructionGroups(
    signature: Signature,
    context?: RequestContext,
  ): Promise<ConfirmedInstructionGroups> {
    return instructionGroups(await this.getConfirmedTransaction(signature, context));
  }

  async confirmTransaction(signature: Signature, context?: RequestContext): Promise<boolean> {
    signatureBytes(signature);
    const result = object(
      await this.#call(
        "getSignatureStatuses",
        [[signature], { searchTransactionHistory: true }],
        context,
      ),
      "result",
    );
    const values = array(result["value"], "result.value");
    const status = values[0];
    if (status === null || status === undefined) return false;
    const decoded = object(status, "result.value[0]");
    if (decoded["err"] !== null) return false;
    return (
      decoded["confirmationStatus"] === "confirmed" ||
      decoded["confirmationStatus"] === "finalized" ||
      decoded["confirmations"] === null
    );
  }

  async transactOutputViewTags(
    signature: Signature,
    context?: RequestContext,
  ): Promise<readonly Bytes32[]> {
    return transactOutputViewTagsFromInstructionGroups(
      await this.confirmedInstructionGroups(signature, context),
    );
  }

  getMerkleProofs(
    _treeAccount: Address,
    _leaves: readonly Bytes32[],
    _config?: IndexerRpcConfig,
    _context?: RequestContext,
  ): Promise<GetMerkleProofsResponse> {
    void [_treeAccount, _leaves, _config, _context];
    return Promise.reject(unsupported("getMerkleProofs"));
  }

  getNonInclusionProofs(
    _treeAccount: Address,
    _leaves: readonly Bytes32[],
    _config?: IndexerRpcConfig,
    _context?: RequestContext,
  ): Promise<GetNonInclusionProofsResponse> {
    void [_treeAccount, _leaves, _config, _context];
    return Promise.reject(unsupported("getNonInclusionProofs"));
  }

  getInputMerkleProofs(
    _inputs: readonly InputUtxoContext[],
    _config?: IndexerRpcConfig,
    _context?: RequestContext,
  ): Promise<readonly SpendProof[]> {
    void [_inputs, _config, _context];
    return Promise.reject(unsupported("getInputMerkleProofs"));
  }

  async #waitForSignature(
    signature: Signature,
    context?: RequestContext,
    resubmit?: () => Promise<Signature>,
  ): Promise<void> {
    const started = Date.now();
    for (let attempt = 1; ; attempt++) {
      if (await this.confirmTransaction(signature, context)) return;
      if (Date.now() - started >= this.#confirmationTimeoutMs) {
        throw new ClientError("CLIENT_CONFIRMATION_TIMEOUT", {
          details: { signature, attempts: attempt },
        });
      }
      await sleep(BigInt(CONFIRMATION_INTERVAL_MS), context);
      // A resubmission that fails is not fatal on its own: the first copy may
      // still confirm, and the timeout above bounds the wait either way.
      if (resubmit !== undefined) await resubmit().catch(() => signature);
    }
  }

  async #call(
    method: string,
    params: readonly unknown[] | null,
    context?: RequestContext,
  ): Promise<unknown> {
    const signal = composeSignal(context, method);
    const id = ++this.#requestId;
    try {
      let response: Response;
      try {
        response = await this.#fetch(this.#url, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
          signal: signal.signal,
        });
      } catch {
        throw requestError(method, signal);
      }
      if (!response.ok) {
        throw new ClientError("CLIENT_RPC_HTTP", {
          details: { method, status: response.status },
        });
      }
      let value: unknown;
      try {
        value = await response.json();
      } catch {
        if (signal.signal.aborted) throw requestError(method, signal);
        throw new ClientError("CLIENT_RPC_JSON", { details: { method } });
      }
      const envelope = object(value, "$");
      const programError = decodeProgramError(envelope["error"]);
      if (programError !== undefined) {
        throw new ClientError("CLIENT_RPC_PROGRAM_ERROR", {
          details: {
            method,
            instructionIndex: programError.instructionIndex,
            programError: decodeShieldedPoolError(programError.code),
          },
        });
      }
      if (
        envelope["jsonrpc"] !== "2.0" ||
        envelope["id"] !== id ||
        !Object.hasOwn(envelope, "result") ||
        Object.hasOwn(envelope, "error")
      ) {
        throw new ClientError("CLIENT_RPC_ENVELOPE", { details: { method } });
      }
      return envelope["result"];
    } finally {
      signal.cleanup();
    }
  }
}

function decodeProgramError(
  value: unknown,
): Readonly<{ instructionIndex: number; code: number }> | undefined {
  const error = plainObject(value);
  const data = plainObject(error?.["data"]);
  const transactionError = plainObject(data?.["err"]);
  const instructionError = transactionError?.["InstructionError"];
  if (!Array.isArray(instructionError) || instructionError.length !== 2) return undefined;
  const entries = instructionError as readonly unknown[];
  const instructionIndex = entries[0];
  const detail = entries[1];
  const custom = plainObject(detail)?.["Custom"];
  if (
    typeof instructionIndex !== "number" ||
    !Number.isSafeInteger(instructionIndex) ||
    instructionIndex < 0 ||
    typeof custom !== "number" ||
    !Number.isSafeInteger(custom) ||
    custom < 0 ||
    custom > 0xffff_ffff
  ) {
    return undefined;
  }
  return { instructionIndex, code: custom };
}

function plainObject(value: unknown): JsonObject | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as JsonObject)
    : undefined;
}

function decodeAccount(value: unknown, path: string): RpcAccount {
  const account = object(value, path);
  const owner = string(account["owner"], `${path}.owner`) as Address;
  addressBytes(owner);
  const data = array(account["data"], `${path}.data`);
  if (data.length !== 2 || data[1] !== "base64") invalid(path);
  return Object.freeze({
    owner,
    data: decodeBase64(data[0], `${path}.data[0]`),
    lamports: unsignedInteger(account["lamports"], `${path}.lamports`),
  });
}

function decodeSignatureStatus(value: unknown, path: string): SignatureStatus {
  const status = object(value, path);
  const confirmations = status["confirmations"];
  const confirmationStatus = status["confirmationStatus"];
  return Object.freeze({
    slot: unsignedInteger(status["slot"], `${path}.slot`),
    ...(confirmations === null || confirmations === undefined
      ? {}
      : { confirmations: safeNumber(confirmations, `${path}.confirmations`) }),
    ...(confirmationStatus === null || confirmationStatus === undefined
      ? {}
      : { confirmationStatus: string(confirmationStatus, `${path}.confirmationStatus`) }),
    ...(status["err"] === null || status["err"] === undefined ? {} : { err: status["err"] }),
  });
}

function serializeTransaction(transaction: Transaction): Uint8Array {
  if (!(transaction.messageBytes instanceof Uint8Array)) {
    throw new ClientError("CLIENT_INVALID_TRANSACTION");
  }
  const count = compactU16(transaction.signatures.length);
  const signatures = transaction.signatures.map((signature) =>
    signature === undefined ? new Uint8Array(64) : signatureBytes(signature),
  );
  return concat(count, ...signatures, transaction.messageBytes);
}

/// Groups a confirmed JSON-encoded transaction. Account indexes resolve against
/// the message keys followed by the loaded address-lookup keys, writable before
/// readonly, which is the order the runtime itself uses.
export function instructionGroups(result: JsonObject): ConfirmedInstructionGroups {
  const meta = object(result["meta"], "result.meta");
  const transaction = object(result["transaction"], "result.transaction");
  const message = object(transaction["message"], "result.transaction.message");
  const accountKeys = [
    ...messageAccountKeys(message),
    ...loadedAccountKeys(meta["loadedAddresses"]),
  ];
  const inner = meta["innerInstructions"];
  if (inner === null || inner === undefined) invalid("result.meta.innerInstructions");
  const groups = array(message["instructions"], "result.transaction.message.instructions").map(
    (raw) => ({ outer: parsedInstruction(accountKeys, raw, 1), inner: [] as ParsedInstruction[] }),
  );
  for (const raw of array(inner, "result.meta.innerInstructions")) {
    const entry = object(raw, "result.meta.innerInstructions[]");
    const index = safeNumber(entry["index"], "result.meta.innerInstructions[].index");
    const group = groups[index];
    if (group === undefined) {
      throw new ClientError("CLIENT_INVALID_RPC_RESPONSE", {
        details: { path: `result.meta.innerInstructions[${String(index)}].index` },
      });
    }
    group.inner = array(entry["instructions"], "inner instructions").map((instruction) =>
      parsedInstruction(accountKeys, instruction),
    );
  }
  return Object.freeze({
    groups: Object.freeze(
      groups.map((group) =>
        Object.freeze({ outer: group.outer, inner: Object.freeze(group.inner) }),
      ),
    ),
  });
}

/// The unique output `view_tag`s of the first shielded-pool `TRANSACT`
/// instruction, which may be an outer instruction or an inner one when another
/// program CPIs into `transact`. Groups are scanned in order and each group's
/// outer instruction precedes its inner instructions.
export function transactOutputViewTagsFromInstructionGroups(
  groups: ConfirmedInstructionGroups,
): readonly Bytes32[] {
  for (const group of groups.groups) {
    for (const instruction of [group.outer, ...group.inner]) {
      const tags = transactViewTags(instruction);
      if (tags !== undefined) return tags;
    }
  }
  throw new ClientError("CLIENT_RPC_TRANSACT_NOT_FOUND");
}

/// `undefined` when the instruction is unrelated; throws when it is a `TRANSACT`
/// call whose payload cannot be decoded or whose owner tag cannot be resolved.
function transactViewTags(instruction: ParsedInstruction): readonly Bytes32[] | undefined {
  if (instruction.programId !== SHIELDED_POOL_PROGRAM_ID) return undefined;
  if (instruction.data[0] !== TRANSACT_TAG) return undefined;
  let decoded;
  try {
    decoded = transactInstructionDataCodec.decode(instruction.data.subarray(1));
  } catch (cause) {
    throw new ClientError("CLIENT_RPC_TRANSACT_DECODE", { cause });
  }
  const tags = decoded.outputs.map((output) => {
    if (output.ownerTag.kind === "inline") return new Uint8Array(output.ownerTag.value) as Bytes32;
    if (output.ownerTag.kind === "p256SigningKey") {
      if (!decoded.p256SigningPkX) throw new ClientError("CLIENT_RPC_OWNER_TAG");
      return new Uint8Array(decoded.p256SigningPkX) as Bytes32;
    }
    const address = instruction.accounts[output.ownerTag.index];
    if (address === undefined) throw new ClientError("CLIENT_RPC_OWNER_TAG");
    return addressBytes(address);
  });
  const unique = new Map(tags.map((tag) => [encodeBase64(tag), tag]));
  return Object.freeze([...unique.values()].sort((left, right) => compareBytes(left, right)));
}

function messageAccountKeys(message: JsonObject): Address[] {
  return array(message["accountKeys"], "result.transaction.message.accountKeys").map(
    (entry, index) => {
      const value =
        typeof entry === "string"
          ? entry
          : string(
              object(entry, `accountKeys[${String(index)}]`)["pubkey"],
              `accountKeys[${String(index)}].pubkey`,
            );
      addressBytes(value as Address);
      return value as Address;
    },
  );
}

function loadedAccountKeys(value: unknown): Address[] {
  if (value === null || value === undefined) return [];
  const loaded = object(value, "result.meta.loadedAddresses");
  return [
    ...array(loaded["writable"], "result.meta.loadedAddresses.writable"),
    ...array(loaded["readonly"], "result.meta.loadedAddresses.readonly"),
  ].map((entry, index) => {
    const address = string(entry, `result.meta.loadedAddresses[${String(index)}]`) as Address;
    addressBytes(address);
    return address;
  });
}

function parsedInstruction(
  accountKeys: readonly Address[],
  raw: unknown,
  stackHeight?: number,
): ParsedInstruction {
  const instruction = object(raw, "instruction");
  const programId = accountKeys[safeNumber(instruction["programIdIndex"], "programIdIndex")];
  if (programId === undefined) invalid("instruction.programIdIndex");
  const accounts = array(instruction["accounts"], "instruction.accounts").map((value) => {
    const address = accountKeys[safeNumber(value, "account index")];
    if (address === undefined) invalid("instruction.accounts[]");
    return address;
  });
  const encoded = string(instruction["data"], "instruction.data");
  const height = stackHeight ?? instruction["stackHeight"];
  // Empty base58 is empty bytes (bs58 / Rust); zero-data instructions still parse.
  const data = decodeBase58Bytes(encoded, "instruction.data");
  // Instruction data travels inside a transaction, so no decode can be longer
  // than the packet the validator accepts.
  if (data.length > TRANSACTION_SIZE_LIMIT) {
    throw new ClientError("CLIENT_INVALID_BASE58", {
      details: {
        field: "instruction.data",
        expectedLength: TRANSACTION_SIZE_LIMIT,
        actualLength: data.length,
      },
    });
  }
  return Object.freeze({
    programId,
    accounts: Object.freeze(accounts),
    data,
    ...(typeof height === "number"
      ? { stackHeight: safeNumber(height, "instruction.stackHeight") }
      : {}),
  });
}

function concat(...parts: readonly Uint8Array[]): Uint8Array {
  const output = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

function object(value: unknown, path: string): JsonObject {
  if (typeof value !== "object" || value === null || Array.isArray(value)) invalid(path);
  return value as JsonObject;
}

function array(value: unknown, path: string): unknown[] {
  if (!Array.isArray(value)) invalid(path);
  return value;
}

function string(value: unknown, path: string): string {
  if (typeof value !== "string") invalid(path);
  return value;
}

function unsignedInteger(value: unknown, path: string): bigint {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    invalid(path);
  }
  return BigInt(value);
}

function safeNumber(value: unknown, path: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) invalid(path);
  return value;
}

function invalid(path: string): never {
  throw new ClientError("CLIENT_INVALID_RPC_RESPONSE", { details: { path } });
}

function unsupported(method: string): ClientError {
  return new ClientError("CLIENT_UNSUPPORTED_RPC_METHOD", { details: { method } });
}
