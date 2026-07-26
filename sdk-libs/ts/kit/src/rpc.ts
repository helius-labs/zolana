import {
  getBase64EncodedWireTransaction,
  type Rpc as KitRpc,
  type SolanaRpcApi,
} from "@solana/kit";
import type {
  GetMerkleProofsResponse,
  GetNonInclusionProofsResponse,
  Rpc,
  RpcAccount,
  SpendProof,
} from "@zolana/client";
import {
  decodeBase58,
  decodeBase64,
  encodeBase64,
  InstructionTag,
  SHIELDED_POOL_PROGRAM_ID,
  type Address,
  type Bytes32,
  type RequestContext,
  type Signature,
} from "@zolana/interface";
import { transactInstructionDataCodec } from "@zolana/interface/codecs";

import { toKitAddress } from "./address.js";
import { KitError } from "./error.js";
import { toKitTransaction } from "./transaction.js";

/**
 * Return type of `createSolanaRpc(url)`. Cluster-specific connections add
 * methods and are still accepted here.
 */
export type KitConnection = KitRpc<SolanaRpcApi>;

export interface KitRpcOptions {
  readonly confirmationTimeoutMs?: number;
}

const DEFAULT_CONFIRMATION_TIMEOUT_MS = 30_000;
const CONFIRMATION_INTERVAL_MS = 250;
const COMMITMENT = "confirmed" as const;

/**
 * Implements Zolana's `Rpc` on a Kit connection so an existing Kit RPC handle
 * can be passed to `createAndSendTransaction` or `ZolanaClient`.
 *
 * The three Merkle-proof methods reject, matching `SolanaRpc`: those answers
 * come from an indexer. Use a `ZolanaIndexer` for them.
 */
export function createKitRpc(connection: KitConnection, options?: KitRpcOptions): Rpc {
  const confirmationTimeoutMs = options?.confirmationTimeoutMs ?? DEFAULT_CONFIRMATION_TIMEOUT_MS;
  if (!Number.isSafeInteger(confirmationTimeoutMs) || confirmationTimeoutMs < 0) {
    throw new KitError(
      "KIT_INVALID_CONFIG",
      "confirmationTimeoutMs must be a non-negative integer",
      {
        details: { confirmationTimeoutMs },
      },
    );
  }

  const rpc: Rpc = {
    async getAccount(address, context) {
      const { value } = await connection
        .getAccountInfo(toKitAddress(address), { commitment: COMMITMENT, encoding: "base64" })
        .send(sendOptions(context));
      return value === null ? undefined : account(value);
    },

    async getProgramAccounts(programAddress, context) {
      const found = await connection
        .getProgramAccounts(toKitAddress(programAddress), {
          commitment: COMMITMENT,
          encoding: "base64",
        })
        .send(sendOptions(context));
      return Object.freeze(
        found.map((entry) =>
          Object.freeze({
            address: entry.pubkey as string as Address,
            account: account(entry.account),
          }),
        ),
      );
    },

    async getMultipleAccounts(addresses, context) {
      const { value } = await connection
        .getMultipleAccounts(addresses.map(toKitAddress), {
          commitment: COMMITMENT,
          encoding: "base64",
        })
        .send(sendOptions(context));
      if (value.length !== addresses.length) {
        throw new KitError(
          "KIT_INVALID_RPC_RESPONSE",
          "getMultipleAccounts answered a different count",
          {
            details: { expected: addresses.length, actual: value.length },
          },
        );
      }
      return Object.freeze(value.map((entry) => (entry === null ? undefined : account(entry))));
    },

    async getBalance(address, context) {
      const { value } = await connection
        .getBalance(toKitAddress(address), { commitment: COMMITMENT })
        .send(sendOptions(context));
      return value;
    },

    async getMinimumBalanceForRentExemption(dataLength, context) {
      if (!Number.isSafeInteger(dataLength) || dataLength < 0) {
        throw new KitError("KIT_INVALID_INTEGER", "dataLength must be a non-negative integer", {
          details: { dataLength },
        });
      }
      return connection
        .getMinimumBalanceForRentExemption(BigInt(dataLength), { commitment: COMMITMENT })
        .send(sendOptions(context));
    },

    async getLatestBlockhash(context) {
      const { value } = await connection
        .getLatestBlockhash({ commitment: COMMITMENT })
        .send(sendOptions(context));
      return Object.freeze({
        blockhash: value.blockhash,
        lastValidBlockHeight: value.lastValidBlockHeight,
      });
    },

    async sendTransaction(transaction, context) {
      return send(transaction, { preflightCommitment: COMMITMENT, skipPreflight: false }, context);
    },

    async sendTransactionWithConfig(transaction, config, context) {
      return send(
        transaction,
        {
          // An absent `preflightCommitment` resolves to `finalized` here and to
          // `confirmed` above, the same split `SolanaRpc` keeps.
          preflightCommitment: config.preflightCommitment ?? "finalized",
          skipPreflight: config.skipPreflight ?? false,
          ...(config.maxRetries === undefined ? {} : { maxRetries: BigInt(config.maxRetries) }),
          ...(config.minContextSlot === undefined ? {} : { minContextSlot: config.minContextSlot }),
        },
        context,
      );
    },

    async confirmTransaction(signature, context) {
      const { value } = await connection
        .getSignatureStatuses([kitSignature(signature)], {
          searchTransactionHistory: true,
        })
        .send(sendOptions(context));
      const status = value[0];
      if (status === null || status === undefined || status.err !== null) return false;
      return (
        status.confirmationStatus === "confirmed" ||
        status.confirmationStatus === "finalized" ||
        status.confirmations === null
      );
    },

    async transactOutputViewTags(signature, context) {
      const confirmed = await getConfirmedTransaction(signature, context);
      return viewTags(confirmed);
    },

    getMerkleProofs(): Promise<GetMerkleProofsResponse> {
      return Promise.reject(unsupported("getMerkleProofs"));
    },

    getNonInclusionProofs(): Promise<GetNonInclusionProofsResponse> {
      return Promise.reject(unsupported("getNonInclusionProofs"));
    },

    getInputMerkleProofs(): Promise<readonly SpendProof[]> {
      return Promise.reject(unsupported("getInputMerkleProofs"));
    },
  };
  return rpc;

  async function send(
    transaction: Parameters<Rpc["sendTransaction"]>[0],
    config: Readonly<{
      preflightCommitment: "processed" | "confirmed" | "finalized";
      skipPreflight: boolean;
      maxRetries?: bigint;
      minContextSlot?: bigint;
    }>,
    context: RequestContext | undefined,
  ): Promise<Signature> {
    const wire = getBase64EncodedWireTransaction(toKitTransaction(transaction));
    const submit = async (): Promise<Signature> =>
      (await connection
        .sendTransaction(wire, { ...config, encoding: "base64" })
        .send(sendOptions(context))) as string as Signature;

    const signature = await submit();
    // Resubmit while waiting if the leader dropped the first send; the payload
    // is unchanged, so the signature is too.
    const started = Date.now();
    for (;;) {
      if (await rpc.confirmTransaction(signature, context)) return signature;
      if (Date.now() - started >= confirmationTimeoutMs) {
        throw new KitError("KIT_CONFIRMATION_TIMEOUT", "transaction was not confirmed in time", {
          details: { signature },
        });
      }
      await sleep(CONFIRMATION_INTERVAL_MS, context);
      await submit().catch(() => signature);
    }
  }

  async function getConfirmedTransaction(
    signature: Signature,
    context: RequestContext | undefined,
  ) {
    const started = Date.now();
    for (;;) {
      const result = await connection
        .getTransaction(kitSignature(signature), {
          commitment: COMMITMENT,
          encoding: "json",
          maxSupportedTransactionVersion: 0,
        })
        .send(sendOptions(context));
      if (result !== null) return result;
      if (Date.now() - started >= confirmationTimeoutMs) {
        throw new KitError(
          "KIT_TRANSACTION_NOT_FOUND",
          "confirmed transaction was never returned",
          {
            details: { signature },
          },
        );
      }
      await sleep(CONFIRMATION_INTERVAL_MS, context);
    }
  }
}

/** Kit brands signatures; Zolana's are already base58 strings of the same bytes. */
function kitSignature(signature: Signature): Parameters<KitConnection["getTransaction"]>[0] {
  return signature as string as Parameters<KitConnection["getTransaction"]>[0];
}

type ConfirmedTransaction = Readonly<{
  meta: Readonly<{
    innerInstructions?:
      | readonly Readonly<{
          index: number;
          instructions: readonly RawInstruction[];
        }>[]
      | null;
    loadedAddresses?: Readonly<{ readonly: readonly string[]; writable: readonly string[] }>;
  }> | null;
  transaction: Readonly<{
    message: Readonly<{ accountKeys: readonly string[]; instructions: readonly RawInstruction[] }>;
  }>;
}>;

type RawInstruction = Readonly<{
  accounts: readonly number[];
  data: string;
  programIdIndex: number;
}>;

/**
 * Unique output view tags from the first shielded-pool `transact` in the
 * confirmed transaction (outer instruction or CPI). Outer instructions are
 * checked before each group's inner instructions.
 */
function viewTags(confirmed: ConfirmedTransaction): readonly Bytes32[] {
  const keys: readonly Address[] = [
    ...confirmed.transaction.message.accountKeys,
    ...(confirmed.meta?.loadedAddresses?.writable ?? []),
    ...(confirmed.meta?.loadedAddresses?.readonly ?? []),
  ].map((key) => key as Address);
  const inner = new Map(
    (confirmed.meta?.innerInstructions ?? []).map((entry) => [entry.index, entry.instructions]),
  );
  const outer = confirmed.transaction.message.instructions;
  for (const [index, instruction] of outer.entries()) {
    for (const candidate of [instruction, ...(inner.get(index) ?? [])]) {
      const tags = transactViewTags(keys, candidate);
      if (tags !== undefined) return tags;
    }
  }
  throw new KitError(
    "KIT_TRANSACT_NOT_FOUND",
    "no shielded-pool transact instruction was executed",
  );
}

function transactViewTags(
  keys: readonly Address[],
  instruction: RawInstruction,
): readonly Bytes32[] | undefined {
  if (keys[instruction.programIdIndex] !== SHIELDED_POOL_PROGRAM_ID) return undefined;
  const data = decodeBase58(instruction.data);
  if (data[0] !== InstructionTag.transact) return undefined;
  let decoded;
  try {
    decoded = transactInstructionDataCodec.decode(data.subarray(1));
  } catch (cause) {
    throw new KitError("KIT_TRANSACT_DECODE", "transact instruction data did not decode", {
      cause,
    });
  }
  const tags = decoded.outputs.map((output) => {
    switch (output.ownerTag.kind) {
      case "inline":
        return new Uint8Array(output.ownerTag.value) as Bytes32;
      case "p256SigningKey": {
        if (!decoded.p256SigningPkX) throw ownerTagUnresolved();
        return new Uint8Array(decoded.p256SigningPkX) as Bytes32;
      }
      case "account": {
        const index = instruction.accounts[output.ownerTag.index];
        const address = index === undefined ? undefined : keys[index];
        if (address === undefined) throw ownerTagUnresolved();
        return decodeBase58(address) as Bytes32;
      }
    }
  });
  const unique = new Map(tags.map((tag) => [encodeBase64(tag), tag]));
  return Object.freeze([...unique.values()].sort(compareBytes));
}

function compareBytes(left: Uint8Array, right: Uint8Array): number {
  const shared = Math.min(left.length, right.length);
  for (let index = 0; index < shared; index++) {
    const difference = (left[index] ?? 0) - (right[index] ?? 0);
    if (difference !== 0) return difference;
  }
  return left.length - right.length;
}

function ownerTagUnresolved(): KitError {
  return new KitError("KIT_OWNER_TAG", "an output's owner tag names an account the message lacks");
}

function account(
  value: Readonly<{ data: readonly [string, string]; lamports: bigint; owner: string }>,
): RpcAccount {
  return Object.freeze({
    owner: value.owner as Address,
    data: decodeBase64(value.data[0]),
    lamports: value.lamports,
  });
}

function sendOptions(context?: RequestContext): Readonly<{ abortSignal?: AbortSignal }> {
  const signal = composeSignal(context);
  return signal === undefined ? {} : { abortSignal: signal };
}

function composeSignal(context?: RequestContext): AbortSignal | undefined {
  if (context?.timeoutMs === undefined) return context?.signal;
  const deadline = AbortSignal.timeout(context.timeoutMs);
  if (context.signal === undefined) return deadline;
  const controller = new AbortController();
  for (const signal of [context.signal, deadline]) {
    if (signal.aborted) {
      controller.abort(signal.reason);
      break;
    }
    signal.addEventListener(
      "abort",
      () => {
        controller.abort(signal.reason);
      },
      { once: true },
    );
  }
  return controller.signal;
}

function sleep(milliseconds: number, context?: RequestContext): Promise<void> {
  return new Promise((resolve, reject) => {
    const signal = composeSignal(context);
    if (signal?.aborted === true) {
      reject(signal.reason as Error);
      return;
    }
    const timer = setTimeout(() => {
      resolve();
    }, milliseconds);
    signal?.addEventListener(
      "abort",
      () => {
        clearTimeout(timer);
        reject(signal.reason as Error);
      },
      { once: true },
    );
  });
}

function unsupported(method: string): KitError {
  return new KitError(
    "KIT_UNSUPPORTED_METHOD",
    `${method} is answered by an indexer, not a Solana node`,
    {
      details: { method },
    },
  );
}
