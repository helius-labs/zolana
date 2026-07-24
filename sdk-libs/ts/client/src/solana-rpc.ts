import { transactInstructionDataCodec } from "@zolana/interface/codecs";
import {
  SHIELDED_POOL_PROGRAM_ID,
  type Address,
  type Bytes32,
  type RequestContext,
  type Signature,
  type Transaction,
} from "@zolana/interface";
import type { InputUtxoContext } from "@zolana/transaction";

import { ClientError } from "./error.js";
import {
  addressBytes,
  composeSignal,
  decodeBase58,
  decodeBase64,
  encodeBase64,
  requestError,
  signatureBytes,
} from "./internal.js";
import type {
  GetMerkleProofsResponse,
  GetNonInclusionProofsResponse,
  IndexerRpcConfig,
  Rpc,
  RpcAccount,
  SpendProof,
} from "./rpc.js";

type JsonObject = Record<string, unknown>;

export class SolanaRpc implements Rpc {
  readonly #fetch: typeof globalThis.fetch;
  readonly #url: URL;
  #requestId = 0;

  constructor(input: Readonly<{ url: URL | string; fetch?: typeof globalThis.fetch }>) {
    const candidate: unknown = input;
    if (typeof candidate !== "object" || candidate === null) {
      throw new ClientError("CLIENT_INVALID_CONFIG");
    }
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

  async sendTransaction(transaction: Transaction, context?: RequestContext): Promise<Signature> {
    const bytes = serializeTransaction(transaction);
    const result = await this.#call(
      "sendTransaction",
      [encodeBase64(bytes), { encoding: "base64", preflightCommitment: "confirmed" }],
      context,
    );
    const signature = string(result, "result") as Signature;
    signatureBytes(signature);
    return signature;
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
    signatureBytes(signature);
    const result = await this.#call(
      "getTransaction",
      [
        signature,
        {
          commitment: "confirmed",
          encoding: "json",
          maxSupportedTransactionVersion: 0,
        },
      ],
      context,
    );
    if (result === null) {
      throw new ClientError("CLIENT_RPC_TRANSACTION_NOT_FOUND", {
        details: { signature },
      });
    }
    return extractOutputViewTags(object(result, "result"));
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

  async #call(
    method: string,
    params: readonly unknown[],
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

function extractOutputViewTags(result: JsonObject): readonly Bytes32[] {
  const transaction = object(result["transaction"], "result.transaction");
  const message = object(transaction["message"], "result.transaction.message");
  const accountKeys = array(message["accountKeys"], "result.transaction.message.accountKeys").map(
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
  const instructions: unknown[] = [
    ...array(message["instructions"], "result.transaction.message.instructions"),
  ];
  const meta = result["meta"];
  if (meta !== null && meta !== undefined) {
    for (const group of array(object(meta, "result.meta")["innerInstructions"] ?? [], "inner")) {
      instructions.push(
        ...array(object(group, "inner group")["instructions"], "inner instructions"),
      );
    }
  }
  for (const raw of instructions) {
    const instruction = object(raw, "instruction");
    const programIndex = safeNumber(instruction["programIdIndex"], "programIdIndex");
    if (accountKeys[programIndex] !== SHIELDED_POOL_PROGRAM_ID) continue;
    const encoded = string(instruction["data"], "instruction.data");
    const data = decodeBase58(
      encoded,
      decodeBase58UnknownLength(encoded).length,
      "instruction.data",
    );
    if (data[0] !== 0) continue;
    let decoded;
    try {
      decoded = transactInstructionDataCodec.decode(data.subarray(1));
    } catch (cause) {
      throw new ClientError("CLIENT_RPC_TRANSACT_DECODE", { cause });
    }
    const accountIndexes = array(instruction["accounts"], "instruction.accounts").map((value) =>
      safeNumber(value, "account index"),
    );
    const tags = decoded.outputs.map((output) => {
      if (output.ownerTag.kind === "inline")
        return new Uint8Array(output.ownerTag.value) as Bytes32;
      if (output.ownerTag.kind === "p256SigningKey") {
        if (!decoded.p256SigningPkX) throw new ClientError("CLIENT_RPC_OWNER_TAG");
        return new Uint8Array(decoded.p256SigningPkX) as Bytes32;
      }
      const messageIndex = accountIndexes[output.ownerTag.index];
      const address = messageIndex === undefined ? undefined : accountKeys[messageIndex];
      if (address === undefined) throw new ClientError("CLIENT_RPC_OWNER_TAG");
      return addressBytes(address);
    });
    const unique = new Map(tags.map((tag) => [encodeBase64(tag), tag]));
    return Object.freeze([...unique.values()].sort((left, right) => compareBytes(left, right)));
  }
  throw new ClientError("CLIENT_RPC_TRANSACT_NOT_FOUND");
}

function decodeBase58UnknownLength(value: string): Uint8Array {
  for (let length = 1; length <= 1232; length++) {
    try {
      return decodeBase58(value, length, "instruction.data");
    } catch {
      continue;
    }
  }
  throw new ClientError("CLIENT_INVALID_BASE58");
}

function compareBytes(left: Uint8Array, right: Uint8Array): number {
  for (let index = 0; index < Math.min(left.length, right.length); index++) {
    const difference = (left[index] ?? 0) - (right[index] ?? 0);
    if (difference !== 0) return difference;
  }
  return left.length - right.length;
}

function compactU16(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff) {
    throw new ClientError("CLIENT_INVALID_INTEGER");
  }
  const bytes: number[] = [];
  let remaining = value;
  do {
    let byte = remaining & 0x7f;
    remaining >>>= 7;
    if (remaining !== 0) byte |= 0x80;
    bytes.push(byte);
  } while (remaining !== 0);
  return Uint8Array.from(bytes);
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
