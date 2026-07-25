import type { Rpc } from "@zolana/client";
import type {
  Address,
  Bytes32,
  Instruction,
  RequestContext,
  Signature,
  Transaction,
} from "@zolana/interface";
import { ShieldedKeypair } from "@zolana/keypair";
import type { TransactionSigner } from "@zolana/wallet";

import { decodeBase58, encodeBase58 } from "./base58.js";
import { TestKitError } from "./error.js";

export interface NativeKeypair {
  readonly address: Address;
  sign(message: Uint8Array): Uint8Array;
}

/**
 * A compiled message plus the signer slots it reserved, in message order. The
 * order is what lets several keypairs each fill their own slot; a signer that
 * only knows its own key cannot work it out from `messageBytes` alone.
 */
export interface CompiledTransaction {
  readonly transaction: Transaction;
  readonly signers: readonly Address[];
}

export function nativeKeypair(seed: Bytes32): NativeKeypair {
  if (!(seed instanceof Uint8Array) || seed.length !== 32) {
    throw new TestKitError("TEST_KIT_INVALID_CONFIG", {
      details: {
        field: "seed",
        expected: 32,
        actual: seed instanceof Uint8Array ? seed.length : -1,
      },
    });
  }
  const keypair = ShieldedKeypair.fromEd25519(new Uint8Array(seed) as Bytes32, 0);
  return Object.freeze({
    address: keypair.shieldedAddress().solanaAddress() as unknown as Address,
    sign: (message: Uint8Array): Uint8Array => keypair.sign(message),
  });
}

/** Adapts a keypair to the single-signer interface the wallet package submits through. */
export function nativeSigner(keypair: NativeKeypair): TransactionSigner {
  return Object.freeze({
    address: keypair.address,
    signNativeTransaction: (transaction: Transaction): Promise<Transaction> =>
      Promise.resolve(
        Object.freeze({
          messageBytes: new Uint8Array(transaction.messageBytes),
          signatures: Object.freeze([
            encodeBase58(keypair.sign(transaction.messageBytes)) as Signature,
          ]),
        }),
      ),
  });
}

export function compileTransaction(
  input: Readonly<{
    feePayer: Address;
    recentBlockhash: string;
    instructions: readonly Instruction[];
  }>,
): CompiledTransaction {
  const accounts = new Map<
    Address,
    { address: Address; isSigner: boolean; isWritable: boolean; order: number }
  >();
  let order = 0;
  accounts.set(input.feePayer, {
    address: input.feePayer,
    isSigner: true,
    isWritable: true,
    order: order++,
  });
  for (const instruction of input.instructions) {
    for (const meta of instruction.accounts) {
      const existing = accounts.get(meta.address);
      accounts.set(meta.address, {
        address: meta.address,
        isSigner: (existing?.isSigner ?? false) || meta.isSigner,
        isWritable: (existing?.isWritable ?? false) || meta.isWritable,
        order: existing?.order ?? order++,
      });
    }
    if (!accounts.has(instruction.programAddress)) {
      accounts.set(instruction.programAddress, {
        address: instruction.programAddress,
        isSigner: false,
        isWritable: false,
        order: order++,
      });
    }
  }
  const ordered = [...accounts.values()].sort((left, right) => {
    if (left.address === input.feePayer) return -1;
    if (right.address === input.feePayer) return 1;
    if (left.isSigner !== right.isSigner) return left.isSigner ? -1 : 1;
    if (left.isWritable !== right.isWritable) return left.isWritable ? -1 : 1;
    const leftBytes = decodeBase58(left.address, "account");
    const rightBytes = decodeBase58(right.address, "account");
    for (let index = 0; index < leftBytes.length; index++) {
      if (leftBytes[index] !== rightBytes[index]) {
        return (leftBytes[index] ?? 0) - (rightBytes[index] ?? 0);
      }
    }
    return left.order - right.order;
  });
  const indexes = new Map(ordered.map((account, index) => [account.address, index]));
  const signers = ordered.filter((account) => account.isSigner);
  const readonlySigners = signers.filter((account) => !account.isWritable).length;
  const readonlyUnsigned = ordered.filter(
    (account) => !account.isSigner && !account.isWritable,
  ).length;
  const parts: Uint8Array[] = [
    Uint8Array.of(signers.length, readonlySigners, readonlyUnsigned),
    compactU16(ordered.length),
    ...ordered.map((account) => decodeBase58(account.address, "account")),
    decodeBase58(input.recentBlockhash, "recentBlockhash"),
    compactU16(input.instructions.length),
  ];
  for (const instruction of input.instructions) {
    const programIndex = indexes.get(instruction.programAddress);
    const accountIndexes = instruction.accounts.map((account) => indexes.get(account.address));
    if (programIndex === undefined || accountIndexes.some((index) => index === undefined)) {
      throw new TestKitError("TEST_KIT_INVALID_CONFIG", {
        details: { field: "instruction", reason: "missingAccount" },
      });
    }
    parts.push(
      Uint8Array.of(programIndex),
      compactU16(accountIndexes.length),
      Uint8Array.from(accountIndexes as number[]),
      compactU16(instruction.data.length),
      instruction.data,
    );
  }
  return Object.freeze({
    transaction: Object.freeze({
      messageBytes: concat(...parts),
      signatures: Object.freeze(signers.map((): Signature | undefined => undefined)),
    }),
    signers: Object.freeze(signers.map((account) => account.address)),
  });
}

export function signTransaction(
  compiled: CompiledTransaction,
  keypairs: readonly NativeKeypair[],
): Transaction {
  const byAddress = new Map(keypairs.map((keypair) => [keypair.address, keypair]));
  const signatures = compiled.signers.map((address) => {
    const keypair = byAddress.get(address);
    if (keypair === undefined) {
      throw new TestKitError("TEST_KIT_INVALID_CONFIG", {
        details: { field: "keypairs", reason: "missingSigner", address },
      });
    }
    return encodeBase58(keypair.sign(compiled.transaction.messageBytes)) as Signature;
  });
  return Object.freeze({
    messageBytes: new Uint8Array(compiled.transaction.messageBytes),
    signatures: Object.freeze(signatures),
  });
}

export async function sendAndConfirm(
  input: Readonly<{
    rpc: Rpc;
    feePayer: Address;
    instructions: readonly Instruction[];
    keypairs: readonly NativeKeypair[];
    timeoutMs?: number;
  }>,
  context?: RequestContext,
): Promise<Signature> {
  const latest = await input.rpc.getLatestBlockhash(context);
  const compiled = compileTransaction({
    feePayer: input.feePayer,
    recentBlockhash: latest.blockhash,
    instructions: input.instructions,
  });
  const signature = await input.rpc.sendTransaction(
    signTransaction(compiled, input.keypairs),
    context,
  );
  await confirm(
    {
      rpc: input.rpc,
      signature,
      ...(input.timeoutMs === undefined ? {} : { timeoutMs: input.timeoutMs }),
    },
    context,
  );
  return signature;
}

export async function confirm(
  input: Readonly<{ rpc: Rpc; signature: Signature; timeoutMs?: number }>,
  context?: RequestContext,
): Promise<void> {
  const timeoutMs = input.timeoutMs ?? 30_000;
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await input.rpc.confirmTransaction(input.signature, context)) return;
    await delay(100);
  }
  throw new TestKitError("TEST_KIT_TIMEOUT", {
    details: { stage: "confirm", signature: input.signature, timeoutMs },
  });
}

export async function requestAirdrop(
  input: Readonly<{ rpcUrl: URL; address: Address; lamports: bigint }>,
): Promise<Signature> {
  return await rpcCall<Signature>(input.rpcUrl, "requestAirdrop", [
    input.address,
    Number(input.lamports),
  ]);
}

/** Not on the `Rpc` interface, so the example asks the validator directly. */
export async function minimumBalanceForRentExemption(
  input: Readonly<{ rpcUrl: URL; space: number }>,
): Promise<bigint> {
  return BigInt(
    await rpcCall<number>(input.rpcUrl, "getMinimumBalanceForRentExemption", [input.space]),
  );
}

async function rpcCall<T>(url: URL, method: string, params: readonly unknown[]): Promise<T> {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const envelope = (await response.json()) as { result?: T; error?: unknown };
  if (envelope.result === undefined) {
    throw new TestKitError("TEST_KIT_RPC", {
      details: { method, error: JSON.stringify(envelope.error) },
    });
  }
  return envelope.result;
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => {
    const timeout = setTimeout(resolve, milliseconds);
    timeout.unref();
  });
}

function compactU16(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff) {
    throw new TestKitError("TEST_KIT_INVALID_CONFIG", {
      details: { field: "transactionLength" },
    });
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
  const result = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}
