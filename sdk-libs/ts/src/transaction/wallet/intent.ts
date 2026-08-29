import { getAddressEncoder } from "@solana/kit";
import { sha256 } from "@noble/hashes/sha2.js";

import type { Address, Bytes32, TransactInstructionData } from "../../interface/types.js";
import type { ShieldedAddress } from "../../keypair/shielded.js";

import type { PreparedTransfer, WithdrawalTarget } from "../instructions/transact.js";
import { SOL_MINT } from "../asset.js";

/** What the user approves, every field is bound into `intentHash`. */
export type TransactionIntent =
  | Readonly<{ kind: "transfer"; asset: Address; amount: bigint; recipient: ShieldedAddress }>
  | Readonly<{ kind: "withdrawal"; asset: Address; amount: bigint; recipient: Address }>
  | Readonly<{ kind: "split"; asset: Address; numOutputs: number; perOutputAmount: bigint }>
  | Readonly<{ kind: "merge"; asset: Address; numInputs: number; mergedAmount: bigint }>
  | Readonly<{
      kind: "ringTransfer";
      ringProgramId: Address;
      asset: Address;
      amount: bigint;
      recipient: ShieldedAddress;
      boundary: "entry" | "transfer" | "exit";
      /** Default-note value the transfer moves into the ring. */
      defaultFunding: bigint;
    }>
  | Readonly<{
      kind: "ringWithdrawal";
      ringProgramId: Address;
      asset: Address;
      amount: bigint;
      recipient: Address;
    }>;

/** An authority's receipt, valid only for the intent whose hash it carries. */
export interface IntentApproval {
  readonly intentHash: Bytes32;
}

const INTENT_DOMAIN = "zolana/intent/v1";
const KIND_TAGS = {
  transfer: 1,
  withdrawal: 2,
  split: 3,
  merge: 4,
  ringTransfer: 5,
  ringWithdrawal: 6,
} as const;
const BOUNDARY_TAGS = { entry: 0, transfer: 1, exit: 2 } as const;

const addressEncoder = getAddressEncoder();

/** Domain-separated sha256 over the fields in declaration order, each at a fixed width. */
export function intentHash(intent: TransactionIntent): Bytes32 {
  const hash = sha256.create();
  hash.update(new TextEncoder().encode(INTENT_DOMAIN));
  hash.update(Uint8Array.of(KIND_TAGS[intent.kind]));
  switch (intent.kind) {
    case "transfer":
      hash.update(addressBytes(intent.asset));
      hash.update(u64(intent.amount));
      hash.update(intent.recipient.toBytes());
      break;
    case "withdrawal":
      hash.update(addressBytes(intent.asset));
      hash.update(u64(intent.amount));
      hash.update(addressBytes(intent.recipient));
      break;
    case "split":
      hash.update(addressBytes(intent.asset));
      hash.update(Uint8Array.of(intent.numOutputs));
      hash.update(u64(intent.perOutputAmount));
      break;
    case "merge":
      hash.update(addressBytes(intent.asset));
      hash.update(Uint8Array.of(intent.numInputs));
      hash.update(u64(intent.mergedAmount));
      break;
    case "ringTransfer":
      hash.update(addressBytes(intent.ringProgramId));
      hash.update(addressBytes(intent.asset));
      hash.update(u64(intent.amount));
      hash.update(intent.recipient.toBytes());
      hash.update(Uint8Array.of(BOUNDARY_TAGS[intent.boundary]));
      hash.update(u64(intent.defaultFunding));
      break;
    case "ringWithdrawal":
      hash.update(addressBytes(intent.ringProgramId));
      hash.update(addressBytes(intent.asset));
      hash.update(u64(intent.amount));
      hash.update(addressBytes(intent.recipient));
      break;
  }
  return hash.digest() as Bytes32;
}

/** @internal Sol binds the recipient account, spl the recipient token account. */
export function withdrawalIntentRecipient(target: WithdrawalTarget): Address {
  return target.kind === "sol" ? target.recipient : target.recipientTokenAccount;
}

/** What a custom authority returns after showing the intent to its user. */
export function approveIntent(intent: TransactionIntent): IntentApproval {
  return Object.freeze({ intentHash: intentHash(intent) });
}

/** @internal */
export function checkIntentApproval(
  approval: IntentApproval,
  intent: TransactionIntent,
  mismatch: (field: string) => Error,
): void {
  if (typeof approval !== "object" || approval === null) throw mismatch("intentHash");
  const expected = intentHash(intent);
  const got = approval.intentHash;
  if (!(got instanceof Uint8Array) || got.length !== 32 || !equalBytes(got, expected)) {
    throw mismatch("intentHash");
  }
}

/** @internal */
export function checkPreparedTransfer(
  prepared: PreparedTransfer,
  intent: TransactionIntent,
  mismatch: (field: string) => Error,
): void {
  switch (intent.kind) {
    case "transfer":
      if (prepared.interfaceTransfers.length > 0) throw mismatch("settlements");
      checkRecipientOutputs(prepared, intent, undefined, mismatch);
      return;
    case "withdrawal":
      checkSettlement(prepared, intent, mismatch);
      return;
    case "ringTransfer": {
      if (prepared.interfaceTransfers.length > 0) throw mismatch("settlements");
      const outputRing = intent.boundary === "exit" ? undefined : intent.ringProgramId;
      checkRecipientOutputs(prepared, intent, outputRing, mismatch);
      if (preparedDefaultFunding(prepared) !== intent.defaultFunding) {
        throw mismatch("defaultFunding");
      }
      return;
    }
    case "ringWithdrawal":
      checkSettlement(prepared, intent, mismatch);
      if (preparedDefaultFunding(prepared) !== 0n) throw mismatch("inputs");
      return;
    default:
      throw mismatch("kind");
  }
}

/** @internal */
export function checkTransactData(
  data: TransactInstructionData,
  intent: TransactionIntent,
  mismatch: (field: string) => Error,
): void {
  if (intent.kind === "merge") throw mismatch("kind");
  if (intent.kind === "withdrawal" || intent.kind === "ringWithdrawal") {
    const transfer = data.interfaceTransfers[0];
    if (data.interfaceTransfers.length !== 1 || transfer === undefined) {
      throw mismatch("settlements");
    }
    const expectedKind = intent.asset === SOL_MINT ? "solWithdrawal" : "splWithdrawal";
    if (transfer.kind !== expectedKind) throw mismatch("settlements");
    if (transfer.amount !== intent.amount) throw mismatch("amount");
    return;
  }
  if (data.interfaceTransfers.length > 0) throw mismatch("settlements");
}

function checkRecipientOutputs(
  prepared: PreparedTransfer,
  intent: Readonly<{ recipient: ShieldedAddress; asset: Address; amount: bigint }>,
  outputRing: Address | undefined,
  mismatch: (field: string) => Error,
): void {
  const recipientBytes = intent.recipient.toBytes();
  let total = 0n;
  for (const output of prepared.outputs.slice(prepared.senderOutputCount)) {
    if (output.isDummy()) continue;
    if (
      output.ownerAddress === undefined ||
      !equalBytes(output.ownerAddress.toBytes(), recipientBytes)
    ) {
      throw mismatch("recipient");
    }
    if (output.asset !== intent.asset) throw mismatch("asset");
    if (output.ringProgramId !== outputRing) throw mismatch("ringProgramId");
    total += output.amount;
  }
  if (total !== intent.amount) throw mismatch("amount");
}

function checkSettlement(
  prepared: PreparedTransfer,
  intent: Readonly<{ asset: Address; amount: bigint; recipient: Address }>,
  mismatch: (field: string) => Error,
): void {
  if (prepared.outputs.slice(prepared.senderOutputCount).some((output) => !output.isDummy())) {
    throw mismatch("outputs");
  }
  const transfer = prepared.interfaceTransfers[0];
  if (prepared.interfaceTransfers.length !== 1 || transfer === undefined) {
    throw mismatch("settlements");
  }
  if (transfer.isDeposit || transfer.amount !== intent.amount) throw mismatch("amount");
  if (transfer.kind === "sol") {
    if (intent.asset !== SOL_MINT) throw mismatch("asset");
    if (transfer.userSolAccount !== intent.recipient) throw mismatch("recipient");
  } else {
    if (transfer.mint !== intent.asset) throw mismatch("asset");
    if (transfer.tokenAccount !== intent.recipient) throw mismatch("recipient");
  }
}

function preparedDefaultFunding(prepared: PreparedTransfer): bigint {
  return prepared.inputs
    .filter((input) => !input.isDummy() && input.utxo.ringProgramId === undefined)
    .reduce((sum, input) => sum + input.utxo.amount, 0n);
}

function addressBytes(value: Address): Uint8Array {
  return new Uint8Array(addressEncoder.encode(value));
}

function u64(value: bigint): Uint8Array {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, value, true);
  return bytes;
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index++) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}
