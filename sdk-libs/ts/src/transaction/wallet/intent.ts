import { getAddressEncoder, isAddress } from "@solana/kit";
import { sha256 } from "@noble/hashes/sha2.js";

import type {
  Address,
  Bytes32,
  TransactInstructionData,
  TransactWithdrawal,
} from "../../interface/types.js";
import { ShieldedAddress } from "../../keypair/shielded.js";

import type { PreparedTransfer, WithdrawalTarget } from "../instructions/transact.js";
import { SOL_MINT } from "../asset.js";
import { TransactionError } from "../error.js";

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
    }>
  | Readonly<{
      kind: "ringEntry";
      ringProgramId: Address;
      asset: Address;
      amount: bigint;
    }>;

/**
 * An authority's receipt, valid only for the intent whose hash it carries.
 * It binds the economic operation, not the compiled message, final signing
 * trusts the assembling client.
 */
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
  ringEntry: 7,
} as const;
const BOUNDARY_TAGS = { entry: 0, transfer: 1, exit: 2 } as const;

const addressEncoder = getAddressEncoder();

/** Domain-separated sha256 over the fields in declaration order, each at a fixed width. */
export function intentHash(intent: TransactionIntent): Bytes32 {
  checkTransactionIntent(
    intent,
    (field) => new TransactionError("TRANSACTION_DESERIALIZE", { field: `intent.${field}` }),
  );
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
    case "ringEntry":
      hash.update(addressBytes(intent.ringProgramId));
      hash.update(addressBytes(intent.asset));
      hash.update(u64(intent.amount));
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
    case "ringEntry":
      checkRingEntry(prepared, intent, mismatch);
      return;
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

type OutputsView = Readonly<{
  outputs: PreparedTransfer["outputs"];
  senderOutputCount: number;
}>;

type SettlementView = OutputsView &
  Readonly<{ interfaceTransfers: PreparedTransfer["interfaceTransfers"] }>;

function checkRecipientOutputs(
  prepared: OutputsView,
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
  prepared: SettlementView,
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

function checkRingEntry(
  prepared: PreparedTransfer,
  intent: Extract<TransactionIntent, { kind: "ringEntry" }>,
  mismatch: (field: string) => Error,
): void {
  if (prepared.interfaceTransfers.length > 0) throw mismatch("settlements");
  if (prepared.inputs.some((input) => input.utxo.ringProgramId !== undefined)) {
    throw mismatch("inputs");
  }
  const owner = prepared.owner.toBytes();
  for (const output of prepared.outputs.slice(0, prepared.senderOutputCount)) {
    if (output.isDummy()) continue;
    if (
      output.ownerAddress === undefined ||
      !equalBytes(output.ownerAddress.toBytes(), owner) ||
      output.asset !== intent.asset ||
      output.ringProgramId !== undefined
    ) {
      throw mismatch("change");
    }
  }
  let entered = 0n;
  for (const output of prepared.outputs.slice(prepared.senderOutputCount)) {
    if (output.isDummy()) continue;
    if (
      output.ownerAddress === undefined ||
      !equalBytes(output.ownerAddress.toBytes(), owner) ||
      output.asset !== intent.asset ||
      output.ringProgramId !== intent.ringProgramId
    ) {
      throw mismatch("outputs");
    }
    entered += output.amount;
  }
  if (entered !== intent.amount) throw mismatch("amount");
}

const U64_MAX = 0xffff_ffff_ffff_ffffn;

/** @internal Structural intents arrive from callers, no field is trusted before it is checked. */
export function checkTransactionIntent(
  intent: TransactionIntent,
  mismatch: (field: string) => Error,
): void {
  if (typeof intent !== "object" || intent === null) throw mismatch("kind");
  checkMint(intent.asset, mismatch);
  switch (intent.kind) {
    case "transfer":
      checkIntentFields(intent, ["kind", "asset", "amount", "recipient"], mismatch);
      checkAmount(intent.amount, mismatch);
      checkShieldedRecipient(intent.recipient, mismatch);
      return;
    case "withdrawal":
      checkIntentFields(intent, ["kind", "asset", "amount", "recipient"], mismatch);
      checkAmount(intent.amount, mismatch);
      checkAccount(intent.recipient, "recipient", mismatch);
      return;
    case "split":
      checkIntentFields(intent, ["kind", "asset", "numOutputs", "perOutputAmount"], mismatch);
      checkCount(intent.numOutputs, "numOutputs", mismatch);
      checkAmount(intent.perOutputAmount, mismatch);
      return;
    case "merge":
      checkIntentFields(intent, ["kind", "asset", "numInputs", "mergedAmount"], mismatch);
      checkCount(intent.numInputs, "numInputs", mismatch);
      checkAmount(intent.mergedAmount, mismatch);
      return;
    case "ringTransfer":
      checkIntentFields(
        intent,
        ["kind", "ringProgramId", "asset", "amount", "recipient", "boundary", "defaultFunding"],
        mismatch,
      );
      checkAccount(intent.ringProgramId, "ringProgramId", mismatch);
      checkAmount(intent.amount, mismatch);
      checkShieldedRecipient(intent.recipient, mismatch);
      if (!(intent.boundary in BOUNDARY_TAGS)) throw mismatch("boundary");
      if (
        typeof intent.defaultFunding !== "bigint" ||
        intent.defaultFunding < 0n ||
        intent.defaultFunding > U64_MAX
      ) {
        throw mismatch("defaultFunding");
      }
      return;
    case "ringWithdrawal":
      checkIntentFields(
        intent,
        ["kind", "ringProgramId", "asset", "amount", "recipient"],
        mismatch,
      );
      checkAccount(intent.ringProgramId, "ringProgramId", mismatch);
      checkAmount(intent.amount, mismatch);
      checkAccount(intent.recipient, "recipient", mismatch);
      return;
    case "ringEntry":
      checkIntentFields(intent, ["kind", "ringProgramId", "asset", "amount"], mismatch);
      checkAccount(intent.ringProgramId, "ringProgramId", mismatch);
      checkAmount(intent.amount, mismatch);
      return;
    default:
      throw mismatch("kind");
  }
}

function checkIntentFields(
  intent: object,
  fields: readonly string[],
  mismatch: (field: string) => Error,
): void {
  const allowed = new Set(fields);
  const extra = Reflect.ownKeys(intent).find((key) => typeof key !== "string" || !allowed.has(key));
  if (extra !== undefined) throw mismatch("shape");
}

/** @internal The fields the client rebinds to the approved intent before anything is proved. */
export interface AuthorizedIntentView {
  readonly proofInputs: Readonly<{
    inputUtxos: PreparedTransfer["inputs"];
    outputs: PreparedTransfer["outputs"];
    externalData: Readonly<{ interfaceTransfers: PreparedTransfer["interfaceTransfers"] }>;
  }>;
  readonly intent: TransactionIntent;
  readonly withdrawal?: TransactWithdrawal | undefined;
  readonly senderOutputCount: number;
  readonly owner: ShieldedAddress;
}

/** @internal A forged or drifted authorization must fail here, never reach the prover. */
export function checkAuthorizedBinding(
  authorized: AuthorizedIntentView,
  mismatch: (field: string) => Error,
): void {
  const intent = authorized.intent;
  checkTransactionIntent(intent, mismatch);
  if (!(authorized.owner instanceof ShieldedAddress)) throw mismatch("owner");
  if (
    !Number.isInteger(authorized.senderOutputCount) ||
    authorized.senderOutputCount < 0 ||
    authorized.senderOutputCount > authorized.proofInputs.outputs.length
  ) {
    throw mismatch("senderOutputCount");
  }
  for (const input of authorized.proofInputs.inputUtxos) {
    if (!input.isDummy() && input.utxo.ringProgramId !== undefined) throw mismatch("inputs");
  }
  const view: SettlementView = {
    outputs: authorized.proofInputs.outputs,
    senderOutputCount: authorized.senderOutputCount,
    interfaceTransfers: authorized.proofInputs.externalData.interfaceTransfers,
  };
  switch (intent.kind) {
    case "transfer":
      if (authorized.withdrawal !== undefined) throw mismatch("withdrawal");
      if (view.interfaceTransfers.length > 0) throw mismatch("settlements");
      checkRecipientOutputs(view, intent, undefined, mismatch);
      checkChangeOutputs(view, authorized.owner, intent.asset, mismatch);
      return;
    case "withdrawal":
      checkSettlement(view, intent, mismatch);
      checkChangeOutputs(view, authorized.owner, intent.asset, mismatch);
      checkWithdrawalAccounts(authorized.withdrawal, intent, mismatch);
      return;
    case "split": {
      if (authorized.withdrawal !== undefined) throw mismatch("withdrawal");
      if (view.interfaceTransfers.length > 0) throw mismatch("settlements");
      const ownerBytes = authorized.owner.toBytes();
      let funded = 0;
      for (const output of view.outputs) {
        if (output.isDummy()) continue;
        if (
          output.ownerAddress === undefined ||
          !equalBytes(output.ownerAddress.toBytes(), ownerBytes)
        ) {
          throw mismatch("recipient");
        }
        if (output.asset !== intent.asset) throw mismatch("asset");
        if (output.ringProgramId !== undefined) throw mismatch("ringProgramId");
        // Zero-amount slots are the split's padding, only funded parts count.
        if (output.amount === 0n) continue;
        funded++;
        if (output.amount !== intent.perOutputAmount) throw mismatch("amount");
      }
      if (funded !== intent.numOutputs) throw mismatch("numOutputs");
      return;
    }
    default:
      throw mismatch("kind");
  }
}

function checkChangeOutputs(
  view: OutputsView,
  owner: ShieldedAddress,
  asset: Address,
  mismatch: (field: string) => Error,
): void {
  const ownerBytes = owner.toBytes();
  for (const output of view.outputs.slice(0, view.senderOutputCount)) {
    if (output.isDummy()) continue;
    if (
      output.ownerAddress === undefined ||
      !equalBytes(output.ownerAddress.toBytes(), ownerBytes) ||
      output.asset !== asset ||
      output.ringProgramId !== undefined
    ) {
      throw mismatch("change");
    }
  }
}

function checkWithdrawalAccounts(
  withdrawal: TransactWithdrawal | undefined,
  intent: Readonly<{ asset: Address; recipient: Address }>,
  mismatch: (field: string) => Error,
): void {
  if (withdrawal === undefined) throw mismatch("withdrawal");
  if (withdrawal.kind === "sol") {
    if (intent.asset !== SOL_MINT) throw mismatch("asset");
    if (withdrawal.recipient !== intent.recipient) throw mismatch("recipient");
    return;
  }
  if (intent.asset === SOL_MINT || withdrawal.mint !== intent.asset) throw mismatch("asset");
  if (withdrawal.recipientTokenAccount !== intent.recipient) throw mismatch("recipient");
}

function checkMint(value: Address, mismatch: (field: string) => Error): void {
  checkAccount(value, "asset", mismatch);
}

function checkAccount(value: Address, field: string, mismatch: (field: string) => Error): void {
  if (typeof value !== "string" || !isAddress(value)) throw mismatch(field);
}

function checkShieldedRecipient(
  recipient: ShieldedAddress,
  mismatch: (field: string) => Error,
): void {
  if (!(recipient instanceof ShieldedAddress)) throw mismatch("recipient");
}

function checkAmount(value: bigint, mismatch: (field: string) => Error): void {
  if (typeof value !== "bigint" || value < 1n || value > U64_MAX) throw mismatch("amount");
}

/** One byte in `intentHash`, a wider count would alias another approval. */
function checkCount(value: number, field: string, mismatch: (field: string) => Error): void {
  if (!Number.isInteger(value) || value < 1 || value > 255) throw mismatch(field);
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
