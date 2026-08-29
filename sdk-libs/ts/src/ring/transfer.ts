import { getSetComputeUnitLimitInstruction } from "@solana-program/compute-budget";
import {
  appendTransactionMessageInstructions,
  compileTransaction,
  compressTransactionMessageUsingAddressLookupTables,
  createTransactionMessage,
  pipe,
  setTransactionMessageFeePayer,
  setTransactionMessageLifetimeUsingBlockhash,
} from "@solana/kit";

import type { ZolanaClient } from "../client/client.js";
import { InstructionTag } from "../interface/program.js";
import { checkedTransactionSize } from "../interface/transaction-size.js";
import type {
  Address,
  RequestContext,
  Transaction,
  TransactInstructionData,
} from "../interface/types.js";
import { customRingPublicInputHash, parseAuditorMessage } from "../keypair/audit.js";
import type { P256PublicKey } from "../keypair/public-key.js";
import { ShieldedAddress } from "../keypair/shielded.js";
import { ViewingKey } from "../keypair/viewing-key.js";
import {
  ConfidentialTransfer,
  SppProofInputs,
  createExternalData,
  type PreparedTransfer,
} from "../transaction/instructions/transact.js";
import { EncryptedScheme, encodeOutputData } from "../transaction/serialization/codecs.js";
import { ProofInputUtxo } from "../transaction/utxo.js";
import type { SpendSession, WalletAuthority } from "../transaction/wallet/authority.js";
import { SOL_MINT, type AssetRegistry } from "../transaction/wallet/asset.js";
import type { Wallet, WalletUtxo } from "../transaction/wallet/state.js";
import { ownerSignerAddresses } from "../client/prover/assembly.js";
import { resolveWithdrawal } from "../wallet/actions.js";
import { resolveRegisteredAddress } from "../wallet/registry.js";

import { fetchRingProgramConfig } from "./config.js";
import { RingError, wrapRingError } from "./error.js";
import { ringTransactInstruction } from "./instructions.js";
import { fetchRingLookupTable } from "./lookup-table.js";

/** Rust `TRANSACT_COMPUTE_UNIT_LIMIT`. The custom-ring transact verifies two proofs. */
export const RING_TRANSACT_COMPUTE_UNIT_LIMIT = 1_400_000;
const MAX_INPUTS = 5;
/** Borsh `Encrypted` tag, its length, the scheme byte and the embedded P-256 key. */
const CONFIDENTIAL_BODY_OVERHEAD = 1 + 4 + 1 + 33;

export interface RingTransferTransactionParams {
  readonly client: ZolanaClient;
  readonly ringProgramId: Address;
  readonly wallet: Wallet;
  readonly authority: WalletAuthority;
  readonly feePayer: Address;
  readonly recipient: Address | ShieldedAddress;
  readonly asset?: Address;
  readonly amount: bigint;
  /** `"default"` funds only from default notes, a pure ring entry, `"ring-or-default"` mixes. */
  readonly inputs?: "ring" | "ring-or-default" | "default";
  /** Must be at least one slot old. */
  readonly lookupTable: Address;
  readonly computeUnitLimit?: number;
}

export interface RingWithdrawalTransactionParams {
  readonly client: ZolanaClient;
  readonly ringProgramId: Address;
  readonly wallet: Wallet;
  readonly authority: WalletAuthority;
  readonly feePayer: Address;
  /** Any Solana account. It needs no registry record and need not exist yet. */
  readonly recipient: Address;
  readonly asset?: Address;
  readonly amount: bigint;
  /** SPL Token or Token-2022 for non-SOL assets, the settlement lands in the recipient's ATA. */
  readonly splTokenProgram?: Address;
  /** Must be at least one slot old. */
  readonly lookupTable: Address;
  readonly computeUnitLimit?: number;
}

/** Mirrors Rust `CustomRingTransferInput`. `prepared` is what `ConfidentialTransfer.prepare` returned. */
export interface CustomRingTransferParams {
  readonly client: ZolanaClient;
  readonly ringProgramId: Address;
  readonly prepared: PreparedTransfer;
  /** The encryption capability of an open spend session. */
  readonly session: Pick<SpendSession, "encryptCustomRingTransfer">;
  readonly assets: AssetRegistry;
  readonly tree: Address;
}

/** Mirrors Rust `ProvenTransfer`. */
export interface ProvenRingTransfer {
  readonly data: TransactInstructionData;
  readonly proof: Uint8Array;
  readonly txViewingPublicKey: P256PublicKey;
  readonly payer: Address;
  readonly tree: Address;
  /** Non-payer ed25519 input owners, they sign the transaction beside the fee payer. */
  readonly ownerSigners: readonly Address[];
}

/** Returns a v0 transaction over `lookupTable`, signed by the fee payer only. */
export async function buildRingTransferTransaction(
  input: RingTransferTransactionParams,
  context?: RequestContext,
): Promise<Transaction> {
  return buildRingSendTransaction(input, "ring", context);
}

/**
 * Value leaves the ring to a default-ring note of the recipient, and the
 * custom-ring proof still covers the exit. Only ring-bound notes fund it, an
 * all-default transact must not reach the audit as an exit.
 */
export async function buildRingExitTransaction(
  input: Omit<RingTransferTransactionParams, "inputs">,
  context?: RequestContext,
): Promise<Transaction> {
  return buildRingSendTransaction({ ...input, inputs: "ring" }, "default", context);
}

async function buildRingSendTransaction(
  input: RingTransferTransactionParams,
  destination: "ring" | "default",
  context?: RequestContext,
): Promise<Transaction> {
  return input.authority.withSpendSession(async (session) => {
    let inputs: readonly ProofInputUtxo[] = [];
    try {
      const asset = input.asset ?? SOL_MINT;
      const nullifierKey = session.nullifierKey();
      const [recipient, address] = await Promise.all([
        resolveRecipient(input, context),
        input.authority.shieldedAddress(),
      ]);
      const selected = selectRingInputs(
        input.wallet,
        input.ringProgramId,
        asset,
        input.amount,
        input.inputs ?? "ring",
        input.client.tree,
      );
      inputs = selected.map(
        (entry) =>
          new ProofInputUtxo({
            utxo: entry.utxo,
            nullifierKey,
            ...(entry.dataHash === undefined ? {} : { dataHash: entry.dataHash }),
            ...(entry.ringDataHash === undefined ? {} : { ringDataHash: entry.ringDataHash }),
          }),
      );
      const transfer = new ConfidentialTransfer(address, inputs, input.feePayer)
        .withCompactChange()
        .withRingProgramId(input.ringProgramId);
      if (destination === "ring") {
        transfer.send(recipient, asset, input.amount);
      } else {
        transfer.sendDefaultRing(recipient, asset, input.amount);
      }
      // Change of a default note becomes ring bound.
      const defaultFunding = selected
        .filter((entry) => entry.utxo.ringProgramId === undefined)
        .reduce((sum, entry) => sum + entry.utxo.amount, 0n);
      const action =
        destination === "default" ? "exit" : defaultFunding > 0n ? "entry" : "transfer";
      const crossing =
        defaultFunding === 0n
          ? ""
          : `, moves ${String(defaultFunding)} ${assetLabel(asset)} of default notes into the ring`;
      await input.authority.requestUserApproval({
        solanaPublicKey: input.authority.solanaPublicKey(),
        summary: `ring ${action} of ${String(input.amount)} ${assetLabel(asset)} in ring ${input.ringProgramId} to a shielded address${crossing}`,
      });
      const proven = await proveCustomRingTransfer(
        {
          client: input.client,
          ringProgramId: input.ringProgramId,
          prepared: transfer.prepare(),
          session,
          assets: input.wallet.registry,
          tree: input.client.tree,
        },
        context,
      );
      const [instruction, tableAddresses, lifetime] = await Promise.all([
        ringTransactInstruction({
          ringProgramId: input.ringProgramId,
          payer: proven.payer,
          inputTree: proven.tree,
          outputTree: proven.tree,
          proof: proven.proof,
          data: proven.data,
          ...(proven.ownerSigners.length === 0 ? {} : { ownerSigners: proven.ownerSigners }),
        }),
        fetchRingLookupTable({
          client: input.client,
          ringProgramId: input.ringProgramId,
          address: input.lookupTable,
          tree: proven.tree,
        }),
        input.client.getLatestBlockhash(context),
      ]);
      const message = pipe(
        createTransactionMessage({ version: 0 }),
        (tx) => setTransactionMessageFeePayer(input.feePayer, tx),
        (tx) => setTransactionMessageLifetimeUsingBlockhash(lifetime, tx),
        (tx) =>
          appendTransactionMessageInstructions(
            [
              getSetComputeUnitLimitInstruction({
                units: input.computeUnitLimit ?? RING_TRANSACT_COMPUTE_UNIT_LIMIT,
              }),
              instruction,
            ],
            tx,
          ),
        (tx) =>
          compressTransactionMessageUsingAddressLookupTables(tx, {
            [input.lookupTable]: [...tableAddresses],
          }),
      );
      return checkedTransactionSize(compileTransaction(message), {
        inputs: proven.data.inputs.length,
        outputs: proven.data.outputs.length,
      });
    } catch (cause) {
      throw wrapRingError("RING_BUILD_TRANSFER", cause);
    } finally {
      for (const proofInput of inputs) proofInput.destroy();
    }
  });
}

/**
 * Value leaves the ring to a plain Solana account. The recipient, the amount
 * and the asset are public, and the custom-ring proof still covers the exit.
 */
export async function buildRingWithdrawalTransaction(
  input: RingWithdrawalTransactionParams,
  context?: RequestContext,
): Promise<Transaction> {
  return input.authority.withSpendSession(async (session) => {
    let inputs: readonly ProofInputUtxo[] = [];
    try {
      const asset = input.asset ?? SOL_MINT;
      const nullifierKey = session.nullifierKey();
      const [address, resolved] = await Promise.all([
        input.authority.shieldedAddress(),
        resolveWithdrawal(input.recipient, asset, input.splTokenProgram),
      ]);
      const selected = selectRingInputs(
        input.wallet,
        input.ringProgramId,
        asset,
        input.amount,
        "ring",
        input.client.tree,
      );
      inputs = selected.map(
        (entry) =>
          new ProofInputUtxo({
            utxo: entry.utxo,
            nullifierKey,
            ...(entry.dataHash === undefined ? {} : { dataHash: entry.dataHash }),
            ...(entry.ringDataHash === undefined ? {} : { ringDataHash: entry.ringDataHash }),
          }),
      );
      const transfer = new ConfidentialTransfer(address, inputs, input.feePayer)
        .withCompactChange()
        .withRingProgramId(input.ringProgramId);
      transfer.withdraw(asset, input.amount, resolved.target);
      await input.authority.requestUserApproval({
        solanaPublicKey: input.authority.solanaPublicKey(),
        summary: `public withdrawal of ${String(input.amount)} ${assetLabel(asset)} from ring ${input.ringProgramId} to ${input.recipient}`,
      });
      const proven = await proveCustomRingTransfer(
        {
          client: input.client,
          ringProgramId: input.ringProgramId,
          prepared: transfer.prepare(),
          session,
          assets: input.wallet.registry,
          tree: input.client.tree,
        },
        context,
      );
      const [instruction, tableAddresses, lifetime] = await Promise.all([
        ringTransactInstruction({
          ringProgramId: input.ringProgramId,
          payer: proven.payer,
          inputTree: proven.tree,
          outputTree: proven.tree,
          proof: proven.proof,
          data: proven.data,
          ...(proven.ownerSigners.length === 0 ? {} : { ownerSigners: proven.ownerSigners }),
          withdrawal: resolved.accounts,
        }),
        fetchRingLookupTable({
          client: input.client,
          ringProgramId: input.ringProgramId,
          address: input.lookupTable,
          tree: proven.tree,
        }),
        input.client.getLatestBlockhash(context),
      ]);
      const message = pipe(
        createTransactionMessage({ version: 0 }),
        (tx) => setTransactionMessageFeePayer(input.feePayer, tx),
        (tx) => setTransactionMessageLifetimeUsingBlockhash(lifetime, tx),
        (tx) =>
          appendTransactionMessageInstructions(
            [
              getSetComputeUnitLimitInstruction({
                units: input.computeUnitLimit ?? RING_TRANSACT_COMPUTE_UNIT_LIMIT,
              }),
              instruction,
            ],
            tx,
          ),
        (tx) =>
          compressTransactionMessageUsingAddressLookupTables(tx, {
            [input.lookupTable]: [...tableAddresses],
          }),
      );
      return checkedTransactionSize(compileTransaction(message), {
        inputs: proven.data.inputs.length,
        outputs: proven.data.outputs.length,
      });
    } catch (cause) {
      throw wrapRingError("RING_BUILD_WITHDRAWAL", cause);
    } finally {
      for (const proofInput of inputs) proofInput.destroy();
    }
  });
}

/** Mirrors Rust `CustomRingTransfer::prove`, the auditor message enters the external data before the SPP proof folds it into `privateTxHash`. */
export async function proveCustomRingTransfer(
  input: CustomRingTransferParams,
  context?: RequestContext,
): Promise<ProvenRingTransfer> {
  // The prover fetches merkle proofs from the client tree only.
  if (input.tree !== input.client.tree) {
    throw new RingError("RING_TREE_MISMATCH", {
      details: { tree: input.tree, clientTree: input.client.tree },
    });
  }
  const config = await fetchRingProgramConfig(input.client, input.ringProgramId, context);
  // A padded change slot pushes the custom-ring instruction past the packet limit
  // even behind an address lookup table.
  if (input.prepared.changeLayout !== "compact") {
    throw new RingError("RING_PADDED_CHANGE", {
      details: { remedy: "prepare the transfer with ConfidentialTransfer.withCompactChange" },
    });
  }
  const prepared = input.prepared;
  checkRingMembership(prepared, input.ringProgramId);
  const encrypted = await input.session.encryptCustomRingTransfer({
    firstNullifier: prepared.firstNullifier,
    outputs: prepared.outputs,
    assets: input.assets,
    auditorPublicKey: config.auditorPublicKey,
  });
  try {
    const proofInputs = frameDummyOutputs(
      prepared.finalize({
        txViewingPublicKey: encrypted.txViewingPublicKey,
        salt: encrypted.salt,
        payload: encrypted.payload,
        messages: [encrypted.auditorMessage],
        instructionDiscriminator: InstructionTag.ringTransact,
      }),
    );
    const data = await input.client.proveRingTransact(
      proofInputs,
      input.ringProgramId,
      undefined,
      context,
    );
    const proof = await input.client.proveCustomRing(
      {
        publicInputHash: customRingPublicInputHash({
          privateTxHash: data.privateTxHash,
          txViewingPublicKey: encrypted.txViewingPublicKey,
          auditorPublicKey: config.auditorPublicKey,
          message: parseAuditorMessage(encrypted.auditorMessage.data),
        }),
        privateTxHash: data.privateTxHash,
        txViewingSecret: encrypted.audit.txViewingSecret,
        ephemeralSecret: encrypted.audit.ephemeralSecret,
        auditorPublicKey: config.auditorPublicKey.toUncompressed(),
      },
      context,
    );
    return Object.freeze({
      data,
      proof,
      txViewingPublicKey: encrypted.txViewingPublicKey,
      payer: prepared.payer,
      tree: input.tree,
      ownerSigners: ownerSignerAddresses(prepared.inputs, prepared.payer),
    });
  } finally {
    encrypted.audit.txViewingSecret.fill(0);
    encrypted.audit.ephemeralSecret.fill(0);
  }
}

/** Mirrors Rust `RingMembership::validate`. @internal */
export function checkRingMembership(prepared: PreparedTransfer, ringProgramId: Address): void {
  const notes = [
    ...prepared.inputs.map((input) => ({
      ring: input.utxo.ringProgramId,
      data: input.ringDataHash,
    })),
    ...prepared.outputs.map((output) => ({
      ring: output.ringProgramId,
      data: output.ringDataHash,
    })),
  ];
  const foreign = notes.find((note) => note.ring !== undefined && note.ring !== ringProgramId);
  if (foreign?.ring !== undefined) {
    throw new RingError("RING_FOREIGN_RING", { details: { ringProgramId: foreign.ring } });
  }
  if (notes.some((note) => note.ring === undefined && note.data !== undefined)) {
    throw new RingError("RING_DATA_OUTSIDE_RING");
  }
}

/** A dummy copies the length of a real slot with its ring binding, else of the first real slot, mirrors Rust `frame_dummy_outputs`. */
export function frameDummyOutputs(proofInputs: SppProofInputs): SppProofInputs {
  const external = proofInputs.externalData;
  const templates = proofInputs.outputs.flatMap((output, index) => {
    if (output.isDummy()) return [];
    const length = external.outputs[index]?.data?.length;
    if (length === undefined) {
      throw new RingError("RING_BUILD_TRANSFER", { details: { reason: "invalid dummy output" } });
    }
    return [{ inRing: output.ringProgramId !== undefined, length }];
  });
  const outputs = external.outputs.map((encoded, index) => {
    const output = proofInputs.outputs[index];
    if (output === undefined || !output.isDummy()) return encoded;
    const inRing = output.ringProgramId !== undefined;
    const template = templates.find((candidate) => candidate.inRing === inRing) ?? templates[0];
    const ciphertextLength =
      template === undefined ? 0 : template.length - CONFIDENTIAL_BODY_OVERHEAD;
    if (template === undefined || ciphertextLength <= 0) {
      throw new RingError("RING_BUILD_TRANSFER", { details: { reason: "invalid dummy output" } });
    }
    const key = ViewingKey.generate();
    const body = new Uint8Array(33 + ciphertextLength);
    body.set(key.publicKey().toBytes(), 0);
    key.destroy();
    globalThis.crypto.getRandomValues(body.subarray(33));
    const scheme = inRing ? EncryptedScheme.ringConfidential : EncryptedScheme.confidential;
    return { ...encoded, data: encodeOutputData(scheme, body, "encrypted") };
  });
  return new SppProofInputs({
    payer: proofInputs.payer,
    inputUtxos: proofInputs.inputUtxos,
    outputs: proofInputs.outputs,
    externalData: createExternalData({ ...external, outputs }),
  });
}

async function resolveRecipient(
  input: RingTransferTransactionParams,
  context: RequestContext | undefined,
): Promise<ShieldedAddress> {
  if (input.recipient instanceof ShieldedAddress) return input.recipient;
  const registered = await resolveRegisteredAddress(
    { rpc: input.client, owner: input.recipient },
    context,
  );
  if (registered === undefined) {
    throw new RingError("RING_BUILD_TRANSFER", {
      details: { reason: "recipient not registered", recipient: input.recipient },
    });
  }
  return registered.address;
}

function assetLabel(asset: Address): string {
  return asset === SOL_MINT ? "SOL" : asset;
}

/**
 * Notes on `tree` the mode admits.
 *
 * @internal Exported for tests only.
 */
export function selectRingInputs(
  wallet: Wallet,
  ringProgramId: Address,
  asset: Address,
  amount: bigint,
  inputs: "ring" | "ring-or-default" | "default",
  tree: Address,
): readonly WalletUtxo[] {
  // Zero selects a note whose whole change would cross the ring boundary.
  if (amount <= 0n) {
    throw new RingError("RING_ZERO_AMOUNT", { details: { asset } });
  }
  const eligible = (entry: WalletUtxo): boolean => {
    if (entry.utxo.ringProgramId === ringProgramId) return inputs !== "default";
    return (
      inputs !== "ring" &&
      entry.utxo.ringProgramId === undefined &&
      entry.ringDataHash === undefined
    );
  };
  // Largest first, a fragmented balance covers with the fewest notes.
  const candidates = wallet
    .utxos()
    .filter(
      (entry) =>
        !entry.spent &&
        entry.utxo.asset === asset &&
        entry.outputContext.tree === tree &&
        eligible(entry),
    )
    .sort((left, right) =>
      left.utxo.amount < right.utxo.amount ? 1 : left.utxo.amount > right.utxo.amount ? -1 : 0,
    );
  const total = candidates.reduce((sum, entry) => sum + entry.utxo.amount, 0n);
  const selected: WalletUtxo[] = [];
  let available = 0n;
  for (const entry of candidates.slice(0, MAX_INPUTS)) {
    selected.push(entry);
    available += entry.utxo.amount;
    if (available >= amount) break;
  }
  if (available < amount) {
    if (total >= amount) {
      throw new RingError("RING_TOO_MANY_INPUTS", {
        details: { selected: candidates.length, maximum: MAX_INPUTS },
      });
    }
    throw new RingError("RING_INSUFFICIENT_BALANCE", {
      details: { asset, requested: amount.toString(), available: total.toString() },
    });
  }
  return Object.freeze(selected);
}
