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
  Bytes32,
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
  WithdrawalTarget,
  SppProofInputs,
  createExternalData,
  type PreparedTransfer,
} from "../transaction/instructions/transact.js";
import { EncryptedScheme, encodeOutputData } from "../transaction/serialization/codecs.js";
import { ProofInputUtxo } from "../transaction/utxo.js";
import type { PrivateTransactionAuthority } from "../transaction/wallet/authority.js";
import { SOL_MINT, type AssetRegistry } from "../transaction/wallet/asset.js";
import type { Wallet, WalletUtxo } from "../transaction/wallet/state.js";
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
  readonly wallet: Wallet;
  readonly authority: PrivateTransactionAuthority;
  readonly feePayer: Address;
  readonly recipient: Address | ShieldedAddress;
  readonly asset?: Address;
  readonly amount: bigint;
  /** `null` is the default pool; an address is the custom-ring program. */
  readonly sourceRing: Address | null;
  /** `null` is the default pool; an address is the custom-ring program. */
  readonly destinationRing: Address | null;
  /** Exact default-pool inputs when entering this ring. */
  readonly inputCommitments?: readonly Bytes32[];
  /** Must be at least one slot old. */
  readonly lookupTable: Address;
  readonly computeUnitLimit?: number;
}

export interface RingWithdrawalTransactionParams {
  readonly client: ZolanaClient;
  readonly ringProgramId: Address;
  readonly wallet: Wallet;
  readonly authority: PrivateTransactionAuthority;
  readonly feePayer: Address;
  /** Any Solana account. It needs no registry record and need not exist yet. */
  readonly recipient: Address;
  readonly asset?: Address;
  readonly amount: bigint;
  /** Must be at least one slot old. */
  readonly lookupTable: Address;
  readonly computeUnitLimit?: number;
}

/** Mirrors Rust `CustomRingTransferInput`. `prepared` is what `ConfidentialTransfer.prepare` returned. */
export interface CustomRingTransferParams {
  readonly client: ZolanaClient;
  readonly ringProgramId: Address;
  readonly prepared: PreparedTransfer;
  readonly authority: PrivateTransactionAuthority;
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
}

/** Returns a v0 transaction over `lookupTable`, signed by the fee payer only. */
export async function buildRingTransferTransaction(
  input: RingTransferTransactionParams,
  context?: RequestContext,
): Promise<Transaction> {
  try {
    const asset = input.asset ?? SOL_MINT;
    const ringProgramId = input.sourceRing ?? input.destinationRing;
    if (
      ringProgramId === null ||
      (input.sourceRing !== null &&
        input.destinationRing !== null &&
        input.sourceRing !== input.destinationRing)
    ) {
      throw new RingError("RING_BUILD_TRANSFER", {
        details: { reason: "a transition must involve exactly one custom ring" },
      });
    }
    const [recipient, address, nullifierKey] = await Promise.all([
      resolveRecipient(input, context),
      input.authority.shieldedAddress(),
      input.authority.spendNullifierKey(),
    ]);
    const selected =
      input.sourceRing !== null
        ? selectRingInputs(input.wallet, ringProgramId, asset, input.amount)
        : selectExactDefaultInputs(input.wallet, asset, input.amount, input.inputCommitments ?? []);
    const inputs = selected.map(
      ({ entry }) =>
        new ProofInputUtxo({
          utxo: entry.utxo,
          nullifierKey,
          ...(entry.dataHash === undefined ? {} : { dataHash: entry.dataHash }),
          ...(entry.ringDataHash === undefined ? {} : { ringDataHash: entry.ringDataHash }),
        }),
    );
    const transfer = new ConfidentialTransfer(address, inputs, input.feePayer)
      .withCompactChange()
      .withRingProgramId(ringProgramId);
    if (input.destinationRing !== null) transfer.send(recipient, asset, input.amount);
    else transfer.sendDefaultRing(recipient, asset, input.amount);
    const tree = selected[0]?.tree ?? input.client.tree;
    await input.authority.requestUserApproval({
      solanaPublicKey: input.authority.solanaPublicKey(),
      summary: `ring transfer of ${String(input.amount)} to a shielded address`,
    });
    const proven = await proveCustomRingTransfer(
      {
        client: input.client,
        ringProgramId,
        prepared: transfer.prepare(),
        authority: input.authority,
        assets: input.wallet.registry,
        tree,
      },
      context,
    );
    const [instruction, tableAddresses, lifetime] = await Promise.all([
      ringTransactInstruction({
        ringProgramId,
        payer: proven.payer,
        inputTree: proven.tree,
        outputTree: proven.tree,
        proof: proven.proof,
        data: proven.data,
      }),
      fetchRingLookupTable({
        client: input.client,
        ringProgramId,
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
  }
}

/**
 * Value leaves the ring to a plain Solana account. The recipient, the amount
 * and the asset are public, and the custom-ring proof still covers the exit.
 */
export async function buildRingWithdrawalTransaction(
  input: RingWithdrawalTransactionParams,
  context?: RequestContext,
): Promise<Transaction> {
  try {
    const asset = input.asset ?? SOL_MINT;
    if (asset !== SOL_MINT) {
      throw new RingError("RING_BUILD_WITHDRAWAL", { details: { reason: "SOL only" } });
    }
    const [address, nullifierKey] = await Promise.all([
      input.authority.shieldedAddress(),
      input.authority.spendNullifierKey(),
    ]);
    const selected = selectRingInputs(input.wallet, input.ringProgramId, asset, input.amount);
    const inputs = selected.map(
      ({ entry }) =>
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
    transfer.withdraw(asset, input.amount, WithdrawalTarget.sol({ recipient: input.recipient }));
    const tree = selected[0]?.tree ?? input.client.tree;
    await input.authority.requestUserApproval({
      solanaPublicKey: input.authority.solanaPublicKey(),
      summary: `public withdrawal of ${String(input.amount)} from the ring to ${input.recipient}`,
    });
    const proven = await proveCustomRingTransfer(
      {
        client: input.client,
        ringProgramId: input.ringProgramId,
        prepared: transfer.prepare(),
        authority: input.authority,
        assets: input.wallet.registry,
        tree,
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
        withdrawal: { kind: "sol", recipient: input.recipient },
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
  }
}

/** Mirrors Rust `CustomRingTransfer::prove`, the auditor message enters the external data before the SPP proof folds it into `privateTxHash`. */
export async function proveCustomRingTransfer(
  input: CustomRingTransferParams,
  context?: RequestContext,
): Promise<ProvenRingTransfer> {
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
  const encrypted = await input.authority.encryptCustomRingTransfer({
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

interface SelectedInput {
  readonly entry: WalletUtxo;
  readonly tree: Address;
}

/** The ring circuit binds every real input to the ring, so notes of other rings are not candidates. */
function selectRingInputs(
  wallet: Wallet,
  ringProgramId: Address,
  asset: Address,
  amount: bigint,
): readonly SelectedInput[] {
  const candidates = wallet
    .utxos()
    .filter(
      (entry) =>
        !entry.spent && entry.utxo.asset === asset && entry.utxo.ringProgramId === ringProgramId,
    );
  const trees = new Set(candidates.map((entry) => entry.outputContext.tree));
  if (trees.size > 1) {
    throw new RingError("RING_MULTIPLE_INPUT_TREES", { details: { asset, treeCount: trees.size } });
  }
  const selected: SelectedInput[] = [];
  let available = 0n;
  for (const entry of candidates) {
    selected.push({ entry, tree: entry.outputContext.tree });
    available += entry.utxo.amount;
    if (available >= amount) break;
  }
  if (available < amount) {
    throw new RingError("RING_INSUFFICIENT_BALANCE", {
      details: { asset, requested: amount.toString(), available: available.toString() },
    });
  }
  if (selected.length > MAX_INPUTS) {
    throw new RingError("RING_TOO_MANY_INPUTS", {
      details: { selected: selected.length, maximum: MAX_INPUTS },
    });
  }
  return Object.freeze(selected);
}

/** Entering a ring may not sweep unrelated default-pool change into it. */
function selectExactDefaultInputs(
  wallet: Wallet,
  asset: Address,
  amount: bigint,
  commitments: readonly Bytes32[],
): readonly SelectedInput[] {
  if (commitments.length === 0 || commitments.length > MAX_INPUTS) {
    throw new RingError("RING_BUILD_TRANSFER", {
      details: { reason: "entering a ring requires one to five exact input commitments" },
    });
  }
  const candidates = wallet
    .utxos()
    .filter(
      (entry) =>
        !entry.spent && entry.utxo.asset === asset && entry.utxo.ringProgramId === undefined,
    );
  const seen = new Set<string>();
  const selected = commitments.map((commitment) => {
    const key = Array.from(commitment, (byte) => byte.toString(16).padStart(2, "0")).join("");
    if (seen.has(key)) {
      throw new RingError("RING_BUILD_TRANSFER", {
        details: { reason: "duplicate default-pool input commitment" },
      });
    }
    seen.add(key);
    const entry = candidates.find((candidate) =>
      candidate.outputContext.hash.every((byte, index) => byte === commitment[index]),
    );
    if (entry === undefined) {
      throw new RingError("RING_BUILD_TRANSFER", {
        details: { reason: "default-pool input is unavailable", commitment: key },
      });
    }
    return { entry, tree: entry.outputContext.tree };
  });
  const trees = new Set(selected.map(({ tree }) => tree));
  if (trees.size !== 1) {
    throw new RingError("RING_MULTIPLE_INPUT_TREES", {
      details: { asset, treeCount: trees.size },
    });
  }
  const available = selected.reduce((sum, { entry }) => sum + entry.utxo.amount, 0n);
  if (available !== amount) {
    throw new RingError("RING_BUILD_TRANSFER", {
      details: {
        reason: "default-pool inputs must exactly equal the amount entering the ring",
        amount: amount.toString(),
        available: available.toString(),
      },
    });
  }
  return Object.freeze(selected);
}
