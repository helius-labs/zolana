import type {
  BlockhashProvider,
  ChainReader,
  KitRpcAccess,
  Prover,
  TreeContext,
} from "../client/ports.js";
import { InstructionTag } from "../interface/program.js";
import { compileUnsignedTransaction } from "../flows/compile.js";
import type {
  Address,
  Instruction,
  RequestContext,
  Transaction,
  TransactInstructionData,
  TransactWithdrawal,
} from "../interface/types.js";
import { initializePoseidon } from "../hasher/index.js";
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
import {
  checkIntentApproval,
  checkPreparedTransfer,
  checkTransactData,
  withdrawalIntentRecipient,
  type TransactionIntent,
} from "../transaction/wallet/intent.js";
import { SOL_MINT, type AssetRegistry } from "../transaction/asset.js";
import type { UtxoReservation, Wallet, WalletUtxo } from "../transaction/wallet/state.js";
import { ownerSignerAddresses } from "../client/prover/assembly.js";
import { resolveWithdrawalSettlement, withdrawalSetupInstructions } from "../flows/settlement.js";
import { resolveShieldedRecipient } from "../wallet/registry.js";

import { fetchRingProgramConfig } from "./config.js";
import { MAX_SPEND_INPUTS, selectUtxos, type SpendSelectionErrors } from "../flows/select.js";
import { reserveEntries, reservedUtxoKeys, unreserved } from "../flows/reserve.js";
import { RingError, wrapRingError } from "./error.js";
import { ringTransactInstruction } from "./instructions.js";
import { fetchRingLookupTable } from "./lookup-table.js";

/** Rust `TRANSACT_COMPUTE_UNIT_LIMIT`. The custom-ring transact verifies two proofs. */
export const RING_TRANSACT_COMPUTE_UNIT_LIMIT = 1_400_000;
/** Borsh `Encrypted` tag, its length, the scheme byte and the embedded P-256 key. */
const CONFIDENTIAL_BODY_OVERHEAD = 1 + 4 + 1 + 33;

export type RingTransferClient = TreeContext &
  BlockhashProvider &
  KitRpcAccess &
  Pick<ChainReader, "getAccount"> &
  Pick<Prover, "proveRingTransact" | "proveCustomRing">;

export interface RingTransferTransactionParams {
  readonly client: RingTransferClient;
  readonly ringProgramId: Address;
  readonly wallet: Wallet;
  readonly authority: WalletAuthority;
  readonly feePayer: Address;
  readonly recipient: Address | ShieldedAddress;
  readonly asset?: Address;
  readonly amount: bigint;
  /** `"default"` funds only from default UTXOs. `"ring-or-default"` mixes both pools. */
  readonly inputs?: "ring" | "ring-or-default" | "default";
  /** Must be at least one slot old. */
  readonly lookupTable: Address;
  readonly computeUnitLimit?: number;
  readonly computeUnitPriceMicroLamports?: bigint;
}

export type RingEntryTransactionParams = Omit<
  RingTransferTransactionParams,
  "recipient" | "inputs"
>;

export interface RingWithdrawalTransactionParams {
  readonly client: RingTransferClient;
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
  readonly computeUnitPriceMicroLamports?: bigint;
}

/** Mirrors Rust `CustomRingTransferInput`. `prepared` is what `ConfidentialTransfer.prepare` returned. */
export interface CustomRingTransferParams {
  readonly client: RingTransferClient;
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
  return buildRingSendTransaction(normalizeRingTransferParams(input), "ring", context);
}

export async function buildRingEntryTransaction(
  input: RingEntryTransactionParams,
  context?: RequestContext,
): Promise<Transaction> {
  const normalized = normalizeRingEntryParams(input);
  return buildRingSpend(
    normalized,
    {
      errorCode: "RING_BUILD_ENTRY",
      selection: "default",
      changeRing: "default",
      resolve: () => Promise.resolve(undefined),
      configure: ({ transfer, owner, asset }) => {
        transfer.sendToRing(owner, asset, normalized.amount, normalized.ringProgramId);
        return {
          intent: {
            kind: "ringEntry",
            ringProgramId: normalized.ringProgramId,
            asset,
            amount: normalized.amount,
          },
          summary: `ring entry of ${String(normalized.amount)} ${assetLabel(asset)} into ring ${normalized.ringProgramId}`,
        };
      },
    },
    context,
  );
}

/**
 * Value leaves the ring to a default-ring UTXO of the recipient, and the
 * custom-ring proof still covers the exit. Only ring-bound UTXOs fund it. An
 * all-default transact must not reach the audit as an exit.
 */
export async function buildRingExitTransaction(
  input: Omit<RingTransferTransactionParams, "inputs">,
  context?: RequestContext,
): Promise<Transaction> {
  return buildRingSendTransaction(
    { ...normalizeRingTransferBase(input), recipient: input.recipient, inputs: "ring" },
    "default",
    context,
  );
}

async function buildRingSendTransaction(
  input: RingTransferTransactionParams,
  destination: "ring" | "default",
  context?: RequestContext,
): Promise<Transaction> {
  return buildRingSpend(
    input,
    {
      errorCode: "RING_BUILD_TRANSFER",
      selection: input.inputs ?? "ring",
      changeRing: "ring",
      resolve: () => resolveRecipient(input, context),
      configure: ({ transfer, resolved: recipient, selected, asset }) => {
        if (destination === "ring") {
          transfer.send(recipient, asset, input.amount);
        } else {
          transfer.sendDefaultRing(recipient, asset, input.amount);
        }
        // Change of a default UTXO becomes ring bound.
        const defaultFunding = selected
          .filter((entry) => entry.utxo.ringProgramId === undefined)
          .reduce((sum, entry) => sum + entry.utxo.amount, 0n);
        const boundary =
          destination === "default" ? "exit" : defaultFunding > 0n ? "entry" : "transfer";
        const crossing =
          defaultFunding === 0n
            ? ""
            : `, moves ${String(defaultFunding)} ${assetLabel(asset)} of default UTXOs into the ring`;
        return {
          intent: {
            kind: "ringTransfer",
            ringProgramId: input.ringProgramId,
            asset,
            amount: input.amount,
            recipient,
            boundary,
            defaultFunding,
          },
          summary: `ring ${boundary} of ${String(input.amount)} ${assetLabel(asset)} in ring ${input.ringProgramId} to a shielded address${crossing}`,
        };
      },
    },
    context,
  );
}

type RingSpendParams = Pick<
  RingTransferTransactionParams,
  | "client"
  | "ringProgramId"
  | "wallet"
  | "authority"
  | "feePayer"
  | "asset"
  | "amount"
  | "lookupTable"
  | "computeUnitLimit"
  | "computeUnitPriceMicroLamports"
>;

interface RingSpendPlan {
  readonly intent: TransactionIntent;
  readonly summary: string;
  readonly withdrawal?: TransactWithdrawal;
  readonly setupInstructions?: readonly Instruction[];
}

interface RingSpendStrategy<R> {
  readonly errorCode: "RING_BUILD_ENTRY" | "RING_BUILD_TRANSFER" | "RING_BUILD_WITHDRAWAL";
  readonly selection: "ring" | "ring-or-default" | "default";
  readonly changeRing: "ring" | "default";
  resolve(): Promise<R>;
  configure(
    input: Readonly<{
      transfer: ConfidentialTransfer;
      resolved: R;
      selected: readonly WalletUtxo[];
      asset: Address;
      owner: ShieldedAddress;
    }>,
  ): RingSpendPlan;
}

async function buildRingSpend<R>(
  input: RingSpendParams,
  strategy: RingSpendStrategy<R>,
  context?: RequestContext,
): Promise<Transaction> {
  return input.authority.withSpendSession(async (session) => {
    let inputs: readonly ProofInputUtxo[] = [];
    let reservation: UtxoReservation | undefined;
    try {
      await initializePoseidon();
      const asset = input.asset ?? SOL_MINT;
      const nullifierKey = session.nullifierKey();
      const [resolved, address] = await Promise.all([
        strategy.resolve(),
        input.authority.shieldedAddress(),
      ]);
      const selected = selectRingInputs(
        input.wallet,
        input.ringProgramId,
        asset,
        input.amount,
        strategy.selection,
        input.client.tree,
      );
      reservation = reserveEntries(input.wallet, selected);
      inputs = selected.map(
        (entry) =>
          new ProofInputUtxo({
            utxo: entry.utxo,
            nullifierKey,
            ...(entry.dataHash === undefined ? {} : { dataHash: entry.dataHash }),
            ...(entry.ringDataHash === undefined ? {} : { ringDataHash: entry.ringDataHash }),
          }),
      );
      const transfer = new ConfidentialTransfer(
        address,
        inputs,
        input.feePayer,
      ).withCompactChange();
      if (strategy.changeRing === "ring") {
        transfer.withRingProgramId(input.ringProgramId);
      }
      const plan = strategy.configure({ transfer, resolved, selected, asset, owner: address });
      const approval = await input.authority.requestUserApproval({
        solanaPublicKey: input.authority.solanaPublicKey(),
        intent: plan.intent,
        summary: plan.summary,
      });
      checkIntentApproval(approval, plan.intent, ringIntentMismatch);
      const prepared = transfer.prepare();
      checkPreparedTransfer(prepared, plan.intent, ringIntentMismatch);
      const proven = await proveCustomRingTransfer(
        {
          client: input.client,
          ringProgramId: input.ringProgramId,
          prepared,
          session,
          assets: input.wallet.registry,
          tree: input.client.tree,
        },
        context,
      );
      checkTransactData(proven.data, plan.intent, ringIntentMismatch);
      const [instruction, tableAddresses, lifetime] = await Promise.all([
        ringTransactInstruction({
          ringProgramId: input.ringProgramId,
          payer: proven.payer,
          inputTree: proven.tree,
          outputTree: proven.tree,
          proof: proven.proof,
          data: proven.data,
          ...(proven.ownerSigners.length === 0 ? {} : { ownerSigners: proven.ownerSigners }),
          ...(plan.withdrawal === undefined ? {} : { withdrawal: plan.withdrawal }),
        }),
        fetchRingLookupTable({
          client: input.client,
          ringProgramId: input.ringProgramId,
          address: input.lookupTable,
          tree: proven.tree,
        }),
        input.client.getLatestBlockhash(context),
      ]);
      return compileUnsignedTransaction({
        feePayer: input.feePayer,
        lifetime,
        computeUnitLimit: input.computeUnitLimit ?? RING_TRANSACT_COMPUTE_UNIT_LIMIT,
        ...(input.computeUnitPriceMicroLamports === undefined
          ? {}
          : { computeUnitPriceMicroLamports: input.computeUnitPriceMicroLamports }),
        instructions: [...(plan.setupInstructions ?? []), instruction],
        lookupTables: { [input.lookupTable]: [...tableAddresses] },
        sizeShape: {
          inputs: proven.data.inputs.length,
          outputs: proven.data.outputs.length,
        },
      });
    } catch (cause) {
      if (reservation !== undefined) input.wallet._releaseReservation(reservation.id);
      throw wrapRingError(strategy.errorCode, cause);
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
  const normalized = normalizeRingWithdrawalParams(input);
  return buildRingSpend(
    normalized,
    {
      errorCode: "RING_BUILD_WITHDRAWAL",
      selection: "ring",
      changeRing: "ring",
      resolve: async () => {
        const asset = normalized.asset ?? SOL_MINT;
        const settlement = await resolveWithdrawalSettlement(
          normalized.recipient,
          asset,
          normalized.splTokenProgram,
        );
        const setupInstructions = await withdrawalSetupInstructions({
          payer: normalized.feePayer,
          recipient: normalized.recipient,
          asset,
          ...(normalized.splTokenProgram === undefined
            ? {}
            : { splTokenProgram: normalized.splTokenProgram }),
        });
        return { settlement, setupInstructions };
      },
      configure: ({ transfer, resolved, asset }) => {
        transfer.withdraw(asset, normalized.amount, resolved.settlement.target);
        return {
          intent: {
            kind: "ringWithdrawal",
            ringProgramId: normalized.ringProgramId,
            asset,
            amount: normalized.amount,
            recipient: withdrawalIntentRecipient(resolved.settlement.target),
          },
          summary: `public withdrawal of ${String(normalized.amount)} ${assetLabel(asset)} from ring ${normalized.ringProgramId} to ${normalized.recipient}`,
          withdrawal: resolved.settlement.accounts,
          setupInstructions: resolved.setupInstructions,
        };
      },
    },
    context,
  );
}

/** Mirrors Rust `CustomRingTransfer::prove`, the auditor message enters the external data before the SPP proof folds it into `privateTxHash`. */
export async function proveCustomRingTransfer(
  input: CustomRingTransferParams,
  context?: RequestContext,
): Promise<ProvenRingTransfer> {
  await initializePoseidon();
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
      prepared
        .finalize({
          txViewingPublicKey: encrypted.txViewingPublicKey,
          salt: encrypted.salt,
          payload: encrypted.payload,
          messages: [encrypted.auditorMessage],
          instructionDiscriminator: InstructionTag.ringTransact,
        })
        .withTrees({ inputTree: input.tree, outputTree: input.tree }),
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
  const utxos = [
    ...prepared.inputs.map((input) => ({
      ring: input.utxo.ringProgramId,
      data: input.ringDataHash,
    })),
    ...prepared.outputs.map((output) => ({
      ring: output.ringProgramId,
      data: output.ringDataHash,
    })),
  ];
  const foreign = utxos.find((utxo) => utxo.ring !== undefined && utxo.ring !== ringProgramId);
  if (foreign?.ring !== undefined) {
    throw new RingError("RING_FOREIGN_RING", { details: { ringProgramId: foreign.ring } });
  }
  if (utxos.some((utxo) => utxo.ring === undefined && utxo.data !== undefined)) {
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
    try {
      body.set(key.publicKey().toBytes(), 0);
    } finally {
      key.destroy();
    }
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

function normalizeRingTransferBase(input: RingSpendParams): RingSpendParams {
  const asset = input.asset;
  const computeUnitLimit = input.computeUnitLimit;
  const computeUnitPriceMicroLamports = input.computeUnitPriceMicroLamports;
  return Object.freeze({
    client: input.client,
    ringProgramId: input.ringProgramId,
    wallet: input.wallet,
    authority: input.authority,
    feePayer: input.feePayer,
    amount: input.amount,
    lookupTable: input.lookupTable,
    ...(asset === undefined ? {} : { asset }),
    ...(computeUnitLimit === undefined ? {} : { computeUnitLimit }),
    ...(computeUnitPriceMicroLamports === undefined ? {} : { computeUnitPriceMicroLamports }),
  });
}

function normalizeRingTransferParams(
  input: RingTransferTransactionParams,
): RingTransferTransactionParams {
  const base = normalizeRingTransferBase(input);
  const inputs = input.inputs;
  return Object.freeze({
    ...base,
    recipient: input.recipient,
    ...(inputs === undefined ? {} : { inputs }),
  });
}

function normalizeRingEntryParams(input: RingEntryTransactionParams): RingEntryTransactionParams {
  return normalizeRingTransferBase(input);
}

function normalizeRingWithdrawalParams(
  input: RingWithdrawalTransactionParams,
): RingWithdrawalTransactionParams {
  const base = normalizeRingTransferBase(input);
  const splTokenProgram = input.splTokenProgram;
  return Object.freeze({
    ...base,
    recipient: input.recipient,
    ...(splTokenProgram === undefined ? {} : { splTokenProgram }),
  });
}

function resolveRecipient(
  input: RingTransferTransactionParams,
  context: RequestContext | undefined,
): Promise<ShieldedAddress> {
  return resolveShieldedRecipient(
    { rpc: input.client, recipient: input.recipient },
    (recipient) =>
      new RingError("RING_BUILD_TRANSFER", {
        details: { reason: "recipient not registered", recipient },
      }),
    context,
  );
}

function assetLabel(asset: Address): string {
  return asset === SOL_MINT ? "SOL" : asset;
}

/**
 * UTXOs on `tree` that the mode admits.
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
  // Zero selects a UTXO whose whole change would cross the ring boundary.
  if (amount <= 0n) {
    throw new RingError("RING_ZERO_AMOUNT", { details: { asset } });
  }
  const reserved = reservedUtxoKeys(wallet);
  return selectUtxos({
    wallet,
    asset,
    target: { kind: "cover", amount },
    policy: {
      eligible: (entry) => {
        if (!unreserved(reserved)(entry)) return false;
        if (entry.utxo.ringProgramId === ringProgramId) return inputs !== "default";
        return (
          inputs !== "ring" &&
          entry.utxo.ringProgramId === undefined &&
          entry.ringDataHash === undefined
        );
      },
      ordering: "largestFirst",
      maxInputs: MAX_SPEND_INPUTS,
      tree: { kind: "fixed", tree },
      errors: ringSelectionErrors,
    },
  }).entries;
}

function ringIntentMismatch(field: string): RingError {
  return new RingError("RING_INTENT_MISMATCH", { details: { field } });
}

const ringSelectionErrors: SpendSelectionErrors = {
  insufficient: ({ asset, requested, available }) =>
    new RingError("RING_INSUFFICIENT_BALANCE", {
      details: { asset, requested: requested.toString(), available: available.toString() },
    }),
  tooManyInputs: ({ eligible, max }) =>
    new RingError("RING_TOO_MANY_INPUTS", { details: { selected: eligible, maximum: max } }),
  overflow: ({ available }) =>
    new RingError("RING_SELECTED_BALANCE_OVERFLOW", {
      details: { available: available.toString() },
    }),
};
