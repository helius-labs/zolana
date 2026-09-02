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
import { hexToBytes } from "@noble/hashes/utils.js";

import type { ZolanaClient } from "../client/client.js";
import { bigintToBytes, hashChain } from "../client/internal.js";
import { ringOpenings } from "../client/prover/assembly.js";
import {
  RING_INLINE_ASSET_SLOTS,
  RING_ANSWER_SLOTS,
  RING_RULE_SLOTS,
  disabledRuleAnswer,
} from "../client/prover/types.js";
import { hashBytes } from "../hasher/index.js";
import { addressBytes } from "../interface/internal.js";
import { InstructionTag } from "../interface/program.js";
import { checkedTransactionSize } from "../interface/transaction-size.js";
import type {
  Address,
  Bytes32,
  RequestContext,
  Transaction,
  TransactInstructionData,
} from "../interface/types.js";
import {
  auditPublicInputHash,
  customRingPublicInputHash,
  parseAuditorMessage,
} from "../keypair/audit.js";
import { ownerHash } from "../keypair/hash.js";
import { poseidon } from "../keypair/poseidon.js";
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
import type { WalletAuthority } from "../transaction/wallet/authority.js";
import { SOL_MINT, type AssetRegistry } from "../transaction/wallet/asset.js";
import type { Wallet, WalletUtxo } from "../transaction/wallet/state.js";
import { equalBytes } from "../wallet/internal.js";
import { resolveRegisteredAddress } from "../wallet/registry.js";

import type { RingPolicyConfig } from "./codecs.js";
import { fetchRingPolicyConfig, fetchRingProgramConfig } from "./config.js";
import { RingError, wrapRingError } from "./error.js";
import { ringTransactInstruction } from "./instructions.js";
import { fetchRingLookupTable } from "./lookup-table.js";

/** Rust `TRANSACT_COMPUTE_UNIT_LIMIT`. The custom-ring transact verifies two proofs. */
export const RING_TRANSACT_COMPUTE_UNIT_LIMIT = 1_400_000;
const MAX_INPUTS = 5;
/** Borsh `Encrypted` tag, its length, the scheme byte and the embedded P-256 key. */
const CONFIDENTIAL_BODY_OVERHEAD = 1 + 4 + 1 + 33;
/**
 * `RuleTable::hash` over an empty table, MUST track Rust/Go `EMPTY_POLICY_HASH`.
 * @internal
 */
export const RING_EMPTY_RULES_POLICY_HASH = hexToBytes(
  "1fdd9c12850df78caef73299c35baf2a64eb41a13b6374e3684a8dc29f3343d4",
) as Bytes32;

export interface RingTransferTransactionParams {
  readonly client: ZolanaClient;
  readonly ringProgramId: Address;
  readonly wallet: Wallet;
  readonly authority: WalletAuthority;
  readonly feePayer: Address;
  readonly recipient: Address | ShieldedAddress;
  readonly asset?: Address;
  readonly amount: bigint;
  /** Destination money tree; defaults to the input note tree. */
  readonly outputTree?: Address;
  /** Required when the policy entries tree differs from the input note tree. */
  readonly entriesRoots?: RingEntriesRoots;
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
  /** Destination money tree for private change; defaults to the input note tree. */
  readonly outputTree?: Address;
  /** Required when the policy entries tree differs from the input note tree. */
  readonly entriesRoots?: RingEntriesRoots;
  /** Must be at least one slot old. */
  readonly lookupTable: Address;
  readonly computeUnitLimit?: number;
}

/** Mirrors Rust `CustomRingTransferInput`. `prepared` is what `ConfidentialTransfer.prepare` returned. */
export interface CustomRingTransferParams {
  readonly client: ZolanaClient;
  readonly ringProgramId: Address;
  readonly prepared: PreparedTransfer;
  readonly authority: WalletAuthority;
  readonly assets: AssetRegistry;
  /** Tree containing the spent notes. */
  readonly tree: Address;
  /** Tree receiving every private output; defaults to `tree`. */
  readonly outputTree?: Address;
  /** A root pair read from `PolicyConfig.entriesTree`, required for migration. */
  readonly entriesRoots?: RingEntriesRoots;
}

/** History entries read from the ring's dedicated policy entries tree. */
export interface RingEntriesRoots {
  readonly stateRoot: Bytes32;
  readonly stateRootIndex: number;
  readonly nullifierRoot: Bytes32;
  readonly nullifierRootIndex: number;
}

/** Mirrors Rust `ProvenTransfer`. */
export interface ProvenRingTransfer {
  readonly data: TransactInstructionData;
  readonly proof: Uint8Array;
  readonly txViewingPublicKey: P256PublicKey;
  readonly payer: Address;
  /** Input money tree, retained as `tree` for compatibility. */
  readonly tree: Address;
  readonly outputTree: Address;
  /** The pinned policy entries tree, absent for an audit-only ring, Rust `Option<Address>`. */
  readonly entriesTree?: Address;
  /** The config tier, false for an audit-only ring that carries no policy accounts. */
  readonly hasPolicy: boolean;
  /** History entries the ring proof binds, sent on the tag-3 wire. */
  readonly stateRootIndex: number;
  readonly nullifierRootIndex: number;
}

/** Returns a v0 transaction over `lookupTable`, signed by the fee payer only. */
export async function buildRingTransferTransaction(
  input: RingTransferTransactionParams,
  context?: RequestContext,
): Promise<Transaction> {
  try {
    const asset = input.asset ?? SOL_MINT;
    const [recipient, address, nullifierKey] = await Promise.all([
      resolveRecipient(input, context),
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
    transfer.send(recipient, asset, input.amount);
    const tree = selected[0]?.tree ?? input.client.tree;
    await input.authority.requestUserApproval({
      solanaPublicKey: input.authority.solanaPublicKey(),
      summary: `ring transfer of ${String(input.amount)} to a shielded address`,
    });
    const proven = await proveCustomRingTransfer(
      {
        client: input.client,
        ringProgramId: input.ringProgramId,
        prepared: transfer.prepare(),
        authority: input.authority,
        assets: input.wallet.registry,
        tree,
        ...(input.outputTree === undefined ? {} : { outputTree: input.outputTree }),
        ...(input.entriesRoots === undefined ? {} : { entriesRoots: input.entriesRoots }),
      },
      context,
    );
    const [instruction, tableAddresses, lifetime] = await Promise.all([
      ringTransactInstruction({
        ringProgramId: input.ringProgramId,
        payer: proven.payer,
        inputTree: proven.tree,
        outputTree: proven.outputTree,
        hasPolicy: proven.hasPolicy,
        ...(proven.hasPolicy ? { entriesTree: proven.entriesTree } : {}),
        proof: proven.proof,
        stateRootIndex: proven.stateRootIndex,
        nullifierRootIndex: proven.nullifierRootIndex,
        data: proven.data,
      }),
      fetchRingLookupTable({
        client: input.client,
        ringProgramId: input.ringProgramId,
        address: input.lookupTable,
        tree: proven.tree,
        outputTree: proven.outputTree,
        hasPolicy: proven.hasPolicy,
        ...(proven.hasPolicy ? { entriesTree: proven.entriesTree } : {}),
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
        ...(input.outputTree === undefined ? {} : { outputTree: input.outputTree }),
        ...(input.entriesRoots === undefined ? {} : { entriesRoots: input.entriesRoots }),
      },
      context,
    );
    const [instruction, tableAddresses, lifetime] = await Promise.all([
      ringTransactInstruction({
        ringProgramId: input.ringProgramId,
        payer: proven.payer,
        inputTree: proven.tree,
        outputTree: proven.outputTree,
        hasPolicy: proven.hasPolicy,
        ...(proven.hasPolicy ? { entriesTree: proven.entriesTree } : {}),
        proof: proven.proof,
        stateRootIndex: proven.stateRootIndex,
        nullifierRootIndex: proven.nullifierRootIndex,
        data: proven.data,
        withdrawal: { kind: "sol", recipient: input.recipient },
      }),
      fetchRingLookupTable({
        client: input.client,
        ringProgramId: input.ringProgramId,
        address: input.lookupTable,
        tree: proven.tree,
        outputTree: proven.outputTree,
        hasPolicy: proven.hasPolicy,
        ...(proven.hasPolicy ? { entriesTree: proven.entriesTree } : {}),
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

/** Mirrors Rust `ListNamespace::new`, the shielded owner hash of the ring's entry notes. */
export function ringNamespaceOwnerHash(namespacePda: Address): Bytes32 {
  return ownerHash(
    hashBytes(addressBytes(namespacePda, "namespacePda")),
    poseidon([new Uint8Array(32)]),
  ) as Bytes32;
}

/** Mirrors Rust `CustomRingTransfer::prove`, the auditor message enters the external data before the SPP proof folds it into `privateTxHash`. */
export async function proveCustomRingTransfer(
  input: CustomRingTransferParams,
  context?: RequestContext,
): Promise<ProvenRingTransfer> {
  const config = await fetchRingProgramConfig(input.client, input.ringProgramId, context);
  // An audit-only ring has no policy config account to read.
  const policy = config.hasPolicy ? await loadPolicyContext(input, context) : undefined;
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
    const openings = ringOpenings(proofInputs);
    const { data, roots } = await input.client.proveRingTransact(
      proofInputs,
      input.ringProgramId,
      undefined,
      context,
    );
    // The audit statement rehashes the auditor message SPP already folded into privateTxHash.
    const message = parseAuditorMessage(encrypted.auditorMessage.data);
    const common = {
      data,
      txViewingPublicKey: encrypted.txViewingPublicKey,
      payer: prepared.payer,
      tree: input.tree,
      outputTree: input.outputTree ?? input.tree,
    } as const;

    if (policy === undefined) {
      const proof = await input.client.proveCustomRingAudit(
        {
          publicInputHash: auditPublicInputHash({
            privateTxHash: data.privateTxHash,
            txViewingPublicKey: encrypted.txViewingPublicKey,
            auditorPublicKey: config.auditorPublicKey,
            message,
          }),
          privateTxHash: data.privateTxHash,
          txViewingSecret: encrypted.audit.txViewingSecret,
          ephemeralSecret: encrypted.audit.ephemeralSecret,
          auditorPublicKey: config.auditorPublicKey.toUncompressed(),
        },
        context,
      );
      return Object.freeze({
        ...common,
        proof,
        hasPolicy: false,
        stateRootIndex: 0,
        nullifierRootIndex: 0,
      });
    }

    const entriesRoots = policy.suppliedEntriesRoots ?? roots;
    // A ring without rules proves the empty table over its own openings, every
    // further policy field is zero or disabled.
    const proof = await input.client.proveCustomRing(
      {
        publicInputHash: customRingPublicInputHash({
          privateTxHash: data.privateTxHash,
          txViewingPublicKey: encrypted.txViewingPublicKey,
          auditorPublicKey: config.auditorPublicKey,
          message,
          policyHash: policy.config.policyHash,
          stateRoot: entriesRoots.stateRoot,
          nullifierRoot: entriesRoots.nullifierRoot,
        }),
        privateTxHash: data.privateTxHash,
        txViewingSecret: encrypted.audit.txViewingSecret,
        ephemeralSecret: encrypted.audit.ephemeralSecret,
        auditorPublicKey: config.auditorPublicKey.toUncompressed(),
        nIn: openings.nIn,
        nOut: openings.nOut,
        inputs: openings.inputs,
        outputs: openings.outputs,
        // Both MUST equal the preimage the SPP assembly folds into
        // `privateTxHash`, else the gnark witness is unsatisfiable.
        addressChain: ringAddressChain(openings.nIn),
        externalDataHash: proofInputs.externalData.hash(),
        sources: policy.config.sources.map((slot) =>
          slot.listId === 0
            ? { listId: 0, ownerHash: new Uint8Array(32) as Bytes32 }
            : { listId: slot.listId, ownerHash: ringNamespaceOwnerHash(slot.namespace) },
        ),
        policyLen: 0,
        rules: zeroFields(RING_RULE_SLOTS),
        inlineAssets: zeroFields(RING_INLINE_ASSET_SLOTS),
        inlineCount: 0,
        stateRoot: entriesRoots.stateRoot,
        nullifierRoot: entriesRoots.nullifierRoot,
        answers: Array.from({ length: RING_ANSWER_SLOTS }, () => disabledRuleAnswer()),
      },
      context,
    );
    return Object.freeze({
      ...common,
      proof,
      entriesTree: policy.config.entriesTree,
      hasPolicy: config.hasPolicy,
      stateRootIndex: entriesRoots.stateRootIndex,
      nullifierRootIndex: entriesRoots.nullifierRootIndex,
    });
  } finally {
    encrypted.audit.txViewingSecret.fill(0);
    encrypted.audit.ephemeralSecret.fill(0);
  }
}

/** The policy account and caller-supplied entries roots a policy ring proves against. */
interface PolicyContext {
  readonly config: RingPolicyConfig;
  readonly suppliedEntriesRoots: RingEntriesRoots | undefined;
}

async function loadPolicyContext(
  input: CustomRingTransferParams,
  context: RequestContext | undefined,
): Promise<PolicyContext> {
  const config = await fetchRingPolicyConfig(input.client, input.ringProgramId, context);
  // The empty-table proof satisfies only an empty rule table, a rules-bearing
  // ring pins a different `policy_hash` and fails in proving.
  if (!equalBytes(config.policyHash, RING_EMPTY_RULES_POLICY_HASH)) {
    throw new RingError("RING_RULES_UNSUPPORTED", {
      details: { ringProgramId: input.ringProgramId, policyHash: config.policyHash },
    });
  }
  return Object.freeze({
    config,
    suppliedEntriesRoots: checkEntriesRoots(input.entriesRoots, config.entriesTree, input.tree),
  });
}

function checkEntriesRoots(
  supplied: RingEntriesRoots | undefined,
  entriesTree: Address,
  inputTree: Address,
): RingEntriesRoots | undefined {
  if (supplied === undefined) {
    if (entriesTree === inputTree) return undefined;
    throw new RingError("RING_ENTRIES_ROOTS_REQUIRED", {
      details: { entriesTree, inputTree },
    });
  }
  if (
    supplied.stateRoot.length !== 32 ||
    supplied.nullifierRoot.length !== 32 ||
    !Number.isInteger(supplied.stateRootIndex) ||
    supplied.stateRootIndex < 0 ||
    supplied.stateRootIndex > 0xffff ||
    !Number.isInteger(supplied.nullifierRootIndex) ||
    supplied.nullifierRootIndex < 0 ||
    supplied.nullifierRootIndex > 0xffff
  ) {
    throw new RingError("RING_ENTRIES_ROOTS_INVALID", { details: { entriesTree } });
  }
  return Object.freeze({
    stateRoot: new Uint8Array(supplied.stateRoot) as Bytes32,
    stateRootIndex: supplied.stateRootIndex,
    nullifierRoot: new Uint8Array(supplied.nullifierRoot) as Bytes32,
    nullifierRootIndex: supplied.nullifierRootIndex,
  });
}

function zeroFields(count: number): readonly Bytes32[] {
  return Object.freeze(Array.from({ length: count }, () => new Uint8Array(32) as Bytes32));
}

/**
 * SPP folds one zero address slot per input into `privateTxHash`, the ring
 * proof binds the same chain over `nIn` zero fields. Mirrors Rust `proof.rs`.
 * @internal
 */
export function ringAddressChain(nIn: number): Bytes32 {
  return bigintToBytes(hashChain(Array.from({ length: nIn }, () => 0n))) as Bytes32;
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
