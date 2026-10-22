/**
 * One transfer pipeline for every rail, Rust `pipeline`. The rail seals the outputs, the audit proof
 * opens them to the auditor, the policy proof checks the ring's table, the SPP proof spends.
 */
import type { AccountMeta, Instruction } from "@solana/kit";

import { compressG2 } from "../client/prover/proof.js";
import { publicSlots, type PublicSlots } from "../client/prover/assembly.js";
import type {
  ChainReader,
  ProvenRingTransact,
  Prover,
  RingRecordReader,
  TreeContext,
} from "../client/ports.js";
import type { FirstContactAnchor } from "../client/prover/ring.js";
import { CUSTOM_RING_PROOF_LENGTH } from "../interface/custom-ring-proof.js";
import { meta, ringTransactAccounts } from "../interface/instructions/index.js";
import { addressBytes } from "../interface/internal.js";
import {
  ringAuthAddress,
  ringConfigAddress,
  ringMemberRegistryAddress,
  treeAddress,
} from "../interface/pda/index.js";
import type { AuditLayout } from "../interface/ring-disclosure-layout.js";
import type {
  Address,
  Bytes32,
  RequestContext,
  TransactInstructionData,
  TransactWithdrawal,
} from "../interface/types.js";
import { ringIdField, senderCommitment, tagEpoch } from "../keypair/ring-stream.js";
import type { ShieldedAddress } from "../keypair/shielded.js";
import {
  SppProofInputs,
  createExternalData,
  interfaceTransferOf,
  settlementAccounts,
} from "../transaction/instructions/transact.js";
import type { ProofOutputUtxo } from "../transaction/utxo.js";
import type { SentFirstContact } from "../transaction/wallet/anonymous-state.js";
import { bytesKey, equalBytes } from "../wallet/internal.js";

import { RingInstructionTag, ringComputeUnitLimit } from "./admin.js";
import {
  auditProofRequest,
  sealAudit,
  sealedAuditMessage,
  type AnonymousAuditValues,
  type SealedAudit,
} from "./audit-proof.js";
import type { RingProgramConfig } from "./codecs.js";
import { demandedCoSigner } from "./cosign.js";
import { RingError } from "./error.js";
import {
  policyProofRequest,
  readPolicy,
  type BoundPolicy,
  type BoundRoot,
  type PolicyInputs,
} from "./policy-proof.js";
import type { PublishedSlot, RingOutputRail } from "./rail.js";
import { auditStatementHash, ringAuditStatement } from "./statement.js";
import {
  PLAIN_GROTH16_PROOF_LENGTH,
  RingTransactData,
  isDataFreeOutput,
  ringDisclosureLayout,
  ringSppInputs,
  type InputTrees,
  type RingRail,
} from "./transact.js";
import { checkTransactionFits } from "../flows/compile.js";
import type { BoundAnchor } from "./trees.js";

/** The client a ring transfer reads the ring and proves with, every rail adds its SPP prover. */
export type RingProvingClient = TreeContext &
  Pick<ChainReader, "getAccount"> &
  Pick<RingRecordReader, "getRingMemberOpenings"> &
  Pick<Prover, "proveRing">;

/** The first contact a pair payment proves, its path among the decoys of its tree. */
export interface AnchorWitness extends BoundAnchor {
  readonly request: FirstContactAnchor;
}

/** An inbox payment's first contact, the leaf it lands at known only after confirmation, Rust `PendingFirstContact`. */
export type PendingFirstContact = Omit<SentFirstContact, "leafIndex">;

/** What the anonymous rail adds to a staged transfer, Rust `AnonymousSpend`. */
export interface AnonymousSpendValues {
  readonly epoch: bigint;
  readonly anchor?: AnchorWitness;
  /** The inbox payments, each becomes its address's newest first contact once it lands. */
  readonly firstContacts: readonly PendingFirstContact[];
}

/** How the SPP proof authorizes the spends of one rail, Rust `Spend`. */
export interface RailSpend {
  readonly rail: RingRail;
  /** The rail's SPP proof over the final inputs, the anonymous rail signs them inside it. */
  prove(
    proofInputs: SppProofInputs,
    coSigner: Address | undefined,
    context: RequestContext | undefined,
  ): Promise<ProvenRingTransact>;
  /** Signs the transaction beside the payer on the delegate rail. */
  readonly delegate?: Address;
  readonly anonymous?: AnonymousSpendValues;
}

/** A transfer past its outputs' sealing, ready for its statements, Rust `Staged`. */
export interface StagedTransfer {
  /** Sealed by the rail, before the auditor message joins the external data. */
  readonly proofInputs: SppProofInputs;
  readonly rail: RingOutputRail;
  readonly sender: ShieldedAddress;
  /** The confidential rail's owner signer run, empty on the other rails. */
  readonly ownerSigners: readonly Address[];
  readonly withdrawal?: TransactWithdrawal;
  readonly spend: RailSpend;
}

/** The accounts a ring transfer names besides its data, Rust `TransactAccounts`. */
export interface RingTransactAccounts {
  /** SPP's fee payer, the only signer an anonymous transfer takes. */
  readonly payer: Address;
  /** One per tree context, in the data's order. */
  readonly inputTrees: readonly Address[];
  readonly outputTree: Address;
  readonly ownerSigners: readonly Address[];
  readonly withdrawal?: TransactWithdrawal;
  readonly curator?: Address;
  /** Signs when the config demands it. */
  readonly coSigner?: Address;
  readonly delegate?: Address;
  /** The first-contact tree of a pair-anchored anonymous payment. */
  readonly anchorTree?: Address;
}

/** Rust `RING_TRANSACT_ACCOUNT_PREFIX_LEN`, `payer, output tree, SPP, system, ring auth`. */
const RING_TRANSACT_ACCOUNT_PREFIX_LEN = 5;

/** Every value a transfer's proofs bind that the chain can move before it lands, Rust `BoundState`. */
export interface RingBoundState {
  /** The registry roots the proofs bind by history slot, the own registry first. */
  readonly roots?: readonly BoundRoot[];
  readonly policy?: BoundPolicy;
  readonly anchor?: BoundAnchor;
  /** The epoch an anonymous transfer's audit proof binds. */
  readonly epoch?: bigint;
}

/** A proven transfer, its compact data, accounts and the chain values its proofs bind, Rust `ProvenRingTransfer`. */
export class ProvenRingTransfer {
  readonly ringProgramId: Address;
  readonly data: RingTransactData;
  readonly accounts: RingTransactAccounts;
  /** Padding included, final slot order. */
  readonly outputs: readonly ProofOutputUtxo[];
  /** The co-signer the config demands, it signs the transaction. */
  readonly coSigner?: Address;
  readonly approvalRequired: boolean;
  /** The registry roots the policy proof binds, a submission proves again once one leaves the history. */
  readonly roots: readonly BoundRoot[];
  readonly policy?: BoundPolicy;
  readonly anchor?: BoundAnchor;
  /** The anonymous statement's epoch. */
  readonly epoch?: bigint;
  /** Each inbox payment, recorded as its address's newest first contact once the transfer lands. */
  readonly firstContacts: readonly PendingFirstContact[];

  /** @internal */
  constructor(fields: Omit<ProvenRingTransfer, "instruction" | "instructionAt">) {
    this.ringProgramId = fields.ringProgramId;
    this.data = fields.data;
    this.accounts = fields.accounts;
    this.outputs = fields.outputs;
    if (fields.coSigner !== undefined) this.coSigner = fields.coSigner;
    this.approvalRequired = fields.approvalRequired;
    this.roots = fields.roots;
    if (fields.policy !== undefined) this.policy = fields.policy;
    if (fields.anchor !== undefined) this.anchor = fields.anchor;
    if (fields.epoch !== undefined) this.epoch = fields.epoch;
    this.firstContacts = fields.firstContacts;
    Object.freeze(this);
  }

  /** The instruction landing in the proof's own epoch. */
  instruction(): Promise<Instruction> {
    return ringTransactInstruction(this.ringProgramId, this.accounts, this.data);
  }

  /** For a transaction sent at `slot`, an anonymous transfer one epoch late names the epoch before the landing slot's. */
  async instructionAt(slot: bigint): Promise<Instruction> {
    if (this.epoch === undefined) return this.instruction();
    const current = tagEpoch(slot);
    if (current !== this.epoch && current !== this.epoch + 1n)
      throw new RingError("RING_EPOCH_PASSED", {
        details: { proofEpoch: this.epoch.toString(), currentEpoch: current.toString() },
      });
    return ringTransactInstruction(this.ringProgramId, this.accounts, {
      ...this.data,
      previousEpoch: current !== this.epoch,
    });
  }
}

/** What a staged transfer's proofs read, valid inside the `assembleStagedTransfer` callback. */
interface AssembledTransfer {
  readonly sealed: SealedAudit;
  readonly published: readonly PublishedSlot[];
  readonly publishedInputs: number;
  readonly proofInputs: SppProofInputs;
  readonly slots: PublicSlots;
  readonly senderPkHash: Bytes32;
  readonly policy: PolicyInputs | undefined;
  readonly approvalRequired: boolean;
  readonly coSigner: Address | undefined;
  readonly privateTxHash: Bytes32;
  readonly privateTxBlinding: Bytes32;
  readonly commitment: Bytes32 | undefined;
  readonly accounts: RingTransactAccounts;
  readonly ringId: Bytes32;
  readonly preview: RingTransactData;
}

export interface RingTransactionFrame {
  readonly priorityFeeLamports?: bigint;
  readonly setupInstructions?: readonly Instruction[];
}

export type StagedTransferInput = Readonly<{
  client: RingProvingClient;
  ringProgramId: Address;
  config: RingProgramConfig;
  staged: StagedTransfer;
  transaction?: RingTransactionFrame;
  approve?: (coSigner: Address | undefined) => Promise<void>;
}>;

/** Rust `Pipeline::assemble` and `Assembled::prove`, no proof is an input to another. */
export function proveStagedTransfer(
  input: StagedTransferInput,
  context?: RequestContext,
): Promise<ProvenRingTransfer> {
  return assembleStagedTransfer(input, context, async (assembled) => {
    await input.approve?.(assembled.coSigner);
    return proveAssembled(input, assembled, context);
  });
}

/** Every chain value is read once, the audit secret lives until `use` settles. */
async function assembleStagedTransfer<T>(
  input: StagedTransferInput,
  context: RequestContext | undefined,
  use: (assembled: AssembledTransfer) => Promise<T>,
): Promise<T> {
  const { client, ringProgramId, config, staged } = input;
  const { rail, sender, spend } = staged;
  const ringRail = spend.rail;
  checkDistinctInputs(staged.proofInputs);
  checkMembership(ringProgramId, staged.proofInputs);
  const shape = staged.proofInputs.checkShape();
  const publishedInputs = staged.proofInputs.inputUtxos.filter((spent) => !spent.isCompact());
  const published = rail.publishedSlots(staged.proofInputs, sender);
  const audit: AuditLayout = Object.freeze({
    exits: published.some((slot) => slot.wire.kind === "exit"),
    keyEscrow: config.keyEscrow,
    dataFree: published.every((slot) => isDataFreeOutput(slot.wire)),
    // A default-ring input takes the entry key, every commitment key refuses ring id zero.
    fullOpenings:
      ringRail === "anonymous" &&
      publishedInputs.some((spent) => !spent.isDummy() && spent.utxo.ringProgramId === undefined),
  });
  const layout = ringDisclosureLayout({
    rail: ringRail,
    nIn: shape.inputs,
    nOut: shape.outputs,
    inputs: publishedInputs.length,
    outputs: published.length,
    layout: audit,
  });
  const auditor = config.auditorPublicKey;
  // The auditor message precedes every hash over the external data.
  const sealed = sealAudit({
    rail,
    audit,
    layout,
    published,
    proofInputs: staged.proofInputs,
    sender,
    auditor,
  });
  try {
    const proofInputs = withAuditorMessage(staged.proofInputs, sealedAuditMessage(sealed, auditor));
    const slots = publicSlots(proofInputs.externalData.interfaceTransfers);
    const senderPkHash = sender.signingPublicKey.ownerProofInputHash();
    const policy = config.hasPolicy
      ? await readPolicy(
          {
            client,
            ringProgramId,
            config,
            rail: ringRail,
            proofInputs,
            sender: senderPkHash,
            publicSlots: slots,
          },
          context,
        )
      : undefined;
    const approvalRequired = policy?.approvalRequired ?? false;
    const coSigner = demandedCoSigner({
      ringProgramId,
      configured: config.coSigner,
      approvalRequired,
      transfers: proofInputs.externalData.interfaceTransfers,
      ownerSigners: staged.ownerSigners,
      ...(spend.delegate === undefined ? {} : { delegate: spend.delegate }),
    });
    const privateTxHash = proofInputs.privateTxHash();
    const privateTxBlinding = proofInputs.privateTxBlinding();
    const anonymous = spend.anonymous;
    const commitment =
      anonymous !== undefined && policy !== undefined
        ? senderCommitment({ senderPkHash, privateTxBlinding })
        : undefined;
    const accounts: RingTransactAccounts = Object.freeze({
      payer: proofInputs.payer,
      inputTrees: Object.freeze(proofInputs.inputTreeIds().map(treeAddress)),
      outputTree: treeAddress(proofInputs.outputTreeId),
      ownerSigners: staged.ownerSigners,
      ...(staged.withdrawal === undefined ? {} : { withdrawal: staged.withdrawal }),
      ...(policy?.curator === undefined ? {} : { curator: policy.curator.registry }),
      ...(coSigner === undefined ? {} : { coSigner }),
      ...(spend.delegate === undefined ? {} : { delegate: spend.delegate }),
      ...(anonymous?.anchor === undefined ? {} : { anchorTree: anonymous.anchor.tree }),
    });
    const ringId = ringIdField(ringProgramId);
    const preview = previewData({
      rail: ringRail,
      shape,
      audit,
      proofInputs,
      published,
      txViewingU: rail.txViewingKey.publicKey().u(),
      ephemeralU: sealed.ephemeralPublicKey.u(),
      sealed: sealed.sealed,
      disclosure: sealed.fields,
      privateTxHash,
      approvalRequired,
      ...(policy === undefined ? {} : { policy: { inputs: policy, senderCommitment: commitment } }),
      ...(anonymous === undefined
        ? {}
        : {
            anonymous:
              anonymous.anchor === undefined
                ? {}
                : {
                    anchor: {
                      tree: anchorSlot(accounts, config.hasPolicy),
                      rootIndex: anonymous.anchor.rootIndex,
                    },
                  },
          }),
    });
    // The program's expansion must reproduce the external data the SPP proof binds.
    if (
      !equalBytes(
        RingTransactData.externalDataHash(
          preview,
          { auditorPubkey: auditor.toBytes(), coSigner: coSignerField(config) },
          proofInputs.externalData.interfaceTransfers.map(settlementAccounts),
        ),
        proofInputs.externalData.hash(),
      )
    )
      throw new RingError("RING_EXTERNAL_DATA_MISMATCH");
    checkTransactionFits({
      ...input.transaction,
      feePayer: proofInputs.payer,
      instructions: [await ringTransactInstruction(ringProgramId, accounts, preview)],
      computeUnitLimit: ringComputeUnitLimit(transactTag(ringRail)),
    });
    return await use(
      Object.freeze({
        sealed,
        published,
        publishedInputs: publishedInputs.length,
        proofInputs,
        slots,
        senderPkHash,
        policy,
        approvalRequired,
        coSigner,
        privateTxHash,
        privateTxBlinding,
        commitment,
        accounts,
        ringId,
        preview,
      }),
    );
  } finally {
    sealed.ephemeralSecret.fill(0);
  }
}

async function proveAssembled(
  input: StagedTransferInput,
  assembled: AssembledTransfer,
  context: RequestContext | undefined,
): Promise<ProvenRingTransfer> {
  const { client, ringProgramId, config, staged } = input;
  const { rail, sender, spend } = staged;
  const ringRail = spend.rail;
  const anonymous = spend.anonymous;
  const { proofInputs, policy, coSigner, privateTxHash, commitment, preview, ringId } = assembled;
  const auditor = config.auditorPublicKey;
  const policyRequest =
    policy === undefined
      ? undefined
      : policyProofRequest(policy, {
          ringId,
          rail: ringRail,
          proofInputs,
          privateTxHash,
          sender: ringRail === "delegate" ? zeroField() : (commitment ?? assembled.senderPkHash),
          senderPkHash: assembled.senderPkHash,
          publicSlots: assembled.slots,
        });
  const auditRequest = auditProofRequest({
    rail,
    sealed: assembled.sealed,
    published: assembled.published,
    proofInputs,
    sender,
    auditor,
    ringId,
    publicInputHash: auditStatementHash(
      ringAuditStatement(preview, {
        ringId,
        auditorPubkey: auditor.toBytes(),
        epoch: anonymous?.epoch ?? 0n,
        firstContactRoot: anonymous?.anchor?.root ?? zeroField(),
        keyEscrow: config.keyEscrow,
      }),
    ),
    ...(anonymous === undefined
      ? {}
      : {
          anonymous: anonymousAuditValues({
            privateTxHash,
            privateTxBlinding: assembled.privateTxBlinding,
            senderCommitment: commitment,
            spend: anonymous,
          }),
        }),
  });
  let proofs: readonly [ProvenRingTransact, Uint8Array, Uint8Array | undefined];
  try {
    // Each request runs in its own async call, a synchronous throw never strands another proof.
    proofs = await Promise.all([
      (async () => spend.prove(proofInputs, coSigner, context))(),
      (async () => client.proveRing(auditRequest, context))(),
      (async () =>
        policyRequest === undefined ? undefined : client.proveRing(policyRequest, context))(),
    ]);
  } finally {
    wipeAuditRequest(auditRequest);
  }
  const [spp, auditProof, policyProof] = proofs;
  const data = provenData({
    preview,
    spp: spp.data,
    privateTxHash,
    publishedInputs: assembled.publishedInputs,
    auditProof,
    ...(policyProof === undefined ? {} : { policyProof }),
  });
  return new ProvenRingTransfer({
    ringProgramId,
    data,
    accounts: assembled.accounts,
    outputs: proofInputs.outputs,
    ...(coSigner === undefined ? {} : { coSigner }),
    approvalRequired: assembled.approvalRequired,
    roots: policy === undefined ? [] : boundRoots(policy),
    ...(policy === undefined
      ? {}
      : { policy: Object.freeze({ ringProgramId, policyHash: policy.pinned.policyHash }) }),
    ...(anonymous?.anchor === undefined
      ? {}
      : {
          anchor: Object.freeze({
            tree: anonymous.anchor.tree,
            rootIndex: anonymous.anchor.rootIndex,
            root: anonymous.anchor.root,
          }),
        }),
    ...(anonymous === undefined ? {} : { epoch: anonymous.epoch }),
    firstContacts: anonymous?.firstContacts ?? [],
  });
}

/** The ring prefix, then SPP's own accounts, the data's tag by its rail, Rust `TransactAccounts::instruction`. */
export async function ringTransactInstruction(
  ringProgramId: Address,
  accounts: RingTransactAccounts,
  data: RingTransactData,
): Promise<Instruction> {
  const spp = ringSppInputs(data);
  const [config, registry, ringAuth] = await Promise.all([
    ringConfigAddress(ringProgramId),
    ringMemberRegistryAddress(ringProgramId),
    ringAuthAddress(ringProgramId),
  ]);
  const sppAccounts = await ringTransactAccounts({
    payer: accounts.payer,
    inputTrees: accounts.inputTrees,
    outputTree: accounts.outputTree,
    ringAuth,
    inputs: spp.inputs,
    treeContexts: spp.treeContexts,
    ...(data.rail === "confidential" && accounts.ownerSigners.length > 0
      ? { ownerSigners: accounts.ownerSigners }
      : {}),
    ...(accounts.withdrawal === undefined ? {} : { withdrawal: accounts.withdrawal }),
  });
  const prefix: AccountMeta[] = [meta(config, false, false)];
  if (data.policy !== undefined) prefix.push(meta(registry, false, false));
  if (accounts.curator !== undefined) prefix.push(meta(accounts.curator, false, false));
  if (accounts.coSigner !== undefined) prefix.push(meta(accounts.coSigner, true, false));
  if (accounts.delegate !== undefined) prefix.push(meta(accounts.delegate, true, false));
  if (data.anchor !== undefined && data.anchor.tree === prefix.length) {
    if (accounts.anchorTree === undefined) throw new RingError("RING_ANCHOR_INVALID");
    prefix.push(meta(accounts.anchorTree, false, false));
  }
  const encoded = RingTransactData.encode(data);
  const bytes = new Uint8Array(1 + encoded.length);
  bytes[0] = transactTag(data.rail);
  bytes.set(encoded, 1);
  return Object.freeze({
    programAddress: ringProgramId,
    accounts: Object.freeze([...prefix, ...sppAccounts]),
    data: bytes,
  });
}

/** The account the anchor's tree slot names, a tree of SPP's list or the prefix slot after the delegate, Rust `anchor_slot`. */
function anchorSlot(accounts: RingTransactAccounts, hasPolicy: boolean): number {
  const prefix =
    1 +
    Number(hasPolicy) +
    Number(accounts.curator !== undefined) +
    Number(accounts.coSigner !== undefined) +
    Number(accounts.delegate !== undefined);
  const tree = accounts.anchorTree;
  if (tree === undefined) throw new RingError("RING_ANCHOR_INVALID");
  if (tree === accounts.outputTree) return prefix + 1;
  const input = accounts.inputTrees.indexOf(tree);
  return input < 0 ? prefix : prefix + RING_TRANSACT_ACCOUNT_PREFIX_LEN + input;
}

/** The auditor message joins the external data, the expiry the compact data carries as a u32. */
function withAuditorMessage(
  proofInputs: SppProofInputs,
  message: Readonly<{ viewTag: Bytes32; data: Uint8Array }>,
): SppProofInputs {
  const external = proofInputs.externalData;
  return new SppProofInputs({
    payer: proofInputs.payer,
    inputUtxos: proofInputs.inputUtxos,
    outputs: proofInputs.outputs,
    externalData: createExternalData({
      instructionDiscriminator: external.instructionDiscriminator,
      expiryUnixTs: U32_MAX,
      interfaceTransfers: external.interfaceTransfers,
      ...(external.dataHash === undefined ? {} : { dataHash: external.dataHash }),
      ...(external.ringDataHash === undefined ? {} : { ringDataHash: external.ringDataHash }),
      txViewingPublicKey: external.txViewingPublicKey,
      salt: external.salt,
      outputs: external.outputs,
      resolvedOwnerTags: external.resolvedOwnerTags,
      messages: [message],
    }),
    blindingSeed: proofInputs.blindingSeed,
    outputTreeId: proofInputs.outputTreeId,
  });
}

/** The compact data before any proof, sized and hashed as the proven one, Rust `preview_parts`. */
function previewData(
  input: Readonly<{
    rail: RingRail;
    shape: Readonly<{ inputs: number; outputs: number }>;
    audit: AuditLayout;
    proofInputs: SppProofInputs;
    published: readonly Readonly<{ wire: RingTransactData["outputs"][number] }>[];
    txViewingU: Bytes32;
    ephemeralU: Bytes32;
    sealed: Bytes32;
    disclosure: readonly Bytes32[];
    privateTxHash: Bytes32;
    approvalRequired: boolean;
    policy?: Readonly<{ inputs: PolicyInputs; senderCommitment: Bytes32 | undefined }>;
    anonymous?: Readonly<{ anchor?: Readonly<{ tree: number; rootIndex: number }> }>;
  }>,
): RingTransactData {
  const external = input.proofInputs.externalData;
  const outputs = input.published.map((slot) => slot.wire);
  const zeroContext = { utxoTreeRootIndex: 0, nullifierTreeRootIndex: 0 };
  const trees = input.proofInputs.inputTreeIds().length;
  const inputTrees: InputTrees =
    trees === 1
      ? { kind: "one", context: zeroContext }
      : { kind: "two", first: zeroContext, second: zeroContext, secondInputs: 0n };
  return Object.freeze({
    rail: input.rail,
    nIn: input.shape.inputs,
    nOut: input.shape.outputs,
    auditProof: new Uint8Array(CUSTOM_RING_PROOF_LENGTH),
    ...(input.policy === undefined
      ? {}
      : {
          policy: {
            proof: new Uint8Array(CUSTOM_RING_PROOF_LENGTH),
            ownRootIndex: input.policy.inputs.own.rootIndex,
            ...(input.policy.inputs.curator === undefined
              ? {}
              : { curatorRootIndex: input.policy.inputs.curator.root.rootIndex }),
            ...(input.policy.senderCommitment === undefined
              ? {}
              : { senderCommitment: input.policy.senderCommitment }),
          },
        }),
    approvalRequired: input.approvalRequired,
    previousEpoch: false,
    ...(input.anonymous?.anchor === undefined ? {} : { anchor: input.anonymous.anchor }),
    expiryUnixTs: Number(U32_MAX),
    txViewingU: input.txViewingU,
    salt: external.salt,
    interfaceTransfers: external.interfaceTransfers.map(interfaceTransferOf),
    ...(external.dataHash === undefined ? {} : { dataHash: external.dataHash }),
    ...(external.ringDataHash === undefined ? {} : { ringDataHash: external.ringDataHash }),
    dataFree: input.audit.dataFree,
    keyEscrow: input.audit.keyEscrow,
    fullOpenings: input.audit.fullOpenings,
    outputs: Object.freeze(outputs),
    ephU: input.ephemeralU,
    sealed: input.sealed,
    disclosure: input.disclosure,
    privateTxHash: input.privateTxHash,
    ...(input.rail === "anonymous"
      ? {
          anonymous: {
            commitment: zeroField(),
            commitmentPok: zeroField(),
            // SPP names the hidden owner's key exactly when a default-ring note is spent.
            ...(input.audit.fullOpenings ? { defaultOwnerTag: zeroField() } : {}),
          },
        }
      : {}),
    sppProof: new Uint8Array(PLAIN_GROTH16_PROOF_LENGTH),
    nullifiers: Object.freeze(
      input.proofInputs.inputUtxos
        .filter((spent) => !spent.isCompact())
        .map((spent) => spent.nullifier()),
    ),
    inputTrees,
  });
}

/** The preview with every proof in place, refused unless SPP published the preview's values. */
function provenData(
  input: Readonly<{
    preview: RingTransactData;
    spp: TransactInstructionData;
    privateTxHash: Bytes32;
    publishedInputs: number;
    auditProof: Uint8Array;
    policyProof?: Uint8Array;
  }>,
): RingTransactData {
  const { preview, spp } = input;
  // SPP publishes the nullifier of every input slot but compact padding.
  const inputs = spp.inputs.slice(0, input.publishedInputs);
  const nullifiers = inputs.map((spent) => spent.nullifierHash);
  if (
    inputs.length !== input.publishedInputs ||
    !equalBytes(spp.privateTxHash, input.privateTxHash) ||
    nullifiers.some(
      (nullifier, index) => !equalBytes(nullifier, preview.nullifiers[index] ?? zeroField()),
    )
  )
    throw new RingError("RING_SPP_PROOF_MISMATCH");
  const [first, second, ...rest] = spp.treeContexts;
  if (first === undefined || rest.length > 0) throw new RingError("RING_SPP_PROOF_MISMATCH");
  const inputTrees: InputTrees =
    second === undefined
      ? { kind: "one", context: first }
      : {
          kind: "two",
          first,
          second,
          secondInputs: inputs.reduce(
            (bits, spent, index) => (spent.treeIndex === 1 ? bits | (1n << BigInt(index)) : bits),
            0n,
          ),
        };
  const circuit = spp.circuit;
  const anonymous =
    circuit.kind === "anonymousRingEddsa"
      ? {
          commitment: circuit.proofData.bsb22Commitment.commitment,
          commitmentPok: circuit.proofData.bsb22Commitment.commitmentPok,
          ...(circuit.proofData.defaultOwnerTag === undefined
            ? {}
            : { defaultOwnerTag: circuit.proofData.defaultOwnerTag }),
        }
      : undefined;
  if ((anonymous !== undefined) !== (preview.rail === "anonymous"))
    throw new RingError("RING_SPP_PROOF_MISMATCH");
  const sppProof = new Uint8Array(PLAIN_GROTH16_PROOF_LENGTH);
  sppProof.set(spp.proof.a, 0);
  sppProof.set(compressG2(spp.proof.b), 32);
  sppProof.set(spp.proof.c, 96);
  return Object.freeze({
    ...preview,
    auditProof: input.auditProof,
    ...(preview.policy === undefined || input.policyProof === undefined
      ? {}
      : { policy: { ...preview.policy, proof: input.policyProof } }),
    ...(anonymous === undefined ? {} : { anonymous }),
    sppProof,
    nullifiers: Object.freeze(nullifiers),
    inputTrees,
  });
}

function anonymousAuditValues(
  input: Readonly<{
    privateTxHash: Bytes32;
    privateTxBlinding: Bytes32;
    senderCommitment: Bytes32 | undefined;
    spend: AnonymousSpendValues;
  }>,
): AnonymousAuditValues {
  return Object.freeze({
    privateTxHash: input.privateTxHash,
    privateTxBlinding: input.privateTxBlinding,
    senderCommitment: input.senderCommitment ?? zeroField(),
    epoch: input.spend.epoch,
    firstContactRoot: input.spend.anchor?.root ?? zeroField(),
    ...(input.spend.anchor === undefined ? {} : { anchor: input.spend.anchor.request }),
  });
}

/** Each real input spends once, a repeated nullifier fails on chain after proving. */
function checkDistinctInputs(proofInputs: SppProofInputs): void {
  const seen = new Set<string>();
  proofInputs.inputUtxos.forEach((spent, index) => {
    if (spent.isDummy()) return;
    const key = bytesKey(spent.nullifier());
    if (seen.has(key)) throw new RingError("RING_DUPLICATE_INPUT", { details: { index } });
    seen.add(key);
  });
}

/** Every ring field names the transfer's ring, and only a ring note carries ring data. */
function checkMembership(ringProgramId: Address, proofInputs: SppProofInputs): void {
  const slots = [
    ...proofInputs.inputUtxos.map((spent) => ({
      ring: spent.utxo.ringProgramId,
      data: spent.ringDataHash,
    })),
    ...proofInputs.outputs.map((output) => ({
      ring: output.ringProgramId,
      data: output.ringDataHash,
    })),
  ];
  for (const { ring, data } of slots) {
    if (ring !== undefined && ring !== ringProgramId)
      throw new RingError("RING_FOREIGN_RING", { details: { ring } });
    if (ring === undefined && data !== undefined) throw new RingError("RING_DATA_OUTSIDE_RING");
  }
}

/** @internal What a submission attempt of `proven` checks before it proves again. */
export function boundState(proven: ProvenRingTransfer): RingBoundState {
  return Object.freeze({
    ...(proven.roots.length === 0 ? {} : { roots: proven.roots }),
    ...(proven.policy === undefined ? {} : { policy: proven.policy }),
    ...(proven.anchor === undefined ? {} : { anchor: proven.anchor }),
    ...(proven.epoch === undefined ? {} : { epoch: proven.epoch }),
  });
}

function boundRoots(policy: PolicyInputs): readonly BoundRoot[] {
  return Object.freeze(
    policy.curator === undefined ? [policy.own] : [policy.own, policy.curator.root],
  );
}

function transactTag(rail: RingRail): RingInstructionTag {
  return rail === "delegate" ? RingInstructionTag.delegateTransact : RingInstructionTag.transact;
}

/** Zero without a co-signer, the anonymous rail's expansion appends it. */
function coSignerField(config: RingProgramConfig): Bytes32 {
  return config.coSigner === undefined
    ? zeroField()
    : (addressBytes(config.coSigner.signer, "coSigner") as Bytes32);
}

function wipeAuditRequest(request: Readonly<{ txViewingSk: Bytes32; ephSk: Bytes32 }>): void {
  request.txViewingSk.fill(0);
  request.ephSk.fill(0);
}

function zeroField(): Bytes32 {
  return new Uint8Array(32) as Bytes32;
}

const U32_MAX = 0xffff_ffffn;
