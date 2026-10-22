/** The three rails of a ring transfer, Rust `RingTransfer<Owner>`, `<Anonymous>` and `<Delegated>`. */
import { ownerSignerAddresses } from "../client/prover/assembly.js";
import type {
  ProofAuthority,
  ProofReader,
  Prover,
  SlotReader,
  WalletKeys,
} from "../client/ports.js";
import { isRingAuthorityShape, type Shape } from "../interface/shape.js";
import { InstructionTag } from "../interface/program.js";
import {
  DELIVERED_AUDIT_CAPACITIES,
  PACKED_AUDIT_CAPACITIES,
} from "../interface/ring-disclosure-layout.js";
import type { Address, RequestContext, TransactWithdrawal } from "../interface/types.js";
import { randomBytes } from "../keypair/bytes.js";
import { tagEpoch } from "../keypair/ring-stream.js";
import type { ShieldedAddress } from "../keypair/shielded.js";
import { ViewingKey } from "../keypair/viewing-key.js";
import type { AssetRegistry } from "../transaction/asset.js";
import {
  ringSpendMessage,
  prepareRingAuthorityTransfer,
  type ConfidentialTransfer,
  type PreparedTransfer,
} from "../transaction/instructions/transact.js";
import type { ProofInputUtxo } from "../transaction/utxo.js";
import type { AnonymousRingState } from "../transaction/wallet/anonymous-state.js";
import { isRingKeys, type RingKeys } from "../transaction/wallet/keys.js";
import { TagAllocation } from "../wallet/anonymous-sync.js";

import {
  anchorWitness,
  anonymousExitTokenOwner,
  checkAnonymousSigner,
  checkAnonymousSlots,
  pendingFirstContacts,
  type AnonymousPayment,
  type AnonymousSpendSigner,
} from "./anonymous.js";
import type { RingProgramConfig } from "./codecs.js";
import { fetchRingProgramConfig, requireActiveRing } from "./config.js";
import { RingError } from "./error.js";
import {
  proveStagedTransfer,
  type ProvenRingTransfer,
  type RingProvingClient,
  type RingTransactionFrame,
  type StagedTransfer,
  type StagedTransferInput,
} from "./pipeline.js";
import { AnonymousSlots, RingOutputRail, type RingDelivery } from "./rail.js";

/** @internal */
export interface RingTransferApproval {
  readonly transaction: RingTransactionFrame;
  /** Runs once the transfer fits its transaction, before any proof. */
  approve(
    transfer: Readonly<{ prepared: PreparedTransfer; coSigner: Address | undefined }>,
  ): Promise<void>;
}

export type CustomRingTransferClient = RingProvingClient & Pick<Prover, "proveRingTransact">;

export type AnonymousTransferClient = RingProvingClient &
  SlotReader &
  Pick<ProofReader, "getMerkleProofs"> &
  Pick<Prover, "proveAnonymousRingTransact">;

export type DelegateTransferClient = RingProvingClient & Pick<Prover, "proveRingAuthorityTransact">;

/** Rust `CustomRingTransferInput`. */
export interface CustomRingTransferInput {
  readonly ringProgramId: Address;
  /** Reads the sender's address and transaction keys and completes its inputs, no secret leaves it. */
  readonly keys: WalletKeys;
  /** Prepared by the rail, every output it already holds keeps its slot. */
  readonly transfer: ConfidentialTransfer;
  readonly assets: AssetRegistry;
}

/** The confidential rail, the owner signs its spends in public, Rust `RingTransfer<Owner>`. */
export class CustomRingTransfer {
  readonly #input: CustomRingTransferInput;
  readonly #withdrawal: TransactWithdrawal | undefined;

  private constructor(input: CustomRingTransferInput, withdrawal: TransactWithdrawal | undefined) {
    this.#input = input;
    this.#withdrawal = withdrawal;
    Object.freeze(this);
  }

  static new(input: CustomRingTransferInput): CustomRingTransfer {
    input.transfer.withRingProgramId(input.ringProgramId);
    return new CustomRingTransfer(input, undefined);
  }

  /** The settlement accounts of the transfer's public withdrawal, Rust `with_interface_transfer_accounts`. */
  withWithdrawalAccounts(withdrawal: TransactWithdrawal): CustomRingTransfer {
    return new CustomRingTransfer(this.#input, withdrawal);
  }

  /** The hidden Ed25519 owner an anonymous ring proves, it must be the sender's signing key. */
  withAnonymousSigner(signer: AnonymousSpendSigner, state: AnonymousRingState): AnonymousTransfer {
    return AnonymousTransfer.of({
      owner: this.#input,
      ...(this.#withdrawal === undefined ? {} : { withdrawal: this.#withdrawal }),
      signer,
      state,
    });
  }

  prove(client: CustomRingTransferClient, context?: RequestContext): Promise<ProvenRingTransfer> {
    return this.#prove(client, undefined, context);
  }

  /** @internal */
  proveApproved(
    client: CustomRingTransferClient,
    approval: RingTransferApproval,
    context?: RequestContext,
  ): Promise<ProvenRingTransfer> {
    return this.#prove(client, approval, context);
  }

  async #prove(
    client: CustomRingTransferClient,
    approval: RingTransferApproval | undefined,
    context: RequestContext | undefined,
  ): Promise<ProvenRingTransfer> {
    const { ringProgramId, keys } = this.#input;
    const config = await activeConfig(client, ringProgramId, context);
    if (config.mode === "anonymous")
      throw new RingError("RING_ANONYMOUS_SIGNER_REQUIRED", { details: { ringProgramId } });
    const sender = keys.address();
    const prepared = this.#input.transfer.prepare();
    checkWithdrawalAccounts(prepared, this.#withdrawal);
    const rail = new RingOutputRail(
      await transactionKey(keys, sender, prepared, context),
      prepared.firstNullifier,
      confidentialDelivery(prepared.shape, "confidential"),
    );
    try {
      const proofInputs = rail.encrypt({
        prepared,
        sender,
        assets: this.#input.assets,
        instructionDiscriminator: InstructionTag.ringTransact,
      });
      const ownerSigners = ownerSignerAddresses(proofInputs.inputUtxos, proofInputs.outputs);
      // A policy ring spends for exactly one owner.
      const mixed = ownerSigners.findIndex((signer) => signer !== ownerSigners[0]);
      if (config.hasPolicy && mixed >= 0)
        throw new RingError("RING_MIXED_OWNERS", { details: { index: mixed } });
      return await proveStagedTransfer(
        {
          client,
          ringProgramId,
          config,
          staged: {
            proofInputs,
            rail,
            sender,
            ownerSigners,
            ...(this.#withdrawal === undefined ? {} : { withdrawal: this.#withdrawal }),
            spend: {
              rail: "confidential",
              prove: (inputs, _coSigner, proveContext) =>
                client.proveRingTransact(
                  inputs,
                  ringProgramId,
                  keys,
                  { outputTree: client },
                  proveContext,
                ),
            },
          },
          ...approvedStage(approval, prepared),
        },
        context,
      );
    } finally {
      rail.txViewingKey.destroy();
    }
  }
}

/** The hidden owner's spends on an anonymous ring, no transaction signer names the owner, Rust `RingTransfer<Anonymous>`. */
export class AnonymousTransfer {
  readonly #owner: CustomRingTransferInput;
  readonly #withdrawal: TransactWithdrawal | undefined;
  readonly #signer: AnonymousSpendSigner;
  readonly #state: AnonymousRingState;
  /** Each payment and its position among the transfer's sends. */
  readonly #payments: readonly Readonly<{ send: number; payment: AnonymousPayment }>[];
  readonly #shape: Shape | undefined;
  readonly #exitTokenOwner: Address | undefined;
  readonly #tagRandom: (length: number) => Uint8Array;

  private constructor(fields: AnonymousFields) {
    this.#owner = fields.owner;
    this.#withdrawal = fields.withdrawal;
    this.#signer = fields.signer;
    this.#state = fields.state;
    this.#payments = fields.payments;
    this.#shape = fields.shape;
    this.#exitTokenOwner = fields.exitTokenOwner;
    this.#tagRandom = fields.tagRandom;
    Object.freeze(this);
  }

  /** @internal */
  static of(
    input: Readonly<{
      owner: CustomRingTransferInput;
      withdrawal?: TransactWithdrawal;
      signer: AnonymousSpendSigner;
      state: AnonymousRingState;
    }>,
  ): AnonymousTransfer {
    return new AnonymousTransfer({
      owner: input.owner,
      withdrawal: input.withdrawal,
      signer: input.signer,
      state: input.state,
      payments: Object.freeze([]),
      shape: undefined,
      exitTokenOwner: undefined,
      tagRandom: randomBytes,
    });
  }

  /** Every ring output owner other than the sender is paid here, Rust `with_payment`. */
  withPayment(payment: AnonymousPayment): AnonymousTransfer {
    if (payment.to.ringProgramId !== this.#owner.ringProgramId)
      throw new RingError("RING_FOREIGN_RING", {
        details: { address: payment.to.ringProgramId, ring: this.#owner.ringProgramId },
      });
    const send = this.#owner.transfer.sendToRing(
      payment.to.recipient,
      payment.asset,
      payment.amount,
      payment.to.ringProgramId,
    );
    return new AnonymousTransfer({
      ...this.#fields(),
      payments: Object.freeze([...this.#payments, Object.freeze({ send, payment })]),
    });
  }

  /** Pads to `shape`, else the transfer takes the smallest supported shape. */
  withShape(shape: Shape): AnonymousTransfer {
    this.#owner.transfer.withShape(shape);
    return new AnonymousTransfer({ ...this.#fields(), shape });
  }

  /** A missing exit token account must be the owner's associated token account. */
  withExitTokenOwner(owner: Address): AnonymousTransfer {
    return new AnonymousTransfer({ ...this.#fields(), exitTokenOwner: owner });
  }

  /** @internal */
  withTagRandom(tagRandom: (length: number) => Uint8Array): AnonymousTransfer {
    return new AnonymousTransfer({ ...this.#fields(), tagRandom });
  }

  prove(client: AnonymousTransferClient, context?: RequestContext): Promise<ProvenRingTransfer> {
    return this.#prove(client, undefined, context);
  }

  /** @internal */
  proveApproved(
    client: AnonymousTransferClient,
    approval: RingTransferApproval,
    context?: RequestContext,
  ): Promise<ProvenRingTransfer> {
    return this.#prove(client, approval, context);
  }

  async #prove(
    client: AnonymousTransferClient,
    approval: RingTransferApproval | undefined,
    context: RequestContext | undefined,
  ): Promise<ProvenRingTransfer> {
    const { ringProgramId, keys } = this.#owner;
    const config = await activeConfig(client, ringProgramId, context);
    if (config.mode !== "anonymous")
      throw new RingError("RING_NOT_ANONYMOUS", { details: { ringProgramId } });
    if (!isRingKeys(keys)) throw new RingError("RING_KEYS_REQUIRED");
    const sender = keys.address();
    const prepared = this.#owner.transfer.prepare();
    checkWithdrawalAccounts(prepared, this.#withdrawal);
    const owner = checkAnonymousSigner({
      signer: this.#signer,
      sender,
      payer: prepared.payer,
      coSigner: config.coSigner?.signer,
    });
    const exitTokenOwner = await anonymousExitTokenOwner(
      {
        client,
        transfers: prepared.interfaceTransfers,
        hiddenOwner: owner,
        ...(this.#exitTokenOwner === undefined ? {} : { tokenOwner: this.#exitTokenOwner }),
      },
      context,
    );
    // Tags bind slots, the slot order is fixed before any stream is read.
    const epoch = tagEpoch(await client.getSlot(context));
    const plan = await this.#plan({ keys, prepared, epoch }, context);
    const rail = new RingOutputRail(
      await transactionKey(keys, sender, prepared, context),
      prepared.firstNullifier,
      { kind: "anonymous", slots: plan.slots },
    );
    try {
      const proofInputs = rail.encrypt({
        prepared,
        sender,
        assets: this.#owner.assets,
        instructionDiscriminator: InstructionTag.ringTransact,
      });
      checkAnonymousSlots(proofInputs);
      const anchor =
        plan.contact === undefined
          ? undefined
          : await anchorWitness({ client, state: this.#state, contact: plan.contact }, context);
      const staged: StagedTransfer = {
        proofInputs,
        rail,
        sender,
        ownerSigners: [],
        ...(this.#withdrawal === undefined ? {} : { withdrawal: this.#withdrawal }),
        spend: {
          rail: "anonymous",
          prove: async (inputs, coSigner, proveContext) =>
            client.proveAnonymousRingTransact(
              {
                proofInputs: inputs,
                ringProgramId,
                owner: {
                  publicKey: owner,
                  signature: await this.#signer.sign(
                    ringSpendMessage(ringProgramId, inputs.messageHash()),
                    proveContext,
                  ),
                },
                ...(config.coSigner === undefined ? {} : { cosigner: config.coSigner.signer }),
                ...(exitTokenOwner === undefined ? {} : { exitTokenOwner }),
                keys,
                config: { outputTree: client },
              },
              proveContext,
            ),
          anonymous: {
            epoch,
            ...(anchor === undefined ? {} : { anchor }),
            firstContacts: pendingFirstContacts({
              rail,
              proofInputs,
              payments: plan.payments,
              epoch,
            }),
          },
        },
      };
      return await proveStagedTransfer(
        { client, ringProgramId, config, staged, ...approvedStage(approval, prepared) },
        context,
      );
    } finally {
      rail.txViewingKey.destroy();
    }
  }

  /**
   * Every payment takes the tag its recipient's stream allocates in `epoch`, the one pair payment
   * names its anchor, Rust `Anonymous::stage`.
   */
  async #plan(
    input: Readonly<{
      keys: RingKeys;
      prepared: PreparedTransfer;
      epoch: bigint;
    }>,
    context: RequestContext | undefined,
  ): Promise<
    Readonly<{
      slots: AnonymousSlots;
      payments: ReadonlyMap<number, AnonymousPayment>;
      contact?: Parameters<typeof anchorWitness>[0]["contact"];
    }>
  > {
    const { keys, prepared } = input;
    const ring = this.#owner.ringProgramId;
    const issued = this.#state.issued.map((address) => address.index);
    const [changeKey, addressKeys] = await Promise.all([
      keys.ringChangeKey(ring, context),
      keys.ringAddressKeys(ring, issued, context),
    ]);
    let slots = AnonymousSlots.create(changeKey, prepared.shape.outputs).withRingAddressKeys(
      addressKeys,
    );
    // `prepare` keeps every send after the change and in order, padding only appends.
    const firstSend = prepared.outputs.length - this.#owner.transfer.recipientCount;
    const payments = new Map(
      this.#payments.map(({ send, payment }) => [firstSend + send, payment] as const),
    );
    const allocation = new TagAllocation(this.#state, input.epoch);
    let contact: Parameters<typeof anchorWitness>[0]["contact"] | undefined;
    for (const [slotIndex, payment] of payments) {
      const tag = allocation.allocate(payment.to, this.#tagRandom);
      if (tag.stream.kind === "pair") contact = tag.stream.contact;
      slots = slots.withPayment(slotIndex, {
        recipient: payment.to.recipient.viewingPublicKey,
        tag: tag.tag,
        position: { kind: tag.stream.kind, index: tag.index },
      });
    }
    return Object.freeze({ slots, payments, ...(contact === undefined ? {} : { contact }) });
  }

  #fields(): AnonymousFields {
    return {
      owner: this.#owner,
      withdrawal: this.#withdrawal,
      signer: this.#signer,
      state: this.#state,
      payments: this.#payments,
      shape: this.#shape,
      exitTokenOwner: this.#exitTokenOwner,
      tagRandom: this.#tagRandom,
    };
  }
}

interface AnonymousFields {
  readonly owner: CustomRingTransferInput;
  readonly withdrawal: TransactWithdrawal | undefined;
  readonly signer: AnonymousSpendSigner;
  readonly state: AnonymousRingState;
  readonly payments: readonly Readonly<{ send: number; payment: AnonymousPayment }>[];
  readonly shape: Shape | undefined;
  readonly exitTokenOwner: Address | undefined;
  readonly tagRandom: (length: number) => Uint8Array;
}

/** One output of a delegate move, inside the ring. */
export interface DelegateOutput {
  readonly recipient: ShieldedAddress;
  readonly asset: Address;
  readonly amount: bigint;
}

/** Rust `DelegateTransferInput`. */
export interface DelegateTransferInput {
  readonly ringProgramId: Address;
  /** Signs the transaction beside the payer. */
  readonly delegate: Address;
  readonly payer: Address;
  /** The member whose notes move, its change returns to it. */
  readonly source: ShieldedAddress;
  /** Completes the source's inputs with the escrowed key the delegate recovered. */
  readonly sourceProofs: ProofAuthority;
  readonly inputs: readonly ProofInputUtxo[];
  readonly outputs: readonly DelegateOutput[];
  readonly assets: AssetRegistry;
  /** The outputs land in the first input's tree unless named. */
  readonly outputTreeId?: number;
}

/** The delegate moves one member's notes with the member's escrowed key, the member does not sign, Rust `RingTransfer<Delegated>`. */
export class DelegateTransfer {
  readonly #input: DelegateTransferInput;
  readonly #shape: Shape | undefined;

  private constructor(input: DelegateTransferInput, shape: Shape | undefined) {
    this.#input = input;
    this.#shape = shape;
    Object.freeze(this);
  }

  static new(input: DelegateTransferInput): DelegateTransfer {
    return new DelegateTransfer(input, undefined);
  }

  /** Pads to `shape`, one of `RING_AUTHORITY_SHAPES`, else the move takes the cheapest that holds it. */
  withShape(shape: Shape): DelegateTransfer {
    if (!isRingAuthorityShape(shape))
      throw new RingError("RING_TRANSACT_DATA_INVALID", {
        details: { reason: "RingShapeUnkeyed", rail: "delegate" },
      });
    return new DelegateTransfer(this.#input, shape);
  }

  prove(client: DelegateTransferClient, context?: RequestContext): Promise<ProvenRingTransfer> {
    return this.#prove(client, undefined, context);
  }

  /** @internal */
  proveApproved(
    client: DelegateTransferClient,
    approval: RingTransferApproval,
    context?: RequestContext,
  ): Promise<ProvenRingTransfer> {
    return this.#prove(client, approval, context);
  }

  async #prove(
    client: DelegateTransferClient,
    approval: RingTransferApproval | undefined,
    context: RequestContext | undefined,
  ): Promise<ProvenRingTransfer> {
    const input = this.#input;
    const { ringProgramId } = input;
    const config = await activeConfig(client, ringProgramId, context);
    if (config.delegate === undefined)
      throw new RingError("RING_DELEGATE_INVALID", { details: { reason: "missing" } });
    if (config.delegate !== input.delegate)
      throw new RingError("RING_DELEGATE_INVALID", { details: { reason: "unauthorized" } });
    if (config.mode !== "registry" || !config.hasPolicy)
      throw new RingError("RING_DELEGATE_INVALID", { details: { reason: "escrow" } });
    // A delegate move spends one member's notes.
    const mixed = input.inputs.findIndex(
      (spent) => !spent.utxo.owner.equals(input.source.signingPublicKey),
    );
    if (mixed >= 0) throw new RingError("RING_MIXED_OWNERS", { details: { index: mixed } });
    const first = input.inputs[0];
    if (first === undefined)
      throw new RingError("RING_DELEGATE_INVALID", { details: { reason: "inputs" } });
    const prepared = prepareRingAuthorityTransfer({
      owner: input.source,
      inputs: input.inputs,
      outputs: input.outputs,
      payer: input.payer,
      ringProgramId,
      outputTreeId: input.outputTreeId ?? first.treeId,
      ...(this.#shape === undefined ? {} : { shape: this.#shape }),
    });
    // The member never signs, a fresh transaction key seals the move to the auditor.
    const rail = new RingOutputRail(
      ViewingKey.generate(),
      prepared.firstNullifier,
      confidentialDelivery(prepared.shape, "delegate"),
    );
    try {
      const proofInputs = rail.encrypt({
        prepared,
        sender: input.source,
        assets: input.assets,
        instructionDiscriminator: InstructionTag.ringAuthorityTransact,
      });
      return await proveStagedTransfer(
        {
          client,
          ringProgramId,
          config,
          staged: {
            proofInputs,
            rail,
            sender: input.source,
            ownerSigners: [],
            spend: {
              rail: "delegate",
              delegate: input.delegate,
              prove: (inputs, _coSigner, proveContext) =>
                client.proveRingAuthorityTransact(
                  inputs,
                  ringProgramId,
                  input.sourceProofs,
                  proveContext,
                  client,
                ),
            },
          },
          ...approvedStage(approval, prepared),
        },
        context,
      );
    } finally {
      rail.txViewingKey.destroy();
    }
  }
}

/** The approval a pipeline runs, bound to the prepared transfer the rail proves. */
function approvedStage(
  approval: RingTransferApproval | undefined,
  prepared: PreparedTransfer,
): Pick<StagedTransferInput, "transaction" | "approve"> {
  if (approval === undefined) return {};
  return {
    transaction: approval.transaction,
    approve: (coSigner) => approval.approve({ prepared, coSigner }),
  };
}

/** The ring's config once SPP's registration admits it, Rust `require_config` and `require_active`. */
async function activeConfig(
  client: RingProvingClient,
  ringProgramId: Address,
  context: RequestContext | undefined,
): Promise<RingProgramConfig> {
  const [config] = await Promise.all([
    fetchRingProgramConfig(client, ringProgramId, context),
    requireActiveRing(client, ringProgramId, context),
  ]);
  return config;
}

/** Up to four outputs pack their ciphertexts, eight and sixteen deliver proven bodies. */
function confidentialDelivery(shape: Shape, rail: "confidential" | "delegate"): RingDelivery {
  if (PACKED_AUDIT_CAPACITIES.includes(shape.outputs)) return { kind: "packed" };
  if (DELIVERED_AUDIT_CAPACITIES.includes(shape.outputs)) return { kind: "delivered" };
  throw new RingError("RING_TRANSACT_DATA_INVALID", {
    details: { reason: "RingShapeUnkeyed", rail },
  });
}

/** The sender's transaction key, derived by its key holder from the first nullifier. */
async function transactionKey(
  keys: WalletKeys,
  sender: ShieldedAddress,
  prepared: PreparedTransfer,
  context: RequestContext | undefined,
): Promise<ViewingKey> {
  const derived = await keys.transactionKeys(
    [{ viewingPublicKey: sender.viewingPublicKey, firstNullifier: prepared.firstNullifier }],
    context,
  );
  const [key, ...extra] = derived;
  for (const surplus of extra) surplus.destroy();
  if (key === undefined)
    throw new RingError("RING_KEYS_REQUIRED", { details: { reason: "transactionKey" } });
  return key;
}

/** A public withdrawal names its settlement accounts, a transfer without one names none. */
function checkWithdrawalAccounts(
  prepared: PreparedTransfer,
  withdrawal: TransactWithdrawal | undefined,
): void {
  const leg = prepared.interfaceTransfers.find((transfer) => !transfer.isDeposit);
  const matches =
    leg === undefined
      ? withdrawal === undefined
      : withdrawal !== undefined &&
        (leg.kind === "sol"
          ? withdrawal.kind === "sol" && withdrawal.recipient === leg.userSolAccount
          : withdrawal.kind === "spl" &&
            withdrawal.mint === leg.mint &&
            withdrawal.recipientTokenAccount === leg.tokenAccount);
  if (!matches) throw new RingError("RING_SETTLEMENT_ACCOUNTS_INVALID");
}
