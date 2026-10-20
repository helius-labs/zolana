/** The hidden owner's rail of an anonymous ring, mirrors Rust `pipeline::anonymous`. */
import type { MessagePartialSigner } from "@solana/kit";

import type { IndexerReader } from "../client/ports.js";
import type { CustomRingAnonymousIdentities } from "../client/prover/types.js";
import { SOLANA_OWNER_TAG, hashBytes } from "../hasher/index.js";
import { addressBytes } from "../interface/internal.js";
import { isAnonymousRingShape } from "../interface/shape.js";
import type { Address, Bytes32, Bytes64, RequestContext } from "../interface/types.js";
import { AUDIT_OUTPUT_SLOTS, type AuditInputOpening } from "../keypair/audit.js";
import { ShieldedPublicKey } from "../keypair/public-key.js";
import { RingAddress } from "../keypair/ring-address.js";
import type { ShieldedAddress } from "../keypair/shielded.js";
import type { SigningKey } from "../keypair/signing-key.js";
import type { ViewingKey } from "../keypair/viewing-key.js";
import { X25519PublicKey } from "../keypair/x25519.js";
import type {
  ConfidentialTransfer,
  PreparedTransfer,
  SppProofInputs,
} from "../transaction/instructions/transact.js";
import {
  EncryptedScheme,
  RING_ANONYMOUS_PLAINTEXT_LENGTH,
  readOutputData,
} from "../transaction/serialization/codecs.js";
import type { ProofOutputUtxo } from "../transaction/utxo.js";
import type { AnonymousRingSlot } from "../transaction/wallet/anonymous-ring.js";
import {
  AnonymousTagAllocator,
  TagStream,
  type AnonymousRingDestination,
} from "../wallet/tag-stream.js";

import { equalBytes } from "../wallet/internal.js";

import { RingError } from "./error.js";
import { signMessage } from "./rpc.js";

/** The hidden owner's Ed25519 key, the signature lives inside the proof so the key may live in a wallet. Rust `AnonymousSpendSigner`. */
export interface AnonymousSpendSigner {
  publicKey(): ShieldedPublicKey;
  /** RFC 8032 Ed25519 over the 84-byte `ringSpendMessage`. */
  sign(message: Uint8Array, context?: RequestContext): Promise<Bytes64>;
}

/** Where a payment to an address is tagged, the full address is always carried. Rust `AnonymousRecipient`. */
export type AnonymousRingRecipient =
  /** A first payment, on the inbox stream of the shared address. */
  | Readonly<{ kind: "address"; address: RingAddress }>
  /** A recipient paid or received from before, on the pair stream toward its viewing key. */
  | Readonly<{ kind: "paired"; address: RingAddress }>;

/** An output built from the address it pays, in the address's ring. Rust `AnonymousPayment`. */
export type AnonymousRingPayment = Readonly<{
  to: AnonymousRingRecipient;
  asset: Address;
  amount: bigint;
}>;

/** A prepared anonymous transfer, each payment slot keeps the address its output was built from. */
export class AnonymousPreparedTransfer {
  readonly transfer: PreparedTransfer;
  readonly #recipients: ReadonlyMap<number, AnonymousRingRecipient>;

  private constructor(
    transfer: PreparedTransfer,
    recipients: ReadonlyMap<number, AnonymousRingRecipient>,
  ) {
    this.transfer = transfer;
    this.#recipients = recipients;
    Object.freeze(this);
  }

  /** Sends every payment after the outputs `transfer` already holds, then prepares it. */
  static prepare(
    transfer: ConfidentialTransfer,
    payments: readonly AnonymousRingPayment[],
  ): AnonymousPreparedTransfer {
    for (const { to, asset, amount } of payments)
      transfer.sendToRing(to.address.recipient, asset, amount, to.address.ringProgramId);
    const prepared = transfer.prepare();
    // `prepare` keeps sends last and in order, padding only appends.
    const first = prepared.outputs.length - payments.length;
    return new AnonymousPreparedTransfer(
      prepared,
      new Map(payments.map((payment, index) => [first + index, payment.to])),
    );
  }

  recipient(slotIndex: number): AnonymousRingRecipient | undefined {
    return this.#recipients.get(slotIndex);
  }

  recipients(): readonly AnonymousRingRecipient[] {
    return [...this.#recipients.values()];
  }
}

/** Signs with an in-process key, the caller keeps and destroys it. */
export function signingKeySpendSigner(key: SigningKey): AnonymousSpendSigner {
  return Object.freeze({
    publicKey: () => key.publicKey(),
    sign: (message: Uint8Array) => Promise.resolve(key.sign(message)),
  });
}

/** Signs through a kit message signer, a wallet adapter's `signMessage`. */
export function messageSignerSpendSigner(signer: MessagePartialSigner): AnonymousSpendSigner {
  // A base58 address decodes to exactly 32 bytes.
  const publicKey = ShieldedPublicKey.fromEd25519(addressBytes(signer.address) as Bytes32);
  return Object.freeze({
    publicKey: () => publicKey,
    sign: (message: Uint8Array) => signMessage(signer, message),
  });
}

/** The hidden owner may sign no public slot, a public signature would undo the hiding. */
export function checkAnonymousSigner(
  input: Readonly<{
    signer: AnonymousSpendSigner;
    viewingKey: ViewingKey;
    sender: ShieldedAddress;
    payer: Address;
    cosigner: Address | undefined;
  }>,
): Bytes32 {
  const signing = input.signer.publicKey();
  if (!(signing instanceof ShieldedPublicKey) || !signing.equals(input.sender.signingPublicKey))
    throw new RingError("RING_ANONYMOUS_SIGNER_MISMATCH", { details: { role: "signing" } });
  if (!input.viewingKey.publicKey().equals(input.sender.viewingPublicKey))
    throw new RingError("RING_ANONYMOUS_SIGNER_MISMATCH", { details: { role: "viewing" } });
  const owner = signing.ed25519();
  if (
    [input.payer, input.cosigner].some(
      (party) => party !== undefined && equalBytes(addressBytes(party), owner),
    )
  )
    throw new RingError("RING_ANONYMOUS_SIGNER_LINKS_OWNER");
  return owner;
}

/** Rust `check_anonymous_slots` over the prepared transfer, before any stream is read. */
export function checkAnonymousSlots(prepared: PreparedTransfer): void {
  if (!isAnonymousRingShape(prepared.shape))
    throw new RingError("RING_ANONYMOUS_SHAPE_UNSUPPORTED", {
      details: { inputs: prepared.shape.inputs, outputs: prepared.shape.outputs },
    });
  const outputs = prepared.proofOutputs();
  if (
    prepared.compactPadding === true ||
    prepared.inputs.some((input) => input.cacheSlot !== undefined || input.isCompact()) ||
    outputs.some(
      (output) =>
        output.cacheSlot !== undefined ||
        output.isCompact() ||
        (!output.isDummy() && output.ownerAddress?.signingPublicKey.signatureType() !== "ed25519"),
    )
  )
    throw new RingError("RING_ANONYMOUS_SLOT_INVALID");
  if (outputs.some(hasOutputData)) throw new RingError("RING_ANONYMOUS_OUTPUT_DATA");
}

function hasOutputData(output: ProofOutputUtxo): boolean {
  const nonzero = (hash: Bytes32 | undefined): boolean =>
    hash !== undefined && hash.some((byte) => byte !== 0);
  return !output.data.isEmpty() || nonzero(output.dataHash) || nonzero(output.ringDataHash);
}

/** One window read per stream, every slot takes the lowest index free in history and in the transaction. */
export async function anonymousSlotTags(
  input: Readonly<{
    indexer: Pick<IndexerReader, "getShieldedTransactionsByTags">;
    viewingKey: ViewingKey;
    sender: ShieldedAddress;
    ringProgramId: Address;
    prepared: AnonymousPreparedTransfer;
  }>,
  context?: RequestContext,
): Promise<readonly (AnonymousRingSlot | undefined)[]> {
  const foreign = input.prepared
    .recipients()
    .find((recipient) => recipient.address.ringProgramId !== input.ringProgramId);
  if (foreign !== undefined)
    throw new RingError("RING_FOREIGN_RING", {
      details: { ringProgramId: foreign.address.ringProgramId },
    });
  const change = new RingAddress({
    recipient: input.sender,
    ringProgramId: input.ringProgramId,
    inboxSecret: input.viewingKey.inboxSecret(0),
  });
  const prepared = input.prepared.transfer;
  const destinations = prepared
    .proofOutputs()
    .map((output, slotIndex): AnonymousRingDestination | undefined => {
      const owner = output.ownerAddress;
      // Padding and exits take no derived tag.
      if (owner === undefined || output.ringProgramId === undefined) return undefined;
      if (owner.signingPublicKey.equals(input.sender.signingPublicKey))
        return { kind: "change", address: change };
      const recipient = input.prepared.recipient(slotIndex);
      if (recipient === undefined)
        throw new RingError("RING_ANONYMOUS_RECIPIENT_UNKNOWN", { details: { slotIndex } });
      return recipient.kind === "address"
        ? { kind: "inbox", address: recipient.address }
        : {
            kind: "pair",
            address: recipient.address,
            counterparty: recipient.address.recipient.viewingPublicKey,
          };
    });
  return new AnonymousTagAllocator({
    stream: new TagStream(input.indexer),
    sender: input.viewingKey,
    firstNullifier: prepared.firstNullifier,
  }).assign(destinations, context);
}

/** Every padded input the disclosure names, zero for a padding slot. Rust `anonymous_disclosure`. */
export function anonymousAuditInputs(prepared: PreparedTransfer): readonly AuditInputOpening[] {
  return Array.from({ length: prepared.shape.inputs }, (_, index) => {
    const input = prepared.inputs[index];
    if (input === undefined || input.isDummy())
      return {
        treeId: 0,
        amount: 0n,
        asset: new Uint8Array(32) as Bytes32,
        blinding: new Uint8Array(32) as Bytes32,
      };
    return {
      treeId: input.treeId,
      amount: input.utxo.amount,
      asset: hashBytes(addressBytes(input.utxo.asset)) as Bytes32,
      blinding: input.utxo.blinding,
    };
  });
}

/** The tagged hidden identities, four recipient slots even when the shape has two. Rust `PendingCustomRingProof::identities`. */
export function anonymousIdentities(
  sender: ShieldedAddress,
  outputs: readonly ProofOutputUtxo[],
): CustomRingAnonymousIdentities {
  const tagged = (key: Bytes32): Uint8Array => Uint8Array.of(SOLANA_OWNER_TAG, ...key);
  const slot = (index: number): ShieldedAddress | undefined => outputs[index]?.ownerAddress;
  return Object.freeze({
    sender: tagged(sender.signingPublicKey.ed25519()),
    recipients: Array.from({ length: AUDIT_OUTPUT_SLOTS }, (_, index) => {
      const owner = slot(index);
      return owner === undefined
        ? new Uint8Array(33)
        : tagged(owner.signingPublicKey.confidentialViewTag());
    }),
    recipientViewingKeys: Array.from(
      { length: AUDIT_OUTPUT_SLOTS },
      (_, index) => slot(index)?.viewingPublicKey.toBytes() ?? new Uint8Array(33),
    ),
  });
}

/** The ring program's per-slot parse of an anonymous transact, refused before any prover round. */
export function checkAnonymousOutputs(proofInputs: SppProofInputs): void {
  const external = proofInputs.externalData;
  if (external.outputs.length !== proofInputs.checkShape().outputs)
    throw new RingError("RING_ANONYMOUS_OUTPUT_COUNT");
  const tags = new Set<string>();
  external.outputs.forEach((output, slotIndex) => {
    const frame = outputFrame(output.data, slotIndex);
    const inline = output.ownerTag.kind === "inline" ? output.ownerTag.value : undefined;
    if (frame.encoding === "encrypted" && frame.scheme === EncryptedScheme.ringAnonymous) {
      if (frame.body.length !== RING_ANONYMOUS_PLAINTEXT_LENGTH)
        throw new RingError("RING_ANONYMOUS_OUTPUT_BODY", { details: { slotIndex } });
      if (inline === undefined || inline[0] !== 0 || inline.every((byte) => byte === 0))
        throw new RingError("RING_ANONYMOUS_TAG", { details: { slotIndex } });
      const key = inline.join(",");
      if (tags.has(key))
        throw new RingError("RING_ANONYMOUS_DUPLICATE_TAG", { details: { slotIndex } });
      tags.add(key);
    } else if (
      frame.encoding !== "encrypted" ||
      frame.scheme !== EncryptedScheme.confidential ||
      inline === undefined ||
      inline.every((byte) => byte === 0) ||
      frame.body.length <= 33 ||
      !isViewingKey(frame.body.subarray(0, 33))
    ) {
      // An exit publishes its owner through the inline tag.
      throw new RingError("RING_ANONYMOUS_OUTPUT_SCHEME", { details: { slotIndex } });
    }
    if (output.utxoHash.every((byte) => byte === 0))
      throw new RingError("RING_ANONYMOUS_OUTPUT_HASH", { details: { slotIndex } });
  });
}

function outputFrame(
  data: Uint8Array | undefined,
  slotIndex: number,
): ReturnType<typeof readOutputData> {
  if (data === undefined)
    throw new RingError("RING_ANONYMOUS_OUTPUT_SCHEME", { details: { slotIndex } });
  try {
    return readOutputData(data);
  } catch (cause) {
    throw new RingError("RING_ANONYMOUS_OUTPUT_SCHEME", { details: { slotIndex }, cause });
  }
}

function isViewingKey(bytes: Uint8Array): boolean {
  try {
    X25519PublicKey.fromBytes(bytes);
    return true;
  } catch {
    return false;
  }
}
