/** The ring output rails, mirrors Rust `zolana-ring-transaction` over the ring program's expansion. */
import { isCanonicalField } from "../interface/canonical-field.js";
import { addressBytes } from "../interface/internal.js";
import type { Address, Bytes16, Bytes31, Bytes32, TransactOutput } from "../interface/types.js";
import {
  BODY_LEN,
  anonymousRingSecret,
  confidentialRingSecret,
  deliveredSlotSecret,
  packedSlotSecret,
  ringTag,
  ringTagField,
  ringTagFromOwnerTag,
  sealDeliveredBody,
  type TagIndex,
} from "../keypair/ring-stream.js";
import { randomSalt } from "../keypair/bytes.js";
import type { ShieldedAddress } from "../keypair/shielded.js";
import { ViewingKey } from "../keypair/viewing-key.js";
import type { X25519PublicKey } from "../keypair/x25519.js";
import { SOL_ASSET_ID, type AssetRegistry } from "../transaction/asset.js";
import { Data } from "../transaction/data.js";
import type { PreparedTransfer, SppProofInputs } from "../transaction/instructions/transact.js";
import {
  EncryptedScheme,
  RECIPIENT_KEY_LEN,
  encodeRingPacked,
  encryptConfidential,
  encryptRingPacked,
  readOutputData,
} from "../transaction/serialization/codecs.js";
import type { ProofOutputUtxo } from "../transaction/utxo.js";
import { equalBytes } from "../wallet/internal.js";

import { RingError } from "./error.js";
import { ringTransactOutput, type RingOutput } from "./transact.js";

/** How the ring outputs of one transfer reach their recipients, Rust `RingDelivery`. */
export type RingDelivery =
  /** Confidential capacity 2 and 4 and the delegate rail at those capacities, scheme 11. */
  | Readonly<{ kind: "packed" }>
  /** Capacity 8 and 16, scheme 10 delivered to the owner's viewing key. */
  | Readonly<{ kind: "delivered" }>
  /** Scheme 9 under a stream tag, each payment delivered to its ring address key. */
  | Readonly<{ kind: "anonymous"; slots: AnonymousSlots }>;

/** The proven stream position of one anonymous payment, Rust `StreamPosition`. */
export type StreamPosition = Readonly<{ kind: "inbox" | "pair"; index: TagIndex }>;

/** One anonymous payment, Rust `StreamPayment`. */
export interface StreamPayment {
  /** The ring address key its body opens under. */
  readonly recipient: X25519PublicKey;
  readonly tag: Bytes31;
  readonly position: StreamPosition;
}

/** One slot of an anonymous transfer as its audit proof places it, Rust `AnonymousSlot`. */
export type AnonymousSlot =
  | Readonly<{ kind: "payment"; payment: StreamPayment }>
  /** The sender's change under a free tag, delivered to its ring change key. */
  | Readonly<{ kind: "change"; tag: Bytes31 }>
  | Readonly<{ kind: "exit" }>
  /** Padding under a free tag. */
  | Readonly<{ kind: "dummy"; tag: Bytes31 }>;

/** The payments of an anonymous transfer by final slot index, Rust `AnonymousSlots`. */
export class AnonymousSlots {
  readonly changeKey: X25519PublicKey;
  readonly #payments: ReadonlyMap<number, StreamPayment>;
  readonly #ringAddressKeys: readonly X25519PublicKey[];
  /** Drawn ahead, a change slot's ring secret binds its tag before the owner tags resolve. */
  readonly #freeTags: readonly Bytes31[];

  private constructor(
    changeKey: X25519PublicKey,
    payments: ReadonlyMap<number, StreamPayment>,
    ringAddressKeys: readonly X25519PublicKey[],
    freeTags: readonly Bytes31[],
  ) {
    this.changeKey = changeKey;
    this.#payments = payments;
    this.#ringAddressKeys = ringAddressKeys;
    this.#freeTags = freeTags;
    Object.freeze(this);
  }

  /** `changeKey` is the sender's ring change key, its change needs no secret to find. */
  static create(changeKey: X25519PublicKey, slots: number): AnonymousSlots {
    return new AnonymousSlots(changeKey, new Map(), [], Array.from({ length: slots }, freeTag));
  }

  /** Refuses a taken slot, a repeated tag and a second pair payment. */
  withPayment(slotIndex: number, payment: StreamPayment): AnonymousSlots {
    const payments = [...this.#payments.values()];
    if (
      this.#payments.has(slotIndex) ||
      payments.some((other) => equalBytes(other.tag, payment.tag)) ||
      (payment.position.kind === "pair" && payments.some((other) => other.position.kind === "pair"))
    )
      throw new RingError("RING_PAYMENT_SLOT", { details: { slotIndex } });
    return new AnonymousSlots(
      this.changeKey,
      new Map([...this.#payments, [slotIndex, Object.freeze({ ...payment })]]),
      [...this.#ringAddressKeys, payment.recipient],
      this.#freeTags,
    );
  }

  /** The sender's own ring address keys, no exit may name one. */
  withRingAddressKeys(keys: readonly X25519PublicKey[]): AnonymousSlots {
    return new AnonymousSlots(
      this.changeKey,
      this.#payments,
      [...this.#ringAddressKeys, ...keys],
      this.#freeTags,
    );
  }

  payment(slotIndex: number): StreamPayment | undefined {
    return this.#payments.get(slotIndex);
  }

  /** Rust `AnonymousSlots::slot`, an output the plan does not name is change, an exit or padding. */
  slot(output: ProofOutputUtxo, sender: ShieldedAddress, slotIndex: number): AnonymousSlot {
    const payment = this.#payments.get(slotIndex);
    const owner = output.ownerAddress;
    if (owner === undefined || output.ringProgramId === undefined) {
      if (payment !== undefined)
        throw new RingError("RING_PAYMENT_SLOT", { details: { slotIndex } });
      if (owner === undefined)
        return Object.freeze({ kind: "dummy", tag: this.#freeTag(slotIndex) });
      if (this.#ringAddressKeys.some((key) => key.equals(owner.viewingPublicKey)))
        throw new RingError("RING_ADDRESS_EXIT", { details: { slotIndex } });
      return Object.freeze({ kind: "exit" });
    }
    if (payment !== undefined) {
      if (!payment.recipient.equals(owner.viewingPublicKey))
        throw new RingError("RING_PAYMENT_SLOT", { details: { slotIndex } });
      return Object.freeze({ kind: "payment", payment });
    }
    if (equalBytes(owner.toBytes(), sender.toBytes()))
      return Object.freeze({ kind: "change", tag: this.#freeTag(slotIndex) });
    throw new RingError("RING_UNPLANNED_OUTPUT", { details: { slotIndex } });
  }

  /** Every planned payment sits on a slot of the transaction. */
  checkPlanned(slots: number): void {
    const outside = [...this.#payments.keys()].find((index) => index >= slots);
    if (outside !== undefined)
      throw new RingError("RING_PAYMENT_SLOT", { details: { slotIndex: outside } });
  }

  #freeTag(slotIndex: number): Bytes31 {
    const tag = this.#freeTags[slotIndex];
    if (tag === undefined) throw new RingError("RING_PAYMENT_SLOT", { details: { slotIndex } });
    return tag;
  }
}

/** One published slot, its compact wire form and what its audit proof opens, Rust `PublishedSlot`. */
export interface PublishedSlot {
  readonly output: ProofOutputUtxo;
  /** The final slot index of `output`. */
  readonly slotIndex: number;
  readonly wire: RingOutput;
  /** The key a delivered or anonymous ring output's body opens under. */
  readonly recipient?: X25519PublicKey;
  /** Set on the anonymous rail. */
  readonly anonymous?: AnonymousSlot;
}

/** How a slot publishes, by rail. */
type Slot =
  | Readonly<{ kind: "ring"; recipient: X25519PublicKey; tag?: Bytes31 }>
  | Readonly<{ kind: "exit" }>
  | Readonly<{ kind: "dummy"; tag?: Bytes31 }>
  | Readonly<{ kind: "compact" }>;

/** The payload SPP binds for one final slot, as the program expands the slot's compact wire. */
type FramedSlot =
  | Readonly<{ kind: "compact" }>
  | Readonly<{ kind: "framed"; viewTag: Bytes32; data: Uint8Array }>;

/** Rust `RingOutputRail`, keyed by a transaction viewing key the caller destroys and a salt drawn per rail. */
export class RingOutputRail {
  readonly txViewingKey: ViewingKey;
  readonly salt: Bytes16;
  readonly delivery: RingDelivery;
  readonly #firstNullifier: Bytes32;

  /** `firstNullifier` is the transfer's input slot 0, padding never moves it. */
  constructor(txViewingKey: ViewingKey, firstNullifier: Bytes32, delivery: RingDelivery) {
    this.txViewingKey = txViewingKey;
    this.salt = randomSalt();
    this.delivery = delivery;
    this.#firstNullifier = firstNullifier;
    Object.freeze(this);
  }

  /** The slot secret of the ring output at `slotIndex`, the root of its blinding and body key. */
  slotSecret(recipient: X25519PublicKey, slotIndex: number): Bytes32 {
    if (this.delivery.kind === "packed") {
      const txViewingSecret = this.txViewingKey.secretBytes();
      try {
        return packedSlotSecret({
          txViewingSecret,
          salt: this.salt,
          outputIndex: slotIndex,
          firstNullifier: this.#firstNullifier,
        });
      } finally {
        txViewingSecret.fill(0);
      }
    }
    const agreement = this.txViewingKey.ecdh(recipient);
    try {
      return deliveredSlotSecret({
        agreement,
        txViewingKey: this.txViewingKey.publicKey(),
        recipientViewingKey: recipient,
        salt: this.salt,
        outputIndex: slotIndex,
        firstNullifier: this.#firstNullifier,
      });
    } finally {
      agreement.fill(0);
    }
  }

  /**
   * Seals every slot of `prepared` and finalizes it, each ring output's blinding from its ring
   * secret, Rust `RingOutputRail::encrypt`.
   */
  encrypt(
    input: Readonly<{
      prepared: PreparedTransfer;
      sender: ShieldedAddress;
      assets: AssetRegistry;
      instructionDiscriminator: number;
    }>,
  ): SppProofInputs {
    const { sender } = input;
    if (this.delivery.kind === "anonymous")
      this.delivery.slots.checkPlanned(input.prepared.shape.outputs);
    const prepared = input.prepared.withRingSecrets(
      input.prepared.outputs.map((output, slotIndex) =>
        this.#ringSecret(output, sender, slotIndex),
      ),
    );
    const slots = prepared
      .proofOutputs()
      .map((output, slotIndex) => this.#frame(output, sender, slotIndex, input.assets));
    return prepared.finalize({
      txViewingPublicKey: this.txViewingKey.publicKey(),
      salt: this.salt,
      payload: slots.map((slot) =>
        slot.kind === "compact" ? undefined : { viewTag: slot.viewTag, data: slot.data },
      ),
      instructionDiscriminator: input.instructionDiscriminator,
      ringSlots: this.delivery.kind === "anonymous" ? "anonymous" : "confidential",
    });
  }

  /**
   * Every published slot in order, each expanding to exactly the output the SPP proof binds, Rust
   * `RingOutputRail::published_slots`.
   */
  publishedSlots(proofInputs: SppProofInputs, sender: ShieldedAddress): readonly PublishedSlot[] {
    const published = proofInputs.externalData.outputs;
    const slots: PublishedSlot[] = [];
    proofInputs.outputs.forEach((output, slotIndex) => {
      if (output.isCompact()) return;
      const expected = published[slots.length];
      if (expected === undefined) throw framingError(slotIndex);
      const slot = this.#slot(output, sender, slotIndex);
      const wire = this.#wire(slot, expected, slotIndex);
      slots.push(
        Object.freeze({
          output,
          slotIndex,
          wire,
          ...(slot.kind === "ring" && this.delivery.kind !== "packed"
            ? { recipient: slot.recipient }
            : {}),
          ...(this.delivery.kind === "anonymous"
            ? { anonymous: this.delivery.slots.slot(output, sender, slotIndex) }
            : {}),
        }),
      );
    });
    if (slots.length !== published.length) throw framingError(proofInputs.outputs.length);
    return Object.freeze(slots);
  }

  /** The round trip through the program's expansion refuses any other framing, Rust `RingOutputRail::wire`. */
  #wire(slot: Slot, published: TransactOutput, slotIndex: number): RingOutput {
    if (published.ownerTag.kind !== "inline" || published.data === undefined)
      throw framingError(slotIndex);
    const ownerTag = published.ownerTag.value;
    const hash = published.utxoHash;
    const body = (scheme: EncryptedScheme): Uint8Array => {
      const frame = readOutputData(published.data ?? new Uint8Array());
      if (frame.encoding !== "encrypted" || frame.scheme !== scheme) throw framingError(slotIndex);
      return frame.body;
    };
    let wire: RingOutput;
    if (slot.kind === "compact") throw framingError(slotIndex);
    if (slot.kind === "exit") {
      wire = { kind: "exit", hash, ownerTag, payload: body(EncryptedScheme.confidential) };
    } else {
      switch (this.delivery.kind) {
        case "packed":
          wire = {
            kind: "packed",
            hash,
            u: ownerTag,
            ciphertext: body(EncryptedScheme.ringConfidentialPacked).subarray(RECIPIENT_KEY_LEN),
          };
          break;
        case "delivered":
          wire = {
            kind: "delivered",
            hash,
            u: ownerTag,
            body: body(EncryptedScheme.ringConfidentialDelivered),
          };
          break;
        case "anonymous": {
          const tag = ringTagFromOwnerTag(ownerTag);
          if (tag === undefined) throw framingError(slotIndex);
          wire = { kind: "anonymous", hash, tag, body: body(EncryptedScheme.ringAnonymous) };
          break;
        }
      }
    }
    const expanded = ringTransactOutput(wire);
    if (
      !equalBytes(expanded.utxoHash, hash) ||
      expanded.ownerTag.kind !== "inline" ||
      !equalBytes(expanded.ownerTag.value, ownerTag) ||
      !equalBytes(expanded.data ?? new Uint8Array(), published.data)
    )
      throw framingError(slotIndex);
    return Object.freeze(wire);
  }

  /** Rust `RingOutputRail::slot`. */
  #slot(output: ProofOutputUtxo, sender: ShieldedAddress, slotIndex: number): Slot {
    const delivered = this.delivery.kind !== "packed";
    if (output.isCompact()) {
      if (delivered)
        throw new RingError("RING_DELIVERED_COMPACT_PADDING", { details: { slotIndex } });
      return Object.freeze({ kind: "compact" });
    }
    const carriesData =
      !output.data.isEmpty() || output.dataHash !== undefined || output.ringDataHash !== undefined;
    if (delivered && !output.isDummy() && carriesData)
      throw new RingError("RING_DELIVERED_OUTPUT_DATA", { details: { slotIndex } });
    if (this.delivery.kind === "anonymous") {
      const slot = this.delivery.slots.slot(output, sender, slotIndex);
      switch (slot.kind) {
        case "payment":
          return Object.freeze({
            kind: "ring",
            recipient: slot.payment.recipient,
            tag: slot.payment.tag,
          });
        case "change":
          return Object.freeze({
            kind: "ring",
            recipient: this.delivery.slots.changeKey,
            tag: slot.tag,
          });
        case "exit":
          return Object.freeze({ kind: "exit" });
        case "dummy":
          return Object.freeze({ kind: "dummy", tag: slot.tag });
      }
    }
    if (output.isDummy()) return Object.freeze({ kind: "dummy" });
    const owner = output.ownerAddress;
    if (output.ringProgramId === undefined || owner === undefined)
      return Object.freeze({ kind: "exit" });
    return Object.freeze({ kind: "ring", recipient: owner.viewingPublicKey });
  }

  /** `undefined` for every slot that is no ring output. */
  #ringSecret(
    output: ProofOutputUtxo,
    sender: ShieldedAddress,
    slotIndex: number,
  ): Bytes32 | undefined {
    const slot = this.#slot(output, sender, slotIndex);
    if (slot.kind !== "ring") return undefined;
    const secret = this.slotSecret(slot.recipient, slotIndex);
    try {
      return slot.tag === undefined
        ? confidentialRingSecret(secret)
        : anonymousRingSecret(secret, slot.tag);
    } finally {
      secret.fill(0);
    }
  }

  /** Rust `RingOutputRail::encode_slot` with the owner tag `owner_tags` resolves for the slot. */
  #frame(
    output: ProofOutputUtxo,
    sender: ShieldedAddress,
    slotIndex: number,
    assets: AssetRegistry,
  ): FramedSlot {
    const slot = this.#slot(output, sender, slotIndex);
    const zero = new Uint8Array(32) as Bytes32;
    switch (slot.kind) {
      case "compact":
        return Object.freeze({ kind: "compact" });
      case "exit": {
        const owner = output.ownerAddress;
        if (owner === undefined)
          throw new RingError("RING_OUTPUT_FRAMING", { details: { slotIndex } });
        const viewTag = owner.signingPublicKey.confidentialViewTag();
        const payload = encryptConfidential(
          this.txViewingKey,
          owner.viewingPublicKey,
          {
            assetId: assets.assetId(output.asset),
            amount: output.amount,
            blinding: output.blinding,
            data: output.data,
          },
          this.salt,
          slotIndex,
        );
        return framed(viewTag, { kind: "exit", hash: zero, ownerTag: viewTag, payload });
      }
      case "ring": {
        if (slot.tag === undefined && this.delivery.kind === "packed") {
          const body = encryptRingPacked(
            this.txViewingKey,
            slot.recipient,
            {
              assetId: assets.assetId(output.asset),
              amount: output.amount,
              blinding: output.blinding,
              data: output.data,
            },
            this.salt,
            slotIndex,
          );
          const u = slot.recipient.u();
          return framed(u, { kind: "packed", hash: zero, u, ciphertext: body.subarray(33) });
        }
        const secret = this.slotSecret(slot.recipient, slotIndex);
        let body: Uint8Array;
        try {
          body = sealDeliveredBody(secret, {
            assetAddress: assetAddressBytes(output.asset),
            amount: output.amount,
          });
        } finally {
          secret.fill(0);
        }
        if (slot.tag !== undefined)
          return framed(ringTagField(slot.tag), {
            kind: "anonymous",
            hash: zero,
            tag: slot.tag,
            body,
          });
        const u = slot.recipient.u();
        return framed(u, { kind: "delivered", hash: zero, u, body });
      }
      case "dummy": {
        const body = randomBytes(BODY_LEN);
        if (slot.tag !== undefined)
          return framed(ringTagField(slot.tag), {
            kind: "anonymous",
            hash: zero,
            tag: slot.tag,
            body,
          });
        // A random key publishes as a real recipient's would.
        const key = ViewingKey.generate();
        try {
          const u = key.publicKey().u();
          if (this.delivery.kind !== "packed")
            return framed(u, { kind: "delivered", hash: zero, u, body });
          const ciphertext = this.txViewingKey.encryptSlot(
            key.publicKey(),
            encodeRingPacked({
              assetId: SOL_ASSET_ID,
              amount: 0n,
              blinding: zero,
              data: new Data(),
            }),
            this.salt,
            slotIndex,
          );
          return framed(u, { kind: "packed", hash: zero, u, ciphertext });
        } finally {
          key.destroy();
        }
      }
    }
  }
}

/** `low248` of a uniform field element, the change and padding tags no stream derives. */
export function freeTag(): Bytes31 {
  for (;;) {
    const value = randomBytes(32);
    // Below 2^254 the modulus accepts about three draws in four.
    value[0] = (value[0] ?? 0) & 0x3f;
    if (isCanonicalField(value)) return ringTag(value as Bytes32);
  }
}

function framed(viewTag: Bytes32, wire: RingOutput): FramedSlot {
  const { data } = ringTransactOutput(wire);
  if (data === undefined) throw new RingError("RING_OUTPUT_FRAMING");
  return Object.freeze({ kind: "framed", viewTag, data });
}

/** The mint bytes, all zero for SOL. */
function assetAddressBytes(asset: Address): Bytes32 {
  return addressBytes(asset, "asset") as Bytes32;
}

function framingError(slotIndex: number): RingError {
  return new RingError("RING_OUTPUT_FRAMING", { details: { slotIndex } });
}

function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}
