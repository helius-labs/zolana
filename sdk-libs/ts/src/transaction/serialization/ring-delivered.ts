import { getAddressDecoder } from "@solana/kit";

import type { Address, Bytes31, Bytes32 } from "../../interface/types.js";
import type { ShieldedPublicKey } from "../../keypair/public-key.js";
import {
  BODY_LEN,
  anonymousRingSecret,
  confidentialRingSecret,
  openDeliveredBody,
} from "../../keypair/ring-stream.js";
import { ringOutputBlinding } from "../../keypair/transact/index.js";

import { Data } from "../data.js";
import { checked, equal } from "../internal.js";
import { Utxo, type TreeId } from "../utxo.js";

const addressDecoder = getAddressDecoder();

/** Where a delivered ring output sits, Rust `RingDeliverySlot`. */
export interface RingDeliverySlot {
  readonly ring: Address;
  readonly firstNullifier: Bytes32;
  readonly outputIndex: number;
  /** The published tag on an anonymous ring, absent on a confidential one. */
  readonly tag?: Bytes31;
}

/** The keys of a delivered output's owner. */
export interface RingNoteOwner {
  readonly signingPublicKey: ShieldedPublicKey;
  readonly nullifierPublicKey: Bytes32;
}

/** One published delivered body and the secret its recipient agreed for it. */
export interface RingDeliveryOpening {
  readonly body: Uint8Array;
  readonly slotSecret: Bytes32;
  readonly owner: RingNoteOwner;
  /** The published commitment and the tree it was appended to. */
  readonly commitment: Bytes32;
  readonly treeId: TreeId;
}

/** A delivered output opened to the note its published commitment binds. */
export interface RingDeliveredNote {
  readonly utxo: Utxo;
  readonly utxoHash: Bytes32;
}

/** CRRA over the tag on an anonymous ring, so an anchor reads the tag back from the blinding. */
export function ringDeliverySecret(slot: RingDeliverySlot, slotSecret: Bytes32): Bytes32 {
  return slot.tag === undefined
    ? confidentialRingSecret(slotSecret)
    : anonymousRingSecret(slotSecret, slot.tag);
}

/** `Poseidon(TXRB, n0, ring_secret, i)`, the blinding SPP's ring rails check. */
export function ringDeliveryBlinding(slot: RingDeliverySlot, slotSecret: Bytes32): Bytes32 {
  const ringSecret = ringDeliverySecret(slot, slotSecret);
  try {
    return ringOutputBlinding({
      firstNullifier: slot.firstNullifier,
      ringSecret,
      outputIndex: slot.outputIndex,
    });
  } finally {
    ringSecret.fill(0);
  }
}

/** `undefined` when the body under the secret rebuilds another commitment, a tag collision or another recipient's output. */
export function openRingDelivery(
  slot: RingDeliverySlot,
  opening: RingDeliveryOpening,
): RingDeliveredNote | undefined {
  const body = openDeliveredBody(opening.slotSecret, checked(opening.body, BODY_LEN, "body"));
  const utxo = new Utxo({
    owner: opening.owner.signingPublicKey,
    asset: addressDecoder.decode(body.assetAddress),
    amount: body.amount,
    blinding: ringDeliveryBlinding(slot, opening.slotSecret),
    data: new Data(),
    ringProgramId: slot.ring,
  });
  const utxoHash = utxo.hash(opening.owner.nullifierPublicKey, opening.treeId);
  return equal(utxoHash, opening.commitment) ? Object.freeze({ utxo, utxoHash }) : undefined;
}
