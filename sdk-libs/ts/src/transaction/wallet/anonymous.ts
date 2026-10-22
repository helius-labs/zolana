import type { Address, Bytes16, Bytes32, Signature } from "../../interface/types.js";
import type { TagIndex } from "../../keypair/ring-stream.js";
import type { IndexedShieldedTransaction } from "../instructions/transact.js";
import type { Utxo } from "../utxo.js";

/** What a scan found in one stream, Rust `AnonymousStream` and the deposit stream. */
export type AnonymousStream =
  | Readonly<{ kind: "inbox"; addressIndex: number; epoch: bigint; index: TagIndex }>
  | Readonly<{ kind: "pair"; addressIndex: number; epoch: bigint; index: TagIndex }>
  | Readonly<{ kind: "change"; firstNullifier: Bytes32 }>
  | Readonly<{ kind: "merge"; firstNullifier: Bytes32 }>
  | Readonly<{ kind: "deposit"; counter: bigint }>;

export interface AnonymousRingNote {
  readonly utxoHash: Bytes32;
  readonly stream: AnonymousStream;
}

/** What one sync read of one anonymous ring. */
export interface AnonymousRingReport {
  readonly ring: Address;
  readonly notes: readonly AnonymousRingNote[];
  /** First contacts the sync added, each opens a pair stream. */
  readonly anchors: readonly Readonly<{
    addressIndex: number;
    epoch: bigint;
    asset: Address;
    amount: bigint;
  }>[];
  /** The last epoch every stream was read through, `undefined` before a whole epoch closed. */
  readonly scannedEpoch: bigint | undefined;
}

/** A commitment-verified anonymous ring note in a mint the registry does not know yet, kept until `resolvePendingNotes` admits it. */
export interface PendingAnonymousNote {
  readonly utxo: Utxo;
  readonly nullifierPublicKey: Bytes32;
  readonly outputContext: Readonly<{
    hash: Bytes32;
    tree: Address;
    treeId: number;
    leafIndex: bigint;
  }>;
  readonly txSignature: Signature;
  readonly slot: bigint;
  readonly slotIndex: number;
}

/** One delivered output under a tag the wallet derived, with the slot secret its keys answered. */
export interface RingDeliveredCandidate {
  readonly transaction: IndexedShieldedTransaction;
  readonly slotIndex: number;
  /** The published tag, absent when the owner tag carries none. */
  readonly tag?: Bytes16;
  readonly slotSecret: Bytes32;
  /** The wallet's own change, recorded without a receipt. */
  readonly change: boolean;
}
