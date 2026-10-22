import { address, type Signature } from "@solana/kit";
import { describe, expect, it } from "vitest";

import type { Bytes32 } from "../src/interface/types.js";
import { Pairing } from "../src/keypair/ring-address.js";
import { tagIndex } from "../src/keypair/ring-stream.js";
import { ShieldedKeypair } from "../src/keypair/shielded.js";
import { SOL_MINT } from "../src/transaction/asset.js";
import { Data } from "../src/transaction/data.js";
import { Utxo } from "../src/transaction/utxo.js";
import {
  AnonymousRingState,
  MAX_ISSUED_ADDRESSES,
  PAIR_IDLE_EPOCHS,
} from "../src/transaction/wallet/anonymous-state.js";
import { deserializeWallet, serializeWallet } from "../src/transaction/wallet/persistence.js";
import { Wallet } from "../src/transaction/wallet/state.js";

const TREE = address("3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3");
const RING = address("29d2S7vB453rNYFdR5Ycwt7y9haRT5fwVwL9zTmBhfV2");
const SIGNATURE = "1".repeat(64) as Signature;

function bytes(value: number): Bytes32 {
  return new Uint8Array(32).fill(value) as Bytes32;
}

/** A wallet with a default note, a ring note, a pending ring note and a cursor. */
function populatedWallet(): Wallet {
  const keypair = ShieldedKeypair.generate();
  const identity = keypair.shieldedAddress();
  const wallet = new Wallet({ identity });
  const utxo = (amount: bigint, ringProgramId?: typeof RING) =>
    new Utxo({
      owner: identity.signingPublicKey,
      asset: SOL_MINT,
      amount,
      blinding: bytes(Number(amount)),
      data: new Data(),
      ...(ringProgramId === undefined ? {} : { ringProgramId }),
    });
  wallet._replace({
    utxos: [
      {
        utxo: utxo(5n),
        outputContext: { hash: bytes(1), tree: TREE, leafIndex: 1n },
        nullifier: bytes(2),
        spent: false,
      },
      {
        utxo: utxo(7n, RING),
        outputContext: { hash: bytes(3), tree: TREE, leafIndex: 2n },
        nullifier: bytes(4),
        spent: false,
      },
    ],
    transactions: [],
    nullifiers: new Set(),
    pendingNotes: [
      {
        utxo: utxo(9n, RING),
        nullifierPublicKey: identity.nullifierPublicKey,
        outputContext: { hash: bytes(5), tree: TREE, treeId: 0, leafIndex: 3n },
        txSignature: SIGNATURE,
        slot: 11n,
        slotIndex: 1,
      },
    ],
    lastSynced: 12n,
  });
  wallet._setSyncCursor("transactions", "aa".repeat(32), Uint8Array.of(1, 2));
  return wallet;
}

/** The version 5 wire of `wallet`, no ring states and every pending note with its v4 pair hint. */
function versionFive(wallet: Wallet): string {
  const snapshot = JSON.parse(serializeWallet(wallet)) as Record<string, unknown>;
  snapshot["version"] = 5;
  delete snapshot["anonymousRings"];
  snapshot["pendingNotes"] = (snapshot["pendingNotes"] as Record<string, unknown>[]).map(
    (note) => ({ ...note, pairU: Buffer.alloc(32, 6).toString("base64") }),
  );
  return JSON.stringify(snapshot);
}

function scannedState(): AnonymousRingState {
  const issued = AnonymousRingState.create(RING, 100n)
    .issue(0, Pairing.any())
    .receive({
      addressIndex: 0,
      pairKey: bytes(10),
      epoch: 100n,
      lastEpoch: 100n,
      asset: SOL_MINT,
      amount: 1_000n,
    });
  return issued.recordFirstContact({
    recipient: ShieldedKeypair.generate().shieldedAddress().viewingPublicKey,
    treeId: 0,
    leafIndex: 4n,
    utxoHash: bytes(7),
    slotSecret: bytes(8),
    firstNullifier: bytes(9),
    slotIndex: 0,
    epoch: 101n,
    index: tagIndex(3),
    asset: SOL_MINT,
    amount: 1_000n,
  });
}

describe("wallet persistence version 6", () => {
  it("keeps every UTXO of a version 5 store and rescans each anonymous ring from its creation", () => {
    const wallet = populatedWallet();
    const restored = deserializeWallet(versionFive(wallet));

    expect(restored.utxos()).toEqual(wallet.utxos());
    expect(restored.pendingNotes()).toEqual(wallet.pendingNotes());
    expect(restored._syncCursor("transactions", "aa".repeat(32))).toEqual(Uint8Array.of(1, 2));
    expect(restored.lastSynced).toBe(12n);
    expect(restored.anonymousRings()).toEqual([]);
    expect(restored.anonymousRing(RING)).toBeUndefined();
    expect(JSON.parse(serializeWallet(restored))).toMatchObject({ version: 6, anonymousRings: [] });
  });

  it("restores the per-ring state a scan reached", () => {
    const wallet = populatedWallet();
    const state = scannedState();
    wallet._setAnonymousRing(state);

    const restored = deserializeWallet(serializeWallet(wallet));
    const ring = restored.anonymousRing(RING);

    expect(ring?.serialize()).toEqual(state.serialize());
    const idleThrough = state.sent[0]!.epoch + PAIR_IDLE_EPOCHS - 1n;
    expect(ring?.firstContact(state.sent[0]!.recipient, idleThrough)).toBeDefined();
    expect(ring?.firstContact(state.sent[0]!.recipient, idleThrough + 1n)).toBeUndefined();
  });

  it("refuses a ring state the wire never writes", () => {
    const wallet = populatedWallet();
    wallet._setAnonymousRing(scannedState());
    const snapshot = JSON.parse(serializeWallet(wallet)) as {
      anonymousRings: Record<string, unknown>[];
      pendingNotes: Record<string, unknown>[];
    };
    const ring = snapshot.anonymousRings[0]!;
    const refused = (mutate: (copy: typeof snapshot) => void) => {
      const copy = structuredClone(snapshot);
      mutate(copy);
      return () => deserializeWallet(JSON.stringify(copy));
    };

    expect(refused((copy) => (copy.anonymousRings[0]!["version"] = 1))).toThrow(
      "TRANSACTION_DESERIALIZE",
    );
    expect(refused((copy) => (copy.anonymousRings[0]!["scannedEpoch"] = 99))).toThrow(
      "TRANSACTION_DESERIALIZE",
    );
    expect(refused((copy) => (copy.anonymousRings[0]!["inboxSecret"] = "00"))).toThrow(
      "TRANSACTION_DESERIALIZE",
    );
    expect(refused((copy) => copy.anonymousRings.push(ring))).toThrow("TRANSACTION_DESERIALIZE");
    const repeated = (field: "issued" | "sent") =>
      refused((copy) => {
        const list = copy.anonymousRings[0]![field] as unknown[];
        list.push(list[0]);
      });
    expect(repeated("issued")).toThrow("TRANSACTION_DESERIALIZE");
    expect(repeated("sent")).toThrow("TRANSACTION_DESERIALIZE");
    expect(
      refused((copy) => {
        const [issued] = copy.anonymousRings[0]!["issued"] as Record<string, unknown>[];
        issued!["index"] = MAX_ISSUED_ADDRESSES;
      }),
    ).toThrow("TRANSACTION_DESERIALIZE");
    expect(
      refused((copy) => {
        const [anchor] = copy.anonymousRings[0]!["received"] as Record<string, unknown>[];
        anchor!["addressIndex"] = MAX_ISSUED_ADDRESSES;
      }),
    ).toThrow("TRANSACTION_DESERIALIZE");
    expect(
      refused((copy) => (copy.pendingNotes[0]!["pairU"] = Buffer.alloc(32).toString("base64"))),
    ).toThrow("TRANSACTION_DESERIALIZE");
  });
});
