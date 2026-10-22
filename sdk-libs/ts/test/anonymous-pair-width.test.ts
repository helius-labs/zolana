import { address } from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import type { GetByTagsRequest } from "../src/client/rpc.js";
import { DEFAULT_INDEXER_RPC_CONFIG } from "../src/client/retry.js";
import { PAGE_LIMIT } from "../src/interface/indexer-limits.js";
import type { Bytes32 } from "../src/interface/types.js";
import { Pairing } from "../src/keypair/ring-address.js";
import {
  EPOCH_SLOTS,
  J_INBOX,
  pairKey,
  pairTag,
  ringTagField,
  tagIndex,
} from "../src/keypair/ring-stream.js";
import type * as RingStream from "../src/keypair/ring-stream.js";
import { ShieldedKeypair } from "../src/keypair/shielded.js";
import { SigningKey } from "../src/keypair/signing-key.js";
import { SOL_MINT } from "../src/transaction/asset.js";
import { ANCHOR_DECOYS, AnonymousRingState } from "../src/transaction/wallet/anonymous-state.js";
import { LocalShieldedKeys } from "../src/transaction/wallet/keys.js";
import { hex } from "../src/transaction/wallet/state.js";
import {
  TagAllocation,
  ringAddressOf,
  scanAnonymousRing,
  type AnonymousIndexer,
} from "../src/wallet/anonymous-sync.js";

import { matchesPage, transactionsPage } from "./helpers/clients.js";

const J_PAIR = vi.hoisted(() => 2);
vi.mock("../src/keypair/ring-stream.js", async (importOriginal) => ({
  ...(await importOriginal<typeof RingStream>()),
  J_PAIR,
}));

const RING = address("3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3");

function filled(value: number): Bytes32 {
  const out = new Uint8Array(32).fill(value) as Bytes32;
  out[0] = 0;
  return out;
}

const OWNER = ShieldedKeypair.fromKeypair(SigningKey.fromEd25519Bytes(filled(1)));

describe("pair stream width", () => {
  it("draws a pair index below J_PAIR", async () => {
    const keys = LocalShieldedKeys.fromKeypair(OWNER);
    const to = await ringAddressOf({ keys, ring: RING, index: 0, pairing: Pairing.any() });
    const slotSecret = filled(0x91);
    const state = AnonymousRingState.create(RING, 0n)
      .recordFirstContact({
        recipient: to.recipient.viewingPublicKey,
        treeId: 0,
        leafIndex: 40n,
        utxoHash: filled(0x90),
        slotSecret: new Uint8Array(slotSecret) as Bytes32,
        firstNullifier: filled(0x92),
        slotIndex: 1,
        epoch: 0n,
        index: tagIndex(0),
        asset: SOL_MINT,
        amount: 500n,
      })
      .rememberDecoys(
        Array.from({ length: ANCHOR_DECOYS }, (_, at) => ({
          treeId: 0,
          leafIndex: BigInt(at),
          hash: filled(0xa0 + at),
        })),
      )
      .pinAnchors();

    const tag = new TagAllocation(state, 0n).allocate(to, (length) =>
      new Uint8Array(length).fill(5),
    );

    expect(tag.stream.kind).toBe("pair");
    expect(tag.index).toBe(1);
    expect(tag.tag).toEqual(pairTag(pairKey(slotSecret), 0n, tagIndex(1)));
  });

  it("reads J_PAIR tags of a live pair in each epoch", async () => {
    const key = filled(0x33);
    const state = AnonymousRingState.deserialize(
      {
        ...AnonymousRingState.create(RING, 0n).serialize(),
        issued: [{ index: 0, pairing: [] }],
        received: [
          {
            addressIndex: 0,
            pairKey: hex(key),
            epoch: 0,
            lastEpoch: 0,
            asset: SOL_MINT,
            amount: "500",
          },
        ],
      },
      "state",
    );
    const requested = new Set<string>();
    const record = (request: GetByTagsRequest) => {
      for (const tag of request.tags) requested.add(hex(tag));
    };
    const indexer: AnonymousIndexer = {
      getEncryptedUtxosByTags: async (request) => {
        record(request);
        return matchesPage();
      },
      getShieldedTransactionsByTags: async (request) => {
        record(request);
        return transactionsPage();
      },
      getShieldedTransactionsByNullifiers: async () => transactionsPage(),
    };

    await scanAnonymousRing({
      keys: LocalShieldedKeys.fromKeypair(OWNER),
      indexer,
      state,
      slot: EPOCH_SLOTS / 2n,
      heldUtxos: [],
      defaultRingSpends: [],
      pageLimit: Number(PAGE_LIMIT),
      nextRpcConfig: () => DEFAULT_INDEXER_RPC_CONFIG,
    });

    const pairTags = Array.from({ length: J_INBOX }, (_, at) =>
      hex(ringTagField(pairTag(key, 0n, tagIndex(at)))),
    );
    expect(pairTags.filter((tag) => requested.has(tag))).toEqual(pairTags.slice(0, J_PAIR));
  });
});
