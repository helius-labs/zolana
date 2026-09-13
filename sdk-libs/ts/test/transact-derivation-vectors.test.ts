import { describe, expect, it } from "vitest";

import vectors from "../../../test-vectors/transact_derivation.json" with { type: "json" };
import {
  P256_OWNER_TAG,
  SOLANA_OWNER_TAG,
  hashBytes,
  p256OwnerIdentity,
  poseidon,
  solanaOwnerIdentity,
} from "../src/hasher/index.js";
import {
  INPUT_TREES,
  ZERO_TREE_SLOT,
  inputTreeSlots,
  treeIdField,
  treeSlotHash,
  treeSlotsHashChain,
} from "../src/interface/tree-slot.js";
import { type Bytes31, type Bytes32, NullifierKey } from "../src/keypair/index.js";
import { mergePrivateTxBlinding } from "../src/keypair/merge/index.js";
import {
  outputBlindingSeed,
  privateTxBlinding,
  transactOutputBlinding,
} from "../src/keypair/transact/index.js";
import { ProofInputUtxo } from "../src/transaction/utxo.js";

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

function bytes(value: string): Uint8Array {
  return Uint8Array.from(Buffer.from(value, "hex"));
}

function field(value: number): Bytes32 {
  const out = new Uint8Array(32);
  new DataView(out.buffer).setUint32(28, value, false);
  return out as Bytes32;
}

describe("shared transact derivation vectors (test-vectors/transact_derivation.json)", () => {
  it("tags owner identities by signing algorithm", () => {
    const section = vectors.owner_identity;
    expect(SOLANA_OWNER_TAG).toBe(0x53);
    expect(P256_OWNER_TAG).toBe(0x50);
    const solanaPubkey = bytes(section.solana_pubkey);
    const p256X = bytes(section.p256_x);
    expect(hex(solanaOwnerIdentity(solanaPubkey))).toBe(section.solana_owner_identity);
    expect(hex(p256OwnerIdentity(p256X))).toBe(section.p256_owner_identity);
    expect(hex(hashBytes(bytes(section.hash_bytes_33_input)))).toBe(section.hash_bytes_33);
    // The tag is what keeps equal key bytes apart across algorithms and from
    // the untagged encoding assets use.
    expect(hex(solanaOwnerIdentity(p256X))).not.toBe(hex(p256OwnerIdentity(p256X)));
    expect(hex(solanaOwnerIdentity(solanaPubkey))).not.toBe(hex(hashBytes(solanaPubkey)));
    expect(() => solanaOwnerIdentity(new Uint8Array(31))).toThrow();
  });

  it("derives the blinding seed family from the first nullifier", () => {
    const section = vectors.blinding_seed;
    const firstNullifier = field(section.first_nullifier);
    const blindingSeed = field(section.blinding_seed);
    const outputSeed = outputBlindingSeed(firstNullifier, blindingSeed);
    expect(hex(outputSeed)).toBe(section.output_blinding_seed);
    expect(hex(privateTxBlinding(firstNullifier, blindingSeed))).toBe(section.private_tx_blinding);
    // The circuit applies TXOB to the derived seed, which is what a client
    // sends and a bundle reader recomputes; the root-seed form pins the
    // primitive itself.
    expect(hex(transactOutputBlinding(firstNullifier, outputSeed, section.output_index))).toBe(
      section.output_blinding_derived,
    );
    expect(hex(transactOutputBlinding(firstNullifier, blindingSeed, section.output_index))).toBe(
      section.output_blinding,
    );
    expect(hex(transactOutputBlinding(firstNullifier, outputSeed, 0))).not.toBe(
      hex(transactOutputBlinding(firstNullifier, outputSeed, 1)),
    );
    const secret = new Uint8Array(31);
    secret[30] = section.merge_nullifier_secret;
    const nullifierKey = NullifierKey.fromSecret(secret as Bytes31);
    try {
      expect(hex(mergePrivateTxBlinding(nullifierKey, firstNullifier))).toBe(
        section.merge_private_tx_blinding,
      );
    } finally {
      nullifierKey.destroy();
    }
    expect(() => transactOutputBlinding(firstNullifier, outputSeed, -1)).toThrow(RangeError);
  });

  it("folds tree slots from the right over a zero suffix", () => {
    const section = vectors.tree_slots;
    expect(INPUT_TREES).toBe(5);
    expect(hex(treeIdField(section.tree_id))).toBe(section.tree_id_field);
    const slot0 = {
      id: section.tree_id,
      utxoRoot: field(section.utxo_root),
      nullifierRoot: field(section.nullifier_root),
    };
    expect(hex(treeSlotHash(slot0))).toBe(section.slot_hash);
    const slots = inputTreeSlots([slot0]);
    expect(slots).toHaveLength(INPUT_TREES);
    expect(hex(treeSlotsHashChain(slots))).toBe(section.single_tree_chain);

    const zero = treeSlotHash(ZERO_TREE_SLOT);
    let suffix = zero;
    const suffixes = [hex(zero)];
    for (let count = 2; count < INPUT_TREES; count += 1) {
      suffix = poseidon([zero, suffix]) as Bytes32;
      suffixes.push(hex(suffix));
    }
    expect(suffixes).toEqual(section.zero_suffix_chains);
    // A single populated slot folds onto the precomputed four-slot suffix,
    // which is how the shielded pool hashes it.
    expect(hex(poseidon([treeSlotHash(slot0), suffix]))).toBe(section.single_tree_chain);
    expect(() => treeIdField(0x1_0000)).toThrow();
    expect(() => treeSlotsHashChain(slots.slice(1))).toThrow(RangeError);
  });

  it("hashes a dummy input under its tree id", () => {
    const section = vectors.dummy_utxo_hash;
    const dummy = ProofInputUtxo.dummy(field(section.blinding), section.tree_id);
    expect(hex(dummy.hash())).toBe(section.hash);
    expect(hex(ProofInputUtxo.dummy(field(section.blinding), 1).hash())).not.toBe(section.hash);
  });
});
