import type { RingKeyRegistryEntry } from "../../src/client/ports.js";
import { Writer } from "../../src/interface/internal.js";
import type { Bytes32 } from "../../src/interface/types.js";
import type { NullifierKey } from "../../src/keypair/nullifier-key.js";
import type { P256PublicKey } from "../../src/keypair/public-key.js";
import { RING_KEY_REGISTRY_ROOT_HISTORY } from "../../src/ring/codecs.js";
import {
  HEAD_MAP_EMPTY_ROOT,
  HEAD_MAP_FIELD_MAX,
  headMapLeaf,
  headMapZeroBytes,
  verifyHeadMapInsert,
} from "../../src/ring/head-map.js";
import { registeredKeyCommitment, sealNullifierKey } from "../../src/ring/key-registry.js";

const ZERO = new Uint8Array(32) as Bytes32;

/** The sentinel-only registry and the insertion of `member` at slot 1. */
export function firstInsertion(member: Bytes32) {
  const zeros = headMapZeroBytes();
  return {
    lowMember: ZERO,
    lowNext: HEAD_MAP_FIELD_MAX,
    lowCtCommitment: ZERO,
    lowIndex: 0n,
    lowProof: zeros.slice(0, 40),
    newProof: [headMapLeaf({ member: ZERO, next: member, nullifier: ZERO }), ...zeros.slice(1, 40)],
  };
}

/** Rust `KeyRegistryRoot` bytes, `root` sits in `history` at `cursor`. */
export function keyRegistryRootData(
  input: Readonly<{
    root: Bytes32;
    nextIndex: bigint;
    bump: number;
    cursor?: number;
    history?: readonly Bytes32[];
  }>,
): Uint8Array {
  const cursor = input.cursor ?? 0;
  const writer = new Writer()
    .u8(9, "discriminator")
    .bytes(input.root)
    .u64(input.nextIndex, "nextIndex")
    .u8(input.bump, "bump")
    .u8(cursor, "historyCursor");
  for (let slot = 0; slot < RING_KEY_REGISTRY_ROOT_HISTORY; slot++) {
    writer.bytes(slot === cursor ? input.root : (input.history?.[slot] ?? ZERO));
  }
  return writer.finish();
}

/** A registry holding `member`'s key alone, the indexer entry opens it under the new root. */
export function oneMemberRegistry(
  input: Readonly<{ member: Bytes32; nullifierKey: NullifierKey; auditor: P256PublicKey }>,
): Readonly<{ root: Bytes32; entry: RingKeyRegistryEntry }> {
  const insertion = firstInsertion(input.member);
  const envelope = sealNullifierKey(input.nullifierKey, input.auditor);
  envelope.ephemeralSecret.fill(0);
  const root = verifyHeadMapInsert({
    root: HEAD_MAP_EMPTY_ROOT,
    appendIndex: 1n,
    member: input.member,
    genesis: registeredKeyCommitment({
      nullifierPublicKey: envelope.nullifierPublicKey,
      ciphertext: envelope.sealed.ciphertext,
    }),
    lowMember: insertion.lowMember,
    lowNext: insertion.lowNext,
    lowNullifier: insertion.lowCtCommitment,
    lowIndex: insertion.lowIndex,
    lowProof: insertion.lowProof,
    newProof: insertion.newProof,
  });
  return {
    root,
    entry: {
      context: { slot: 1n, blockTime: 1n },
      root,
      nextIndex: 2n,
      member: input.member,
      next: HEAD_MAP_FIELD_MAX,
      index: 1n,
      ephemeralPublicKey: envelope.sealed.ephemeralPublicKey,
      ciphertext: envelope.sealed.ciphertext,
      proof: insertion.newProof,
    },
  };
}
