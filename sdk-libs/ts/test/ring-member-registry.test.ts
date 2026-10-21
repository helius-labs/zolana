import { address, type Address } from "@solana/kit";
import { beforeAll, describe, expect, it, vi } from "vitest";

import records from "../../../test-vectors/ring-records.json" with { type: "json" };
import type { RingMemberOpening, RingRecordReader, RingSealedKey } from "../src/client/ports.js";
import type { RingProofRequest } from "../src/client/prover/ring.js";
import type { RpcAccount } from "../src/client/rpc.js";
import { initializePoseidon } from "../src/hasher/index.js";
import { SYSTEM_PROGRAM } from "../src/interface/instructions/index.js";
import { addressBytes } from "../src/interface/internal.js";
import {
  ringConfigPda,
  ringMemberRegistryPda,
  ringRecordQueuePda,
} from "../src/interface/pda/index.js";
import type { Bytes31, Bytes32 } from "../src/interface/types.js";
import { NullifierKey } from "../src/keypair/nullifier-key.js";
import { ShieldedKeypair } from "../src/keypair/shielded.js";
import { SigningKey } from "../src/keypair/signing-key.js";
import { X25519Keypair, X25519PublicKey } from "../src/keypair/x25519.js";
import {
  AUTHORITY_RESERVED_LEAVES,
  MEMBER_QUEUE_LIMIT,
  type RingMode,
} from "../src/ring/codecs.js";
import { MEMBER_REGISTRY_CAPACITY } from "../src/interface/member-registry.js";
import { MEMBER_REGISTRY_EMPTY_ROOT, escrowKeyHash } from "../src/ring/member-registry.js";
import { memberOfTag } from "../src/ring/policy.js";
import {
  NullifierKeyEscrow,
  RegisterKey,
  fetchRingSealedKey,
  openNullifierKey,
  openRingSealedKey,
  sealNullifierKey,
  sealNullifierKeyWith,
} from "../src/ring/register-key.js";
import { registerKeyStatementHash } from "../src/ring/statement.js";
import { recordTree, type FixtureRecord } from "./helpers/member-registry.js";
import {
  memberRegistryData,
  ownedAccount,
  recordQueueData,
  ringProgramConfigData,
} from "./helpers/ring-accounts.js";

// custom-rings/client/src/encryption.rs `the_sealed_key_and_its_escrow_key_match_the_pinned_vector`.
const AUDITOR_SK = hex("01323130373635343b3a39383f3e3d3c23222120272625242b2a29282f2e2d2c");
const EPHEMERAL_SK = hex("011013121514171619181b1a1d1c1f1e010003020504070609080b0a0d0c0f0e");
const NULLIFIER_SECRET = hex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
const NULLIFIER_PK = hex("2d1faf6cf358763421511eb637adf7b6609443d38edc4ed2b042dfbf834b03f5");
const EPH_PK = hex("043632fe89228ea5215eea45a56704f569e3929868a8573363d015e39609f0eb63");
const CIPHERTEXT = hex("2c2a1650e3a2a0d012a0d438341ff610ad99bd3c1cde0dd169179174880e755d");
const KEY_HASH = hex("1c73c14786dd7354525c98368bca8dbc5f836e957c45f552f377c84e266546c4");

const RING = address("9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh");
const AUTHORITY = address("4Nd1mBQtrMJVYVfKf2PJy9NZUZdTAsp7D4xWLs4gDB4T");
const PAYER = address("3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3");
const PROOF = Uint8Array.from({ length: 192 }, (_, index) => 255 - index);
const AUDITOR = X25519Keypair.fromBytes(AUDITOR_SK);

beforeAll(initializePoseidon);

function hex(value: string): Uint8Array {
  return Uint8Array.from(Buffer.from(value, "hex"));
}

function actor(seed: number) {
  const keypair = ShieldedKeypair.fromKeypair(
    SigningKey.fromEd25519Bytes(new Uint8Array(32).fill(seed) as Bytes32),
  );
  const shielded = keypair.shieldedAddress();
  const signer = shielded.solanaAddress();
  return { keypair, shielded, signer, member: memberOfTag(addressBytes(signer)) };
}

/** The chain and indexer of a ring whose registry holds `members`. */
async function ring(
  members: readonly FixtureRecord[],
  options: Readonly<{
    mode?: RingMode;
    insertFee?: bigint;
    opening?: RingMemberOpening;
    pending?: bigint;
    nextIndex?: number;
  }> = {},
) {
  const tree = recordTree(members);
  const [[config, configBump], [registry, registryBump], [queue, queueBump]] = await Promise.all([
    ringConfigPda(RING),
    ringMemberRegistryPda(RING),
    ringRecordQueuePda(RING),
  ]);
  const accounts = new Map<Address, RpcAccount>([
    [
      config,
      ownedAccount(
        RING,
        ringProgramConfigData({
          authority: AUTHORITY,
          auditorPublicKey: AUDITOR.publicKey().toBytes(),
          bump: configBump,
          hasPolicy: true,
          mode: options.mode ?? "registry",
          insertFee: options.insertFee ?? 1_000_000n,
        }),
      ),
    ],
    [
      registry,
      ownedAccount(
        RING,
        memberRegistryData({
          bump: registryBump,
          history: [{ root: tree.root, applied: 0n, slot: 1n }],
          nextIndex: options.nextIndex ?? tree.nextIndex,
        }),
      ),
    ],
    [
      queue,
      ownedAccount(
        RING,
        recordQueueData({
          bump: queueBump,
          head: 0n,
          tail: options.pending ?? 0n,
          chainHead: new Uint8Array(32) as Bytes32,
        }),
      ),
    ],
  ]);
  const getRingMemberOpenings = vi.fn<RingRecordReader["getRingMemberOpenings"]>(
    async (request) => ({
      context: { slot: 1n, blockTime: 1n },
      root: { root: request.expectedRoot, rootIndex: 0, applied: 0n, nextIndex: tree.nextIndex },
      openings: request.members.map((member) => options.opening ?? tree.opening(member)),
    }),
  );
  return {
    tree,
    accounts: { config, registry, queue },
    client: {
      getAccount: async (account: Address) => accounts.get(account),
      getRingMemberOpenings,
    },
  };
}

function escrow(nullifierKey: NullifierKey) {
  const proveRing = vi.fn(async (_request: RingProofRequest) => PROOF);
  return { authority: new NullifierKeyEscrow(nullifierKey, { proveRing }), proveRing };
}

/** A member whose record escrows its sealed key, served beside the record. */
function registered(seed: number) {
  const who = actor(seed);
  const envelope = sealNullifierKey(who.keypair.nullifierKey(), AUDITOR.publicKey());
  envelope.ephemeralSecret.fill(0);
  const sealed: RingSealedKey = {
    owner: who.signer,
    nullifierPk: envelope.nullifierPublicKey,
    ephemeralPublicKey: envelope.sealed.ephemeralPublicKey,
    ciphertext: envelope.sealed.ciphertext,
  };
  const record: FixtureRecord = {
    member: who.member,
    lists: 1n << 7n,
    escrowKey: escrowKeyHash({ nullifierPk: sealed.nullifierPk, ciphertext: sealed.ciphertext }),
    sealed,
  };
  return { ...who, record, sealed };
}

describe("nullifier key envelope", () => {
  it("matches the Rust vector and opens only for the auditor", () => {
    const ephemeral = X25519Keypair.fromBytes(EPHEMERAL_SK);
    const nullifierKey = NullifierKey.fromSecret(NULLIFIER_SECRET as Bytes31);
    const envelope = sealNullifierKeyWith(ephemeral, nullifierKey, AUDITOR.publicKey());
    expect(envelope.nullifierPublicKey).toEqual(NULLIFIER_PK);
    expect(envelope.sealed.ephemeralPublicKey.toBytes()).toEqual(EPH_PK);
    expect(envelope.sealed.ciphertext).toEqual(CIPHERTEXT);
    expect(
      escrowKeyHash({
        nullifierPk: envelope.nullifierPublicKey,
        ciphertext: envelope.sealed.ciphertext,
      }),
    ).toEqual(KEY_HASH);
    expect(openNullifierKey(envelope.sealed, AUDITOR).secretBytes()).toEqual(NULLIFIER_SECRET);
    const fresh = sealNullifierKey(nullifierKey, AUDITOR.publicKey());
    expect(fresh.sealed.ciphertext).not.toEqual(CIPHERTEXT);
    expect(openNullifierKey(fresh.sealed, AUDITOR).secretBytes()).toEqual(NULLIFIER_SECRET);
  });

  it("pins the sentinel-only root the registry starts from", () => {
    expect(Buffer.from(MEMBER_REGISTRY_EMPTY_ROOT).toString("hex")).toBe(records.empty_root);
    expect(recordTree().root).toEqual(MEMBER_REGISTRY_EMPTY_ROOT);
  });
});

describe("key registration", () => {
  it("seals the member's key, proves the envelope and pays the insert fee to the authority", async () => {
    const who = actor(7);
    const { client, accounts } = await ring([]);
    const { authority, proveRing } = escrow(who.keypair.nullifierKey());
    const proven = await new RegisterKey({
      ringProgramId: RING,
      member: who.shielded,
      payer: PAYER,
      authority,
    }).prove(client);
    const data = proven.instruction.data ?? new Uint8Array();
    expect(data).toHaveLength(289);
    expect(data[0]).toBe(29);
    expect(data.subarray(1, 193)).toEqual(PROOF);
    const nullifierPk = data.subarray(193, 225) as Bytes32;
    const ephU = data.subarray(225, 257) as Bytes32;
    const ciphertext = data.subarray(257, 289) as Bytes32;
    expect(nullifierPk).toEqual(who.shielded.nullifierPublicKey);
    expect(
      proven.instruction.accounts?.map(({ address: account, role }) => [account, role]),
    ).toEqual([
      [who.signer, 2],
      [accounts.config, 0],
      [accounts.registry, 0],
      [accounts.queue, 1],
      [PAYER, 3],
      [AUTHORITY, 1],
      [SYSTEM_PROGRAM, 0],
    ]);
    const request = proveRing.mock.calls[0]?.[0];
    if (request?.kind !== "registerKey") throw new Error("register key request");
    expect(request.member).toEqual(who.member);
    expect(request.publicInputHash).toEqual(
      registerKeyStatementHash({
        member: who.member,
        nullifierPk,
        auditorPubkey: AUDITOR.publicKey().toBytes(),
        ephU,
        ciphertext,
      }),
    );
    expect(request.nullifierSecret.every((byte) => byte === 0)).toBe(true);
    expect(request.ephSk.every((byte) => byte === 0)).toBe(true);
    const sealed = {
      ephemeralPublicKey: X25519PublicKey.fromBytes(Uint8Array.of(4, ...ephU)),
      ciphertext,
    };
    expect(openNullifierKey(sealed, AUDITOR).secretBytes()).toEqual(
      who.keypair.nullifierKey().secretBytes(),
    );
    authority.destroy();
  });

  it("takes no fee accounts under a zero fee and registers a present member without a key", async () => {
    const who = actor(8);
    const { client } = await ring([{ member: who.member, lists: 1n }], { insertFee: 0n });
    const { authority } = escrow(who.keypair.nullifierKey());
    const proven = await new RegisterKey({
      ringProgramId: RING,
      member: who.shielded,
      payer: PAYER,
      authority,
    }).prove(client);
    expect(proven.instruction.accounts).toHaveLength(4);
  });

  it.each([
    ["an anonymous ring", "RING_ANONYMOUS_REFUSED"],
    ["an escrow of another key", "RING_NULLIFIER_KEY_MISMATCH"],
    ["a member whose record escrows a key", "RING_KEY_ALREADY_REGISTERED"],
    ["an opening under another root", "RING_MEMBER_REGISTRY_INVALID"],
    ["a queue holding the member limit", "RING_RECORD_QUEUE_FULL"],
    ["a registry whose member leaves are taken", "RING_REGISTRY_FULL"],
  ] as const)("refuses %s before any proof", async (refusal, causeCode) => {
    const who = registered(9);
    const stranger = actor(10);
    const honest = recordTree([]);
    const moved = honest.opening(who.member);
    const opening: RingMemberOpening =
      moved.kind === "absent" ? { ...moved, low: { ...moved.low, lists: 1n } } : moved;
    const { client } = await ring(
      refusal === "a member whose record escrows a key" ? [who.record] : [],
      {
        ...(refusal === "an anonymous ring" ? { mode: "anonymous" as const } : {}),
        ...(refusal === "an opening under another root" ? { opening } : {}),
        ...(refusal === "a queue holding the member limit" ? { pending: MEMBER_QUEUE_LIMIT } : {}),
        ...(refusal === "a registry whose member leaves are taken"
          ? { nextIndex: Number(MEMBER_REGISTRY_CAPACITY - AUTHORITY_RESERVED_LEAVES) }
          : {}),
      },
    );
    const key =
      refusal === "an escrow of another key"
        ? stranger.keypair.nullifierKey()
        : who.keypair.nullifierKey();
    const { authority, proveRing } = escrow(key);
    await expect(
      new RegisterKey({
        ringProgramId: RING,
        member: who.shielded,
        payer: PAYER,
        authority,
      }).prove(client),
    ).rejects.toMatchObject({ code: "RING_BUILD_KEY_REGISTRATION", causeCode });
    expect(proveRing).not.toHaveBeenCalled();
  });
});

describe("escrowed keys", () => {
  it("opens a registered member's key for the auditor only", async () => {
    const who = registered(11);
    const { client, tree } = await ring([who.record]);
    const entry = await fetchRingSealedKey({ client, ringProgramId: RING, member: who.member });
    expect(entry.root).toEqual(tree.root);
    expect(entry.sealed).toEqual(who.sealed);
    expect(openRingSealedKey(entry, AUDITOR).secretBytes()).toEqual(
      who.keypair.nullifierKey().secretBytes(),
    );
    expect(() => openRingSealedKey(entry, X25519Keypair.generate())).toThrow(
      expect.objectContaining({ code: "RING_KEY_ENVELOPE_INVALID" }),
    );
  });

  it("refuses an envelope the record does not bind and an absent member", async () => {
    const who = registered(12);
    const ciphertext = Uint8Array.from(who.sealed.ciphertext) as Bytes32;
    ciphertext[0] = (ciphertext[0] ?? 0) ^ 1;
    const altered = { ...who.sealed, ciphertext };
    const { client } = await ring([{ ...who.record, sealed: altered }]);
    await expect(
      fetchRingSealedKey({ client, ringProgramId: RING, member: who.member }),
    ).rejects.toMatchObject({ code: "RING_KEY_NOT_REGISTERED" });
    await expect(
      fetchRingSealedKey({ client, ringProgramId: RING, member: actor(13).member }),
    ).rejects.toMatchObject({ code: "RING_KEY_NOT_REGISTERED" });
  });
});
