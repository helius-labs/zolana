import {
  auditRingTransaction,
  auditorMessage,
  recoverTransactionViewingKey,
} from "../src/ring/audit.js";
import { emptyMemberRecord, emptyRegistryTip, registryFixture } from "./helpers/member-registry.js";
import { ViewingKey } from "../src/keypair/viewing-key.js";
import { X25519Secret } from "../src/keypair/x25519.js";
import {
  address,
  getAddressDecoder,
  getCompiledTransactionMessageDecoder,
  decompileTransactionMessage,
  signTransactionWithSigners,
  type Address,
  type Signature,
} from "@solana/kit";
import { beforeAll, describe, expect, it, vi } from "vitest";

import { prepareTransfer } from "../src/client/prover/assembly.js";
import { ClientError } from "../src/client/error.js";
import type { RingMemberRecordResponse } from "../src/client/ports.js";
import type {
  CustomRingRegisterKeyProofRequest,
  CustomRingPolicyProofRequest,
} from "../src/client/prover/types.js";
import { initializePoseidon } from "../src/hasher/index.js";
import { MERGE_INPUT_COUNT } from "../src/interface/constants.js";
import { Writer, addressBytes } from "../src/interface/internal.js";
import {
  ringConfigPda,
  ringDelegatePda,
  ringMemberRegistryRootPda,
  treeAddress,
} from "../src/interface/pda/index.js";
import { SHIELDED_POOL_PROGRAM_ID } from "../src/interface/program.js";
import type { Bytes16, Bytes31, Bytes32, Bytes33, Bytes128 } from "../src/interface/types.js";
import { NullifierKey } from "../src/keypair/nullifier-key.js";
import {
  mergeDummyNullifier,
  mergeOutputBlinding,
  mergeOutputKey,
} from "../src/keypair/merge/index.js";
import {
  encodeMergeOutputData,
  encryptMergeOutput,
} from "../src/transaction/serialization/merge.js";
import { ShieldedKeypair } from "../src/keypair/shielded.js";
import { SigningKey } from "../src/keypair/signing-key.js";

import { AssetRegistry, SOL_MINT } from "../src/transaction/asset.js";
import { bigIntBytes } from "../src/transaction/internal.js";
import { Data } from "../src/transaction/data.js";
import type { IndexedShieldedTransaction } from "../src/transaction/instructions/transact.js";
import {
  EncryptedScheme,
  encodeOutputData,
  encryptConfidential,
} from "../src/transaction/serialization/codecs.js";
import { createProofOutput, Utxo } from "../src/transaction/utxo.js";
import { encryptCustomRingTransfer } from "../src/transaction/wallet/encrypt-rails.js";
import type { WalletUtxo } from "../src/transaction/wallet/state.js";
import {
  decodeRingMemberRegistryRoot,
  RING_MEMBER_REGISTRY_ROOT_HISTORY,
} from "../src/ring/codecs.js";
import { fetchRingMemberRegistryRoot } from "../src/ring/config.js";
import { buildRingDelegateRecoveredTransaction } from "../src/ring/delegate.js";
import {
  MEMBER_REGISTRY_EMPTY_ROOT,
  MEMBER_REGISTRY_FIELD_MAX,
  verifyMemberRegistryInsert,
} from "../src/ring/member-registry-tree.js";
import { registerRingKeyInstruction } from "../src/ring/instructions.js";
import {
  buildRingKeyRegistrationTransaction,
  createRingKeyRegistrationSubmission,
  fetchRingSealedKey,
  openNullifierKey,
  openRingSealedKey,
  prepareRingKeyRegistration,
  registeredKeyHash,
  registerKeyPublicInputHash,
  sealNullifierKey,
  sealNullifierKeyWith,
  type RingKeyRegistrationClient,
  type SealedNullifierKey,
} from "../src/ring/member-registry.js";
import { RingError } from "../src/ring/error.js";
import { buildRuleTable, memberOfTag, ringNamespaceOwnerHash } from "../src/ring/policy.js";
import { ringPolicyNamespaceAddress } from "../src/ring/config.js";
import { recoverRingMemberNotes } from "../src/ring/recover.js";
import { BLOCKHASH, ringAuditReader, transactionsPage } from "./helpers/clients.js";
import {
  ownSources,
  ownedAccount,
  policyConfigPda,
  ringPolicyConfigData,
  ringProgramConfigData,
} from "./helpers/ring-accounts.js";
import { treeAccount } from "./helpers/tree-account.js";
import {
  firstInsertion,
  memberRegistryRootData,
  oneMemberRegistry,
} from "./helpers/member-registry.js";

function hex(value: string): Uint8Array {
  return Uint8Array.from(Buffer.from(value, "hex"));
}

function filled(byte: number, length = 32): Uint8Array {
  return new Uint8Array(length).fill(byte);
}

/** A blinding below the field order. */
function blinding(byte: number): Bytes32 {
  const bytes = filled(byte);
  bytes[0] = 0;
  return bytes as Bytes32;
}

// Vectors from custom-rings/client/src/encryption.rs
// `the_sealed_key_and_its_registration_statement_match_the_pinned_vector`.
const AUDITOR_SK = hex(
  "01323130373635343b3a39383f3e3d3c23222120272625242b2a29282f2e2d2c",
) as Bytes32;
const EPHEMERAL_SK = hex(
  "011013121514171619181b1a1d1c1f1e010003020504070609080b0a0d0c0f0e",
) as Bytes32;
const NULLIFIER_SECRET = hex(
  "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
) as Bytes31;
const MEMBER_TAG = filled(9) as Bytes32;
const NULLIFIER_PK = hex("2d1faf6cf358763421511eb637adf7b6609443d38edc4ed2b042dfbf834b03f5");
const EPH_PK = hex("043632fe89228ea5215eea45a56704f569e3929868a8573363d015e39609f0eb63");
const CIPHERTEXT = hex("2c2a1650e3a2a0d012a0d438341ff610ad99bd3c1cde0dd169179174880e755d");
const KEY_HASH = hex("1c73c14786dd7354525c98368bca8dbc5f836e957c45f552f377c84e266546c4");
const REGISTRY_NEW_ROOT = hex("133b1a84f6508b81465d8c2388be5210ec4171ef8347193f9dcad621953c5015");
const PUBLIC_INPUT_HASH = hex("2b36575112a72041181227ef0313db6e9d340e56e378dd9e4368eaf9c50c8bfb");

const RING = address("9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh");
const TREE = treeAddress(0);

beforeAll(initializePoseidon);

function actor(seed: number) {
  const keypair = ShieldedKeypair.fromKeypair(SigningKey.fromEd25519Bytes(filled(seed) as Bytes32));
  const address = keypair.shieldedAddress();
  return {
    keypair,
    address,
    enrolment: { address, nullifierKey: keypair.nullifierKey() },
  };
}

describe("nullifier key envelope", () => {
  it("matches the Rust vector and opens only for the auditor", () => {
    const auditor = X25519Secret.fromBytes(AUDITOR_SK);
    const ephemeral = X25519Secret.fromBytes(EPHEMERAL_SK);
    const nullifierKey = NullifierKey.fromSecret(NULLIFIER_SECRET);
    const envelope = sealNullifierKeyWith(ephemeral, nullifierKey, auditor.publicKey());
    expect(envelope.nullifierPublicKey).toEqual(NULLIFIER_PK);
    expect(envelope.sealed.ephemeralPublicKey.toBytes()).toEqual(EPH_PK);
    expect(envelope.sealed.ciphertext).toEqual(CIPHERTEXT);
    expect(envelope.ephemeralSecret).toEqual(EPHEMERAL_SK);
    const opened = openNullifierKey(envelope.sealed, auditor);
    expect(opened.secretBytes()).toEqual(NULLIFIER_SECRET);
    const stranger = X25519Secret.fromBytes(EPHEMERAL_SK);
    try {
      expect(openNullifierKey(envelope.sealed, stranger).secretBytes()).not.toEqual(
        NULLIFIER_SECRET,
      );
    } catch (cause) {
      expect(cause).toMatchObject({ code: "RING_KEY_ENVELOPE_INVALID" });
    }
    const fresh = sealNullifierKey(nullifierKey, auditor.publicKey());
    expect(fresh.sealed.ciphertext).not.toEqual(CIPHERTEXT);
    expect(openNullifierKey(fresh.sealed, auditor).secretBytes()).toEqual(NULLIFIER_SECRET);
  });

  it("hashes the registered key, the registry root and the statement like Rust", () => {
    const auditor = X25519Secret.fromBytes(AUDITOR_SK);
    const member = memberOfTag(MEMBER_TAG);
    const key = registeredKeyHash({
      nullifierPublicKey: NULLIFIER_PK as Bytes32,
      ciphertext: CIPHERTEXT as Bytes32,
    });
    expect(key).toEqual(KEY_HASH);
    const insertion = firstInsertion(member);
    const registryNewRoot = verifyMemberRegistryInsert({
      root: MEMBER_REGISTRY_EMPTY_ROOT,
      appendIndex: 1n,
      member,
      lists: 0n,
      escrowKey: key,
      lowMember: insertion.lowMember,
      lowNext: insertion.lowNext,
      lowLists: 0n,
      lowEscrowKey: insertion.lowKeyHash,
      lowIndex: insertion.lowIndex,
      lowProof: insertion.lowProof,
      newProof: insertion.newProof,
    });
    expect(registryNewRoot).toEqual(REGISTRY_NEW_ROOT);
    expect(
      registerKeyPublicInputHash({
        registryOldRoot: MEMBER_REGISTRY_EMPTY_ROOT,
        registryNewRoot,
        member,
        nullifierPublicKey: NULLIFIER_PK as Bytes32,
        auditorPublicKey: auditor.publicKey(),
        ephemeralPublicKey: X25519Secret.fromBytes(EPHEMERAL_SK).publicKey(),
        ciphertext: CIPHERTEXT as Bytes32,
        newIndex: 1n,
      }),
    ).toEqual(PUBLIC_INPUT_HASH);
  });

  it("encodes the register key instruction like the mollusk fixture", async () => {
    // custom-rings/program/tests/common/mod.rs `register_key_fixture`.
    const member = getAddressDecoder().decode(filled(7));
    const instruction = await registerRingKeyInstruction({
      ringProgramId: RING,
      member,
      proof: Uint8Array.from([
        ...filled(1),
        ...filled(2, 64),
        ...filled(3),
        ...filled(4),
        ...filled(5),
      ]),
      registryOldRootIndex: 0,
      registryNewRoot: filled(0x11) as Bytes32,
      item: {
        member: filled(7) as Bytes32,
        oldLists: 0n,
        oldEscrowKey: filled(0) as Bytes32,
        lists: 0n,
        escrowKey: filled(0x13) as Bytes32,
        index: 1n,
      },
      nullifierPublicKey: filled(0x12) as Bytes32,
      ephemeralPublicKey: filled(0x02, 33) as Bytes33,
      ciphertext: filled(0x44) as Bytes32,
    });
    expect(instruction.data).toEqual(
      Uint8Array.from([
        29,
        ...hex(
          "0101010101010101010101010101010101010101010101010101010101010101" +
            "0202020202020202020202020202020202020202020202020202020202020202" +
            "0202020202020202020202020202020202020202020202020202020202020202" +
            "0303030303030303030303030303030303030303030303030303030303030303" +
            "0404040404040404040404040404040404040404040404040404040404040404" +
            "0505050505050505050505050505050505050505050505050505050505050505" +
            "00" +
            "11".repeat(32) +
            "07".repeat(32) +
            "00".repeat(8 + 32 + 8) +
            "13".repeat(32) +
            "0100000000000000" +
            "1212121212121212121212121212121212121212121212121212121212121212" +
            "020202020202020202020202020202020202020202020202020202020202020202" +
            "4444444444444444444444444444444444444444444444444444444444444444",
        ),
      ]),
    );
    expect(instruction.data?.length).toBe(443);
    expect(instruction.accounts?.map((account) => account.address)).toEqual([
      member,
      (await ringConfigPda(RING))[0],
      (await ringMemberRegistryRootPda(RING))[0],
    ]);
  });
});

describe("key registry root", () => {
  it("decodes the account with its root history and refuses another layout", async () => {
    const [rootAddress, bump] = await ringMemberRegistryRootPda(RING);
    const data = memberRegistryRootData({
      root: MEMBER_REGISTRY_EMPTY_ROOT,
      nextIndex: 1n,
      bump: bump,
    });
    expect(decodeRingMemberRegistryRoot(data)).toEqual({
      root: MEMBER_REGISTRY_EMPTY_ROOT,
      nextIndex: 1n,
      bump,
      historyCursor: 0,
      history: [
        MEMBER_REGISTRY_EMPTY_ROOT,
        ...Array.from({ length: 31 }, () => new Uint8Array(32)),
      ],
    });
    const advanced = decodeRingMemberRegistryRoot(
      memberRegistryRootData({
        root: filled(5) as Bytes32,
        nextIndex: 3n,
        bump,
        cursor: 31,
        history: [MEMBER_REGISTRY_EMPTY_ROOT],
      }),
    );
    expect(advanced.historyCursor).toBe(31);
    expect(advanced.history[0]).toEqual(MEMBER_REGISTRY_EMPTY_ROOT);
    expect(advanced.history[31]).toEqual(filled(5));
    for (const cursor of [1, RING_MEMBER_REGISTRY_ROOT_HISTORY]) {
      const unwritten = new Uint8Array(data);
      unwritten[10] = cursor;
      expect(() => decodeRingMemberRegistryRoot(unwritten)).toThrow("RING_MEMBER_REGISTRY_INVALID");
    }
    expect(() => decodeRingMemberRegistryRoot(data.subarray(0, 42))).toThrow(
      "RING_MEMBER_REGISTRY_INVALID",
    );
    expect(() =>
      decodeRingMemberRegistryRoot(
        memberRegistryRootData({
          root: MEMBER_REGISTRY_EMPTY_ROOT,
          nextIndex: 0n,
          bump: bump,
        }),
      ),
    ).toThrow("RING_MEMBER_REGISTRY_INVALID");
    const otherKind = new Uint8Array(data);
    otherKind[0] = 8;
    expect(() => decodeRingMemberRegistryRoot(otherKind)).toThrow("RING_MEMBER_REGISTRY_INVALID");
    await expect(
      fetchRingMemberRegistryRoot({ getAccount: async () => undefined }, RING),
    ).rejects.toMatchObject({ code: "RING_MEMBER_REGISTRY_MISSING" });
    await expect(
      fetchRingMemberRegistryRoot(
        {
          getAccount: async (key) =>
            key === rootAddress
              ? ownedAccount(
                  RING,
                  memberRegistryRootData({
                    root: MEMBER_REGISTRY_EMPTY_ROOT,
                    nextIndex: 1n,
                    bump: bump ^ 1,
                  }),
                )
              : undefined,
        },
        RING,
      ),
    ).rejects.toMatchObject({ code: "RING_MEMBER_REGISTRY_INVALID" });
  });
});

function wrongKeyPassingPad(sealed: SealedNullifierKey): X25519Secret {
  for (let scalar = 2n; scalar < 4096n; scalar++) {
    const key = X25519Secret.fromBytes(bigIntBytes(scalar) as Bytes32);
    try {
      openNullifierKey(sealed, key).destroy();
      return key;
    } catch (error) {
      if (!(error instanceof RingError && error.code === "RING_KEY_ENVELOPE_INVALID")) throw error;
    }
  }
  throw new Error("no wrong key passes the pad byte");
}

async function registrationFixture(input: Readonly<{ registered?: boolean }> = {}) {
  const auditor = X25519Secret.fromBytes(AUDITOR_SK);
  const member = actor(3);
  const identity = memberOfTag(member.address.confidentialViewTag());
  const [config, configBump] = await ringConfigPda(RING);
  const [rootAddress, rootBump] = await ringMemberRegistryRootPda(RING);
  const insertion = firstInsertion(identity);
  // A pinned seal fixes which wrong key passes the pad byte.
  const envelope = sealNullifierKeyWith(
    X25519Secret.fromBytes(EPHEMERAL_SK),
    member.keypair.nullifierKey(),
    auditor.publicKey(),
  );
  const key = registeredKeyHash({
    nullifierPublicKey: envelope.nullifierPublicKey,
    ciphertext: envelope.sealed.ciphertext,
  });
  const registeredRoot = verifyMemberRegistryInsert({
    root: MEMBER_REGISTRY_EMPTY_ROOT,
    appendIndex: 1n,
    member: identity,
    lists: 0n,
    escrowKey: key,
    lowMember: insertion.lowMember,
    lowNext: insertion.lowNext,
    lowLists: 0n,
    lowEscrowKey: insertion.lowKeyHash,
    lowIndex: insertion.lowIndex,
    lowProof: insertion.lowProof,
    newProof: insertion.newProof,
  });
  const root = input.registered
    ? { root: registeredRoot, nextIndex: 2n }
    : { root: MEMBER_REGISTRY_EMPTY_ROOT, nextIndex: 1n };
  const entry: RingMemberRecordResponse = {
    context: { slot: 1n, blockTime: 1n },
    root: registeredRoot,
    nextIndex: 2n,
    rootIndex: 0,
    present: true,
    low: null,
    record: {
      member: identity,
      next: MEMBER_REGISTRY_FIELD_MAX,
      lists: 0n,
      escrowKey: key,
      ephemeralPublicKey: envelope.sealed.ephemeralPublicKey,
      ciphertext: envelope.sealed.ciphertext,
    },
    index: 1n,
    path: insertion.newProof,
  };
  let request: CustomRingRegisterKeyProofRequest | undefined;
  // The flow wipes the secrets once the prover returns, the test keeps copies.
  const prove = vi.fn(async (proofRequest: CustomRingRegisterKeyProofRequest) => {
    request = {
      ...proofRequest,
      nullifierSecret: new Uint8Array(proofRequest.nullifierSecret) as Bytes32,
      ephemeralSecret: new Uint8Array(proofRequest.ephemeralSecret) as Bytes32,
    };
    return new Uint8Array(192);
  });
  const client: RingKeyRegistrationClient = {
    getAccount: async (key) => {
      if (key === config)
        return ownedAccount(
          RING,
          ringProgramConfigData({
            authority: member.address.solanaAddress(),
            auditorPublicKey: auditor.publicKey().toBytes(),
            bump: configBump,
            hasPolicy: false,
          }),
        );
      if (key === rootAddress)
        return ownedAccount(
          RING,
          memberRegistryRootData({
            root: root.root,
            nextIndex: root.nextIndex,
            bump: rootBump,
          }),
        );
      return undefined;
    },
    getLatestBlockhash: async () => BLOCKHASH,
    getRingMemberRegistryRoot: async () => emptyRegistryTip(),
    getRingMemberRecord: async () => (input.registered ? entry : emptyMemberRecord()),
    proveCustomRingRegisterKey: prove,
  };
  return {
    auditor,
    member,
    identity,
    client,
    prove,
    request: () => request,
    envelope,
    entry,
  };
}

describe("key registration flow", () => {
  it("registers an existing member without changing its lists or append cursor", async () => {
    const test = await registrationFixture();
    const registry = registryFixture([{ member: test.identity, lists: 0x85n }]);
    const [root, bump] = await ringMemberRegistryRootPda(RING);
    const getAccount = test.client.getAccount;
    const client = {
      ...test.client,
      getAccount: async (key: Address) =>
        key === root
          ? ownedAccount(RING, memberRegistryRootData({ ...registry.tip, bump }))
          : getAccount(key),
      getRingMemberRecord: async () => registry.read(test.identity),
      getRingMemberRegistryRoot: async () => registry.tip,
    };
    await expect(
      prepareRingKeyRegistration({
        client,
        ringProgramId: RING,
        member: test.member.enrolment,
      }),
    ).resolves.toMatchObject({ kind: "pending" });
    const request = test.request();
    if (request === undefined) throw new Error("missing proof");
    expect(request.oldLists).toBe(0x85n);
    expect(request.update.exists).toBe(true);
    expect(request.update.index).toBe(1n);
    const envelope = sealNullifierKeyWith(
      X25519Secret.fromBytes(request.ephemeralSecret),
      test.member.keypair.nullifierKey(),
      test.auditor.publicKey(),
    );
    const reference = registryFixture([
      {
        member: test.identity,
        lists: 0x85n,
        escrowKey: registeredKeyHash({
          nullifierPublicKey: envelope.nullifierPublicKey,
          ciphertext: envelope.sealed.ciphertext,
        }),
      },
    ]);
    expect(request.registryNewRoot).toEqual(reference.root);
    expect(reference.tip.nextIndex).toBe(registry.tip.nextIndex);
  });

  it("seals the lent key, proves the append and pays as the member", async () => {
    const test = await registrationFixture();
    const preparation = await prepareRingKeyRegistration({
      client: test.client,
      ringProgramId: RING,
      member: test.member.enrolment,
    });
    expect(preparation.kind).toBe("pending");
    expect(test.prove).toHaveBeenCalledTimes(1);
    const request = test.request();
    if (request === undefined) throw new Error("registration proof missing");
    expect(request.member).toEqual(test.identity);
    expect(request.update.index).toBe(1n);
    expect(request.nullifierSecret[0]).toBe(0);
    expect(request.nullifierSecret.subarray(1)).toEqual(
      test.member.keypair.nullifierKey().secretBytes(),
    );
    expect(request.auditorPublicKey).toEqual(test.auditor.publicKey().u());
    // The ephemeral scalar the prover witnesses reproduces the sealed envelope.
    const envelope = sealNullifierKeyWith(
      X25519Secret.fromBytes(request.ephemeralSecret),
      test.member.keypair.nullifierKey(),
      test.auditor.publicKey(),
    );
    const insertion = firstInsertion(test.identity);
    const registryNewRoot = verifyMemberRegistryInsert({
      root: MEMBER_REGISTRY_EMPTY_ROOT,
      appendIndex: 1n,
      member: test.identity,
      lists: 0n,
      escrowKey: registeredKeyHash({
        nullifierPublicKey: envelope.nullifierPublicKey,
        ciphertext: envelope.sealed.ciphertext,
      }),
      lowMember: insertion.lowMember,
      lowNext: insertion.lowNext,
      lowLists: 0n,
      lowEscrowKey: insertion.lowKeyHash,
      lowIndex: insertion.lowIndex,
      lowProof: insertion.lowProof,
      newProof: insertion.newProof,
    });
    expect(request.registryNewRoot).toEqual(registryNewRoot);
    expect(request.publicInputHash).toEqual(
      registerKeyPublicInputHash({
        registryOldRoot: MEMBER_REGISTRY_EMPTY_ROOT,
        registryNewRoot,
        member: test.identity,
        nullifierPublicKey: envelope.nullifierPublicKey,
        auditorPublicKey: test.auditor.publicKey(),
        ephemeralPublicKey: envelope.sealed.ephemeralPublicKey,
        ciphertext: envelope.sealed.ciphertext,
        newIndex: 1n,
      }),
    );
    const transaction = await buildRingKeyRegistrationTransaction({
      client: test.client,
      ringProgramId: RING,
      member: test.member.enrolment,
    });
    expect(Object.keys(transaction.signatures)).toEqual([test.member.address.solanaAddress()]);
  });

  it("rebuilds after a stale registry root failure and never while the send is unknown", async () => {
    const test = await registrationFixture();
    const submission = await createRingKeyRegistrationSubmission({
      client: test.client,
      ringProgramId: RING,
      member: test.member.enrolment,
    });
    const signer = test.member.keypair.toSolanaSigner();
    const sign = vi.fn(async (transaction: Parameters<typeof signTransactionWithSigners>[1]) =>
      signTransactionWithSigners([signer], transaction),
    );
    const send = vi.fn(async () => undefined);
    const unknown = await submission.send({
      sign,
      send,
      status: async () => ({ kind: "unknown" }),
    });
    expect(unknown.kind).toBe("unknown");
    expect(test.prove).toHaveBeenCalledTimes(1);
    let statuses = 0;
    const result = await submission.send({
      sign,
      send,
      status: async () =>
        statuses++ === 0
          ? { kind: "failed", instructionIndex: 0, customCode: 8161 }
          : { kind: "confirmed", slot: 9n },
    });
    expect(result).toMatchObject({ kind: "confirmed", attempts: 2 });
    expect(test.prove).toHaveBeenCalledTimes(2);
  });

  it("refuses a stale insertion before proving and keeps indexer outages distinct", async () => {
    const test = await registrationFixture();
    await expect(
      buildRingKeyRegistrationTransaction({
        client: {
          ...test.client,
          getRingMemberRegistryRoot: async () => ({
            ...(await test.client.getRingMemberRegistryRoot({
              ringProgramId: RING,
            })),
            nextIndex: 2n,
          }),
        },
        ringProgramId: RING,
        member: test.member.enrolment,
      }),
    ).rejects.toMatchObject({ code: "RING_MEMBER_REGISTRY_STALE" });
    expect(test.prove).not.toHaveBeenCalled();
    const abort = new AbortController();
    await expect(
      prepareRingKeyRegistration(
        {
          client: {
            ...test.client,
            getRingMemberRecord: async () => {
              abort.abort();
              throw new ClientError("CLIENT_MEMBER_REGISTRY_OUT_OF_SYNC", {
                details: { method: "getRingMemberRecord" },
              });
            },
          },
          ringProgramId: RING,
          member: test.member.enrolment,
        },
        { signal: abort.signal },
      ),
    ).rejects.toMatchObject({ code: "CLIENT_ABORTED" });
  });

  it("refuses a lent nullifier key that does not derive the address", async () => {
    const test = await registrationFixture();
    const other = actor(4);
    await expect(
      prepareRingKeyRegistration({
        client: test.client,
        ringProgramId: RING,
        member: {
          address: test.member.address,
          nullifierKey: other.keypair.nullifierKey(),
        },
      }),
    ).rejects.toMatchObject({ code: "RING_NULLIFIER_KEY_MISMATCH" });
    expect(test.prove).not.toHaveBeenCalled();
  });

  it("reports a registered member and opens its sealed key under the root", async () => {
    const test = await registrationFixture({ registered: true });
    const preparation = await prepareRingKeyRegistration({
      client: test.client,
      ringProgramId: RING,
      member: test.member.enrolment,
    });
    expect(preparation.kind).toBe("registered");
    if (preparation.kind !== "registered") throw new Error("unreachable");
    expect(preparation.sealed.ciphertext).toEqual(test.envelope.sealed.ciphertext);
    const entry = await fetchRingSealedKey({
      client: test.client,
      ringProgramId: RING,
      member: test.identity,
    });
    const opened = openRingSealedKey(entry, test.auditor);
    expect(opened.publicKey()).toEqual(test.member.keypair.nullifierPublicKey());
    // The pad byte is no authenticator, inclusion refuses a wrong key that passes it.
    expect(() => openRingSealedKey(entry, X25519Secret.fromBytes(EPHEMERAL_SK))).toThrow(
      /RING_KEY_(ENVELOPE|REGISTRY)_INVALID/,
    );
    expect(() => openRingSealedKey(entry, wrongKeyPassingPad(entry.sealed))).toThrow(
      "RING_MEMBER_REGISTRY_INVALID",
    );
    const forged = {
      ...entry,
      proof: [filled(1) as Bytes32, ...entry.proof.slice(1)],
    };
    expect(() => openRingSealedKey(forged, test.auditor)).toThrow("RING_MEMBER_REGISTRY_INVALID");
    await expect(
      fetchRingSealedKey({
        client: {
          ...test.client,
          getRingMemberRecord: async () => ({ ...test.entry, nextIndex: 3n }),
        },
        ringProgramId: RING,
        member: test.identity,
      }),
    ).rejects.toMatchObject({ code: "RING_MEMBER_REGISTRY_STALE" });
  });
});

/** One ring transaction paying `outputs` to `source`, encrypted the way a sender does. */
function ringTransaction(
  input: Readonly<{
    auditor: X25519Secret;
    source: ReturnType<typeof actor>;
    assets?: AssetRegistry;
    outputs: readonly Readonly<{
      amount: bigint;
      asset?: Address;
      hash?: Bytes32;
      recipient?: ReturnType<typeof actor>;
      data?: Data;
      dataHash?: Bytes32;
      ringDataHash?: Bytes32;
    }>[];
    nullifiers?: readonly Bytes32[];
  }>,
): IndexedShieldedTransaction {
  const tx = ViewingKey.generate();
  const proofOutputs = input.outputs.map((output, index) =>
    createProofOutput({
      ownerAddress: (output.recipient ?? input.source).address,
      asset: output.asset ?? SOL_MINT,
      amount: output.amount,
      blinding: blinding(50 + index),
      ringProgramId: RING,
      ...(output.data === undefined ? {} : { data: output.data }),
      ...(output.dataHash === undefined ? {} : { dataHash: output.dataHash }),
      ...(output.ringDataHash === undefined ? {} : { ringDataHash: output.ringDataHash }),
    }),
  );
  if (proofOutputs.length === 0) {
    tx.destroy();
    return {
      slot: 1n,
      txSignature: "1".repeat(87) as Signature,
      eventIndex: 0,
      ringProgramId: RING,
      outputSlots: [],
      messages: [],
      nullifiers: [...(input.nullifiers ?? [])],
      proofless: false,
    };
  }
  const encrypted = encryptCustomRingTransfer(tx, {
    outputs: proofOutputs,
    assets: input.assets ?? new AssetRegistry(),
    auditorPublicKey: input.auditor.publicKey(),
    outputTreeId: 0,
  });
  tx.destroy();
  return {
    slot: 1n,
    txSignature: "1".repeat(87) as Signature,
    eventIndex: 0,
    ringProgramId: RING,
    txViewingPublicKey: encrypted.txViewingPublicKey,
    salt: encrypted.salt,
    outputSlots: input.outputs.map((output, index) => {
      const recipient = output.recipient ?? input.source;
      const proofOutput = proofOutputs[index];
      const payload = encrypted.payload[index];
      if (proofOutput === undefined || payload === undefined) throw new Error("output fixture");
      return {
        viewTag: recipient.address.confidentialViewTag(),
        outputContext: {
          hash: output.hash ?? proofOutput.hash(0),
          tree: TREE,
          leafIndex: BigInt(index),
        },
        payload: payload.data,
      };
    }),
    messages: [encrypted.auditorMessage],
    nullifiers: [...(input.nullifiers ?? [])],
    proofless: false,
  };
}

describe("ring member recovery", () => {
  it.each(["malformed", "wrongRecipient", "wrongAmount", "unknownAsset", "unprovedData"] as const)(
    "recovers proved openings despite %s recipient data",
    async (corruption) => {
      const auditor = X25519Secret.generate();
      const source = actor(3);
      const other = actor(4);
      const original = ringTransaction({
        auditor,
        source,
        outputs: [{ amount: 7n, dataHash: blinding(corruption === "unprovedData" ? 0 : 1) }],
      });
      const key = recoverTransactionViewingKey(
        auditor,
        auditorMessage(original, auditor.publicKey()),
      );
      let payload: Uint8Array;
      try {
        if (original.salt === undefined) throw new Error("salt");
        payload =
          corruption === "malformed"
            ? Uint8Array.of(255)
            : encodeOutputData(
                EncryptedScheme.ringConfidential,
                encryptConfidential(
                  key,
                  corruption === "wrongRecipient"
                    ? other.address.viewingPublicKey
                    : source.address.viewingPublicKey,
                  {
                    assetId: corruption === "unknownAsset" ? 999n : 1n,
                    amount: corruption === "wrongAmount" ? 999n : 7n,
                    blinding: blinding(50),
                    data: new Data(
                      corruption === "unprovedData"
                        ? [
                            { kind: "utxoData", bytes: Uint8Array.of(9) },
                            { kind: "memo", bytes: Uint8Array.of(10) },
                          ]
                        : [],
                    ),
                    ringProgramId: RING,
                  },
                  original.salt,
                  0,
                ),
                "encrypted",
              );
      } finally {
        key.destroy();
      }
      const transaction = {
        ...original,
        outputSlots: original.outputSlots.map((slot) => ({ ...slot, payload })),
      };
      const audited = auditRingTransaction({
        auditor,
        transaction,
        assets: new AssetRegistry(),
      });
      expect(audited.outputOpenings).toHaveLength(1);
      expect(audited.outputContexts[0]).toEqual(transaction.outputSlots[0]?.outputContext);
      expect(audited.undecryptableSlots).toEqual(
        corruption === "wrongRecipient" || corruption === "unprovedData" ? [] : [0],
      );
      if (corruption === "unprovedData") expect(audited.outputs[0]?.data.records()).toHaveLength(2);
      const getProgramAccounts = vi.fn(() => ({ send: async () => [] }));
      const getShieldedTransactionsByNullifiers = vi.fn(async () => transactionsPage());
      const recovered = await recoverRingMemberNotes({
        client: {
          ...ringAuditReader({
            getShieldedTransactionsByTags: async () =>
              transactionsPage({ transactions: [transaction] }),
            solanaRpc: { getProgramAccounts },
          }),
          getShieldedTransactionsByNullifiers,
        },
        ringProgramId: RING,
        auditor,
        source: source.address,
        nullifierKey: source.keypair.nullifierKey(),
        assets: new AssetRegistry(),
        resolveTreeId: () => 0,
        origin: {
          ringInvoked: async () => true,
          confirmedTransaction: async (transaction: IndexedShieldedTransaction) => transaction,
        },
      });
      expect(recovered.notes.map((note) => note.utxo.amount)).toEqual([7n]);
      expect(recovered.notes[0]?.dataHash).toEqual(
        corruption === "unprovedData" ? undefined : blinding(1),
      );
      expect(recovered.notes[0]?.utxo.data.records()).toEqual([]);
      expect(recovered.unopened).toEqual([]);
      expect(getShieldedTransactionsByNullifiers).toHaveBeenCalledTimes(1);
      expect(getProgramAccounts).not.toHaveBeenCalled();
    },
  );

  it("retains unresolved proved assets and still checks whether their nullifiers were spent", async () => {
    const auditor = X25519Secret.generate();
    const source = actor(3);
    const asset = getAddressDecoder().decode(filled(9));
    const transaction = ringTransaction({
      auditor,
      source,
      assets: new AssetRegistry([[2n, asset]]),
      outputs: [{ amount: 7n, asset }],
    });
    const slot = transaction.outputSlots[0];
    if (slot === undefined) throw new Error("slot");
    const nullifier = source.keypair
      .nullifierKey()
      .nullifier(slot.outputContext.hash, blinding(50));
    for (const spent of [false, true]) {
      const query = vi.fn(async (request: Readonly<{ nullifiers: readonly Bytes32[] }>) => {
        expect(request.nullifiers).toEqual([nullifier]);
        return transactionsPage({
          transactions: spent
            ? [
                ringTransaction({
                  auditor,
                  source,
                  outputs: [],
                  nullifiers: [nullifier],
                }),
              ]
            : [],
        });
      });
      const recovered = await recoverRingMemberNotes({
        client: {
          ...ringAuditReader({
            getShieldedTransactionsByTags: async () =>
              transactionsPage({ transactions: [transaction] }),
            solanaRpc: { getProgramAccounts: () => ({ send: async () => [] }) },
          }),
          getShieldedTransactionsByNullifiers: query,
        },
        ringProgramId: RING,
        auditor,
        source: source.address,
        nullifierKey: source.keypair.nullifierKey(),
        assets: new AssetRegistry(),
        resolveTreeId: () => 0,
        origin: {
          ringInvoked: async () => true,
          confirmedTransaction: async (transaction: IndexedShieldedTransaction) => transaction,
        },
      });
      expect(recovered.notes).toEqual([]);
      expect(recovered.unopened).toEqual(spent ? [] : [slot.outputContext.hash]);
      expect(query).toHaveBeenCalledTimes(1);
    }
  });

  it("rebuilds the member's unspent notes from the auditor's view", async () => {
    const auditor = X25519Secret.generate();
    const source = actor(3);
    const other = actor(4);
    const transaction = ringTransaction({
      auditor,
      source,
      outputs: [
        { amount: 7n },
        { amount: 5n },
        { amount: 9n, dataHash: filled(1) as Bytes32 },
        { amount: 3n, recipient: other },
      ],
    });
    const nullifierKey = source.keypair.nullifierKey();
    const spentSlot = transaction.outputSlots[1];
    if (spentSlot === undefined) throw new Error("slot");
    const spent = new Utxo({
      owner: source.keypair.signingPublicKey(),
      asset: SOL_MINT,
      amount: 5n,
      blinding: blinding(51),
      ringProgramId: RING,
    }).nullifier(spentSlot.outputContext.hash, nullifierKey);
    const byNullifiers = vi.fn(async (request: Readonly<{ nullifiers: readonly Bytes32[] }>) =>
      transactionsPage({
        transactions: [
          ringTransaction({
            auditor,
            source,
            outputs: [],
            nullifiers: request.nullifiers.filter((nullifier) => nullifier.join() === spent.join()),
          }),
        ],
        scannedThrough: new Uint8Array(1),
      }),
    );
    const client = {
      ...ringAuditReader({
        getShieldedTransactionsByTags: async () =>
          transactionsPage({ transactions: [transaction] }),
      }),
      getShieldedTransactionsByNullifiers: byNullifiers,
    };
    const recovered = await recoverRingMemberNotes({
      client,
      ringProgramId: RING,
      auditor,
      source: source.address,
      nullifierKey,
      assets: new AssetRegistry(),
      resolveTreeId: () => 0,
      origin: {
        ringInvoked: async () => true,
        confirmedTransaction: async (transaction: IndexedShieldedTransaction) => transaction,
      },
    });
    expect(recovered.notes.map((note) => note.utxo.amount)).toEqual([7n, 9n]);
    expect(recovered.notes[0]?.outputContext).toEqual(transaction.outputSlots[0]?.outputContext);
    expect(recovered.unopened).toEqual([]);
    expect(byNullifiers.mock.calls[0]?.[0]?.nullifiers).toHaveLength(3);
    await expect(
      recoverRingMemberNotes({
        client,
        ringProgramId: RING,
        auditor,
        source: source.address,
        nullifierKey: other.keypair.nullifierKey(),
        assets: new AssetRegistry(),
        resolveTreeId: () => 0,
      }),
    ).rejects.toMatchObject({ code: "RING_NULLIFIER_KEY_MISMATCH" });
    await expect(
      recoverRingMemberNotes({
        client: {
          ...client,
          getShieldedTransactionsByTags: async () =>
            transactionsPage({
              transactions: [transaction],
              nextCursor: new Uint8Array(1),
            }),
        },
        ringProgramId: RING,
        auditor,
        source: source.address,
        nullifierKey,
        assets: new AssetRegistry(),
        resolveTreeId: () => 0,
        origin: {
          ringInvoked: async () => true,
          confirmedTransaction: async (transaction: IndexedShieldedTransaction) => transaction,
        },
        maxPages: 1,
      }),
    ).rejects.toMatchObject({ code: "RING_RECOVERY_INCOMPLETE" });
  });
});

function mergeTransaction(
  source: ReturnType<typeof actor>,
  inputs: readonly WalletUtxo[],
  treeId = 0,
  ringDataHash = new Uint8Array(32) as Bytes32,
  width = MERGE_INPUT_COUNT,
): { transaction: IndexedShieldedTransaction; note: WalletUtxo } {
  const first = inputs[0];
  if (first === undefined) throw new Error("merge inputs missing");
  const key = source.keypair.nullifierKey();
  try {
    const nullifiers = inputs.map((input) => input.nullifier);
    while (nullifiers.length < width)
      nullifiers.push(mergeDummyNullifier(key, first.nullifier, nullifiers.length));
    const utxo = new Utxo({
      owner: source.address.signingPublicKey,
      asset: SOL_MINT,
      amount: inputs.reduce((sum, input) => sum + input.utxo.amount, 0n),
      blinding: mergeOutputBlinding(key, first.nullifier),
      ringProgramId: RING,
    });
    const outputContext = {
      hash: utxo.hash(source.address.nullifierPublicKey, treeId, undefined, ringDataHash),
      tree: treeAddress(treeId),
      leafIndex: 4n,
    };
    const salt = new Uint8Array(16).fill(treeId + 1) as Bytes16;
    return {
      transaction: {
        txSignature: "1".repeat(87) as Signature,
        slot: 2n,
        eventIndex: 0,
        ringProgramId: RING,
        proofless: false,
        nullifiers,
        outputSlots: [
          {
            viewTag: first.nullifier,
            outputContext,
            payload: encodeMergeOutputData({
              ringDataHash,
              salt,
              ciphertext: encryptMergeOutput(
                { amount: utxo.amount, mint: utxo.asset },
                mergeOutputKey(key, first.nullifier),
                salt,
              ),
            }),
          },
        ],
        messages: [],
      },
      note: {
        utxo,
        outputContext,
        nullifier: utxo.nullifier(outputContext.hash, key),
        ringDataHash,
        spent: false,
      },
    };
  } finally {
    key.destroy();
  }
}

describe("recovery closure", () => {
  it("reports recipient encrypted deposits separately without claiming their spend status", async () => {
    const source = actor(3);
    const auditor = X25519Secret.generate();
    const key = source.keypair.nullifierKey();
    const ciphertext = new Uint8Array([35, 36, 37]);
    const body = new Writer()
      .bytes(blinding(32))
      .bytes(addressBytes(SOL_MINT))
      .u64(7n, "amount")
      .u8(0, "dataHash")
      .bytes(addressBytes(RING))
      .bytes(new Uint8Array(32))
      .bytes(auditor.publicKey().toBytes())
      .bytes(new Uint8Array(16))
      .u32(ciphertext.length, "ciphertextLength")
      .bytes(ciphertext)
      .finish();
    const commitment = blinding(12);
    const deposit: IndexedShieldedTransaction = {
      txSignature: "1".repeat(87) as Signature,
      slot: 1n,
      eventIndex: 0,
      ringProgramId: RING,
      proofless: true,
      nullifiers: [],
      messages: [],
      outputSlots: [
        {
          viewTag: source.address.viewingPublicKey.x(),
          outputContext: { hash: commitment, tree: TREE, leafIndex: 1n },
          payload: encodeOutputData(EncryptedScheme.ringDeposit, body, "encrypted"),
        },
      ],
    };
    const requested: Bytes32[][] = [];
    const client = {
      ...ringAuditReader({
        getShieldedTransactionsByTags: async (request) => {
          requested.push([...request.tags]);
          return transactionsPage({
            transactions:
              request.ringProgramId === RING
                ? [
                    deposit,
                    {
                      ...deposit,
                      outputSlots: deposit.outputSlots.map((slot) => ({
                        ...slot,
                        payload: new Uint8Array([255]),
                      })),
                    },
                  ]
                : [],
          });
        },
      }),
      getShieldedTransactionsByNullifiers: vi.fn(async () => transactionsPage()),
    };
    const input = {
      client,
      ringProgramId: RING,
      auditor,
      source: source.address,
      nullifierKey: key,
      assets: new AssetRegistry(),
      resolveTreeId: () => 0,
    };
    const result = await recoverRingMemberNotes({
      ...input,
      origin: {
        ringInvoked: async () => true,
        confirmedTransaction: async (transaction: IndexedShieldedTransaction) => transaction,
      },
    });
    expect(result.notes).toEqual([]);
    expect(result.unopened).toEqual([]);
    expect(result.unsupportedDeposits).toEqual([commitment]);
    expect(requested).toContainEqual([]);
    expect(client.getShieldedTransactionsByNullifiers).not.toHaveBeenCalled();
    const foreign = await recoverRingMemberNotes({
      ...input,
      origin: {
        ringInvoked: async () => false,
        confirmedTransaction: async () => undefined,
      },
    });
    expect(foreign.unsupportedDeposits).toEqual([]);
    key.destroy();
    auditor.destroy();
  });

  it("recovers successive auditorless merges across trees and checks successor spends", async () => {
    const source = actor(3);
    const auditor = X25519Secret.generate();
    const key = source.keypair.nullifierKey();
    const seed = ringTransaction({
      auditor,
      source,
      outputs: [{ amount: 2n }, { amount: 3n }, { amount: 4n }],
    });
    const predecessors = seed.outputSlots.map((slot, index): WalletUtxo => {
      const utxo = new Utxo({
        owner: source.address.signingPublicKey,
        asset: SOL_MINT,
        amount: BigInt(index + 2),
        blinding: blinding(50 + index),
        ringProgramId: RING,
      });
      return {
        utxo,
        outputContext: slot.outputContext,
        nullifier: utxo.nullifier(slot.outputContext.hash, key),
        spent: false,
      };
    });
    const first = mergeTransaction(source, predecessors.slice(0, 2), 0, blinding(7), 36);
    const last = predecessors[2];
    if (last === undefined) throw new Error("third note missing");
    const second = mergeTransaction(source, [first.note, last], 1);
    const queried: Bytes32[][] = [];
    const client = {
      ...ringAuditReader({
        getShieldedTransactionsByTags: async () => transactionsPage({ transactions: [seed] }),
      }),
      getShieldedTransactionsByNullifiers: async (
        request: Readonly<{ nullifiers: readonly Bytes32[] }>,
      ) => {
        queried.push([...request.nullifiers]);
        const transactions = [second.transaction, first.transaction].filter((transaction) =>
          transaction.nullifiers.some((nullifier) =>
            request.nullifiers.some((requested) => requested.join() === nullifier.join()),
          ),
        );
        if (request.nullifiers.some((nullifier) => nullifier.join() === last.nullifier.join()))
          transactions.push({
            ...second.transaction,
            nullifiers: [second.note.nullifier],
            outputSlots: [],
          });
        return transactionsPage({
          transactions,
        });
      },
    };
    const result = await recoverRingMemberNotes({
      client,
      ringProgramId: RING,
      auditor,
      source: source.address,
      nullifierKey: key,
      assets: new AssetRegistry(),
      resolveTreeId: (tree) => (tree === TREE ? 0 : 1),
      origin: {
        ringInvoked: async () => true,
        confirmedTransaction: async (transaction: IndexedShieldedTransaction) => transaction,
      },
    });
    expect(result.notes).toHaveLength(1);
    expect(result.notes[0]?.utxo.amount).toBe(9n);
    expect(result.notes[0]?.outputContext).toEqual(second.note.outputContext);
    expect(result.unopened).toEqual([]);
    expect(queried.flat()).toContainEqual(second.note.nullifier);
    await expect(
      recoverRingMemberNotes({
        client,
        ringProgramId: RING,
        auditor,
        source: source.address,
        nullifierKey: key,
        assets: new AssetRegistry(),
        resolveTreeId: (tree) => (tree === TREE ? 0 : 1),
        origin: {
          ringInvoked: async () => true,
          confirmedTransaction: async (transaction: IndexedShieldedTransaction) => transaction,
        },
        maxPages: 1,
      }),
    ).rejects.toMatchObject({ code: "RING_RECOVERY_INCOMPLETE" });

    const incomplete = await recoverRingMemberNotes({
      client,
      ringProgramId: RING,
      auditor,
      source: source.address,
      nullifierKey: key,
      assets: new AssetRegistry(),
      resolveTreeId: () => 0,
      origin: {
        ringInvoked: async () => true,
        confirmedTransaction: async (transaction: IndexedShieldedTransaction) => transaction,
      },
    });
    expect(incomplete.notes).toEqual([]);
    expect(incomplete.unopened).toEqual([second.note.outputContext.hash]);
    key.destroy();
    auditor.destroy();
  });

  it.each(["ordinary", "unprovedData", "unreadable"] as const)(
    "decrypts an unseen-input merge despite %s predecessor delivery",
    async (delivery) => {
      const source = actor(3);
      const auditor = X25519Secret.generate();
      const key = source.keypair.nullifierKey();
      const original = ringTransaction({
        auditor,
        source,
        outputs: [
          {
            amount: 2n,
            dataHash: blinding(0),
            ...(delivery === "unprovedData"
              ? {
                  data: new Data([{ kind: "utxoData", bytes: Uint8Array.of(9) }]),
                }
              : {}),
          },
        ],
      });
      const seed =
        delivery === "unreadable"
          ? {
              ...original,
              outputSlots: original.outputSlots.map((slot) => ({
                ...slot,
                payload: Uint8Array.of(255),
              })),
            }
          : original;
      const seedSlot = seed.outputSlots[0];
      if (seedSlot === undefined) throw new Error("seed output missing");
      const known = new Utxo({
        owner: source.address.signingPublicKey,
        asset: SOL_MINT,
        amount: 2n,
        blinding: blinding(50),
        ringProgramId: RING,
      });
      const unseen = new Utxo({
        owner: source.address.signingPublicKey,
        asset: SOL_MINT,
        amount: 40n,
        blinding: blinding(60),
        ringProgramId: RING,
      });
      const unseenContext = {
        hash: unseen.hash(source.address.nullifierPublicKey, 0),
        tree: TREE,
        leafIndex: 9n,
      };
      // The unseen input is first, so recovery cannot derive the output by
      // summing known inputs or requiring a known first-nullifier predecessor.
      const merged = mergeTransaction(source, [
        {
          utxo: unseen,
          outputContext: unseenContext,
          nullifier: unseen.nullifier(unseenContext.hash, key),
          spent: false,
        },
        {
          utxo: known,
          outputContext: seedSlot.outputContext,
          nullifier: known.nullifier(seedSlot.outputContext.hash, key),
          spent: false,
        },
      ]);
      const authenticate = vi.fn(async (transaction: IndexedShieldedTransaction) => {
        if (transaction !== seed && transaction !== merged.transaction)
          throw new RingError("RING_ORIGIN_DECODE");
        return transaction;
      });
      const query = vi.fn(async (request: Readonly<{ nullifiers: readonly Bytes32[] }>) =>
        transactionsPage({
          transactions: merged.transaction.nullifiers.some((nullifier) =>
            request.nullifiers.some((requested) => requested.join() === nullifier.join()),
          )
            ? [merged.transaction]
            : [],
        }),
      );
      try {
        const result = await recoverRingMemberNotes({
          client: {
            ...ringAuditReader({
              getShieldedTransactionsByTags: async (request) =>
                transactionsPage({
                  transactions: request.ringProgramId === undefined ? [seed] : [],
                }),
            }),
            getShieldedTransactionsByNullifiers: query,
          },
          ringProgramId: RING,
          auditor,
          source: source.address,
          nullifierKey: key,
          assets: new AssetRegistry(),
          resolveTreeId: () => 0,
          origin: { ringInvoked: async () => true, confirmedTransaction: authenticate },
        });
        expect(result.unopened).toEqual([]);
        expect(result.unsupportedDeposits).toEqual([]);
        expect(result.notes).toHaveLength(1);
        expect(result.notes[0]?.utxo.amount).toBe(42n);
        expect(result.notes[0]?.outputContext).toEqual(merged.note.outputContext);
        expect(result.notes[0]?.nullifier).toEqual(merged.note.nullifier);
        expect(authenticate).toHaveBeenCalledWith(merged.transaction, RING, undefined);
        expect(query.mock.calls.flatMap(([request]) => request.nullifiers)).toContainEqual(
          merged.note.nullifier,
        );
      } finally {
        key.destroy();
        auditor.destroy();
      }
    },
  );

  it("authenticates spend responses before hiding a recovered note", async () => {
    const source = actor(3);
    const auditor = X25519Secret.generate();
    const key = source.keypair.nullifierKey();
    const seed = ringTransaction({
      auditor,
      source,
      outputs: [{ amount: 7n }],
    });
    const authenticate = vi.fn(async (transaction: IndexedShieldedTransaction) => {
      if (transaction !== seed) throw new RingError("RING_ORIGIN_DECODE");
      return transaction;
    });
    const spendQuery = vi.fn(async (request: { nullifiers: readonly Bytes32[] }) =>
      transactionsPage({
        transactions: [{ ...seed, nullifiers: [...request.nullifiers] }],
      }),
    );
    try {
      await expect(
        recoverRingMemberNotes({
          client: {
            ...ringAuditReader({
              getShieldedTransactionsByTags: async (request) =>
                transactionsPage({
                  transactions: request.ringProgramId === undefined ? [seed] : [],
                }),
            }),
            getShieldedTransactionsByNullifiers: spendQuery,
          },
          ringProgramId: RING,
          auditor,
          source: source.address,
          nullifierKey: key,
          assets: new AssetRegistry(),
          resolveTreeId: () => 0,
          origin: {
            ringInvoked: async () => true,
            confirmedTransaction: authenticate,
          },
        }),
      ).rejects.toMatchObject({ code: "RING_ORIGIN_DECODE" });
      expect(spendQuery).toHaveBeenCalledOnce();
      expect(authenticate).toHaveBeenCalledTimes(2);
      expect(authenticate.mock.calls[1]?.[0].nullifiers).toEqual(
        spendQuery.mock.calls[0]?.[0].nullifiers,
      );
    } finally {
      key.destroy();
      auditor.destroy();
    }
  });

  it("recovers proved data hashes without trusting recipient metadata", async () => {
    const source = actor(3);
    const auditor = X25519Secret.generate();
    const key = source.keypair.nullifierKey();
    const dataHash = blinding(4);
    const ringDataHash = blinding(5);
    const data = new Data([
      { kind: "ringData", bytes: new Uint8Array([1]) },
      { kind: "utxoData", bytes: new Uint8Array([2]) },
    ]);
    const seed = ringTransaction({
      auditor,
      source,
      outputs: [{ amount: 7n, data, dataHash, ringDataHash }],
    });
    const client = {
      ...ringAuditReader({
        getShieldedTransactionsByTags: async () => transactionsPage({ transactions: [seed] }),
      }),
      getShieldedTransactionsByNullifiers: async () => transactionsPage(),
    };
    const input = {
      client,
      ringProgramId: RING,
      auditor,
      source: source.address,
      nullifierKey: key,
      assets: new AssetRegistry(),
      resolveTreeId: () => 0,
      origin: {
        ringInvoked: async () => true,
        confirmedTransaction: async (transaction: IndexedShieldedTransaction) => transaction,
      },
    };
    const disclosed = await recoverRingMemberNotes(input);
    expect(disclosed.notes[0]).toMatchObject({ dataHash, ringDataHash });
    expect(disclosed.notes[0]?.utxo.data.records()).toEqual([]);
    expect(disclosed.unopened).toEqual([]);
    const spent = await recoverRingMemberNotes({
      ...input,
      client: {
        ...client,
        getShieldedTransactionsByNullifiers: async (request) =>
          transactionsPage({
            transactions: [
              {
                ...seed,
                outputSlots: [],
                messages: [],
                nullifiers: [...request.nullifiers],
              },
            ],
          }),
      },
    });
    expect(spent.notes).toEqual([]);
    expect(spent.unopened).toEqual([]);
    key.destroy();
    auditor.destroy();
  });

  it(
    "bounds each nullifier request while scanning more than a thousand historical notes",
    { timeout: 120_000 },
    async () => {
      const source = actor(3);
      const auditor = X25519Secret.generate();
      const key = source.keypair.nullifierKey();
      const seeds = Array.from({ length: 251 }, (_, batch) =>
        ringTransaction({
          auditor,
          source,
          outputs: Array.from({ length: 4 }, (_, index) => ({
            amount: BigInt(batch * 4 + index + 1),
          })),
        }),
      );
      const sizes: number[] = [];
      const client = {
        ...ringAuditReader({
          getShieldedTransactionsByTags: async () => transactionsPage({ transactions: seeds }),
        }),
        getShieldedTransactionsByNullifiers: async (
          request: Readonly<{ nullifiers: readonly Bytes32[] }>,
        ) => {
          sizes.push(request.nullifiers.length);
          if (request.nullifiers.length > 1000) throw new Error("Photon request limit");
          return transactionsPage();
        },
      };
      const result = await recoverRingMemberNotes({
        client,
        ringProgramId: RING,
        auditor,
        source: source.address,
        nullifierKey: key,
        assets: new AssetRegistry(),
        resolveTreeId: () => 0,
        origin: {
          ringInvoked: async () => true,
          confirmedTransaction: async (transaction: IndexedShieldedTransaction) => transaction,
        },
      });
      expect(result.notes).toHaveLength(1004);
      expect(sizes).toEqual([1000, 4]);
      key.destroy();
      auditor.destroy();
    },
  );
});

describe("recovered delegate move", () => {
  it.each([false, true])(
    "builds a recovered delegate move with compact padding %s",
    async (compactPadding) => {
      const auditor = X25519Secret.generate();
      const source = actor(3);
      const delegate = getAddressDecoder().decode(filled(8));
      const [config, configBump] = await ringConfigPda(RING);
      const [delegatePda, delegateBump] = await ringDelegatePda(RING);
      const [policyPda, policyBump] = await policyConfigPda(RING);
      const [registryPda, registryBump] = await ringMemberRegistryRootPda(RING);
      const namespace = await ringPolicyNamespaceAddress(RING);
      const table = buildRuleTable({ rules: [] });
      const registry = oneMemberRegistry({
        member: memberOfTag(source.address.confidentialViewTag()),
        nullifierKey: source.keypair.nullifierKey(),
        auditor: auditor.publicKey(),
      });
      const notes = [0, 1].map((index): WalletUtxo => {
        const utxo = new Utxo({
          owner: source.keypair.signingPublicKey(),
          asset: SOL_MINT,
          amount: 6n,
          blinding: blinding(60 + index),
          ringProgramId: RING,
        });
        const hash = utxo.hash(source.address.nullifierPublicKey, 0);
        return {
          utxo,
          outputContext: { hash, tree: TREE, leafIndex: BigInt(index) },
          nullifier: utxo.nullifier(hash, source.keypair.nullifierKey()),
          spent: false,
        };
      });
      let policy: CustomRingPolicyProofRequest | undefined;
      let owners: readonly string[] = [];
      const transaction = await buildRingDelegateRecoveredTransaction({
        client: {
          proofDataSource: "client",
          tree: TREE,
          treeId: 0,
          commitment: "confirmed",
          proofService: {
            prove: () => Promise.reject(new Error("the fake authority rail proves inline")),
            proveMerge: () => Promise.reject(new Error("no merge in a delegate move")),
          },
          solanaRpc: {
            getProgramAccounts: () => ({ send: async () => [] }),
          } as never,
          getLatestBlockhash: async () => BLOCKHASH,
          getAccount: async (key: Address) => {
            if (key === config)
              return ownedAccount(
                RING,
                ringProgramConfigData({
                  authority: delegate,
                  auditorPublicKey: auditor.publicKey().toBytes(),
                  bump: configBump,
                  hasPolicy: true,
                  keyEscrow: true,
                }),
              );
            if (key === policyPda)
              return ownedAccount(
                RING,
                ringPolicyConfigData({
                  table,
                  sources: ownSources(table, namespace),
                  addressTree: TREE,
                  bump: policyBump,
                  namespaceOwnerHash: ringNamespaceOwnerHash(namespace),
                }),
              );
            if (key === registryPda)
              return ownedAccount(
                RING,
                memberRegistryRootData({
                  root: registry.root,
                  nextIndex: 2n,
                  bump: registryBump,
                  cursor: 1,
                  history: [MEMBER_REGISTRY_EMPTY_ROOT],
                }),
              );
            if (key === delegatePda)
              return ownedAccount(RING, Uint8Array.of(6, ...addressBytes(delegate), delegateBump));
            if (key === TREE)
              return ownedAccount(
                SHIELDED_POOL_PROGRAM_ID,
                treeAccount({ stateCursor: 7, written: 8, nullifierCursor: 4n }),
              );
            return undefined;
          },
          getRingMemberRecord: async () => registry.entry,
          proveRingAuthorityTransact: async (inputs) => {
            owners = inputs.inputUtxos
              .filter((input) => !input.isDummy())
              .map((input) => input.utxo.owner.toBytes().join(","));
            return {
              data: prepareTransfer(inputs, { kind: "ringAuthority", ring: RING })
                .finish([
                  {
                    treeId: 0,
                    slot: {
                      id: 0,
                      utxoRoot: blinding(92),
                      nullifierRoot: blinding(93),
                    },
                    utxoRootIndex: 4,
                    nullifierRootIndex: 3,
                  },
                ])
                .withProof({
                  a: filled(0) as Bytes32,
                  b: new Uint8Array(128) as Bytes128,
                  c: filled(0) as Bytes32,
                }),
              roots: {
                stateRoot: blinding(92),
                stateRootIndex: 4,
                nullifierRoot: blinding(93),
                nullifierRootIndex: 3,
              },
            };
          },
          proveCustomRingDelegatePolicy: async (request) => {
            policy = request;
            return new Uint8Array(192);
          },
          proveCustomRingBase: async () => {
            throw new Error("a delegate move proves the policy");
          },
        },
        ringProgramId: RING,
        source: source.address,
        nullifierKey: source.keypair.nullifierKey(),
        notes,
        compactPadding,
        delegate,
        feePayer: delegate,
        outputs: [4n, 5n].map((amount) => ({ recipient: source.address, asset: SOL_MINT, amount })),
      });
      expect(Object.keys(transaction.signatures)).toEqual([delegate]);
      expect(owners).toEqual(Array(2).fill(source.keypair.signingPublicKey().toBytes().join(",")));
      expect(policy?.twoByThree).toBe(compactPadding);
      expect(policy?.nIn).toBe(compactPadding ? 2 : 4);
      expect(policy?.nOut).toBe(compactPadding ? 3 : 4);
      const compiled = getCompiledTransactionMessageDecoder().decode(transaction.messageBytes);
      if (compiled.version !== 1) throw new Error("expected V1");
      const instruction = decompileTransactionMessage(compiled, {
        lastValidBlockHeight: 1n,
      }).instructions.find((instruction) => instruction.programAddress === RING);
      expect(instruction?.data?.[0]).toBe(compactPadding ? 34 : 38);
      expect(policy?.auditorPublicKey).toEqual(auditor.publicKey().u());
      expect(policy?.memberRegistryRoot).toEqual(registry.root);
      expect(policy?.treeSlots).toHaveLength(1);
      expect(
        policy?.outputs.filter((output) => output.ctHash?.some((byte) => byte !== 0)),
      ).toHaveLength(3);
      expect(policy?.subjects?.find((subject) => subject?.present)).toMatchObject({
        next: registry.entry.record!.next,
        index: 1n,
        path: registry.entry.path,
      });
    },
  );
});
