import {
  address,
  getAddressDecoder,
  signTransactionWithSigners,
  type Address,
  type Signature,
} from "@solana/kit";
import { beforeAll, describe, expect, it, vi } from "vitest";

import { ClientError } from "../src/client/error.js";
import type { RingKeyRegistryEntry } from "../src/client/ports.js";
import type {
  CustomRingRegisterKeyProofRequest,
  CustomRingBaseProofRequest,
} from "../src/client/prover/types.js";
import { initializePoseidon } from "../src/hasher/index.js";
import { Writer, addressBytes } from "../src/interface/internal.js";
import {
  ringConfigPda,
  ringDelegatePda,
  ringKeyRegistryRootPda,
  treeAddress,
} from "../src/interface/pda/index.js";
import { SHIELDED_POOL_PROGRAM_ID } from "../src/interface/program.js";
import type {
  Bytes16,
  Bytes31,
  Bytes32,
  Bytes33,
  Bytes128,
  TransactInstructionData,
} from "../src/interface/types.js";
import { auditorMessageData, encryptTransactionViewingSecret } from "../src/keypair/audit.js";
import { NullifierKey } from "../src/keypair/nullifier-key.js";
import { ShieldedKeypair } from "../src/keypair/shielded.js";
import { SigningKey } from "../src/keypair/signing-key.js";
import { ViewingKey } from "../src/keypair/viewing-key.js";
import { AssetRegistry, SOL_ASSET_ID, SOL_MINT } from "../src/transaction/asset.js";
import { Data } from "../src/transaction/data.js";
import type { IndexedShieldedTransaction } from "../src/transaction/instructions/transact.js";
import {
  EncryptedScheme,
  encodeOutputData,
  encryptConfidential,
} from "../src/transaction/serialization/codecs.js";
import { Utxo } from "../src/transaction/utxo.js";
import { KeypairWalletAuthority } from "../src/transaction/wallet/authority.js";
import type { WalletUtxo } from "../src/transaction/wallet/state.js";
import { decodeRingKeyRegistryRoot } from "../src/ring/codecs.js";
import { fetchRingKeyRegistryRoot } from "../src/ring/config.js";
import { buildRingDelegateRecoveredTransaction } from "../src/ring/delegate.js";
import {
  HEAD_MAP_EMPTY_ROOT,
  HEAD_MAP_FIELD_MAX,
  headMapLeaf,
  headMapZeroBytes,
  verifyHeadMapInsert,
} from "../src/ring/head-map.js";
import { registerRingKeyInstruction } from "../src/ring/instructions.js";
import {
  buildRingKeyRegistrationTransaction,
  createRingKeyRegistrationSubmission,
  fetchRingSealedKey,
  openNullifierKey,
  openRingSealedKey,
  prepareRingKeyRegistration,
  registeredKeyCommitment,
  registerKeyPublicInputHash,
  sealNullifierKey,
  sealNullifierKeyWith,
  type RingKeyRegistrationClient,
} from "../src/ring/key-registry.js";
import { memberOfTag } from "../src/ring/policy.js";
import { recoverRingMemberNotes } from "../src/ring/recover.js";
import { BLOCKHASH, ringAuditReader, transactionsPage } from "./helpers/clients.js";
import { ownedAccount, ringProgramConfigData } from "./helpers/ring-accounts.js";
import { treeAccount } from "./helpers/tree-account.js";

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
const EPH_PK = hex("0268737cf1d852483220d399b5321261d5e9e90d8214dc62b4f7e4d0fee955c5d5");
const CIPHERTEXT = hex("f329a32e36717753ba70f955e2102b53fa3a1bfd7389ebda109030ea70602d40");
const GENESIS = hex("095939aeb6e0dc92dd4455bab6058c5c5f639b52a610932c22e517fc87d64a94");
const REGISTRY_NEW_ROOT = hex("01c9026ae3349a610ca0d39793c06c924e3ad8e2dcacb64c120c800185372618");
const PUBLIC_INPUT_HASH = hex("2f3163cf5ea64c46bcf1a4b97b0aabccc674aa6056daa42cb63007bb1d9534a9");

const RING = address("9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh");
const TREE = treeAddress(0);

beforeAll(initializePoseidon);

/** The sentinel-only registry and the insertion of `member` at slot 1. */
function firstInsertion(member: Bytes32) {
  const zeros = headMapZeroBytes();
  return {
    lowMember: filled(0) as Bytes32,
    lowNext: HEAD_MAP_FIELD_MAX,
    lowCtCommitment: filled(0) as Bytes32,
    lowIndex: 0n,
    lowProof: zeros.slice(0, 40),
    newProof: [
      headMapLeaf({ member: filled(0) as Bytes32, next: member, nullifier: filled(0) as Bytes32 }),
      ...zeros.slice(1, 40),
    ],
  };
}

function registryRootData(root: Bytes32, nextIndex: bigint, bump: number): Uint8Array {
  return new Writer()
    .u8(9, "discriminator")
    .bytes(root)
    .u64(nextIndex, "nextIndex")
    .u8(bump, "bump")
    .finish();
}

function actor(seed: number) {
  const keypair = ShieldedKeypair.fromKeypair(SigningKey.fromEd25519Bytes(filled(seed) as Bytes32));
  const address = keypair.shieldedAddress();
  return {
    keypair,
    address,
    authority: new KeypairWalletAuthority({ solanaPublicKey: address.solanaAddress(), keypair }),
  };
}

describe("nullifier key envelope", () => {
  it("matches the Rust vector and opens only for the auditor", () => {
    const auditor = ViewingKey.fromBytes(AUDITOR_SK);
    const ephemeral = ViewingKey.fromBytes(EPHEMERAL_SK);
    const nullifierKey = NullifierKey.fromSecret(NULLIFIER_SECRET);
    const envelope = sealNullifierKeyWith(ephemeral, nullifierKey, auditor.publicKey());
    expect(envelope.nullifierPublicKey).toEqual(NULLIFIER_PK);
    expect(envelope.sealed.ephemeralPublicKey.toBytes()).toEqual(EPH_PK);
    expect(envelope.sealed.ciphertext).toEqual(CIPHERTEXT);
    expect(envelope.ephemeralSecret).toEqual(EPHEMERAL_SK);
    const opened = openNullifierKey(envelope.sealed, auditor);
    expect(opened.secretBytes()).toEqual(NULLIFIER_SECRET);
    const stranger = ViewingKey.fromBytes(EPHEMERAL_SK);
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

  it("hashes the genesis leaf, the registry root and the statement like Rust", () => {
    const auditor = ViewingKey.fromBytes(AUDITOR_SK);
    const member = memberOfTag(MEMBER_TAG);
    const genesis = registeredKeyCommitment({
      nullifierPublicKey: NULLIFIER_PK as Bytes32,
      ciphertext: CIPHERTEXT as Bytes32,
    });
    expect(genesis).toEqual(GENESIS);
    const insertion = firstInsertion(member);
    const registryNewRoot = verifyHeadMapInsert({
      root: HEAD_MAP_EMPTY_ROOT,
      appendIndex: 1n,
      member,
      genesis,
      lowMember: insertion.lowMember,
      lowNext: insertion.lowNext,
      lowNullifier: insertion.lowCtCommitment,
      lowIndex: insertion.lowIndex,
      lowProof: insertion.lowProof,
      newProof: insertion.newProof,
    });
    expect(registryNewRoot).toEqual(REGISTRY_NEW_ROOT);
    expect(
      registerKeyPublicInputHash({
        registryOldRoot: HEAD_MAP_EMPTY_ROOT,
        registryNewRoot,
        member,
        nullifierPublicKey: NULLIFIER_PK as Bytes32,
        auditorPublicKey: auditor.publicKey(),
        ephemeralPublicKey: ViewingKey.fromBytes(EPHEMERAL_SK).publicKey(),
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
      registryOldRoot: HEAD_MAP_EMPTY_ROOT,
      registryNewRoot: filled(0x11) as Bytes32,
      registryNextIndex: 1n,
      nullifierPublicKey: filled(0x12) as Bytes32,
      ephemeralPublicKey: filled(0x02, 33) as Bytes33,
      ciphertext: filled(0x44) as Bytes32,
    });
    expect(instruction.data).toEqual(
      Uint8Array.from([
        30,
        ...hex(
          "0101010101010101010101010101010101010101010101010101010101010101" +
            "0202020202020202020202020202020202020202020202020202020202020202" +
            "0202020202020202020202020202020202020202020202020202020202020202" +
            "0303030303030303030303030303030303030303030303030303030303030303" +
            "0404040404040404040404040404040404040404040404040404040404040404" +
            "0505050505050505050505050505050505050505050505050505050505050505" +
            "03a753cd12b351201070a629c59b9a162c53a1fd33a138cbd6be814bfcfe980e" +
            "1111111111111111111111111111111111111111111111111111111111111111" +
            "0100000000000000" +
            "1212121212121212121212121212121212121212121212121212121212121212" +
            "020202020202020202020202020202020202020202020202020202020202020202" +
            "4444444444444444444444444444444444444444444444444444444444444444",
        ),
      ]),
    );
    expect(instruction.data?.length).toBe(362);
    expect(instruction.accounts?.map((account) => account.address)).toEqual([
      member,
      (await ringConfigPda(RING))[0],
      (await ringKeyRegistryRootPda(RING))[0],
    ]);
  });
});

describe("key registry root", () => {
  it("decodes the 42-byte account and refuses another discriminator", async () => {
    const [rootAddress, bump] = await ringKeyRegistryRootPda(RING);
    const data = registryRootData(HEAD_MAP_EMPTY_ROOT, 1n, bump);
    expect(decodeRingKeyRegistryRoot(data)).toEqual({
      root: HEAD_MAP_EMPTY_ROOT,
      nextIndex: 1n,
      bump,
    });
    expect(() =>
      decodeRingKeyRegistryRoot(registryRootData(HEAD_MAP_EMPTY_ROOT, 0n, bump)),
    ).toThrow("RING_KEY_REGISTRY_INVALID");
    const headMap = new Uint8Array(data);
    headMap[0] = 8;
    expect(() => decodeRingKeyRegistryRoot(headMap)).toThrow("RING_KEY_REGISTRY_INVALID");
    await expect(
      fetchRingKeyRegistryRoot({ getAccount: async () => undefined }, RING),
    ).rejects.toMatchObject({ code: "RING_KEY_REGISTRY_MISSING" });
    await expect(
      fetchRingKeyRegistryRoot(
        {
          getAccount: async (key) =>
            key === rootAddress
              ? ownedAccount(RING, registryRootData(HEAD_MAP_EMPTY_ROOT, 1n, bump ^ 1))
              : undefined,
        },
        RING,
      ),
    ).rejects.toMatchObject({ code: "RING_KEY_REGISTRY_INVALID" });
  });
});

async function registrationFixture(input: Readonly<{ registered?: boolean }> = {}) {
  const auditor = ViewingKey.fromBytes(AUDITOR_SK);
  const member = actor(3);
  const identity = memberOfTag(member.address.confidentialViewTag());
  const [config, configBump] = await ringConfigPda(RING);
  const [rootAddress, rootBump] = await ringKeyRegistryRootPda(RING);
  const insertion = firstInsertion(identity);
  const envelope = sealNullifierKey(member.keypair.nullifierKey(), auditor.publicKey());
  const genesis = registeredKeyCommitment({
    nullifierPublicKey: envelope.nullifierPublicKey,
    ciphertext: envelope.sealed.ciphertext,
  });
  const registeredRoot = verifyHeadMapInsert({
    root: HEAD_MAP_EMPTY_ROOT,
    appendIndex: 1n,
    member: identity,
    genesis,
    lowMember: insertion.lowMember,
    lowNext: insertion.lowNext,
    lowNullifier: insertion.lowCtCommitment,
    lowIndex: insertion.lowIndex,
    lowProof: insertion.lowProof,
    newProof: insertion.newProof,
  });
  const root = input.registered
    ? { root: registeredRoot, nextIndex: 2n }
    : { root: HEAD_MAP_EMPTY_ROOT, nextIndex: 1n };
  const entry: RingKeyRegistryEntry = {
    context: { slot: 1n, blockTime: 1n },
    root: registeredRoot,
    nextIndex: 2n,
    member: identity,
    next: HEAD_MAP_FIELD_MAX,
    index: 1n,
    ephemeralPublicKey: envelope.sealed.ephemeralPublicKey,
    ciphertext: envelope.sealed.ciphertext,
    proof: insertion.newProof,
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
        return ownedAccount(RING, registryRootData(root.root, root.nextIndex, rootBump));
      return undefined;
    },
    getLatestBlockhash: async () => BLOCKHASH,
    getRingKeyRegistryRegisterProof: async () => ({
      context: { slot: 1n, blockTime: 1n },
      root: HEAD_MAP_EMPTY_ROOT,
      nextIndex: 1n,
      member: identity,
      ...insertion,
    }),
    getRingKeyRegistryEntry: async () => {
      if (input.registered) return entry;
      throw new ClientError("CLIENT_KEY_REGISTRY_MEMBER_UNREGISTERED", {
        details: { method: "getRingKeyRegistryEntry" },
      });
    },
    proveCustomRingRegisterKey: prove,
  };
  return { auditor, member, identity, client, prove, request: () => request, envelope, entry };
}

describe("key registration flow", () => {
  it("seals the lent key, proves the append and pays as the member", async () => {
    const test = await registrationFixture();
    const preparation = await prepareRingKeyRegistration({
      client: test.client,
      ringProgramId: RING,
      authority: test.member.authority,
    });
    expect(preparation.kind).toBe("pending");
    expect(test.prove).toHaveBeenCalledTimes(1);
    const request = test.request();
    if (request === undefined) throw new Error("registration proof missing");
    expect(request.member).toEqual(test.identity);
    expect(request.newIndex).toBe(1n);
    expect(request.nullifierSecret[0]).toBe(0);
    expect(request.nullifierSecret.subarray(1)).toEqual(
      test.member.keypair.nullifierKey().secretBytes(),
    );
    expect(request.auditorPublicKey).toEqual(test.auditor.publicKey().toUncompressed());
    // The ephemeral scalar the prover witnesses reproduces the sealed envelope.
    const envelope = sealNullifierKeyWith(
      ViewingKey.fromBytes(request.ephemeralSecret),
      test.member.keypair.nullifierKey(),
      test.auditor.publicKey(),
    );
    const insertion = firstInsertion(test.identity);
    const registryNewRoot = verifyHeadMapInsert({
      root: HEAD_MAP_EMPTY_ROOT,
      appendIndex: 1n,
      member: test.identity,
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
    expect(request.headNewRoot).toEqual(registryNewRoot);
    expect(request.publicInputHash).toEqual(
      registerKeyPublicInputHash({
        registryOldRoot: HEAD_MAP_EMPTY_ROOT,
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
      authority: test.member.authority,
    });
    expect(Object.keys(transaction.signatures)).toEqual([test.member.address.solanaAddress()]);
  });

  it("rebuilds after a stale registry root failure and never while the send is unknown", async () => {
    const test = await registrationFixture();
    const submission = await createRingKeyRegistrationSubmission({
      client: test.client,
      ringProgramId: RING,
      authority: test.member.authority,
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
          ? { kind: "failed", instructionIndex: 0, customCode: 8169 }
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
          getRingKeyRegistryRegisterProof: async () => ({
            ...(await test.client.getRingKeyRegistryRegisterProof({
              ringProgramId: RING,
              member: test.identity,
              expectedRoot: HEAD_MAP_EMPTY_ROOT,
              expectedNextIndex: 1n,
            })),
            nextIndex: 2n,
          }),
        },
        ringProgramId: RING,
        authority: test.member.authority,
      }),
    ).rejects.toMatchObject({ code: "RING_KEY_REGISTRY_STALE" });
    expect(test.prove).not.toHaveBeenCalled();
    await expect(
      prepareRingKeyRegistration({
        client: {
          ...test.client,
          getRingKeyRegistryEntry: async () => {
            throw new ClientError("CLIENT_KEY_REGISTRY_OUT_OF_SYNC", {
              details: { method: "getRingKeyRegistryEntry" },
            });
          },
        },
        ringProgramId: RING,
        authority: test.member.authority,
      }),
    ).rejects.toMatchObject({ code: "CLIENT_KEY_REGISTRY_OUT_OF_SYNC" });
  });

  it("refuses a lent nullifier key that does not derive the address", async () => {
    const test = await registrationFixture();
    const other = actor(4);
    await expect(
      prepareRingKeyRegistration({
        client: test.client,
        ringProgramId: RING,
        authority: {
          withSyncSession: (run) =>
            run({
              syncMaterial: async () => ({
                identity: test.member.address,
                viewingKeys: [],
                nullifierKey: other.keypair.nullifierKey(),
              }),
            }),
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
      authority: test.member.authority,
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
    expect(() => openRingSealedKey(entry, ViewingKey.fromBytes(EPHEMERAL_SK))).toThrow();
    const forged = { ...entry, proof: [filled(1) as Bytes32, ...entry.proof.slice(1)] };
    expect(() => openRingSealedKey(forged, test.auditor)).toThrow("RING_KEY_REGISTRY_INVALID");
    await expect(
      fetchRingSealedKey({
        client: {
          ...test.client,
          getRingKeyRegistryEntry: async () => ({ ...test.entry, nextIndex: 3n }),
        },
        ringProgramId: RING,
        member: test.identity,
      }),
    ).rejects.toMatchObject({ code: "RING_KEY_REGISTRY_STALE" });
  });
});

/** One ring transaction paying `outputs` to `source`, encrypted the way a sender does. */
function ringTransaction(
  input: Readonly<{
    auditor: ViewingKey;
    source: ReturnType<typeof actor>;
    outputs: readonly Readonly<{
      amount: bigint;
      hash?: Bytes32;
      recipient?: ReturnType<typeof actor>;
    }>[];
    nullifiers?: readonly Bytes32[];
  }>,
): IndexedShieldedTransaction {
  const tx = ViewingKey.generate();
  const salt = filled(0, 16) as Bytes16;
  const encrypted = encryptTransactionViewingSecret(tx.secretBytes(), input.auditor.publicKey());
  return {
    slot: 1n,
    txSignature: "1".repeat(87) as Signature,
    txViewingPublicKey: tx.publicKey(),
    salt,
    outputSlots: input.outputs.map((output, index) => {
      const recipient = output.recipient ?? input.source;
      const utxo = new Utxo({
        owner: recipient.keypair.signingPublicKey(),
        asset: SOL_MINT,
        amount: output.amount,
        blinding: blinding(50 + index),
        ringProgramId: RING,
      });
      return {
        viewTag: recipient.address.confidentialViewTag(),
        outputContext: {
          hash: output.hash ?? utxo.hash(recipient.address.nullifierPublicKey, 0),
          tree: TREE,
          leafIndex: BigInt(index),
        },
        payload: encodeOutputData(
          EncryptedScheme.ringConfidential,
          encryptConfidential(
            tx,
            recipient.address.viewingPublicKey,
            {
              assetId: SOL_ASSET_ID,
              amount: output.amount,
              blinding: blinding(50 + index),
              data: new Data(),
              ringProgramId: RING,
            },
            salt,
            index,
          ),
          "encrypted",
        ),
      };
    }),
    messages: [auditorMessageData(encrypted.message, input.auditor.publicKey())],
    nullifiers: [...(input.nullifiers ?? [])],
    proofless: false,
  };
}

describe("ring member recovery", () => {
  it("rebuilds the member's unspent notes from the auditor's view", async () => {
    const auditor = ViewingKey.generate();
    const source = actor(3);
    const other = actor(4);
    const transaction = ringTransaction({
      auditor,
      source,
      outputs: [
        { amount: 7n },
        { amount: 5n },
        { amount: 9n, hash: filled(1) as Bytes32 },
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
      origin: { ringInvoked: async () => true },
    });
    expect(recovered.notes.map((note) => note.utxo.amount)).toEqual([7n]);
    expect(recovered.notes[0]?.outputContext).toEqual(transaction.outputSlots[0]?.outputContext);
    expect(recovered.unopened).toEqual([filled(1)]);
    expect(byNullifiers.mock.calls[0]?.[0]?.nullifiers).toHaveLength(2);
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
            transactionsPage({ transactions: [transaction], nextCursor: new Uint8Array(1) }),
        },
        ringProgramId: RING,
        auditor,
        source: source.address,
        nullifierKey,
        assets: new AssetRegistry(),
        resolveTreeId: () => 0,
        origin: { ringInvoked: async () => true },
        maxPages: 1,
      }),
    ).rejects.toMatchObject({ code: "RING_RECOVERY_INCOMPLETE" });
  });
});

describe("recovered delegate move", () => {
  it("spends recovered notes with the opened key, no wallet and no approval", async () => {
    const auditor = ViewingKey.generate();
    const source = actor(3);
    const recipient = actor(4);
    const delegate = getAddressDecoder().decode(filled(8));
    const [config, configBump] = await ringConfigPda(RING);
    const [delegatePda, delegateBump] = await ringDelegatePda(RING);
    const utxo = new Utxo({
      owner: source.keypair.signingPublicKey(),
      asset: SOL_MINT,
      amount: 10n,
      blinding: blinding(60),
      ringProgramId: RING,
    });
    const hash = utxo.hash(source.address.nullifierPublicKey, 0);
    const note: WalletUtxo = {
      utxo,
      outputContext: { hash, tree: TREE, leafIndex: 0n },
      nullifier: utxo.nullifier(hash, source.keypair.nullifierKey()),
      spent: false,
    };
    let audit: CustomRingBaseProofRequest | undefined;
    let owners: readonly string[] = [];
    const data: TransactInstructionData = {
      expiryUnixTs: 0n,
      privateTxHash: filled(0) as Bytes32,
      circuit: { kind: "ringAuthority", inputs: 2, outputs: 2, publicAssetSlots: 3 },
      txViewingPk: new Uint8Array(33) as Bytes33,
      salt: new Uint8Array(16) as Bytes16,
      proof: {
        a: new Uint8Array(32) as Bytes32,
        b: new Uint8Array(128) as Bytes128,
        c: new Uint8Array(32) as Bytes32,
      },
      inputs: [],
      treeContexts: [{ utxoTreeRootIndex: 0, nullifierTreeRootIndex: 0 }],
      interfaceTransfers: [],
      outputs: [],
      messages: [],
    };
    const transaction = await buildRingDelegateRecoveredTransaction({
      client: {
        tree: TREE,
        treeId: 0,
        commitment: "confirmed",
        solanaRpc: { getProgramAccounts: () => ({ send: async () => [] }) } as never,
        getLatestBlockhash: async () => BLOCKHASH,
        getAccount: async (key: Address) => {
          if (key === config)
            return ownedAccount(
              RING,
              ringProgramConfigData({
                authority: delegate,
                auditorPublicKey: auditor.publicKey().toBytes(),
                bump: configBump,
                hasPolicy: false,
              }),
            );
          if (key === delegatePda)
            return ownedAccount(RING, Uint8Array.of(6, ...addressBytes(delegate), delegateBump));
          if (key === TREE)
            return ownedAccount(
              SHIELDED_POOL_PROGRAM_ID,
              treeAccount({ stateCursor: 7, written: 8, nullifierCursor: 9n }),
            );
          return undefined;
        },
        getMerkleProofs: async () => {
          throw new Error("no policy");
        },
        getNonInclusionProofs: async () => {
          throw new Error("no policy");
        },
        getEncryptedUtxosByTags: async () => {
          throw new Error("no policy");
        },
        getShieldedTransactionsByNullifiers: async () => {
          throw new Error("no policy");
        },
        proveRingAuthorityTransact: async (inputs) => {
          owners = inputs.inputUtxos
            .filter((input) => !input.isDummy())
            .map((input) => input.utxo.owner.toBytes().join(","));
          return {
            data,
            roots: {
              stateRoot: filled(92) as Bytes32,
              stateRootIndex: 4,
              nullifierRoot: filled(93) as Bytes32,
              nullifierRootIndex: 5,
            },
          };
        },
        proveCustomRingDelegatePolicy: async () => {
          throw new Error("audit-only ring");
        },
        proveCustomRingBase: async (request) => {
          audit = request;
          return new Uint8Array(192);
        },
      },
      ringProgramId: RING,
      source: source.address,
      nullifierKey: source.keypair.nullifierKey(),
      notes: [note],
      delegate,
      feePayer: delegate,
      outputs: [{ recipient: recipient.address, asset: SOL_MINT, amount: 4n }],
    });
    expect(Object.keys(transaction.signatures)).toEqual([delegate]);
    expect(owners).toEqual([source.keypair.signingPublicKey().toBytes().join(",")]);
    expect(audit?.auditorPublicKey).toEqual(auditor.publicKey().toUncompressed());
  });
});
