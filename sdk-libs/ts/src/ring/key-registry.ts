import type {
  BlockhashProvider,
  ChainReader,
  Prover,
  RingKeyRegistryReader,
} from "../client/ports.js";
import { ClientError } from "../client/error.js";
import { compileUnsignedTransaction } from "../flows/compile.js";
import { hashBytes, initializePoseidon } from "../hasher/index.js";
import { addressBytes } from "../interface/internal.js";
import { pack33, rightAlign } from "../interface/merge-utils.js";
import type { Address, Bytes31, Bytes32, RequestContext, Transaction } from "../interface/types.js";
import { auditSharedSecret } from "../keypair/audit.js";
import { symmetricApply } from "../keypair/merge/index.js";
import { NullifierKey } from "../keypair/nullifier-key.js";
import type { P256PublicKey } from "../keypair/public-key.js";
import { ViewingKey } from "../keypair/viewing-key.js";
import { bigIntBytes, hashChain, poseidon } from "../transaction/internal.js";
import type { SyncAuthority, WalletSyncMaterial } from "../transaction/wallet/authority.js";
import { equalBytes } from "../wallet/internal.js";
import { fetchRingKeyRegistryRoot, fetchRingProgramConfig } from "./config.js";
import { RingError } from "./error.js";
import {
  HEAD_MAP_CAPACITY,
  HEAD_MAP_HEIGHT,
  checkedHeadMapField,
  headMapLeaf,
  headMapRootFromProof,
  verifyHeadMapInsert,
} from "./head-map.js";
import {
  RING_REGISTER_KEY_COMPUTE_UNIT_LIMIT,
  registerRingKeyInstruction,
} from "./instructions.js";
import { memberOfTag, type Member } from "./policy.js";
import { RingTransactionSubmission, type RingSubmissionAttempt } from "./submission.js";

/** Rust `NF_KEY_ENC_INFO`, separates the key stream from the audit stream. */
export const NF_KEY_ENC_INFO = new TextEncoder().encode("CRING/nfk1");

/** Carries a nullifier key encrypted to the ring auditor. */
export interface SealedNullifierKey {
  readonly ephemeralPublicKey: P256PublicKey;
  readonly ciphertext: Bytes32;
}

/** Holds the sealed key and temporary encryption proof material. */
export interface NullifierKeyEnvelope {
  readonly ephemeralSecret: Bytes32;
  readonly sealed: SealedNullifierKey;
  readonly nullifierPublicKey: Bytes32;
}

/** Binds key disclosure to a member and a registry root transition. */
export interface RegisterKeyStatement {
  readonly registryOldRoot: Bytes32;
  readonly registryNewRoot: Bytes32;
  readonly member: Member;
  readonly nullifierPublicKey: Bytes32;
  readonly auditorPublicKey: P256PublicKey;
  readonly ephemeralPublicKey: P256PublicKey;
  readonly ciphertext: Bytes32;
  readonly newIndex: bigint;
}

export type RingKeyRegistrationClient = Pick<ChainReader, "getAccount"> &
  RingKeyRegistryReader &
  BlockhashProvider &
  Pick<Prover, "proveCustomRingRegisterKey">;

/** Registers a member's key under that member's Solana signature. */
export interface RingKeyRegistrationParams {
  readonly client: RingKeyRegistrationClient;
  readonly ringProgramId: Address;
  /** Lends the member's address and nullifier key, its Solana key signs and pays. */
  readonly authority: SyncAuthority;
  readonly priorityFeeLamports?: bigint;
}

export type RingKeyRegistrationPreparation =
  | Readonly<{ kind: "registered"; sealed: SealedNullifierKey }>
  | Readonly<{ kind: "pending"; submission: RingTransactionSubmission }>;

export type RingSealedKeyClient = Pick<ChainReader, "getAccount"> &
  Pick<RingKeyRegistryReader, "getRingKeyRegistryEntry">;

/** Requires an opened key or known nullifier public key to verify inclusion. */
export interface RingSealedKeyEntry {
  readonly sealed: SealedNullifierKey;
  readonly member: Member;
  readonly root: Bytes32;
  readonly next: Bytes32;
  readonly index: bigint;
  readonly proof: readonly Bytes32[];
}

/** `(ephemeral, auditor)` fixes the keystream, the ephemeral scalar is never taken from a caller. */
export function sealNullifierKey(
  nullifierKey: NullifierKey,
  auditorPublicKey: P256PublicKey,
): NullifierKeyEnvelope {
  const ephemeral = ViewingKey.generate();
  try {
    return sealNullifierKeyWith(ephemeral, nullifierKey, auditorPublicKey);
  } finally {
    ephemeral.destroy();
  }
}

/** @internal Byte zero of the plaintext is the pad the circuit pins. */
export function sealNullifierKeyWith(
  ephemeral: ViewingKey,
  nullifierKey: NullifierKey,
  auditorPublicKey: P256PublicKey,
): NullifierKeyEnvelope {
  const secret = nullifierKey.secretBytes();
  const plaintext = rightAlign(secret);
  let dh: Bytes32 | undefined;
  let shared: Bytes32 | undefined;
  try {
    const ephemeralPublicKey = ephemeral.publicKey();
    dh = ephemeral.ecdh(auditorPublicKey);
    shared = auditSharedSecret(dh, ephemeralPublicKey, auditorPublicKey);
    const ciphertext = symmetricApply(shared, NF_KEY_ENC_INFO, plaintext) as Bytes32;
    return Object.freeze({
      ephemeralSecret: ephemeral.secretBytes(),
      sealed: Object.freeze({ ephemeralPublicKey, ciphertext }),
      nullifierPublicKey: nullifierKey.publicKey(),
    });
  } finally {
    secret.fill(0);
    plaintext.fill(0);
    dh?.fill(0);
    shared?.fill(0);
  }
}

/** Authenticate decoded keys through registry inclusion. */
export function openNullifierKey(sealed: SealedNullifierKey, auditor: ViewingKey): NullifierKey {
  let dh: Bytes32 | undefined;
  let shared: Bytes32 | undefined;
  let plaintext: Uint8Array | undefined;
  try {
    dh = auditor.ecdh(sealed.ephemeralPublicKey);
    shared = auditSharedSecret(dh, sealed.ephemeralPublicKey, auditor.publicKey());
    plaintext = symmetricApply(shared, NF_KEY_ENC_INFO, sealed.ciphertext);
    if (plaintext[0] !== 0) throw new RingError("RING_KEY_ENVELOPE_INVALID");
    return NullifierKey.fromSecret(plaintext.subarray(1) as Bytes31);
  } finally {
    dh?.fill(0);
    shared?.fill(0);
    plaintext?.fill(0);
  }
}

/** Mirrors Rust `RegisteredKey::commitment`, the member's registry leaf slot. */
export function registeredKeyCommitment(
  key: Readonly<{ nullifierPublicKey: Bytes32; ciphertext: Bytes32 }>,
): Bytes32 {
  return poseidon([
    checkedHeadMapField(key.nullifierPublicKey),
    hashBytes(key.ciphertext) as Bytes32,
  ]);
}

export function registerKeyPublicInputHash(input: RegisterKeyStatement): Bytes32 {
  const [auditorLow, auditorHigh] = pack33(input.auditorPublicKey.toBytes());
  const [ephLow, ephHigh] = pack33(input.ephemeralPublicKey.toBytes());
  return hashChain([
    input.registryOldRoot,
    input.registryNewRoot,
    input.member,
    input.nullifierPublicKey,
    auditorLow,
    auditorHigh,
    ephLow,
    ephHigh,
    hashBytes(input.ciphertext) as Bytes32,
    bigIntBytes(input.newIndex) as Bytes32,
  ]);
}

export async function prepareRingKeyRegistration(
  input: RingKeyRegistrationParams,
  context?: RequestContext,
): Promise<RingKeyRegistrationPreparation> {
  await initializePoseidon();
  const identity = await memberIdentity(input.authority);
  try {
    const entry = await fetchRingSealedKey(
      { client: input.client, ringProgramId: input.ringProgramId, member: identity.member },
      context,
    );
    checkRegisteredKey(entry, identity.nullifierPublicKey);
    return { kind: "registered", sealed: entry.sealed };
  } catch (cause) {
    if (!(cause instanceof ClientError) || cause.code !== "CLIENT_KEY_REGISTRY_MEMBER_UNREGISTERED")
      throw cause;
  }
  return { kind: "pending", submission: await registrationSubmission(input, context) };
}

export async function createRingKeyRegistrationSubmission(
  input: RingKeyRegistrationParams,
  context?: RequestContext,
): Promise<RingTransactionSubmission> {
  await initializePoseidon();
  return registrationSubmission(input, context);
}

export async function buildRingKeyRegistrationTransaction(
  input: RingKeyRegistrationParams,
  context?: RequestContext,
): Promise<Transaction> {
  await initializePoseidon();
  return (await buildRegistrationAttempt(input, context)).transaction;
}

export async function fetchRingSealedKey(
  input: Readonly<{ client: RingSealedKeyClient; ringProgramId: Address; member: Member }>,
  context?: RequestContext,
): Promise<RingSealedKeyEntry> {
  const root = await fetchRingKeyRegistryRoot(input.client, input.ringProgramId, context);
  const entry = await input.client.getRingKeyRegistryEntry(
    {
      ringProgramId: input.ringProgramId,
      member: input.member,
      expectedRoot: root.root,
      expectedNextIndex: root.nextIndex,
    },
    context,
  );
  if (
    !equalBytes(entry.root, root.root) ||
    entry.nextIndex !== root.nextIndex ||
    !equalBytes(entry.member, input.member)
  )
    throw new RingError("RING_KEY_REGISTRY_STALE");
  if (
    entry.index === 0n ||
    entry.index >= entry.nextIndex ||
    entry.proof.length !== HEAD_MAP_HEIGHT
  )
    throw new RingError("RING_KEY_REGISTRY_INVALID", { details: { reason: "entry" } });
  return Object.freeze({
    sealed: Object.freeze({
      ephemeralPublicKey: entry.ephemeralPublicKey,
      ciphertext: entry.ciphertext,
    }),
    member: input.member,
    root: entry.root,
    next: entry.next,
    index: entry.index,
    proof: entry.proof,
  });
}

/** The opened key must reproduce the leaf under the root read from Solana. */
export function openRingSealedKey(entry: RingSealedKeyEntry, auditor: ViewingKey): NullifierKey {
  // 1. Recover nullifier material without granting a Solana signing capability.
  const nullifierKey = openNullifierKey(entry.sealed, auditor);
  try {
    // 2. Authenticate the opened key against the supplied registry root.
    checkRegisteredKey(entry, nullifierKey.publicKey());
  } catch (cause) {
    nullifierKey.destroy();
    throw cause;
  }
  return nullifierKey;
}

/** Connects the registration signer to its shielded nullifier public key. */
interface MemberIdentity {
  readonly payer: Address;
  readonly member: Member;
  readonly nullifierPublicKey: Bytes32;
}

function checkRegisteredKey(entry: RingSealedKeyEntry, nullifierPublicKey: Bytes32): void {
  const leaf = headMapLeaf({
    member: entry.member,
    next: entry.next,
    nullifier: registeredKeyCommitment({ nullifierPublicKey, ciphertext: entry.sealed.ciphertext }),
  });
  if (
    !equalBytes(headMapRootFromProof({ leaf, index: entry.index, proof: entry.proof }), entry.root)
  )
    throw new RingError("RING_KEY_REGISTRY_INVALID", { details: { reason: "inclusion" } });
}

/** The circuit binds a free nullifier key, the address check is the only tie to the member. */
function checkedIdentity(material: WalletSyncMaterial): MemberIdentity {
  const identity = material.identity;
  if (!equalBytes(material.nullifierKey.publicKey(), identity.nullifierPublicKey))
    throw new RingError("RING_NULLIFIER_KEY_MISMATCH");
  return Object.freeze({
    payer: identity.solanaAddress(),
    member: memberOfTag(identity.confidentialViewTag()),
    nullifierPublicKey: identity.nullifierPublicKey,
  });
}

function memberIdentity(authority: SyncAuthority): Promise<MemberIdentity> {
  return authority.withSyncSession(async (session) =>
    checkedIdentity(await session.syncMaterial()),
  );
}

async function registrationSubmission(
  input: RingKeyRegistrationParams,
  context?: RequestContext,
): Promise<RingTransactionSubmission> {
  const held: RingKeyRegistrationParams = Object.freeze({ ...input });
  const identity = await memberIdentity(held.authority);
  const intent = hashChain([
    checkedHeadMapField(hashBytes(addressBytes(held.ringProgramId))),
    identity.member,
    identity.nullifierPublicKey,
  ]);
  const build = async (context?: RequestContext): Promise<RingSubmissionAttempt> => ({
    ...(await buildRegistrationAttempt(held, context)),
    intentHash: intent,
    ringInstructionIndex: 0,
  });
  return new RingTransactionSubmission({
    first: await build(context),
    build,
    windowChanged: async () => false,
  });
}

async function buildRegistrationAttempt(
  input: RingKeyRegistrationParams,
  context?: RequestContext,
): Promise<Pick<RingSubmissionAttempt, "transaction" | "lastValidBlockHeight">> {
  const { client, ringProgramId } = input;
  return input.authority.withSyncSession(async (session) => {
    // 1. Bind registration to the member's identity and configured auditor.
    const material = await session.syncMaterial();
    const { payer, member } = checkedIdentity(material);
    const auditor = (await fetchRingProgramConfig(client, ringProgramId, context)).auditorPublicKey;
    const root = await fetchRingKeyRegistryRoot(client, ringProgramId, context);
    if (root.nextIndex >= HEAD_MAP_CAPACITY)
      throw new RingError("RING_KEY_REGISTRY_INVALID", { details: { reason: "capacity" } });
    const insertion = await client.getRingKeyRegistryRegisterProof(
      { ringProgramId, member, expectedRoot: root.root, expectedNextIndex: root.nextIndex },
      context,
    );
    if (
      !equalBytes(insertion.root, root.root) ||
      !equalBytes(insertion.member, member) ||
      insertion.nextIndex !== root.nextIndex
    )
      throw new RingError("RING_KEY_REGISTRY_STALE");
    // 2. Seal the member's key and authenticate the insertion path.
    const envelope = sealNullifierKey(material.nullifierKey, auditor);
    const secret = material.nullifierKey.secretBytes();
    const nullifierSecret = rightAlign(secret);
    secret.fill(0);
    try {
      const genesis = registeredKeyCommitment({
        nullifierPublicKey: envelope.nullifierPublicKey,
        ciphertext: envelope.sealed.ciphertext,
      });
      const registryNewRoot = verifyHeadMapInsert({
        root: root.root,
        appendIndex: root.nextIndex,
        member,
        genesis,
        lowMember: insertion.lowMember,
        lowNext: insertion.lowNext,
        lowNullifier: insertion.lowCtCommitment,
        lowIndex: insertion.lowIndex,
        lowProof: insertion.lowProof,
        newProof: insertion.newProof,
      });
      const publicInputHash = registerKeyPublicInputHash({
        registryOldRoot: root.root,
        registryNewRoot,
        member,
        nullifierPublicKey: envelope.nullifierPublicKey,
        auditorPublicKey: auditor,
        ephemeralPublicKey: envelope.sealed.ephemeralPublicKey,
        ciphertext: envelope.sealed.ciphertext,
        newIndex: root.nextIndex,
      });
      // 3. Prove key disclosure and registry insertion in one statement.
      const proof = await client.proveCustomRingRegisterKey(
        {
          publicInputHash,
          headOldRoot: root.root,
          headNewRoot: registryNewRoot,
          member,
          newIndex: root.nextIndex,
          nullifierSecret,
          ephemeralSecret: envelope.ephemeralSecret,
          auditorPublicKey: auditor.toUncompressed(),
          lowMember: insertion.lowMember,
          lowNext: insertion.lowNext,
          lowNullifier: insertion.lowCtCommitment,
          lowIndex: insertion.lowIndex,
          lowProof: insertion.lowProof,
          newProof: insertion.newProof,
        },
        context,
      );
      const instruction = await registerRingKeyInstruction({
        ringProgramId,
        member: payer,
        proof,
        registryOldRoot: root.root,
        registryNewRoot,
        registryNextIndex: root.nextIndex,
        nullifierPublicKey: envelope.nullifierPublicKey,
        ephemeralPublicKey: envelope.sealed.ephemeralPublicKey.toBytes(),
        ciphertext: envelope.sealed.ciphertext,
      });
      const lifetime = await client.getLatestBlockhash(context);
      const transaction = compileUnsignedTransaction({
        feePayer: payer,
        lifetime,
        instructions: [instruction],
        computeUnitLimit: RING_REGISTER_KEY_COMPUTE_UNIT_LIMIT,
        ...(input.priorityFeeLamports === undefined
          ? {}
          : { priorityFeeLamports: input.priorityFeeLamports }),
      });
      return { transaction, lastValidBlockHeight: lifetime.lastValidBlockHeight };
    } finally {
      nullifierSecret.fill(0);
      envelope.ephemeralSecret.fill(0);
    }
  });
}
