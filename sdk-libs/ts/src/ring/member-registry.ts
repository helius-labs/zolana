import { X25519PublicKey, X25519Keypair } from "../keypair/x25519.js";
import type {
  BlockhashProvider,
  ChainReader,
  Prover,
  RingMemberRegistryReader,
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
import { bigIntBytes, hashChain, poseidon } from "../transaction/internal.js";
import type { ShieldedAddress } from "../keypair/shielded.js";
import { equalBytes } from "../wallet/internal.js";
import type { RingMemberRegistryRoot } from "./codecs.js";
import { fetchRingMemberRegistryRoot, fetchRingProgramConfig } from "./config.js";
import { RingError } from "./error.js";
import {
  checkedRegistryField,
  memberRegistryLeaf,
  memberRegistryRootFromProof,
  MemberRegistryOverlay,
  updateMemberRecord,
} from "./member-registry-tree.js";
import { readRingMemberRecord } from "./member-record.js";
import {
  RING_REGISTER_KEY_COMPUTE_UNIT_LIMIT,
  registerRingKeyInstruction,
} from "./instructions.js";
import { memberOfTag, type Member } from "./policy.js";
import { waitForProjection } from "../client/retry.js";
import { MEMBER_REGISTRY_PROJECTION_ERRORS } from "./projection.js";
import { RingTransactionSubmission, type RingSubmissionAttempt } from "./submission.js";

/** Rust `NF_KEY_ENC_INFO`, separates the key stream from the audit stream. */
export const NF_KEY_ENC_INFO = new TextEncoder().encode("CRING/nfk1");

import type { RingSealedNullifierKey as SealedNullifierKey } from "../client/ports.js";
export type { RingSealedNullifierKey as SealedNullifierKey } from "../client/ports.js";

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
  readonly auditorPublicKey: X25519PublicKey;
  readonly ephemeralPublicKey: X25519PublicKey;
  readonly ciphertext: Bytes32;
  readonly newIndex: bigint;
}

export type RingKeyRegistrationClient = Pick<ChainReader, "getAccount"> &
  RingMemberRegistryReader &
  BlockhashProvider &
  Pick<Prover, "proveCustomRingRegisterKey">;

/** Registers a member's key under that member's Solana signature. */
export interface RingKeyRegistrationParams {
  readonly client: RingKeyRegistrationClient;
  readonly ringProgramId: Address;
  readonly member: RingKeyRegistrationMember;
  readonly priorityFeeLamports?: bigint;
}

/** The nullifier secret leaves its holder only here, `ShieldedKeys` never releases it. The Solana key of `address` signs and pays. */
export interface RingKeyRegistrationMember {
  readonly address: ShieldedAddress;
  readonly nullifierKey: NullifierKey;
}

export type RingKeyRegistrationPreparation =
  | Readonly<{ kind: "registered"; sealed: SealedNullifierKey }>
  | Readonly<{ kind: "pending"; submission: RingTransactionSubmission }>;

export type RingSealedKeyClient = Pick<ChainReader, "getAccount"> &
  Pick<RingMemberRegistryReader, "getRingMemberRecord">;

/** Requires an opened key or known nullifier public key to verify inclusion. */
export interface RingSealedKeyEntry {
  readonly sealed: SealedNullifierKey;
  readonly member: Member;
  readonly root: Bytes32;
  readonly next: Bytes32;
  readonly lists: bigint;
  readonly escrowKey: Bytes32;
  readonly index: bigint;
  readonly proof: readonly Bytes32[];
}

/** `(ephemeral, auditor)` fixes the keystream, the ephemeral scalar is never taken from a caller. */
export function sealNullifierKey(
  nullifierKey: NullifierKey,
  auditorPublicKey: X25519PublicKey,
): NullifierKeyEnvelope {
  const ephemeral = X25519Keypair.generate();
  try {
    return sealNullifierKeyWith(ephemeral, nullifierKey, auditorPublicKey);
  } finally {
    ephemeral.destroy();
  }
}

/** @internal Byte zero of the plaintext is the pad the circuit pins. */
export function sealNullifierKeyWith(
  ephemeral: X25519Keypair,
  nullifierKey: NullifierKey,
  auditorPublicKey: X25519PublicKey,
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
export function openNullifierKey(sealed: SealedNullifierKey, auditor: X25519Keypair): NullifierKey {
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

/** Mirrors Rust `RegisteredKey::hash`, the member's registry leaf key. */
export function registeredKeyHash(
  key: Readonly<{ nullifierPublicKey: Bytes32; ciphertext: Bytes32 }>,
): Bytes32 {
  return poseidon([
    checkedRegistryField(key.nullifierPublicKey),
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
  const identity = checkedIdentity(input.member);
  try {
    const entry = await fetchRingSealedKey(
      { client: input.client, ringProgramId: input.ringProgramId, member: identity.member },
      context,
    );
    checkRegisteredKey(entry, identity.nullifierPublicKey);
    return { kind: "registered", sealed: entry.sealed };
  } catch (cause) {
    if (
      !(cause instanceof ClientError) ||
      cause.code !== "CLIENT_MEMBER_REGISTRY_MEMBER_UNREGISTERED"
    )
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
  return waitForProjection(
    async (attemptContext) =>
      readSealedKey(
        {
          ...input,
          registry: await fetchRingMemberRegistryRoot(
            input.client,
            input.ringProgramId,
            attemptContext,
          ),
        },
        attemptContext,
      ),
    MEMBER_REGISTRY_PROJECTION_ERRORS,
    context,
  );
}

/** @internal The indexer answer must sit under the registry root read from Solana. */
export async function readSealedKey(
  input: Readonly<{
    client: Pick<RingMemberRegistryReader, "getRingMemberRecord">;
    ringProgramId: Address;
    member: Member;
    registry: RingMemberRegistryRoot;
  }>,
  context: RequestContext,
): Promise<RingSealedKeyEntry> {
  const registry = input.registry;
  const read = await readRingMemberRecord({ ...input, registry }, context);
  if (!read.opening.present || read.sealed === null)
    throw new ClientError("CLIENT_MEMBER_REGISTRY_MEMBER_UNREGISTERED", {
      details: { method: "getRingMemberRecord" },
    });
  const { record, index, path } = read.opening;
  return {
    sealed: read.sealed,
    member: input.member,
    root: registry.root,
    next: record.next,
    lists: record.lists,
    escrowKey: record.escrowKey,
    index,
    proof: path,
  };
}

/** The opened key must reproduce the leaf under the root read from Solana. */
export function openRingSealedKey(entry: RingSealedKeyEntry, auditor: X25519Keypair): NullifierKey {
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
  if (!registersKey(entry, nullifierPublicKey))
    throw new RingError("RING_MEMBER_REGISTRY_INVALID", { details: { reason: "inclusion" } });
}

/** @internal Mirrors Go `KeyOpening.AssertEscrowed`, the member's leaf holds the key under the root. */
export function registersKey(entry: RingSealedKeyEntry, nullifierPublicKey: Bytes32): boolean {
  const leaf = memberRegistryLeaf({
    member: entry.member,
    next: entry.next,
    lists: entry.lists,
    escrowKey: registeredKeyHash({ nullifierPublicKey, ciphertext: entry.sealed.ciphertext }),
  });
  return (
    equalBytes(
      entry.escrowKey,
      registeredKeyHash({ nullifierPublicKey, ciphertext: entry.sealed.ciphertext }),
    ) &&
    equalBytes(
      memberRegistryRootFromProof({ leaf, index: entry.index, proof: entry.proof }),
      entry.root,
    )
  );
}

/** The circuit binds a free nullifier key, the address check is the only tie to the member. */
function checkedIdentity(member: RingKeyRegistrationMember): MemberIdentity {
  const identity = member.address;
  if (!equalBytes(member.nullifierKey.publicKey(), identity.nullifierPublicKey))
    throw new RingError("RING_NULLIFIER_KEY_MISMATCH");
  return Object.freeze({
    payer: identity.solanaAddress(),
    member: memberOfTag(identity.confidentialViewTag()),
    nullifierPublicKey: identity.nullifierPublicKey,
  });
}

async function registrationSubmission(
  input: RingKeyRegistrationParams,
  context?: RequestContext,
): Promise<RingTransactionSubmission> {
  const held: RingKeyRegistrationParams = Object.freeze({ ...input });
  const identity = checkedIdentity(held.member);
  const intent = hashChain([
    hashBytes(addressBytes(held.ringProgramId)) as Bytes32,
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
  });
}

async function buildRegistrationAttempt(
  input: RingKeyRegistrationParams,
  context?: RequestContext,
): Promise<Pick<RingSubmissionAttempt, "transaction" | "lastValidBlockHeight">> {
  const { client, ringProgramId } = input;
  const { payer, member } = checkedIdentity(input.member);
  const config = await fetchRingProgramConfig(client, ringProgramId, context);
  if (config.mode === "anonymous") throw new RingError("RING_ANONYMOUS_REFUSED");
  const auditor = config.auditorPublicKey;
  const { root, read, tip } = await waitForProjection(
    async (context) => {
      const root = await fetchRingMemberRegistryRoot(client, ringProgramId, context);
      const [read, tip] = await Promise.all([
        readRingMemberRecord({ client, ringProgramId, member, registry: root }, context),
        client.getRingMemberRegistryRoot({ ringProgramId }, context),
      ]);
      if (
        !equalBytes(tip.root, root.root) ||
        tip.nextIndex !== root.nextIndex ||
        tip.rootIndex !== root.historyCursor
      )
        throw new RingError("RING_MEMBER_REGISTRY_STALE");
      return { root, read, tip };
    },
    MEMBER_REGISTRY_PROJECTION_ERRORS,
    context,
  );
  // 2. Seal the member's key and authenticate the insertion path.
  const envelope = sealNullifierKey(input.member.nullifierKey, auditor);
  const secret = input.member.nullifierKey.secretBytes();
  const nullifierSecret = rightAlign(secret);
  secret.fill(0);
  try {
    const key = registeredKeyHash({
      nullifierPublicKey: envelope.nullifierPublicKey,
      ciphertext: envelope.sealed.ciphertext,
    });
    if (read.opening.present && !equalBytes(read.opening.record.escrowKey, new Uint8Array(32)))
      throw new RingError("RING_MEMBER_REGISTRY_INVALID");
    const overlay = new MemberRegistryOverlay(root.root, root.nextIndex, tip.appendPath);
    const changed = updateMemberRecord({
      root: root.root,
      nextIndex: root.nextIndex,
      member,
      opening: read.opening,
      lists: read.opening.present ? read.opening.record.lists : 0n,
      escrowKey: key,
      overlay,
    });
    const registryNewRoot = changed.root;
    const publicInputHash = registerKeyPublicInputHash({
      registryOldRoot: root.root,
      registryNewRoot,
      member,
      nullifierPublicKey: envelope.nullifierPublicKey,
      auditorPublicKey: auditor,
      ephemeralPublicKey: envelope.sealed.ephemeralPublicKey,
      ciphertext: envelope.sealed.ciphertext,
      newIndex: changed.item.index,
    });
    // 3. Prove key disclosure and registry insertion in one statement.
    const proof = await client.proveCustomRingRegisterKey(
      {
        publicInputHash,
        registryOldRoot: root.root,
        registryNewRoot,
        member,
        oldLists: changed.item.oldLists,
        update: changed.update,
        nullifierSecret,
        ephemeralSecret: envelope.ephemeralSecret,
        auditorPublicKey: auditor.u(),
      },
      context,
    );
    const instruction = await registerRingKeyInstruction({
      ringProgramId,
      member: payer,
      proof,
      registryOldRootIndex: root.historyCursor,
      registryNewRoot,
      item: changed.item,
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
}
