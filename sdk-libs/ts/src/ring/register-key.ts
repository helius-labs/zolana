import type { Address, Instruction } from "@solana/kit";

import type {
  ChainReader,
  Prover,
  RingRecordReader,
  RingSealedKey,
  RingSealedNullifierKey as SealedNullifierKey,
} from "../client/ports.js";
import { waitForProjection } from "../client/retry.js";
import { meta, type SignerAccount } from "../interface/instructions/index.js";
import { Writer, addressBytes } from "../interface/internal.js";
import type { MemberRecord, QuadPath } from "../interface/member-registry.js";
import {
  ringConfigAddress,
  ringMemberRegistryAddress,
  ringRecordQueueAddress,
} from "../interface/pda/index.js";
import type { Bytes31, Bytes32, RequestContext } from "../interface/types.js";
import { auditSharedSecret } from "../keypair/audit.js";
import { symmetricApply } from "../keypair/merge/index.js";
import { NullifierKey } from "../keypair/nullifier-key.js";
import type { ShieldedAddress } from "../keypair/shielded.js";
import { X25519Keypair, type X25519PublicKey } from "../keypair/x25519.js";
import { ZERO_32, equal, rightAlign } from "../transaction/internal.js";

import { RingInstructionTag } from "./admin.js";
import { checkedCustomRingProof, queueAdmitsMemberWrite } from "./codecs.js";
import { fetchRingMemberRegistry, fetchRingProgramConfig, fetchRingRecordQueue } from "./config.js";
import { RingError, wrapRingError } from "./error.js";
import type { MemberOpeningRead } from "./member-registry.js";
import { memberOfTag } from "./policy.js";
import { MEMBER_REGISTRY_PROJECTION_ERRORS } from "./projection.js";
import { feeAccounts } from "./records.js";
import { readNewest } from "./registered-record.js";
import { registerKeyStatementHash } from "./statement.js";

/** Rust `NF_KEY_ENC_INFO`, separates the key stream from the audit stream. */
export const NF_KEY_ENC_INFO = new TextEncoder().encode("CRING/nfk1");

export type { SealedNullifierKey };

/** Rust `NullifierKeyEnvelope`, the sealed key and the ephemeral secret its proof witnesses. */
export interface NullifierKeyEnvelope {
  readonly ephemeralSecret: Bytes32;
  readonly sealed: SealedNullifierKey;
  readonly nullifierPublicKey: Bytes32;
}

/** The member and the auditor an escrow binds. */
export interface KeyEscrowRequest {
  /** The owner identity of the signing member. */
  readonly member: Bytes32;
  readonly auditorPublicKey: X25519PublicKey;
}

/** A sealed nullifier key and the 192-byte proof of its envelope. */
export interface ProvenEscrow {
  readonly nullifierPk: Bytes32;
  readonly ephU: Bytes32;
  readonly ciphertext: Bytes32;
  readonly proof: Uint8Array;
}

/** Rust `KeyEscrowAuthority`, the holder seals and proves so the nullifier secret never leaves it. */
export interface KeyEscrowAuthority {
  nullifierPublicKey(): Bytes32;
  proveEscrow(request: KeyEscrowRequest, context?: RequestContext): Promise<ProvenEscrow>;
}

/** An in-process `KeyEscrowAuthority` over a copy of the key, `destroy` wipes the copy. */
export class NullifierKeyEscrow implements KeyEscrowAuthority {
  readonly #key: NullifierKey;
  readonly #prover: Pick<Prover, "proveRing">;

  constructor(nullifierKey: NullifierKey, prover: Pick<Prover, "proveRing">) {
    this.#key = nullifierKey.clone();
    this.#prover = prover;
  }

  nullifierPublicKey(): Bytes32 {
    return this.#key.publicKey();
  }

  async proveEscrow(request: KeyEscrowRequest, context?: RequestContext): Promise<ProvenEscrow> {
    const envelope = sealNullifierKey(this.#key, request.auditorPublicKey);
    const secret = this.#key.secretBytes();
    const nullifierSecret = rightAlign(secret);
    secret.fill(0);
    try {
      const ephU = envelope.sealed.ephemeralPublicKey.u();
      const publicInputHash = registerKeyStatementHash({
        member: request.member,
        nullifierPk: envelope.nullifierPublicKey,
        auditorPubkey: request.auditorPublicKey.toBytes(),
        ephU,
        ciphertext: envelope.sealed.ciphertext,
      });
      const proof = await this.#prover.proveRing(
        {
          kind: "registerKey",
          publicInputHash,
          member: request.member,
          nullifierSecret,
          ephSk: envelope.ephemeralSecret,
          auditorPk: request.auditorPublicKey.u(),
        },
        context,
      );
      return Object.freeze({
        nullifierPk: envelope.nullifierPublicKey,
        ephU,
        ciphertext: envelope.sealed.ciphertext,
        proof: checkedCustomRingProof(proof),
      });
    } finally {
      nullifierSecret.fill(0);
      envelope.ephemeralSecret.fill(0);
    }
  }

  destroy(): void {
    this.#key.destroy();
  }
}

export type RingKeyRegistrationClient = Pick<ChainReader, "getAccount"> &
  Pick<RingRecordReader, "getRingMemberOpenings">;

/** `RegisterKey` instruction ready to sign by the member. */
export interface ProvenKeyRegistration {
  readonly instruction: Instruction;
}

/** Rust `RegisterKey`, queues the member's sealed nullifier key as the escrow key of its record. */
export class RegisterKey {
  readonly #ringProgramId: Address;
  readonly #member: ShieldedAddress;
  readonly #payer: SignerAccount;
  readonly #authority: KeyEscrowAuthority;

  constructor(
    input: Readonly<{
      ringProgramId: Address;
      /** Its Solana key signs, its nullifier key is the one escrowed. */
      member: ShieldedAddress;
      /** Pays the insert fee the config charges a member. */
      payer: SignerAccount;
      authority: KeyEscrowAuthority;
    }>,
  ) {
    this.#ringProgramId = input.ringProgramId;
    this.#member = input.member;
    this.#payer = input.payer;
    this.#authority = input.authority;
  }

  /** Refuses a member whose record already escrows a key, a second key never replaces it. */
  async prove(
    client: RingKeyRegistrationClient,
    context?: RequestContext,
  ): Promise<ProvenKeyRegistration> {
    try {
      const config = await fetchRingProgramConfig(client, this.#ringProgramId, context);
      if (config.mode === "anonymous") throw new RingError("RING_ANONYMOUS_REFUSED");
      const nullifierPk = this.#authority.nullifierPublicKey();
      if (!equal(nullifierPk, this.#member.nullifierPublicKey))
        throw new RingError("RING_NULLIFIER_KEY_MISMATCH");
      const signer = this.#member.solanaAddress();
      const member = memberOfTag(addressBytes(signer, "member"));
      await checkQueueAdmits(client, this.#ringProgramId, context);
      const { read } = await readRecord(client, this.#ringProgramId, member, context);
      const registered = read.record();
      if (registered !== undefined && !equal(registered.escrowKey, ZERO_32))
        throw new RingError("RING_KEY_ALREADY_REGISTERED");
      const escrow = await this.#authority.proveEscrow(
        { member, auditorPublicKey: config.auditorPublicKey },
        context,
      );
      if (!equal(escrow.nullifierPk, nullifierPk))
        throw new RingError("RING_NULLIFIER_KEY_MISMATCH");
      const [configAddress, registry, queue] = await Promise.all([
        ringConfigAddress(this.#ringProgramId),
        ringMemberRegistryAddress(this.#ringProgramId),
        ringRecordQueueAddress(this.#ringProgramId),
      ]);
      const data = new Writer()
        .u8(RingInstructionTag.registerKey, "tag")
        .bytes(checkedCustomRingProof(escrow.proof))
        .bytes(escrow.nullifierPk, 32, "nullifierPk")
        .bytes(escrow.ephU, 32, "ephU")
        .bytes(escrow.ciphertext, 32, "ciphertext")
        .finish();
      return Object.freeze({
        instruction: {
          programAddress: this.#ringProgramId,
          accounts: [
            meta(signer, true, false),
            meta(configAddress, false, false),
            meta(registry, false, false),
            meta(queue, false, true),
            ...feeAccounts(config, signer, this.#payer),
          ],
          data,
        },
      });
    } catch (cause) {
      throw wrapRingError("RING_BUILD_KEY_REGISTRATION", cause);
    }
  }
}

export type RingSealedKeyClient = RingKeyRegistrationClient;

/** A member's record under the chain's current root, escrowing `sealed`. */
export interface RingSealedKeyEntry {
  readonly member: Bytes32;
  readonly root: Bytes32;
  readonly record: MemberRecord;
  readonly path: QuadPath;
  readonly sealed: RingSealedKey;
}

/** The key `member` escrowed, refused unless its record binds the served envelope. */
export async function fetchRingSealedKey(
  input: Readonly<{ client: RingSealedKeyClient; ringProgramId: Address; member: Bytes32 }>,
  context?: RequestContext,
): Promise<RingSealedKeyEntry> {
  const { root, read } = await readRecord(input.client, input.ringProgramId, input.member, context);
  const served = read.opening.sealedKey;
  const escrowed = served === undefined ? undefined : read.escrowed(served.nullifierPk);
  if (escrowed === undefined) throw new RingError("RING_KEY_NOT_REGISTERED");
  return Object.freeze({
    member: input.member,
    root,
    record: escrowed.record,
    path: escrowed.path,
    sealed: escrowed.sealed,
  });
}

/** The auditor's opening of an escrowed key, the opened key must be the one the record binds. */
export function openRingSealedKey(entry: RingSealedKeyEntry, auditor: X25519Keypair): NullifierKey {
  const key = openNullifierKey(entry.sealed, auditor);
  if (!equal(key.publicKey(), entry.sealed.nullifierPk)) {
    key.destroy();
    throw new RingError("RING_KEY_ENVELOPE_INVALID");
  }
  return key;
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

/** The pad alone does not authenticate the key against its registry record. */
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

/** Rust `RecordQueue::admit_member_write`, the refusal the program makes before it verifies. */
async function checkQueueAdmits(
  client: Pick<ChainReader, "getAccount">,
  ringProgramId: Address,
  context: RequestContext | undefined,
): Promise<void> {
  const [registry, queue] = await Promise.all([
    fetchRingMemberRegistry(client, ringProgramId, context),
    fetchRingRecordQueue(client, ringProgramId, context),
  ]);
  switch (queueAdmitsMemberWrite(queue, registry)) {
    case "queueFull":
      throw new RingError("RING_RECORD_QUEUE_FULL");
    case "authorityLeafReserve":
      throw new RingError("RING_REGISTRY_FULL");
    case "admitted":
      return;
  }
}

/** `member`'s opening under the chain's current root, an absent member reads no record. */
async function readRecord(
  client: RingKeyRegistrationClient,
  ringProgramId: Address,
  member: Bytes32,
  context: RequestContext | undefined,
): Promise<Readonly<{ root: Bytes32; read: MemberOpeningRead }>> {
  return waitForProjection(
    async (attemptContext) => {
      const { root, reads } = await readNewest(
        { client, ringProgramId, members: [member] },
        attemptContext,
      );
      const [read] = reads;
      if (read === undefined)
        throw new RingError("RING_MEMBER_REGISTRY_INVALID", { details: { reason: "openings" } });
      return { root, read };
    },
    MEMBER_REGISTRY_PROJECTION_ERRORS,
    context,
  );
}
