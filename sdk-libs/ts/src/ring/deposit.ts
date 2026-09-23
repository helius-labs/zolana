import { compileUnsignedTransaction } from "../flows/compile.js";
import { DEFAULT_COMPUTE_UNIT_LIMIT } from "../flows/internal.js";
import type { DepositClient } from "../wallet/deposit.js";
import type { Prover, RingKeyRegistryReader } from "../client/ports.js";
import { CUSTOM_RING_PROOF_LENGTH } from "../interface/custom-ring-proof.js";
import { RING_DEPOSIT_AUDIT_SLOTS } from "./deposit-capsule.js";
import { copyBytes } from "../interface/internal.js";
import type { Address, Bytes32, RequestContext, Transaction } from "../interface/types.js";
import type { SignerAccount } from "../interface/instructions/index.js";
import { ringDepositInstruction } from "./deposit-instruction.js";
import { initializePoseidon } from "../hasher/index.js";
import { randomBlinding, randomSalt } from "../keypair/bytes.js";
import { ShieldedAddress } from "../keypair/shielded.js";
import { ViewingKey } from "../keypair/viewing-key.js";
import { encodeRingDepositPlaintext } from "../transaction/serialization/ring-deposit.js";
import { ownerUtxoHash } from "../transaction/utxo.js";
import { SOL_MINT } from "../transaction/asset.js";
import { resolveDepositSettlement } from "../flows/settlement.js";
import { resolveShieldedRecipient } from "../wallet/registry.js";

import { fetchRingCoSigner, fetchRingDepositAudit, fetchRingProgramConfig } from "./config.js";
import { DEPOSIT_DEMAND, checkRingCoSigner } from "./cosign.js";
import { RingError, wrapRingError } from "./error.js";
import { openRingEscrowedKeys } from "./key-escrow.js";
import {
  ringDepositContextHash,
  ringDepositPublicInputHash,
  sealRingDepositOpenings,
} from "./deposit-audit.js";

const ZERO_32 = new Uint8Array(32) as Bytes32;
export const RING_DEPOSIT_COMPUTE_UNIT_LIMIT = 1_400_000;

export type RingDepositClient = DepositClient &
  Pick<Prover, "proveCustomRingDeposit"> &
  Pick<RingKeyRegistryReader, "getRingKeyRegistryEntry">;

export interface RingDepositTransactionParams {
  readonly client: RingDepositClient;
  readonly ringProgramId: Address;
  readonly feePayer: Address;
  readonly depositor?: Address;
  readonly tree?: Address;
  readonly recipient: Address | ShieldedAddress;
  readonly asset?: Address;
  readonly amount: bigint;
  readonly splTokenAccount?: Address;
  readonly splTokenProgram?: Address | null;
  readonly memo?: Uint8Array;
  /** The ring's co-signer when its scope covers deposits. */
  readonly cosigner?: SignerAccount;
}

/** Mirrors Rust `RingDeposit`, a ring that escrows keys always audits. */
export async function buildRingDepositTransaction(
  input: RingDepositTransactionParams,
  context?: RequestContext,
): Promise<Transaction> {
  try {
    await initializePoseidon();
    const recipient = await resolveShieldedRecipient(
      { rpc: input.client, recipient: input.recipient },
      (unregistered) =>
        new RingError("RING_BUILD_DEPOSIT", {
          details: { reason: "recipient not registered", recipient: unregistered },
        }),
      context,
    );
    const depositor = input.depositor ?? input.feePayer;
    const tree = input.tree ?? input.client.tree;
    const asset = input.asset ?? SOL_MINT;
    // 1. Read the ring's signature, deposit disclosure and key escrow requirements.
    const [{ auditorPublicKey, keyEscrow }, coSigner, depositAudit] = await Promise.all([
      fetchRingProgramConfig(input.client, input.ringProgramId, context),
      fetchRingCoSigner(input.client, input.ringProgramId, context),
      fetchRingDepositAudit(input.client, input.ringProgramId, context),
    ]);
    checkRingCoSigner({
      ringProgramId: input.ringProgramId,
      configured: coSigner,
      supplied: input.cosigner,
      demand: DEPOSIT_DEMAND,
      approvalRequired: false,
    });
    const settlement = await resolveDepositSettlement(
      {
        asset,
        depositor,
        ...(input.splTokenAccount === undefined ? {} : { splTokenAccount: input.splTokenAccount }),
        ...(input.splTokenProgram === undefined ? {} : { splTokenProgram: input.splTokenProgram }),
      },
      () => new RingError("RING_BUILD_DEPOSIT", { details: { reason: "missing token account" } }),
    );
    const owner = {
      ownerPkHash: recipient.signingPublicKey.ownerProofInputHash(),
      nullifierPk: recipient.nullifierPublicKey,
    };
    const escrow = keyEscrow
      ? await openRingEscrowedKeys(
          { client: input.client, ringProgramId: input.ringProgramId, owners: [owner] },
          context,
        )
      : undefined;
    const audited = depositAudit || escrow !== undefined;
    const blinding = randomBlinding();
    const ownerHash = recipient.ownerHash();
    const envelope = ViewingKey.generate();
    let ephemeralSecret: Bytes32 | undefined;
    let plaintext: Uint8Array | undefined;
    let instruction;
    try {
      const salt = randomSalt();
      plaintext = encodeRingDepositPlaintext({
        blinding,
        ...(input.memo === undefined ? {} : { memo: input.memo }),
        ringData: new Uint8Array(),
      });
      const ciphertext = envelope.encryptRingDeposit(recipient.viewingPublicKey, plaintext, salt);
      // 2. Keep recipient ciphertext and add required auditor disclosure.
      const sealed = audited
        ? sealRingDepositOpenings(
            [{ ownerHash, blinding, recipientCiphertext: ciphertext }],
            auditorPublicKey,
          )
        : undefined;
      ephemeralSecret = sealed?.ephemeralSecret;
      const capsule = sealed?.payloads[0] ?? ciphertext;
      const ownerCommitment = ownerUtxoHash(ownerHash, blinding);
      instruction = await ringDepositInstruction({
        ...(sealed === undefined ? {} : { proof: new Uint8Array(CUSTOM_RING_PROOF_LENGTH) }),
        ringProgramId: input.ringProgramId,
        tree,
        depositor,
        ...(escrow === undefined ? {} : { keyRegistryRootIndex: escrow.rootIndex }),
        ...(input.cosigner === undefined ? {} : { cosigner: input.cosigner }),
        deposits: [
          {
            asset: settlement,
            viewTag: recipient.viewingPublicKey.x(),
            ownerUtxoHash: ownerCommitment,
            amount: input.amount,
            ringDataHash: ZERO_32,
            encrypted: {
              txViewingPublicKey: envelope.publicKey().toBytes(),
              salt,
              ciphertext: capsule,
            },
          },
        ],
      });
      // 3. Bind disclosure to the SPP payload and destination tree.
      if (sealed !== undefined) {
        const wire = instruction.data;
        if (wire === undefined) throw new RingError("RING_BUILD_DEPOSIT");
        // The SPP wire follows the proof and the registry root index.
        const contextHash = ringDepositContextHash(
          input.ringProgramId,
          tree,
          wire.slice(2 + CUSTOM_RING_PROOF_LENGTH),
        );
        const firstSlot = <T>(value: T, zero: T): readonly T[] =>
          Array.from({ length: RING_DEPOSIT_AUDIT_SLOTS }, (_, index) =>
            index === 0 ? value : zero,
          );
        const proof = await input.client.proveCustomRingDeposit(
          {
            publicInputHash: ringDepositPublicInputHash({
              contextHash,
              ownerCommitments: [ownerCommitment],
              capsules: sealed.capsules,
              auditorPublicKey,
              ...(escrow === undefined ? {} : { keyRegistryRoot: escrow.root }),
            }),
            contextHash,
            count: 1,
            ownerPkHashes: firstSlot(owner.ownerPkHash, ZERO_32),
            nullifierPks: firstSlot(owner.nullifierPk, ZERO_32),
            blindings: firstSlot(blinding, ZERO_32),
            keys: firstSlot(escrow?.keys[0], undefined),
            ephemeralSecret: sealed.ephemeralSecret,
            auditorPublicKey: auditorPublicKey.toUncompressed(),
            ...(escrow === undefined ? {} : { keyRegistryRoot: escrow.root }),
          },
          context,
        );
        const data = new Uint8Array(wire);
        data.set(copyBytes(proof, CUSTOM_RING_PROOF_LENGTH, "deposit proof"), 1);
        instruction = Object.freeze({ ...instruction, data });
      }
    } finally {
      envelope.destroy();
      blinding.fill(0);
      ownerHash.fill(0);
      ephemeralSecret?.fill(0);
      plaintext?.fill(0);
    }
    const lifetime = await input.client.getLatestBlockhash(context);
    return compileUnsignedTransaction({
      feePayer: input.feePayer,
      lifetime,
      computeUnitLimit: audited ? RING_DEPOSIT_COMPUTE_UNIT_LIMIT : DEFAULT_COMPUTE_UNIT_LIMIT,
      instructions: [instruction],
    });
  } catch (cause) {
    throw wrapRingError("RING_BUILD_DEPOSIT", cause);
  }
}
