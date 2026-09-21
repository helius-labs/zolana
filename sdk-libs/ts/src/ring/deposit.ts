import { compileUnsignedTransaction } from "../flows/compile.js";
import { DEFAULT_COMPUTE_UNIT_LIMIT } from "../flows/internal.js";
import type { DepositClient } from "../wallet/deposit.js";
import type { Prover } from "../client/ports.js";
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
import {
  ringDepositContextHash,
  ringDepositPublicInputHash,
  sealRingDepositOpenings,
} from "./deposit-audit.js";

const ZERO_32 = new Uint8Array(32) as Bytes32;
export const RING_DEPOSIT_COMPUTE_UNIT_LIMIT = 1_400_000;

export type RingDepositClient = DepositClient & Pick<Prover, "proveCustomRingDeposit">;

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

/** Mirrors Rust `ring_deposit_sol`. The output is ring-bound, so only the ring's transact can spend it. */
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
    // 1. Read the ring's signature and deposit disclosure requirements.
    const [{ hasPolicy, auditorPublicKey }, coSigner, depositAudit] = await Promise.all([
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
      const sealed = depositAudit
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
        hasPolicy,
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
        const contextHash = ringDepositContextHash(
          input.ringProgramId,
          tree,
          wire.slice(1 + CUSTOM_RING_PROOF_LENGTH),
        );
        const proof = await input.client.proveCustomRingDeposit(
          {
            publicInputHash: ringDepositPublicInputHash({
              contextHash,
              ownerCommitments: [ownerCommitment],
              capsules: sealed.capsules,
              auditorPublicKey,
            }),
            contextHash,
            count: 1,
            ownerHashes: Array.from({ length: RING_DEPOSIT_AUDIT_SLOTS }, (_, index) =>
              index === 0 ? ownerHash : ZERO_32,
            ),
            blindings: Array.from({ length: RING_DEPOSIT_AUDIT_SLOTS }, (_, index) =>
              index === 0 ? blinding : ZERO_32,
            ),
            ephemeralSecret: sealed.ephemeralSecret,
            auditorPublicKey: auditorPublicKey.toUncompressed(),
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
      computeUnitLimit: depositAudit ? RING_DEPOSIT_COMPUTE_UNIT_LIMIT : DEFAULT_COMPUTE_UNIT_LIMIT,
      instructions: [instruction],
    });
  } catch (cause) {
    throw wrapRingError("RING_BUILD_DEPOSIT", cause);
  }
}
