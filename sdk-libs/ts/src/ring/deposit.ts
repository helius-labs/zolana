import { compileUnsignedTransaction } from "../flows/compile.js";
import type { ZolanaClient } from "../client/client.js";
import type { Address, Bytes32, RequestContext, Transaction } from "../interface/types.js";
import { ringDepositInstruction } from "../interface/instructions/index.js";
import { initializePoseidon } from "../hasher/index.js";
import { randomBlinding, randomSalt } from "../keypair/bytes.js";
import { ShieldedAddress } from "../keypair/shielded.js";
import { ViewingKey } from "../keypair/viewing-key.js";
import { encodeRingDepositPlaintext } from "../transaction/serialization/ring-deposit.js";
import { ownerUtxoHash } from "../transaction/utxo.js";
import { SOL_MINT } from "../transaction/wallet/asset.js";
import { resolveDepositSettlement } from "../flows/settlement.js";
import { resolveShieldedRecipient } from "../wallet/registry.js";

import { RingError, wrapRingError } from "./error.js";

const ZERO_32 = new Uint8Array(32) as Bytes32;

export interface RingDepositTransactionParams {
  readonly client: ZolanaClient;
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
    const envelope = ViewingKey.generate();
    const salt = randomSalt();
    const ciphertext = envelope.encryptRingDeposit(
      recipient.viewingPublicKey,
      encodeRingDepositPlaintext({
        blinding,
        ...(input.memo === undefined ? {} : { memo: input.memo }),
        ringData: new Uint8Array(),
      }),
      salt,
    );
    const instruction = await ringDepositInstruction({
      ringProgramId: input.ringProgramId,
      tree,
      depositor,
      deposits: [
        {
          asset: settlement,
          viewTag: recipient.viewingPublicKey.x(),
          ownerUtxoHash: ownerUtxoHash(recipient.ownerHash(), blinding),
          amount: input.amount,
          ringDataHash: ZERO_32,
          encrypted: {
            txViewingPublicKey: envelope.publicKey().toBytes(),
            salt,
            ciphertext,
          },
        },
      ],
    });
    envelope.destroy();
    const lifetime = await input.client.getLatestBlockhash(context);
    return compileUnsignedTransaction({
      feePayer: input.feePayer,
      lifetime,
      instructions: [instruction],
    });
  } catch (cause) {
    throw wrapRingError("RING_BUILD_DEPOSIT", cause);
  }
}
