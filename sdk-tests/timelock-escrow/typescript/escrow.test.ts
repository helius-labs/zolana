/// <reference types="node" />

import { createSprClient, initializePoseidon } from "@heliuslabs/spr";
import { DepositAsset, depositInstruction } from "@heliuslabs/spr/interface";
import {
  SOLANA_OWNER_TAG,
  bytes32,
  randomBlinding,
  solanaOwnerIdentity,
} from "@heliuslabs/spr/keypair";
import {
  ShieldedPda,
  ProgramOwner,
  bindProgramTransaction,
  type ProgramWalletUtxo,
} from "@heliuslabs/spr/program";
import { AssetRegistry, TransactionError } from "@heliuslabs/spr/transaction";
import { bytesToBigInt } from "@heliuslabs/spr/internal";
import {
  SOLANA_ERROR__INSTRUCTION_ERROR__CUSTOM,
  SOLANA_ERROR__JSON_RPC__SERVER_ERROR_SEND_TRANSACTION_PREFLIGHT_FAILURE,
  getAddressEncoder,
  isSolanaError,
} from "@solana/kit";
import { describe, expect, it } from "vitest";

import {
  ESCROW_OUTPUT_SLOT,
  airdrop,
  clientConfig,
  creatorTransactions,
  escrowAuthority,
  escrowInstruction,
  escrowProgramId,
  escrowUtxos,
  prove,
  randomKeypair,
  sendAndConfirmFactory,
  spendableSol,
  withdrawInstruction,
} from "./escrow.js";
import { Timings } from "./timings.js";
import { ProgramProver, wasm, wasmLoadMs } from "./wasm.js";

const DEPOSITS = [250_000_000n, 250_000_000n] as const;
const LOCK_AMOUNT = 300_000_000n;
const UNLOCK_TIMESTAMP = 1_000_000n;
const CREATOR_LAMPORTS = 2_000_000_000n;
const U64_MAX = (1n << 64n) - 1n;
// TimelockEscrowError codes (sdk-tests/timelock-escrow/program/src/error.rs).
const PROOF_VERIFICATION_FAILED = 9000;
const NOT_YET_UNLOCKED = 9005;
const REQUIREMENT_FAILED = {
  code: "TRANSACTION_PROGRAM_BUILD",
  cause: { category: "external", code: "PROGRAM_REQUIREMENT_FAILED" },
} as const;

function total(utxos: readonly ProgramWalletUtxo[]): bigint {
  return utxos.reduce((sum, utxo) => sum + utxo.utxo.amount, 0n);
}

/** The code and sanitized cause of a program transaction build that must fail. */
async function buildFailure(
  build: Promise<unknown>,
): Promise<Pick<TransactionError, "code" | "cause">> {
  const error = await build.then(
    () => undefined,
    (failure: unknown) => failure,
  );
  if (!(error instanceof TransactionError))
    throw new Error("the build did not fail with a TransactionError", { cause: error });
  return { code: error.code, cause: error.cause };
}

/** The custom program error that fails a transaction in preflight simulation. */
async function programFailure(
  sending: Promise<unknown>,
): Promise<Readonly<{ index: number; code: number }>> {
  const error = await sending.then(
    () => undefined,
    (failure: unknown) => failure,
  );
  if (
    !isSolanaError(
      error,
      SOLANA_ERROR__JSON_RPC__SERVER_ERROR_SEND_TRANSACTION_PREFLIGHT_FAILURE,
    ) ||
    !isSolanaError(error.cause, SOLANA_ERROR__INSTRUCTION_ERROR__CUSTOM)
  )
    throw new Error("the transaction did not fail with a custom program error", { cause: error });
  return { index: error.cause.context.index, code: error.cause.context.code };
}

describe("timelock escrow", () => {
  it("locks shielded SOL in an escrow and withdraws it after unlock, with wasm proofs", async () => {
    await initializePoseidon();
    const config = clientConfig();
    const client = await createSprClient(config);
    const programId = escrowProgramId();
    const creator = randomKeypair();
    const signer = creator.toSolanaSigner();
    await airdrop(config, signer.address, CREATOR_LAMPORTS);
    const send = sendAndConfirmFactory(client, signer);
    const viewingKey = creator.viewingKey();
    const timings = new Timings();
    timings.record("wasm module load", wasmLoadMs);
    try {
      const assets = new AssetRegistry();
      const buildEscrow = bindProgramTransaction(wasm.escrowTransaction, { assets });
      const buildWithdraw = bindProgramTransaction(wasm.withdrawTransaction, { assets });
      using escrowProver = new ProgramProver("escrow");
      using withdrawProver = new ProgramProver("withdraw");
      const address = creator.shieldedAddress();
      const sender = address.toBytes();
      const authority = await escrowAuthority(programId, signer.address);
      const creatorKey = Uint8Array.from(getAddressEncoder().encode(signer.address));
      const creatorIdentity = bytesToBigInt(solanaOwnerIdentity(creatorKey)).toString();
      const otherIdentity = bytesToBigInt(
        solanaOwnerIdentity(crypto.getRandomValues(new Uint8Array(32))),
      ).toString();
      const shielded = DEPOSITS.reduce((sum, amount) => sum + amount, 0n);
      const txContext = () => ({ blindingSeed: randomBlinding(), outputTreeId: client.treeId });

      const depositSlot = await send([
        await depositInstruction({
          tree: client.tree,
          depositor: signer,
          deposits: DEPOSITS.map((amount) => ({
            asset: DepositAsset.sol(),
            viewTag: address.confidentialViewTag(),
            recipientOwnerHash: address.ownerHash(),
            amount,
          })),
        }),
      ]);
      const deposited = await spendableSol(
        client,
        creator,
        await creatorTransactions(client, creator, authority, depositSlot),
        assets,
      );
      expect({ balance: total(deposited), utxos: deposited.length }).toEqual({
        balance: shielded,
        utxos: DEPOSITS.length,
      });

      const escrowInput = {
        private: {
          txContext: txContext(),
          tokenUtxosAssetA: [...deposited],
          unlock: UNLOCK_TIMESTAMP,
          amount: LOCK_AMOUNT,
        },
        public: {
          escrowOwner: authority.address(address.viewingPublicKey).toBytes(),
          creatorIdentity,
        },
      };
      // The circuit binds the spent inputs' owner to the public creator identity.
      const forgedIdentity = {
        ...escrowInput,
        public: { ...escrowInput.public, creatorIdentity: otherIdentity },
      };
      expect(await buildFailure(buildEscrow(forgedIdentity, sender, signer.address))).toEqual(
        REQUIREMENT_FAILED,
      );
      const unknownPublicInput = {
        ...escrowInput,
        public: { ...escrowInput.public, unexpectedIdentity: "0" },
      };
      expect(await buildFailure(buildEscrow(unknownPublicInput, sender, signer.address))).toEqual({
        code: "TRANSACTION_PROGRAM_BUILD",
        cause: { category: "external", code: "TRANSACTION_INVALID_INPUT" },
      });
      expect(
        await buildFailure(
          buildEscrow(
            {
              ...escrowInput,
              private: {
                ...escrowInput.private,
                tokenUtxosAssetA: [...deposited, ...deposited, ...deposited],
              },
            },
            sender,
            signer.address,
          ),
        ),
      ).toEqual({
        code: "TRANSACTION_PROGRAM_BUILD",
        cause: { category: "external", code: "TRANSACTION_TOO_MANY_INPUTS" },
      });
      const escrowTransaction = await timings.measureAsync(
        "escrow escrowTransaction (proof inputs)",
        () => buildEscrow(escrowInput, sender, signer.address),
      );
      const escrowProof = prove(timings, escrowProver, escrowTransaction);
      expect(escrowProof.publicInputs).toEqual([escrowTransaction.publicHash]);
      const secondProof = escrowProver.prove(escrowTransaction);
      expect(secondProof.publicInputs).toEqual(escrowProof.publicInputs);
      expect(secondProof.compressedProof).not.toEqual(escrowProof.compressedProof);
      expect(() =>
        escrowProver.prove({
          proofInputs: escrowTransaction.proofInputs,
          publicHash: bytes32(escrowTransaction.publicHash.map((byte) => byte ^ 1)),
        }),
      ).toThrow("proof public hash differs from its transaction");
      {
        using mismatched = new ProgramProver("escrow", "withdraw");
        expect(() => mismatched.prove(escrowTransaction)).toThrowError(
          expect.objectContaining({
            name: "ProofVerificationError",
            code: "PROOF_VERIFICATION_FAILED",
            circuit: "escrow",
            verifyingKey: "withdraw",
          }),
        );
      }
      const escrowProofInputs = escrowTransaction.transaction.encryptWithKeys(creator);
      const escrowTransact = await timings.measureAsync(
        "escrow SPP proveTransact (Go prover)",
        () => client.proveTransact(escrowProofInputs, [creator]),
      );
      const escrowSlot = await send([
        await escrowInstruction({
          programId,
          client,
          creator: signer,
          authority,
          proof: escrowProof.compressedProof,
          viewingPublicKey: address.viewingPublicKey,
          transact: escrowTransact,
        }),
      ]);

      const afterEscrow = await creatorTransactions(client, creator, authority, escrowSlot);
      const escrows = escrowUtxos(
        timings,
        viewingKey,
        afterEscrow,
        authority,
        assets,
        client.treeId,
      );
      expect({
        balance: total(await spendableSol(client, creator, afterEscrow, assets)),
        escrows: escrows.map((escrow) => ({ utxoHash: escrow.utxo.utxoHash, data: escrow.data })),
      }).toEqual({
        balance: shielded - LOCK_AMOUNT,
        escrows: [
          {
            utxoHash: escrowTransaction.transaction.outputHashes[ESCROW_OUTPUT_SLOT],
            data: {
              creator: {
                key: { tag: SOLANA_OWNER_TAG, bytes: creatorKey },
                nullifierPk: bytesToBigInt(creator.nullifierPublicKey()).toString(),
              },
              unlock: UNLOCK_TIMESTAMP,
            },
          },
        ],
      });

      // Padding may reuse the escrow tag; a decoded state must still match its commitment.
      const stateHash = escrowTransaction.transaction.outputHashes[ESCROW_OUTPUT_SLOT];
      if (stateHash === undefined) throw new Error("the escrow transaction has no state hash");
      const indexedEscrow = afterEscrow.find((transaction) =>
        transaction.outputSlots.some((slot) =>
          Buffer.from(slot.outputContext.hash).equals(stateHash),
        ),
      );
      const stateSlot = indexedEscrow?.outputSlots[ESCROW_OUTPUT_SLOT];
      if (indexedEscrow === undefined || stateSlot === undefined)
        throw new Error("the escrow transaction is missing its state output");
      const padding = {
        ...indexedEscrow,
        outputSlots: indexedEscrow.outputSlots.map((slot, index) =>
          index === ESCROW_OUTPUT_SLOT
            ? { ...slot, payload: new Uint8Array(slot.payload.length).fill(255) }
            : slot,
        ),
      };
      expect(escrowUtxos(timings, viewingKey, [padding], authority, assets, client.treeId)).toEqual(
        [],
      );
      const wrongCommitment = {
        ...indexedEscrow,
        outputSlots: indexedEscrow.outputSlots.map((slot, index) =>
          index === ESCROW_OUTPUT_SLOT
            ? {
                ...slot,
                outputContext: { ...slot.outputContext, hash: bytes32(new Uint8Array(32)) },
              }
            : slot,
        ),
      };
      expect(() =>
        escrowUtxos(timings, viewingKey, [wrongCommitment], authority, assets, client.treeId),
      ).toThrowError(
        expect.objectContaining({
          name: "ClientError.DataHashMismatch",
        }),
      );

      const [escrow] = escrows;
      if (escrow === undefined) throw new Error("the creator has no open escrow");
      const withdrawInput = {
        private: { txContext: txContext(), escrow: escrow.utxo, terms: escrow.data },
        public: { unlock: escrow.data.unlock, creatorIdentity },
      };
      // The circuit binds the public unlock time and creator to the escrow's terms.
      const forgedUnlock = {
        ...withdrawInput,
        public: { ...withdrawInput.public, unlock: escrow.data.unlock - 1n },
      };
      expect(await buildFailure(buildWithdraw(forgedUnlock, sender, signer.address))).toEqual(
        REQUIREMENT_FAILED,
      );
      const forgedCreator = {
        ...withdrawInput,
        public: { ...withdrawInput.public, creatorIdentity: otherIdentity },
      };
      expect(await buildFailure(buildWithdraw(forgedCreator, sender, signer.address))).toEqual(
        REQUIREMENT_FAILED,
      );
      const withdrawTransaction = await timings.measureAsync(
        "withdraw withdrawTransaction (proof inputs)",
        () => buildWithdraw(withdrawInput, sender, signer.address),
      );
      const withdrawProof = prove(timings, withdrawProver, withdrawTransaction);
      expect(withdrawProof.publicInputs).toEqual([withdrawTransaction.publicHash]);
      const withdrawProofInputs = withdrawTransaction.transaction.encryptWithKeys(creator);
      const shieldedPda = ShieldedPda.withViewingKey(
        authority.pda,
        ProgramOwner.nullifierKey(),
        creator.viewingKey(),
      );
      const withdrawTransact = await timings
        .measureAsync("withdraw SPP proveTransact (Go prover)", () =>
          client.proveTransact(withdrawProofInputs, [shieldedPda]),
        )
        .finally(() => shieldedPda.destroy());
      const withdrawAt = (unlock: bigint) =>
        withdrawInstruction({
          programId,
          client,
          creator: signer,
          authority,
          proof: withdrawProof.compressedProof,
          unlock,
          transact: withdrawTransact,
        });
      // An unlock time that has not arrived is refused before the proof is checked.
      expect(await programFailure(send([await withdrawAt(U64_MAX)]))).toEqual({
        index: 0,
        code: NOT_YET_UNLOCKED,
      });
      // A past unlock time other than the proven one fails verification.
      expect(await programFailure(send([await withdrawAt(escrow.data.unlock - 1n)]))).toEqual({
        index: 0,
        code: PROOF_VERIFICATION_FAILED,
      });
      const withdrawSlot = await send([await withdrawAt(escrow.data.unlock)]);

      const afterWithdraw = await creatorTransactions(client, creator, authority, withdrawSlot);
      expect({
        balance: total(await spendableSol(client, creator, afterWithdraw, assets)),
        escrows: escrowUtxos(timings, viewingKey, afterWithdraw, authority, assets, client.treeId),
      }).toEqual({ balance: shielded, escrows: [] });
      console.log(timings.report());
    } finally {
      viewingKey.destroy();
      creator.destroy();
    }
  });
});
