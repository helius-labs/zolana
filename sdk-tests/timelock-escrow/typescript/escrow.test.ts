/// <reference types="node" />

import { createZolanaClient, initializePoseidon } from "@heliuslabs/zolana";
import { LocalKeys, NullifierKeyProofAuthority } from "@heliuslabs/zolana/client";
import { DepositAsset, depositInstruction } from "@heliuslabs/zolana/interface";
import { SOLANA_OWNER_TAG, randomBlinding, solanaOwnerIdentity } from "@heliuslabs/zolana/keypair";
import {
  AssetRegistry,
  ProgramOwner,
  decodeProgramTransaction,
  type ProgramWalletUtxo,
} from "@heliuslabs/zolana/transaction";
import { getAddressEncoder } from "@solana/kit";
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
import { wasm, wasmLoadMs } from "./wasm.js";

const DEPOSITS = [250_000_000n, 250_000_000n] as const;
const LOCK_AMOUNT = 300_000_000n;
const UNLOCK_TIMESTAMP = 1_000_000n;
const CREATOR_LAMPORTS = 2_000_000_000n;

function total(utxos: readonly ProgramWalletUtxo[]): bigint {
  return utxos.reduce((sum, utxo) => sum + utxo.utxo.amount, 0n);
}

describe("timelock escrow", () => {
  it("locks shielded SOL in an escrow and withdraws it after unlock, with wasm proofs", async () => {
    await initializePoseidon();
    const config = clientConfig();
    const client = await createZolanaClient(config);
    const programId = escrowProgramId();
    const creator = randomKeypair();
    const signer = creator.toSolanaSigner();
    await airdrop(config, signer.address, CREATOR_LAMPORTS);
    const send = sendAndConfirmFactory(client, signer);
    const creatorKeys = LocalKeys.fromKeypair(creator, client.proofService);
    const programNullifierKey = ProgramOwner.nullifierKey();
    const programKeys = new NullifierKeyProofAuthority(programNullifierKey, client.proofService);
    programNullifierKey.destroy();
    const viewingKey = creator.viewingKey();
    const timings = new Timings();
    timings.record("wasm module load", wasmLoadMs);
    try {
      const assets = new AssetRegistry();
      const address = creator.shieldedAddress();
      const sender = address.toBytes();
      const authority = await escrowAuthority(programId, signer.address);
      const creatorKey = Uint8Array.from(getAddressEncoder().encode(signer.address));
      const creatorIdentity = solanaOwnerIdentity(creatorKey);
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

      const escrowTransaction = timings.measure("escrow escrowTransaction (proof inputs)", () =>
        wasm.escrowTransaction(
          {
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
          },
          sender,
          signer.address,
        ),
      );
      const escrowProof = prove(timings, "escrow", escrowTransaction);
      expect(escrowProof.publicHash).toEqual(escrowTransaction.publicHash);
      const escrowProofInputs = (
        await decodeProgramTransaction(escrowTransaction.finalizedTx, assets)
      ).toProofInputs(creator);
      const escrowTransact = await timings.measureAsync(
        "escrow SPP proveTransact (Go prover)",
        () => client.proveTransact(escrowProofInputs, creatorKeys),
      );
      const escrowSlot = await send([
        await escrowInstruction({
          programId,
          client,
          creator: signer,
          authority,
          proof: escrowProof.compressedProof,
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
            utxoHash: escrowTransaction.finalizedTx.outputHashes[ESCROW_OUTPUT_SLOT],
            data: {
              creator: {
                tag: SOLANA_OWNER_TAG,
                key: creatorKey,
                nullifierPk: creator.nullifierPublicKey(),
              },
              unlock: UNLOCK_TIMESTAMP,
            },
          },
        ],
      });

      const [escrow] = escrows;
      if (escrow === undefined) throw new Error("the creator has no open escrow");
      const withdrawTransaction = timings.measure(
        "withdraw withdrawTransaction (proof inputs)",
        () =>
          wasm.withdrawTransaction(
            {
              private: { txContext: txContext(), escrow: escrow.utxo, terms: escrow.data },
              public: { unlock: escrow.data.unlock, creatorIdentity },
            },
            sender,
            signer.address,
          ),
      );
      const withdrawProof = prove(timings, "withdraw", withdrawTransaction);
      expect(withdrawProof.publicHash).toEqual(withdrawTransaction.publicHash);
      const withdrawProofInputs = (
        await decodeProgramTransaction(withdrawTransaction.finalizedTx, assets)
      ).toProofInputs(creator);
      const withdrawTransact = await timings.measureAsync(
        "withdraw SPP proveTransact (Go prover)",
        () => client.proveTransact(withdrawProofInputs, programKeys),
      );
      const withdrawSlot = await send([
        await withdrawInstruction({
          programId,
          client,
          creator: signer,
          authority,
          proof: withdrawProof.compressedProof,
          unlock: escrow.data.unlock,
          transact: withdrawTransact,
        }),
      ]);

      const afterWithdraw = await creatorTransactions(client, creator, authority, withdrawSlot);
      expect({
        balance: total(await spendableSol(client, creator, afterWithdraw, assets)),
        escrows: escrowUtxos(timings, viewingKey, afterWithdraw, authority, assets, client.treeId),
      }).toEqual({ balance: shielded, escrows: [] });
      console.log(timings.report());
    } finally {
      viewingKey.destroy();
      programKeys.destroy();
      creatorKeys.destroy();
      creator.destroy();
    }
  });
});
