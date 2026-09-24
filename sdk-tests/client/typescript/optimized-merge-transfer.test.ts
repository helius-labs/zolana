/// <reference types="node" />

import {
  SOL_MINT,
  buildRegistrationTransaction,
  buildSetMergingEnabledTransaction,
  createZolanaClient,
} from "@heliuslabs/zolana";
import { getCacheAddress } from "@heliuslabs/zolana/addresses";
import { LocalKeys, MERGE_TRANSACT_COMPUTE_UNIT_LIMIT, atSlot } from "@heliuslabs/zolana/client";
import {
  DepositAsset,
  MERGE_INPUT_COUNT,
  TransactCacheAccounts,
  closeCacheInstruction,
  createCacheInstruction,
  decodeCache,
  depositInstruction,
  transactInstruction,
} from "@heliuslabs/zolana/interface";
import { getMergeTransactInstructionAsync } from "@heliuslabs/zolana/instructions";
import {
  AssetRegistry,
  ConfidentialTransfer,
  Merge,
  ProofInputUtxo,
  Utxo,
  decryptToBalances,
} from "@heliuslabs/zolana/transaction";
import { describe, expect, it } from "vitest";

import {
  fundedKeypair,
  fundedSigner,
  sendAndConfirmFactory,
  setup,
  signSendAndConfirm,
  userRecordAddress,
} from "./setup.js";

const UTXO_COUNT = MERGE_INPUT_COUNT;
const DEPOSIT_AMOUNT = 100_000_000n;
const TRANSFER_AMOUNT = 500_000_000n;
const SENDER_LAMPORTS = 2_000_000_000n;
const RENT_SPONSOR_LAMPORTS = 1_000_000_000n;
const CACHE_NONCE = 0n;
const CACHE_EXPIRES_AT = 2_000_000_000n;
const CACHE_SLOT = 0;
const DEPOSIT_COMPUTE_UNIT_LIMIT = 1_400_000;

function log(started: number, event: string): void {
  console.log(`t+${((performance.now() - started) / 1000).toFixed(3).padStart(7)}s  ${event}`);
}

describe("example: optimized merge and transfer", () => {
  it("spends a merged balance from a cache slot while the merge is still being proven", async () => {
    const { recipient: recipientKeypair, clientConfig } = await setup();
    const client = await createZolanaClient(clientConfig);
    const senderKeypair = await fundedKeypair(clientConfig, SENDER_LAMPORTS);
    const senderSigner = senderKeypair.toSolanaSigner();
    const senderAddress = senderKeypair.shieldedAddress();
    const senderKeys = LocalKeys.fromKeypair(senderKeypair, client.proofService);
    const rentSponsor = await fundedSigner(clientConfig, RENT_SPONSOR_LAMPORTS);
    const sendAsSender = sendAndConfirmFactory(client, senderSigner);
    const sendAsSponsor = sendAndConfirmFactory(client, rentSponsor);
    const assets = new AssetRegistry();

    // 1. The sender registers and opts into merging, so any payer may merge for it.
    const registration = await buildRegistrationTransaction({
      client,
      owner: senderSigner.address,
      address: senderAddress,
    });
    if (registration !== undefined) {
      await signSendAndConfirm(client, registration, [senderSigner]);
    }
    await signSendAndConfirm(
      client,
      await buildSetMergingEnabledTransaction({
        client,
        owner: senderSigner.address,
        enabled: true,
      }),
      [senderSigner],
    );

    // 2. The private balance arrives as one UTXO per deposit.
    const senderViewTag = senderAddress.confidentialViewTag();
    const depositTx = await sendAsSender(
      [
        await depositInstruction({
          tree: client.tree,
          depositor: senderSigner,
          deposits: Array.from({ length: UTXO_COUNT }, () => ({
            asset: DepositAsset.sol(),
            viewTag: senderViewTag,
            recipientOwnerHash: senderAddress.ownerHash(),
            amount: DEPOSIT_AMOUNT,
          })),
        }),
      ],
      { computeUnitLimit: DEPOSIT_COMPUTE_UNIT_LIMIT },
    );
    const deposited = await decryptToBalances({
      keypair: senderKeypair,
      registry: assets,
      transactions: (
        await client.getShieldedTransactionsByTags(
          { tags: [senderViewTag] },
          atSlot(depositTx.slot),
        )
      ).transactions,
    });
    const utxos = deposited.balance(SOL_MINT).utxos;
    expect(utxos).toHaveLength(UTXO_COUNT);
    const total = deposited.balance(SOL_MINT).amount;

    // 3. The cache address is known before the account exists, so the merge proof can name it.
    const cache = await getCacheAddress(rentSponsor.address, CACHE_NONCE);
    const prepared = Merge.fromKeypair(
      senderKeypair,
      utxos.map((utxo) => ProofInputUtxo.fromKeypair(utxo, senderKeypair, {}, client.treeId)),
      client.treeId,
    ).prepare();

    // 4. The merged output is predictable, so the transfer can spend it from the cache slot.
    const mergedInput = ProofInputUtxo.fromKeypair(
      new Utxo({
        owner: senderAddress.signingPublicKey,
        asset: SOL_MINT,
        amount: total,
        blinding: prepared.output.blinding,
      }),
      senderKeypair,
      {},
      client.treeId,
    );
    expect(mergedInput.hash()).toEqual(prepared.outputHash());
    const transfer = new ConfidentialTransfer(
      senderAddress,
      [mergedInput.withCacheSlot(CACHE_SLOT)],
      senderSigner.address,
    ).withOutputTreeId(client.treeId);
    transfer.send(recipientKeypair.shieldedAddress(), SOL_MINT, TRANSFER_AMOUNT);
    const transferProofInputs = transfer.sign(senderKeypair, assets).withReadCache(cache);

    // 5. Both proofs are requested at once; the merge is sent as soon as its proof is ready.
    const started = performance.now();
    log(started, "merge and transfer proofs requested");
    const transferProof = client.proveTransact(transferProofInputs, senderKeys).then((data) => {
      log(started, "transfer proof ready");
      return data;
    });
    const mergeSent = client
      .proveMerge({ prepared, keys: senderKeys, cache: { address: cache, slot: CACHE_SLOT } })
      .then(async (merged) => {
        log(started, "merge proof ready");
        // 6. Cache creation is idempotent, so it rides in the merge transaction.
        await sendAsSponsor(
          [
            await createCacheInstruction({
              payer: rentSponsor,
              data: {
                writeAuthority: rentSponsor.address,
                nonce: CACHE_NONCE,
                treeId: client.treeId,
                expiresAt: CACHE_EXPIRES_AT,
              },
            }),
            await getMergeTransactInstructionAsync({
              inputTree: client.tree,
              outputTree: client.tree,
              payer: rentSponsor,
              userRecord: await userRecordAddress(senderSigner.address),
              cache: { cache, writer: rentSponsor },
              data: merged.data,
            }),
          ],
          { computeUnitLimit: MERGE_TRANSACT_COMPUTE_UNIT_LIMIT },
        );
        log(started, "merge transaction confirmed");
        return merged;
      });
    const [transferData, merged] = await Promise.all([transferProof, mergeSent]);
    expect(merged.outputHash).toEqual(prepared.outputHash());

    // 7. Wait for the slot the transfer proved against to hold the merge output.
    for (let attempt = 0; ; attempt += 1) {
      const account = await client.getAccount(cache);
      const slot =
        account === undefined ? undefined : decodeCache(account.data).utxoHashes[CACHE_SLOT];
      if (slot !== undefined && Buffer.from(slot).equals(Buffer.from(merged.outputHash))) break;
      if (attempt === 120)
        throw new Error(`cache slot ${String(CACHE_SLOT)} never held the merge output`);
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
    log(started, `cache slot ${String(CACHE_SLOT)} holds the merge output`);

    // 8. The transfer reads the cache; the same transaction closes it and refunds the sponsor.
    const sponsorBefore = await client.getBalance(rentSponsor.address);
    const transferTx = await sendAsSender([
      await transactInstruction({
        payer: senderSigner,
        inputTree: client.tree,
        outputTree: client.tree,
        cache: TransactCacheAccounts.read(cache),
        data: transferData,
      }),
      closeCacheInstruction({ cache, rentRecipient: rentSponsor.address, writer: rentSponsor }),
    ]);
    log(started, "transfer transaction confirmed");

    expect(await client.getAccount(cache)).toBeUndefined();
    expect(await client.getBalance(rentSponsor.address)).toBeGreaterThan(sponsorBefore);

    const recipientViewTag = recipientKeypair.shieldedAddress().confidentialViewTag();
    const { transactions } = await client.getShieldedTransactionsByTags(
      { tags: [senderViewTag, recipientViewTag] },
      atSlot(transferTx.slot),
    );
    const senderBalance = await decryptToBalances({
      keypair: senderKeypair,
      registry: assets,
      transactions,
    });
    const recipientBalance = await decryptToBalances({
      keypair: recipientKeypair,
      registry: assets,
      transactions,
    });
    expect(senderBalance.balance(SOL_MINT).amount).toBe(total - TRANSFER_AMOUNT);
    expect(recipientBalance.balance(SOL_MINT).amount).toBe(TRANSFER_AMOUNT);
  }, 600_000);
});
