/// <reference types="node" />

import { SOL_MINT, createZolanaClient } from "@zolana/sdk";
import { atSlot } from "@zolana/sdk/client";
import {
  depositInstruction,
  transactInstruction,
  DepositAsset,
  TransactWithdrawal,
} from "@zolana/sdk/interface";
import { randomBlinding } from "@zolana/sdk/keypair";
import {
  AssetRegistry,
  ConfidentialTransfer,
  ProofInputUtxo,
  decryptToBalances,
  WithdrawalTarget,
} from "@zolana/sdk/transaction";
import { describe, expect, it } from "vitest";

import { sendAndConfirmFactory, setup } from "./setup.js";

const DEPOSIT_AMOUNT = 1_000_000_000n;
const TRANSFER_AMOUNT = 300_000_000n;
const WITHDRAW_AMOUNT = 300_000_000n;

describe("example: deposit, transfer, withdraw", () => {
  it("executes a deposit from public to confidential balance, transfer between confidential balances, and confidential to public balance", async () => {
    const { sender: senderKeypair, recipient: recipientKeypair, spl, clientConfig } = await setup();

    // Connect to localnet; the config is empty (all default ports) unless the
    // test recipe runs the stack on ZOLANA_PORT_OFFSET-shifted URLs.
    const client = await createZolanaClient(clientConfig);
    // devnet: one url serves the RPC, the indexer, and the prover.
    // const client = await createZolanaClient({
    //     solanaRpcUrl: `https://devnet.helius-rpc.com?api-key=${process.env.API_KEY!}`,
    // });

    // Initialize the sender's private wallet and local authority
    // to decrypt transactions and sync balances.
    // The Solana signer and private wallet are derived from the same Ed25519 seed.
    const senderSigner = senderKeypair.toSolanaSigner();
    const senderAddress = senderKeypair.shieldedAddress();
    const recipient = recipientKeypair.shieldedAddress();

    // The SDK hands back instructions; the app owns signing and sending.
    const sendAndConfirm = sendAndConfirmFactory(client, senderSigner);

    // Mints that are registered with Solana Rings for privacy.
    const assets = new AssetRegistry([[spl.assetId, spl.mint]]);

    // Deposit SOL into the sender's private balance.
    // A deposit from a public balance reveals
    // sender, recipient, asset and amount.
    // Alternatively, you can onramp fiat directly to a private balance.

    // 1. Move public SOL into the sender's private balance.
    // The view tag is the sender's Solana public key in confidential rings.
    // Used by the indexer to fetch the sender's outputs.
    const senderViewTag = senderAddress.confidentialViewTag();
    const depositIx = await depositInstruction({
      tree: client.tree,
      depositor: senderSigner,
      deposits: [
        {
          asset: DepositAsset.sol(),
          viewTag: senderViewTag,
          recipientOwnerHash: senderAddress.ownerHash(),
          blinding: randomBlinding(),
          amount: DEPOSIT_AMOUNT,
        },
      ],
    });

    // 2. Send and confirm like any Solana transaction; confirmation yields the landed slot.
    const depositTx = await sendAndConfirm([depositIx]);

    // 3. Fetch transaction outputs from the indexer, gated on the deposit's slot.
    // The indexer returns encrypted outputs by view tag.
    const depositResponse = await client.getShieldedTransactionsByTags(
      { tags: [senderViewTag] },
      atSlot(depositTx.slot),
    );

    // 4. The sender decrypts the transaction outputs locally to read the private balance.
    const balancesAfterDeposit = await decryptToBalances({
      keypair: senderKeypair,
      registry: assets,
      transactions: depositResponse.transactions,
    });
    const depositBalance = balancesAfterDeposit.balance(SOL_MINT);
    expect(depositBalance.amount).toBe(DEPOSIT_AMOUNT);
    expect(depositBalance.utxos).toHaveLength(1);

    // Confidential SOL transfer to the recipient's private balance.
    // A confidential transfer reveals only sender and recipient,
    // not the asset or amount.

    // 1. Select private token accounts (UTXOs) that make up the private balance for the transfer.
    const transferUtxo = depositBalance.utxos[0]!;

    // 2. Prepare the selected UTXOs as inputs for the zero-knowledge proof.
    const transferInput = ProofInputUtxo.fromKeypair(transferUtxo, senderKeypair);

    // 3. Build and sign the confidential transfer.
    // Signing encrypts the asset and amount and produces the proof inputs for the ZK prover.
    const transfer = new ConfidentialTransfer(senderAddress, [transferInput], senderSigner.address);
    transfer.send(recipient, SOL_MINT, TRANSFER_AMOUNT);
    const transferProofInputs = transfer.sign(senderKeypair, assets);

    // 4. Fetch the ZK proof to prove the sender can spend the balance without revealing asset and amount.
    const transferData = await client.proveTransact(transferProofInputs);

    // 5. Build the instruction with the state Merkle tree and Solana accounts required for the transfer.
    // Private transfers move balances only between private token accounts, not public token accounts.
    const transferInstruction = transactInstruction({
      payer: senderSigner,
      inputTree: client.tree,
      outputTree: client.tree,
      data: transferData,
    });

    // 6. Send and confirm like any Solana transaction; confirmation yields the landed slot.
    const transferTx = await sendAndConfirm([transferInstruction]);

    // 7. Fetch the sender's outputs again, gated on the transfer's slot,
    // and read the remaining private balance.
    const transferResponse = await client.getShieldedTransactionsByTags(
      { tags: [senderViewTag] },
      atSlot(transferTx.slot),
    );
    const balancesAfterTransfer = await decryptToBalances({
      keypair: senderKeypair,
      registry: assets,
      transactions: transferResponse.transactions,
    });
    const transferBalance = balancesAfterTransfer.balance(SOL_MINT);
    expect(transferBalance.amount).toBe(DEPOSIT_AMOUNT - TRANSFER_AMOUNT);
    expect(transferBalance.utxos).toHaveLength(1);

    // Withdraw SOL from the sender's private balance to their public balance.
    // A withdrawal reveals the sender, recipient, asset, and amount.

    // 1. Select private token accounts (UTXOs) that make up the private balance for the withdrawal.
    const withdrawalUtxo = transferBalance.utxos[0]!;

    // 2. Prepare the selected UTXOs as inputs for the zero-knowledge proof.
    const withdrawalInput = ProofInputUtxo.fromKeypair(withdrawalUtxo, senderKeypair);

    // 3. Build and sign the private-to-public withdrawal.
    // Signing encrypts the asset and amount of the remaining private balance
    // and produces the proof inputs for the ZK prover.
    const withdrawal = new ConfidentialTransfer(
      senderAddress,
      [withdrawalInput],
      senderSigner.address,
    );
    withdrawal.withdraw(
      SOL_MINT,
      WITHDRAW_AMOUNT,
      WithdrawalTarget.sol({ recipient: senderSigner.address }),
    );
    const withdrawalProofInputs = withdrawal.sign(senderKeypair, assets);

    // 4. Fetch the ZK proof to prove the sender can spend the balance.
    const withdrawalData = await client.proveTransact(withdrawalProofInputs);

    // 5. Build the instruction with the state Merkle tree and Solana accounts required for the withdrawal.
    const withdrawalInstruction = transactInstruction({
      payer: senderSigner,
      inputTree: client.tree,
      outputTree: client.tree,
      withdrawal: TransactWithdrawal.sol({ recipient: senderSigner.address }),
      data: withdrawalData,
    });

    // 6. Send and confirm like any Solana transaction; confirmation yields the landed slot.
    const withdrawalTx = await sendAndConfirm([withdrawalInstruction]);

    // 7. Fetch the sender's outputs again, gated on the withdrawal's slot,
    // and read the remaining private balance.
    const withdrawalResponse = await client.getShieldedTransactionsByTags(
      { tags: [senderViewTag] },
      atSlot(withdrawalTx.slot),
    );
    const balancesAfterWithdrawal = await decryptToBalances({
      keypair: senderKeypair,
      registry: assets,
      transactions: withdrawalResponse.transactions,
    });
    const withdrawalBalance = balancesAfterWithdrawal.balance(SOL_MINT);
    expect(withdrawalBalance.amount).toBe(DEPOSIT_AMOUNT - TRANSFER_AMOUNT - WITHDRAW_AMOUNT);
    expect(withdrawalBalance.utxos).toHaveLength(1);

    // 8. Read remaining private balance and the public balance.
    const solanaBalance = await client.getBalance(senderSigner.address);
    console.log(
      `withdraw private_balance=${withdrawalBalance.amount} ` +
        `solana_balance=${solanaBalance} tx=${withdrawalTx.signature}`,
    );
  }, 600_000);
});
