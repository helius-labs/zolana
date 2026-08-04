/// <reference types="node" />

import { DEFAULT_TREE_ADDRESS, SOL_MINT, createZolanaClient } from "@zolana/sdk";
import {
  DepositAsset,
  TransactWithdrawal,
  depositInstruction,
  transactInstruction,
} from "@zolana/sdk/interface";
import { randomBlinding } from "@zolana/sdk/keypair";
import {
  AssetRegistry,
  ConfidentialTransfer,
  ProofInputUtxo,
  WithdrawalTarget,
  decryptToBalances,
} from "@zolana/sdk/transaction";
import { describe, it } from "vitest";

import { sendAndConfirmFactory, setup } from "./setup.js";

const DEPOSIT_AMOUNT = 1_000_000_000n;
const TRANSFER_AMOUNT = 300_000_000n;
const WITHDRAW_AMOUNT = 300_000_000n;

describe("example: deposit, transfer, withdraw", () => {
  it("executes a deposit from public to confidential balance, transfer between confidential balances, and confidential to public balance", async () => {
    const { sender: senderKeypair, recipient: recipientKeypair, spl } = await setup();

    // No url reaches the local validator, photon, and prover on their own ports.
    const client = await createZolanaClient({});
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
    const senderViewTag = senderAddress.confidentialViewTag();
    const depositIx = await depositInstruction({
      tree: DEFAULT_TREE_ADDRESS,
      sender: senderSigner,
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

    // 2. Send like any Solana transaction.
    const depositSignature = await sendAndConfirm([depositIx]);
    // Photon indexes asynchronously, so wait for this exact signature before
    // reading a balance that depends on it.
    await client.confirmPrivateTransaction(depositSignature);

    // 3. Fetch transaction outputs from the indexer.
    // The indexer returns encrypted outputs by view tag.
    const depositResponse = await client.getShieldedTransactionsByTags(senderViewTag);

    // 4. The sender decrypts the transaction outputs locally to read the private balance.
    const balancesAfterDeposit = decryptToBalances({
      keypair: senderKeypair,
      registry: assets,
      transactions: depositResponse.transactions,
    });
    const depositBalance = balancesAfterDeposit.balance(SOL_MINT);

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
      feePayer: senderSigner,
      inputTree: DEFAULT_TREE_ADDRESS,
      outputTree: DEFAULT_TREE_ADDRESS,
      data: transferData,
    });

    // 6. Send and confirm like any Solana transaction.
    const transferSignature = await sendAndConfirm([transferInstruction]);
    await client.confirmPrivateTransaction(transferSignature);

    // 7. Fetch the sender's outputs again and read the remaining private balance.
    const transferResponse = await client.getShieldedTransactionsByTags(senderViewTag);
    const balancesAfterTransfer = decryptToBalances({
      keypair: senderKeypair,
      registry: assets,
      transactions: transferResponse.transactions,
    });
    const transferBalance = balancesAfterTransfer.balance(SOL_MINT);

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
      feePayer: senderSigner,
      inputTree: DEFAULT_TREE_ADDRESS,
      outputTree: DEFAULT_TREE_ADDRESS,
      withdrawal: TransactWithdrawal.sol({ recipient: senderSigner.address }),
      data: withdrawalData,
    });

    // 6. Send and confirm like any Solana transaction.
    const withdrawalSignature = await sendAndConfirm([withdrawalInstruction]);
    await client.confirmPrivateTransaction(withdrawalSignature);

    // 7. Fetch the sender's outputs again and read the remaining private balance.
    const withdrawalResponse = await client.getShieldedTransactionsByTags(senderViewTag);
    const balancesAfterWithdrawal = decryptToBalances({
      keypair: senderKeypair,
      registry: assets,
      transactions: withdrawalResponse.transactions,
    });
    const withdrawalBalance = balancesAfterWithdrawal.balance(SOL_MINT);

    // 8. Read remaining private balance and the public balance.
    const solanaBalance = await client.getBalance(senderSigner.address);
    console.log(
      `withdraw private_balance=${withdrawalBalance.amount} ` +
        `solana_balance=${solanaBalance} tx=${withdrawalSignature}`,
    );
  }, 600_000);
});
