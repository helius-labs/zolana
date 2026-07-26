use anyhow::{anyhow, Result};
use client_example::{setup, SetupContext};
use solana_signer::Signer;
use zolana_client::{IndexerRpcConfig, Rpc, SolanaRpc, ZolanaClient};
use zolana_interface::instruction::{Deposit, Transact, TransactSolWithdrawal, TransactWithdrawal};
use zolana_keypair::random_blinding;
use zolana_transaction::{
    decrypt_transactions,
    instructions::{
        transact::{ConfidentialTransfer, WithdrawalTarget},
        types::SppProofInputUtxo,
    },
    AssetRegistry, SOL_MINT,
};

const DEPOSIT_AMOUNT: u64 = 1_000_000_000;
const TRANSFER_AMOUNT: u64 = 300_000_000;
const WITHDRAW_AMOUNT: u64 = 300_000_000;

// Deposit SOL into a private balance, transfer confidentially to a second
// wallet, and withdraw to a public balance.
fn main() -> Result<()> {
    // Load the fee payer and localnet settings.
    let SetupContext {
        rpc_url,
        indexer_url,
        prover_url,
        tree,
        sender: sender_keypair,
        recipient: recipient_keypair,
    } = setup()?;

    let client = ZolanaClient::from_urls(SolanaRpc::new(rpc_url), &indexer_url, prover_url, tree);
    let assets = AssetRegistry::default();

    let sender_solana_keypair = sender_keypair.to_solana_keypair()?;
    let sender_shielded_address = sender_keypair.shielded_address()?;

    // Deposit to a private balance.
    let sender_balances_after_deposit = {
        // 1. Move public SOL into the sender's private balance.
        let deposit_ix = Deposit {
            tree,
            depositor: sender_solana_keypair.pubkey(),
            spl: None,
            view_tag: sender_shielded_address.confidential_view_tag()?,
            owner: sender_shielded_address.owner_hash()?,
            blinding: random_blinding(),
            amount: DEPOSIT_AMOUNT,
            utxo_data: None,
            memo: None,
        }
        .instruction();

        // 2. Send like any Solana transaction.
        client.create_and_send_transaction(
            &[deposit_ix],
            sender_solana_keypair.pubkey(),
            &[&sender_solana_keypair],
        )?;

        // 3. Read the balance from the indexer. A deposit is a public Solana
        // transaction that reveals the asset and amount.
        let sender_tag = sender_shielded_address.confidential_view_tag()?;
        let response = client.get_shielded_transactions_by_tags(
            vec![sender_tag],
            None,
            Some(50),
            Some(IndexerRpcConfig::wait()),
        )?;

        let balances = decrypt_transactions(&sender_keypair, &response.transactions, &assets)
            .map_err(|e| anyhow!("decrypt sender transactions: {e:?}"))?;

        let balance = balances
            .get_balance(SOL_MINT)
            .expect("failed to fetch sender's utxo");
        assert_eq!(balance.amount, DEPOSIT_AMOUNT);
        assert_eq!(balance.utxos.len(), 1);

        balances
    };

    // Transfer to a private balance.
    let sender_balances_after_transfer = {
        // 1. Select Private Token Accounts to spend.
        let utxo = sender_balances_after_deposit
            .get_balance(SOL_MINT)
            .expect("failed to fetch deposited utxo")
            .utxos[0]
            .clone();
        let input_utxo = SppProofInputUtxo::new(utxo, &sender_keypair);

        // 2. Build and sign the transfer; signing encrypts asset and amount.
        let recipient_address = recipient_keypair.shielded_address()?;
        let mut transfer = ConfidentialTransfer::new(
            sender_shielded_address,
            vec![input_utxo],
            sender_solana_keypair.pubkey(),
        );
        transfer.send(&recipient_address, SOL_MINT, TRANSFER_AMOUNT)?;
        let proof_inputs = transfer.sign(&sender_keypair, &assets)?;

        // 3. Fetch zk proof to prove the sender can spend the balance without revealing asset and amount.
        let transfer_data = client.prove_transact(proof_inputs, Some(IndexerRpcConfig::wait()))?;

        // 4. Wrap the proof and encrypted outputs in a single Solana instruction.
        let transfer_ix = Transact {
            payer: sender_solana_keypair.pubkey(),
            tree,
            withdrawal: None,
            data: transfer_data,
        }
        .instruction();

        // 5. Send and confirm like any Solana transaction.
        let signature = client.create_and_send_transaction(
            &[transfer_ix],
            sender_solana_keypair.pubkey(),
            &[&sender_solana_keypair],
        )?;
        client.confirm_private_transaction_sync(signature)?;

        // Fetch and decrypt the recipient's balance.
        let recipient_tag = recipient_address.confidential_view_tag()?;
        let response = client.get_shielded_transactions_by_tags(
            vec![recipient_tag],
            None,
            None,
            Some(IndexerRpcConfig::wait()),
        )?;

        let recipient_balances =
            decrypt_transactions(&recipient_keypair, &response.transactions, &assets)
                .map_err(|e| anyhow!("decrypt recipient transactions: {e:?}"))?;
        let recipient_balance = recipient_balances
            .get_balance(SOL_MINT)
            .expect("failed to fetch recipient's utxo");
        assert_eq!(recipient_balance.amount, TRANSFER_AMOUNT);
        assert_eq!(recipient_balance.utxos.len(), 1);
        println!(
            "transfer recipient_balance={} tx={signature}",
            recipient_balance.amount
        );

        // Read the sender's remaining private balance from the indexer.
        let sender_tag = sender_shielded_address.confidential_view_tag()?;
        let response = client.get_shielded_transactions_by_tags(
            vec![sender_tag],
            None,
            Some(50),
            Some(IndexerRpcConfig::wait()),
        )?;
        let sender_balances =
            decrypt_transactions(&sender_keypair, &response.transactions, &assets)
                .map_err(|e| anyhow!("decrypt sender transactions: {e:?}"))?;
        let sender_balance = sender_balances
            .get_balance(SOL_MINT)
            .expect("failed to fetch sender's utxo");
        assert_eq!(sender_balance.amount, DEPOSIT_AMOUNT - TRANSFER_AMOUNT);
        assert_eq!(sender_balance.utxos.len(), 1);

        sender_balances
    };

    // Withdraw to a public balance.
    {
        // 1. Select Private Token Accounts to spend.
        let utxo = sender_balances_after_transfer
            .get_balance(SOL_MINT)
            .and_then(|balance| balance.utxos.first())
            .expect("failed to fetch sender's utxo")
            .clone();
        let input_utxo = SppProofInputUtxo::new(utxo, &sender_keypair);

        // 2. Build and sign the withdrawal; signing encrypts the change that stays private.
        let mut withdrawal = ConfidentialTransfer::new(
            sender_shielded_address,
            vec![input_utxo],
            sender_solana_keypair.pubkey(),
        );
        withdrawal.withdraw(
            SOL_MINT,
            WITHDRAW_AMOUNT,
            WithdrawalTarget::Sol {
                recipient: sender_solana_keypair.pubkey(),
            },
        )?;
        let proof_inputs = withdrawal.sign(&sender_keypair, &assets)?;

        // 3. Fetch zk proof to prove the sender can spend the balance.
        let withdrawal_data =
            client.prove_transact(proof_inputs, Some(IndexerRpcConfig::wait()))?;

        // 4. Combine the proof and the withdrawal accounts in a single Solana instruction.
        let withdraw_ix = Transact {
            payer: sender_solana_keypair.pubkey(),
            tree,
            withdrawal: Some(TransactWithdrawal::Sol(TransactSolWithdrawal {
                recipient: sender_solana_keypair.pubkey(),
            })),
            data: withdrawal_data,
        }
        .instruction();

        // 5. Send and confirm like any Solana transaction.
        let signature = client.create_and_send_transaction(
            &[withdraw_ix],
            sender_solana_keypair.pubkey(),
            &[&sender_solana_keypair],
        )?;
        client.confirm_private_transaction_sync(signature)?;

        // Read the sender's remaining private balance from the indexer.
        let sender_tag = sender_shielded_address.confidential_view_tag()?;
        let response = client.get_shielded_transactions_by_tags(
            vec![sender_tag],
            None,
            Some(50),
            Some(IndexerRpcConfig::wait()),
        )?;
        let sender_balances =
            decrypt_transactions(&sender_keypair, &response.transactions, &assets)
                .map_err(|e| anyhow!("decrypt sender transactions: {e:?}"))?;
        let sender_balance = sender_balances
            .get_balance(SOL_MINT)
            .expect("failed to fetch sender's utxo");
        assert_eq!(
            sender_balance.amount,
            DEPOSIT_AMOUNT - TRANSFER_AMOUNT - WITHDRAW_AMOUNT
        );
        assert_eq!(sender_balance.utxos.len(), 1);

        // Report the public SOL withdrawal.
        let solana_balance = client.get_balance(sender_solana_keypair.pubkey())?;
        println!("withdraw solana_balance={solana_balance} tx={signature}");
    }
    Ok(())
}
