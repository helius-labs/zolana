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

// 1. The sender deposits SOL into their confidential balance.
// 2. The sender transfers SOL to the recipient's confidential balance.
// 3. The sender withdraws the remaining SOL back to their own Solana account.
fn main() -> Result<()> {
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

    // 1. The sender deposits DEPOSIT_AMOUNT SOL to their confidential balance.
    let sender_balances_after_deposit = {
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
        client.create_and_send_transaction(
            &[deposit_ix],
            sender_solana_keypair.pubkey(),
            &[&sender_solana_keypair],
        )?;

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

    // 2. The sender transfers TRANSFER_AMOUNT SOL to the recipient's confidential balance.
    let sender_balances_after_transfer = {
        // 2.1. Fetch and deserialize (deposits are not encrypted).
        let utxo = sender_balances_after_deposit
            .get_balance(SOL_MINT)
            .expect("failed to fetch deposited utxo")
            .utxos[0]
            .clone();

        // 2.2. Build the confidential transfer to the recipient and sign it.
        let input_utxo = SppProofInputUtxo::new(utxo, &sender_keypair);
        let recipient_address = recipient_keypair.shielded_address()?;
        let mut transfer = ConfidentialTransfer::new(
            sender_shielded_address,
            vec![input_utxo],
            sender_solana_keypair.pubkey(),
        );
        transfer.send(&recipient_address, SOL_MINT, TRANSFER_AMOUNT)?;
        let proof_inputs = transfer.sign(&sender_keypair, &assets)?;

        // 2.3. Prove the transaction and send the transact instruction.
        let transfer_data = client.prove_transact(proof_inputs, Some(IndexerRpcConfig::wait()))?;

        let transfer_ix = Transact {
            payer: sender_solana_keypair.pubkey(),
            tree,
            withdrawal: None,
            data: transfer_data,
        }
        .instruction();
        let signature = client.create_and_send_transaction(
            &[transfer_ix],
            sender_solana_keypair.pubkey(),
            &[&sender_solana_keypair],
        )?;
        client.confirm_private_transaction_sync(signature)?;

        // 2.4. Fetch and decrypt the recipient's balance to confirm the transfer landed.
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

        // 2.5. Fetch and decrypt the sender's remaining balance after the transfer.
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

    // 3. The sender withdraws WITHDRAW_AMOUNT SOL from their confidential balance back
    // to their own Solana account.
    {
        // 3.1. Use the sender's remaining SOL utxo from the transfer step.
        let utxo = sender_balances_after_transfer
            .get_balance(SOL_MINT)
            .and_then(|balance| balance.utxos.first())
            .expect("failed to fetch sender's utxo")
            .clone();

        // 3.2. Build the withdrawal to the sender's own Solana account and sign it.
        let input_utxo = SppProofInputUtxo::new(utxo, &sender_keypair);

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

        // 3.3. Prove the transaction and send the transact instruction, this time
        // with the withdrawal accounts attached.
        let withdrawal_data =
            client.prove_transact(proof_inputs, Some(IndexerRpcConfig::wait()))?;

        let withdraw_ix = Transact {
            payer: sender_solana_keypair.pubkey(),
            tree,
            withdrawal: Some(TransactWithdrawal::Sol(TransactSolWithdrawal {
                recipient: sender_solana_keypair.pubkey(),
            })),
            data: withdrawal_data,
        }
        .instruction();
        let signature = client.create_and_send_transaction(
            &[withdraw_ix],
            sender_solana_keypair.pubkey(),
            &[&sender_solana_keypair],
        )?;
        client.confirm_private_transaction_sync(signature)?;

        // 3.4. Fetch and decrypt the sender's remaining confidential balance after the
        // withdrawal.
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

        // 3.5. Confirm the withdrawn amount landed in the sender's Solana balance.
        let solana_balance = client.get_balance(sender_solana_keypair.pubkey())?;
        println!("withdraw solana_balance={solana_balance} tx={signature}");
    }
    Ok(())
}
