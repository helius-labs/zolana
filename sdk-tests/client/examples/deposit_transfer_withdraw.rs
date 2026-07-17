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

// 1. Alice deposits SOL into her confidential balance.
// 2. Alice transfers SOL to Bob's confidential balance.
// 3. Alice withdraws the remaining SOL back to her own Solana account.
fn main() -> Result<()> {
    let SetupContext {
        rpc_url,
        indexer_url,
        prover_url,
        tree,
        alice: alice_keypair,
        bob: bob_keypair,
    } = setup()?;

    let client = ZolanaClient::from_urls(SolanaRpc::new(rpc_url), &indexer_url, prover_url, tree);
    let assets = AssetRegistry::default();

    let alice_solana_keypair = alice_keypair.to_solana_keypair()?;
    let alice_shielded_address = alice_keypair.shielded_address()?;

    // 1. Alice deposits DEPOSIT_AMOUNT SOL to her confidential balance.
    let alice_balances_after_deposit = {
        let deposit_ix = Deposit {
            tree,
            depositor: alice_solana_keypair.pubkey(),
            spl: None,
            view_tag: alice_shielded_address.confidential_view_tag()?,
            owner: alice_shielded_address.owner_hash()?,
            blinding: random_blinding(),
            amount: DEPOSIT_AMOUNT,
            utxo_data: None,
            memo: None,
        }
        .instruction();
        client.create_and_send_transaction(
            &[deposit_ix],
            alice_solana_keypair.pubkey(),
            &[&alice_solana_keypair],
        )?;

        let alice_tag = alice_shielded_address.confidential_view_tag()?;
        let response = client.get_shielded_transactions_by_tags(
            vec![alice_tag],
            None,
            Some(50),
            Some(IndexerRpcConfig::wait()),
        )?;

        let balances = decrypt_transactions(&alice_keypair, &response.transactions, &assets)
            .map_err(|e| anyhow!("decrypt alice transactions: {e:?}"))?;

        let balance = balances
            .get_balance(SOL_MINT)
            .expect("failed to fetch alice's utxo");
        assert_eq!(balance.amount, DEPOSIT_AMOUNT);
        assert_eq!(balance.utxos.len(), 1);

        balances
    };

    // 2. Alice transfers TRANSFER_AMOUNT SOL to Bob's confidential balance.
    let alice_balances_after_transfer = {
        // 2.1. Fetch and deserialize (deposits are not encrypted).
        let utxo = alice_balances_after_deposit
            .get_balance(SOL_MINT)
            .expect("failed to fetch deposited utxo")
            .utxos[0]
            .clone();

        // 2.2. Build the confidential transfer to Bob and sign it.
        let input_utxo = SppProofInputUtxo::new(utxo, &alice_keypair);
        let bob_address = bob_keypair.shielded_address()?;
        let mut transfer = ConfidentialTransfer::new(
            alice_shielded_address,
            vec![input_utxo],
            alice_solana_keypair.pubkey(),
        );
        transfer.send(&bob_address, SOL_MINT, TRANSFER_AMOUNT)?;
        let proof_inputs = transfer.sign(&alice_keypair, &assets)?;

        // 2.3. Prove the transaction and send the transact instruction.
        let transfer_data = client.prove_transact(proof_inputs, Some(IndexerRpcConfig::wait()))?;

        let transfer_ix = Transact {
            payer: alice_solana_keypair.pubkey(),
            tree,
            withdrawal: None,
            data: transfer_data,
        }
        .instruction();
        let signature = client.create_and_send_transaction(
            &[transfer_ix],
            alice_solana_keypair.pubkey(),
            &[&alice_solana_keypair],
        )?;
        client.confirm_private_transaction_sync(signature)?;

        // 2.4. Fetch and decrypt Bob's balance to confirm the transfer landed.
        let bob_tag = bob_address.confidential_view_tag()?;
        let response = client.get_shielded_transactions_by_tags(
            vec![bob_tag],
            None,
            None,
            Some(IndexerRpcConfig::wait()),
        )?;

        let bob_balances = decrypt_transactions(&bob_keypair, &response.transactions, &assets)
            .map_err(|e| anyhow!("decrypt bob transactions: {e:?}"))?;
        let bob_balance = bob_balances
            .get_balance(SOL_MINT)
            .expect("failed to fetch bob's utxo");
        assert_eq!(bob_balance.amount, TRANSFER_AMOUNT);
        assert_eq!(bob_balance.utxos.len(), 1);
        println!("transfer bob_balance={} tx={signature}", bob_balance.amount);

        // 2.5. Fetch and decrypt Alice's remaining balance after the transfer.
        let alice_tag = alice_shielded_address.confidential_view_tag()?;
        let response = client.get_shielded_transactions_by_tags(
            vec![alice_tag],
            None,
            Some(50),
            Some(IndexerRpcConfig::wait()),
        )?;
        let alice_balances = decrypt_transactions(&alice_keypair, &response.transactions, &assets)
            .map_err(|e| anyhow!("decrypt alice transactions: {e:?}"))?;
        let alice_balance = alice_balances
            .get_balance(SOL_MINT)
            .expect("failed to fetch alice's utxo");
        assert_eq!(alice_balance.amount, DEPOSIT_AMOUNT - TRANSFER_AMOUNT);
        assert_eq!(alice_balance.utxos.len(), 1);

        alice_balances
    };

    // 3. Alice withdraws WITHDRAW_AMOUNT SOL from her confidential balance back
    // to her own Solana account.
    {
        // 3.1. Use Alice's remaining SOL utxo from the transfer step.
        let utxo = alice_balances_after_transfer
            .get_balance(SOL_MINT)
            .and_then(|balance| balance.utxos.first())
            .expect("failed to fetch alice's utxo")
            .clone();

        // 3.2. Build the withdrawal to Alice's own Solana account and sign it.
        let input_utxo = SppProofInputUtxo::new(utxo, &alice_keypair);

        let mut withdrawal = ConfidentialTransfer::new(
            alice_shielded_address,
            vec![input_utxo],
            alice_solana_keypair.pubkey(),
        );
        withdrawal.withdraw(
            SOL_MINT,
            WITHDRAW_AMOUNT,
            WithdrawalTarget::Sol {
                user_sol_account: alice_solana_keypair.pubkey(),
            },
        )?;
        let proof_inputs = withdrawal.sign(&alice_keypair, &assets)?;

        // 3.3. Prove the transaction and send the transact instruction, this time
        // with the withdrawal accounts attached.
        let withdrawal_data =
            client.prove_transact(proof_inputs, Some(IndexerRpcConfig::wait()))?;

        let withdraw_ix = Transact {
            payer: alice_solana_keypair.pubkey(),
            tree,
            withdrawal: Some(TransactWithdrawal::Sol(TransactSolWithdrawal {
                recipient: alice_solana_keypair.pubkey(),
            })),
            data: withdrawal_data,
        }
        .instruction();
        let signature = client.create_and_send_transaction(
            &[withdraw_ix],
            alice_solana_keypair.pubkey(),
            &[&alice_solana_keypair],
        )?;
        client.confirm_private_transaction_sync(signature)?;

        // 3.4. Fetch and decrypt Alice's remaining confidential balance after the
        // withdrawal.
        let alice_tag = alice_shielded_address.confidential_view_tag()?;
        let response = client.get_shielded_transactions_by_tags(
            vec![alice_tag],
            None,
            Some(50),
            Some(IndexerRpcConfig::wait()),
        )?;
        let alice_balances = decrypt_transactions(&alice_keypair, &response.transactions, &assets)
            .map_err(|e| anyhow!("decrypt alice transactions: {e:?}"))?;
        let alice_balance = alice_balances
            .get_balance(SOL_MINT)
            .expect("failed to fetch alice's utxo");
        assert_eq!(
            alice_balance.amount,
            DEPOSIT_AMOUNT - TRANSFER_AMOUNT - WITHDRAW_AMOUNT
        );
        assert_eq!(alice_balance.utxos.len(), 1);

        // 3.5. Confirm the withdrawn amount landed in Alice's Solana balance.
        let solana_balance = client.get_balance(alice_solana_keypair.pubkey())?;
        println!("withdraw solana_balance={solana_balance} tx={signature}");
    }
    Ok(())
}
