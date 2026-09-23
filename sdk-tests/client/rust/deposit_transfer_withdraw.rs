use anyhow::{anyhow, Result};
use client_example::{setup, SetupContext};
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{IndexerRpcConfig, Rpc, SolanaRpc, ZolanaClient};
use zolana_interface::pda;
use zolana_program::instruction::{
    AssetDeposit, Deposit, DepositAsset, Transact, TransactInterfaceTransferAccounts,
    TransactSolTransferAccounts,
};
use zolana_transaction::{
    decrypt_spendable,
    instructions::transact::{ConfidentialTransaction, Shape},
    Address, AssetBalance, AssetRegistry, Balances, WalletUtxo, SOL_MINT,
};

/// Step 2 of the flow for the single-input case: the largest note that covers
/// `amount`.
///
/// Not `utxos.first()`. A padded transfer leaves the sender a zero-amount note
/// in slot 0 -- the SPL change slot, empty because the transfer moves no SPL
/// asset -- and notes come back in publication order, so `first()` picks the
/// one worth nothing and the next transaction spends an input slot on it.
/// Zero-amount notes are real UTXOs the balance reports; they are just never
/// what you want to spend.
fn select_input_utxo(balances: &Balances, mint: Address, amount: u64) -> Result<WalletUtxo> {
    balances
        .get_balance(mint)
        .into_iter()
        .flat_map(|balance| balance.utxos.iter())
        .filter(|utxo| utxo.utxo.amount >= amount)
        .max_by_key(|utxo| utxo.utxo.amount)
        .cloned()
        .ok_or_else(|| anyhow!("no private note covers {amount} of {mint}"))
}

/// How many of a balance's notes are worth nothing. A padded confidential
/// transaction leaves one behind every time, and no path reclaims them.
fn zero_amount_notes(balance: &AssetBalance) -> usize {
    balance
        .utxos
        .iter()
        .filter(|utxo| utxo.utxo.amount == 0)
        .count()
}

const DEPOSIT_AMOUNT: u64 = 1_000_000_000;
const TRANSFER_AMOUNT: u64 = 300_000_000;
const WITHDRAW_AMOUNT: u64 = 300_000_000;

fn main() -> Result<()> {
    let SetupContext {
        rpc_url,
        indexer_url,
        prover_url,
        tree_id,
        sender,
        recipient_address,
    } = setup()?;

    // Load the funded fee payer and localnet settings, then connect.
    let client = ZolanaClient::from_urls(SolanaRpc::new(rpc_url), &indexer_url, prover_url)?;

    // Mints that are registered with Solana Rings for privacy.
    let assets = AssetRegistry::default();
    // SPL: assets.insert(spl.asset_id, spl.mint)?;

    // Initialize the sender's private wallet and local authority
    // to decrypt transactions and sync balances.
    // The Solana signer and private wallet are derived from the same Ed25519 seed.
    let sender_shielded_address = sender.shielded_address()?;

    // Deposit SOL into the sender's private balance.
    // A deposit from a public balance reveals
    // sender, recipient, asset and amount.
    // Alternatively, you can onramp fiat directly to a private balance.

    // A deposit is public, so it has no UTXOs to select and nothing to
    // encrypt: it starts at step 6 of the flow, building the instruction.
    // 6. Build the deposit instruction.
    let sender_balances_after_deposit = {
        let deposit_ix = Deposit {
            // The tree's only representation is its raw id; the account is
            // derived here, where the derivation is visible.
            tree: pda::tree(tree_id),
            depositor: sender.pubkey(),
            deposits: vec![AssetDeposit {
                asset: DepositAsset::Sol,
                // SPL: asset: DepositAsset::Spl(zolana_program::instruction::DepositSplAccounts {
                // SPL:     mint: spl.mint,
                // SPL:     user_token: spl.user_token_account,
                // SPL:     token_program: spl.token_program,
                // SPL: }),
                view_tag: sender_shielded_address.confidential_view_tag()?,
                owner: sender_shielded_address.owner_hash()?,
                amount: DEPOSIT_AMOUNT,
                utxo_data: None,
                memo: None,
            }],
        }
        .instruction()?;

        // 7 and 8. Sign, send and confirm. One call does all three here, and
        // the landed slot gates
        // the indexer fetch below.
        let signature = client.create_and_send_transaction(
            &[deposit_ix],
            sender.pubkey(),
            &[&sender],
            client.compute_budget(),
        )?;
        let slot = landed_slot(&client, signature)?;

        // 1.1. Request the encrypted UTXOs by view tag, gated on that slot.
        // The indexer returns encrypted outputs by view tag, the sender's public key in Confidential Rings.
        let sender_tag = sender_shielded_address.confidential_view_tag()?;
        let response = client.get_shielded_transactions_by_tags(
            vec![sender_tag],
            None,
            Some(50),
            Some(IndexerRpcConfig::at_slot(slot)),
        )?;

        // 1.2. Decrypt them. Each note comes back as a `WalletUtxo`
        // carrying its commitment, nullifier, tree id and leaf index, so
        // nothing downstream needs a key, or a second lookup, to spend it.
        let balances = decrypt_spendable(&sender, &response.transactions, &assets)
            .map_err(|e| anyhow!("decrypt sender transactions: {e:?}"))?
            .balances;

        let sender_balance = balances
            .get_balance(SOL_MINT)
            // SPL: .get_balance(spl.mint)
            .expect("failed to fetch sender's utxo");
        assert_eq!(sender_balance.amount, DEPOSIT_AMOUNT);
        // A proofless deposit publishes one output, so one note.
        assert_eq!(sender_balance.utxos.len(), 1);

        balances
    };

    // Confidential SOL transfer to the recipient's private balance.
    // A confidential transfer reveals only sender and recipient,
    // not the asset or amount.
    let sender_balances_after_transfer = {
        // 2. Select the input UTXOs, by value rather than by position.
        let transfer_utxo =
            select_input_utxo(&sender_balances_after_deposit, SOL_MINT, TRANSFER_AMOUNT)?;
        // SPL: select_input_utxo(&sender_balances_after_deposit, spl.mint, TRANSFER_AMOUNT)?;

        // 3. Create the output, then finalize both input and output slots.
        let mut transfer =
            ConfidentialTransaction::new(vec![transfer_utxo.clone()], sender.pubkey())?
                .with_output_tree_id(tree_id)?;
        transfer.transfer_sol(&recipient_address, TRANSFER_AMOUNT)?;
        transfer.pad_utxos(Shape::IN2_OUT3, &sender_shielded_address)?;
        // 4. Encrypt each output for its owner.
        let proof_inputs = transfer.encrypt(&sender)?;

        // 5. Prove. The witnesses are fetched inside this call, each under the
        // tree id its input carries, so no tree is named here.
        let transfer_data = client.prove_transact(proof_inputs, None, &sender)?;

        // 6. Build the instruction. The accounts come from the ids: one input
        // tree per spent note, and the tree the outputs were hashed under.
        let transfer_ix = Transact {
            payer: sender.pubkey(),
            input_trees: vec![pda::tree(transfer_utxo.tree_id())],
            output_tree: pda::tree(tree_id),
            owner_signers: Vec::new(),
            interface_transfer_accounts: Vec::new(),
            data: transfer_data,
        }
        .instruction();

        // 7 and 8. Sign, send and confirm; confirmation yields the landed slot.
        let signature = client.create_and_send_transaction(
            &[transfer_ix],
            sender.pubkey(),
            &[&sender],
            client.compute_budget(),
        )?;
        let slot = landed_slot(&client, signature)?;

        // 1 again. Sync, gated on the transfer's slot, and read the remaining
        // private balance.
        let sender_tag = sender_shielded_address.confidential_view_tag()?;
        let response = client.get_shielded_transactions_by_tags(
            vec![sender_tag],
            None,
            Some(50),
            Some(IndexerRpcConfig::at_slot(slot)),
        )?;
        let sender_balances = decrypt_spendable(&sender, &response.transactions, &assets)
            .map_err(|e| anyhow!("decrypt sender transactions: {e:?}"))?
            .balances;
        let sender_balance = sender_balances
            .get_balance(SOL_MINT)
            // SPL: .get_balance(spl.mint)
            .expect("failed to fetch sender's utxo");
        assert_eq!(sender_balance.amount, DEPOSIT_AMOUNT - TRANSFER_AMOUNT);
        // The sender owns the change and the trailing zero-value padding note.
        assert_eq!(sender_balance.utxos.len(), 2);
        assert_eq!(zero_amount_notes(sender_balance), 1);

        sender_balances
    };

    // Withdraw SOL back to the sender's public balance.
    // A withdrawal from a confidential balance reveals
    // sender, recipient, asset and amount.
    {
        // 2. Select the input UTXOs by value.
        let withdrawal_utxo =
            select_input_utxo(&sender_balances_after_transfer, SOL_MINT, WITHDRAW_AMOUNT)?;
        // SPL: select_input_utxo(&sender_balances_after_transfer, spl.mint, WITHDRAW_AMOUNT)?;

        // 3. Add the public withdrawal and finalize its private change.
        let mut withdrawal =
            ConfidentialTransaction::new(vec![withdrawal_utxo.clone()], sender.pubkey())?
                .with_output_tree_id(tree_id)?;
        withdrawal.withdraw_sol(WITHDRAW_AMOUNT, sender.pubkey())?;
        withdrawal.pad_utxos(Shape::IN2_OUT2, &sender_shielded_address)?;
        // 4. Encrypt the outputs.
        let proof_inputs = withdrawal.encrypt(&sender)?;

        // 5. Prove.
        let withdrawal_data = client.prove_transact(proof_inputs, None, &sender)?;

        // 6. Build the instruction, proof and settlement accounts together.
        let withdraw_ix = Transact {
            payer: sender.pubkey(),
            input_trees: vec![pda::tree(withdrawal_utxo.tree_id())],
            output_tree: pda::tree(tree_id),
            owner_signers: Vec::new(),
            interface_transfer_accounts: vec![TransactInterfaceTransferAccounts::Sol(
                TransactSolTransferAccounts {
                    recipient: sender.pubkey(),
                },
            )],
            // SPL: interface_transfer_accounts: vec![
            // SPL:     TransactInterfaceTransferAccounts::SplWithdrawal(
            // SPL:         zolana_program::instruction::TransactSplWithdrawalAccounts {
            // SPL:             mint: spl.mint,
            // SPL:             vault: spl.vault,
            // SPL:             user_token_account: spl.user_token_account,
            // SPL:             token_program: spl.token_program,
            // SPL:         },
            // SPL:     ),
            // SPL: ],
            data: withdrawal_data,
        }
        .instruction();

        // 7 and 8. Sign, send and confirm.
        let signature = client.create_and_send_transaction(
            &[withdraw_ix],
            sender.pubkey(),
            &[&sender],
            client.compute_budget(),
        )?;
        let slot = landed_slot(&client, signature)?;

        // 1 again. Sync, gated on the withdrawal's slot, and read the
        // remaining private balance.
        let sender_tag = sender_shielded_address.confidential_view_tag()?;
        let response = client.get_shielded_transactions_by_tags(
            vec![sender_tag],
            None,
            Some(50),
            Some(IndexerRpcConfig::at_slot(slot)),
        )?;
        let sender_balances = decrypt_spendable(&sender, &response.transactions, &assets)
            .map_err(|e| anyhow!("decrypt sender transactions: {e:?}"))?
            .balances;
        let sender_balance = sender_balances
            .get_balance(SOL_MINT)
            // SPL: .get_balance(spl.mint)
            .expect("failed to fetch sender's utxo");
        assert_eq!(
            sender_balance.amount,
            DEPOSIT_AMOUNT - TRANSFER_AMOUNT - WITHDRAW_AMOUNT
        );
        // Three: the change, plus one zero-amount note from each of the two
        // confidential transactions. Nothing reclaims them, so they accumulate
        // one per transfer for as long as the wallet keeps transacting.
        assert_eq!(sender_balance.utxos.len(), 3);
        assert_eq!(zero_amount_notes(sender_balance), 2);

        // The public side, for comparison: the withdrawal moved value out.
        let solana_balance = client.get_balance(sender.pubkey())?;
        println!("withdraw solana_balance={solana_balance} tx={signature}");
        // SPL: println!(
        // SPL:     "withdraw user_token={} tx={signature}",
        // SPL:     spl.user_token_account,
        // SPL: );
    }
    Ok(())
}

/// Slot the confirmed transaction landed in, which drives the indexer
/// freshness gate on the fetches that read the transaction back.
fn landed_slot(client: &ZolanaClient<SolanaRpc>, signature: Signature) -> Result<u64> {
    client
        .get_signature_statuses(vec![signature])?
        .first()
        .and_then(|status| status.as_ref())
        .map(|status| status.slot)
        .ok_or_else(|| anyhow!("transaction status missing after confirmation"))
}
