//! Helpers shared by the two merge examples: the timeline log, packing a merge
//! proof into instruction data, and the assertions both flows make.

use anyhow::{anyhow, Result};
use solana_signature::Signature;
use zolana_client::{
    IndexerRpcConfig, MergeProofResult, Proof, ProofCompressed, Rpc, ShieldedTransaction,
    ZolanaClient,
};
use zolana_interface::instruction::instruction_data::MergeTransactIxData;
use zolana_keypair::ShieldedKeypair;
use zolana_transaction::{
    decrypt_spendable,
    instructions::{merge::MergeProofInputs, transact::canonical_shape},
    AssetRegistry, WalletUtxo, SOL_MINT,
};

/// Prints one timeline entry, so a run shows what was proven when and which
/// transaction went out when.
pub fn log(started: std::time::Instant, event: &str) {
    println!("t+{:>7.3}s  {event}", started.elapsed().as_secs_f64());
}

/// Packs a merge proof into the instruction data the `MergeTransact` builder
/// takes.
pub fn merge_instruction_data(
    merge: &MergeProofResult,
    proof: Proof,
) -> Result<MergeTransactIxData> {
    Ok(merge.instruction_data(ProofCompressed::try_from(proof)?.to_merge_proof()?))
}

pub fn landed_slot<R: Rpc>(client: &ZolanaClient<R>, signature: Signature) -> Result<u64> {
    client
        .get_signature_statuses(vec![signature])?
        .first()
        .and_then(|status| status.as_ref())
        .map(|status| status.slot)
        .ok_or_else(|| anyhow!("transaction {signature} has no confirmed slot"))
}

/// The balance is too wide for one transfer: shape selection reaches five
/// inputs on its own, so these UTXOs have to be consolidated by a merge first.
pub fn assert_balance_needs_merging(utxos: &[WalletUtxo], expected: usize) {
    assert_eq!(
        utxos.len(),
        expected,
        "the wallet should hold {expected} utxos"
    );
    assert!(
        canonical_shape(utxos.len(), 2).is_err(),
        "{} utxos should not fit any auto-selected transfer shape",
        utxos.len()
    );
}

/// A merge at the widest supported input count leaves no padding slot, so no
/// dummy nullifier proofs have to be fetched.
pub fn assert_merge_needs_no_padding(prepared: &MergeProofInputs) -> Result<()> {
    assert!(
        prepared.dummy_nullifiers().is_empty(),
        "a full-width merge should need no padding"
    );
    Ok(())
}

/// The UTXO the transfer spends is exactly the output the merge will produce,
/// which is what lets the transfer be proven before the merge is sent.
pub fn assert_merge_output_is_predicted(
    transfer_input: &WalletUtxo,
    merge: &MergeProofResult,
) -> Result<()> {
    assert_eq!(
        transfer_input.utxo_hash, merge.output_hash,
        "the predicted merge output should match the commitment the merge proves"
    );
    Ok(())
}

/// The recipient received the transfer and the sender kept the change.
pub fn assert_balances_after_transfer<R: Rpc>(
    client: &ZolanaClient<R>,
    sender: &ShieldedKeypair,
    recipient: &ShieldedKeypair,
    assets: &AssetRegistry,
    slot: u64,
    sent: u64,
    kept: u64,
) -> Result<()> {
    let response = client.get_shielded_transactions_by_tags(
        vec![
            sender.shielded_address()?.confidential_view_tag()?,
            recipient.shielded_address()?.confidential_view_tag()?,
        ],
        None,
        Some(50),
        Some(IndexerRpcConfig::at_slot(slot)),
    )?;
    assert_eq!(balance(sender, &response.transactions, assets)?, kept);
    assert_eq!(balance(recipient, &response.transactions, assets)?, sent);
    Ok(())
}

fn balance(
    keypair: &ShieldedKeypair,
    transactions: &[ShieldedTransaction],
    assets: &AssetRegistry,
) -> Result<u64> {
    Ok(decrypt_spendable(keypair, transactions, assets)
        .map_err(|e| anyhow!("decrypt transactions: {e:?}"))?
        .balances
        .get_balance(SOL_MINT)
        .map(|balance| balance.amount)
        .unwrap_or_default())
}
