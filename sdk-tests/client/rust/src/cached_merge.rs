//! Helpers for the cached merge + transfer example: building the proof inputs
//! for a transfer that spends out of a cache, and polling the cache account.

use anyhow::{anyhow, Result};
use solana_address::Address;
use solana_instruction::Instruction;
use zolana_client::{
    assemble, transaction_size, AssembledTransfer, ComputeBudgetConfig, Rpc, ZolanaClient,
};
use zolana_interface::state::cache::CacheAccount;
use zolana_program::instruction::MergeTransact;
use zolana_transaction::instructions::{merge::MergeProofInputs, transact::SppProofInputs};

pub fn assemble_cached_transfer<R: Rpc>(
    client: &ZolanaClient<R>,
    tree: Address,
    proof_inputs: SppProofInputs,
) -> Result<AssembledTransfer> {
    let nullifier_proofs = client
        .get_non_inclusion_proofs(tree, proof_inputs.dummy_nullifiers(), None)?
        .proofs;
    Ok(assemble(proof_inputs, &[], &nullifier_proofs)?)
}

/// Polls the cache account until `slot` holds `commitment`. A production client
/// subscribes to the account instead; with several merges sharing one cache it
/// checks the slots it needs rather than counting confirmations.
pub fn wait_for_cache_commitment<R: Rpc>(
    client: &ZolanaClient<R>,
    cache: Address,
    slot: u8,
    commitment: &[u8; 32],
) -> Result<CacheAccount> {
    for _ in 0..120 {
        if let Some(account) = client.get_account(cache)? {
            let state: CacheAccount = *bytemuck::from_bytes(&account.data);
            if state.utxo_hashes.get(usize::from(slot)) == Some(commitment) {
                return Ok(state);
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    Err(anyhow!("cache slot {slot} did not receive the commitment"))
}

/// The transfer closed the cache in the same transaction and the rent went back
/// to the sponsor that funded it.
pub fn assert_cache_closed_and_refunded<R: Rpc>(
    client: &ZolanaClient<R>,
    cache: Address,
    rent_sponsor: Address,
    sponsor_before: u64,
) -> Result<()> {
    assert!(
        client.get_account(cache)?.is_none(),
        "the cache should be closed"
    );
    assert!(
        client.get_balance(rent_sponsor)? > sponsor_before,
        "the rent sponsor should be refunded"
    );
    Ok(())
}

/// A merge below the widest circuit is compact-padded up to it: each padding
/// slot only proves its derived nullifier absent and adds nothing to the
/// instruction.
pub fn assert_merge_is_compact_padded(
    prepared: &MergeProofInputs,
    real_inputs: usize,
    circuit_width: usize,
) -> Result<()> {
    assert_eq!(prepared.input_utxos.len(), circuit_width);
    assert_eq!(
        prepared.dummy_nullifiers().len(),
        circuit_width - real_inputs,
        "every slot past the real inputs should be compact padding"
    );
    prepared.check_padding()?;
    Ok(())
}

/// `merge`, sent after `preceding` in one transaction, carries the most real
/// inputs that fit: it clears the v1 ceilings and one more nullifier would not.
pub fn assert_widest_merge_that_fits(
    payer: &Address,
    preceding: &[Instruction],
    merge: &MergeTransact,
    compute_budget: ComputeBudgetConfig,
) -> Result<()> {
    let size = |merge: &MergeTransact| {
        let mut instructions = preceding.to_vec();
        instructions.push(merge.instruction());
        transaction_size(payer, &instructions, compute_budget)
    };
    let fitted = size(merge)?;
    assert!(
        fitted.fits(),
        "the merge transaction should fit: {fitted:?}"
    );
    let mut data = merge.data.clone();
    data.nullifiers.push([u8::MAX; 32]);
    let overflow = size(&MergeTransact {
        input_tree: merge.input_tree,
        output_tree: merge.output_tree,
        payer: merge.payer,
        user_record: merge.user_record,
        data,
        cache: merge.cache,
    })?;
    assert!(
        !overflow.fits(),
        "one more merge input should not fit: {overflow:?}"
    );
    println!(
        "merge transaction: {} bytes, {} addresses",
        fitted.bytes, fitted.addresses
    );
    Ok(())
}
