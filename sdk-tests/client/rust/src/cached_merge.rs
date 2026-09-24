//! Helpers for the cached merge + transfer example: building the proof inputs
//! for a transfer that spends out of a cache, and polling the cache account.

use anyhow::{anyhow, Result};
use solana_address::Address;
use zolana_client::{assemble, AssembledTransfer, Rpc, ZolanaClient};
use zolana_interface::state::cache::CacheAccount;
use zolana_transaction::instructions::transact::SppProofInputs;

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
