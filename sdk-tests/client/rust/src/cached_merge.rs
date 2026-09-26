//! Helpers for the cached merge + transfer example: proving a transfer that
//! spends out of a cache by either proof data route, and polling the cache
//! account.

use anyhow::{anyhow, Result};
use solana_address::Address;
use zolana_client::{
    assemble, prover::indexed::PreparedIndexedTransfer, AssembledTransfer, ProofAuthority,
    ProofCompressed, ProofDataSource, ProverClient, Rpc, ZolanaClient,
};
use zolana_interface::{
    instruction::instruction_data::transact::TransactIxData, state::cache::CacheAccount,
};
use zolana_keypair::ShieldedKeypair;
use zolana_transaction::instructions::transact::SppProofInputs;

/// A transfer whose real inputs are read from a cache.
pub struct CachedTransfer<'a> {
    pub transaction: SppProofInputs,
    pub owner: &'a ShieldedKeypair,
    pub tree: Address,
}

pub enum PreparedTransfer {
    Client(Box<AssembledTransfer>),
    Prover(Box<PreparedIndexedTransfer>),
}

impl CachedTransfer<'_> {
    /// Only the padding inputs need Merkle data, a cached input proves against the cache.
    pub fn prepare<R: Rpc>(
        self,
        source: ProofDataSource,
        client: &ZolanaClient<R>,
    ) -> Result<PreparedTransfer> {
        if source == ProofDataSource::Prover {
            return Ok(PreparedTransfer::Prover(Box::new(
                PreparedIndexedTransfer::new(self.transaction, self.owner)?,
            )));
        }
        let nullifier_proofs = client
            .get_non_inclusion_proofs(self.tree, self.transaction.dummy_nullifiers(), None)?
            .proofs;
        let mut transfer = assemble(self.transaction, &[], &nullifier_proofs)?;
        self.owner
            .complete_inputs(&mut transfer.prover_inputs.inputs)?;
        Ok(PreparedTransfer::Client(Box::new(transfer)))
    }
}

impl PreparedTransfer {
    pub fn prove(self, prover: &ProverClient) -> Result<TransactIxData> {
        match self {
            Self::Client(transfer) => {
                let proof = prover.prove_transfer(&transfer.prover_inputs)?;
                Ok(transfer.with_proof(ProofCompressed::try_from(proof)?.to_transact_proof()))
            }
            Self::Prover(prepared) => Ok(prover.prove_indexed(prepared.as_ref())?.data),
        }
    }
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
