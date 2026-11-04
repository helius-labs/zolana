use solana_address::Address;
use spr_keypair::{viewing_key::Salt, NullifierKey, PublicKey};

use crate::{error::TransactionError, utxo::SppProofInputUtxo, SppProofOutputUtxo};

use super::{MergeOutputCiphertext, MergeSeed};

#[derive(Clone, Debug)]
pub enum MergeRail {
    /// `merge_transact` or `merge_ring`, keyed on the nullifier secret.
    Classic,
    /// `merge_ring_v2` under a nonzero key, keyed on the nullifier secret.
    RingV2,
    /// `merge_ring_v2` under the zero key, where the owner account signs.
    RingV2ZeroKey(MergeSeed),
}

#[derive(Clone)]
pub struct MergeProofInputs {
    pub input_utxos: Vec<SppProofInputUtxo>,
    pub output_utxo: SppProofOutputUtxo,
    pub expiry_unix_ts: u64,
    pub signing_pubkey: PublicKey,
    pub output_tree_id: u16,
    pub ring_program_id: Option<Address>,
    /// Fresh per proof: a merge rebuilt on the same first nullifier keeps its
    /// key, and the salt keeps its pads from repeating.
    pub output_ciphertext_salt: Salt,
    /// The output's amount and mint under the per-merge key; the proof binds it.
    pub output_ciphertext: MergeOutputCiphertext,
    pub rail: MergeRail,
}

impl MergeProofInputs {
    pub fn output_hash(&self) -> Result<[u8; 32], TransactionError> {
        self.output_utxo.hash(self.output_tree_id)
    }

    pub fn seed(&self, nullifier_key: &NullifierKey) -> MergeSeed {
        match &self.rail {
            MergeRail::RingV2ZeroKey(seed) => seed.clone(),
            MergeRail::Classic | MergeRail::RingV2 => MergeSeed::from_nullifier_key(nullifier_key),
        }
    }
}
