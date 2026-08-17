//! High-level policy-ring merge build: [`MergeRing`] names which UTXOs to
//! consolidate, the derived single output, and the ring program every input is
//! owned by; [`PreparedMergeRing`] pads to
//! [`MERGE_INPUTS`](crate::instructions::merge::MERGE_INPUTS) and yields the
//! input commitments to fetch Merkle proofs for. Like the default merge, the merge-ring
//! proof proves ownership in-circuit from the nullifier secret, so there is no
//! signing step. Every input and the output share a `ring_program_id`; policy-data
//! hashes remain in the witness and the ring selects the output policy-data hash.

use solana_address::Address;
use zolana_keypair::{PublicKey, ShieldedKeypairTrait};

use crate::{
    error::TransactionError,
    instructions::{
        merge::{
            has_utxo_data, merge_output_blinding, pad_with_dummies, real_input_contexts,
            validate_merge_inputs,
        },
        types::{InputUtxoContext, SppProofInputUtxo},
    },
    SppProofOutputUtxo,
};

/// A policy-ring merge plan: the real UTXOs to consolidate (no Merkle proofs, no
/// padding), the derived single output, the owner identity, and the ring program
/// every input is owned by. Every input must share one owner (P256 or Solana),
/// asset, and `ring_program_id`.
pub struct MergeRing {
    inputs: Vec<SppProofInputUtxo>,
    output: SppProofOutputUtxo,
    expiry_unix_ts: u64,
    signing_pubkey: PublicKey,
    ring_program_id: Address,
}

impl MergeRing {
    /// Validate the inputs, derive the merged output bound to `ring_program_id`
    /// and `output_ring_data_hash`, and bind the owner identity and a fresh
    /// ephemeral viewing scalar from the keypair.
    pub fn new<K: ShieldedKeypairTrait>(
        keypair: &K,
        inputs: Vec<SppProofInputUtxo>,
        ring_program_id: Address,
        output_ring_data_hash: Option<[u8; 32]>,
    ) -> Result<Self, TransactionError> {
        // The policy-ring merge consolidates only UTXOs already owned by the
        // calling ring, so every input must carry exactly this ring_program_id.
        // Policy-ring data is allowed (the calling ring authorizes its state
        // transition before CPI and the merge-ring circuit commits every hash);
        // owner/program UTXO data is never mergeable.
        let (asset, total) = validate_merge_inputs(keypair, &inputs, |index, spend| {
            if spend.utxo.ring_program_id != Some(ring_program_id) {
                return Err(TransactionError::MergeInputRingMismatch { index });
            }
            if has_utxo_data(spend) {
                return Err(TransactionError::MergeInputHasData { index });
            }
            Ok(())
        })?;

        let first_nullifier = inputs[0].nullifier()?;
        // The merged output preserves ring ownership.
        let output = match output_ring_data_hash {
            Some(ring_data_hash) => {
                SppProofOutputUtxo::new(asset, total, keypair.shielded_address()?)?
                    .with_ring_data_hash(ring_program_id, ring_data_hash)
            }
            None => SppProofOutputUtxo::new(asset, total, keypair.shielded_address()?)?
                .with_ring_program_id(ring_program_id),
        };

        let mut output = output;
        output.blinding = merge_output_blinding(&keypair.nullifier_key(), &first_nullifier)?;

        Ok(Self {
            inputs,
            output,
            // Never expires by default; `merge_ring` rejects `current_ts >
            // expiry`, so set this explicitly for a relayer deadline.
            expiry_unix_ts: u64::MAX,
            signing_pubkey: keypair.signing_pubkey(),
            ring_program_id,
        })
    }

    pub fn with_expiry(mut self, expiry_unix_ts: u64) -> Self {
        self.expiry_unix_ts = expiry_unix_ts;
        self
    }

    /// Pad to [`MERGE_INPUTS`](crate::instructions::merge::MERGE_INPUTS) with
    /// dummy inputs (real inputs first), producing the proofless
    /// [`PreparedMergeRing`].
    pub fn prepare(self) -> PreparedMergeRing {
        let MergeRing {
            mut inputs,
            output,
            expiry_unix_ts,
            signing_pubkey,
            ring_program_id,
        } = self;
        pad_with_dummies(&mut inputs);
        PreparedMergeRing {
            inputs,
            output,
            expiry_unix_ts,
            signing_pubkey,
            ring_program_id,
        }
    }
}

/// A policy-ring merge padded to
/// [`MERGE_INPUTS`](crate::instructions::merge::MERGE_INPUTS) (real inputs
/// first, dummies at the tail), still proofless. Carries the shared
/// `ring_program_id` the proof commits. [`Self::input_utxo_hashes`] yields what
/// to fetch Merkle proofs for.
pub struct PreparedMergeRing {
    pub inputs: Vec<SppProofInputUtxo>,
    pub output: SppProofOutputUtxo,
    pub expiry_unix_ts: u64,
    pub signing_pubkey: PublicKey,
    pub ring_program_id: Address,
}

impl PreparedMergeRing {
    /// Commitments for the real inputs only. UTXO program data is not mergeable,
    /// while policy-ring data remains part of each input commitment.
    pub fn input_utxo_hashes(&self) -> Result<Vec<InputUtxoContext>, TransactionError> {
        real_input_contexts(&self.inputs, has_utxo_data)
    }

    /// Deterministic padding nullifiers whose non-inclusion proofs must be
    /// fetched before constructing the merge-ring circuit witness.
    pub fn dummy_nullifiers(
        &self,
        nullifier_key: &zolana_keypair::NullifierKey,
    ) -> Result<Vec<[u8; 32]>, TransactionError> {
        super::merge::derive_dummy_nullifiers(&self.inputs, nullifier_key)
    }
}

#[cfg(test)]
mod tests {
    use zolana_keypair::{viewing_key::random_blinding, ShieldedKeypair};

    use super::*;
    use crate::{instructions::merge::MERGE_INPUTS, utxo::Utxo, Data, DataRecord};

    const RING: [u8; 32] = [3u8; 32];

    fn ring_input(keypair: &ShieldedKeypair, amount: u64) -> SppProofInputUtxo {
        let utxo = Utxo {
            owner: keypair.signing_pubkey(),
            asset: Address::default(),
            amount,
            blinding: random_blinding(),
            ring_program_id: Some(Address::new_from_array(RING)),
            data: Data::default(),
        };
        SppProofInputUtxo::new(utxo, keypair)
    }

    #[test]
    fn accepts_matching_ring_inputs_and_preserves_ring_on_output() {
        let keypair = ShieldedKeypair::new_p256().expect("keypair");
        let ring = Address::new_from_array(RING);
        let inputs = vec![ring_input(&keypair, 10), ring_input(&keypair, 20)];

        let prepared = MergeRing::new(&keypair, inputs, ring, None)
            .expect("merge-ring plan")
            .prepare();

        assert_eq!(prepared.inputs.len(), MERGE_INPUTS);
        assert_eq!(prepared.output.amount, 30);
        assert_eq!(prepared.ring_program_id, ring);
    }

    #[test]
    fn rejects_input_bound_to_a_different_ring() {
        let keypair = ShieldedKeypair::new_p256().expect("keypair");
        let ring = Address::new_from_array(RING);
        let mut input = ring_input(&keypair, 10);
        input.utxo.ring_program_id = Some(Address::new_from_array([9u8; 32]));

        let Err(error) = MergeRing::new(&keypair, vec![input], ring, None) else {
            panic!("ring mismatch must be rejected");
        };

        assert_eq!(error, TransactionError::MergeInputRingMismatch { index: 0 });
    }

    #[test]
    fn rejects_unbound_input() {
        let keypair = ShieldedKeypair::new_p256().expect("keypair");
        let ring = Address::new_from_array(RING);
        let mut input = ring_input(&keypair, 10);
        input.utxo.ring_program_id = None;

        let Err(error) = MergeRing::new(&keypair, vec![input], ring, None) else {
            panic!("unbound input must be rejected");
        };

        assert_eq!(error, TransactionError::MergeInputRingMismatch { index: 0 });
    }

    #[test]
    fn rejects_input_owned_by_a_different_key() {
        let keypair = ShieldedKeypair::new_p256().expect("keypair");
        let other = ShieldedKeypair::new_p256().expect("other keypair");
        let ring = Address::new_from_array(RING);
        let mut input = ring_input(&keypair, 10);
        input.utxo.owner = other.signing_pubkey();

        let Err(error) = MergeRing::new(&keypair, vec![input], ring, None) else {
            panic!("foreign owner must be rejected");
        };

        assert_eq!(
            error,
            TransactionError::MergeInputOwnerMismatch { index: 0 }
        );
    }

    #[test]
    fn rejects_input_with_a_different_nullifier_key() {
        let keypair = ShieldedKeypair::new_p256().expect("keypair");
        let other = ShieldedKeypair::new_p256().expect("other keypair");
        let ring = Address::new_from_array(RING);
        let utxo = Utxo {
            owner: keypair.signing_pubkey(),
            asset: Address::default(),
            amount: 10,
            blinding: random_blinding(),
            ring_program_id: Some(ring),
            data: Data::default(),
        };
        let input = SppProofInputUtxo::new(utxo, &other);

        let Err(error) = MergeRing::new(&keypair, vec![input], ring, None) else {
            panic!("foreign nullifier key must be rejected");
        };

        assert_eq!(
            error,
            TransactionError::MergeInputNullifierKeyMismatch { index: 0 }
        );
    }

    #[test]
    fn preserves_input_and_output_ring_data_hashes() {
        let keypair = ShieldedKeypair::new_p256().expect("keypair");
        let ring = Address::new_from_array(RING);
        let input_ring_data_hash = [1u8; 32];
        let output_ring_data_hash = [2u8; 32];
        let input = ring_input(&keypair, 10).with_ring_data_hash(input_ring_data_hash);
        let input_hash = input.hash().expect("input hash");

        let prepared = MergeRing::new(&keypair, vec![input], ring, Some(output_ring_data_hash))
            .expect("ring data is authorized by the calling ring")
            .prepare();

        assert_eq!(prepared.output.ring_data_hash, Some(output_ring_data_hash));
        let commitments = prepared.input_utxo_hashes().expect("input commitments");
        assert_eq!(commitments.len(), 1);
        assert_eq!(
            commitments.first().expect("commitment").utxo_hash,
            input_hash
        );
    }

    #[test]
    fn rejects_input_carrying_utxo_program_data() {
        let keypair = ShieldedKeypair::new_p256().expect("keypair");
        let ring = Address::new_from_array(RING);
        let mut input = ring_input(&keypair, 10);
        input.utxo.data = Data::new(vec![DataRecord::UtxoData(vec![1])]);

        let Err(error) = MergeRing::new(&keypair, vec![input], ring, None) else {
            panic!("utxo program data must be rejected");
        };

        assert_eq!(error, TransactionError::MergeInputHasData { index: 0 });
    }
}
