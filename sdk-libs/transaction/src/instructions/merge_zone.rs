//! High-level policy-zone merge build: [`MergeZone`] names which UTXOs to
//! consolidate, the derived single output, and the zone program every input is
//! owned by; [`PreparedMergeZone`] pads to [`MERGE_INPUTS`] and yields the input
//! commitments to fetch Merkle proofs for. Like the default merge, the merge-zone
//! proof proves ownership in-circuit from the nullifier secret, so there is no
//! signing step. Every input and the output share a `zone_program_id`; policy-data
//! hashes remain in the witness and the zone selects the output policy-data hash.

use p256::SecretKey;
use solana_address::Address;
use zolana_keypair::{P256Pubkey, PublicKey, ShieldedKeypairTrait};

use crate::{
    error::TransactionError,
    instructions::{
        merge::{
            fresh_tx_viewing_sk, has_utxo_data, pad_with_dummies, real_input_contexts,
            validate_merge_inputs,
        },
        types::{InputUtxoContext, SppProofInputUtxo},
    },
    SppProofOutputUtxo,
};

/// A policy-zone merge plan: the real UTXOs to consolidate (no Merkle proofs, no
/// padding), the derived single output, the owner identity, and the zone program
/// every input is owned by. Every input must share one owner (P256 or Solana),
/// asset, and `zone_program_id`.
pub struct MergeZone {
    inputs: Vec<SppProofInputUtxo>,
    output: SppProofOutputUtxo,
    expiry_unix_ts: u64,
    signing_pubkey: PublicKey,
    user_viewing_pk: P256Pubkey,
    tx_viewing_sk: SecretKey,
    zone_program_id: Address,
}

impl MergeZone {
    /// Validate the inputs, derive the merged output bound to `zone_program_id`
    /// and `output_zone_data_hash`, and bind the owner identity and a fresh
    /// ephemeral viewing scalar from the keypair.
    pub fn new<K: ShieldedKeypairTrait>(
        keypair: &K,
        inputs: Vec<SppProofInputUtxo>,
        zone_program_id: Address,
        output_zone_data_hash: Option<[u8; 32]>,
    ) -> Result<Self, TransactionError> {
        // The policy-zone merge consolidates only UTXOs already owned by the
        // calling zone, so every input must carry exactly this zone_program_id.
        // Policy-zone data is allowed (the calling zone authorizes its state
        // transition before CPI and the merge-zone circuit commits every hash);
        // owner/program UTXO data is never mergeable.
        let (asset, total) = validate_merge_inputs(keypair, &inputs, |index, spend| {
            if spend.utxo.zone_program_id != Some(zone_program_id) {
                return Err(TransactionError::MergeInputZoneMismatch { index });
            }
            if has_utxo_data(spend) {
                return Err(TransactionError::MergeInputHasData { index });
            }
            Ok(())
        })?;

        // The merged output preserves zone ownership.
        let output = match output_zone_data_hash {
            Some(zone_data_hash) => {
                SppProofOutputUtxo::new(asset, total, keypair.shielded_address()?)?
                    .with_zone_data_hash(zone_program_id, zone_data_hash)
            }
            None => SppProofOutputUtxo::new(asset, total, keypair.shielded_address()?)?
                .with_zone_program_id(zone_program_id),
        };

        Ok(Self {
            inputs,
            output,
            // Never expires by default; `merge_zone` rejects `current_ts >
            // expiry`, so set this explicitly for a relayer deadline.
            expiry_unix_ts: u64::MAX,
            signing_pubkey: keypair.signing_pubkey(),
            user_viewing_pk: keypair.viewing_pubkey(),
            tx_viewing_sk: fresh_tx_viewing_sk()?,
            zone_program_id,
        })
    }

    pub fn with_expiry(mut self, expiry_unix_ts: u64) -> Self {
        self.expiry_unix_ts = expiry_unix_ts;
        self
    }

    /// Pad to [`MERGE_INPUTS`] with dummy inputs (real inputs first), producing the
    /// proofless [`PreparedMergeZone`].
    pub fn prepare(self) -> PreparedMergeZone {
        let MergeZone {
            mut inputs,
            output,
            expiry_unix_ts,
            signing_pubkey,
            user_viewing_pk,
            tx_viewing_sk,
            zone_program_id,
        } = self;
        pad_with_dummies(&mut inputs);
        PreparedMergeZone {
            inputs,
            output,
            expiry_unix_ts,
            signing_pubkey,
            user_viewing_pk,
            tx_viewing_sk,
            zone_program_id,
        }
    }
}

/// A policy-zone merge padded to [`MERGE_INPUTS`] (real inputs first, dummies at
/// the tail), still proofless. Carries the shared `zone_program_id` the proof
/// commits. [`Self::input_utxo_hashes`] yields what to fetch Merkle proofs for.
pub struct PreparedMergeZone {
    pub inputs: Vec<SppProofInputUtxo>,
    pub output: SppProofOutputUtxo,
    pub expiry_unix_ts: u64,
    pub signing_pubkey: PublicKey,
    pub user_viewing_pk: P256Pubkey,
    pub tx_viewing_sk: SecretKey,
    pub zone_program_id: Address,
}

impl PreparedMergeZone {
    /// Commitments for the real inputs only. UTXO program data is not mergeable,
    /// while policy-zone data remains part of each input commitment.
    pub fn input_utxo_hashes(&self) -> Result<Vec<InputUtxoContext>, TransactionError> {
        real_input_contexts(&self.inputs, has_utxo_data)
    }
}

#[cfg(test)]
mod tests {
    use zolana_keypair::{viewing_key::random_blinding, ShieldedKeypair};

    use super::*;
    use crate::{utxo::Utxo, Data, DataRecord};

    const ZONE: [u8; 32] = [3u8; 32];

    fn zone_input(keypair: &ShieldedKeypair, amount: u64) -> SppProofInputUtxo {
        let utxo = Utxo {
            owner: keypair.signing_pubkey(),
            asset: Address::default(),
            amount,
            blinding: random_blinding(),
            zone_program_id: Some(Address::new_from_array(ZONE)),
            data: Data::default(),
        };
        SppProofInputUtxo::new(utxo, keypair)
    }

    #[test]
    fn accepts_matching_zone_inputs_and_preserves_zone_on_output() {
        let keypair = ShieldedKeypair::new().expect("keypair");
        let zone = Address::new_from_array(ZONE);
        let inputs = vec![zone_input(&keypair, 10), zone_input(&keypair, 20)];

        let prepared = MergeZone::new(&keypair, inputs, zone, None)
            .expect("merge-zone plan")
            .prepare();

        assert_eq!(prepared.inputs.len(), MERGE_INPUTS);
        assert_eq!(prepared.output.amount, 30);
        assert_eq!(prepared.zone_program_id, zone);
    }

    #[test]
    fn rejects_input_bound_to_a_different_zone() {
        let keypair = ShieldedKeypair::new().expect("keypair");
        let zone = Address::new_from_array(ZONE);
        let mut input = zone_input(&keypair, 10);
        input.utxo.zone_program_id = Some(Address::new_from_array([9u8; 32]));

        let Err(error) = MergeZone::new(&keypair, vec![input], zone, None) else {
            panic!("zone mismatch must be rejected");
        };

        assert_eq!(error, TransactionError::MergeInputZoneMismatch { index: 0 });
    }

    #[test]
    fn rejects_unbound_input() {
        let keypair = ShieldedKeypair::new().expect("keypair");
        let zone = Address::new_from_array(ZONE);
        let mut input = zone_input(&keypair, 10);
        input.utxo.zone_program_id = None;

        let Err(error) = MergeZone::new(&keypair, vec![input], zone, None) else {
            panic!("unbound input must be rejected");
        };

        assert_eq!(error, TransactionError::MergeInputZoneMismatch { index: 0 });
    }

    #[test]
    fn rejects_input_owned_by_a_different_key() {
        let keypair = ShieldedKeypair::new().expect("keypair");
        let other = ShieldedKeypair::new().expect("other keypair");
        let zone = Address::new_from_array(ZONE);
        let mut input = zone_input(&keypair, 10);
        input.utxo.owner = other.signing_pubkey();

        let Err(error) = MergeZone::new(&keypair, vec![input], zone, None) else {
            panic!("foreign owner must be rejected");
        };

        assert_eq!(
            error,
            TransactionError::MergeInputOwnerMismatch { index: 0 }
        );
    }

    #[test]
    fn rejects_input_with_a_different_nullifier_key() {
        let keypair = ShieldedKeypair::new().expect("keypair");
        let other = ShieldedKeypair::new().expect("other keypair");
        let zone = Address::new_from_array(ZONE);
        let utxo = Utxo {
            owner: keypair.signing_pubkey(),
            asset: Address::default(),
            amount: 10,
            blinding: random_blinding(),
            zone_program_id: Some(zone),
            data: Data::default(),
        };
        let input = SppProofInputUtxo::new(utxo, &other);

        let Err(error) = MergeZone::new(&keypair, vec![input], zone, None) else {
            panic!("foreign nullifier key must be rejected");
        };

        assert_eq!(
            error,
            TransactionError::MergeInputNullifierKeyMismatch { index: 0 }
        );
    }

    #[test]
    fn preserves_input_and_output_zone_data_hashes() {
        let keypair = ShieldedKeypair::new().expect("keypair");
        let zone = Address::new_from_array(ZONE);
        let input_zone_data_hash = [1u8; 32];
        let output_zone_data_hash = [2u8; 32];
        let input = zone_input(&keypair, 10).with_zone_data_hash(input_zone_data_hash);
        let input_hash = input.hash().expect("input hash");

        let prepared = MergeZone::new(&keypair, vec![input], zone, Some(output_zone_data_hash))
            .expect("zone data is authorized by the calling zone")
            .prepare();

        assert_eq!(prepared.output.zone_data_hash, Some(output_zone_data_hash));
        let commitments = prepared.input_utxo_hashes().expect("input commitments");
        assert_eq!(commitments.len(), 1);
        assert_eq!(
            commitments.first().expect("commitment").utxo_hash,
            input_hash
        );
    }

    #[test]
    fn rejects_input_carrying_utxo_program_data() {
        let keypair = ShieldedKeypair::new().expect("keypair");
        let zone = Address::new_from_array(ZONE);
        let mut input = zone_input(&keypair, 10);
        input.utxo.data = Data::new(vec![DataRecord::UtxoData(vec![1])]);

        let Err(error) = MergeZone::new(&keypair, vec![input], zone, None) else {
            panic!("utxo program data must be rejected");
        };

        assert_eq!(error, TransactionError::MergeInputHasData { index: 0 });
    }
}
