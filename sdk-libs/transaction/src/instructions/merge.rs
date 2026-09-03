//! High-level merge build: [`Merge`] names which UTXOs to consolidate and the
//! derived single output; [`PreparedMerge`] pads to the smallest supported shape
//! that fits and yields the input commitments to fetch Merkle proofs for. Merge
//! proves ownership in-circuit from the nullifier secret, so there is no signing
//! step.

use solana_address::Address;
use zolana_hasher::{primitives::right_align, Hasher, Poseidon};
use zolana_keypair::{NullifierKey, PublicKey, ShieldedKeypairTrait};

use crate::{
    error::TransactionError,
    instructions::types::{InputUtxoContext, SppProofInputUtxo},
    SppProofOutputUtxo,
};

pub use zolana_interface::instruction::instruction_data::merge_transact::{
    MAX_MERGE_INPUTS, MERGE_SUPPORTED_INPUT_COUNTS,
};

/// Smallest supported merge arity, and the one a routine consolidation pads up
/// to. Real inputs sit at the front; padding fills the rest with dummies.
pub const MERGE_DEFAULT_INPUTS: usize = 8;

/// The shape a merge of `real_inputs` real UTXOs is padded to: the smallest
/// supported arity that fits.
///
/// A wider shape is not free -- each arity has its own proving key and a
/// proportionally larger proof cost -- so a small consolidation must not land in
/// the large circuit. On-chain it is not free either: the measured
/// `merge_transact` cost is 193k-212k CU at 8 inputs against 406k-446k CU at 36
/// (`program-tests/shielded-pool/tests/merge/functional.rs`, 2026-09), and no
/// shape fits the 200,000 CU per-instruction default, so the submitter must
/// raise the compute limit either way. Returns `None` when no supported shape is
/// wide enough.
pub fn merge_padded_input_count(real_inputs: usize) -> Option<usize> {
    MERGE_SUPPORTED_INPUT_COUNTS
        .iter()
        .copied()
        .filter(|supported| *supported >= real_inputs)
        .min()
}

/// Domain separators (32-bit ASCII tags) for the deterministic merge-output
/// recovery scheme, mirroring `circuits/spp_merge/shared/derivation.go`.
pub const DOMAIN_MERGE_OUTPUT_BLINDING_V1: u32 = 0x544d_4f42; // "TMOB"
pub const DOMAIN_MERGE_DUMMY_NULLIFIER: u32 = 0x544d_444e; // "TMDN"

/// The merged output's blinding, derived in-circuit from the owner's nullifier
/// secret and the first (always real) input's single-use nullifier. The wallet
/// recovers the output by recomputing this value and checking the resulting
/// UTXO hash against the on-chain output commitment. The nullifier secret is
/// known to the owner alone -- unlike a UTXO blinding, which the sender of
/// that UTXO also knows -- so only the owner can run this derivation.
pub fn merge_output_blinding(
    nullifier_key: &NullifierKey,
    first_nullifier: &[u8; 32],
) -> Result<[u8; 32], TransactionError> {
    Ok(Poseidon::hashv(&[
        &right_align(&DOMAIN_MERGE_OUTPUT_BLINDING_V1.to_be_bytes()),
        &right_align(&nullifier_key.secret()),
        first_nullifier,
    ])?)
}

/// The published nullifier of a dummy (padding) input slot, derived in-circuit
/// from the owner's nullifier secret, the first real input's single-use
/// nullifier, and the slot index. Seeding with the nullifier secret (owner-only)
/// rather than an input blinding (also known to that UTXO's sender) hides which
/// slots are padding, while the fixed derivation prevents a prover from
/// smuggling a real wallet nullifier into one.
pub fn merge_dummy_nullifier(
    nullifier_key: &NullifierKey,
    first_nullifier: &[u8; 32],
    slot_index: u8,
) -> Result<[u8; 32], TransactionError> {
    Ok(Poseidon::hashv(&[
        &right_align(&DOMAIN_MERGE_DUMMY_NULLIFIER.to_be_bytes()),
        &right_align(&nullifier_key.secret()),
        first_nullifier,
        &right_align(&u32::from(slot_index).to_be_bytes()),
    ])?)
}

/// A merge plan: the real UTXOs to consolidate (no Merkle proofs, no padding), the
/// derived single output, and the owner identity. Every input must share one owner
/// (P256 or Solana) and asset.
pub struct Merge {
    inputs: Vec<SppProofInputUtxo>,
    output: SppProofOutputUtxo,
    expiry_unix_ts: u64,
    signing_pubkey: PublicKey,
}

impl Merge {
    /// Validate the inputs, derive the merged output, and bind the owner identity
    /// and a fresh ephemeral viewing scalar from the keypair.
    pub fn new<K: ShieldedKeypairTrait>(
        keypair: &K,
        inputs: Vec<SppProofInputUtxo>,
    ) -> Result<Self, TransactionError> {
        // The default merge only consolidates plain utxos: no input may be bound
        // to a ring or carry program/ring data.
        let (asset, total) = validate_merge_inputs(keypair, &inputs, |index, spend| {
            if spend.utxo.ring_program_id.is_some() {
                return Err(TransactionError::MergeInputRingMismatch { index });
            }
            if has_data(spend) {
                return Err(TransactionError::MergeInputHasData { index });
            }
            Ok(())
        })?;

        // The output blinding is derived, not random: slot 0 is always real
        // (validation rejects empty inputs), and the circuit derives the same
        // value from the owner's nullifier secret and the first nullifier. The
        // wallet later reconstructs the output the same way.
        let first_nullifier = inputs[0].nullifier()?;
        let mut output = SppProofOutputUtxo::new(asset, total, keypair.shielded_address()?)?;
        output.blinding = merge_output_blinding(&keypair.nullifier_key(), &first_nullifier)?;

        Ok(Self {
            inputs,
            output,
            // Never expires by default; `merge_transact` rejects `current_ts >
            // expiry`, so set this explicitly for a relayer deadline.
            expiry_unix_ts: u64::MAX,
            signing_pubkey: keypair.signing_pubkey(),
        })
    }

    pub fn with_expiry(mut self, expiry_unix_ts: u64) -> Self {
        self.expiry_unix_ts = expiry_unix_ts;
        self
    }

    /// Pad to the smallest supported shape that fits with dummy inputs (real
    /// inputs first), producing the proofless [`PreparedMerge`].
    pub fn prepare(self) -> PreparedMerge {
        let Merge {
            mut inputs,
            output,
            expiry_unix_ts,
            signing_pubkey,
        } = self;
        pad_with_dummies(&mut inputs);
        PreparedMerge {
            inputs,
            output,
            expiry_unix_ts,
            signing_pubkey,
        }
    }
}

/// The validation both merge rails share: 1..=[`MAX_MERGE_INPUTS`] inputs bound
/// to one owner identity -- the proof binds every input to a single rail, exact
/// owner, and nullifier key from `keypair` -- and one asset. `check` adds the
/// rail's ring-binding and data policy per input. Returns the shared asset and
/// the overflow-checked merged amount.
pub(crate) fn validate_merge_inputs<K: ShieldedKeypairTrait>(
    keypair: &K,
    inputs: &[SppProofInputUtxo],
    check: impl Fn(usize, &SppProofInputUtxo) -> Result<(), TransactionError>,
) -> Result<(Address, u64), TransactionError> {
    if inputs.is_empty() {
        return Err(TransactionError::NoInputs);
    }
    if inputs.len() > MAX_MERGE_INPUTS {
        return Err(TransactionError::TooManyInputs {
            got: inputs.len(),
            max: MAX_MERGE_INPUTS,
        });
    }

    let asset = inputs.first().ok_or(TransactionError::NoInputs)?.utxo.asset;
    let owner = keypair.signing_pubkey();
    let owner_rail = keypair.curve();
    let nullifier_pubkey = keypair.nullifier_pubkey()?;
    let mut total = 0u64;
    for (index, spend) in inputs.iter().enumerate() {
        if spend.utxo.owner.curve()? != owner_rail {
            return Err(TransactionError::MergeInputRailMismatch { index });
        }
        if spend.utxo.owner != owner {
            return Err(TransactionError::MergeInputOwnerMismatch { index });
        }
        if spend.nullifier_key.pubkey()? != nullifier_pubkey {
            return Err(TransactionError::MergeInputNullifierKeyMismatch { index });
        }
        if spend.utxo.asset != asset {
            return Err(TransactionError::MergeInputAssetMismatch { index });
        }
        check(index, spend)?;
        total = total
            .checked_add(spend.utxo.amount)
            .ok_or(TransactionError::SelectedBalanceOverflow)?;
    }
    Ok((asset, total))
}

/// Pad to the smallest supported shape that fits, with dummy inputs, real
/// inputs first. `validate_merge_inputs` has already refused a count above
/// [`MAX_MERGE_INPUTS`], so a shape always exists.
pub(crate) fn pad_with_dummies(inputs: &mut Vec<SppProofInputUtxo>) {
    let target = merge_padded_input_count(inputs.len()).unwrap_or(MAX_MERGE_INPUTS);
    while inputs.len() < target {
        inputs.push(SppProofInputUtxo::new_dummy());
    }
}

pub(crate) fn derive_dummy_nullifiers(
    inputs: &[SppProofInputUtxo],
    nullifier_key: &NullifierKey,
) -> Result<Vec<[u8; 32]>, TransactionError> {
    let first = inputs.first().ok_or(TransactionError::NoInputs)?;
    if first.is_dummy() {
        return Err(TransactionError::NoInputs);
    }
    let first_nullifier = first.nullifier()?;
    inputs
        .iter()
        .enumerate()
        .filter(|(_, input)| input.is_dummy())
        .map(|(slot, _)| merge_dummy_nullifier(nullifier_key, &first_nullifier, slot as u8))
        .collect()
}

/// Commitments for the real inputs only; dummy padding has a zero owner and no
/// meaningful commitment to look up. `has_disqualifying_data` re-applies the
/// rail's data policy so a prepared plan cannot smuggle in an input its rail
/// rejects.
pub(crate) fn real_input_contexts(
    inputs: &[SppProofInputUtxo],
    has_disqualifying_data: impl Fn(&SppProofInputUtxo) -> bool,
) -> Result<Vec<InputUtxoContext>, TransactionError> {
    inputs
        .iter()
        .filter(|spend| !spend.is_dummy())
        .enumerate()
        .map(|(index, spend)| {
            if has_disqualifying_data(spend) {
                return Err(TransactionError::MergeInputHasData { index });
            }
            Ok(InputUtxoContext {
                index,
                utxo_hash: spend.hash()?,
                nullifier: spend.nullifier()?,
            })
        })
        .collect()
}

/// A merge padded to a supported shape (real inputs first, dummies at the tail),
/// still proofless. [`Self::input_utxo_hashes`] yields what to fetch Merkle proofs
/// for.
pub struct PreparedMerge {
    pub inputs: Vec<SppProofInputUtxo>,
    pub output: SppProofOutputUtxo,
    pub expiry_unix_ts: u64,
    pub signing_pubkey: PublicKey,
}

impl PreparedMerge {
    /// Commitments for the real inputs only. Merge assembly only supports clean
    /// inputs, so an input that committed to program or ring data is rejected.
    pub fn input_utxo_hashes(&self) -> Result<Vec<InputUtxoContext>, TransactionError> {
        real_input_contexts(&self.inputs, has_data)
    }

    /// Deterministic padding nullifiers whose non-inclusion proofs must be
    /// fetched before constructing the merge circuit witness.
    pub fn dummy_nullifiers(
        &self,
        nullifier_key: &zolana_keypair::NullifierKey,
    ) -> Result<Vec<[u8; 32]>, TransactionError> {
        derive_dummy_nullifiers(&self.inputs, nullifier_key)
    }
}

/// Whether an input carries program or ring data: an external `data_hash`,
/// `ring_data_hash`, or inline UTXO data. Default-ring merge and split consolidate
/// only plain utxos, so any of these disqualifies the input. Option semantics: a
/// `Some(_)` hash means "has data" regardless of the hash value (an all-zero hash
/// still binds committed data).
pub(crate) fn has_data(spend: &SppProofInputUtxo) -> bool {
    spend.data_hash.is_some() || spend.ring_data_hash.is_some() || !spend.utxo.data.is_empty()
}

/// Whether an input carries program-controlled UTXO data. Policy-ring merges may
/// consume `ring_data_hash` values after the ring has authorized their transition,
/// but `utxo_data` remains owner/program controlled and is never mergeable.
pub(crate) fn has_utxo_data(spend: &SppProofInputUtxo) -> bool {
    spend.data_hash.is_some() || spend.utxo.data.utxo_data().is_some()
}

#[cfg(test)]
mod tests {
    use solana_address::Address;
    use zolana_keypair::{viewing_key::random_blinding, ShieldedKeypair, SigningKey};

    use super::*;
    use crate::{data::DataRecord, utxo::Utxo, Data};

    fn plain_input(keypair: &ShieldedKeypair, asset: Address, amount: u64) -> SppProofInputUtxo {
        let utxo = Utxo {
            owner: keypair.signing_pubkey(),
            asset,
            amount,
            blinding: random_blinding(),
            ring_program_id: None,
            data: Data::default(),
        };
        SppProofInputUtxo::new(utxo, keypair)
    }

    #[test]
    fn accepts_matching_plain_inputs_and_pads_to_shape() {
        let keypair = ShieldedKeypair::new_p256().expect("keypair");
        let inputs = vec![
            plain_input(&keypair, Address::default(), 10),
            plain_input(&keypair, Address::default(), 20),
        ];

        let prepared = Merge::new(&keypair, inputs).expect("merge plan").prepare();

        assert_eq!(prepared.inputs.len(), MERGE_DEFAULT_INPUTS);
        assert_eq!(prepared.output.amount, 30);
    }

    #[test]
    fn rejects_input_owned_by_a_different_key() {
        let keypair = ShieldedKeypair::new_p256().expect("keypair");
        let other = ShieldedKeypair::new_p256().expect("other keypair");
        // Same rail (both P256), different owner: the exact-owner check fires.
        let mut input = plain_input(&keypair, Address::default(), 10);
        input.utxo.owner = other.signing_pubkey();

        let Err(error) = Merge::new(&keypair, vec![input]) else {
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
        let utxo = Utxo {
            owner: keypair.signing_pubkey(),
            asset: Address::default(),
            amount: 10,
            blinding: random_blinding(),
            ring_program_id: None,
            data: Data::default(),
        };
        let input = SppProofInputUtxo::new(utxo, &other);

        let Err(error) = Merge::new(&keypair, vec![input]) else {
            panic!("foreign nullifier key must be rejected");
        };

        assert_eq!(
            error,
            TransactionError::MergeInputNullifierKeyMismatch { index: 0 }
        );
    }

    #[test]
    fn rejects_ring_bound_input() {
        let keypair = ShieldedKeypair::new_p256().expect("keypair");
        let mut input = plain_input(&keypair, Address::default(), 10);
        input.utxo.ring_program_id = Some(Address::new_from_array([3u8; 32]));

        let Err(error) = Merge::new(&keypair, vec![input]) else {
            panic!("ring-bound input must be rejected");
        };

        assert_eq!(error, TransactionError::MergeInputRingMismatch { index: 0 });
    }

    #[test]
    fn rejects_input_carrying_inline_data() {
        let keypair = ShieldedKeypair::new_p256().expect("keypair");
        let mut input = plain_input(&keypair, Address::default(), 10);
        input.utxo.data = Data::new(vec![DataRecord::Memo(b"utxo".to_vec())]);

        let Err(error) = Merge::new(&keypair, vec![input]) else {
            panic!("input carrying data must be rejected");
        };

        assert_eq!(error, TransactionError::MergeInputHasData { index: 0 });
    }

    #[test]
    fn rejects_input_carrying_a_committed_data_hash() {
        let keypair = ShieldedKeypair::new_p256().expect("keypair");
        let input = plain_input(&keypair, Address::default(), 10).with_data_hash([1u8; 32]);

        let Err(error) = Merge::new(&keypair, vec![input]) else {
            panic!("committed data hash must be rejected");
        };

        assert_eq!(error, TransactionError::MergeInputHasData { index: 0 });
    }

    #[test]
    fn rejects_input_on_a_different_rail() {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&random_blinding());
        let eddsa = ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&seed))
            .expect("eddsa keypair");
        let p256 = ShieldedKeypair::new_p256().expect("p256 keypair");
        // A P256-owned input under an ed25519 merging keypair mismatches the rail.
        let input = plain_input(&p256, Address::default(), 10);

        let Err(error) = Merge::new(&eddsa, vec![input]) else {
            panic!("rail mismatch must be rejected");
        };

        assert_eq!(error, TransactionError::MergeInputRailMismatch { index: 0 });
    }
}
