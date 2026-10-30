//! Proof-authority and merge capabilities that consume the nullifier secret.
//!
//! Every other use of the secret derives from it, and those live behind
//! [`ShieldedKeys`](spr_transaction::keys::ShieldedKeys), which returns
//! results rather than key material. Proving is the exception: the circuit takes
//! the raw secret as a witness field, so something has to put it there. That is
//! these capabilities. Callers request operations rather than extracting keys.

use num_bigint::BigUint;
use spr_keypair::{NullifierKey, ShieldedAddress, ShieldedKeypair};

use crate::{
    error::ClientError,
    prover::{
        field::{be, right_align_slice},
        TransferInput,
    },
};

/// The operations needed to assemble a merge without exposing a nullifier key.
pub trait MergeKeys: Send + Sync {
    fn address(&self) -> Result<ShieldedAddress, ClientError>;

    fn derive_merge(
        &self,
        requests: &[spr_transaction::DeriveRequest],
    ) -> Result<Vec<[u8; 32]>, ClientError>;

    /// Complete the merge proof inputs without returning a long-lived key.
    fn complete_merge_inputs(
        &self,
        inputs: &mut crate::prover::MergeInputs,
    ) -> Result<(), ClientError>;
}

pub struct LocalMergeKeys {
    address: ShieldedAddress,
    nullifier_key: NullifierKey,
}

impl LocalMergeKeys {
    pub fn new(address: ShieldedAddress, nullifier_key: NullifierKey) -> Result<Self, ClientError> {
        if nullifier_key.pubkey()? != address.nullifier_pubkey {
            return Err(ClientError::MergeNullifierKeyMismatch);
        }
        Ok(Self {
            address,
            nullifier_key,
        })
    }
}

impl MergeKeys for LocalMergeKeys {
    fn address(&self) -> Result<ShieldedAddress, ClientError> {
        Ok(self.address)
    }

    fn derive_merge(
        &self,
        requests: &[spr_transaction::DeriveRequest],
    ) -> Result<Vec<[u8; 32]>, ClientError> {
        use spr_transaction::{
            instructions::merge::{
                merge_dummy_nullifier, merge_output_blinding, merge_output_key,
                merge_private_tx_blinding,
            },
            DeriveRequest,
        };
        requests
            .iter()
            .map(|request| {
                Ok(match request {
                    DeriveRequest::Nullifier {
                        utxo_hash,
                        blinding,
                    } => self.nullifier_key.nullifier(utxo_hash, blinding)?,
                    DeriveRequest::MergeDummyNullifier {
                        first_nullifier,
                        slot_index,
                    } => merge_dummy_nullifier(&self.nullifier_key, first_nullifier, *slot_index)?,
                    DeriveRequest::MergeOutputBlinding { first_nullifier } => {
                        merge_output_blinding(&self.nullifier_key, first_nullifier)?
                    }
                    DeriveRequest::MergePrivateTxBlinding { first_nullifier } => {
                        merge_private_tx_blinding(&self.nullifier_key, first_nullifier)?
                    }
                    DeriveRequest::MergeOutputKey { first_nullifier } => {
                        merge_output_key(&self.nullifier_key, first_nullifier)?
                    }
                })
            })
            .collect()
    }

    fn complete_merge_inputs(
        &self,
        inputs: &mut crate::prover::MergeInputs,
    ) -> Result<(), ClientError> {
        inputs.user_nullifier_secret = be(&right_align_slice(&*self.nullifier_key.secret())?);
        Ok(())
    }
}

impl MergeKeys for ShieldedKeypair {
    fn address(&self) -> Result<ShieldedAddress, ClientError> {
        Ok(self.shielded_address()?)
    }

    fn derive_merge(
        &self,
        requests: &[spr_transaction::DeriveRequest],
    ) -> Result<Vec<[u8; 32]>, ClientError> {
        Ok(spr_transaction::ShieldedKeys::derive(self, requests)?)
    }

    fn complete_merge_inputs(
        &self,
        inputs: &mut crate::prover::MergeInputs,
    ) -> Result<(), ClientError> {
        inputs.user_nullifier_secret = be(&right_align_slice(&*self.nullifier_key.secret())?);
        Ok(())
    }
}

/// Completes a witness whose real inputs it owns.
///
/// Assembly leaves every real input without a secret
/// ([`TransferInput::nullifier_secret`] is `None`); a padding or address slot
/// carries a genuine zero, and an input belonging to another owner arrives
/// complete. So no
/// type on the assembly path holds key material, and the secret enters the
/// witness here, one call before it goes on the wire.
///
/// Completing is all an authority does. The caller proves the completed
/// witness, so proving somewhere else means implementing
/// [`Prover`](crate::Prover), not an authority.
/// [`AssembledTransfer::prove`](crate::AssembledTransfer::prove) completes and
/// proves in one call.
///
/// `Send + Sync` because the async proving paths hold a `&dyn ProofAuthority`
/// across an await, and their futures have to be `Send` to run on a
/// multi-threaded runtime.
pub trait ProofAuthority: Send + Sync {
    /// Whether this authority can complete inputs of this nullifier public key.
    /// Provider errors must be returned, rather than interpreted as a mismatch.
    fn owns_nullifier_pubkey(&self, nullifier_pubkey: &[u8; 32]) -> Result<bool, ClientError>;

    /// Fill in the nullifier secret of every input this authority owns, and
    /// check each completed input's nullifier against the one it already
    /// carries.
    ///
    /// Every rail shares [`TransferInput`], so this one method completes a
    /// transfer, a ring transfer and a ring-authority transfer alike.
    fn complete_inputs(&self, inputs: &mut [TransferInput]) -> Result<(), ClientError>;
}

/// The in-process authority: the secret is held here, and only this function
/// reads it.
///
/// The nullifier check guards a failure with no other signal. The input carries
/// a nullifier computed when it was built, while the circuit derives its own
/// from the secret witnessed here; the two are only equal if the secret is the
/// one that built the input. The first nullifier is also the seed of
/// `derive_private_tx_blinding`, so a disagreement makes the client and the
/// prover commit to different private transaction hashes and the proof fails
/// against the locally assembled public input.
fn complete_owned_inputs(
    nullifier_key: &NullifierKey,
    inputs: &mut [TransferInput],
) -> Result<(), ClientError> {
    let secret = right_align_slice(&*nullifier_key.secret())?;
    let secret = be(&secret);
    for (index, input) in inputs.iter_mut().enumerate() {
        // Padding, an address and another owner's input arrive complete; only an
        // input waiting for this authority is absent.
        if input.nullifier_secret.is_some() {
            continue;
        }
        let utxo_hash = input.utxo.hash()?;
        let nullifier = nullifier_key.nullifier(&utxo_hash, &input.utxo.blinding)?;
        if BigUint::from_bytes_be(&nullifier) != input.nullifier {
            return Err(ClientError::InputNullifierMismatch { index });
        }
        input.nullifier_secret = Some(secret.clone());
    }
    Ok(())
}

impl ProofAuthority for NullifierKey {
    fn owns_nullifier_pubkey(&self, nullifier_pubkey: &[u8; 32]) -> Result<bool, ClientError> {
        Ok(self.pubkey()? == *nullifier_pubkey)
    }

    fn complete_inputs(&self, inputs: &mut [TransferInput]) -> Result<(), ClientError> {
        complete_owned_inputs(self, inputs)
    }
}

impl ProofAuthority for ShieldedKeypair {
    fn owns_nullifier_pubkey(&self, nullifier_pubkey: &[u8; 32]) -> Result<bool, ClientError> {
        self.nullifier_key.owns_nullifier_pubkey(nullifier_pubkey)
    }

    fn complete_inputs(&self, inputs: &mut [TransferInput]) -> Result<(), ClientError> {
        complete_owned_inputs(&self.nullifier_key, inputs)
    }
}

pub(crate) fn complete_with_authorities(
    inputs: &mut [TransferInput],
    original: &[spr_transaction::utxo::SppProofInputUtxo],
    authorities: &[&dyn ProofAuthority],
) -> Result<(), ClientError> {
    if inputs.len() != original.len() {
        return Err(ClientError::WitnessInputCountMismatch {
            got: inputs.len(),
            expected: original.len(),
        });
    }
    for (index, (input, original)) in inputs.iter_mut().zip(original).enumerate() {
        if original.is_dummy() || original.is_address() {
            continue;
        }
        let mut selected = None;
        for authority in authorities {
            if authority.owns_nullifier_pubkey(&original.nullifier_pubkey)? {
                if selected.is_some() {
                    return Err(ClientError::AmbiguousProofAuthority { index });
                }
                selected = Some(*authority);
            }
        }
        let authority = selected.ok_or(ClientError::MissingProofAuthority { index })?;
        input.nullifier_secret = None;
        authority
            .complete_inputs(core::slice::from_mut(input))
            .map_err(|error| match error {
                ClientError::InputNullifierMismatch { .. } => {
                    ClientError::InputNullifierMismatch { index }
                }
                other => other,
            })?;
        let secret = input
            .nullifier_secret
            .as_ref()
            .ok_or(ClientError::MissingNullifierSecret { index })?;
        let secret = right_align_slice(&secret.to_bytes_be())?;
        let nullifier_pubkey = spr_keypair::hash::poseidon(&[&secret])?;
        let utxo_hash = input.utxo.hash()?;
        if utxo_hash != original.utxo_hash {
            return Err(
                spr_transaction::TransactionError::InputCommitmentMismatch { index }.into(),
            );
        }
        let nullifier = spr_keypair::hash::poseidon(&[&utxo_hash, &input.utxo.blinding, &secret])?;
        if nullifier_pubkey != original.nullifier_pubkey
            || be(&nullifier) != input.nullifier
            || input.nullifier != be(&original.published_nullifier())
        {
            return Err(ClientError::InputNullifierMismatch { index });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {

    fn wallet_input(
        utxo: Utxo,
        key: &spr_keypair::NullifierKey,
        tree_id: u16,
    ) -> spr_transaction::WalletUtxo {
        let nullifier_pubkey = key.pubkey().unwrap();
        let utxo_hash = utxo
            .hash(&nullifier_pubkey, &[0; 32], &[0; 32], tree_id)
            .unwrap();
        let nullifier = key.nullifier(&utxo_hash, &utxo.blinding).unwrap();
        spr_transaction::WalletUtxo {
            utxo,
            nullifier_pubkey,
            utxo_hash,
            nullifier,
            tx_viewing_key: None,
            data_hash: None,
            ring_data_hash: None,
            tree_id,
            leaf_index: 0,
            latest_tree_id: None,
            slot: 0,
            tx_signature: Default::default(),
            slot_index: 0,
        }
    }

    use spr_transaction::{utxo::SppProofInputUtxo, Data, Utxo};

    use super::*;
    use crate::ProofInputUtxo;
    use crate::{
        prover::transact::assembly::{assemble_inputs, OwnerMode, TransferInputUtxo},
        rpc::{MerkleContext, MerkleProof, NonInclusionProof, NULLIFIER_TREE_HEIGHT},
        SpendProof, STATE_TREE_HEIGHT,
    };

    fn keypair() -> ShieldedKeypair {
        ShieldedKeypair::from_keypair(spr_keypair::SigningKey::from_ed25519_bytes(&[7u8; 32]))
            .expect("ed25519 keypair")
    }

    /// One real input of `owner` plus one padding slot, assembled the way every
    /// rail assembles them.
    fn assembled_inputs(owner: &ShieldedKeypair) -> Vec<TransferInput> {
        let utxo: SppProofInputUtxo = wallet_input(
            Utxo {
                owner: owner.signing_pubkey(),
                asset: spr_transaction::Mint::SOL,
                amount: 3,
                blinding: [2u8; 32],
                ring_program_id: None,
                data: Data::default(),
            },
            &owner.nullifier_key,
            0,
        )
        .into();
        let dummy = SppProofInputUtxo::dummy_with_blinding([5u8; 32], 0).unwrap();
        let mut real_nf = non_inclusion_proof();
        real_nf.leaf = utxo.nullifier;
        let mut dummy_nf = non_inclusion_proof();
        dummy_nf.leaf = dummy.nullifier;
        let input_utxos = [
            TransferInputUtxo {
                utxo: utxo.clone(),
                proof: Some(SpendProof {
                    state: MerkleProof {
                        leaf: utxo.utxo_hash,
                        merkle_context: MerkleContext {
                            tree_type: 0,
                            tree: spr_interface::pda::tree(0),
                        },
                        path: vec![[0u8; 32]; STATE_TREE_HEIGHT],
                        leaf_index: 0,
                        root: [0u8; 32],
                        root_seq: 0,
                        root_index: 0,
                    },
                    nullifier: real_nf,
                }),
                nullifier_proof: None,
            },
            TransferInputUtxo {
                utxo: dummy,
                proof: None,
                nullifier_proof: Some(dummy_nf),
            },
        ];

        assemble_inputs(&input_utxos, &OwnerMode::SolanaEddsa)
            .expect("assemble inputs")
            .inputs
    }

    fn non_inclusion_proof() -> NonInclusionProof {
        NonInclusionProof {
            leaf: [0u8; 32],
            merkle_context: MerkleContext {
                tree_type: 0,
                tree: spr_interface::pda::tree(0),
            },
            path: vec![[0u8; 32]; NULLIFIER_TREE_HEIGHT],
            low_element: [0u8; 32],
            low_element_index: 0,
            high_element: [u8::MAX; 32],
            high_element_index: 1,
            root: [0u8; 32],
            root_seq: 0,
            root_index: 0,
        }
    }

    /// The real slot gets the authority's secret; the padding slot keeps the
    /// public zero it was assembled with, rather than being filled in as though
    /// it were owned.
    #[test]
    fn completion_fills_the_owned_input_and_leaves_padding_at_its_public_zero() {
        let owner = keypair();
        let mut inputs = assembled_inputs(&owner);

        owner.complete_inputs(&mut inputs).expect("complete inputs");

        let secret = right_align_slice(&*owner.nullifier_key.secret()).expect("secret field");
        assert_eq!(
            inputs
                .first()
                .and_then(|input| input.nullifier_secret.clone()),
            Some(be(&secret))
        );
        assert_eq!(
            inputs
                .get(1)
                .and_then(|input| input.nullifier_secret.clone()),
            Some(BigUint::ZERO)
        );
    }

    /// A nullifier that disagrees with the one the secret derives is the only
    /// evidence that the input and the secret describe different spends, and it
    /// has to fail here: the prover would derive its own and build a different
    /// private transaction hash without saying so.
    #[test]
    fn an_input_whose_nullifier_the_secret_does_not_derive_is_refused() {
        let owner = keypair();
        let mut inputs = assembled_inputs(&owner);
        let real = inputs.first_mut().expect("real input slot");
        real.nullifier += 1u8;

        assert!(matches!(
            owner.complete_inputs(&mut inputs),
            Err(ClientError::InputNullifierMismatch { index: 0 })
        ));
    }

    /// The secret must match the input, not merely be some owner's secret.
    #[test]
    fn another_owners_secret_does_not_complete_this_input() {
        let owner = keypair();
        let other =
            ShieldedKeypair::from_keypair(spr_keypair::SigningKey::from_ed25519_bytes(&[9u8; 32]))
                .expect("ed25519 keypair");
        let mut inputs = assembled_inputs(&owner);

        assert!(matches!(
            other.complete_inputs(&mut inputs),
            Err(ClientError::InputNullifierMismatch { index: 0 })
        ));
    }

    /// Completion is over the witness's own commitment, so a slot whose UTXO
    /// body was edited after assembly no longer derives its nullifier.
    #[test]
    fn a_witness_commitment_edited_after_assembly_no_longer_derives_its_nullifier() {
        let owner = keypair();
        let mut inputs = assembled_inputs(&owner);
        let real = inputs.first_mut().expect("real input slot");
        real.utxo = ProofInputUtxo {
            amount: [9u8; 32],
            ..real.utxo.clone()
        };

        assert!(matches!(
            owner.complete_inputs(&mut inputs),
            Err(ClientError::InputNullifierMismatch { index: 0 })
        ));
    }
}
