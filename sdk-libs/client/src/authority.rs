//! The one capability that consumes the nullifier secret.
//!
//! Every other use of the secret derives from it, and those live behind
//! [`ShieldedKeys`](zolana_transaction::keys::ShieldedKeys), which returns
//! results rather than key material. Proving is the exception: the circuit takes
//! the raw secret as a witness field, so something has to put it there. That is
//! this trait, and nothing else in the client holds a
//! [`NullifierKey`].

use num_bigint::BigUint;
use zolana_keypair::{NullifierKey, ShieldedKeypair};

use crate::{
    error::ClientError,
    prover::{
        field::{be, right_align_slice},
        Proof, ProverClient, TransferInput, TransferInputs,
    },
};

/// Completes a witness whose real inputs it owns, then proves it.
///
/// Assembly leaves every real input without a secret
/// ([`TransferInput::nullifier_secret`] is `None`); a padding slot carries a
/// genuine zero, and an input belonging to another owner arrives complete. So no
/// type on the assembly path holds key material, and the secret enters the
/// witness here, one call before it goes on the wire.
///
/// `Send + Sync` because the async proving paths hold a `&dyn ProofAuthority`
/// across an await, and their futures have to be `Send` to run on a
/// multi-threaded runtime.
pub trait ProofAuthority: Send + Sync {
    /// Fill in the nullifier secret of every input this authority owns, and
    /// check each completed input's nullifier against the one it already
    /// carries.
    ///
    /// Every rail shares [`TransferInput`], so this one method completes a
    /// transfer, a ring transfer and a ring-authority transfer alike. Prefer
    /// [`Self::prove_transfer`], which completes and proves in one call; this is
    /// the seam the async prover and the ring rails prove through.
    fn complete_inputs(&self, inputs: &mut [TransferInput]) -> Result<(), ClientError>;

    /// Complete the witness and prove it.
    fn prove_transfer(
        &self,
        prover: &ProverClient,
        inputs: &mut TransferInputs,
    ) -> Result<Proof, ClientError> {
        self.complete_inputs(&mut inputs.inputs)?;
        prover.prove_transfer(inputs)
    }
}

/// The in-process authority: the secret is held here, and only this function
/// reads it.
///
/// The nullifier check guards a failure with no other signal. The input carries
/// a nullifier computed when it was built, while the circuit derives its own
/// from the secret witnessed here; the two are only equal if the secret is the
/// one that built the input. The first nullifier is also the seed of
/// `derive_private_tx_blinding`, so a disagreement makes the client and the
/// prover commit to different private transaction hashes -- and nothing reports
/// that until `validate_authorization` rejects the P-256 signature or an eddsa
/// proof fails against its public input.
fn complete_owned_inputs(
    nullifier_key: &NullifierKey,
    inputs: &mut [TransferInput],
) -> Result<(), ClientError> {
    let secret = right_align_slice(&*nullifier_key.secret())?;
    let secret = be(&secret);
    for (index, input) in inputs.iter_mut().enumerate() {
        // A padding slot and another owner's input both arrive complete; only an
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
    fn complete_inputs(&self, inputs: &mut [TransferInput]) -> Result<(), ClientError> {
        complete_owned_inputs(self, inputs)
    }
}

impl ProofAuthority for ShieldedKeypair {
    fn complete_inputs(&self, inputs: &mut [TransferInput]) -> Result<(), ClientError> {
        complete_owned_inputs(&self.nullifier_key, inputs)
    }
}

#[cfg(test)]
mod tests {

    fn wallet_input(
        utxo: Utxo,
        key: &zolana_keypair::NullifierKey,
        tree_id: u16,
    ) -> zolana_transaction::WalletUtxo {
        let nullifier_pubkey = key.pubkey().unwrap();
        let utxo_hash = utxo
            .hash(&nullifier_pubkey, &[0; 32], &[0; 32], tree_id)
            .unwrap();
        let nullifier = key.nullifier(&utxo_hash, &utxo.blinding).unwrap();
        zolana_transaction::WalletUtxo {
            utxo,
            nullifier_pubkey,
            utxo_hash,
            nullifier,
            data_hash: None,
            ring_data_hash: None,
            tree_id,
            leaf_index: 0,
            slot: 0,
            tx_signature: Default::default(),
            slot_index: 0,
        }
    }

    use zolana_transaction::{utxo::SppProofInputUtxo, Data, Utxo};

    use super::*;
    use crate::ProofInputUtxo;
    use crate::{
        prover::transact::assembly::{assemble_inputs, OwnerMode, TransferInputUtxo},
        rpc::{MerkleContext, MerkleProof, NonInclusionProof, NULLIFIER_TREE_HEIGHT},
        SpendProof, STATE_TREE_HEIGHT,
    };

    fn keypair() -> ShieldedKeypair {
        ShieldedKeypair::from_keypair(zolana_keypair::SigningKey::from_ed25519_bytes(&[7u8; 32]))
            .expect("eddsa keypair")
    }

    /// One real input of `owner` plus one padding slot, assembled the way every
    /// rail assembles them.
    fn assembled_inputs(owner: &ShieldedKeypair) -> Vec<TransferInput> {
        let utxo: SppProofInputUtxo = wallet_input(
            Utxo {
                owner: owner.signing_pubkey(),
                asset: zolana_transaction::Mint::SOL,
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
                            tree: zolana_interface::pda::tree(0),
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

        assemble_inputs(&input_utxos, &OwnerMode::ConfidentialEddsa)
            .expect("assemble inputs")
            .inputs
    }

    fn non_inclusion_proof() -> NonInclusionProof {
        NonInclusionProof {
            leaf: [0u8; 32],
            merkle_context: MerkleContext {
                tree_type: 0,
                tree: zolana_interface::pda::tree(0),
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
        let other = ShieldedKeypair::from_keypair(zolana_keypair::SigningKey::from_ed25519_bytes(
            &[9u8; 32],
        ))
        .expect("eddsa keypair");
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
