use solana_address::Address;
use zolana_client::{
    attach_input_proofs, ClientError, NonInclusionProof, RingAuthorityProver, SpendProof,
};
use zolana_transaction::{
    error::TransactionError,
    instructions::{
        transact::{
            shape::Shape,
            spp_proof_inputs::{first_nullifier, PublicTransfers},
        },
        types::{InputUtxoContext, SppProofInputUtxo},
    },
    utxo::{derive_output_blinding_seed, derive_private_tx_blinding},
    ExternalData, SppProofOutputUtxo,
};

/// A prepared, unsigned ring-authority transact. `external_data`'s
/// `instruction_discriminator` must be `RING_AUTHORITY_TRANSACT` (tag 21) so its
/// `external_data_hash` matches what the program recomputes on-chain.
pub struct PreparedRingAuthority {
    pub inputs: Vec<SppProofInputUtxo>,
    pub outputs: Vec<SppProofOutputUtxo>,
    /// The transaction's private random root seed. See
    /// [`SppProofInputs::blinding_seed`](zolana_transaction::instructions::transact::SppProofInputs).
    pub blinding_seed: [u8; 32],
    /// Raw id of the tree every output is appended to.
    // TODO(tree-id): resolve the tree id from the tree account.
    pub output_tree_id: u16,
    pub public_transfers: PublicTransfers,
    pub external_data: ExternalData,
    pub payer: Address,
    /// The ring program; bound to the public `ring_program_id` and to each
    /// non-dummy UTXO's ring field by the circuit. Every input/output UTXO must
    /// already carry this `ring_program_id`.
    pub ring_program_id: Option<Address>,
    pub shape: Shape,
}

impl PreparedRingAuthority {
    /// Nullifier of the first input slot, which must be a real spend.
    pub fn first_nullifier(&self) -> Result<[u8; 32], TransactionError> {
        first_nullifier(&self.inputs)
    }

    /// Seed every physical output blinding derives from.
    pub fn output_blinding_seed(&self) -> Result<[u8; 32], TransactionError> {
        derive_output_blinding_seed(&self.first_nullifier()?, &self.blinding_seed)
    }

    /// Final `private_tx_hash` preimage element.
    pub fn private_tx_blinding(&self) -> Result<[u8; 32], TransactionError> {
        derive_private_tx_blinding(&self.first_nullifier()?, &self.blinding_seed)
    }

    /// Commitments for the real inputs only; dummy padding has a zero owner and no
    /// meaningful commitment to look up.
    pub fn input_utxo_hashes(&self) -> Result<Vec<InputUtxoContext>, TransactionError> {
        self.inputs
            .iter()
            .filter(|spend| !spend.is_dummy())
            .enumerate()
            .map(|(index, spend)| {
                Ok(InputUtxoContext {
                    index,
                    utxo_hash: spend.hash()?,
                    nullifier: spend.nullifier()?,
                })
            })
            .collect()
    }
}

/// A prepared authority move plus the state and nullifier proofs needed by the
/// shared transaction prover.
pub struct RingAuthorityWitness {
    pub prepared: PreparedRingAuthority,
    /// One proof per real input, in input order.
    pub proofs: Vec<SpendProof>,
    /// One nullifier non-inclusion proof per dummy input, in dummy-slot order.
    pub dummy_nullifier_proofs: Vec<NonInclusionProof>,
}

impl TryFrom<RingAuthorityWitness> for RingAuthorityProver {
    type Error = ClientError;

    fn try_from(witness: RingAuthorityWitness) -> Result<Self, Self::Error> {
        let RingAuthorityWitness {
            prepared,
            proofs,
            dummy_nullifier_proofs,
        } = witness;
        let PreparedRingAuthority {
            inputs,
            outputs,
            blinding_seed,
            output_tree_id,
            public_transfers,
            external_data,
            payer,
            ring_program_id,
            shape,
        } = prepared;
        let inputs = attach_input_proofs(inputs, &proofs, &dummy_nullifier_proofs)?;

        Ok(RingAuthorityProver {
            inputs,
            outputs,
            blinding_seed,
            output_tree_id,
            external_data,
            public_transfers,
            payer,
            allow_dummy_inputs: true,
            ring_program_id,
            shape: Some(shape),
        })
    }
}
