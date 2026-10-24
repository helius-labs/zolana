use zolana_program::{
    circuit::{constant, nonzero_hash_chain, poseidon, zero, Assert, CircuitVar, PublicHashOutput},
    conversion::ProofInput,
    CircuitError, DOMAIN_PRIVATE_TX_BLINDING_V1, DOMAIN_TRANSACT_OUTPUT_BLINDING_SEED_V1,
    DOMAIN_TRANSACT_OUTPUT_BLINDING_V1,
};

/// A utxo opening with already committed owner and asset identities. The
/// shielded pool proves ownership and inclusion of the same utxo hashes.
#[derive(Clone, Debug, Default, PartialEq, Eq, ProofInput)]
pub struct ProofInputUtxo {
    pub domain: [u8; 32],
    pub tree_id: [u8; 32],
    pub owner_hash: [u8; 32],
    pub asset: [u8; 32],
    pub amount: [u8; 32],
    pub blinding: [u8; 32],
    pub data_hash: [u8; 32],
    pub ring_data_hash: [u8; 32],
    pub ring_program_id: [u8; 32],
}

impl ProofInputUtxo {
    pub fn hash(&self) -> Result<[u8; 32], zolana_transaction::TransactionError> {
        zolana_transaction::utxo::ProofInputUtxo {
            domain: self.domain,
            tree_id: self.tree_id,
            owner_hash: self.owner_hash,
            asset: self.asset,
            amount: self.amount,
            blinding: self.blinding,
            data_hash: self.data_hash,
            ring_data_hash: self.ring_data_hash,
            ring_program_id: self.ring_program_id,
        }
        .hash()
    }
}

impl From<zolana_transaction::utxo::ProofInputUtxo> for ProofInputUtxo {
    fn from(utxo: zolana_transaction::utxo::ProofInputUtxo) -> Self {
        Self {
            domain: utxo.domain,
            tree_id: utxo.tree_id,
            owner_hash: utxo.owner_hash,
            asset: utxo.asset,
            amount: utxo.amount,
            blinding: utxo.blinding,
            data_hash: utxo.data_hash,
            ring_data_hash: utxo.ring_data_hash,
            ring_program_id: utxo.ring_program_id,
        }
    }
}

impl ProofInputUtxoCircuit {
    pub(super) fn assert_default_ring(&self) -> Result<(), CircuitError> {
        self.domain.assert_equal(
            &constant(u64::from(zolana_interface::UTXO_DOMAIN)),
            "the utxo is not a spendable utxo",
        )?;
        self.ring_data_hash
            .assert_equal(&zero(), "the utxo belongs to a ring")?;
        self.ring_program_id
            .assert_equal(&zero(), "the utxo belongs to a ring")
    }

    pub(super) fn hash(&self) -> Result<CircuitVar, CircuitError> {
        let ring = poseidon(&[self.ring_data_hash.clone(), self.ring_program_id.clone()])?;
        let owner = poseidon(&[self.owner_hash.clone(), self.blinding.clone()])?;
        poseidon(&[
            self.domain.clone(),
            self.tree_id.clone(),
            self.asset.clone(),
            self.amount.clone(),
            self.data_hash.clone(),
            ring,
            owner,
        ])
    }
}

pub struct Commitment(pub(super) CircuitVar);

impl PublicHashOutput for Commitment {
    fn public_hash(&self) -> &CircuitVar {
        &self.0
    }
}

pub(super) fn check_private_tx_hash(
    inputs: &[CircuitVar],
    outputs: &[CircuitVar],
    blinding: &CircuitVar,
    expected: &CircuitVar,
) -> Result<(), CircuitError> {
    poseidon(&[
        nonzero_hash_chain(inputs)?,
        nonzero_hash_chain(outputs)?,
        zero(),
        blinding.clone(),
    ])?
    .assert_equal(expected, "the proof describes another transaction")
}

pub(super) fn check_transaction_blindings(
    first_nullifier: &CircuitVar,
    blinding_seed: &CircuitVar,
    private_tx_blinding: &CircuitVar,
    output_blindings: &[&CircuitVar],
) -> Result<(), CircuitError> {
    poseidon(&[
        constant(u64::from(DOMAIN_PRIVATE_TX_BLINDING_V1)),
        first_nullifier.clone(),
        blinding_seed.clone(),
    ])?
    .assert_equal(
        private_tx_blinding,
        "the transaction blinding does not derive from the order",
    )?;
    let output_seed = poseidon(&[
        constant(u64::from(DOMAIN_TRANSACT_OUTPUT_BLINDING_SEED_V1)),
        first_nullifier.clone(),
        blinding_seed.clone(),
    ])?;
    for (slot, blinding) in output_blindings.iter().enumerate() {
        poseidon(&[
            constant(u64::from(DOMAIN_TRANSACT_OUTPUT_BLINDING_V1)),
            first_nullifier.clone(),
            output_seed.clone(),
            constant(slot as u64),
        ])?
        .assert_equal(
            blinding,
            "an output blinding does not derive from the order",
        )?;
    }
    Ok(())
}
