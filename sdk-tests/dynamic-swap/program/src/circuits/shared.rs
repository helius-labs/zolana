use spr_program::{
    circuit::nonzero_hash_chain, input, poseidon, require, require_eq, CircuitError, Field,
    DOMAIN_PRIVATE_TX_BLINDING_V1, DOMAIN_TRANSACT_OUTPUT_BLINDING_SEED_V1,
    DOMAIN_TRANSACT_OUTPUT_BLINDING_V1,
};

/// Domain of a settle transaction's blinding seed,
/// `Poseidon(domain, order_blinding)`, as a big-endian tag in the last bytes
/// of the field element. The order opening fixes the seed, so the taker
/// recomputes its payout note without a ciphertext.
pub const SETTLE_BLINDING_DOMAIN: [u8; 4] = *b"DSTX";
/// Domain of a cancel transaction's blinding seed, see
/// [`SETTLE_BLINDING_DOMAIN`].
pub const CANCEL_BLINDING_DOMAIN: [u8; 4] = *b"DCNL";

/// `Poseidon(domain, order_blinding)`: the blinding seed of a transaction that
/// spends the order.
pub(super) fn order_blinding_seed(
    domain: [u8; 4],
    order_blinding: Field,
) -> Result<Field, CircuitError> {
    poseidon(&[Field::from(u32::from_be_bytes(domain)), order_blinding])
}

/// Requires `value < 2^64`: a token amount or booked total that a field
/// subtraction must not have wrapped.
pub(super) fn require_u64(value: Field) {
    let _ = value.to_bits::<64>();
}

/// Requires a checked `u64` operation not to overflow. Native execution
/// records the failure and continues with zero.
pub(super) fn require_some(value: Option<u64>) -> u64 {
    require(value.is_some());
    value.unwrap_or(0)
}

/// A utxo opening with already committed owner and asset identities. The
/// shielded pool proves ownership and inclusion of the same utxo hashes.
#[input]
pub struct ProofInputUtxo {
    pub domain: Field,
    pub tree_id: Field,
    pub owner_hash: Field,
    pub asset: Field,
    pub amount: Field,
    pub blinding: Field,
    pub data_hash: Field,
    pub ring_data_hash: Field,
    pub ring_program_id: Field,
}

impl ProofInputUtxo {
    pub(super) fn assert_default_ring(&self) {
        require_eq(self.domain, Field::from(spr_interface::UTXO_DOMAIN));
        require_eq(self.ring_data_hash, Field::zero());
        require_eq(self.ring_program_id, Field::zero());
    }

    pub fn hash(&self) -> Result<Field, CircuitError> {
        let ring = poseidon(&[self.ring_data_hash, self.ring_program_id])?;
        let owner = poseidon(&[self.owner_hash, self.blinding])?;
        poseidon(&[
            self.domain,
            self.tree_id,
            self.asset,
            self.amount,
            self.data_hash,
            ring,
            owner,
        ])
    }
}

/// What a dynamic-swap program proves: the hash of its public inputs and the
/// private transaction hash. The generated entry circuit exposes it as the
/// proof's one public input.
pub struct Commitment(pub(super) Field);

impl Commitment {
    pub fn public_hash(&self) -> &Field {
        &self.0
    }
}

pub(super) fn check_private_tx_hash(
    inputs: &[Field],
    outputs: &[Field],
    blinding: Field,
    expected: Field,
) -> Result<(), CircuitError> {
    require_eq(
        poseidon(&[
            nonzero_hash_chain(inputs)?,
            nonzero_hash_chain(outputs)?,
            Field::zero(),
            blinding,
        ])?,
        expected,
    );
    Ok(())
}

pub(super) fn check_transaction_blindings(
    first_nullifier: Field,
    blinding_seed: Field,
    private_tx_blinding: Field,
    output_blindings: &[Field],
) -> Result<(), CircuitError> {
    require_eq(
        poseidon(&[
            Field::from(DOMAIN_PRIVATE_TX_BLINDING_V1),
            first_nullifier,
            blinding_seed,
        ])?,
        private_tx_blinding,
    );
    let output_seed = poseidon(&[
        Field::from(DOMAIN_TRANSACT_OUTPUT_BLINDING_SEED_V1),
        first_nullifier,
        blinding_seed,
    ])?;
    for (slot, blinding) in (0u64..).zip(output_blindings) {
        require_eq(
            poseidon(&[
                Field::from(DOMAIN_TRANSACT_OUTPUT_BLINDING_V1),
                first_nullifier,
                output_seed,
                Field::from(slot),
            ])?,
            *blinding,
        );
    }
    Ok(())
}
