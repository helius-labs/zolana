use ark_ff::{BigInteger, PrimeField};
use zolana_client::ProofInputUtxo;

use crate::{constant, value, CircuitVar, Field, RelationError, TxContext, Utxo};

pub fn field(bytes: &[u8; 32], name: &'static str) -> Result<Field, RelationError> {
    let field = Field::from_be_bytes_mod_order(bytes);
    if field_bytes(&field) == *bytes {
        Ok(field)
    } else {
        Err(RelationError::NonCanonical(name))
    }
}

pub fn var(bytes: &[u8; 32], name: &'static str) -> Result<CircuitVar, RelationError> {
    Ok(constant(field(bytes, name)?))
}

pub fn field_bytes(field: &Field) -> [u8; 32] {
    be_bytes(field)
}

pub(crate) fn be_bytes(element: &impl PrimeField) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    let big_endian = element.into_bigint().to_bytes_be();
    for (target, source) in bytes.iter_mut().rev().zip(big_endian.iter().rev()) {
        *target = *source;
    }
    bytes
}

pub fn to_bytes(var: &CircuitVar) -> Result<[u8; 32], RelationError> {
    Ok(field_bytes(&value(var)?))
}

pub fn tx_context(
    first_nullifier: &[u8; 32],
    blinding_seed: &[u8; 32],
    output_tree_id: u16,
) -> Result<TxContext, RelationError> {
    Ok(TxContext {
        first_nullifier: var(first_nullifier, "first nullifier")?,
        blinding_seed: var(blinding_seed, "blinding seed")?,
        output_tree_id: constant(u64::from(output_tree_id)),
    })
}

pub fn utxo(proof_inputs: &ProofInputUtxo) -> Result<Utxo, RelationError> {
    Ok(Utxo {
        domain: var(&proof_inputs.domain, "utxo domain")?,
        owner: var(&proof_inputs.owner_hash, "utxo owner")?,
        asset: var(&proof_inputs.asset, "utxo asset")?,
        amount: var(&proof_inputs.amount, "utxo amount")?,
        blinding: var(&proof_inputs.blinding, "utxo blinding")?,
        data_hash: var(&proof_inputs.data_hash, "utxo data hash")?,
        ring_data_hash: var(&proof_inputs.ring_data_hash, "utxo ring data hash")?,
        ring_program_id: var(&proof_inputs.ring_program_id, "utxo ring program id")?,
        tree_id: var(&proof_inputs.tree_id, "utxo tree id")?,
    })
}
