use borsh::{BorshDeserialize, BorshSerialize};
use zolana_hasher::{
    hash_chain::create_hash_chain_4_from_slice as chain,
    primitives::{hash_bytes, is_canonical_bn254_scalar_be, solana_owner_identity},
    Hasher, HasherError, Keccak,
};

use crate::{event::OutputUtxo, SHIELDED_POOL_PROGRAM_ID};

pub const BUFFER_SEED: &[u8] = b"direct_spend";
pub const CERTIFICATE_INPUTS: usize = 36;
pub const MAX_INPUTS: usize = 512;
pub const GKR_PAYMENT_INPUTS: [usize; 2] = [144, MAX_INPUTS];
pub const MAX_CERTIFICATES: usize = 16;
pub const MAX_PAYLOAD: usize = 24_000;
pub const CERTIFICATE_DOMAIN: u64 = 0x44534331;
pub const BALANCE_DOMAIN: u64 = 0x44534231;
pub const FRESHNESS_DOMAIN: u64 = 0x44534631;
pub const PAYMENT_DOMAIN: u64 = 0x44535031;
pub const ADMITTED_PAYMENT_DOMAIN: u64 = 0x44535032;

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Proof {
    pub a: [u8; 32],
    pub b: [u8; 128],
    pub c: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Root {
    pub index: u16,
    pub value: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Certificate {
    pub tree: [u8; 32],
    pub state_root: Root,
    pub nullifiers: Vec<[u8; 32]>,
    pub value_commitment: [u8; 32],
}

impl Certificate {
    pub fn validate(&self, capacity: usize) -> bool {
        !self.nullifiers.is_empty()
            && self.nullifiers.len() <= capacity
            && self
                .nullifiers
                .iter()
                .all(|n| *n != [0; 32] && is_canonical_bn254_scalar_be(n))
            && self.value_commitment != [0; 32]
            && is_canonical_bn254_scalar_be(&self.value_commitment)
    }

    pub fn fields(
        &self,
        id: [u8; 32],
        owner: &[u8; 32],
        tree_id: u16,
        capacity: usize,
    ) -> Result<Vec<[u8; 32]>, HasherError> {
        Ok(vec![
            field(CERTIFICATE_DOMAIN),
            id,
            field(tree_id.into()),
            self.state_root.value,
            solana_owner_identity(owner)?,
            field(self.nullifiers.len() as u64),
            self.nullifier_hash(capacity)?,
            self.value_commitment,
        ])
    }

    pub fn freshness_fields(
        &self,
        root: Root,
        tree_id: u16,
        capacity: usize,
    ) -> Result<Vec<[u8; 32]>, HasherError> {
        Ok(vec![
            field(FRESHNESS_DOMAIN),
            field(tree_id.into()),
            root.value,
            field(self.nullifiers.len() as u64),
            self.nullifier_hash(capacity)?,
        ])
    }

    fn nullifier_hash(&self, capacity: usize) -> Result<[u8; 32], HasherError> {
        let mut nullifiers = self.nullifiers.clone();
        nullifiers.resize(capacity, [0; 32]);
        chain(&nullifiers)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum PaymentInputs {
    Certificates(Vec<[u8; 32]>),
    Notes {
        certificate: Certificate,
        freshness: Root,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Output {
    pub recipient: [u8; 32],
    pub utxo: OutputUtxo,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Payment {
    pub inputs: PaymentInputs,
    pub output_tree: [u8; 32],
    pub expiry_slot: u64,
    pub max_forester_fee: u64,
    pub outputs: Vec<Output>,
    pub tx_viewing_pk: [u8; 33],
    pub salt: [u8; 16],
}

impl Payment {
    pub fn validate(&self) -> bool {
        let inputs = match &self.inputs {
            PaymentInputs::Certificates(ids) => !ids.is_empty() && ids.len() <= MAX_CERTIFICATES,
            PaymentInputs::Notes { certificate, .. } => certificate.validate(MAX_INPUTS),
        };
        inputs
            && self.outputs.len() == 2
            && self.outputs.iter().all(|output| {
                (output.utxo.data.is_empty()
                    || zolana_event::is_confidential_encrypted_output(&output.utxo.data))
                    && is_canonical_bn254_scalar_be(&output.utxo.utxo_hash)
            })
    }

    pub fn intent(&self, owner: &[u8; 32], buffer: &[u8; 32]) -> Result<[u8; 32], HasherError> {
        let bytes = borsh::to_vec(self).expect("serializing a payment into a Vec cannot fail");
        let mut hash = Keccak::hashv(&[
            b"SPP direct spend v1",
            &SHIELDED_POOL_PROGRAM_ID,
            owner,
            buffer,
            &bytes,
        ])?;
        hash[0] &= 0x1f;
        Ok(hash)
    }

    pub fn balance_fields(
        &self,
        intent: [u8; 32],
        output_tree_id: u16,
        values: &[[[u8; 32]; 2]],
        capacity: usize,
    ) -> Result<Vec<[u8; 32]>, HasherError> {
        let mut inputs: Vec<_> = values.iter().flatten().copied().collect();
        inputs.resize(capacity * 2, [0; 32]);
        let mut outputs = Vec::with_capacity(4);
        for output in &self.outputs {
            outputs.push(output.utxo.utxo_hash);
            outputs.push(solana_owner_identity(&output.recipient)?);
        }
        Ok(vec![
            field(BALANCE_DOMAIN),
            intent,
            field(output_tree_id.into()),
            chain(&inputs)?,
            chain(&outputs)?,
        ])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Payload {
    Certificate {
        statement: Certificate,
        proof: Proof,
    },
    Payment {
        statement: Payment,
        proof: Proof,
    },
    GkrPayment {
        statement: Payment,
        proof: Proof,
        commitment: crate::verifying_keys::Bsb22Commitment,
        inputs: u16,
    },
    AdmittedPayment {
        statement: Payment,
        proof: Proof,
        commitment: crate::verifying_keys::Bsb22Commitment,
        inputs: u16,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum BufferInstruction {
    Create { nonce: [u8; 32], size: u16 },
    Write { offset: u16, bytes: Vec<u8> },
    Close,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct PrepareCertificate {
    pub freshness: Root,
    pub proof: Proof,
}

pub fn certificate_id(buffer: &[u8; 32]) -> Result<[u8; 32], HasherError> {
    hash_bytes(buffer)
}

pub fn field(value: u64) -> [u8; 32] {
    let mut field = [0; 32];
    field[24..].copy_from_slice(&value.to_be_bytes());
    field
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payment(data: Vec<u8>) -> Payment {
        Payment {
            inputs: PaymentInputs::Certificates(vec![[2; 32]]),
            output_tree: [3; 32],
            expiry_slot: u64::MAX,
            max_forester_fee: 0,
            outputs: vec![
                Output {
                    recipient: [4; 32],
                    utxo: OutputUtxo {
                        view_tag: [0; 32],
                        utxo_hash: [1; 32],
                        data,
                    },
                };
                2
            ],
            tx_viewing_pk: [0; 33],
            salt: [0; 16],
        }
    }

    #[test]
    fn output_data_accepts_only_empty_or_confidential_envelopes() {
        assert!(payment(Vec::new()).validate());
        assert!(!payment(vec![1]).validate());
        let data =
            borsh::to_vec(&zolana_event::OutputDataEncoding::Encrypted(vec![3, 1, 2])).unwrap();
        let original = payment(data);
        assert!(original.validate());
        let before = original.intent(&[5; 32], &[6; 32]).unwrap();
        let mut changed = original.clone();
        changed.outputs[0].utxo.data[6] ^= 1;
        assert_ne!(before, changed.intent(&[5; 32], &[6; 32]).unwrap());
        changed = original.clone();
        changed.outputs[0].utxo.view_tag[0] ^= 1;
        assert_ne!(before, changed.intent(&[5; 32], &[6; 32]).unwrap());
        changed = original;
        changed.salt[0] ^= 1;
        assert_ne!(before, changed.intent(&[5; 32], &[6; 32]).unwrap());
    }
}
