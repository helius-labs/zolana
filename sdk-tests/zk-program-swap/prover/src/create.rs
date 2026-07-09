use std::collections::HashMap;

use groth16_solana::groth16::negate_g1_be;
use solana_address::Address;
use solana_bn254::compression::prelude::{alt_bn128_g1_compress_be, alt_bn128_g2_compress_be};
use swap_program::instructions::{create_swap::CreateProof, shared::u64_to_field};
use zolana_hasher::{Hasher, Poseidon};

use crate::{
    bytes_to_decimal_string, ffi, order_terms::OrderTerms, CircuitId, ProveOutput,
    UtxoFieldElements, WitnessBundle,
};

#[derive(Debug, thiserror::Error)]
pub enum CreateError {
    #[error("ffi error: {0}")]
    Ffi(#[from] ffi::Error),
    #[error("keypair error: {0}")]
    Keypair(#[from] zolana_keypair::KeypairError),
    #[error("poseidon hashing failed")]
    Poseidon,
    #[error("compress G1 failed: {0}")]
    CompressG1(String),
    #[error("compress G2 failed: {0}")]
    CompressG2(String),
}

#[derive(Debug, Clone, Copy)]
pub struct OrderProof {
    pub proof_a: [u8; 32],
    pub proof_b: [u8; 64],
    pub proof_c: [u8; 32],
    pub commitment: Option<([u8; 32], [u8; 32])>,
}

impl From<OrderProof> for CreateProof {
    fn from(proof: OrderProof) -> Self {
        Self {
            proof_a: proof.proof_a,
            proof_b: proof.proof_b,
            proof_c: proof.proof_c,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CreateProofResult {
    pub proof: OrderProof,
    pub public_input_hash: [u8; 32],
    pub private_tx_hash: [u8; 32],
    pub escrow_hash: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct CreateProofInputs {
    pub source_mint: [u8; 32],
    pub source_amount: u64,
    pub escrow_authority: [u8; 32],
    pub escrow_blinding: [u8; 32],
    pub destination_mint: [u8; 32],
    pub destination_amount: u64,
    pub maker_owner_hash: [u8; 32],
    pub maker_viewing_pk: [u8; 33],
    pub expiry: u64,
    pub taker_pk_fe: [u8; 32],
    pub fill_mode: u64,
    pub external_data_hash: [u8; 32],
    pub source_input_hash: [u8; 32],
    pub change_amount: u64,
    pub change_blinding: [u8; 32],
    pub marker_owner_hash: [u8; 32],
}

fn poseidon(inputs: &[&[u8; 32]]) -> Result<[u8; 32], CreateError> {
    let slices: Vec<&[u8]> = inputs.iter().map(|i| i.as_slice()).collect();
    Poseidon::hashv(&slices).map_err(|_| CreateError::Poseidon)
}

fn hash_chain(inputs: &[[u8; 32]]) -> Result<[u8; 32], CreateError> {
    let mut iter = inputs.iter();
    let first = match iter.next() {
        Some(v) => *v,
        None => return Ok([0u8; 32]),
    };
    let mut acc = first;
    for next in iter {
        acc = poseidon(&[&acc, next])?;
    }
    Ok(acc)
}

impl CreateProofInputs {
    fn order_terms(&self) -> Result<OrderTerms, CreateError> {
        Ok(OrderTerms {
            destination_asset: Address::new_from_array(self.destination_mint),
            destination_amount: self.destination_amount,
            destination: self.maker_address_fe()?,
            expiry: self.expiry,
            taker: self.taker_pk_fe,
            fill_mode: self.fill_mode,
        })
    }

    fn source_asset(&self) -> Result<[u8; 32], CreateError> {
        Ok(crate::asset_field(&self.source_mint)?)
    }

    fn destination_asset(&self) -> Result<[u8; 32], CreateError> {
        Ok(crate::asset_field(&self.destination_mint)?)
    }

    fn escrow(&self) -> Result<UtxoFieldElements, CreateError> {
        Ok(UtxoFieldElements::plain(
            crate::escrow_owner_hash(&self.escrow_authority)?,
            self.source_asset()?,
            self.source_amount,
            self.escrow_blinding,
            self.order_terms()?.data_hash()?,
        ))
    }

    fn change(&self) -> Result<UtxoFieldElements, CreateError> {
        Ok(UtxoFieldElements::plain(
            self.maker_owner_hash,
            self.source_asset()?,
            self.change_amount,
            self.change_blinding,
            [0u8; 32],
        ))
    }

    fn marker(&self) -> Result<UtxoFieldElements, CreateError> {
        Ok(UtxoFieldElements::plain(
            self.marker_owner_hash,
            crate::asset_field(&[0u8; 32])?,
            0,
            [0u8; 32],
            [0u8; 32],
        ))
    }

    fn maker_address_fe(&self) -> Result<[u8; 32], CreateError> {
        crate::order_terms::maker_address_fe(&self.maker_owner_hash, &self.maker_viewing_pk)
            .map_err(|_| CreateError::Poseidon)
    }

    pub fn change_output_hash(&self) -> Result<[u8; 32], CreateError> {
        if self.change_amount == 0 {
            return Ok([0u8; 32]);
        }
        Ok(self.change()?.hash()?)
    }

    fn private_tx_hash(
        &self,
        escrow_hash: &[u8; 32],
        marker_hash: &[u8; 32],
    ) -> Result<[u8; 32], CreateError> {
        let input_chain = hash_chain(&[self.source_input_hash, [0u8; 32]])?;
        let output_chain = hash_chain(&[self.change_output_hash()?, *escrow_hash, *marker_hash])?;
        let address_chain = hash_chain(&[[0u8; 32], [0u8; 32]])?;
        poseidon(&[
            &input_chain,
            &output_chain,
            &address_chain,
            &self.external_data_hash,
        ])
    }

    pub fn public_input_hash(&self) -> Result<[u8; 32], CreateError> {
        let escrow_hash = self.escrow()?.hash()?;
        let marker_hash = self.marker()?.hash()?;
        self.private_tx_hash(&escrow_hash, &marker_hash)
    }

    fn witness(&self) -> Result<WitnessBundle, CreateError> {
        let escrow = self.escrow()?;
        let change = self.change()?;
        let marker = self.marker()?;
        let escrow_hash = escrow.hash()?;
        let marker_hash = marker.hash()?;
        let private_tx_hash = self.private_tx_hash(&escrow_hash, &marker_hash)?;

        let scalars: [(&str, [u8; 32]); 9] = [
            ("PrivateTxHash", private_tx_hash),
            ("Order_DestinationAsset", self.destination_asset()?),
            ("Order_DestinationAmount", u64_to_field(self.destination_amount)),
            ("Order_MakerOwnerHash", self.maker_owner_hash),
            ("Order_Expiry", u64_to_field(self.expiry)),
            ("Order_TakerPkFe", self.taker_pk_fe),
            ("Order_FillMode", u64_to_field(self.fill_mode)),
            ("SourceInputHash", self.source_input_hash),
            ("ExternalDataHash", self.external_data_hash),
        ];

        let mut map = HashMap::new();
        for (key, value) in scalars.iter() {
            map.insert(key.to_string(), vec![bytes_to_decimal_string(value)]);
        }
        for (key, value) in escrow
            .witness_entries("Escrow")
            .into_iter()
            .chain(change.witness_entries("Change"))
            .chain(marker.witness_entries("Marker"))
        {
            map.insert(key, value);
        }
        map.insert(
            "Order_MakerViewingPk".to_string(),
            self.maker_viewing_pk.iter().map(|b| b.to_string()).collect(),
        );

        Ok(WitnessBundle {
            witness: map,
            public_input_hash: private_tx_hash,
            private_tx_hash,
        })
    }

    pub fn prove(&self) -> Result<CreateProofResult, CreateError> {
        let escrow_hash = self.escrow()?.hash()?;
        let WitnessBundle {
            witness,
            public_input_hash,
            private_tx_hash,
        } = self.witness()?;
        let out = ffi::prove(CircuitId::Create, &witness)?;
        let proof = gnark_proof_to_wire(&out)?;
        Ok(CreateProofResult {
            proof,
            public_input_hash,
            private_tx_hash,
            escrow_hash,
        })
    }
}

pub fn gnark_proof_to_wire(out: &ProveOutput) -> Result<OrderProof, CreateError> {
    let neg_a = negate_g1_be(&out.proof_a);

    let proof_a =
        alt_bn128_g1_compress_be(&neg_a).map_err(|e| CreateError::CompressG1(format!("{e:?}")))?;
    let proof_b = alt_bn128_g2_compress_be(&out.proof_b)
        .map_err(|e| CreateError::CompressG2(format!("{e:?}")))?;
    let proof_c = alt_bn128_g1_compress_be(&out.proof_c)
        .map_err(|e| CreateError::CompressG1(format!("{e:?}")))?;

    Ok(OrderProof {
        proof_a,
        proof_b,
        proof_c,
        commitment: None,
    })
}

pub fn gnark_proof_to_wire_committed(out: &ProveOutput) -> Result<OrderProof, CreateError> {
    let mut proof = gnark_proof_to_wire(out)?;
    let commitment = alt_bn128_g1_compress_be(&out.proof_commitment)
        .map_err(|e| CreateError::CompressG1(format!("{e:?}")))?;
    let commitment_pok = alt_bn128_g1_compress_be(&out.proof_commitment_pok)
        .map_err(|e| CreateError::CompressG1(format!("{e:?}")))?;
    proof.commitment = Some((commitment, commitment_pok));
    Ok(proof)
}
