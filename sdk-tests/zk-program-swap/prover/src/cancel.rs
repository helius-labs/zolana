use std::collections::HashMap;

use solana_address::Address;
use swap_program::instructions::{cancel::CancelProof, shared::u64_to_field};
use zolana_hasher::{Hasher, Poseidon};

use crate::{
    bytes_to_decimal_string, create::gnark_proof_to_wire, ffi, order_terms::OrderTerms, CircuitId,
    OrderProof, WitnessBundle,
};

pub const UTXO_DOMAIN: u64 = 1;

#[derive(Debug, thiserror::Error)]
pub enum CancelError {
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

impl From<crate::create::CreateError> for CancelError {
    fn from(e: crate::create::CreateError) -> Self {
        match e {
            crate::create::CreateError::Ffi(e) => CancelError::Ffi(e),
            crate::create::CreateError::Keypair(e) => CancelError::Keypair(e),
            crate::create::CreateError::Poseidon => CancelError::Poseidon,
            crate::create::CreateError::CompressG1(s) => CancelError::CompressG1(s),
            crate::create::CreateError::CompressG2(s) => CancelError::CompressG2(s),
        }
    }
}

impl From<OrderProof> for CancelProof {
    fn from(proof: OrderProof) -> Self {
        Self {
            proof_a: proof.proof_a,
            proof_b: proof.proof_b,
            proof_c: proof.proof_c,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CancelProofResult {
    pub proof: OrderProof,
    pub public_input_hash: [u8; 32],
    pub private_tx_hash: [u8; 32],
    pub escrow_hash: [u8; 32],
    pub source_output_hash: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct CancelProofInputs {
    pub source_asset_id: u64,
    pub source_mint: [u8; 32],
    pub source_amount: u64,
    pub escrow_authority: [u8; 32],
    pub escrow_blinding: [u8; 32],
    pub destination_mint: [u8; 32],
    pub destination_amount: u64,
    pub maker_owner_hash: [u8; 32],
    pub maker_owner_pk_field: [u8; 32],
    pub maker_nullifier_pk: [u8; 32],
    pub maker_viewing_pk: [u8; 33],
    pub expiry: u64,
    pub taker_pk_fe: [u8; 32],
    pub fill_mode: u64,
    pub source_output_blinding: [u8; 32],
    pub external_data_hash: [u8; 32],
}

fn poseidon(inputs: &[&[u8; 32]]) -> Result<[u8; 32], CancelError> {
    let slices: Vec<&[u8]> = inputs.iter().map(|i| i.as_slice()).collect();
    Poseidon::hashv(&slices).map_err(|_| CancelError::Poseidon)
}

fn hash_chain(inputs: &[[u8; 32]]) -> Result<[u8; 32], CancelError> {
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

impl CancelProofInputs {
    fn order_terms(&self) -> OrderTerms {
        OrderTerms {
            destination_asset: Address::new_from_array(self.destination_mint),
            destination_amount: self.destination_amount,
            maker_owner_hash: self.maker_owner_hash,
            maker_viewing_pk: self.maker_viewing_pk,
            expiry: self.expiry,
            taker_pk_fe: self.taker_pk_fe,
            fill_mode: self.fill_mode,
        }
    }

    fn source_asset(&self) -> Result<[u8; 32], CancelError> {
        Ok(crate::asset_field(&self.source_mint)?)
    }

    fn destination_asset(&self) -> Result<[u8; 32], CancelError> {
        Ok(crate::asset_field(&self.destination_mint)?)
    }

    fn escrow_owner(&self) -> Result<[u8; 32], CancelError> {
        Ok(crate::escrow_owner_hash(&self.escrow_authority)?)
    }

    fn escrow_hash(&self) -> Result<[u8; 32], CancelError> {
        let domain = u64_to_field(UTXO_DOMAIN);
        let asset = self.source_asset()?;
        let amount = u64_to_field(self.source_amount);
        let data_hash = self.order_terms().data_hash()?;
        let owner = self.escrow_owner()?;

        let zero = [0u8; 32];
        let owner_utxo_hash = poseidon(&[&owner, &self.escrow_blinding])?;
        let zone_hash = poseidon(&[&zero, &zero])?;
        poseidon(&[
            &domain,
            &asset,
            &amount,
            &data_hash,
            &zone_hash,
            &owner_utxo_hash,
        ])
    }

    fn source_output_hash(&self) -> Result<[u8; 32], CancelError> {
        self.source_output_hash_for_owner(&self.maker_owner_hash)
    }

    fn source_output_hash_for_owner(&self, owner: &[u8; 32]) -> Result<[u8; 32], CancelError> {
        let domain = u64_to_field(UTXO_DOMAIN);
        let asset = self.source_asset()?;
        let amount = u64_to_field(self.source_amount);

        let zero = [0u8; 32];
        let owner_utxo_hash = poseidon(&[owner, &self.source_output_blinding])?;
        let zone_hash = poseidon(&[&zero, &zero])?;
        poseidon(&[
            &domain,
            &asset,
            &amount,
            &zero,
            &zone_hash,
            &owner_utxo_hash,
        ])
    }

    fn private_tx_hash(
        &self,
        escrow_hash: &[u8; 32],
        source_output_hash: &[u8; 32],
    ) -> Result<[u8; 32], CancelError> {
        let input_chain = hash_chain(&[*escrow_hash])?;
        let output_chain = hash_chain(&[*source_output_hash])?;
        let address_chain = hash_chain(&[[0u8; 32]])?;
        poseidon(&[
            &input_chain,
            &output_chain,
            &address_chain,
            &self.external_data_hash,
        ])
    }

    pub fn public_input_hash(&self) -> Result<[u8; 32], CancelError> {
        let escrow_hash = self.escrow_hash()?;
        let source_output_hash = self.source_output_hash()?;
        let private_tx_hash = self.private_tx_hash(&escrow_hash, &source_output_hash)?;
        let expiry = u64_to_field(self.expiry);
        poseidon(&[&private_tx_hash, &expiry, &self.maker_owner_pk_field])
    }

    fn witness_map(
        &self,
        public_input_hash: &[u8; 32],
        private_tx_hash: &[u8; 32],
    ) -> Result<HashMap<String, Vec<String>>, CancelError> {
        let expiry = u64_to_field(self.expiry);
        let entries: [(&str, [u8; 32]); 16] = [
            ("PublicInputHash", *public_input_hash),
            ("PrivateTxHash", *private_tx_hash),
            ("Expiry", expiry),
            ("SourceAsset", self.source_asset()?),
            ("EscrowOwner", self.escrow_owner()?),
            ("SourceAmount", u64_to_field(self.source_amount)),
            ("EscrowBlinding", self.escrow_blinding),
            ("DestinationAsset", self.destination_asset()?),
            ("DestinationAmount", u64_to_field(self.destination_amount)),
            ("MakerOwnerHash", self.maker_owner_hash),
            ("MakerOwnerPkField", self.maker_owner_pk_field),
            ("MakerNullifierPk", self.maker_nullifier_pk),
            ("TakerPkFe", self.taker_pk_fe),
            ("FillMode", u64_to_field(self.fill_mode)),
            ("SourceOutputBlinding", self.source_output_blinding),
            ("ExternalDataHash", self.external_data_hash),
        ];

        let mut map = HashMap::new();
        for (key, value) in entries.iter() {
            map.insert(key.to_string(), vec![bytes_to_decimal_string(value)]);
        }
        map.insert(
            "MakerViewingPk".to_string(),
            self.maker_viewing_pk
                .iter()
                .map(|b| b.to_string())
                .collect(),
        );
        Ok(map)
    }

    fn witness(&self) -> Result<WitnessBundle, CancelError> {
        let escrow_hash = self.escrow_hash()?;
        let source_output_hash = self.source_output_hash()?;
        let private_tx_hash = self.private_tx_hash(&escrow_hash, &source_output_hash)?;
        let expiry = u64_to_field(self.expiry);
        let public_input_hash = poseidon(&[&private_tx_hash, &expiry, &self.maker_owner_pk_field])?;
        let witness = self.witness_map(&public_input_hash, &private_tx_hash)?;
        Ok(WitnessBundle {
            witness,
            public_input_hash,
            private_tx_hash,
        })
    }

    pub fn prove_with_source_output_owner(
        &self,
        owner: &[u8; 32],
    ) -> Result<CancelProofResult, CancelError> {
        let escrow_hash = self.escrow_hash()?;
        let source_output_hash = self.source_output_hash_for_owner(owner)?;
        let private_tx_hash = self.private_tx_hash(&escrow_hash, &source_output_hash)?;
        let expiry = u64_to_field(self.expiry);
        let public_input_hash = poseidon(&[&private_tx_hash, &expiry, &self.maker_owner_pk_field])?;
        let witness = self.witness_map(&public_input_hash, &private_tx_hash)?;

        let out = ffi::prove(CircuitId::Cancel, &witness)?;
        let proof = gnark_proof_to_wire(&out)?;
        Ok(CancelProofResult {
            proof,
            public_input_hash,
            private_tx_hash,
            escrow_hash,
            source_output_hash,
        })
    }

    pub fn prove(&self) -> Result<CancelProofResult, CancelError> {
        let escrow_hash = self.escrow_hash()?;
        let source_output_hash = self.source_output_hash()?;
        let WitnessBundle {
            witness,
            public_input_hash,
            private_tx_hash,
        } = self.witness()?;
        let out = ffi::prove(CircuitId::Cancel, &witness)?;
        let proof = gnark_proof_to_wire(&out)?;
        Ok(CancelProofResult {
            proof,
            public_input_hash,
            private_tx_hash,
            escrow_hash,
            source_output_hash,
        })
    }
}
