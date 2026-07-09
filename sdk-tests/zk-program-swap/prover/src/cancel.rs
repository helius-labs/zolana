use std::collections::HashMap;

use solana_address::Address;
use swap_program::instructions::{cancel::CancelProof, shared::u64_to_field};
use zolana_hasher::{Hasher, Poseidon};

use crate::{
    bytes_to_decimal_string, create::gnark_proof_to_wire, ffi, order_terms::OrderTerms, CircuitId,
    OrderProof, UtxoFieldElements,
};

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
    pub escrow_utxo_hash: [u8; 32],
    pub source_output_hash: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct CancelProofInputs {
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

struct CancelBuild {
    witness: HashMap<String, Vec<String>>,
    public_input_hash: [u8; 32],
    private_tx_hash: [u8; 32],
    escrow_utxo_hash: [u8; 32],
    source_output_hash: [u8; 32],
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
    fn order_terms(&self) -> Result<OrderTerms, CancelError> {
        Ok(OrderTerms {
            destination_asset: Address::new_from_array(self.destination_mint),
            destination_amount: self.destination_amount,
            destination: crate::order_terms::maker_address_fe(
                &self.maker_owner_hash,
                &self.maker_viewing_pk,
            )?,
            expiry: self.expiry,
            taker: self.taker_pk_fe,
            fill_mode: self.fill_mode,
        })
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

    fn escrow_utxo(&self) -> Result<UtxoFieldElements, CancelError> {
        Ok(UtxoFieldElements::plain(
            self.escrow_owner()?,
            self.source_asset()?,
            self.source_amount,
            self.escrow_blinding,
            self.order_terms()?.data_hash()?,
        ))
    }

    fn source_output_utxo(&self, owner: &[u8; 32]) -> Result<UtxoFieldElements, CancelError> {
        Ok(UtxoFieldElements::plain(
            *owner,
            self.source_asset()?,
            self.source_amount,
            self.source_output_blinding,
            [0u8; 32],
        ))
    }

    fn private_tx_hash(
        &self,
        escrow_utxo_hash: &[u8; 32],
        source_output_hash: &[u8; 32],
    ) -> Result<[u8; 32], CancelError> {
        let input_chain = hash_chain(&[*escrow_utxo_hash])?;
        let output_chain = hash_chain(&[*source_output_hash])?;
        let address_chain = hash_chain(&[[0u8; 32]])?;
        poseidon(&[
            &input_chain,
            &output_chain,
            &address_chain,
            &self.external_data_hash,
        ])
    }

    fn witness_map(
        &self,
        escrow: &UtxoFieldElements,
        source_output: &UtxoFieldElements,
        public_input_hash: &[u8; 32],
        private_tx_hash: &[u8; 32],
    ) -> Result<HashMap<String, Vec<String>>, CancelError> {
        let scalars: [(&str, [u8; 32]); 11] = [
            ("Public_PublicInputHash", *public_input_hash),
            ("Public_PrivateTxHash", *private_tx_hash),
            ("Order_DestinationAsset", self.destination_asset()?),
            (
                "Order_DestinationAmount",
                u64_to_field(self.destination_amount),
            ),
            ("Order_MakerOwnerHash", self.maker_owner_hash),
            ("Order_Expiry", u64_to_field(self.expiry)),
            ("Order_TakerPkFe", self.taker_pk_fe),
            ("Order_FillMode", u64_to_field(self.fill_mode)),
            ("MakerOwnerPkField", self.maker_owner_pk_field),
            ("MakerNullifierPk", self.maker_nullifier_pk),
            ("ExternalDataHash", self.external_data_hash),
        ];

        let mut map = HashMap::new();
        for (key, value) in scalars.iter() {
            map.insert(key.to_string(), vec![bytes_to_decimal_string(value)]);
        }
        map.insert(
            "Order_MakerViewingPk".to_string(),
            self.maker_viewing_pk
                .iter()
                .map(|b| b.to_string())
                .collect(),
        );
        for (key, values) in escrow.witness_entries("Escrow") {
            map.insert(key, values);
        }
        for (key, values) in source_output.witness_entries("SourceOutput") {
            map.insert(key, values);
        }
        Ok(map)
    }

    fn build(&self, source_output_owner: &[u8; 32]) -> Result<CancelBuild, CancelError> {
        let escrow = self.escrow_utxo()?;
        let source_output = self.source_output_utxo(source_output_owner)?;
        let escrow_utxo_hash = escrow.hash()?;
        let source_output_hash = source_output.hash()?;
        let private_tx_hash = self.private_tx_hash(&escrow_utxo_hash, &source_output_hash)?;
        let expiry = u64_to_field(self.expiry);
        let public_input_hash = poseidon(&[&private_tx_hash, &expiry, &self.maker_owner_pk_field])?;
        let witness = self.witness_map(
            &escrow,
            &source_output,
            &public_input_hash,
            &private_tx_hash,
        )?;
        Ok(CancelBuild {
            witness,
            public_input_hash,
            private_tx_hash,
            escrow_utxo_hash,
            source_output_hash,
        })
    }

    pub fn public_input_hash(&self) -> Result<[u8; 32], CancelError> {
        Ok(self.build(&self.maker_owner_hash)?.public_input_hash)
    }

    pub fn prove_with_source_output_owner(
        &self,
        owner: &[u8; 32],
    ) -> Result<CancelProofResult, CancelError> {
        self.prove_build(self.build(owner)?)
    }

    pub fn prove(&self) -> Result<CancelProofResult, CancelError> {
        self.prove_build(self.build(&self.maker_owner_hash)?)
    }

    fn prove_build(&self, build: CancelBuild) -> Result<CancelProofResult, CancelError> {
        let CancelBuild {
            witness,
            public_input_hash,
            private_tx_hash,
            escrow_utxo_hash,
            source_output_hash,
        } = build;
        let out = ffi::prove(CircuitId::Cancel, &witness)?;
        let proof = gnark_proof_to_wire(&out)?;
        Ok(CancelProofResult {
            proof,
            public_input_hash,
            private_tx_hash,
            escrow_utxo_hash,
            source_output_hash,
        })
    }
}
