use std::collections::HashMap;

use solana_address::Address;
use swap_program::instructions::{fill::FillProof, shared::u64_to_field};
use zolana_hasher::{Hasher, Poseidon};

use crate::{
    bytes_to_decimal_string, create::gnark_proof_to_wire, ffi, order_terms::OrderTerms,
    utxo::UtxoFieldElements, CircuitId, OrderProof,
};

pub const DESTINATION_BLINDING_DOMAIN: u64 = 0x46494C4C44455256;

const DESTINATION_BLINDING_TOP_BYTE: usize = 0;

#[derive(Debug, thiserror::Error)]
pub enum FillError {
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

impl From<crate::create::CreateError> for FillError {
    fn from(e: crate::create::CreateError) -> Self {
        match e {
            crate::create::CreateError::Ffi(e) => FillError::Ffi(e),
            crate::create::CreateError::Keypair(e) => FillError::Keypair(e),
            crate::create::CreateError::Poseidon => FillError::Poseidon,
            crate::create::CreateError::CompressG1(s) => FillError::CompressG1(s),
            crate::create::CreateError::CompressG2(s) => FillError::CompressG2(s),
        }
    }
}

pub fn derive_destination_blinding(
    escrow_blinding: &[u8; 32],
) -> Result<[u8; 32], zolana_keypair::KeypairError> {
    let domain = u64_to_field(DESTINATION_BLINDING_DOMAIN);
    let mut out = zolana_keypair::hash::poseidon(&[escrow_blinding, &domain])?;
    out[DESTINATION_BLINDING_TOP_BYTE] = 0;
    Ok(out)
}

impl From<OrderProof> for FillProof {
    fn from(proof: OrderProof) -> Self {
        Self {
            proof_a: proof.proof_a,
            proof_b: proof.proof_b,
            proof_c: proof.proof_c,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FillProofResult {
    pub proof: OrderProof,
    pub public_input_hash: [u8; 32],
    pub private_tx_hash: [u8; 32],
    pub destination_output_blinding: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct FillProofInputs {
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
    pub taker_address: [u8; 32],
    pub taker_in_blinding: [u8; 32],
    pub source_output_blinding: [u8; 32],
    pub external_data_hash: [u8; 32],
}

fn poseidon(inputs: &[&[u8; 32]]) -> Result<[u8; 32], FillError> {
    let slices: Vec<&[u8]> = inputs.iter().map(|i| i.as_slice()).collect();
    Poseidon::hashv(&slices).map_err(|_| FillError::Poseidon)
}

fn hash_chain(inputs: &[[u8; 32]]) -> Result<[u8; 32], FillError> {
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

struct FillUtxos {
    escrow: UtxoFieldElements,
    taker_in: UtxoFieldElements,
    source_output: UtxoFieldElements,
    destination_output: UtxoFieldElements,
}

struct FillDerivation {
    utxos: FillUtxos,
    private_tx_hash: [u8; 32],
    public_input_hash: [u8; 32],
    destination_output_blinding: [u8; 32],
}

impl FillProofInputs {
    fn order_terms(&self) -> Result<OrderTerms, FillError> {
        Ok(OrderTerms {
            destination_asset: Address::new_from_array(self.destination_mint),
            destination_amount: self.destination_amount,
            destination: crate::order_terms::maker_address_fe(
                &self.maker_owner_hash,
                &self.maker_viewing_pk,
            )?,
            expiry: self.expiry,
            taker: self.taker_pk_fe,
            fill_mode: crate::order_terms::FILL_MODE_DERIVED,
        })
    }

    fn source_asset(&self) -> Result<[u8; 32], FillError> {
        Ok(crate::asset_field(&self.source_mint)?)
    }

    fn destination_asset(&self) -> Result<[u8; 32], FillError> {
        Ok(crate::asset_field(&self.destination_mint)?)
    }

    fn escrow_owner(&self) -> Result<[u8; 32], FillError> {
        Ok(crate::escrow_owner_hash(&self.escrow_authority)?)
    }

    pub fn destination_output_blinding(&self) -> Result<[u8; 32], FillError> {
        Ok(derive_destination_blinding(&self.escrow_blinding)?)
    }

    fn utxos(&self, destination_output_blinding: &[u8; 32]) -> Result<FillUtxos, FillError> {
        let source_asset = self.source_asset()?;
        let destination_asset = self.destination_asset()?;
        let data_hash = self.order_terms()?.data_hash()?;
        let zero = [0u8; 32];

        let escrow = UtxoFieldElements::plain(
            self.escrow_owner()?,
            source_asset,
            self.source_amount,
            self.escrow_blinding,
            data_hash,
        );
        let taker_in = UtxoFieldElements::plain(
            self.taker_address,
            destination_asset,
            self.destination_amount,
            self.taker_in_blinding,
            zero,
        );
        let source_output = UtxoFieldElements::plain(
            self.taker_address,
            source_asset,
            self.source_amount,
            self.source_output_blinding,
            zero,
        );
        let destination_output = UtxoFieldElements::plain(
            self.maker_owner_hash,
            destination_asset,
            self.destination_amount,
            *destination_output_blinding,
            zero,
        );

        Ok(FillUtxos {
            escrow,
            taker_in,
            source_output,
            destination_output,
        })
    }

    fn private_tx_hash(
        &self,
        escrow_utxo_hash: &[u8; 32],
        taker_utxo_hash: &[u8; 32],
        source_output_hash: &[u8; 32],
        destination_output_hash: &[u8; 32],
    ) -> Result<[u8; 32], FillError> {
        let input_chain = hash_chain(&[*escrow_utxo_hash, *taker_utxo_hash])?;
        let output_chain = hash_chain(&[*source_output_hash, *destination_output_hash])?;
        let address_chain = hash_chain(&[[0u8; 32], [0u8; 32]])?;
        poseidon(&[
            &input_chain,
            &output_chain,
            &address_chain,
            &self.external_data_hash,
        ])
    }

    fn derive(&self, destination_output_blinding: &[u8; 32]) -> Result<FillDerivation, FillError> {
        let utxos = self.utxos(destination_output_blinding)?;
        let escrow_utxo_hash = utxos.escrow.hash()?;
        let taker_utxo_hash = utxos.taker_in.hash()?;
        let source_output_hash = utxos.source_output.hash()?;
        let destination_output_hash = utxos.destination_output.hash()?;
        let private_tx_hash = self.private_tx_hash(
            &escrow_utxo_hash,
            &taker_utxo_hash,
            &source_output_hash,
            &destination_output_hash,
        )?;
        let expiry = u64_to_field(self.expiry);
        let public_input_hash = poseidon(&[&private_tx_hash, &expiry])?;
        Ok(FillDerivation {
            utxos,
            private_tx_hash,
            public_input_hash,
            destination_output_blinding: *destination_output_blinding,
        })
    }

    pub fn public_input_hash(&self) -> Result<[u8; 32], FillError> {
        Ok(self
            .derive(&self.destination_output_blinding()?)?
            .public_input_hash)
    }

    fn witness_map(&self, derived: &FillDerivation) -> Result<ffi::WitnessMap, FillError> {
        let mut map = HashMap::new();
        for utxo_entries in [
            derived.utxos.escrow.witness_entries("Core_Escrow"),
            derived.utxos.taker_in.witness_entries("Core_TakerIn"),
            derived
                .utxos
                .source_output
                .witness_entries("Core_SourceOutput"),
            derived
                .utxos
                .destination_output
                .witness_entries("Core_DestinationOutput"),
        ] {
            for (key, value) in utxo_entries {
                map.insert(key, value);
            }
        }

        let scalars: [(&str, [u8; 32]); 9] = [
            ("Public_PublicInputHash", derived.public_input_hash),
            ("Public_PrivateTxHash", derived.private_tx_hash),
            ("Core_Order_DestinationAsset", self.destination_asset()?),
            (
                "Core_Order_DestinationAmount",
                u64_to_field(self.destination_amount),
            ),
            ("Core_Order_MakerOwnerHash", self.maker_owner_hash),
            ("Core_Order_Expiry", u64_to_field(self.expiry)),
            ("Core_Order_TakerPkFe", self.taker_pk_fe),
            (
                "Core_Order_FillMode",
                u64_to_field(crate::order_terms::FILL_MODE_DERIVED),
            ),
            ("Core_ExternalDataHash", self.external_data_hash),
        ];
        for (key, value) in scalars.iter() {
            map.insert(key.to_string(), vec![bytes_to_decimal_string(value)]);
        }
        map.insert(
            "Core_Order_MakerViewingPk".to_string(),
            self.maker_viewing_pk
                .iter()
                .map(|b| b.to_string())
                .collect(),
        );

        Ok(map)
    }

    fn prove_with_derivation(
        &self,
        derived: &FillDerivation,
    ) -> Result<FillProofResult, FillError> {
        let witness = self.witness_map(derived)?;
        let out = ffi::prove(CircuitId::Fill, &witness)?;
        let proof = gnark_proof_to_wire(&out)?;
        Ok(FillProofResult {
            proof,
            public_input_hash: derived.public_input_hash,
            private_tx_hash: derived.private_tx_hash,
            destination_output_blinding: derived.destination_output_blinding,
        })
    }

    pub fn prove(&self) -> Result<FillProofResult, FillError> {
        let derived = self.derive(&self.destination_output_blinding()?)?;
        self.prove_with_derivation(&derived)
    }

    pub fn prove_with_destination_output_blinding(
        &self,
        blinding: &[u8; 32],
    ) -> Result<FillProofResult, FillError> {
        let derived = self.derive(blinding)?;
        self.prove_with_derivation(&derived)
    }
}
