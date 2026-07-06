use std::collections::HashMap;

use solana_address::Address;
use swap_program::instructions::shared::u64_to_field;
use zolana_hasher::{Hasher, Poseidon};

use crate::{
    bytes_to_decimal_string, create::gnark_proof_to_wire, ffi, order_terms::OrderTerms, CircuitId,
    OrderProof, WitnessBundle,
};

pub const UTXO_DOMAIN: u64 = 1;

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

#[derive(Debug, Clone)]
pub struct FillProofResult {
    pub proof: OrderProof,
    pub public_input_hash: [u8; 32],
    pub private_tx_hash: [u8; 32],
    pub escrow_hash: [u8; 32],
    pub taker_utxo_hash: [u8; 32],
    pub destination_output_hash: [u8; 32],
    pub source_output_hash: [u8; 32],
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

fn plain_utxo_hash(
    domain: &[u8; 32],
    asset: &[u8; 32],
    amount: &[u8; 32],
    data_hash: &[u8; 32],
    owner: &[u8; 32],
    blinding: &[u8; 32],
) -> Result<[u8; 32], FillError> {
    let zero = [0u8; 32];
    let owner_utxo_hash = poseidon(&[owner, blinding])?;
    let zone_hash = poseidon(&[&zero, &zero])?;
    poseidon(&[
        domain,
        asset,
        amount,
        data_hash,
        &zone_hash,
        &owner_utxo_hash,
    ])
}

impl FillProofInputs {
    fn order_terms(&self) -> OrderTerms {
        OrderTerms {
            destination_asset: Address::new_from_array(self.destination_mint),
            destination_amount: self.destination_amount,
            maker_owner_hash: self.maker_owner_hash,
            maker_viewing_pk: self.maker_viewing_pk,
            expiry: self.expiry,
            taker_pk_fe: self.taker_pk_fe,
            fill_mode: crate::order_terms::FILL_MODE_DERIVED,
        }
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

    fn escrow_hash(&self) -> Result<[u8; 32], FillError> {
        let domain = u64_to_field(UTXO_DOMAIN);
        plain_utxo_hash(
            &domain,
            &self.source_asset()?,
            &u64_to_field(self.source_amount),
            &self.order_terms().data_hash()?,
            &self.escrow_owner()?,
            &self.escrow_blinding,
        )
    }

    fn taker_utxo_hash(&self) -> Result<[u8; 32], FillError> {
        let domain = u64_to_field(UTXO_DOMAIN);
        let zero = [0u8; 32];
        plain_utxo_hash(
            &domain,
            &self.destination_asset()?,
            &u64_to_field(self.destination_amount),
            &zero,
            &self.taker_address,
            &self.taker_in_blinding,
        )
    }

    fn destination_output_hash_for(
        &self,
        amount: u64,
        owner: &[u8; 32],
        blinding: &[u8; 32],
    ) -> Result<[u8; 32], FillError> {
        let domain = u64_to_field(UTXO_DOMAIN);
        let zero = [0u8; 32];
        plain_utxo_hash(
            &domain,
            &self.destination_asset()?,
            &u64_to_field(amount),
            &zero,
            owner,
            blinding,
        )
    }

    fn destination_output_hash(&self) -> Result<[u8; 32], FillError> {
        self.destination_output_hash_for(
            self.destination_amount,
            &self.maker_owner_hash,
            &self.destination_output_blinding()?,
        )
    }

    fn source_output_hash(&self) -> Result<[u8; 32], FillError> {
        let domain = u64_to_field(UTXO_DOMAIN);
        let zero = [0u8; 32];
        plain_utxo_hash(
            &domain,
            &self.source_asset()?,
            &u64_to_field(self.source_amount),
            &zero,
            &self.taker_address,
            &self.source_output_blinding,
        )
    }

    fn private_tx_hash_for(
        &self,
        escrow_hash: &[u8; 32],
        taker_utxo_hash: &[u8; 32],
        source_output_hash: &[u8; 32],
        destination_output_hash: &[u8; 32],
    ) -> Result<[u8; 32], FillError> {
        let input_chain = hash_chain(&[*escrow_hash, *taker_utxo_hash])?;
        let output_chain = hash_chain(&[*source_output_hash, *destination_output_hash])?;
        let address_chain = hash_chain(&[[0u8; 32], [0u8; 32]])?;
        poseidon(&[
            &input_chain,
            &output_chain,
            &address_chain,
            &self.external_data_hash,
        ])
    }

    pub fn public_input_hash(&self) -> Result<[u8; 32], FillError> {
        let escrow_hash = self.escrow_hash()?;
        let taker_utxo_hash = self.taker_utxo_hash()?;
        let source_output_hash = self.source_output_hash()?;
        let destination_output_hash = self.destination_output_hash()?;
        let private_tx_hash = self.private_tx_hash_for(
            &escrow_hash,
            &taker_utxo_hash,
            &source_output_hash,
            &destination_output_hash,
        )?;
        let expiry = u64_to_field(self.expiry);
        poseidon(&[&private_tx_hash, &expiry])
    }

    fn witness_map(
        &self,
        public_input_hash: &[u8; 32],
        private_tx_hash: &[u8; 32],
    ) -> Result<HashMap<String, Vec<String>>, FillError> {
        let entries: [(&str, [u8; 32]); 15] = [
            ("PublicInputHash", *public_input_hash),
            ("PrivateTxHash", *private_tx_hash),
            ("Expiry", u64_to_field(self.expiry)),
            ("SourceAsset", self.source_asset()?),
            ("DestinationAsset", self.destination_asset()?),
            ("EscrowOwner", self.escrow_owner()?),
            ("SourceAmount", u64_to_field(self.source_amount)),
            ("EscrowBlinding", self.escrow_blinding),
            ("DestinationAmount", u64_to_field(self.destination_amount)),
            ("MakerOwnerHash", self.maker_owner_hash),
            ("TakerPkFe", self.taker_pk_fe),
            ("TakerAddress", self.taker_address),
            ("TakerInBlinding", self.taker_in_blinding),
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

    fn witness(&self) -> Result<(WitnessBundle, FillHashes), FillError> {
        let hashes = self.hashes()?;
        let private_tx_hash = self.private_tx_hash_for(
            &hashes.escrow_hash,
            &hashes.taker_utxo_hash,
            &hashes.source_output_hash,
            &hashes.destination_output_hash,
        )?;
        let expiry = u64_to_field(self.expiry);
        let public_input_hash = poseidon(&[&private_tx_hash, &expiry])?;
        let witness = self.witness_map(&public_input_hash, &private_tx_hash)?;
        Ok((
            WitnessBundle {
                witness,
                public_input_hash,
                private_tx_hash,
            },
            hashes,
        ))
    }

    fn hashes(&self) -> Result<FillHashes, FillError> {
        Ok(FillHashes {
            escrow_hash: self.escrow_hash()?,
            taker_utxo_hash: self.taker_utxo_hash()?,
            destination_output_hash: self.destination_output_hash()?,
            source_output_hash: self.source_output_hash()?,
        })
    }

    pub fn prove(&self) -> Result<FillProofResult, FillError> {
        let (bundle, hashes) = self.witness()?;
        let WitnessBundle {
            witness,
            public_input_hash,
            private_tx_hash,
        } = bundle;
        let out = ffi::prove(CircuitId::Fill, &witness)?;
        let proof = gnark_proof_to_wire(&out)?;
        Ok(FillProofResult {
            proof,
            public_input_hash,
            private_tx_hash,
            escrow_hash: hashes.escrow_hash,
            taker_utxo_hash: hashes.taker_utxo_hash,
            destination_output_hash: hashes.destination_output_hash,
            source_output_hash: hashes.source_output_hash,
            destination_output_blinding: self.destination_output_blinding()?,
        })
    }

    pub fn prove_with_destination_output_blinding(
        &self,
        blinding: &[u8; 32],
    ) -> Result<FillProofResult, FillError> {
        let escrow_hash = self.escrow_hash()?;
        let taker_utxo_hash = self.taker_utxo_hash()?;
        let source_output_hash = self.source_output_hash()?;
        let destination_output_hash = self.destination_output_hash_for(
            self.destination_amount,
            &self.maker_owner_hash,
            blinding,
        )?;
        let private_tx_hash = self.private_tx_hash_for(
            &escrow_hash,
            &taker_utxo_hash,
            &source_output_hash,
            &destination_output_hash,
        )?;
        let expiry = u64_to_field(self.expiry);
        let public_input_hash = poseidon(&[&private_tx_hash, &expiry])?;
        let witness = self.witness_map(&public_input_hash, &private_tx_hash)?;
        let out = ffi::prove(CircuitId::Fill, &witness)?;
        let proof = gnark_proof_to_wire(&out)?;
        Ok(FillProofResult {
            proof,
            public_input_hash,
            private_tx_hash,
            escrow_hash,
            taker_utxo_hash,
            destination_output_hash,
            source_output_hash,
            destination_output_blinding: *blinding,
        })
    }
}

struct FillHashes {
    escrow_hash: [u8; 32],
    taker_utxo_hash: [u8; 32],
    destination_output_hash: [u8; 32],
    source_output_hash: [u8; 32],
}
