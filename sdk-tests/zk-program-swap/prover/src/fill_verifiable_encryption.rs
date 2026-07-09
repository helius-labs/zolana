use std::collections::HashMap;

use solana_address::Address;
use swap_program::instructions::{
    fill_verifiable_encryption::FillVerifiableEncryptionProof, shared::u64_to_field,
};
use zolana_hasher::{Hasher, Poseidon};
use zolana_keypair::merge::{merge_ciphertext_hash, symmetric_apply, MERGE_INFO};

use crate::{
    bytes_to_decimal_string,
    create::gnark_proof_to_wire_committed,
    ffi,
    order_terms::{OrderTerms, FILL_ENC_KDF_DOMAIN, FILL_MODE_VERIFIABLE},
    utxo::UtxoFieldElements,
    CircuitId, OrderProof,
};

#[derive(Debug, thiserror::Error)]
pub enum FillVerifiableEncryptionError {
    #[error("ffi error: {0}")]
    Ffi(#[from] ffi::Error),
    #[error("poseidon hashing failed")]
    Poseidon,
    #[error("compress failed: {0}")]
    Compress(String),
    #[error("keypair error: {0}")]
    Keypair(String),
    #[error("invalid taker key")]
    TakerKey,
    #[error("malformed fill plaintext")]
    Plaintext,
}

impl From<crate::create::CreateError> for FillVerifiableEncryptionError {
    fn from(e: crate::create::CreateError) -> Self {
        match e {
            crate::create::CreateError::Ffi(e) => FillVerifiableEncryptionError::Ffi(e),
            crate::create::CreateError::Keypair(e) => FillVerifiableEncryptionError::from(e),
            crate::create::CreateError::Poseidon => FillVerifiableEncryptionError::Poseidon,
            crate::create::CreateError::CompressG1(s) => FillVerifiableEncryptionError::Compress(s),
            crate::create::CreateError::CompressG2(s) => FillVerifiableEncryptionError::Compress(s),
        }
    }
}

impl From<zolana_keypair::KeypairError> for FillVerifiableEncryptionError {
    fn from(e: zolana_keypair::KeypairError) -> Self {
        FillVerifiableEncryptionError::Keypair(format!("{e:?}"))
    }
}

impl From<OrderProof> for FillVerifiableEncryptionProof {
    fn from(proof: OrderProof) -> Self {
        let (commitment, commitment_pok) = proof
            .commitment
            .expect("fill proof carries a BSB22 commitment");
        Self {
            proof_a: proof.proof_a,
            proof_b: proof.proof_b,
            proof_c: proof.proof_c,
            commitment,
            commitment_pok,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FillVerifiableEncryptionProofResult {
    pub proof: OrderProof,
    pub public_input_hash: [u8; 32],
    pub private_tx_hash: [u8; 32],
    pub ciphertext: Vec<u8>,
    pub ct_hash: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct FillVerifiableEncryptionProofInputs {
    pub source_mint: [u8; 32],
    pub destination_mint: [u8; 32],
    pub source_amount: u64,
    pub escrow_authority: [u8; 32],
    pub escrow_blinding: [u8; 32],
    pub destination_amount: u64,
    pub maker_owner_hash: [u8; 32],
    pub maker_viewing_pk: [u8; 33],
    pub expiry: u64,
    pub taker_pk_fe: [u8; 32],
    pub taker_nullifier_pk: [u8; 32],
    pub taker_in_blinding: [u8; 32],
    pub destination_output_blinding: [u8; 32],
    pub source_output_blinding: [u8; 32],
    pub external_data_hash: [u8; 32],
}

fn poseidon(inputs: &[&[u8; 32]]) -> Result<[u8; 32], FillVerifiableEncryptionError> {
    let slices: Vec<&[u8]> = inputs.iter().map(|i| i.as_slice()).collect();
    Poseidon::hashv(&slices).map_err(|_| FillVerifiableEncryptionError::Poseidon)
}

fn hash_chain(inputs: &[[u8; 32]]) -> Result<[u8; 32], FillVerifiableEncryptionError> {
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

#[derive(Default)]
struct FillVerifiableEncryptionOverrides {
    taker_owner: Option<[u8; 32]>,
    destination_owner: Option<[u8; 32]>,
    destination_amount: Option<u64>,
}

struct FillVerifiableEncryptionUtxos {
    escrow: UtxoFieldElements,
    taker_in: UtxoFieldElements,
    source_output: UtxoFieldElements,
    destination_output: UtxoFieldElements,
}

struct FillVerifiableEncryptionDerivation {
    utxos: FillVerifiableEncryptionUtxos,
    private_tx_hash: [u8; 32],
    ciphertext: Vec<u8>,
    ct_hash: [u8; 32],
    public_input_hash: [u8; 32],
}

impl FillVerifiableEncryptionProofInputs {
    fn destination_plaintext(&self) -> Result<Vec<u8>, FillVerifiableEncryptionError> {
        let mut pt = Vec::with_capacity(8 + 32 + 31);
        pt.extend_from_slice(&self.destination_amount.to_be_bytes());
        pt.extend_from_slice(&self.destination_asset()?);
        pt.extend_from_slice(
            self.destination_output_blinding
                .get(1..32)
                .expect("32-byte blinding has a 31-byte tail"),
        );
        Ok(pt)
    }

    fn source_asset(&self) -> Result<[u8; 32], FillVerifiableEncryptionError> {
        Ok(crate::asset_field(&self.source_mint)?)
    }

    fn destination_asset(&self) -> Result<[u8; 32], FillVerifiableEncryptionError> {
        Ok(crate::asset_field(&self.destination_mint)?)
    }

    fn escrow_owner(&self) -> Result<[u8; 32], FillVerifiableEncryptionError> {
        Ok(crate::escrow_owner_hash(&self.escrow_authority)?)
    }

    fn taker_address(&self) -> Result<[u8; 32], FillVerifiableEncryptionError> {
        poseidon(&[&self.taker_pk_fe, &self.taker_nullifier_pk])
    }

    fn ciphertext(&self) -> Result<(Vec<u8>, [u8; 32]), FillVerifiableEncryptionError> {
        let domain = u64_to_field(FILL_ENC_KDF_DOMAIN);
        let shared_secret = poseidon(&[&self.escrow_blinding, &domain])?;
        let mut buf = self.destination_plaintext()?;
        symmetric_apply(&shared_secret, MERGE_INFO, &mut buf)
            .map_err(|e| FillVerifiableEncryptionError::Keypair(format!("{e:?}")))?;
        let ct_hash = merge_ciphertext_hash(&buf)
            .map_err(|e| FillVerifiableEncryptionError::Keypair(format!("{e:?}")))?;
        Ok((buf, ct_hash))
    }

    fn utxos(
        &self,
        overrides: &FillVerifiableEncryptionOverrides,
    ) -> Result<FillVerifiableEncryptionUtxos, FillVerifiableEncryptionError> {
        let source_asset = self.source_asset()?;
        let destination_asset = self.destination_asset()?;
        let zero = [0u8; 32];

        let data_hash = OrderTerms {
            destination_asset: Address::new_from_array(self.destination_mint),
            destination_amount: self.destination_amount,
            destination: crate::order_terms::maker_address_fe(
                &self.maker_owner_hash,
                &self.maker_viewing_pk,
            )?,
            expiry: self.expiry,
            taker: self.taker_pk_fe,
            fill_mode: FILL_MODE_VERIFIABLE,
        }
        .data_hash()?;

        let taker_owner = match overrides.taker_owner {
            Some(owner) => owner,
            None => self.taker_address()?,
        };
        let destination_owner = overrides.destination_owner.unwrap_or(self.maker_owner_hash);
        let destination_amount = overrides
            .destination_amount
            .unwrap_or(self.destination_amount);

        let escrow = UtxoFieldElements::plain(
            self.escrow_owner()?,
            source_asset,
            self.source_amount,
            self.escrow_blinding,
            data_hash,
        );
        let taker_in = UtxoFieldElements::plain(
            taker_owner,
            destination_asset,
            self.destination_amount,
            self.taker_in_blinding,
            zero,
        );
        let source_output = UtxoFieldElements::plain(
            taker_owner,
            source_asset,
            self.source_amount,
            self.source_output_blinding,
            zero,
        );
        let destination_output = UtxoFieldElements::plain(
            destination_owner,
            destination_asset,
            destination_amount,
            self.destination_output_blinding,
            zero,
        );

        Ok(FillVerifiableEncryptionUtxos {
            escrow,
            taker_in,
            source_output,
            destination_output,
        })
    }

    fn derive(
        &self,
        overrides: &FillVerifiableEncryptionOverrides,
    ) -> Result<FillVerifiableEncryptionDerivation, FillVerifiableEncryptionError> {
        let utxos = self.utxos(overrides)?;
        let escrow_utxo_hash = utxos.escrow.hash()?;
        let taker_utxo_hash = utxos.taker_in.hash()?;
        let source_output_hash = utxos.source_output.hash()?;
        let destination_output_hash = utxos.destination_output.hash()?;

        let input_chain = hash_chain(&[escrow_utxo_hash, taker_utxo_hash])?;
        let output_chain = hash_chain(&[source_output_hash, destination_output_hash])?;
        let address_chain = hash_chain(&[[0u8; 32], [0u8; 32]])?;
        let private_tx_hash = poseidon(&[
            &input_chain,
            &output_chain,
            &address_chain,
            &self.external_data_hash,
        ])?;

        let (ciphertext, ct_hash) = self.ciphertext()?;
        let expiry = u64_to_field(self.expiry);
        let public_input_hash = poseidon(&[&private_tx_hash, &expiry, &ct_hash])?;

        Ok(FillVerifiableEncryptionDerivation {
            utxos,
            private_tx_hash,
            ciphertext,
            ct_hash,
            public_input_hash,
        })
    }

    pub fn public_input_hash(&self) -> Result<[u8; 32], FillVerifiableEncryptionError> {
        Ok(self
            .derive(&FillVerifiableEncryptionOverrides::default())?
            .public_input_hash)
    }

    pub fn destination_ciphertext(&self) -> Result<Vec<u8>, FillVerifiableEncryptionError> {
        Ok(self.ciphertext()?.0)
    }

    fn witness_map(
        &self,
        derived: &FillVerifiableEncryptionDerivation,
    ) -> Result<HashMap<String, Vec<String>>, FillVerifiableEncryptionError> {
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

        let scalars: [(&str, [u8; 32]); 10] = [
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
            ("Core_Order_FillMode", u64_to_field(FILL_MODE_VERIFIABLE)),
            ("Core_ExternalDataHash", self.external_data_hash),
            ("TakerNullifierPk", self.taker_nullifier_pk),
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

    pub fn prove(
        &self,
    ) -> Result<FillVerifiableEncryptionProofResult, FillVerifiableEncryptionError> {
        self.prove_with_overrides(FillVerifiableEncryptionOverrides::default())
    }

    pub fn prove_with_destination_output_owner(
        &self,
        destination_output_owner: &[u8; 32],
    ) -> Result<FillVerifiableEncryptionProofResult, FillVerifiableEncryptionError> {
        self.prove_with_overrides(FillVerifiableEncryptionOverrides {
            destination_owner: Some(*destination_output_owner),
            ..Default::default()
        })
    }

    pub fn prove_with_destination_output_amount(
        &self,
        destination_output_amount: u64,
    ) -> Result<FillVerifiableEncryptionProofResult, FillVerifiableEncryptionError> {
        self.prove_with_overrides(FillVerifiableEncryptionOverrides {
            destination_amount: Some(destination_output_amount),
            ..Default::default()
        })
    }

    pub fn prove_with_taker_address(
        &self,
        taker_address: &[u8; 32],
    ) -> Result<FillVerifiableEncryptionProofResult, FillVerifiableEncryptionError> {
        self.prove_with_overrides(FillVerifiableEncryptionOverrides {
            taker_owner: Some(*taker_address),
            ..Default::default()
        })
    }

    fn prove_with_overrides(
        &self,
        overrides: FillVerifiableEncryptionOverrides,
    ) -> Result<FillVerifiableEncryptionProofResult, FillVerifiableEncryptionError> {
        let derived = self.derive(&overrides)?;
        let witness = self.witness_map(&derived)?;
        let out = ffi::prove(CircuitId::FillVerifiableEncryption, &witness)?;
        let proof = gnark_proof_to_wire_committed(&out)?;
        Ok(FillVerifiableEncryptionProofResult {
            proof,
            public_input_hash: derived.public_input_hash,
            private_tx_hash: derived.private_tx_hash,
            ciphertext: derived.ciphertext,
            ct_hash: derived.ct_hash,
        })
    }

    pub fn decrypt_destination(
        &self,
        ciphertext: &[u8],
    ) -> Result<([u8; 32], u64), FillVerifiableEncryptionError> {
        let domain = u64_to_field(FILL_ENC_KDF_DOMAIN);
        let shared_secret = poseidon(&[&self.escrow_blinding, &domain])?;
        let mut plaintext = ciphertext.to_vec();
        symmetric_apply(&shared_secret, MERGE_INFO, &mut plaintext)
            .map_err(|e| FillVerifiableEncryptionError::Keypair(format!("{e:?}")))?;
        let amount_bytes: [u8; 8] = plaintext
            .get(0..8)
            .ok_or(FillVerifiableEncryptionError::Plaintext)?
            .try_into()
            .map_err(|_| FillVerifiableEncryptionError::Plaintext)?;
        let amount = u64::from_be_bytes(amount_bytes);
        let asset: [u8; 32] = plaintext
            .get(8..40)
            .ok_or(FillVerifiableEncryptionError::Plaintext)?
            .try_into()
            .map_err(|_| FillVerifiableEncryptionError::Plaintext)?;
        Ok((asset, amount))
    }
}
