use std::collections::HashMap;

use solana_address::Address;
use swap_program::instructions::shared::u64_to_field;
use zolana_hasher::{Hasher, Poseidon};
use zolana_keypair::merge::{merge_ciphertext_hash, symmetric_apply, MERGE_INFO};

use crate::{
    bytes_to_decimal_string,
    create::gnark_proof_to_wire_committed,
    ffi,
    order_terms::{OrderTerms, FILL_ENC_KDF_DOMAIN, FILL_MODE_VERIFIABLE},
    CircuitId, OrderProof,
};

pub const UTXO_DOMAIN: u64 = 1;

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

#[derive(Debug, Clone)]
pub struct FillVerifiableEncryptionProofResult {
    pub proof: OrderProof,
    pub public_input_hash: [u8; 32],
    pub private_tx_hash: [u8; 32],
    pub escrow_hash: [u8; 32],
    pub taker_utxo_hash: [u8; 32],
    pub destination_output_hash: [u8; 32],
    pub source_output_hash: [u8; 32],
    pub ciphertext: Vec<u8>,
    pub ct_hash: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct FillVerifiableEncryptionProofInputs {
    pub source_asset_id: u64,
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

fn plain_utxo_hash(
    domain: &[u8; 32],
    asset: &[u8; 32],
    amount: &[u8; 32],
    data_hash: &[u8; 32],
    owner: &[u8; 32],
    blinding: &[u8; 32],
) -> Result<[u8; 32], FillVerifiableEncryptionError> {
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

struct FillVerifiableEncryptionDerivation {
    taker_address: [u8; 32],
    escrow_hash: [u8; 32],
    taker_utxo_hash: [u8; 32],
    destination_output_hash: [u8; 32],
    source_output_hash: [u8; 32],
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

    fn derive(&self) -> Result<FillVerifiableEncryptionDerivation, FillVerifiableEncryptionError> {
        let domain = u64_to_field(UTXO_DOMAIN);
        let source_asset = self.source_asset()?;
        let destination_asset = self.destination_asset()?;
        let source_amount = u64_to_field(self.source_amount);
        let destination_amount = u64_to_field(self.destination_amount);
        let expiry = u64_to_field(self.expiry);
        let zero = [0u8; 32];

        let taker_address = self.taker_address()?;

        let data_hash = OrderTerms {
            destination_asset: Address::new_from_array(self.destination_mint),
            destination_amount: self.destination_amount,
            maker_owner_hash: self.maker_owner_hash,
            maker_viewing_pk: self.maker_viewing_pk,
            expiry: self.expiry,
            taker_pk_fe: self.taker_pk_fe,
            fill_mode: FILL_MODE_VERIFIABLE,
        }
        .data_hash()?;
        let escrow_owner = self.escrow_owner()?;

        let escrow_hash = plain_utxo_hash(
            &domain,
            &source_asset,
            &source_amount,
            &data_hash,
            &escrow_owner,
            &self.escrow_blinding,
        )?;
        let taker_utxo_hash = plain_utxo_hash(
            &domain,
            &destination_asset,
            &destination_amount,
            &zero,
            &taker_address,
            &self.taker_in_blinding,
        )?;
        let destination_output_hash = plain_utxo_hash(
            &domain,
            &destination_asset,
            &destination_amount,
            &zero,
            &self.maker_owner_hash,
            &self.destination_output_blinding,
        )?;
        let source_output_hash = plain_utxo_hash(
            &domain,
            &source_asset,
            &source_amount,
            &zero,
            &taker_address,
            &self.source_output_blinding,
        )?;

        let input_chain = hash_chain(&[escrow_hash, taker_utxo_hash])?;
        let output_chain = hash_chain(&[source_output_hash, destination_output_hash])?;
        let address_chain = hash_chain(&[[0u8; 32], [0u8; 32]])?;
        let private_tx_hash = poseidon(&[
            &input_chain,
            &output_chain,
            &address_chain,
            &self.external_data_hash,
        ])?;

        let (ciphertext, ct_hash) = self.ciphertext()?;
        let public_input_hash = poseidon(&[&private_tx_hash, &expiry, &ct_hash])?;

        Ok(FillVerifiableEncryptionDerivation {
            taker_address,
            escrow_hash,
            taker_utxo_hash,
            destination_output_hash,
            source_output_hash,
            private_tx_hash,
            ciphertext,
            ct_hash,
            public_input_hash,
        })
    }

    pub fn public_input_hash(&self) -> Result<[u8; 32], FillVerifiableEncryptionError> {
        Ok(self.derive()?.public_input_hash)
    }

    /// The destination-output ciphertext the fill proof commits via `ctHash`.
    /// Depends only on the escrow blinding and the destination plaintext, not on
    /// `external_data_hash`, so a caller can place it in the SPP transact's tail
    /// ciphertext slot before computing `external_data_hash` and proving.
    pub fn destination_ciphertext(&self) -> Result<Vec<u8>, FillVerifiableEncryptionError> {
        Ok(self.ciphertext()?.0)
    }

    fn private_tx_hash_with_destination_output(
        &self,
        derived: &FillVerifiableEncryptionDerivation,
        destination_owner: Option<[u8; 32]>,
        destination_amount: Option<u64>,
    ) -> Result<[u8; 32], FillVerifiableEncryptionError> {
        let domain = u64_to_field(UTXO_DOMAIN);
        let destination_asset = self.destination_asset()?;
        let destination_amount_fe =
            u64_to_field(destination_amount.unwrap_or(self.destination_amount));
        let zero = [0u8; 32];
        let owner = destination_owner.unwrap_or(self.maker_owner_hash);
        let destination_output_hash = plain_utxo_hash(
            &domain,
            &destination_asset,
            &destination_amount_fe,
            &zero,
            &owner,
            &self.destination_output_blinding,
        )?;
        let input_chain = hash_chain(&[derived.escrow_hash, derived.taker_utxo_hash])?;
        let output_chain = hash_chain(&[derived.source_output_hash, destination_output_hash])?;
        let address_chain = hash_chain(&[[0u8; 32], [0u8; 32]])?;
        poseidon(&[
            &input_chain,
            &output_chain,
            &address_chain,
            &self.external_data_hash,
        ])
    }

    fn witness(
        &self,
        derived: &FillVerifiableEncryptionDerivation,
    ) -> Result<HashMap<String, Vec<String>>, FillVerifiableEncryptionError> {
        let mut map = HashMap::new();

        let scalars: [(&str, [u8; 32]); 17] = [
            ("PublicInputHash", derived.public_input_hash),
            ("PrivateTxHash", derived.private_tx_hash),
            ("Expiry", u64_to_field(self.expiry)),
            ("SourceAsset", self.source_asset()?),
            ("DestinationAsset", self.destination_asset()?),
            ("EscrowOwner", self.escrow_owner()?),
            ("SourceAmount", u64_to_field(self.source_amount)),
            ("EscrowBlinding", self.escrow_blinding),
            ("DestinationAmount", u64_to_field(self.destination_amount)),
            ("MakerOwnerHash", self.maker_owner_hash),
            ("TakerPkFe", self.taker_pk_fe),
            ("TakerNullifierPk", self.taker_nullifier_pk),
            ("TakerAddress", derived.taker_address),
            ("TakerInBlinding", self.taker_in_blinding),
            (
                "DestinationOutputBlinding",
                self.destination_output_blinding,
            ),
            ("SourceOutputBlinding", self.source_output_blinding),
            ("ExternalDataHash", self.external_data_hash),
        ];
        for (key, value) in scalars.iter() {
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

    pub fn prove(
        &self,
    ) -> Result<FillVerifiableEncryptionProofResult, FillVerifiableEncryptionError> {
        self.prove_inner(None, None, None)
    }

    pub fn prove_with_destination_output_owner(
        &self,
        destination_output_owner: &[u8; 32],
    ) -> Result<FillVerifiableEncryptionProofResult, FillVerifiableEncryptionError> {
        self.prove_inner(Some(*destination_output_owner), None, None)
    }

    pub fn prove_with_destination_output_amount(
        &self,
        destination_output_amount: u64,
    ) -> Result<FillVerifiableEncryptionProofResult, FillVerifiableEncryptionError> {
        self.prove_inner(None, Some(destination_output_amount), None)
    }

    pub fn prove_with_taker_address(
        &self,
        taker_address: &[u8; 32],
    ) -> Result<FillVerifiableEncryptionProofResult, FillVerifiableEncryptionError> {
        self.prove_inner(None, None, Some(*taker_address))
    }

    fn prove_inner(
        &self,
        destination_owner_override: Option<[u8; 32]>,
        destination_amount_override: Option<u64>,
        taker_address_override: Option<[u8; 32]>,
    ) -> Result<FillVerifiableEncryptionProofResult, FillVerifiableEncryptionError> {
        let derived = self.derive()?;
        let mut witness = self.witness(&derived)?;

        if let Some(taker_address) = taker_address_override {
            witness.insert(
                "TakerAddress".to_string(),
                vec![bytes_to_decimal_string(&taker_address)],
            );
        }
        if let Some(owner) = destination_owner_override {
            let tampered_private_tx_hash =
                self.private_tx_hash_with_destination_output(&derived, Some(owner), None)?;
            witness.insert(
                "PrivateTxHash".to_string(),
                vec![bytes_to_decimal_string(&tampered_private_tx_hash)],
            );
        }
        if let Some(amount) = destination_amount_override {
            let tampered_private_tx_hash =
                self.private_tx_hash_with_destination_output(&derived, None, Some(amount))?;
            witness.insert(
                "PrivateTxHash".to_string(),
                vec![bytes_to_decimal_string(&tampered_private_tx_hash)],
            );
        }

        let out = ffi::prove(CircuitId::FillVerifiableEncryption, &witness)?;
        let proof = gnark_proof_to_wire_committed(&out)?;
        Ok(FillVerifiableEncryptionProofResult {
            proof,
            public_input_hash: derived.public_input_hash,
            private_tx_hash: derived.private_tx_hash,
            escrow_hash: derived.escrow_hash,
            taker_utxo_hash: derived.taker_utxo_hash,
            destination_output_hash: derived.destination_output_hash,
            source_output_hash: derived.source_output_hash,
            ciphertext: derived.ciphertext,
            ct_hash: derived.ct_hash,
        })
    }

    /// The maker recovers the destination output's `(asset, amount)` by
    /// decrypting the ciphertext with the key derived from the escrow blinding it
    /// holds. `asset` is the `asset_field(mint)` field element committed in the
    /// destination UTXO, so the maker can reconstruct the output hash from the
    /// ciphertext alone. The destination blinding is the remaining plaintext field.
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
