use pinocchio::error::ProgramError;
use zolana_hasher::{
    primitives::{hash_bytes, right_align},
    sha256::Sha256BE,
    Hasher, Poseidon,
};
use zolana_interface::{ADDRESS_DOMAIN, SOL_ASSET_FIELD, UTXO_DOMAIN};

use crate::error::CompressionError;

pub const STATE_DATA_LEN: usize = 72;
const PDA_OWNER_TAG: u8 = 2;
const SOL_ASSET_ID: u64 = 1;
const TRANSFER_PLAINTEXT: u8 = 4;
pub const PLAINTEXT_TRANSFER_SCHEME: u8 = 7;
pub const RECIPIENT_POSITION: u8 = 2;
pub const ACCOUNT_DATA_DOMAIN: &[u8; 42] = b"zolana:compression-example:account-data:v1";
const STATE_DATA_LEN_U16: u16 = STATE_DATA_LEN as u16;
const PLAINTEXT_TRANSFER_LEN: usize = 161;
const PLAINTEXT_BLOB_LEN: usize = 1 + PLAINTEXT_TRANSFER_LEN;
const ENCODED_PAYLOAD_LEN: usize = 1 + 4 + PLAINTEXT_BLOB_LEN;

pub struct DerivedAddress {
    pub owner_hash: [u8; 32],
    pub address_seed: [u8; 32],
    pub address_utxo_hash: [u8; 32],
    pub address: [u8; 32],
}

pub struct DerivedState {
    pub state_data: [u8; STATE_DATA_LEN],
    pub data_hash: [u8; 32],
}

fn hashv(values: &[&[u8]]) -> Result<[u8; 32], ProgramError> {
    Poseidon::hashv(values).map_err(|_| CompressionError::HashingFailed.into())
}

fn hash_bytes_field<const N: usize>(bytes: &[u8; N]) -> Result<[u8; 32], ProgramError> {
    hash_bytes(bytes).map_err(|_| CompressionError::HashingFailed.into())
}

pub fn field_u16(value: u16) -> [u8; 32] {
    right_align(&value.to_be_bytes())
}

pub fn field_u64(value: u64) -> [u8; 32] {
    right_align(&value.to_be_bytes())
}

pub fn derive_blinding(seed: &[u8; 32]) -> Result<[u8; 32], ProgramError> {
    let mut preimage = [0u8; 32];
    preimage[..31].copy_from_slice(&seed[1..]);
    preimage[31] = RECIPIENT_POSITION;
    Sha256BE::hash(&preimage).map_err(|_| CompressionError::HashingFailed.into())
}

pub fn derive_address(pda: &[u8; 32]) -> Result<DerivedAddress, ProgramError> {
    let owner_pk_field = hash_bytes_field(pda)?;
    let zero = [0u8; 32];
    let nullifier_pk = hashv(&[&zero])?;
    let owner_hash = hashv(&[&owner_pk_field, &nullifier_pk])?;
    let address_seed = owner_pk_field;
    let owner_utxo_hash = hashv(&[&owner_hash, &address_seed])?;
    let ring_hash = hashv(&[&zero, &zero])?;
    let address_utxo_hash = hashv(&[
        &field_u16(ADDRESS_DOMAIN),
        &zero,
        &zero,
        &zero,
        &ring_hash,
        &owner_utxo_hash,
    ])?;
    let address = hashv(&[&address_utxo_hash, &address_seed, &zero])?;

    Ok(DerivedAddress {
        owner_hash,
        address_seed,
        address_utxo_hash,
        address,
    })
}

pub fn account_data_hash(
    address: &[u8; 32],
    authority: &[u8; 32],
    value: u64,
) -> Result<[u8; 32], ProgramError> {
    let authority_field = hash_bytes_field(authority)?;
    let data_domain = hash_bytes_field(ACCOUNT_DATA_DOMAIN)?;
    hashv(&[address, &data_domain, &authority_field, &field_u64(value)])
}

pub fn derive_state(
    address: &[u8; 32],
    authority: &[u8; 32],
    value: u64,
) -> Result<DerivedState, ProgramError> {
    let data_hash = account_data_hash(address, authority, value)?;

    let mut state_data = [0u8; STATE_DATA_LEN];
    state_data[..32].copy_from_slice(address);
    state_data[32..64].copy_from_slice(authority);
    state_data[64..].copy_from_slice(&value.to_le_bytes());

    Ok(DerivedState {
        state_data,
        data_hash,
    })
}

pub fn state_utxo_hash(
    owner_hash: &[u8; 32],
    data_hash: &[u8; 32],
    blinding: &[u8; 32],
) -> Result<[u8; 32], ProgramError> {
    let zero = [0u8; 32];
    let ring_hash = hashv(&[&zero, &zero])?;
    let owner_utxo_hash = hashv(&[owner_hash, blinding])?;
    hashv(&[
        &field_u16(UTXO_DOMAIN),
        &SOL_ASSET_FIELD,
        &zero,
        data_hash,
        &ring_hash,
        &owner_utxo_hash,
    ])
}

pub fn nullifier(utxo_hash: &[u8; 32], blinding: &[u8; 32]) -> Result<[u8; 32], ProgramError> {
    hashv(&[utxo_hash, blinding, &[0u8; 32]])
}

pub fn plaintext_payload(
    pda: &[u8; 32],
    state_data: &[u8; STATE_DATA_LEN],
    output_seed: [u8; 32],
) -> Result<Vec<u8>, ProgramError> {
    let mut payload = Vec::with_capacity(ENCODED_PAYLOAD_LEN);

    // OutputDataEncoding::Plaintext(Vec<u8>) in Borsh.
    payload.push(0);
    payload.extend_from_slice(&(PLAINTEXT_BLOB_LEN as u32).to_le_bytes());
    payload.push(PLAINTEXT_TRANSFER_SCHEME);

    // PlaintextTransfer in its existing wincode schema.
    payload.push(TRANSFER_PLAINTEXT);
    payload.extend_from_slice(&output_seed);
    payload.push(0); // sender: None
    payload.push(1); // one recipient
    payload.push(PDA_OWNER_TAG);
    payload.extend_from_slice(pda);
    payload.push(0); // final unused byte of PublicKey's fixed [u8; 34] representation
    payload.extend_from_slice(&SOL_ASSET_ID.to_le_bytes());
    payload.extend_from_slice(&0u64.to_le_bytes());
    payload.push(1); // one data record
    payload.push(2); // DataRecord::UtxoData
    payload.extend_from_slice(&STATE_DATA_LEN_U16.to_le_bytes());
    payload.extend_from_slice(state_data);

    if payload.len() != ENCODED_PAYLOAD_LEN {
        return Err(CompressionError::SerializationFailed.into());
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_address::address;
    use zolana_keypair::{hash::owner_hash, NullifierKey, PublicKey};
    use zolana_transaction::{
        serialization::{
            plaintext::{PlaintextEncode, PlaintextTransfer},
            OwnerCx, UtxoSerialization,
        },
        AssetRegistry, Data as TransactionData, DataRecord as TransactionDataRecord,
        ProofInputUtxo, Utxo, SOL_MINT,
    };

    const TEST_PDA: solana_address::Address =
        address!("6ZKEgsScJbL6JVDpbHLCFCUiPEVgmMSt1j6NudNLqEvh");

    #[test]
    fn commitments_match_existing_utxo_types() {
        let authority = [8u8; 32];
        let output_seed = [9u8; 32];
        let address = derive_address(TEST_PDA.as_array()).unwrap();
        let state = derive_state(&address.address, &authority, 42).unwrap();
        let owner = PublicKey::from_pda(&TEST_PDA);
        let nullifier_key = NullifierKey::from_secret([0u8; 31]);
        let nullifier_pk = nullifier_key.pubkey().unwrap();
        let expected_owner_hash = owner_hash(&owner, &nullifier_pk).unwrap();
        assert_eq!(address.owner_hash, expected_owner_hash);

        let address_seed = hash_bytes(TEST_PDA.as_array()).unwrap();
        let address_input = ProofInputUtxo {
            domain: right_align(&ADDRESS_DOMAIN.to_be_bytes()),
            owner_hash: expected_owner_hash,
            blinding: address_seed,
            ..ProofInputUtxo::default()
        };
        assert_eq!(address.address_utxo_hash, address_input.hash().unwrap());
        assert_eq!(
            address.address,
            nullifier_key
                .nullifier(&address.address_utxo_hash, &address_seed)
                .unwrap()
        );

        let output_blinding = zolana_transaction::derive_blinding(&output_seed, RECIPIENT_POSITION);
        let output = ProofInputUtxo::new(expected_owner_hash, &SOL_MINT, 0, &output_blinding)
            .unwrap()
            .with_data_hash(state.data_hash);
        assert_eq!(
            state_utxo_hash(&address.owner_hash, &state.data_hash, &output_blinding).unwrap(),
            output.hash().unwrap()
        );
    }

    #[test]
    fn payload_matches_existing_plaintext_utxo_encoding() {
        let authority = [8u8; 32];
        let seed = [9u8; 32];
        let address = derive_address(TEST_PDA.as_array()).unwrap();
        let state = derive_state(&address.address, &authority, 42).unwrap();
        let expected = plaintext_payload(TEST_PDA.as_array(), &state.state_data, seed).unwrap();
        let owner = PublicKey::from_pda(&TEST_PDA);
        let utxo = Utxo {
            owner,
            asset: SOL_MINT,
            amount: 0,
            blinding: zolana_transaction::derive_blinding(&seed, RECIPIENT_POSITION),
            ring_program_id: None,
            data: TransactionData::new(vec![TransactionDataRecord::UtxoData(
                state.state_data.to_vec(),
            )]),
        };
        let encoded = PlaintextTransfer::encode(
            &[utxo],
            &OwnerCx {
                owner,
                assets: &AssetRegistry::default(),
                ring_program_id: None,
            },
            TEST_PDA.to_bytes(),
            &PlaintextEncode {
                blinding_seed: seed,
            },
        )
        .unwrap();
        assert_eq!(expected, encoded.data);
    }
}
