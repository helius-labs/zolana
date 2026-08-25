use borsh::{BorshDeserialize, BorshSerialize};
use pinocchio::error::ProgramError;
use zolana_hasher::{
    primitives::{hash_bytes, right_align},
    Hasher, Poseidon,
};
use zolana_interface::{ADDRESS_DOMAIN, SOL_ASSET_FIELD, UTXO_DOMAIN};

use crate::error::CompressionError;

pub const STATE_DATA_LEN: usize = 80;
const OUTPUT_DATA_PLAINTEXT: u8 = 0;
pub const ACCOUNT_DATA_DOMAIN: &[u8; 42] = b"zolana:compression-example:account-data:v1";

pub struct DerivedAddress {
    pub owner_hash: [u8; 32],
    pub address_seed: [u8; 32],
    pub address_utxo_hash: [u8; 32],
    pub address: [u8; 32],
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

// The blinding is the account version: 0 on create, incremented by one on
// every update. A changing blinding keeps every state UTXO commitment unique
// even when the value repeats, so the nullifier never collides.
pub fn version_blinding(version: u64) -> [u8; 32] {
    field_u64(version)
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

#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, PartialEq, Eq)]
pub struct AccountState {
    pub address: [u8; 32],
    pub authority: [u8; 32],
    pub value: u64,
    pub version: u64,
}

impl AccountState {
    pub fn data_hash(&self) -> Result<[u8; 32], ProgramError> {
        let authority_field = hash_bytes_field(&self.authority)?;
        let data_domain = hash_bytes_field(ACCOUNT_DATA_DOMAIN)?;
        hashv(&[
            &self.address,
            &data_domain,
            &authority_field,
            &field_u64(self.value),
            &field_u64(self.version),
        ])
    }

    pub fn blinding(&self) -> [u8; 32] {
        version_blinding(self.version)
    }

    pub fn utxo_hash(&self, owner_hash: &[u8; 32]) -> Result<[u8; 32], ProgramError> {
        state_utxo_hash(owner_hash, &self.data_hash()?, &self.blinding())
    }

    pub fn to_vec(&self) -> Result<Vec<u8>, ProgramError> {
        let mut bytes = Vec::with_capacity(STATE_DATA_LEN);
        self.serialize(&mut bytes)
            .map_err(|_| CompressionError::SerializationFailed)?;
        Ok(bytes)
    }

    // The example's custom output payload is the account state itself, whose
    // version is also the blinding; owner, asset, and amount are fixed by the
    // program and not published. The state is wrapped in the protocol's
    // `OutputDataEncoding::Plaintext(Vec<u8>)` Borsh envelope so wallets can
    // still classify the output.
    pub fn to_output_data(&self) -> Result<Vec<u8>, ProgramError> {
        let mut payload = Vec::with_capacity(1 + 4 + STATE_DATA_LEN);
        payload.push(OUTPUT_DATA_PLAINTEXT);
        payload.extend_from_slice(&(STATE_DATA_LEN as u32).to_le_bytes());
        self.serialize(&mut payload)
            .map_err(|_| CompressionError::SerializationFailed)?;
        Ok(payload)
    }
}

fn state_utxo_hash(
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

#[cfg(test)]
mod tests {
    use super::*;
    use solana_address::address;
    use zolana_interface::event::OutputDataEncoding;
    use zolana_keypair::{hash::owner_hash, NullifierKey, PublicKey};
    use zolana_transaction::{ProofInputUtxo, SOL_MINT};

    const TEST_PDA: solana_address::Address =
        address!("6ZKEgsScJbL6JVDpbHLCFCUiPEVgmMSt1j6NudNLqEvh");

    #[test]
    fn commitments_match_existing_utxo_types() {
        let authority = [8u8; 32];
        let address = derive_address(TEST_PDA.as_array()).unwrap();
        let state = AccountState {
            address: address.address,
            authority,
            value: 42,
            version: 9,
        };
        let data_hash = state.data_hash().unwrap();
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

        let output_blinding = state.blinding();
        let output = ProofInputUtxo::new(expected_owner_hash, &SOL_MINT, 0, &output_blinding)
            .unwrap()
            .with_data_hash(data_hash);
        assert_eq!(
            state.utxo_hash(&address.owner_hash).unwrap(),
            output.hash().unwrap()
        );
    }

    #[test]
    fn payload_envelope_is_a_plaintext_output_data_encoding() {
        let address = derive_address(TEST_PDA.as_array()).unwrap();
        let state = AccountState {
            address: address.address,
            authority: [8u8; 32],
            value: 42,
            version: 9,
        };
        let encoded = state.to_output_data().unwrap();
        let envelope: OutputDataEncoding = borsh::from_slice(&encoded).unwrap();
        let OutputDataEncoding::Plaintext(blob) = envelope else {
            panic!("payload envelope is not plaintext");
        };
        assert_eq!(blob.len(), STATE_DATA_LEN);
        assert_eq!(state.to_vec().unwrap(), blob);
        let decoded: AccountState = borsh::from_slice(&blob).unwrap();
        assert_eq!(decoded, state);
    }
}
