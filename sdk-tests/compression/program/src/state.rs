use borsh::{BorshDeserialize, BorshSerialize};
use pinocchio::error::ProgramError;
use zolana_hasher::{
    primitives::{hash_bytes, right_align},
    Hasher, Poseidon,
};
use zolana_interface::{ADDRESS_DOMAIN, SOL_ASSET_FIELD, UTXO_DOMAIN};

use crate::error::CompressionError;

pub const STATE_DATA_LEN: usize = 112;
const OUTPUT_DATA_PLAINTEXT: u8 = 0;
pub const ACCOUNT_DATA_DOMAIN: &[u8; 42] = b"zolana:compression-example:account-data:v1";

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

/// Private seed for the output blinding. A plaintext example has nothing to
/// hide, so the version keeps every blinding re-derivable from state the client
/// already holds.
pub fn version_blinding(version: u64) -> [u8; 32] {
    field_u64(version)
}

/// Domain separator for SPP transaction output blindings: ASCII `"TXOB"`. Must
/// match `DOMAIN_TRANSACT_OUTPUT_BLINDING_V1` in
/// `sdk-libs/transaction/src/utxo.rs` and `OutputBlindingDomainV1` in the Go
/// circuit.
const OUTPUT_BLINDING_DOMAIN_V1: u32 = 0x5458_4f42;

/// Create and update each publish exactly one output, in slot 0.
const OUTPUT_SLOT: u32 = 0;

/// The blinding the transfer circuit recomputes for this example's single output
/// slot. The first nullifier makes the value unique across accepted
/// transactions, which also means a version alone does not determine it: the
/// current blinding lives in the account state, and the spent one arrives in the
/// update instruction data.
pub fn output_blinding(first_nullifier: &[u8; 32], version: u64) -> Result<[u8; 32], ProgramError> {
    hashv(&[
        &right_align(&OUTPUT_BLINDING_DOMAIN_V1.to_be_bytes()),
        first_nullifier,
        &version_blinding(version),
        &right_align(&OUTPUT_SLOT.to_be_bytes()),
    ])
}

pub struct PdaOwner {
    pub owner_hash: [u8; 32],
    pub address_seed: [u8; 32],
}

impl PdaOwner {
    pub fn new(pda: &[u8; 32]) -> Result<Self, ProgramError> {
        let owner_pk_field = hash_bytes_field(pda)?;
        let nullifier_pk = hashv(&[&[0u8; 32]])?;
        let owner_hash = hashv(&[&owner_pk_field, &nullifier_pk])?;
        Ok(Self {
            owner_hash,
            address_seed: owner_pk_field,
        })
    }

    pub fn address_utxo_hash(&self) -> Result<[u8; 32], ProgramError> {
        let zero = [0u8; 32];
        let owner_utxo_hash = hashv(&[&self.owner_hash, &self.address_seed])?;
        let ring_hash = hashv(&[&zero, &zero])?;
        hashv(&[
            &field_u16(ADDRESS_DOMAIN),
            &zero,
            &zero,
            &zero,
            &ring_hash,
            &owner_utxo_hash,
        ])
    }

    pub fn address(&self) -> Result<[u8; 32], ProgramError> {
        nullifier(&self.address_utxo_hash()?, &self.address_seed)
    }
}

#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, PartialEq, Eq)]
pub struct AccountState {
    pub address: [u8; 32],
    pub authority: [u8; 32],
    pub value: u64,
    pub version: u64,
    /// The UTXO blinding, published with the plaintext state because it is
    /// derived from the creating transaction's first nullifier and so cannot be
    /// recovered from the other fields.
    pub blinding: [u8; 32],
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
            &self.blinding,
        ])
    }

    pub fn utxo_hash(&self, owner_hash: &[u8; 32]) -> Result<[u8; 32], ProgramError> {
        state_utxo_hash(owner_hash, &self.data_hash()?, &self.blinding)
    }

    pub fn to_vec(&self) -> Result<Vec<u8>, ProgramError> {
        let mut bytes = Vec::with_capacity(STATE_DATA_LEN);
        self.serialize(&mut bytes)
            .map_err(|_| CompressionError::SerializationFailed)?;
        Ok(bytes)
    }

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
    use zolana_transaction::{utxo::derive_transact_output_blinding, ProofInputUtxo, SOL_MINT};

    const TEST_PDA: solana_address::Address =
        address!("6ZKEgsScJbL6JVDpbHLCFCUiPEVgmMSt1j6NudNLqEvh");

    #[test]
    fn commitments_match_existing_utxo_types() {
        let authority = [8u8; 32];
        let pda_owner = PdaOwner::new(TEST_PDA.as_array()).unwrap();
        let first_nullifier = [3u8; 32];
        let state = AccountState {
            address: pda_owner.address().unwrap(),
            authority,
            value: 42,
            version: 9,
            blinding: output_blinding(&first_nullifier, 9).unwrap(),
        };
        let data_hash = state.data_hash().unwrap();
        let owner = PublicKey::from_pda(&TEST_PDA);
        let nullifier_key = NullifierKey::from_secret([0u8; 31]);
        let nullifier_pk = nullifier_key.pubkey().unwrap();
        let expected_owner_hash = owner_hash(&owner, &nullifier_pk).unwrap();
        assert_eq!(pda_owner.owner_hash, expected_owner_hash);

        let address_seed = hash_bytes(TEST_PDA.as_array()).unwrap();
        let address_input = ProofInputUtxo {
            domain: right_align(&ADDRESS_DOMAIN.to_be_bytes()),
            owner_hash: expected_owner_hash,
            blinding: address_seed,
            ..ProofInputUtxo::default()
        };
        let address_utxo_hash = pda_owner.address_utxo_hash().unwrap();
        assert_eq!(address_utxo_hash, address_input.hash().unwrap());
        assert_eq!(
            state.address,
            nullifier_key
                .nullifier(&address_utxo_hash, &address_seed)
                .unwrap()
        );

        assert_eq!(
            state.blinding,
            derive_transact_output_blinding(&first_nullifier, &version_blinding(9), 0).unwrap(),
            "output blinding must match the canonical SDK derivation"
        );
        let output = ProofInputUtxo::new(expected_owner_hash, &SOL_MINT, 0, &state.blinding)
            .unwrap()
            .with_data_hash(data_hash);
        assert_eq!(
            state.utxo_hash(&pda_owner.owner_hash).unwrap(),
            output.hash().unwrap()
        );
    }

    #[test]
    fn payload_envelope_is_a_plaintext_output_data_encoding() {
        let pda_owner = PdaOwner::new(TEST_PDA.as_array()).unwrap();
        let state = AccountState {
            address: pda_owner.address().unwrap(),
            authority: [8u8; 32],
            value: 42,
            version: 9,
            blinding: output_blinding(&[3u8; 32], 9).unwrap(),
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
