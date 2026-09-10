use borsh::{BorshDeserialize, BorshSerialize};
use pinocchio::error::ProgramError;
use zolana_hasher::{
    primitives::{hash_bytes, right_align, solana_owner_identity},
    Hasher, Poseidon,
};
use zolana_interface::{ADDRESS_DOMAIN, SOL_ASSET_FIELD, UTXO_DOMAIN};
use zolana_program::derivation::{
    derive_output_blinding_seed, derive_private_tx_blinding, derive_transact_output_blinding,
};

use crate::error::CompressionError;

pub const STATE_DATA_LEN: usize = 112;
const OUTPUT_DATA_PLAINTEXT: u8 = 0;
pub const ACCOUNT_DATA_DOMAIN: &[u8; 42] = b"zolana:compression-example:account-data:v1";

/// Output slot the compressed account's UTXO occupies in every SPP transaction
/// this program builds. Each transition has exactly one real output, so the
/// program and the SDK both build a single-output transaction and derive the
/// blinding for slot 0. Changing either side's output layout breaks this
/// invariant and the pool rejects the CPI.
pub const ACCOUNT_OUTPUT_SLOT: u32 = 0;

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

/// Tag byte above the version in [`blinding_seed`]. It keeps the seed non-zero
/// for version 0, which the prover rejects, and separates it from a bare
/// version number.
const BLINDING_SEED_TAG: u8 = b'C';

/// The SPP blinding seed of the transition that produces state `version`:
/// `BLINDING_SEED_TAG * 2^64 + version` as a field element. Compressed state is
/// public, so the seed hides nothing here; being deterministic, it lets the
/// program recompute every value the circuit derives from it (output blinding
/// and private transaction blinding) instead of trusting instruction data. The
/// first nullifier is folded into each derivation and enters the nullifier
/// tree once, so the values stay unique across transactions.
pub fn blinding_seed(version: u64) -> [u8; 32] {
    let mut seed = field_u64(version);
    seed[23] = BLINDING_SEED_TAG;
    seed
}

/// Blinding of the account UTXO created at `version`, as the circuit derives it
/// from [`blinding_seed`] and the transaction's first nullifier for
/// [`ACCOUNT_OUTPUT_SLOT`]: `Poseidon(TXOB, first_nullifier,
/// Poseidon(TXOS, first_nullifier, blinding_seed), ACCOUNT_OUTPUT_SLOT)`.
pub fn output_blinding(first_nullifier: &[u8; 32], version: u64) -> Result<[u8; 32], ProgramError> {
    let seed = derive_output_blinding_seed(first_nullifier, &blinding_seed(version))
        .map_err(|_| CompressionError::HashingFailed)?;
    derive_transact_output_blinding(first_nullifier, &seed, ACCOUNT_OUTPUT_SLOT)
        .map_err(|_| CompressionError::HashingFailed.into())
}

/// Fifth `private_tx_hash` preimage element of the transition that produces
/// state `version`: `Poseidon(TXPB, first_nullifier, blinding_seed)`.
pub fn private_tx_blinding(
    first_nullifier: &[u8; 32],
    version: u64,
) -> Result<[u8; 32], ProgramError> {
    derive_private_tx_blinding(first_nullifier, &blinding_seed(version))
        .map_err(|_| CompressionError::HashingFailed.into())
}

pub struct PdaOwner {
    pub owner_hash: [u8; 32],
    pub address_seed: [u8; 32],
}

impl PdaOwner {
    pub fn new(pda: &[u8; 32]) -> Result<Self, ProgramError> {
        // The owner identity is algorithm tagged: a PDA owner is a Solana key,
        // so it hashes under SOLANA_OWNER_TAG like every ed25519 owner.
        let owner_pk_field =
            solana_owner_identity(pda).map_err(|_| CompressionError::HashingFailed)?;
        let nullifier_pk = hashv(&[&[0u8; 32]])?;
        let owner_hash = hashv(&[&owner_pk_field, &nullifier_pk])?;
        Ok(Self {
            owner_hash,
            address_seed: owner_pk_field,
        })
    }

    /// The address UTXO's commitment in the tree with the raw id `tree_id`. The
    /// tree id is the second Poseidon element of every UTXO hash, so an address
    /// proven against one tree does not carry over to another.
    pub fn address_utxo_hash(&self, tree_id: u16) -> Result<[u8; 32], ProgramError> {
        let zero = [0u8; 32];
        let owner_utxo_hash = hashv(&[&self.owner_hash, &self.address_seed])?;
        let ring_hash = hashv(&[&zero, &zero])?;
        hashv(&[
            &field_u16(ADDRESS_DOMAIN),
            &field_u16(tree_id),
            &zero,
            &zero,
            &zero,
            &ring_hash,
            &owner_utxo_hash,
        ])
    }

    pub fn address(&self, tree_id: u16) -> Result<[u8; 32], ProgramError> {
        nullifier(&self.address_utxo_hash(tree_id)?, &self.address_seed)
    }
}

#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, PartialEq, Eq)]
pub struct AccountState {
    pub address: [u8; 32],
    pub authority: [u8; 32],
    pub value: u64,
    pub version: u64,
    /// The UTXO blinding ([`output_blinding`] of `version` and the creating
    /// transaction's first nullifier). Published with the plaintext state so a
    /// reader can spend the UTXO without replaying the transition chain that
    /// produced that first nullifier.
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

    pub fn utxo_hash(&self, owner_hash: &[u8; 32], tree_id: u16) -> Result<[u8; 32], ProgramError> {
        state_utxo_hash(owner_hash, &self.data_hash()?, &self.blinding, tree_id)
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
    tree_id: u16,
) -> Result<[u8; 32], ProgramError> {
    let zero = [0u8; 32];
    let ring_hash = hashv(&[&zero, &zero])?;
    let owner_utxo_hash = hashv(&[owner_hash, blinding])?;
    hashv(&[
        &field_u16(UTXO_DOMAIN),
        &field_u16(tree_id),
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
    use zolana_interface::{output_data::OutputDataEncoding, tree_slot::tree_id_field};
    use zolana_keypair::hash::poseidon;
    use zolana_keypair::{hash::owner_hash, NullifierKey, PublicKey};
    use zolana_transaction::{utxo, ProofInputUtxo, SOL_MINT};

    const TEST_PDA: solana_address::Address =
        address!("6ZKEgsScJbL6JVDpbHLCFCUiPEVgmMSt1j6NudNLqEvh");

    /// Non-zero so a dropped tree id would change every commitment below.
    const TEST_TREE_ID: u16 = 3;

    /// The program's version seed derivations must equal what an SDK client
    /// gets when it feeds the same `blinding_seed` into `zolana_transaction::utxo`
    /// for output slot 0, and both must be the circuit's Poseidon preimages
    /// under the ASCII domain tags, recomputed here without either crate.
    #[test]
    fn version_blinding_seed_derivations_match_sdk_transaction_math() {
        let first_nullifier = [3u8; 32];
        let version = 9;
        let root_seed = blinding_seed(version);
        let mut expected_blinding_seed = field_u64(version);
        expected_blinding_seed[23] = BLINDING_SEED_TAG;
        assert_eq!(root_seed, expected_blinding_seed);
        assert_ne!(blinding_seed(0), [0u8; 32]);

        let seed = utxo::derive_output_blinding_seed(&first_nullifier, &root_seed).unwrap();
        let expected_seed =
            poseidon(&[&right_align(b"TXOS"), &first_nullifier, &root_seed]).unwrap();
        assert_eq!(seed, expected_seed);

        let blinding = output_blinding(&first_nullifier, version).unwrap();
        assert_eq!(
            blinding,
            utxo::derive_transact_output_blinding(&first_nullifier, &seed, ACCOUNT_OUTPUT_SLOT)
                .unwrap()
        );
        assert_eq!(
            blinding,
            poseidon(&[
                &right_align(b"TXOB"),
                &first_nullifier,
                &seed,
                &right_align(&ACCOUNT_OUTPUT_SLOT.to_be_bytes()),
            ])
            .unwrap()
        );

        let tx_blinding = private_tx_blinding(&first_nullifier, version).unwrap();
        assert_eq!(
            tx_blinding,
            utxo::derive_private_tx_blinding(&first_nullifier, &root_seed).unwrap()
        );
        assert_eq!(
            tx_blinding,
            poseidon(&[&right_align(b"TXPB"), &first_nullifier, &root_seed]).unwrap()
        );
        assert_ne!(tx_blinding, seed);
        assert_ne!(
            output_blinding(&first_nullifier, version).unwrap(),
            output_blinding(&first_nullifier, version + 1).unwrap()
        );
        assert_ne!(
            output_blinding(&first_nullifier, version).unwrap(),
            output_blinding(&[4u8; 32], version).unwrap()
        );
    }

    #[test]
    fn commitments_match_existing_utxo_types() {
        let authority = [8u8; 32];
        let pda_owner = PdaOwner::new(TEST_PDA.as_array()).unwrap();
        let first_nullifier = [3u8; 32];
        let state = AccountState {
            address: pda_owner.address(TEST_TREE_ID).unwrap(),
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

        let address_seed = solana_owner_identity(TEST_PDA.as_array()).unwrap();
        let address_input = ProofInputUtxo {
            domain: right_align(&ADDRESS_DOMAIN.to_be_bytes()),
            tree_id: tree_id_field(TEST_TREE_ID),
            owner_hash: expected_owner_hash,
            blinding: address_seed,
            ..ProofInputUtxo::default()
        };
        let address_utxo_hash = pda_owner.address_utxo_hash(TEST_TREE_ID).unwrap();
        assert_eq!(address_utxo_hash, address_input.hash().unwrap());
        assert_eq!(
            state.address,
            nullifier_key
                .nullifier(&address_utxo_hash, &address_seed)
                .unwrap()
        );

        let output = ProofInputUtxo::new(
            expected_owner_hash,
            &SOL_MINT,
            0,
            &state.blinding,
            TEST_TREE_ID,
        )
        .unwrap()
        .with_data_hash(data_hash);
        assert_eq!(
            state
                .utxo_hash(&pda_owner.owner_hash, TEST_TREE_ID)
                .unwrap(),
            output.hash().unwrap()
        );
    }

    #[test]
    fn payload_envelope_is_a_plaintext_output_data_encoding() {
        let pda_owner = PdaOwner::new(TEST_PDA.as_array()).unwrap();
        let state = AccountState {
            address: pda_owner.address(TEST_TREE_ID).unwrap(),
            authority: [8u8; 32],
            value: 42,
            version: 9,
            blinding: [7u8; 32],
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
