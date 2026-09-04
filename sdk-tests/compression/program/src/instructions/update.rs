use light_program_profiler::profile;
use pinocchio::{AccountView, ProgramResult};
use wincode::{SchemaRead, SchemaWrite};
use zolana_interface::{
    instruction::{
        instruction_data::transact::{
            hash_external_data, CircuitId, InputUtxo, OwnerTag, TransactIxData, TransactIxDataRef,
            TransactOutput, TransactProof,
        },
        tag::TRANSACT,
    },
    N_PUBLIC_SLOTS,
};

use crate::{
    error::CompressionError,
    instructions::shared::{cpi_spp_transact_signed, private_tx_hash, TransitionAccounts},
    state::{nullifier, AccountState, PdaOwner},
};

#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct UpdateIxData {
    pub old_value: u64,
    pub version: u64,
    pub new_value: u64,
    pub nullifier_tree_root_index: u16,
    pub utxo_tree_root_index: u16,
    pub proof: TransactProof,
}

#[inline(never)]
#[profile]
pub fn process_update_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let UpdateIxData {
        old_value,
        version,
        new_value,
        nullifier_tree_root_index,
        utxo_tree_root_index,
        proof,
    } = wincode::deserialize_exact(data).map_err(|_| CompressionError::InvalidInstructionData)?;

    let parsed = TransitionAccounts::validate_and_parse(accounts)?;
    let authority = *parsed.authority.address();
    let (pda, bump) = (parsed.pda, parsed.bump);

    let pda_bytes = pda.to_bytes();
    let owner = PdaOwner::new(&pda_bytes)?;
    let address = owner.address()?;
    let state = AccountState {
        address,
        authority: authority.to_bytes(),
        value: new_value,
        version: version
            .checked_add(1)
            .ok_or(CompressionError::InvalidInstructionData)?,
    };
    let output_hash = state.utxo_hash(&owner.owner_hash)?;
    let payload = state.to_output_data()?;

    let old_state = AccountState {
        address,
        authority: authority.to_bytes(),
        value: old_value,
        version,
    };
    let old_hash = old_state.utxo_hash(&owner.owner_hash)?;
    let nullifier_hash = nullifier(&old_hash, &old_state.blinding())?;

    // Build the transaction with a placeholder private hash, then hash exactly
    // the external-data prefix the shielded pool reads back out of the
    // instruction. Every output here is `Inline`-tagged, so no account
    // addresses are appended.
    let mut transact = TransactIxData {
        expiry_unix_ts: u64::MAX,
        tx_viewing_pk: [0u8; 33],
        salt: [0u8; 16],
        interface_transfers: Vec::new(),
        outputs: vec![TransactOutput {
            utxo_hash: output_hash,
            owner_tag: OwnerTag::Inline(pda_bytes),
            data: Some(payload),
        }],
        messages: Vec::new(),
        data_hash: None,
        ring_data_hash: None,
        circuit: CircuitId::ConfidentialEddsa(1, 1, N_PUBLIC_SLOTS as u8),
        proof,
        private_tx_hash: [0u8; 32],
        inputs: vec![InputUtxo {
            nullifier_hash,
            nullifier_tree_root_index,
            utxo_tree_root_index,
        }],
    };
    let placeholder_bytes = transact
        .serialize()
        .map_err(|_| CompressionError::SerializationFailed)?;
    let (_, external_data) = TransactIxDataRef::parse_with_external_data_prefix(&placeholder_bytes)
        .map_err(|_| CompressionError::SerializationFailed)?;
    let external_data_hash = hash_external_data(TRANSACT, external_data, core::iter::empty())
        .map_err(|_| CompressionError::HashingFailed)?;
    transact.private_tx_hash =
        private_tx_hash(old_hash, output_hash, [0u8; 32], &external_data_hash)?;
    let transact_bytes = transact
        .serialize()
        .map_err(|_| CompressionError::SerializationFailed)?;
    cpi_spp_transact_signed(&authority, &pda, bump, accounts, &transact_bytes)
}
