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
    instructions::shared::{cpi_spp_transact_signed, private_tx_hash, tree_id, TransitionAccounts},
    state::{nullifier, output_blinding, private_tx_blinding, AccountState, PdaOwner},
};

#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct UpdateIxData {
    pub old_value: u64,
    pub version: u64,
    /// Blinding of the UTXO being spent. It derives from the first nullifier of
    /// the transition that created it, which this transaction does not see, so
    /// the client supplies it. A wrong value yields a UTXO hash and nullifier
    /// the pool cannot find in its trees, so it needs no check here.
    pub old_blinding: [u8; 32],
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
        old_blinding,
        new_value,
        nullifier_tree_root_index,
        utxo_tree_root_index,
        proof,
    } = wincode::deserialize_exact(data).map_err(|_| CompressionError::InvalidInstructionData)?;

    let parsed = TransitionAccounts::validate_and_parse(accounts)?;
    let input_tree_id = tree_id(parsed.input_tree)?;
    let output_tree_id = tree_id(parsed.output_tree)?;
    let authority = *parsed.authority.address();
    let (pda, bump) = (parsed.pda, parsed.bump);

    let pda_bytes = pda.to_bytes();
    let owner = PdaOwner::new(&pda_bytes)?;
    let address = owner.address(input_tree_id)?;
    let new_version = version
        .checked_add(1)
        .ok_or(CompressionError::InvalidInstructionData)?;
    let old_state = AccountState {
        address,
        authority: authority.to_bytes(),
        value: old_value,
        version,
        blinding: old_blinding,
    };
    let old_hash = old_state.utxo_hash(&owner.owner_hash, input_tree_id)?;
    let nullifier_hash = nullifier(&old_hash, &old_blinding)?;
    // The spent UTXO's nullifier is this transaction's first nullifier, and the
    // new version is its blinding seed; both derivations are recomputed
    // here rather than read from instruction data.
    let state = AccountState {
        address,
        authority: authority.to_bytes(),
        value: new_value,
        version: new_version,
        blinding: output_blinding(&nullifier_hash, new_version)?,
    };
    let output_hash = state.utxo_hash(&owner.owner_hash, output_tree_id)?;
    let payload = state.to_output_data()?;

    let transact = TransactIxData {
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
    let mut bytes = transact
        .serialize()
        .map_err(|_| CompressionError::SerializationFailed)?;
    let (_, external_data_prefix) = TransactIxDataRef::parse_with_external_data_prefix(&bytes)
        .map_err(|_| CompressionError::SerializationFailed)?;
    let external_data_len = external_data_prefix.len();
    let external_data_hash =
        hash_external_data(TRANSACT, external_data_prefix, core::iter::empty())
            .map_err(|_| CompressionError::HashingFailed)?;
    let private_tx_hash = private_tx_hash(
        old_hash,
        output_hash,
        [0u8; 32],
        &external_data_hash,
        &private_tx_blinding(&nullifier_hash, new_version)?,
    )?;
    // `private_tx_hash` is the first field after the external-data prefix; patch
    // it in place instead of serializing the instruction a second time.
    bytes
        .get_mut(external_data_len..)
        .and_then(|rest| rest.get_mut(..32))
        .ok_or(CompressionError::SerializationFailed)?
        .copy_from_slice(&private_tx_hash);
    cpi_spp_transact_signed(&authority, &pda, bump, accounts, &bytes)
}
