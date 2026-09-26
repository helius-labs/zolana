use light_program_profiler::profile;
use pinocchio::{address::address_eq, AccountView, ProgramResult};
use wincode::{SchemaRead, SchemaWrite};
use zolana_interface::{
    instruction::{
        instruction_data::transact::{
            CircuitId, InputUtxo, OwnerTag, TransactOutput, TransactProof, TreeContext,
        },
        tag::TRANSACT,
    },
    N_PUBLIC_SLOTS,
};
use zolana_program::{TransactExternalData, TransactInputs};

use crate::{
    error::CompressionError,
    instructions::shared::{
        cpi_spp_transact_signed, private_tx_hash, tree_id, TransitionAccounts, DEFAULT_TREE,
    },
    state::{nullifier, output_blinding, private_tx_blinding, AccountState, PdaOwner},
};

#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct CreateIxData {
    pub new_value: u64,
    pub nullifier_tree_root_index: u16,
    pub utxo_tree_root_index: u16,
    pub proof: TransactProof,
}

#[inline(never)]
#[profile]
pub fn process_create_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let CreateIxData {
        new_value,
        nullifier_tree_root_index,
        utxo_tree_root_index,
        proof,
    } = wincode::deserialize_exact(data).map_err(|_| CompressionError::InvalidInstructionData)?;

    let parsed = TransitionAccounts::validate_and_parse(accounts)?;
    if !address_eq(parsed.input_tree.address(), &DEFAULT_TREE)
        || !address_eq(parsed.output_tree.address(), &DEFAULT_TREE)
    {
        return Err(CompressionError::InvalidTree.into());
    }
    let input_tree_id = tree_id(parsed.input_tree)?;
    let output_tree_id = tree_id(parsed.output_tree)?;
    let authority = *parsed.authority.address();
    let (pda, bump) = (parsed.pda, parsed.bump);

    let pda_bytes = pda.to_bytes();
    let owner = PdaOwner::new(&pda_bytes)?;
    let address_utxo_hash = owner.address_utxo_hash(input_tree_id)?;
    let address = nullifier(&address_utxo_hash, &owner.address_seed)?;
    // The address nullifier is this transaction's only, and therefore first,
    // nullifier: the value the circuit binds every derived blinding to. The
    // blinding seed is the new version (0), so both derivations are
    // recomputed here rather than read from instruction data.
    let state = AccountState {
        address,
        authority: authority.to_bytes(),
        value: new_value,
        version: 0,
        blinding: output_blinding(&address, 0)?,
    };
    let output_hash = state.utxo_hash(&owner.owner_hash, output_tree_id)?;
    let payload = state.to_output_data()?;

    let external = TransactExternalData::single_output(TransactOutput {
        utxo_hash: output_hash,
        owner_tag: OwnerTag::Inline(pda_bytes),
        data: Some(payload),
    });
    let external_data_hash = external
        .hash(TRANSACT, &[], &[pda_bytes])
        .map_err(|_| CompressionError::HashingFailed)?;
    let private_tx = private_tx_hash(
        [0u8; 32],
        output_hash,
        address,
        &external_data_hash,
        &private_tx_blinding(&address, 0)?,
    )?;

    let transact = external.into_ix_data(
        private_tx,
        CircuitId::ConfidentialEddsa(1, 1, N_PUBLIC_SLOTS as u8),
        proof,
        TransactInputs {
            inputs: vec![InputUtxo {
                nullifier_hash: address,
                tree_index: 0,
            }],
            tree_contexts: vec![TreeContext {
                utxo_tree_root_index,
                nullifier_tree_root_index,
            }],
        },
    );
    let transact_bytes = transact
        .serialize()
        .map_err(|_| CompressionError::SerializationFailed)?;
    cpi_spp_transact_signed(&authority, &pda, bump, accounts, &transact_bytes)
}
