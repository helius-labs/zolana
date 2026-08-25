use light_program_profiler::profile;
use pinocchio::{address::address_eq, AccountView, ProgramResult};
use wincode::{SchemaRead, SchemaWrite};
use zolana_interface::{
    event::MessageData,
    instruction::{
        instruction_data::transact::{
            CircuitId, ExternalDataHash, InputUtxo, OwnerTag, ResolvedOutput, TransactIxData,
            TransactOutput, TransactProof,
        },
        tag::TRANSACT,
    },
    N_PUBLIC_SLOTS,
};

use crate::{
    error::CompressionError,
    instructions::shared::{
        cpi_spp_transact_signed, private_tx_hash, TransitionAccounts, DEFAULT_TREE,
    },
    state::{nullifier, AccountState, PdaOwner},
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
    let authority = *parsed.authority.address();
    let (pda, bump) = (parsed.pda, parsed.bump);

    let pda_bytes = pda.to_bytes();
    let owner = PdaOwner::new(&pda_bytes)?;
    let address_utxo_hash = owner.address_utxo_hash()?;
    let address = nullifier(&address_utxo_hash, &owner.address_seed)?;
    let state = AccountState {
        address,
        authority: authority.to_bytes(),
        value: new_value,
        version: 0,
    };
    let output_hash = state.utxo_hash(&owner.owner_hash)?;
    let payload = state.to_output_data()?;

    let resolved_output = [ResolvedOutput {
        utxo_hash: &output_hash,
        owner_tag: pda_bytes,
        data: Some(payload.as_slice()),
    }];
    let messages: &[MessageData] = &[];
    let external_data_hash = ExternalDataHash {
        spp_instruction_discriminator: TRANSACT,
        expiry_unix_ts: u64::MAX,
        interface_transfers: &[],
        data_hash: None,
        ring_data_hash: None,
        tx_viewing_pk: &[0u8; 33],
        salt: &[0u8; 16],
        outputs: &resolved_output,
        messages,
    }
    .hash()
    .map_err(|_| CompressionError::HashingFailed)?;
    let private_tx = private_tx_hash(
        [0u8; 32],
        output_hash,
        address_utxo_hash,
        &external_data_hash,
    )?;

    let transact = TransactIxData {
        expiry_unix_ts: u64::MAX,
        private_tx_hash: private_tx,
        circuit: CircuitId::ConfidentialEddsa(1, 1, N_PUBLIC_SLOTS as u8),
        tx_viewing_pk: [0u8; 33],
        salt: [0u8; 16],
        proof,
        inputs: vec![InputUtxo {
            nullifier_hash: address,
            nullifier_tree_root_index,
            utxo_tree_root_index,
        }],
        interface_transfers: Vec::new(),
        data_hash: None,
        ring_data_hash: None,
        outputs: vec![TransactOutput {
            utxo_hash: output_hash,
            owner_tag: OwnerTag::Inline(pda_bytes),
            data: Some(payload),
        }],
        messages: Vec::new(),
    };
    let transact_bytes = transact
        .serialize()
        .map_err(|_| CompressionError::SerializationFailed)?;
    cpi_spp_transact_signed(&authority, &pda, bump, accounts, &transact_bytes)
}
