use light_program_profiler::profile;
use pinocchio::{AccountView, ProgramResult};
use wincode::{SchemaRead, SchemaWrite};
use zolana_interface::{
    event::MessageData,
    instruction::{
        instruction_data::transact::{
            CircuitId, ExternalDataHash, OwnerTag, ResolvedOutput, TransactIxData,
        },
        tag::TRANSACT,
    },
    N_PUBLIC_SLOTS,
};

use crate::{
    error::CompressionError,
    instructions::shared::{cpi_spp_transact_signed, private_tx_hash, TransitionAccounts},
    state::{
        derive_address, derive_blinding, derive_state, nullifier, plaintext_payload,
        state_utxo_hash,
    },
};

#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct CreateIxData {
    pub new_value: u64,
    pub output_seed: [u8; 32],
    pub transact: TransactIxData,
}

#[inline(never)]
#[profile]
pub fn process_create_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let CreateIxData {
        new_value,
        output_seed,
        transact,
    } = wincode::deserialize_exact(data).map_err(|_| CompressionError::InvalidInstructionData)?;

    let parsed = TransitionAccounts::validate_and_parse(accounts)?;
    let authority = *parsed.authority.address();
    let (pda, bump) = (parsed.pda, parsed.bump);

    if transact.expiry_unix_ts != u64::MAX
        || transact.circuit != CircuitId::ConfidentialEddsa(1, 1, N_PUBLIC_SLOTS as u8)
        || transact.tx_viewing_pk != [0u8; 33]
        || transact.salt != [0u8; 16]
        || !transact.interface_transfers.is_empty()
        || transact.data_hash.is_some()
        || transact.ring_data_hash.is_some()
        || !transact.messages.is_empty()
    {
        return Err(CompressionError::InvalidTransact.into());
    }
    let [input] = transact.inputs.as_slice() else {
        return Err(CompressionError::InvalidTransact.into());
    };
    let [output] = transact.outputs.as_slice() else {
        return Err(CompressionError::InvalidTransact.into());
    };
    let Some(output_data) = output.data.as_deref() else {
        return Err(CompressionError::InvalidTransact.into());
    };

    let pda_bytes = pda.to_bytes();
    let address = derive_address(&pda_bytes)?;
    let state = derive_state(&address.address, authority.as_array(), new_value)?;
    let output_blinding = derive_blinding(&output_seed)?;
    let expected_output_hash =
        state_utxo_hash(&address.owner_hash, &state.data_hash, &output_blinding)?;
    if output.utxo_hash != expected_output_hash || output.owner_tag != OwnerTag::Inline(pda_bytes) {
        return Err(CompressionError::InvalidState.into());
    }
    let expected_payload = plaintext_payload(&pda_bytes, &state.state_data, output_seed)?;
    if output_data != expected_payload.as_slice() {
        return Err(CompressionError::InvalidState.into());
    }

    let resolved_output = [ResolvedOutput {
        utxo_hash: &output.utxo_hash,
        owner_tag: pda_bytes,
        data: Some(output_data),
    }];
    let messages: &[MessageData] = &[];
    let external_data_hash = ExternalDataHash {
        spp_instruction_discriminator: TRANSACT,
        expiry_unix_ts: transact.expiry_unix_ts,
        interface_transfers: &[],
        data_hash: None,
        ring_data_hash: None,
        tx_viewing_pk: &transact.tx_viewing_pk,
        salt: &transact.salt,
        outputs: &resolved_output,
        messages,
    }
    .hash()
    .map_err(|_| CompressionError::HashingFailed)?;

    let expected_nullifier = nullifier(&address.address_utxo_hash, &address.address_seed)?;
    if input.nullifier_hash != expected_nullifier {
        return Err(CompressionError::InvalidAddress.into());
    }
    let expected_private_tx = private_tx_hash(
        [0u8; 32],
        expected_output_hash,
        address.address_utxo_hash,
        &external_data_hash,
    )?;
    if transact.private_tx_hash != expected_private_tx {
        return Err(CompressionError::InvalidTransact.into());
    }

    let transact_bytes = transact
        .serialize()
        .map_err(|_| CompressionError::SerializationFailed)?;
    cpi_spp_transact_signed(&authority, &pda, bump, accounts, &transact_bytes)
}
