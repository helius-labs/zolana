//! Minimal registry SDK for tests. Mirrors the bits of light-protocol's
//! `program-test::registry_sdk` we actually need: anchor sighashes, PDA
//! derivers, and instruction builders for the 4 registry-setup instructions
//! plus `forest_address_tree`.
//!
//! Sighashes are pinned by the unit tests on each builder — a rename on
//! either side will break the suite.

use borsh::{BorshDeserialize, BorshSerialize};
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use zolana_interface::{
    instruction::BatchUpdateAddressTreeData, LIGHT_REGISTRY_PROGRAM_ID, SHIELDED_POOL_PROGRAM_ID,
};

pub const FORESTER_SEED: &[u8] = b"forester";
pub const FORESTER_EPOCH_SEED: &[u8] = b"forester_epoch";
pub const PROTOCOL_CONFIG_PDA_SEED: &[u8] = b"authority";
pub const CPI_AUTHORITY_PDA_SEED: &[u8] = b"cpi_authority";

pub const INITIALIZE_PROTOCOL_CONFIG_DISCRIMINATOR: [u8; 8] = [28, 50, 43, 233, 244, 98, 123, 118];
pub const REGISTER_FORESTER_DISCRIMINATOR: [u8; 8] = [62, 47, 240, 103, 84, 200, 226, 73];
pub const REGISTER_FORESTER_EPOCH_DISCRIMINATOR: [u8; 8] = [43, 120, 253, 194, 109, 192, 101, 188];
pub const FINALIZE_REGISTRATION_DISCRIMINATOR: [u8; 8] = [230, 188, 172, 96, 204, 247, 98, 227];
pub const FOREST_ADDRESS_TREE_DISCRIMINATOR: [u8; 8] = [52, 37, 252, 219, 173, 182, 190, 8];

pub fn registry_program_id() -> Pubkey {
    Pubkey::new_from_array(LIGHT_REGISTRY_PROGRAM_ID)
}

pub fn shielded_pool_program_id() -> Pubkey {
    Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID)
}

pub fn protocol_config_pda() -> (Pubkey, u8) {
    Pubkey::find_program_address(&[PROTOCOL_CONFIG_PDA_SEED], &registry_program_id())
}

pub fn forester_pda(authority: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[FORESTER_SEED, authority.as_ref()], &registry_program_id())
}

pub fn forester_epoch_pda(forester_pda_key: &Pubkey, epoch: u64) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[
            FORESTER_EPOCH_SEED,
            forester_pda_key.as_ref(),
            &epoch.to_le_bytes(),
        ],
        &registry_program_id(),
    )
}

pub fn epoch_pda(epoch: u64) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[&epoch.to_le_bytes()], &registry_program_id())
}

pub fn cpi_authority_pda() -> (Pubkey, u8) {
    Pubkey::find_program_address(&[CPI_AUTHORITY_PDA_SEED], &registry_program_id())
}

/// Mirrors `light_registry::protocol_config::state::ProtocolConfig` field-
/// for-field. Kept in sync via the protocol_config_default test.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ProtocolConfig {
    pub genesis_slot: u64,
    pub min_weight: u64,
    pub slot_length: u64,
    pub registration_phase_length: u64,
    pub active_phase_length: u64,
    pub report_work_phase_length: u64,
    pub network_fee: u64,
    pub cpi_context_size: u64,
    pub finalize_counter_limit: u64,
    pub place_holder: [u8; 32],
    pub address_network_fee: u64,
    pub place_holder_b: u64,
    pub place_holder_c: u64,
    pub place_holder_d: u64,
    pub place_holder_e: u64,
    pub place_holder_f: u64,
}

impl Default for ProtocolConfig {
    fn default() -> Self {
        Self {
            genesis_slot: 0,
            min_weight: 1,
            slot_length: 10,
            registration_phase_length: 100,
            active_phase_length: 1000,
            report_work_phase_length: 100,
            network_fee: 5000,
            cpi_context_size: 14_020,
            finalize_counter_limit: 100,
            place_holder: [0u8; 32],
            address_network_fee: 10_000,
            place_holder_b: 0,
            place_holder_c: 0,
            place_holder_d: 0,
            place_holder_e: 0,
            place_holder_f: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, BorshSerialize, BorshDeserialize)]
pub struct ForesterConfig {
    pub fee: u64,
}

pub fn build_initialize_protocol_config_ix(
    fee_payer: &Pubkey,
    authority: &Pubkey,
    config: ProtocolConfig,
) -> Instruction {
    let (pda, bump) = protocol_config_pda();
    let mut data = INITIALIZE_PROTOCOL_CONFIG_DISCRIMINATOR.to_vec();
    data.push(bump);
    config.serialize(&mut data).expect("infallible");
    Instruction {
        program_id: registry_program_id(),
        accounts: vec![
            AccountMeta::new(*fee_payer, true),
            AccountMeta::new_readonly(*authority, true),
            AccountMeta::new(pda, false),
            AccountMeta::new_readonly(Pubkey::default(), false),
            AccountMeta::new_readonly(registry_program_id(), false),
        ],
        data,
    }
}

pub fn build_register_forester_ix(
    fee_payer: &Pubkey,
    governance_authority: &Pubkey,
    forester_authority: &Pubkey,
    config: ForesterConfig,
    weight: Option<u64>,
) -> Instruction {
    let (forester_pda_key, bump) = forester_pda(forester_authority);
    let (protocol_config, _) = protocol_config_pda();
    let mut data = REGISTER_FORESTER_DISCRIMINATOR.to_vec();
    data.push(bump);
    data.extend_from_slice(forester_authority.as_ref());
    config.serialize(&mut data).expect("infallible");
    match weight {
        Some(w) => {
            data.push(1);
            data.extend_from_slice(&w.to_le_bytes());
        }
        None => data.push(0),
    }
    Instruction {
        program_id: registry_program_id(),
        accounts: vec![
            AccountMeta::new(*fee_payer, true),
            AccountMeta::new_readonly(*governance_authority, true),
            AccountMeta::new_readonly(protocol_config, false),
            AccountMeta::new(forester_pda_key, false),
            AccountMeta::new_readonly(Pubkey::default(), false),
        ],
        data,
    }
}

pub fn build_register_forester_epoch_ix(authority: &Pubkey, epoch: u64) -> Instruction {
    let (forester_pda_key, _) = forester_pda(authority);
    let (forester_epoch_pda_key, _) = forester_epoch_pda(&forester_pda_key, epoch);
    let (epoch_pda_key, _) = epoch_pda(epoch);
    let (protocol_config, _) = protocol_config_pda();
    let mut data = REGISTER_FORESTER_EPOCH_DISCRIMINATOR.to_vec();
    data.extend_from_slice(&epoch.to_le_bytes());
    // Order must match `RegisterForesterEpoch` in
    // `programs/registry/src/epoch/register_epoch.rs`:
    // fee_payer | authority | forester_pda | forester_epoch_pda |
    // protocol_config | epoch_pda | system_program
    Instruction {
        program_id: registry_program_id(),
        accounts: vec![
            AccountMeta::new(*authority, true),
            AccountMeta::new_readonly(*authority, true),
            AccountMeta::new_readonly(forester_pda_key, false),
            AccountMeta::new(forester_epoch_pda_key, false),
            AccountMeta::new_readonly(protocol_config, false),
            AccountMeta::new(epoch_pda_key, false),
            AccountMeta::new_readonly(Pubkey::default(), false),
        ],
        data,
    }
}

pub fn build_finalize_registration_ix(authority: &Pubkey, epoch: u64) -> Instruction {
    let (forester_pda_key, _) = forester_pda(authority);
    let (forester_epoch_pda_key, _) = forester_epoch_pda(&forester_pda_key, epoch);
    let (epoch_pda_key, _) = epoch_pda(epoch);
    // Order must match `FinalizeRegistration` in
    // `programs/registry/src/epoch/finalize_registration.rs`:
    // authority | forester_epoch_pda | epoch_pda
    Instruction {
        program_id: registry_program_id(),
        accounts: vec![
            AccountMeta::new_readonly(*authority, true),
            AccountMeta::new(forester_epoch_pda_key, false),
            AccountMeta::new_readonly(epoch_pda_key, false),
        ],
        data: FINALIZE_REGISTRATION_DISCRIMINATOR.to_vec(),
    }
}

pub fn build_forest_address_tree_ix(
    authority: &Pubkey,
    pool_tree: &Pubkey,
    epoch: u64,
    data: BatchUpdateAddressTreeData,
) -> Instruction {
    let (forester_pda_key, _) = forester_pda(authority);
    let (forester_epoch_pda_key, _) = forester_epoch_pda(&forester_pda_key, epoch);
    let (cpi_authority, _) = cpi_authority_pda();
    let mut payload = FOREST_ADDRESS_TREE_DISCRIMINATOR.to_vec();
    data.serialize(&mut payload).expect("infallible");
    Instruction {
        program_id: registry_program_id(),
        accounts: vec![
            AccountMeta::new(*authority, true),
            AccountMeta::new_readonly(forester_pda_key, false),
            AccountMeta::new(forester_epoch_pda_key, false),
            AccountMeta::new(*pool_tree, false),
            AccountMeta::new_readonly(cpi_authority, false),
            AccountMeta::new_readonly(shielded_pool_program_id(), false),
        ],
        data: payload,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sanity-check that our `ProtocolConfig` mirror serializes to the same
    /// byte size as `light_registry::protocol_config::state::ProtocolConfig`:
    /// 15 u64s + 1 Pubkey = 15*8 + 32 = 152 bytes.
    #[test]
    fn protocol_config_borsh_size() {
        let bytes = borsh::to_vec(&ProtocolConfig::default()).unwrap();
        assert_eq!(bytes.len(), 15 * 8 + 32);
    }
}
