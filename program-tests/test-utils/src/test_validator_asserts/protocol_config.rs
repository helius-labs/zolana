use solana_address::Address;
use solana_pubkey::Pubkey;
use zolana_client::{ClientError, Rpc};
use zolana_interface::state::{discriminator::PROTOCOL_CONFIG, ProtocolConfig};

use super::fetch_state;

#[track_caller]
pub fn assert_protocol_config<R: Rpc>(
    rpc: &R,
    config: &Pubkey,
    authority: &Pubkey,
    next_tree_id: u16,
) -> Result<(), ClientError> {
    let cfg: ProtocolConfig = fetch_state(rpc, config)?;
    let authority = Address::new_from_array(authority.to_bytes());
    let expected = ProtocolConfig {
        discriminator: PROTOCOL_CONFIG,
        protocol_authority: authority,
        tree_creation_authority: authority,
        forester_authority: authority,
        ring_creation_authority: authority,
        fee_authority: authority,
        tree_creation_is_permissionless: 0,
        ring_creation_is_permissionless: 0,
        spl_interface_creation_is_permissionless: 0,
        next_tree_id,
    };
    assert_eq!(cfg, expected, "protocol config");
    Ok(())
}
