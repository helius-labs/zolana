use rings_client::{ClientError, Rpc};
use rings_interface::state::{discriminator::PROTOCOL_CONFIG, ProtocolConfig};
use solana_address::Address;
use solana_pubkey::Pubkey;

use super::fetch_state;

#[track_caller]
pub fn assert_protocol_config<R: Rpc>(
    rpc: &R,
    config: &Pubkey,
    authority: &Pubkey,
) -> Result<(), ClientError> {
    let cfg: ProtocolConfig = fetch_state(rpc, config)?;
    let authority = Address::new_from_array(authority.to_bytes());
    let expected = ProtocolConfig {
        discriminator: PROTOCOL_CONFIG,
        protocol_authority: authority,
        tree_creation_authority: authority,
        forester_authority: authority,
        zone_creation_authority: authority,
        tree_creation_is_permissionless: 0,
        zone_creation_is_permissionless: 0,
        spl_interface_creation_is_permissionless: 0,
    };
    assert_eq!(cfg, expected, "protocol config");
    Ok(())
}
