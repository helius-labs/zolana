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
    merge_authority: &[u8; 32],
) -> Result<(), ClientError> {
    let cfg: ProtocolConfig = fetch_state(rpc, config)?;
    let authority = Address::new_from_array(authority.to_bytes());
    let expected = ProtocolConfig {
        discriminator: PROTOCOL_CONFIG,
        protocol_authority: authority,
        tree_creation_authority: authority,
        forester_authority: authority,
        zone_creation_authority: authority,
        merge_authority: Address::new_from_array(*merge_authority),
        tree_creation_is_permissionless: 0,
        zone_creation_is_permissionless: 0,
    };
    assert_eq!(cfg, expected, "protocol config");
    Ok(())
}
