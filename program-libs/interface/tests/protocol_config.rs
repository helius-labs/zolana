use solana_address::Address;
use zolana_interface::{
    error::InterfaceError,
    state::{discriminator::PROTOCOL_CONFIG, ProtocolConfig},
};

fn protocol_config() -> ProtocolConfig {
    ProtocolConfig {
        discriminator: PROTOCOL_CONFIG,
        protocol_authority: Address::new_from_array([1; 32]),
        tree_creation_authority: Address::new_from_array([2; 32]),
        forester_authority: Address::new_from_array([3; 32]),
        zone_creation_authority: Address::new_from_array([4; 32]),
        tree_creation_is_permissionless: 0,
        zone_creation_is_permissionless: 0,
        spl_interface_creation_is_permissionless: 1,
    }
}

#[test]
fn parses_only_exact_protocol_config_bytes() {
    let config = protocol_config();
    assert_eq!(
        ProtocolConfig::from_account_bytes(bytemuck::bytes_of(&config)).unwrap(),
        &config
    );

    assert_eq!(
        ProtocolConfig::from_account_bytes(&[0; ProtocolConfig::SIZE - 1]),
        Err(InterfaceError::InvalidProtocolConfigData)
    );
    let mut too_long = bytemuck::bytes_of(&config).to_vec();
    too_long.push(0);
    assert_eq!(
        ProtocolConfig::from_account_bytes(&too_long),
        Err(InterfaceError::InvalidProtocolConfigData)
    );

    let mut wrong_discriminator = config;
    wrong_discriminator.discriminator = 0;
    assert_eq!(
        ProtocolConfig::from_account_bytes(bytemuck::bytes_of(&wrong_discriminator)),
        Err(InterfaceError::InvalidDiscriminator)
    );
}
