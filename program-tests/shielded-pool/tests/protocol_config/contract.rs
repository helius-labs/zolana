use bytemuck::from_bytes;
use solana_account::Account;
use solana_keypair::Keypair;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_account_checks::AccountError;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{UpdateProtocolConfig, UpdateProtocolConfigData},
    pda,
    state::{discriminator, ProtocolConfig},
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_program_test::{Rejection, ZolanaProgramTest};
use zolana_test_utils::mollusk::{expect_err_exact, mollusk_with_program};

const SBF_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/deploy");

/// Run `update_protocol_config` against a fabricated account in the config
/// slot and require the exact `InvalidProtocolConfig` rejection.
fn expect_update_rejects_config_account(config_account: Account) {
    let authority = Keypair::new();
    let ix = UpdateProtocolConfig {
        authority: authority.pubkey(),
        update: UpdateProtocolConfigData::TreeCreationPermissionless(true),
    }
    .instruction();
    let (mollusk, _program_id) =
        mollusk_with_program(SBF_DIR, SHIELDED_POOL_PROGRAM_ID, "shielded_pool_program");
    let accounts = vec![
        (
            authority.pubkey(),
            Account {
                lamports: 1_000_000_000,
                data: Vec::new(),
                owner: Pubkey::default(),
                executable: false,
                rent_epoch: 0,
            },
        ),
        (pda::protocol_config(), config_account),
    ];

    expect_err_exact(
        &mollusk,
        &ix,
        &accounts,
        ProgramError::Custom(ShieldedPoolError::InvalidProtocolConfig as u32),
    );
}

#[test]
fn update_rejects_a_wrong_size_config_account() {
    // Program-owned and correctly stamped, but one byte short of the canonical
    // ProtocolConfig::SIZE.
    let mut data = vec![0u8; ProtocolConfig::SIZE - 1];
    *data.get_mut(0).expect("discriminator byte") = discriminator::PROTOCOL_CONFIG;
    expect_update_rejects_config_account(Account {
        lamports: 1_000_000_000,
        data,
        owner: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        executable: false,
        rent_epoch: 0,
    });
}

#[test]
fn update_rejects_a_cosplay_config_account() {
    // Program-owned and correctly sized, but stamped as another account type:
    // the discriminator alone must gate the load.
    let mut data = vec![0u8; ProtocolConfig::SIZE];
    *data.get_mut(0).expect("discriminator byte") = discriminator::RING_CONFIG;
    expect_update_rejects_config_account(Account {
        lamports: 1_000_000_000,
        data,
        owner: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        executable: false,
        rent_epoch: 0,
    });
}

#[test]
fn update_rejects_a_malformed_borsh_payload() {
    let mut backend = ZolanaProgramTest::new().expect("program test");
    let authority = Keypair::new();
    backend
        .create_protocol_config(&authority)
        .expect("create protocol config");
    let expected = read_config(&backend);
    let base = UpdateProtocolConfig {
        authority: authority.pubkey(),
        update: UpdateProtocolConfigData::TreeCreationPermissionless(true),
    }
    .instruction();

    // Unknown enum tag: UpdateProtocolConfigData has variants 0..=6.
    let mut unknown_variant = base.clone();
    unknown_variant.data.truncate(1);
    unknown_variant.data.push(8);
    let error = backend
        .create_and_send_default_payer_transaction(&[unknown_variant], &[&authority])
        .expect_err("an unknown update variant must be rejected");
    Rejection::pool(ShieldedPoolError::InvalidInstructionData).assert_litesvm(error);

    // ProtocolAuthority variant carrying a truncated 16-byte address.
    let mut truncated_address = base;
    truncated_address.data.truncate(1);
    truncated_address.data.push(0);
    truncated_address.data.extend_from_slice(&[0xAA; 16]);
    let error = backend
        .create_and_send_default_payer_transaction(&[truncated_address], &[&authority])
        .expect_err("a truncated address payload must be rejected");
    Rejection::pool(ShieldedPoolError::InvalidInstructionData).assert_litesvm(error);

    assert_eq!(
        read_config(&backend),
        expected,
        "rejected updates wrote nothing"
    );
}

/// Parse the on-chain config account back into its typed layout, so every
/// assertion below covers each field rather than "something changed".
fn read_config(backend: &ZolanaProgramTest) -> ProtocolConfig {
    let data = backend
        .account_data(&pda::protocol_config())
        .expect("config account");
    *from_bytes::<ProtocolConfig>(&data)
}

/// Creates the config, then walks every updatable field with a distinct value
/// and re-reads the full struct after each write. Asserting complete struct
/// equality (not just the touched field) pins that no update writes into a
/// sibling field.
#[test]
fn create_and_update_protocol_config() {
    let mut backend = ZolanaProgramTest::new().expect("program test");
    let authority = Keypair::new();
    assert!(backend.account_data(&pda::protocol_config()).is_none());
    backend
        .create_protocol_config(&authority)
        .expect("create protocol config");

    let mut expected = ProtocolConfig {
        discriminator: discriminator::PROTOCOL_CONFIG,
        protocol_authority: authority.pubkey().to_bytes().into(),
        tree_creation_authority: authority.pubkey().to_bytes().into(),
        forester_authority: authority.pubkey().to_bytes().into(),
        ring_creation_authority: authority.pubkey().to_bytes().into(),
        fee_authority: authority.pubkey().to_bytes().into(),
        tree_creation_is_permissionless: 0,
        ring_creation_is_permissionless: 0,
        spl_interface_creation_is_permissionless: 0,
        next_tree_id: 0,
    };
    assert_eq!(read_config(&backend), expected, "config after create");

    // Distinct keys per authority field, so a field-swapping write cannot pass.
    let next_forester = Keypair::new();
    backend
        .send_protocol_config_update(
            &authority,
            UpdateProtocolConfigData::ForesterAuthority(next_forester.pubkey().to_bytes().into()),
        )
        .expect("update forester authority");
    expected.forester_authority = next_forester.pubkey().to_bytes().into();
    assert_eq!(read_config(&backend), expected, "forester rotated");

    let next_tree = Keypair::new();
    backend
        .send_protocol_config_update(
            &authority,
            UpdateProtocolConfigData::TreeCreationAuthority(next_tree.pubkey().to_bytes().into()),
        )
        .expect("update tree creation authority");
    expected.tree_creation_authority = next_tree.pubkey().to_bytes().into();
    assert_eq!(read_config(&backend), expected, "tree authority rotated");

    let next_ring = Keypair::new();
    backend
        .send_protocol_config_update(
            &authority,
            UpdateProtocolConfigData::RingCreationAuthority(next_ring.pubkey().to_bytes().into()),
        )
        .expect("update ring creation authority");
    expected.ring_creation_authority = next_ring.pubkey().to_bytes().into();
    assert_eq!(read_config(&backend), expected, "ring authority rotated");

    let next_fee = Keypair::new();
    backend
        .send_protocol_config_update(
            &authority,
            UpdateProtocolConfigData::FeeAuthority(next_fee.pubkey().to_bytes().into()),
        )
        .expect("update fee authority");
    expected.fee_authority = next_fee.pubkey().to_bytes().into();
    assert_eq!(read_config(&backend), expected, "fee authority rotated");

    backend
        .send_protocol_config_update(
            &authority,
            UpdateProtocolConfigData::TreeCreationPermissionless(true),
        )
        .expect("toggle tree permissionless");
    expected.tree_creation_is_permissionless = 1;
    assert_eq!(read_config(&backend), expected, "tree flag toggled");

    backend
        .send_protocol_config_update(
            &authority,
            UpdateProtocolConfigData::RingCreationPermissionless(true),
        )
        .expect("toggle ring permissionless");
    expected.ring_creation_is_permissionless = 1;
    assert_eq!(read_config(&backend), expected, "ring flag toggled");

    backend
        .send_protocol_config_update(
            &authority,
            UpdateProtocolConfigData::SplInterfaceCreationPermissionless(true),
        )
        .expect("toggle spl permissionless");
    expected.spl_interface_creation_is_permissionless = 1;
    assert_eq!(read_config(&backend), expected, "spl flag toggled");

    // Rotate the protocol authority last: the incoming key must co-sign, and
    // afterwards only the new key may update; the previous authority is
    // rejected with the exact authorization error.
    let next_protocol = Keypair::new();
    let rotate_ix = UpdateProtocolConfig {
        authority: authority.pubkey(),
        update: UpdateProtocolConfigData::ProtocolAuthority(
            next_protocol.pubkey().to_bytes().into(),
        ),
    }
    .instruction();

    // Without the incoming authority's signature the rotation must fail: an
    // unsigned co-signer meta is 20009, and a co-signer that does not match
    // the instruction's new authority is 7000.
    let mut unsigned_rotation = rotate_ix.clone();
    unsigned_rotation
        .accounts
        .get_mut(2)
        .expect("new authority meta")
        .is_signer = false;
    let error = backend
        .create_and_send_default_payer_transaction(&[unsigned_rotation], &[&authority])
        .expect_err("rotation without the incoming authority's signature must fail");
    Rejection::custom(u32::from(AccountError::InvalidSigner)).assert_litesvm(error);
    assert_eq!(
        read_config(&backend),
        expected,
        "unsigned rotation wrote nothing"
    );

    let impostor = Keypair::new();
    let mut mismatched_rotation = rotate_ix.clone();
    mismatched_rotation
        .accounts
        .get_mut(2)
        .expect("new authority meta")
        .pubkey = impostor.pubkey();
    let error = backend
        .create_and_send_default_payer_transaction(&[mismatched_rotation], &[&authority, &impostor])
        .expect_err("rotation co-signed by a key other than the new authority must fail");
    Rejection::pool(ShieldedPoolError::InvalidInstructionData).assert_litesvm(error);
    assert_eq!(
        read_config(&backend),
        expected,
        "mismatched rotation wrote nothing"
    );

    backend
        .create_and_send_default_payer_transaction(&[rotate_ix], &[&authority, &next_protocol])
        .expect("rotate protocol authority");
    expected.protocol_authority = next_protocol.pubkey().to_bytes().into();
    assert_eq!(read_config(&backend), expected, "protocol rotated");

    backend
        .airdrop(&next_protocol.pubkey(), 1_000_000_000)
        .expect("fund rotated authority");
    backend
        .send_protocol_config_update(
            &next_protocol,
            UpdateProtocolConfigData::TreeCreationPermissionless(false),
        )
        .expect("rotated authority updates");
    expected.tree_creation_is_permissionless = 0;
    assert_eq!(read_config(&backend), expected, "rotated authority wrote");

    let error = backend
        .send_protocol_config_update(
            &authority,
            UpdateProtocolConfigData::TreeCreationPermissionless(true),
        )
        .expect_err("pre-rotation authority must be rejected");
    Rejection::pool(ShieldedPoolError::UnauthorizedCaller).assert_litesvm(error);
    assert_eq!(
        read_config(&backend),
        expected,
        "rejected update wrote nothing"
    );
}
