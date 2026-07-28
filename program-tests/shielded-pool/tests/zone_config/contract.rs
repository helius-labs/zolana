use solana_instruction::{error::InstructionError, AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_system_interface::error::SystemError;
use zolana_account_checks::AccountError;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{
        encode_instruction, tag, CreateZoneConfig, CreateZoneConfigData, UpdateZoneConfig,
        UpdateZoneConfigOwner,
    },
    pda,
    state::{discriminator::ZONE_CONFIG, ZoneConfig},
};
use zolana_program_test::{Rejection, ZONE_TEST_PROGRAM_ID};
use zolana_test_utils::{
    backend::LiteSvmPoolBackend,
    litesvm_asserts::{assert_custom, assert_instruction_error},
};

/// Backend with the zone test program loaded: the `zone_auth` PDA can only
/// sign its own creation through the zone program's `invoke_signed`.
fn zone_backend() -> LiteSvmPoolBackend {
    let mut backend = LiteSvmPoolBackend::initialized();
    backend
        .rpc
        .load_zone_test_program()
        .expect("load zone test program");
    backend
}

fn zone_program() -> Pubkey {
    Pubkey::new_from_array(ZONE_TEST_PROGRAM_ID)
}

fn zone_config_address() -> Pubkey {
    pda::zone_auth(&zone_program()).0
}

fn read_zone_config(backend: &LiteSvmPoolBackend, address: &Pubkey) -> ZoneConfig {
    let bytes = backend
        .rpc
        .account_data(address)
        .expect("zone config account");
    assert_eq!(bytes.len(), ZoneConfig::SIZE);
    *bytemuck::from_bytes::<ZoneConfig>(&bytes)
}

#[test]
fn zone_config_create_update_and_owner_rotation() {
    let mut backend = zone_backend();
    let zone_config = backend
        .rpc
        .create_zone_config(&backend.authority, &backend.authority.pubkey(), true)
        .expect("create zone config");
    backend
        .rpc
        .update_zone_config(&backend.authority, &zone_config, false)
        .expect("disable zone authority execution");
    let next = Keypair::new();
    backend
        .rpc
        .update_zone_config_owner(&backend.authority, &zone_config, &next)
        .expect("rotate zone owner");
    backend
        .rpc
        .update_zone_config(&next, &zone_config, true)
        .expect("new owner update");
}

#[test]
fn zone_config_creation_rejects_an_unsigned_payer() {
    let mut backend = zone_backend();
    // Through the zone program the `zone_auth` PDA still signs via
    // `invoke_signed`; only the payer's signature is withheld, so the failing
    // check is the payer signer check, not the unsigned-config check (7014).
    let data = CreateZoneConfigData {
        program_id: ZONE_TEST_PROGRAM_ID.into(),
        authority: backend.authority.pubkey().to_bytes().into(),
        zone_authority_transact_is_enabled: true,
    };
    let ix = Instruction {
        program_id: zone_program(),
        accounts: vec![
            AccountMeta::new(backend.authority.pubkey(), false),
            AccountMeta::new_readonly(pda::protocol_config(), false),
            AccountMeta::new(zone_config_address(), false),
            AccountMeta::new_readonly(Pubkey::default(), false),
            AccountMeta::new_readonly(backend.rpc.program_id, false),
        ],
        data: encode_instruction(tag::CREATE_ZONE_CONFIG, &data),
    };

    let err = backend
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect_err("unsigned payer must fail");
    assert_custom(err, u32::from(AccountError::InvalidSigner));
    assert!(
        backend.rpc.account_data(&zone_config_address()).is_none(),
        "rejected create must not allocate the config"
    );
}

#[test]
fn zone_config_creation_rejects_a_wrong_system_program() {
    let mut backend = LiteSvmPoolBackend::initialized();
    let mut ix = CreateZoneConfig {
        payer: backend.authority.pubkey(),
        program_id: ZONE_TEST_PROGRAM_ID.into(),
        authority: backend.authority.pubkey().to_bytes().into(),
        zone_authority_transact_is_enabled: true,
    }
    .instruction()
    .expect("build create zone config");
    // Direct SPP call: the system-program check precedes the zone_auth
    // signature check, so no zone signature is needed to pin it.
    ix.accounts.get_mut(2).expect("zone config meta").is_signer = false;
    ix.accounts.get_mut(3).expect("system program meta").pubkey = Pubkey::new_unique();

    let err = backend
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[&backend.authority])
        .expect_err("wrong system program must fail");
    assert_instruction_error(err, InstructionError::IncorrectProgramId);
}

#[test]
fn zone_config_creation_rejects_a_truncated_payload() {
    let mut backend = LiteSvmPoolBackend::initialized();
    let mut ix = CreateZoneConfig {
        payer: backend.authority.pubkey(),
        program_id: ZONE_TEST_PROGRAM_ID.into(),
        authority: backend.authority.pubkey().to_bytes().into(),
        zone_authority_transact_is_enabled: true,
    }
    .instruction()
    .expect("build create zone config");
    ix.accounts.get_mut(2).expect("zone config meta").is_signer = false;
    // Borsh parsing happens before any account check; cut the payload mid-field.
    ix.data.truncate(33);

    let err = backend
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[&backend.authority])
        .expect_err("truncated payload must fail");
    Rejection::pool(ShieldedPoolError::InvalidInstructionData).assert_litesvm(err);
}

#[test]
fn zone_config_creation_initializes_the_exact_account_state() {
    let mut backend = zone_backend();
    let authority = Keypair::new();

    let zone_config = backend
        .rpc
        .create_zone_config(&backend.authority, &authority.pubkey(), true)
        .expect("create zone config");
    let account = backend
        .rpc
        .svm
        .get_account(&zone_config)
        .expect("zone config account");
    assert_eq!(
        account.owner, backend.rpc.program_id,
        "config owner is the shielded-pool program"
    );
    assert_eq!(account.data.len(), ZoneConfig::SIZE);
    let config: &ZoneConfig = bytemuck::from_bytes(&account.data);
    assert_eq!(
        config,
        &ZoneConfig {
            discriminator: ZONE_CONFIG,
            authority: authority.pubkey().to_bytes().into(),
            program_id: ZONE_TEST_PROGRAM_ID.into(),
            zone_authority_transact_is_enabled: 1,
            bump: pda::zone_auth(&zone_program()).1,
        },
        "config after create"
    );
}

#[test]
fn zone_config_creation_rejects_double_initialization() {
    let mut backend = zone_backend();
    let zone_config = backend
        .rpc
        .create_zone_config(&backend.authority, &backend.authority.pubkey(), true)
        .expect("create zone config");
    let config_after_create = backend.rpc.account_data(&zone_config).expect("config data");

    let err = backend
        .rpc
        .create_zone_config(&backend.authority, &backend.authority.pubkey(), false)
        .expect_err("re-creating an existing zone config must fail");
    // The second create fails inside the system-program CPI (the account
    // already exists and owns data); an inner CPI error propagates as-is, so
    // the observable code is the system program's `AccountAlreadyInUse`.
    assert_custom(err, SystemError::AccountAlreadyInUse as u32);
    assert_eq!(
        backend.rpc.account_data(&zone_config).expect("config data"),
        config_after_create,
        "rejected re-init must leave the config untouched"
    );
}

#[test]
fn zone_config_creation_changes_only_the_config_and_payer() {
    let mut backend = zone_backend();
    let zone_config = backend
        .rpc
        .create_zone_config(&backend.authority, &backend.authority.pubkey(), true)
        .expect("create zone config");

    // Rent moves from the instruction payer and the fee from the transaction
    // fee payer; every other message account must be untouched.
    let trace = backend
        .rpc
        .last_transaction_trace()
        .expect("creation trace");
    let allowed = [
        zone_config,
        backend.authority.pubkey(),
        backend.rpc.payer.pubkey(),
    ];
    let unexpected: Vec<Pubkey> = trace
        .changed_accounts()
        .map(|transition| transition.address)
        .filter(|address| !allowed.contains(address))
        .collect();
    assert!(
        unexpected.is_empty(),
        "creation must not touch other accounts: {unexpected:?}"
    );
}

#[test]
fn zone_owner_rotation_rejects_a_non_authority_signer() {
    let mut backend = zone_backend();
    let zone_config = backend
        .rpc
        .create_zone_config(&backend.authority, &backend.authority.pubkey(), true)
        .expect("create zone config");
    let intruder = Keypair::new();
    let next = Keypair::new();

    let err = backend
        .rpc
        .update_zone_config_owner(&intruder, &zone_config, &next)
        .expect_err("a signer that is not the stored authority must fail");
    Rejection::pool(ShieldedPoolError::UnauthorizedCaller).assert_litesvm(err);
    assert_eq!(
        read_zone_config(&backend, &zone_config)
            .authority
            .to_bytes(),
        backend.authority.pubkey().to_bytes(),
        "rejected rotation must not change the authority"
    );
}

#[test]
fn zone_owner_rotation_changes_only_the_authority_field() {
    let mut backend = zone_backend();
    let zone_config = backend
        .rpc
        .create_zone_config(&backend.authority, &backend.authority.pubkey(), true)
        .expect("create zone config");
    let mut expected = read_zone_config(&backend, &zone_config);
    let next = Keypair::new();

    backend
        .rpc
        .update_zone_config_owner(&backend.authority, &zone_config, &next)
        .expect("rotate zone owner");
    expected.authority = next.pubkey().to_bytes().into();
    assert_eq!(
        read_zone_config(&backend, &zone_config),
        expected,
        "only the authority field may change"
    );
    let trace = backend
        .rpc
        .last_transaction_trace()
        .expect("rotation trace");
    let allowed = [zone_config, backend.rpc.payer.pubkey()];
    let unexpected: Vec<Pubkey> = trace
        .changed_accounts()
        .map(|transition| transition.address)
        .filter(|address| !allowed.contains(address))
        .collect();
    assert!(
        unexpected.is_empty(),
        "rotation must not touch other accounts: {unexpected:?}"
    );
}

#[test]
fn zone_owner_rotation_rejects_a_truncated_payload() {
    let mut backend = zone_backend();
    let zone_config = backend
        .rpc
        .create_zone_config(&backend.authority, &backend.authority.pubkey(), true)
        .expect("create zone config");
    let next = Keypair::new();
    let mut ix = UpdateZoneConfigOwner {
        authority: backend.authority.pubkey(),
        zone_config,
        new_authority: next.pubkey().to_bytes().into(),
    }
    .instruction();
    ix.data.truncate(16);

    let err = backend
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[&backend.authority, &next])
        .expect_err("truncated payload must fail");
    Rejection::pool(ShieldedPoolError::InvalidInstructionData).assert_litesvm(err);
}

#[test]
fn zone_config_update_rejects_a_truncated_payload() {
    let mut backend = zone_backend();
    let zone_config = backend
        .rpc
        .create_zone_config(&backend.authority, &backend.authority.pubkey(), true)
        .expect("create zone config");
    let mut ix = UpdateZoneConfig {
        authority: backend.authority.pubkey(),
        zone_config,
        zone_authority_transact_is_enabled: false,
    }
    .instruction();
    // Only the tag remains; the borsh bool payload is missing entirely.
    ix.data.truncate(1);

    let err = backend
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[&backend.authority])
        .expect_err("truncated payload must fail");
    Rejection::pool(ShieldedPoolError::InvalidInstructionData).assert_litesvm(err);
}

#[test]
fn zone_owner_burn_freezes_the_toggle_for_the_old_authority() {
    let mut backend = zone_backend();
    let zone_config = backend
        .rpc
        .create_zone_config(&backend.authority, &backend.authority.pubkey(), true)
        .expect("create zone config");
    backend
        .rpc
        .update_zone_config(&backend.authority, &zone_config, false)
        .expect("disable zone authority transact");

    // A rotation to Address::default() is unreachable by construction: the
    // incoming authority must co-sign and nothing can sign for the default
    // address, so the attempt dies on the co-signer signature check.
    let mut ix = UpdateZoneConfigOwner {
        authority: backend.authority.pubkey(),
        zone_config,
        new_authority: Pubkey::default().to_bytes().into(),
    }
    .instruction();
    ix.accounts
        .get_mut(2)
        .expect("new authority meta")
        .is_signer = false;
    let err = backend
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[&backend.authority])
        .expect_err("rotation to the default address must fail");
    assert_custom(err, u32::from(AccountError::InvalidSigner));

    // The practical burn: rotate to a signing key whose secret is then
    // discarded. Afterwards the old authority can neither toggle nor rotate.
    let burn = Keypair::new();
    backend
        .rpc
        .update_zone_config_owner(&backend.authority, &zone_config, &burn)
        .expect("burn rotation");
    let err = backend
        .rpc
        .update_zone_config(&backend.authority, &zone_config, true)
        .expect_err("old authority toggle must fail after the burn");
    Rejection::pool(ShieldedPoolError::UnauthorizedCaller).assert_litesvm(err);
    let next = Keypair::new();
    let err = backend
        .rpc
        .update_zone_config_owner(&backend.authority, &zone_config, &next)
        .expect_err("old authority rotation must fail after the burn");
    Rejection::pool(ShieldedPoolError::UnauthorizedCaller).assert_litesvm(err);
    // The enabled flag stays exactly in its last state.
    let config = read_zone_config(&backend, &zone_config);
    assert_eq!(config.zone_authority_transact_is_enabled, 0);
    assert_eq!(config.authority.to_bytes(), burn.pubkey().to_bytes());
}

#[test]
fn zone_config_creation_succeeds_for_a_prefunded_pda() {
    let mut backend = zone_backend();
    // An attacker donation to the target PDA must not block creation (the
    // pinocchio helper falls back to allocate + assign + top-up).
    let prefunded = zone_config_address();
    backend
        .rpc
        .airdrop(&prefunded, 1_000_000)
        .expect("prefund zone config PDA");

    let zone_config = backend
        .rpc
        .create_zone_config(&backend.authority, &backend.authority.pubkey(), true)
        .expect("create config over prefunded PDA");
    assert_eq!(zone_config, prefunded);
    let config = read_zone_config(&backend, &zone_config);
    assert_eq!(config.discriminator, ZONE_CONFIG);
    assert_eq!(
        config.authority.to_bytes(),
        backend.authority.pubkey().to_bytes()
    );
}
