use solana_instruction::{error::InstructionError, AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_system_interface::error::SystemError;
use zolana_account_checks::AccountError;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{
        encode_instruction, tag, CreateRingConfig, CreateRingConfigData, UpdateRingConfig,
        UpdateRingConfigOwner,
    },
    pda,
    state::{discriminator::RING_CONFIG, RingConfig},
};
use zolana_program_test::{Rejection, RING_TEST_PROGRAM_ID};
use zolana_test_utils::backend::LiteSvmPoolBackend;

/// Backend with the ring test program loaded: the `ring_auth` PDA can only
/// sign its own creation through the ring program's `invoke_signed`.
fn ring_backend() -> LiteSvmPoolBackend {
    let mut backend = LiteSvmPoolBackend::initialized();
    backend
        .rpc
        .load_ring_test_program()
        .expect("load ring test program");
    backend
}

fn ring_program() -> Pubkey {
    Pubkey::new_from_array(RING_TEST_PROGRAM_ID)
}

fn ring_config_address() -> Pubkey {
    pda::ring_auth(&ring_program()).0
}

fn read_ring_config(backend: &LiteSvmPoolBackend, address: &Pubkey) -> RingConfig {
    let bytes = backend
        .rpc
        .account_data(address)
        .expect("ring config account");
    assert_eq!(bytes.len(), RingConfig::SIZE);
    *bytemuck::from_bytes::<RingConfig>(&bytes)
}

#[test]
fn ring_config_create_update_and_owner_rotation() {
    let mut backend = ring_backend();
    let ring_config = backend
        .rpc
        .create_ring_config(&backend.authority, &backend.authority.pubkey(), true)
        .expect("create ring config");
    let config = read_ring_config(&backend, &ring_config);
    assert_eq!(
        config.authority.to_bytes(),
        backend.authority.pubkey().to_bytes(),
        "create stores the named authority"
    );
    assert_eq!(
        config.program_id.to_bytes(),
        RING_TEST_PROGRAM_ID,
        "create stores the ring program id"
    );
    assert_eq!(
        config.ring_authority_transact_is_enabled, 1,
        "create enables ring authority transact"
    );

    backend
        .rpc
        .update_ring_config(&backend.authority, &ring_config, false)
        .expect("disable ring authority execution");
    let config = read_ring_config(&backend, &ring_config);
    assert_eq!(
        config.ring_authority_transact_is_enabled, 0,
        "update disables ring authority transact"
    );
    assert_eq!(
        config.authority.to_bytes(),
        backend.authority.pubkey().to_bytes(),
        "update leaves the authority untouched"
    );

    let next = Keypair::new();
    backend
        .rpc
        .update_ring_config_owner(&backend.authority, &ring_config, &next)
        .expect("rotate ring owner");
    let config = read_ring_config(&backend, &ring_config);
    assert_eq!(
        config.authority.to_bytes(),
        next.pubkey().to_bytes(),
        "rotation installs the new authority"
    );
    assert_eq!(
        config.ring_authority_transact_is_enabled, 0,
        "rotation leaves the enabled flag untouched"
    );

    backend
        .rpc
        .update_ring_config(&next, &ring_config, true)
        .expect("new owner update");
    let config = read_ring_config(&backend, &ring_config);
    assert_eq!(
        config.ring_authority_transact_is_enabled, 1,
        "new owner re-enables ring authority transact"
    );
    assert_eq!(
        config.authority.to_bytes(),
        next.pubkey().to_bytes(),
        "new owner update leaves the authority untouched"
    );
}

#[test]
fn ring_config_creation_rejects_an_unsigned_payer() {
    let mut backend = ring_backend();
    // Through the ring program the `ring_auth` PDA still signs via
    // `invoke_signed`; only the payer's signature is withheld, so the failing
    // check is the payer signer check, not the unsigned-config check (7014).
    let data = CreateRingConfigData {
        program_id: RING_TEST_PROGRAM_ID.into(),
        authority: backend.authority.pubkey().to_bytes().into(),
        ring_authority_transact_is_enabled: true,
    };
    let ix = Instruction {
        program_id: ring_program(),
        accounts: vec![
            AccountMeta::new(backend.authority.pubkey(), false),
            AccountMeta::new_readonly(pda::protocol_config(), false),
            AccountMeta::new(ring_config_address(), false),
            AccountMeta::new_readonly(Pubkey::default(), false),
            AccountMeta::new_readonly(backend.rpc.program_id, false),
        ],
        data: encode_instruction(tag::CREATE_RING_CONFIG, &data),
    };

    let err = backend
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect_err("unsigned payer must fail");
    Rejection::custom(u32::from(AccountError::InvalidSigner)).assert_litesvm(err);
    assert!(
        backend.rpc.account_data(&ring_config_address()).is_none(),
        "rejected create must not allocate the config"
    );
    backend
        .rpc
        .last_transaction_trace()
        .expect("rejected transaction trace")
        .assert_rolled_back_except(&[backend.rpc.payer.pubkey()]);
}

#[test]
fn ring_config_creation_rejects_a_wrong_system_program() {
    let mut backend = LiteSvmPoolBackend::initialized();
    let mut ix = CreateRingConfig {
        payer: backend.authority.pubkey(),
        program_id: RING_TEST_PROGRAM_ID.into(),
        authority: backend.authority.pubkey().to_bytes().into(),
        ring_authority_transact_is_enabled: true,
    }
    .instruction()
    .expect("build create ring config");
    // Direct SPP call: the system-program check precedes the ring_auth
    // signature check, so no ring signature is needed to pin it.
    ix.accounts.get_mut(2).expect("ring config meta").is_signer = false;
    ix.accounts.get_mut(3).expect("system program meta").pubkey = Pubkey::new_unique();

    let err = backend
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[&backend.authority])
        .expect_err("wrong system program must fail");
    Rejection::new(InstructionError::IncorrectProgramId).assert_litesvm(err);
    backend
        .rpc
        .last_transaction_trace()
        .expect("rejected transaction trace")
        .assert_rolled_back_except(&[backend.rpc.payer.pubkey()]);
}

#[test]
fn ring_config_creation_rejects_a_truncated_payload() {
    let mut backend = LiteSvmPoolBackend::initialized();
    let mut ix = CreateRingConfig {
        payer: backend.authority.pubkey(),
        program_id: RING_TEST_PROGRAM_ID.into(),
        authority: backend.authority.pubkey().to_bytes().into(),
        ring_authority_transact_is_enabled: true,
    }
    .instruction()
    .expect("build create ring config");
    ix.accounts.get_mut(2).expect("ring config meta").is_signer = false;
    // Borsh parsing happens before any account check; cut the payload mid-field.
    ix.data.truncate(33);

    let err = backend
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[&backend.authority])
        .expect_err("truncated payload must fail");
    Rejection::pool(ShieldedPoolError::InvalidInstructionData).assert_litesvm(err);
    backend
        .rpc
        .last_transaction_trace()
        .expect("rejected transaction trace")
        .assert_rolled_back_except(&[backend.rpc.payer.pubkey()]);
}

#[test]
fn ring_config_creation_initializes_the_exact_account_state() {
    let mut backend = ring_backend();
    let authority = Keypair::new();

    let ring_config = backend
        .rpc
        .create_ring_config(&backend.authority, &authority.pubkey(), true)
        .expect("create ring config");
    let account = backend
        .rpc
        .svm
        .get_account(&ring_config)
        .expect("ring config account");
    assert_eq!(
        account.owner, backend.rpc.program_id,
        "config owner is the shielded-pool program"
    );
    assert_eq!(account.data.len(), RingConfig::SIZE);
    let config: &RingConfig = bytemuck::from_bytes(&account.data);
    assert_eq!(
        config,
        &RingConfig {
            discriminator: RING_CONFIG,
            authority: authority.pubkey().to_bytes().into(),
            program_id: RING_TEST_PROGRAM_ID.into(),
            ring_authority_transact_is_enabled: 1,
            bump: pda::ring_auth(&ring_program()).1,
        },
        "config after create"
    );
}

#[test]
fn ring_config_creation_rejects_double_initialization() {
    let mut backend = ring_backend();
    let ring_config = backend
        .rpc
        .create_ring_config(&backend.authority, &backend.authority.pubkey(), true)
        .expect("create ring config");
    let config_after_create = backend.rpc.account_data(&ring_config).expect("config data");

    let err = backend
        .rpc
        .create_ring_config(&backend.authority, &backend.authority.pubkey(), false)
        .expect_err("re-creating an existing ring config must fail");
    // The second create fails inside the system-program CPI (the account
    // already exists and owns data); an inner CPI error propagates as-is, so
    // the observable code is the system program's `AccountAlreadyInUse`.
    Rejection::custom(SystemError::AccountAlreadyInUse as u32).assert_litesvm(err);
    assert_eq!(
        backend.rpc.account_data(&ring_config).expect("config data"),
        config_after_create,
        "rejected re-init must leave the config untouched"
    );
    backend
        .rpc
        .last_transaction_trace()
        .expect("rejected transaction trace")
        .assert_rolled_back_except(&[backend.rpc.payer.pubkey()]);
}

#[test]
fn ring_config_creation_changes_only_the_config_and_payer() {
    let mut backend = ring_backend();
    let ring_config = backend
        .rpc
        .create_ring_config(&backend.authority, &backend.authority.pubkey(), true)
        .expect("create ring config");

    // Rent moves from the instruction payer and the fee from the transaction
    // fee payer; every other message account must be untouched.
    let trace = backend
        .rpc
        .last_transaction_trace()
        .expect("creation trace");
    let allowed = [
        ring_config,
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
fn ring_owner_rotation_rejects_a_non_authority_signer() {
    let mut backend = ring_backend();
    let ring_config = backend
        .rpc
        .create_ring_config(&backend.authority, &backend.authority.pubkey(), true)
        .expect("create ring config");
    let intruder = Keypair::new();
    let next = Keypair::new();

    let err = backend
        .rpc
        .update_ring_config_owner(&intruder, &ring_config, &next)
        .expect_err("a signer that is not the stored authority must fail");
    Rejection::pool(ShieldedPoolError::UnauthorizedCaller).assert_litesvm(err);
    assert_eq!(
        read_ring_config(&backend, &ring_config)
            .authority
            .to_bytes(),
        backend.authority.pubkey().to_bytes(),
        "rejected rotation must not change the authority"
    );
    backend
        .rpc
        .last_transaction_trace()
        .expect("rejected transaction trace")
        .assert_rolled_back_except(&[backend.rpc.payer.pubkey()]);
}

#[test]
fn ring_owner_rotation_changes_only_the_authority_field() {
    let mut backend = ring_backend();
    let ring_config = backend
        .rpc
        .create_ring_config(&backend.authority, &backend.authority.pubkey(), true)
        .expect("create ring config");
    let mut expected = read_ring_config(&backend, &ring_config);
    let next = Keypair::new();

    backend
        .rpc
        .update_ring_config_owner(&backend.authority, &ring_config, &next)
        .expect("rotate ring owner");
    expected.authority = next.pubkey().to_bytes().into();
    assert_eq!(
        read_ring_config(&backend, &ring_config),
        expected,
        "only the authority field may change"
    );
    let trace = backend
        .rpc
        .last_transaction_trace()
        .expect("rotation trace");
    let allowed = [ring_config, backend.rpc.payer.pubkey()];
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
fn ring_owner_rotation_rejects_a_legacy_payload() {
    let mut backend = ring_backend();
    let ring_config = backend
        .rpc
        .create_ring_config(&backend.authority, &backend.authority.pubkey(), true)
        .expect("create ring config");
    let next = Keypair::new();
    let mut ix = UpdateRingConfigOwner {
        authority: backend.authority.pubkey(),
        ring_config,
        new_authority: next.pubkey().to_bytes().into(),
    }
    .instruction();
    // PR172 removed the borsh payload: the instruction data is exactly the tag
    // byte and ANY trailing bytes (a legacy encoding, or junk) are rejected.
    ix.data.extend_from_slice(&[7u8; 16]);

    let err = backend
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[&backend.authority, &next])
        .expect_err("a payload after the tag must fail");
    Rejection::pool(ShieldedPoolError::InvalidInstructionData).assert_litesvm(err);
    backend
        .rpc
        .last_transaction_trace()
        .expect("rejected transaction trace")
        .assert_rolled_back_except(&[backend.rpc.payer.pubkey()]);
}

#[test]
fn ring_config_update_rejects_a_truncated_payload() {
    let mut backend = ring_backend();
    let ring_config = backend
        .rpc
        .create_ring_config(&backend.authority, &backend.authority.pubkey(), true)
        .expect("create ring config");
    let mut ix = UpdateRingConfig {
        authority: backend.authority.pubkey(),
        ring_config,
        ring_authority_transact_is_enabled: false,
    }
    .instruction();
    // Only the tag remains; the borsh bool payload is missing entirely.
    ix.data.truncate(1);

    let err = backend
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[&backend.authority])
        .expect_err("truncated payload must fail");
    Rejection::pool(ShieldedPoolError::InvalidInstructionData).assert_litesvm(err);
    backend
        .rpc
        .last_transaction_trace()
        .expect("rejected transaction trace")
        .assert_rolled_back_except(&[backend.rpc.payer.pubkey()]);
}

#[test]
fn ring_owner_burn_freezes_the_toggle_for_the_old_authority() {
    let mut backend = ring_backend();
    let ring_config = backend
        .rpc
        .create_ring_config(&backend.authority, &backend.authority.pubkey(), true)
        .expect("create ring config");
    backend
        .rpc
        .update_ring_config(&backend.authority, &ring_config, false)
        .expect("disable ring authority transact");

    // A rotation to Address::default() is unreachable by construction: the
    // incoming authority must co-sign and nothing can sign for the default
    // address, so the attempt dies on the co-signer signature check.
    let mut ix = UpdateRingConfigOwner {
        authority: backend.authority.pubkey(),
        ring_config,
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
    Rejection::custom(u32::from(AccountError::InvalidSigner)).assert_litesvm(err);
    backend
        .rpc
        .last_transaction_trace()
        .expect("rejected transaction trace")
        .assert_rolled_back_except(&[backend.rpc.payer.pubkey()]);

    // The practical burn: rotate to a signing key whose secret is then
    // discarded. Afterwards the old authority can neither toggle nor rotate.
    let burn = Keypair::new();
    backend
        .rpc
        .update_ring_config_owner(&backend.authority, &ring_config, &burn)
        .expect("burn rotation");
    let err = backend
        .rpc
        .update_ring_config(&backend.authority, &ring_config, true)
        .expect_err("old authority toggle must fail after the burn");
    Rejection::pool(ShieldedPoolError::UnauthorizedCaller).assert_litesvm(err);
    backend
        .rpc
        .last_transaction_trace()
        .expect("rejected transaction trace")
        .assert_rolled_back_except(&[backend.rpc.payer.pubkey()]);
    let next = Keypair::new();
    let err = backend
        .rpc
        .update_ring_config_owner(&backend.authority, &ring_config, &next)
        .expect_err("old authority rotation must fail after the burn");
    Rejection::pool(ShieldedPoolError::UnauthorizedCaller).assert_litesvm(err);
    backend
        .rpc
        .last_transaction_trace()
        .expect("rejected transaction trace")
        .assert_rolled_back_except(&[backend.rpc.payer.pubkey()]);
    // The enabled flag stays exactly in its last state.
    let config = read_ring_config(&backend, &ring_config);
    assert_eq!(config.ring_authority_transact_is_enabled, 0);
    assert_eq!(config.authority.to_bytes(), burn.pubkey().to_bytes());
}

#[test]
fn ring_config_creation_succeeds_for_a_prefunded_pda() {
    let mut backend = ring_backend();
    // An attacker donation to the target PDA must not block creation (the
    // pinocchio helper falls back to allocate + assign + top-up; see
    // spl_interface/contract.rs for the full rationale).
    let prefunded = ring_config_address();
    backend
        .rpc
        .airdrop(&prefunded, 1_000_000)
        .expect("prefund ring config PDA");

    let ring_config = backend
        .rpc
        .create_ring_config(&backend.authority, &backend.authority.pubkey(), true)
        .expect("create config over prefunded PDA");
    assert_eq!(ring_config, prefunded);
    let config = read_ring_config(&backend, &ring_config);
    assert_eq!(config.discriminator, RING_CONFIG);
    assert_eq!(
        config.authority.to_bytes(),
        backend.authority.pubkey().to_bytes()
    );
}
