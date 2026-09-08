use solana_instruction::{error::InstructionError, AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_system_interface::error::SystemError;
use zolana_account_checks::AccountError;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{
        encode_instruction, tag, CreateRingConfig, CreateRingConfigData, SetRingActivation,
        UpdateRingConfig, UpdateRingConfigOwner,
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
        .create_ring_config(&backend.authority, &backend.authority.pubkey())
        .expect("create ring config");
    let bump = pda::ring_auth(&ring_program()).1;
    assert_eq!(
        read_ring_config(&backend, &ring_config),
        RingConfig {
            discriminator: RING_CONFIG,
            authority: backend.authority.pubkey().to_bytes().into(),
            program_id: RING_TEST_PROGRAM_ID.into(),
            ring_authority_transact_is_enabled: 0,
            paused: 0,
            activated: 0,
            bump,
        },
        "create initializes an inert config on a permissioned pool"
    );

    backend
        .rpc
        .set_ring_activation(&backend.authority, &ring_config, true, true)
        .expect("governance admits the ring and enables the authority rail");
    backend
        .rpc
        .update_ring_config(&backend.authority, &ring_config, true)
        .expect("the ring pauses itself");
    assert_eq!(
        read_ring_config(&backend, &ring_config),
        RingConfig {
            discriminator: RING_CONFIG,
            authority: backend.authority.pubkey().to_bytes().into(),
            program_id: RING_TEST_PROGRAM_ID.into(),
            ring_authority_transact_is_enabled: 1,
            paused: 1,
            activated: 1,
            bump,
        },
        "governance owns activation and the rail; the ring owns only the pause"
    );

    let next = Keypair::new();
    backend
        .rpc
        .update_ring_config_owner(&backend.authority, &ring_config, &next)
        .expect("rotate ring owner");
    assert_eq!(
        read_ring_config(&backend, &ring_config),
        RingConfig {
            discriminator: RING_CONFIG,
            authority: next.pubkey().to_bytes().into(),
            program_id: RING_TEST_PROGRAM_ID.into(),
            ring_authority_transact_is_enabled: 1,
            paused: 1,
            activated: 1,
            bump,
        },
        "rotation changes only the authority while paused"
    );

    backend
        .rpc
        .update_ring_config(&next, &ring_config, false)
        .expect("new owner unpauses the ring");
    assert_eq!(
        read_ring_config(&backend, &ring_config),
        RingConfig {
            discriminator: RING_CONFIG,
            authority: next.pubkey().to_bytes().into(),
            program_id: RING_TEST_PROGRAM_ID.into(),
            ring_authority_transact_is_enabled: 1,
            paused: 0,
            activated: 1,
            bump,
        },
        "the new owner can unpause but cannot touch the governance flags"
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
        .create_ring_config(&backend.authority, &authority.pubkey())
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
            ring_authority_transact_is_enabled: 0,
            paused: 0,
            activated: 0,
            bump: pda::ring_auth(&ring_program()).1,
        },
        "create lands inert: governance owns activation and the authority rail"
    );
}

#[test]
fn ring_config_creation_rejects_double_initialization() {
    let mut backend = ring_backend();
    let ring_config = backend
        .rpc
        .create_ring_config(&backend.authority, &backend.authority.pubkey())
        .expect("create ring config");
    let config_after_create = backend.rpc.account_data(&ring_config).expect("config data");

    let err = backend
        .rpc
        .create_ring_config(&backend.authority, &backend.authority.pubkey())
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
        .create_ring_config(&backend.authority, &backend.authority.pubkey())
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
        .create_ring_config(&backend.authority, &backend.authority.pubkey())
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
        .create_ring_config(&backend.authority, &backend.authority.pubkey())
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
        .create_ring_config(&backend.authority, &backend.authority.pubkey())
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
fn ring_config_update_rejects_a_legacy_two_bool_payload() {
    let mut backend = ring_backend();
    let ring_config = backend
        .rpc
        .create_ring_config(&backend.authority, &backend.authority.pubkey())
        .expect("create ring config");
    let mut ix = UpdateRingConfig {
        authority: backend.authority.pubkey(),
        ring_config,
        paused: false,
    }
    .instruction();
    // The payload used to carry the enabled flag ahead of `paused`. That flag is
    // governance-owned now, so the former two-bool payload is trailing garbage
    // and `try_from_slice` must reject it rather than silently ignore the byte.
    ix.data.push(1);

    let err = backend
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[&backend.authority])
        .expect_err("legacy two-bool payload must fail");
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
        .create_ring_config(&backend.authority, &backend.authority.pubkey())
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
        .update_ring_config(&backend.authority, &ring_config, false)
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
        .create_ring_config(&backend.authority, &backend.authority.pubkey())
        .expect("create config over prefunded PDA");
    assert_eq!(ring_config, prefunded);
    let config = read_ring_config(&backend, &ring_config);
    assert_eq!(config.discriminator, RING_CONFIG);
    assert_eq!(
        config.authority.to_bytes(),
        backend.authority.pubkey().to_bytes()
    );
}

/// INV-SET-RING-ACT-02: only `protocol_config.ring_creation_authority` may
/// activate, in either direction.
#[test]
fn set_ring_activation_rejects_a_foreign_authority() {
    let mut backend = ring_backend();
    let ring_config = backend
        .rpc
        .create_ring_config(&backend.authority, &backend.authority.pubkey())
        .expect("create ring config");
    let stranger = Keypair::new();
    backend
        .rpc
        .airdrop(&stranger.pubkey(), 1_000_000_000)
        .expect("fund stranger");

    let err = backend
        .rpc
        .set_ring_activation(&stranger, &ring_config, true, true)
        .expect_err("a foreign authority must not admit a ring");
    Rejection::pool(ShieldedPoolError::UnauthorizedCaller).assert_litesvm(err);
    let config = read_ring_config(&backend, &ring_config);
    assert_eq!(
        (config.activated, config.ring_authority_transact_is_enabled),
        (0, 0),
        "a rejected activation leaves both governance flags untouched"
    );
}

/// INV-SET-RING-ACT-01: the signer check is in the processor, so an unsigned
/// authority reports the account-iterator error, not an authority mismatch.
#[test]
fn set_ring_activation_rejects_an_unsigned_authority() {
    let mut backend = ring_backend();
    let ring_config = backend
        .rpc
        .create_ring_config(&backend.authority, &backend.authority.pubkey())
        .expect("create ring config");
    let mut ix = SetRingActivation {
        authority: backend.authority.pubkey(),
        ring_config,
        activated: true,
        ring_authority_transact_is_enabled: true,
    }
    .instruction();
    ix.accounts.get_mut(0).expect("authority meta").is_signer = false;

    let err = backend
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect_err("an unsigned authority must fail");
    Rejection::custom(u32::from(AccountError::InvalidSigner)).assert_litesvm(err);
}

/// INV-SET-RING-ACT-04 and -05: governance writes exactly its two flags, in
/// both directions, and never the ring's `paused`.
#[test]
fn set_ring_activation_changes_only_the_governance_flags() {
    let mut backend = ring_backend();
    let ring_config = backend
        .rpc
        .create_ring_config(&backend.authority, &backend.authority.pubkey())
        .expect("create ring config");
    let before = read_ring_config(&backend, &ring_config);

    // The ring pauses itself first, so the frame assert has a nonzero `paused`
    // to preserve.
    backend
        .rpc
        .update_ring_config(&backend.authority, &ring_config, true)
        .expect("ring pauses itself");
    backend
        .rpc
        .set_ring_activation(&backend.authority, &ring_config, true, true)
        .expect("governance admits the ring and enables the rail");
    assert_eq!(
        read_ring_config(&backend, &ring_config),
        RingConfig {
            activated: 1,
            ring_authority_transact_is_enabled: 1,
            paused: 1,
            ..before
        },
        "activation writes both governance flags and preserves the ring's pause"
    );

    backend
        .rpc
        .set_ring_activation(&backend.authority, &ring_config, false, false)
        .expect("governance deactivates the ring");
    assert_eq!(
        read_ring_config(&backend, &ring_config),
        RingConfig {
            activated: 0,
            ring_authority_transact_is_enabled: 0,
            paused: 1,
            ..before
        },
        "deactivation is permitted and still preserves the ring's pause"
    );
}

/// The ring authority can no longer reach the authority-transact rail: the
/// payload has no such field, and an update leaves the byte untouched.
#[test]
fn ring_update_cannot_enable_the_authority_rail() {
    let mut backend = ring_backend();
    let ring_config = backend
        .rpc
        .create_ring_config(&backend.authority, &backend.authority.pubkey())
        .expect("create ring config");
    backend
        .rpc
        .set_ring_activation(&backend.authority, &ring_config, true, false)
        .expect("governance admits the ring with the rail off");

    for paused in [true, false] {
        backend
            .rpc
            .update_ring_config(&backend.authority, &ring_config, paused)
            .expect("ring toggles its own pause");
        let config = read_ring_config(&backend, &ring_config);
        assert_eq!(
            (config.ring_authority_transact_is_enabled, config.activated),
            (0, 1),
            "the ring's own update must not move either governance flag"
        );
    }
}

/// INV-SET-RING-ACT-03: the config slot must hold a real, program-owned,
/// stamped ring config; a funded system account in that slot is rejected.
#[test]
fn set_ring_activation_rejects_a_cosplay_config_account() {
    let mut backend = ring_backend();
    let impostor_config = Pubkey::new_unique();
    backend
        .rpc
        .airdrop(&impostor_config, 1_000_000)
        .expect("fund impostor config");

    let ix = SetRingActivation {
        authority: backend.authority.pubkey(),
        ring_config: impostor_config,
        activated: true,
        ring_authority_transact_is_enabled: true,
    }
    .instruction();
    let err = backend
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[&backend.authority])
        .expect_err("a non-config account in the config slot must fail");
    Rejection::pool(ShieldedPoolError::InvalidRingConfig).assert_litesvm(err);
}

/// INV-SET-RING-ACT-04: each governance flag independently takes exactly the
/// supplied value, over all four combinations and in both directions.
#[test]
fn set_ring_activation_sets_both_flags() {
    let mut backend = ring_backend();
    let ring_config = backend
        .rpc
        .create_ring_config(&backend.authority, &backend.authority.pubkey())
        .expect("create ring config");
    let before = read_ring_config(&backend, &ring_config);

    for (activated, enabled) in [(true, true), (false, true), (true, false), (false, false)] {
        backend
            .rpc
            .set_ring_activation(&backend.authority, &ring_config, activated, enabled)
            .expect("governance sets both flags");
        assert_eq!(
            read_ring_config(&backend, &ring_config),
            RingConfig {
                activated: u8::from(activated),
                ring_authority_transact_is_enabled: u8::from(enabled),
                ..before
            },
            "flags ({activated}, {enabled}) are written exactly and independently"
        );
    }
}
