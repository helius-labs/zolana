use solana_instruction::error::InstructionError;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_system_interface::error::SystemError;
use zolana_account_checks::AccountError;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::CreateAssetCounter,
    pda,
    state::{discriminator::SPL_ASSET_COUNTER, SplAssetCounter},
};
use zolana_program_test::Rejection;
use zolana_test_utils::{
    backend::LiteSvmPoolBackend,
    litesvm_asserts::{assert_custom, assert_instruction_error},
};

#[test]
fn asset_counter_assigns_distinct_canonical_interfaces() {
    let mut backend = LiteSvmPoolBackend::initialized();
    backend
        .rpc
        .create_asset_counter(&backend.authority)
        .expect("create asset counter");
    assert!(backend
        .rpc
        .account_data(&pda::spl_asset_counter())
        .is_some());

    let first = backend.rpc.create_mint().expect("first mint");
    let second = backend.rpc.create_mint().expect("second mint");
    let first_accounts = backend
        .rpc
        .create_spl_interface(&backend.authority, &first)
        .expect("first interface");
    let second_accounts = backend
        .rpc
        .create_spl_interface(&backend.authority, &second)
        .expect("second interface");
    assert_ne!(first_accounts, second_accounts);
    for address in [
        pda::spl_asset_registry(&first),
        pda::spl_asset_vault(&first),
        pda::spl_asset_registry(&second),
        pda::spl_asset_vault(&second),
    ] {
        assert!(
            backend.rpc.account_data(&address).is_some(),
            "missing {address}"
        );
    }
}

#[test]
fn asset_counter_rejects_a_non_protocol_authority() {
    let mut backend = LiteSvmPoolBackend::initialized();
    let intruder = Keypair::new();
    backend
        .rpc
        .airdrop(&intruder.pubkey(), 1_000_000_000)
        .expect("fund intruder");

    let error = backend
        .rpc
        .create_asset_counter(&intruder)
        .expect_err("a signer that is not the protocol authority must be rejected");
    Rejection::pool(ShieldedPoolError::UnauthorizedCaller).assert_litesvm(error);
    assert!(
        backend
            .rpc
            .account_data(&pda::spl_asset_counter())
            .is_none(),
        "rejected create must not allocate the counter"
    );
}

#[test]
fn asset_counter_creation_rejects_an_unsigned_authority() {
    let mut backend = LiteSvmPoolBackend::initialized();
    let mut ix = CreateAssetCounter {
        authority: backend.authority.pubkey(),
    }
    .instruction();
    ix.accounts.first_mut().expect("authority meta").is_signer = false;

    let err = backend
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect_err("unsigned authority must fail");
    assert_custom(err, u32::from(AccountError::InvalidSigner));
    assert!(
        backend
            .rpc
            .account_data(&pda::spl_asset_counter())
            .is_none(),
        "rejected create must not allocate the counter"
    );
}

#[test]
fn asset_counter_creation_rejects_a_wrong_system_program() {
    let mut backend = LiteSvmPoolBackend::initialized();
    let mut ix = CreateAssetCounter {
        authority: backend.authority.pubkey(),
    }
    .instruction();
    ix.accounts.get_mut(3).expect("system program meta").pubkey = Pubkey::new_unique();

    let err = backend
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[&backend.authority])
        .expect_err("wrong system program must fail");
    assert_instruction_error(err, InstructionError::IncorrectProgramId);
}

#[test]
fn asset_counter_creation_rejects_trailing_instruction_bytes() {
    let mut backend = LiteSvmPoolBackend::initialized();
    let mut ix = CreateAssetCounter {
        authority: backend.authority.pubkey(),
    }
    .instruction();
    ix.data.push(0xFF);

    let err = backend
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[&backend.authority])
        .expect_err("non-empty instruction payload must fail");
    Rejection::pool(ShieldedPoolError::InvalidInstructionData).assert_litesvm(err);
    assert!(
        backend
            .rpc
            .account_data(&pda::spl_asset_counter())
            .is_none(),
        "rejected create must not allocate the counter"
    );
}

#[test]
fn asset_counter_creation_initializes_complete_state() {
    let mut backend = LiteSvmPoolBackend::initialized();
    backend
        .rpc
        .create_asset_counter(&backend.authority)
        .expect("create asset counter");

    let account = backend
        .rpc
        .svm
        .get_account(&pda::spl_asset_counter())
        .expect("counter account");
    assert_eq!(
        account.owner, backend.rpc.program_id,
        "counter owner is the shielded-pool program"
    );
    assert_eq!(account.data.len(), SplAssetCounter::SIZE);
    // The fetched bytes make no alignment promise for the 8-aligned struct.
    let counter: SplAssetCounter = bytemuck::pod_read_unaligned(&account.data);
    assert_eq!(
        counter,
        SplAssetCounter {
            discriminator: SPL_ASSET_COUNTER,
            reserved: [0u8; 7],
            next_id: 2,
        },
        "counter after create"
    );
}

#[test]
fn asset_counter_creation_changes_only_the_counter_and_authority() {
    let mut backend = LiteSvmPoolBackend::initialized();
    backend
        .rpc
        .create_asset_counter(&backend.authority)
        .expect("create asset counter");

    // Rent moves from the authority and the fee from the transaction fee
    // payer; every other message account must be untouched.
    let trace = backend
        .rpc
        .last_transaction_trace()
        .expect("creation trace");
    let allowed = [
        pda::spl_asset_counter(),
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
fn asset_counter_creation_succeeds_for_a_prefunded_pda() {
    let mut backend = LiteSvmPoolBackend::initialized();
    // An attacker donation to the target PDA must not block creation (the
    // pinocchio helper falls back to allocate + assign + top-up).
    let prefunded = pda::spl_asset_counter();
    backend
        .rpc
        .airdrop(&prefunded, 1_000_000)
        .expect("prefund counter PDA");

    let created = backend
        .rpc
        .create_asset_counter(&backend.authority)
        .expect("create counter over prefunded PDA");
    assert_eq!(created, prefunded);
    let counter: SplAssetCounter =
        bytemuck::pod_read_unaligned(&backend.rpc.account_data(&prefunded).expect("counter data"));
    assert_eq!(counter.discriminator, SPL_ASSET_COUNTER);
    assert_eq!(counter.next_id, 2);
}

#[test]
fn asset_counter_rejects_double_initialization() {
    let mut backend = LiteSvmPoolBackend::initialized();
    backend
        .rpc
        .create_asset_counter(&backend.authority)
        .expect("create asset counter");
    let counter_after_create = backend
        .rpc
        .account_data(&pda::spl_asset_counter())
        .expect("counter data");

    let error = backend
        .rpc
        .create_asset_counter(&backend.authority)
        .expect_err("re-initializing the singleton counter must fail");
    // The second create fails inside the system-program CPI; an inner CPI
    // error propagates as-is, so the observable code is the system program's
    // `AccountAlreadyInUse`, not a pool error.
    assert_custom(error, SystemError::AccountAlreadyInUse as u32);
    assert_eq!(
        backend
            .rpc
            .account_data(&pda::spl_asset_counter())
            .expect("counter data"),
        counter_after_create,
        "rejected re-init must leave the counter untouched"
    );
}
