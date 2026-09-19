use solana_hash::Hash;
use solana_instruction::Instruction;
use solana_keypair::Signer;
use solana_message::v1;
use solana_pubkey::Pubkey;
use zolana_client::rpc::{
    compile_message, sign_transaction, ComputeBudgetConfig, MAX_LOADED_ACCOUNTS_DATA_SIZE,
};

#[test]
fn a_compute_unit_price_converts_to_the_lamport_fee_the_runtime_charged() {
    // The three cases `get_prioritization_fee` pins: a sub-lamport fee
    // rounds up to one, an exact lamport stays one, and a hair over one
    // lamport rounds up to two.
    for (price, limit, expected_fee) in [
        (999_999, 1, 1),
        (1_000_000, 1, 1),
        (1_000_001, 1, 2),
        (25_000, 450_000, 11_250),
        (u64::MAX, u32::MAX, u64::MAX),
    ] {
        let config = ComputeBudgetConfig::new(limit)
            .with_compute_unit_price(price)
            .transaction_config();
        assert_eq!(
            config,
            v1::TransactionConfig::empty()
                .with_compute_unit_limit(limit)
                .with_loaded_accounts_data_size_limit(MAX_LOADED_ACCOUNTS_DATA_SIZE)
                .with_priority_fee(expected_fee)
        );
    }
}

/// An unset v1 header field is zero, not a default, so a config that omits
/// either ceiling produces a transaction that cannot execute at all. Both
/// are always written.
#[test]
fn a_transaction_config_always_states_both_ceilings() {
    let without_priority = ComputeBudgetConfig::new(450_000).transaction_config();
    assert_eq!(
        without_priority,
        v1::TransactionConfig::empty()
            .with_compute_unit_limit(450_000)
            .with_loaded_accounts_data_size_limit(MAX_LOADED_ACCOUNTS_DATA_SIZE)
    );

    let with_priority = ComputeBudgetConfig::new(450_000)
        .with_compute_unit_price(25_000)
        .transaction_config();
    assert_eq!(
        with_priority,
        v1::TransactionConfig::empty()
            .with_compute_unit_limit(450_000)
            .with_loaded_accounts_data_size_limit(MAX_LOADED_ACCOUNTS_DATA_SIZE)
            .with_priority_fee(11_250)
    );
}

/// The implicit budget a legacy transaction used to receive, now stated.
/// Every call site that sent no compute-budget instruction is routed
/// through this, so it has to reproduce the runtime's rule exactly --
/// 200,000 per instruction, capped at 1,400,000 for the transaction.
#[test]
fn an_instruction_count_reproduces_the_implicit_legacy_budget() {
    assert_eq!(
        ComputeBudgetConfig::for_instruction_count(1).cu_limit,
        200_000
    );
    assert_eq!(
        ComputeBudgetConfig::for_instruction_count(3).cu_limit,
        600_000
    );
    assert_eq!(
        ComputeBudgetConfig::for_instruction_count(7).cu_limit,
        1_400_000
    );
    // Past seven instructions the transaction ceiling binds, not the sum.
    assert_eq!(
        ComputeBudgetConfig::for_instruction_count(64).cu_limit,
        1_400_000
    );
    assert_eq!(ComputeBudgetConfig::for_instruction_count(0).cu_limit, 0);
}

/// Legacy partial signing tolerated the same signer twice;
/// `VersionedTransaction::try_new` refuses a list longer than the required
/// signatures. A fee payer that also owns a shielded input arrives twice,
/// so the duplicate is dropped rather than passed on.
#[test]
fn a_repeated_signer_is_passed_once() {
    use solana_keypair::Keypair;

    let payer = Keypair::new();
    let other = Keypair::new();
    // Two required signers, so the duplicate is the only thing the list
    // holds beyond what the message asks for.
    let instruction = Instruction::new_with_bytes(
        Pubkey::new_unique(),
        &[],
        vec![
            solana_instruction::AccountMeta::new(payer.pubkey(), true),
            solana_instruction::AccountMeta::new(other.pubkey(), true),
        ],
    );
    let message = compile_message(
        &payer.pubkey(),
        core::slice::from_ref(&instruction),
        Hash::default(),
        ComputeBudgetConfig::new(200_000),
    )
    .expect("compile");

    let signers: Vec<&dyn Signer> = vec![&payer, &other, &payer];
    let transaction =
        sign_transaction(message, &signers).expect("a repeated signer must not fail signing");
    assert_eq!(transaction.signatures.len(), 2);
}
