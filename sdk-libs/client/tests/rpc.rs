use solana_hash::Hash;
use solana_instruction::Instruction;
use solana_keypair::Signer;
use solana_message::v1;
use solana_pubkey::Pubkey;
use zolana_client::rpc::{
    compile_message, sign_transaction, ComputeBudgetConfig, MAX_LOADED_ACCOUNTS_DATA_SIZE,
};

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
        .with_priority_fee(11_250)
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

/// Signing and sending are version 1. A legacy message is the format
/// `VersionedTransaction::try_new` still accepts, and this client does not.
#[test]
fn a_legacy_message_is_refused() {
    use solana_keypair::Keypair;
    use solana_message::{Message, VersionedMessage};
    use zolana_client::ClientError;

    let payer = Keypair::new();
    let message = VersionedMessage::Legacy(Message::new(&[], Some(&payer.pubkey())));
    let error = sign_transaction(message, &[&payer]).expect_err("legacy message");
    assert!(matches!(error, ClientError::UnsupportedTransactionVersion));
}

/// solana-rpc-client 4.1 sent `bincode::serialize` of `VersionedTransaction`.
/// That writes signatures, then the message. A v1 transaction's wire format is
/// the message, then a raw signature array, and the read side rejects the
/// swapped bytes at the config mask. No RPC is involved.
#[test]
fn serde_encoded_v1_bytes_fail_the_config_mask_check() {
    use solana_keypair::Keypair;
    use solana_transaction::versioned::VersionedTransaction;

    let payer = Keypair::new();
    let instruction = Instruction::new_with_bytes(
        Pubkey::new_unique(),
        &[1, 2, 3],
        vec![solana_instruction::AccountMeta::new(payer.pubkey(), true)],
    );
    let message = compile_message(
        &payer.pubkey(),
        core::slice::from_ref(&instruction),
        Hash::default(),
        ComputeBudgetConfig::new(200_000).with_priority_fee(5_000),
    )
    .expect("compile");
    let transaction = sign_transaction(message, &[&payer]).expect("sign");

    let serde_bytes = bincode::serialize(&transaction).expect("serde encode");
    let wire_bytes = wincode::serialize(&transaction).expect("wire encode");
    let wire: VersionedTransaction =
        wincode::deserialize(&wire_bytes).expect("wire bytes round-trip");
    assert_eq!(wire, transaction);

    let error = wincode::deserialize::<VersionedTransaction>(&serde_bytes)
        .expect_err("serde bytes are not the v1 wire format");
    assert!(
        error
            .to_string()
            .contains("invalid transaction config mask"),
        "{error}"
    );
}
