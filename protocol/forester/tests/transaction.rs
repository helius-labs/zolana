use forester::transaction::{
    compile_message, sign_transaction, transaction_size, ComputeBudgetConfig,
    MAX_LOADED_ACCOUNTS_DATA_SIZE,
};
use solana_hash::Hash;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::VersionedMessage;
use solana_signer::Signer;

#[test]
fn repeated_payer_signer_produces_one_valid_signature_and_matching_size() {
    let payer = Keypair::new();
    let instruction = Instruction {
        program_id: solana_address::Address::new_unique(),
        accounts: vec![AccountMeta::new(payer.pubkey(), true)],
        data: vec![1, 2, 3],
    };
    let budget = ComputeBudgetConfig::for_instruction_count(1);
    let size =
        transaction_size(&payer.pubkey(), std::slice::from_ref(&instruction), budget).unwrap();
    let message =
        compile_message(&payer.pubkey(), &[instruction], Hash::new_unique(), budget).unwrap();
    let VersionedMessage::V1(ref v1) = message else {
        panic!("protocol transactions must be v1");
    };
    assert_eq!(
        v1.config,
        solana_message::v1::TransactionConfig::empty()
            .with_compute_unit_limit(200_000)
            .with_loaded_accounts_data_size_limit(MAX_LOADED_ACCOUNTS_DATA_SIZE)
    );
    let transaction = sign_transaction(message, &[&payer, &payer]).unwrap();
    assert_eq!(transaction.signatures.len(), 1);
    assert!(
        transaction.signatures[0].verify(payer.pubkey().as_ref(), &transaction.message.serialize())
    );
    assert_eq!(size.bytes, 64 + transaction.message.serialize().len());
}
