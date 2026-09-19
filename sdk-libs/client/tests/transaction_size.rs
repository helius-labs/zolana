use solana_instruction::AccountMeta;
use solana_keypair::{Keypair, Signer};
use solana_pubkey::Pubkey;

use solana_hash::Hash;
use solana_instruction::Instruction;
use solana_message::v1;
use zolana_client::rpc::{
    compile_message, sign_transaction, transaction_size, ComputeBudgetConfig,
};

fn wire_size(
    instructions: &[Instruction],
    signers: &[&dyn Signer],
    budget: ComputeBudgetConfig,
) -> usize {
    let payer = signers.first().expect("fee payer").pubkey();
    let message = compile_message(&payer, instructions, Hash::default(), budget).expect("compile");
    let transaction = sign_transaction(message, signers).expect("sign");
    wincode::serialize(&transaction)
        .expect("serialize signed transaction")
        .len()
}

fn instruction_touching(accounts: usize) -> Instruction {
    Instruction::new_with_bytes(
        Pubkey::new_unique(),
        &[],
        (0..accounts)
            .map(|_| AccountMeta::new(Pubkey::new_unique(), false))
            .collect(),
    )
}

#[test]
fn size_matches_signed_wire_bytes_with_repeated_accounts_and_priority_fees() {
    for signer_count in [1, 2, 5] {
        let keys: Vec<_> = (0..signer_count).map(|_| Keypair::new()).collect();
        let payer = keys.first().expect("fee payer").pubkey();
        let signers: Vec<&dyn Signer> = keys.iter().map(|key| key as &dyn Signer).collect();
        let accounts: Vec<_> = keys
            .iter()
            .map(|key| AccountMeta::new(key.pubkey(), true))
            .collect();
        let instruction = Instruction::new_with_bytes(
            Pubkey::new_unique(),
            &[1, 2, 3],
            accounts.iter().chain(&accounts).cloned().collect(),
        );
        for budget in [
            ComputeBudgetConfig::new(200_000),
            ComputeBudgetConfig::new(200_000).with_compute_unit_price(25_000),
        ] {
            let instructions = core::slice::from_ref(&instruction);
            let measured = transaction_size(&payer, instructions, budget).expect("measure");
            assert_eq!(measured.bytes, wire_size(instructions, &signers, budget));
        }
    }
}

#[test]
fn header_fields_are_counted_at_the_wire_limit() {
    let payer = Keypair::new();
    for budget in [
        ComputeBudgetConfig::new(200_000),
        ComputeBudgetConfig::new(200_000).with_compute_unit_price(25_000),
    ] {
        let mut instruction = Instruction::new_with_bytes(Pubkey::new_unique(), &[], vec![]);
        let overhead = wire_size(core::slice::from_ref(&instruction), &[&payer], budget);
        let payload_size = v1::MAX_TRANSACTION_SIZE
            .checked_sub(overhead)
            .expect("header fits");
        instruction.data.resize(payload_size, 0);
        let measured =
            transaction_size(&payer.pubkey(), core::slice::from_ref(&instruction), budget)
                .expect("measure at limit");
        assert_eq!(measured.bytes, v1::MAX_TRANSACTION_SIZE);
        assert!(measured.fits());

        instruction.data.push(0);
        let instructions = core::slice::from_ref(&instruction);
        let measured =
            transaction_size(&payer.pubkey(), instructions, budget).expect("measure over limit");
        assert_eq!(measured.bytes, wire_size(instructions, &[&payer], budget));
        assert_eq!(measured.bytes, v1::MAX_TRANSACTION_SIZE + 1);
        assert!(!measured.fits());
    }
}

/// A transaction can sit well inside the byte ceiling and still be
/// unsendable, because v1 caps the account keys at 64 independently. A wide
/// spend adds a nullifier PDA per input, so this is the ceiling that moves
/// with the shape.
#[test]
fn the_address_ceiling_binds_independently_of_the_byte_ceiling() {
    let payer = Pubkey::new_unique();

    // 62 accounts plus the payer and the program: exactly at the cap.
    let budget = ComputeBudgetConfig::new(200_000);
    let at_cap = transaction_size(
        &payer,
        core::slice::from_ref(&instruction_touching(62)),
        budget,
    )
    .expect("measure");
    assert_eq!(at_cap.addresses, usize::from(v1::MAX_ADDRESSES));
    assert!(at_cap.bytes <= v1::MAX_TRANSACTION_SIZE);
    assert!(at_cap.fits());

    // One more account, still only a couple of kilobytes, and it cannot be
    // sent at all.
    let over_cap = transaction_size(
        &payer,
        core::slice::from_ref(&instruction_touching(63)),
        budget,
    )
    .expect("measure");
    assert_eq!(over_cap.addresses, usize::from(v1::MAX_ADDRESSES) + 1);
    assert!(
        over_cap.bytes <= v1::MAX_TRANSACTION_SIZE,
        "this case is only interesting while the byte ceiling is not the one binding"
    );
    assert!(!over_cap.fits());
}
