//! Measuring a transaction against the v1 limits.
//!
//! v1 has two ceilings, and a transaction has to clear both: 4,096 wire bytes,
//! and 64 account addresses. The byte ceiling is the one the shielded pool was
//! built around; the address ceiling is the one that creeps up unnoticed,
//! because a wide spend adds one nullifier PDA per input.

use solana_address::Address;
use solana_hash::Hash;
use solana_instruction::Instruction;
use solana_message::v1;

use crate::{error::ClientError, ComputeBudgetConfig};

/// The one-byte version prefix a v1 transaction carries ahead of its message.
const VERSION_PREFIX_LEN: usize = 1;
pub const SIGNATURE_LEN: usize = 64;

/// What a compiled transaction costs against each v1 ceiling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransactionSize {
    pub bytes: usize,
    pub addresses: usize,
}

impl TransactionSize {
    /// Whether the transaction clears both ceilings. Neither alone is enough.
    pub fn fits(&self) -> bool {
        self.bytes <= v1::MAX_TRANSACTION_SIZE && self.addresses <= usize::from(v1::MAX_ADDRESSES)
    }
}

/// Measure `instructions` as the v1 transaction they would be sent as.
///
/// Includes the configured header fields and every signature required by the
/// compiled message. Use the same budget as the sender.
pub fn transaction_size(
    payer: &Address,
    instructions: &[Instruction],
    compute_budget: ComputeBudgetConfig,
) -> Result<TransactionSize, ClientError> {
    let message = v1::Message::try_compile_with_config(
        payer,
        instructions,
        Hash::default(),
        compute_budget.transaction_config(),
    )
    .map_err(|error| ClientError::TransactionCompile(error.to_string()))?;
    let signatures = usize::from(message.header.num_required_signatures);
    let bytes = signatures
        .checked_mul(SIGNATURE_LEN)
        .and_then(|signatures| signatures.checked_add(VERSION_PREFIX_LEN))
        .and_then(|overhead| overhead.checked_add(message.size()))
        .ok_or_else(|| ClientError::TransactionCompile("transaction size overflow".to_owned()))?;
    Ok(TransactionSize {
        bytes,
        addresses: message.account_keys.len(),
    })
}

#[cfg(test)]
mod tests {
    use solana_instruction::AccountMeta;
    use solana_keypair::{Keypair, Signer};
    use solana_pubkey::Pubkey;

    use super::*;
    use crate::{compile_message, sign_transaction};

    fn wire_size(
        instructions: &[Instruction],
        signers: &[&dyn Signer],
        budget: ComputeBudgetConfig,
    ) -> usize {
        let payer = signers.first().expect("fee payer").pubkey();
        let message =
            compile_message(&payer, instructions, Hash::default(), budget).expect("compile");
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
            let measured = transaction_size(&payer.pubkey(), instructions, budget)
                .expect("measure over limit");
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
}
