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

use crate::error::ClientError;

/// The one-byte version prefix a v1 transaction carries ahead of its message.
const V1_VERSION_PREFIX_LEN: usize = 1;
pub const SIGNATURE_LEN: usize = 64;

/// What a compiled transaction costs against each v1 ceiling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct V1TransactionSize {
    pub bytes: usize,
    pub addresses: usize,
}

impl V1TransactionSize {
    /// Whether the transaction clears both ceilings. Neither alone is enough.
    pub fn fits(&self) -> bool {
        self.bytes <= v1::MAX_TRANSACTION_SIZE && self.addresses <= usize::from(v1::MAX_ADDRESSES)
    }
}

/// Measure `instructions` as the v1 transaction they would be sent as.
///
/// `signatures` is the number the transaction will carry, which the caller
/// knows and the unsigned message does not: the signatures are the difference
/// between a compiled message and the bytes that go on the wire.
pub fn v1_transaction_size(
    payer: &Address,
    instructions: &[Instruction],
    signatures: usize,
) -> Result<V1TransactionSize, ClientError> {
    let message = v1::Message::try_compile(payer, instructions, Hash::default())
        .map_err(|error| ClientError::TransactionCompile(error.to_string()))?;
    let bytes = signatures
        .checked_mul(SIGNATURE_LEN)
        .and_then(|signatures| signatures.checked_add(V1_VERSION_PREFIX_LEN))
        .and_then(|overhead| overhead.checked_add(message.size()))
        .ok_or_else(|| ClientError::TransactionCompile("transaction size overflow".to_owned()))?;
    Ok(V1TransactionSize {
        bytes,
        addresses: message.account_keys.len(),
    })
}

#[cfg(test)]
mod tests {
    use solana_instruction::AccountMeta;
    use solana_pubkey::Pubkey;

    use super::*;

    fn instruction_touching(accounts: usize) -> Instruction {
        Instruction::new_with_bytes(
            Pubkey::new_unique(),
            &[],
            (0..accounts)
                .map(|_| AccountMeta::new(Pubkey::new_unique(), false))
                .collect(),
        )
    }

    /// The wire bytes are the message plus the version prefix plus one
    /// signature each, and it is the signatures the compiled message cannot
    /// tell you about -- getting that wrong under-reports by 64 bytes a time,
    /// which is exactly the margin a wide shape runs on.
    #[test]
    fn the_wire_size_counts_the_prefix_and_every_signature() {
        let payer = Pubkey::new_unique();
        let instruction = instruction_touching(3);
        let message =
            v1::Message::try_compile(&payer, core::slice::from_ref(&instruction), Hash::default())
                .expect("compile");

        for signatures in [1, 2, 5] {
            let measured =
                v1_transaction_size(&payer, core::slice::from_ref(&instruction), signatures)
                    .expect("measure");
            assert_eq!(
                measured.bytes,
                V1_VERSION_PREFIX_LEN + message.size() + signatures * SIGNATURE_LEN
            );
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
        let at_cap =
            v1_transaction_size(&payer, core::slice::from_ref(&instruction_touching(62)), 1)
                .expect("measure");
        assert_eq!(at_cap.addresses, usize::from(v1::MAX_ADDRESSES));
        assert!(at_cap.bytes <= v1::MAX_TRANSACTION_SIZE);
        assert!(at_cap.fits());

        // One more account, still only a couple of kilobytes, and it cannot be
        // sent at all.
        let over_cap =
            v1_transaction_size(&payer, core::slice::from_ref(&instruction_touching(63)), 1)
                .expect("measure");
        assert_eq!(over_cap.addresses, usize::from(v1::MAX_ADDRESSES) + 1);
        assert!(
            over_cap.bytes <= v1::MAX_TRANSACTION_SIZE,
            "this case is only interesting while the byte ceiling is not the one binding"
        );
        assert!(!over_cap.fits());
    }
}
