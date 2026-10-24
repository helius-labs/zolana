use solana_address::Address;
use solana_hash::Hash;
use solana_instruction::Instruction;
use solana_message::{v1, VersionedMessage};
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;

use crate::Error;

use crate::ComputeBudgetConfig;

/// Compile `instructions` into an unsigned v1 message.
///
/// v1 takes no compute-budget instructions, which is where the ceilings in
/// `compute_budget` would otherwise go, and it has no address lookup tables.
pub fn compile_message(
    payer: &Address,
    instructions: &[Instruction],
    recent_blockhash: Hash,
    compute_budget: ComputeBudgetConfig,
) -> Result<VersionedMessage, Error> {
    v1::Message::try_compile_with_config(
        payer,
        instructions,
        recent_blockhash,
        compute_budget.transaction_config(),
    )
    .map(VersionedMessage::V1)
    .map_err(|error| Error::Compile(error.to_string()))
}

pub(crate) fn ensure_version_1(message: &VersionedMessage) -> Result<(), Error> {
    match message {
        VersionedMessage::V1(_) => Ok(()),
        VersionedMessage::Legacy(_) | VersionedMessage::V0(_) => Err(Error::UnsupportedVersion),
    }
}

/// Sign a compiled message, passing each signer once.
///
/// `VersionedTransaction::try_new` refuses a signer list longer than the
/// message's required signatures, where legacy partial signing tolerated a
/// repeat. A fee payer that also owns a shielded input is one account key but
/// two entries in the caller's list (payer and owner signer), so the
/// duplicates are dropped here rather than at every call site.
pub fn sign_transaction(
    message: VersionedMessage,
    signers: &[&dyn Signer],
) -> Result<VersionedTransaction, Error> {
    ensure_version_1(&message)?;
    let mut unique: Vec<(Address, &dyn Signer)> = Vec::with_capacity(signers.len());
    for signer in signers {
        let pubkey = signer
            .try_pubkey()
            .map_err(|error| Error::Signing(error.to_string()))?;
        if unique.iter().any(|(kept, _)| *kept == pubkey) {
            continue;
        }
        unique.push((pubkey, *signer));
    }
    let unique = unique
        .into_iter()
        .map(|(_, signer)| signer)
        .collect::<Vec<_>>();
    VersionedTransaction::try_new(message, &unique)
        .map_err(|error| Error::Signing(error.to_string()))
}
