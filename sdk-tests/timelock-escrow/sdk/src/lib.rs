pub mod instructions;
pub mod prover;
pub mod shared;
pub mod state;

use solana_instruction::AccountMeta;
use solana_pubkey::Pubkey;
pub use timelock_escrow_program::{
    instructions::{
        escrow::{EscrowIxData, EscrowProof},
        withdraw::{WithdrawIxData, WithdrawProof},
    },
    tag, ESCROW_AUTHORITY_PDA_SEED,
};
use zolana_interface::{instruction::TransactIxData, pda};

/// The escrow-authority PDA the timelock escrow program signs with
/// (`invoke_signed`) to spend an escrow UTXO. It owns the escrow UTXO
/// (`PublicKey::from_ed25519(pda)`), holds no data, and is never created.
pub fn escrow_authority_pda() -> Pubkey {
    let (pda, _bump) =
        Pubkey::find_program_address(&[ESCROW_AUTHORITY_PDA_SEED], &timelock_escrow_program::ID);
    pda
}

pub(crate) fn err(e: impl core::fmt::Debug) -> anyhow::Error {
    anyhow::anyhow!("{e:?}")
}

pub(crate) fn nullifier_marker_accounts(
    tree: &Pubkey,
    transact: &TransactIxData,
) -> Vec<AccountMeta> {
    transact
        .inputs
        .iter()
        .map(|input| AccountMeta::new(pda::nullifier_marker(tree, &input.nullifier_hash).0, false))
        .collect()
}
