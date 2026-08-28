pub mod index;
pub mod instructions;
pub mod prover;
pub mod shared;
pub mod state;

use solana_pubkey::Pubkey;
pub use swap_program::{
    instructions::{
        cancel::{CancelIxData, CancelProof},
        make::{MakeIxData, MakeProof, MarkerData},
        take::{TakeIxData, TakeProof},
        take_verifiable_encryption::{
            TakeVerifiableEncryptionIxData, TakeVerifiableEncryptionProof,
        },
    },
    tag, ORDER_AUTHORITY_PDA_SEED,
};

/// The order-authority PDA the swap program signs with (`invoke_signed`) to spend
/// an order UTXO. It owns the order UTXO (`PublicKey::from_ed25519(pda)`), holds no
/// data, and is never created.
pub fn order_authority_pda() -> Pubkey {
    let (pda, _bump) = Pubkey::find_program_address(&[ORDER_AUTHORITY_PDA_SEED], &swap_program::ID);
    pda
}
pub(crate) fn err(e: impl core::fmt::Debug) -> anyhow::Error {
    anyhow::anyhow!("{e:?}")
}
