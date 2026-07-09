pub mod discover;
pub mod instructions;
pub mod order;
pub mod prover;

use solana_instruction::AccountMeta;
use solana_pubkey::Pubkey;
pub use swap_program::{
    instructions::{
        cancel::CancelProof,
        create_swap::{CreateProof, MarkerData},
        fill::FillProof,
        fill_verifiable_encryption::FillVerifiableEncryptionProof,
    },
    tag, ESCROW_AUTHORITY_PDA_SEED, SWAP_PROGRAM_ID,
};
use zolana_interface::SHIELDED_POOL_PROGRAM_ID;

pub(crate) fn program_id_pubkey() -> Pubkey {
    Pubkey::new_from_array(*SWAP_PROGRAM_ID.as_array())
}

/// The escrow-authority PDA the swap program signs with (`invoke_signed`) to spend
/// an escrow. It owns the escrow UTXO (`PublicKey::from_ed25519(pda)`), holds no
/// data, and is never created.
pub fn escrow_authority_pda() -> Pubkey {
    let (pda, _bump) =
        Pubkey::find_program_address(&[ESCROW_AUTHORITY_PDA_SEED], &program_id_pubkey());
    pda
}

pub(crate) fn spp_program_meta() -> AccountMeta {
    AccountMeta::new_readonly(Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID), false)
}

pub(crate) fn err(e: impl core::fmt::Debug) -> anyhow::Error {
    anyhow::anyhow!("{e:?}")
}
