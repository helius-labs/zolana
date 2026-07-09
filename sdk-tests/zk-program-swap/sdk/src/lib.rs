pub mod discover;
pub mod instructions;
pub mod order;
pub mod prover;

use anyhow::{bail, Result};
pub use instructions::{
    cancel::cancel, create_swap::create_swap, fill::fill,
    fill_verifiable_encryption::fill_verifiable_encryption,
};
use solana_instruction::{AccountMeta, Instruction};
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

/// Build an order-lifecycle instruction: the signer-checked `payer`, followed
/// by the SPP `transact` accounts the program forwards to its CPI (the SPP
/// program account last). `spp_accounts` is exactly the `accounts` of the SPP
/// `Transact::instruction()`, whose payer is the same `payer`.
pub(crate) fn lifecycle_instruction(
    tag: u8,
    payer: Pubkey,
    spp_accounts: Vec<AccountMeta>,
    ix_body: Vec<u8>,
) -> Instruction {
    let mut accounts = vec![AccountMeta::new(payer, true)];
    accounts.extend(spp_accounts);
    let mut instruction_data = vec![tag];
    instruction_data.extend_from_slice(&ix_body);
    Instruction {
        program_id: program_id_pubkey(),
        accounts,
        data: instruction_data,
    }
}

pub(crate) fn check_private_tx_hash(label: &str, got: [u8; 32], expected: [u8; 32]) -> Result<()> {
    if got != expected {
        bail!("{label} private_tx_hash does not match the shared inputs");
    }
    Ok(())
}

pub(crate) fn err(e: impl core::fmt::Debug) -> anyhow::Error {
    anyhow::anyhow!("{e:?}")
}
