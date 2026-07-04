use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::pda;

/// Build an idempotent SPL Associated Token Account creation instruction for
/// `(owner, mint)`, funded by `payer`.
///
/// Unlike the sibling builders in this module (which target the shielded-pool
/// program via `PROGRAM_ID_PUBKEY`), this targets the SPL Associated Token
/// Account program via `pda::associated_token_program_id()`. It emits the
/// `CreateIdempotent` variant (data byte `1`), so it is a no-op when the ATA
/// already exists and callers need no prior existence check.
pub struct CreateAssociatedTokenAccount {
    pub payer: Pubkey,
    pub owner: Pubkey,
    pub mint: Pubkey,
}

impl CreateAssociatedTokenAccount {
    /// The canonical associated token account this instruction creates.
    pub fn address(&self) -> Pubkey {
        pda::associated_token_address(&self.owner, &self.mint)
    }

    pub fn instruction(&self) -> Instruction {
        let ata = self.address();
        Instruction {
            program_id: pda::associated_token_program_id(),
            accounts: vec![
                AccountMeta::new(self.payer, true),
                AccountMeta::new(ata, false),
                AccountMeta::new_readonly(self.owner, false),
                AccountMeta::new_readonly(self.mint, false),
                // System program id is all-zeros, matching `Pubkey::default()`.
                AccountMeta::new_readonly(Pubkey::default(), false),
                AccountMeta::new_readonly(pda::spl_token_program_id(), false),
            ],
            // `1` selects SPL ATA `CreateIdempotent`; an empty payload is the
            // non-idempotent `Create`.
            data: vec![1u8],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_idempotent_create_ata_instruction() {
        let payer = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let builder = CreateAssociatedTokenAccount { payer, owner, mint };
        let ata = pda::associated_token_address(&owner, &mint);
        let ix = builder.instruction();

        assert_eq!(ix.program_id, pda::associated_token_program_id());
        assert_eq!(ix.data, vec![1u8]);
        assert_eq!(builder.address(), ata);

        assert_eq!(ix.accounts.len(), 6);
        // payer: signer + writable.
        assert_eq!(ix.accounts[0].pubkey, payer);
        assert!(ix.accounts[0].is_signer);
        assert!(ix.accounts[0].is_writable);
        // ata: writable, not a signer.
        assert_eq!(ix.accounts[1].pubkey, ata);
        assert!(!ix.accounts[1].is_signer);
        assert!(ix.accounts[1].is_writable);
        // owner, mint, system program, token program: readonly, not signers.
        assert_eq!(ix.accounts[2].pubkey, owner);
        assert_eq!(ix.accounts[3].pubkey, mint);
        assert_eq!(ix.accounts[4].pubkey, Pubkey::default());
        assert_eq!(ix.accounts[5].pubkey, pda::spl_token_program_id());
        for meta in &ix.accounts[2..] {
            assert!(!meta.is_signer);
            assert!(!meta.is_writable);
        }
    }
}
