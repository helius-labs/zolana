//! Builder for the Squads ring `deposit` (tag 1) instruction on both rails.
//!
//! The instruction is proofless: the depositor signs and funds the transfer, the
//! recipient `owner` is derived on-chain from the recipient viewing key account,
//! and the asset is inferred by SPP from the forwarded settlement accounts.

use rand::RngCore;
use solana_instruction::Instruction;
use solana_pubkey::Pubkey;
use zolana_interface::{
    instruction::{DepositAssetKind, EncryptedRingDepositData},
    pda, SHIELDED_POOL_PROGRAM_ID, SPL_TOKEN_PROGRAM_ID,
};
use zolana_squads_interface::instruction::{
    builders::{Deposit, DepositSettlement},
    DepositIxData,
};

/// A fresh 31-byte blinding, sent in the clear per deposit.
pub(crate) fn random_blinding() -> [u8; 32] {
    let mut blinding = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut blinding[1..]);
    blinding
}

/// The rail-agnostic inputs to a ring deposit.
pub(crate) struct RingDeposit {
    pub(crate) asset: DepositAssetKind,
    pub(crate) depositor: Pubkey,
    pub(crate) recipient_vka: Pubkey,
    pub(crate) ring_auth: Pubkey,
    pub(crate) tree: Pubkey,
    pub(crate) view_tag: [u8; 32],
    pub(crate) blinding: [u8; 32],
    pub(crate) amount: u64,
}

impl RingDeposit {
    fn data(&self) -> DepositIxData {
        DepositIxData {
            view_tag: self.view_tag,
            asset: self.asset,
            amount: self.amount,
            blinding: self.blinding,
            // SPP and the ring both treat this as opaque. The suite asserts the
            // settled state directly rather than by decrypting.
            encrypted: EncryptedRingDepositData {
                tx_viewing_pk: [0u8; 33],
                salt: [0u8; 16],
                ciphertext: Vec::new(),
            },
        }
    }

    fn build(&self, settlement: DepositSettlement) -> Instruction {
        Deposit {
            depositor: self.depositor,
            recipient_viewing_key_account: self.recipient_vka,
            ring_auth: self.ring_auth,
            spp_program: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
            tree: self.tree,
            settlement,
            data: self.data(),
        }
        .instruction()
    }

    /// Build a SOL-rail deposit. Returns the instruction and the canonical SOL
    /// interface PDA the funds settle into. `depositor` signs and funds.
    pub(crate) fn sol_ix(&self) -> (Instruction, Pubkey) {
        let sol_interface = pda::sol_interface();
        let ix = self.build(DepositSettlement::Sol { sol_interface });
        (ix, sol_interface)
    }

    /// Build an SPL-rail deposit. Returns the instruction and the per-mint vault
    /// PDA the tokens settle into. `depositor` owns `user_token` and signs.
    pub(crate) fn spl_ix(&self, mint: Pubkey, user_token: Pubkey) -> (Instruction, Pubkey) {
        let vault = pda::spl_interface(&mint);
        let ix = self.build(DepositSettlement::Spl {
            user_token,
            vault,
            registry: pda::spl_asset_registry(&mint),
            token_program: Pubkey::new_from_array(SPL_TOKEN_PROGRAM_ID),
        });
        (ix, vault)
    }
}
