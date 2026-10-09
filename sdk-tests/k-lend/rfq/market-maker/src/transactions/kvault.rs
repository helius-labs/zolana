use sha2::{Digest, Sha256};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use zolana_client::AsyncRpc;
use zolana_interface::pda::spl_token_program_id;

use k_lend_rfq_sdk::pair::{Pair, VaultState, PROGRAM_ID};

use crate::error::MakerError;

const KLEND_PROGRAM_ID: Address =
    Address::from_str_const("KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYavgmjD");

fn discriminator(preimage: &str) -> [u8; 8] {
    let hash = Sha256::digest(preimage.as_bytes());
    let mut out = [0u8; 8];
    out.copy_from_slice(hash.get(..8).unwrap_or_default());
    out
}

fn pda(seeds: &[&[u8]]) -> Address {
    Address::find_program_address(seeds, &PROGRAM_ID).0
}

fn event_authority() -> Address {
    pda(&[b"__event_authority"])
}

fn global_config() -> Address {
    pda(&[b"global_config"])
}

pub struct UserAccounts {
    pub user: Address,
    pub token_account: Address,
    pub shares_account: Address,
}

pub struct Deposit<'a> {
    pub pair: &'a Pair,
    pub user: &'a UserAccounts,
    pub max_amount: u64,
}

impl Deposit<'_> {
    pub fn instruction(&self) -> Instruction {
        let token_program = spl_token_program_id();
        let mut data = discriminator("global:deposit").to_vec();
        data.extend_from_slice(&self.max_amount.to_le_bytes());
        Instruction {
            program_id: PROGRAM_ID,
            accounts: vec![
                AccountMeta::new(self.user.user, true),
                AccountMeta::new(self.pair.vault, false),
                AccountMeta::new(self.pair.token_vault, false),
                AccountMeta::new_readonly(self.pair.token_mint, false),
                AccountMeta::new_readonly(self.pair.authority, false),
                AccountMeta::new(self.pair.shares_mint, false),
                AccountMeta::new(self.user.token_account, false),
                AccountMeta::new(self.user.shares_account, false),
                AccountMeta::new_readonly(KLEND_PROGRAM_ID, false),
                AccountMeta::new_readonly(token_program, false),
                AccountMeta::new_readonly(token_program, false),
                AccountMeta::new_readonly(event_authority(), false),
                AccountMeta::new_readonly(PROGRAM_ID, false),
            ],
            data,
        }
    }
}

pub struct WithdrawFromAvailable<'a> {
    pub pair: &'a Pair,
    pub user: &'a UserAccounts,
    pub shares: u64,
}

impl WithdrawFromAvailable<'_> {
    pub fn instruction(&self) -> Instruction {
        let token_program = spl_token_program_id();
        let mut data = discriminator("global:withdraw_from_available").to_vec();
        data.extend_from_slice(&self.shares.to_le_bytes());
        Instruction {
            program_id: PROGRAM_ID,
            accounts: vec![
                AccountMeta::new_readonly(self.user.user, true),
                AccountMeta::new(self.pair.vault, false),
                AccountMeta::new_readonly(global_config(), false),
                AccountMeta::new(self.pair.token_vault, false),
                AccountMeta::new_readonly(self.pair.authority, false),
                AccountMeta::new(self.user.token_account, false),
                AccountMeta::new(self.pair.token_mint, false),
                AccountMeta::new(self.user.shares_account, false),
                AccountMeta::new(self.pair.shares_mint, false),
                AccountMeta::new_readonly(token_program, false),
                AccountMeta::new_readonly(token_program, false),
                AccountMeta::new_readonly(KLEND_PROGRAM_ID, false),
                AccountMeta::new_readonly(event_authority(), false),
                AccountMeta::new_readonly(PROGRAM_ID, false),
            ],
            data,
        }
    }
}

pub async fn read_vault(rpc: &dyn AsyncRpc, vault: Address) -> Result<VaultState, MakerError> {
    let account = rpc
        .get_account(vault)
        .await
        .map_err(MakerError::Rpc)?
        .ok_or(MakerError::VaultMissing { vault })?;
    VaultState::from_data(&account.data).map_err(|error| MakerError::VaultState {
        vault,
        reason: error.to_string(),
    })
}
