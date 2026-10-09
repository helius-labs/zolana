use anyhow::{anyhow, Result};
use sha2::{Digest, Sha256};
use solana_account::Account;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use zolana_client::{Rpc, SolanaRpc};
use zolana_interface::pda::spl_token_program_id;

use k_lend_rfq_sdk::pair::{Pair, PROGRAM_ID};

pub const KLEND_PROGRAM_ID: Address =
    Address::from_str_const("KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYavgmjD");
pub const VAULT_STATE_SIZE: usize = 8 + 62544;
const SYSTEM_PROGRAM_ID: Address = Address::new_from_array([0; 32]);
const SYSVAR_RENT_ID: Address =
    Address::from_str_const("SysvarRent111111111111111111111111111111111");
const GLOBAL_CONFIG_SIZE: usize = 8 + 1024;
const TOKEN_ACCOUNT_AMOUNT_OFFSET: usize = 64;

fn discriminator(preimage: &str) -> [u8; 8] {
    let hash = Sha256::digest(preimage.as_bytes());
    let mut out = [0u8; 8];
    out.copy_from_slice(hash.get(..8).unwrap_or_default());
    out
}

pub fn global_config() -> Address {
    Address::find_program_address(&[b"global_config"], &PROGRAM_ID).0
}

pub fn global_config_account(admin: &Address) -> Account {
    let mut data = vec![0u8; GLOBAL_CONFIG_SIZE];
    for (range, bytes) in [
        (0..8, discriminator("account:GlobalConfig").as_slice()),
        (8..40, admin.as_ref()),
        (40..72, admin.as_ref()),
    ] {
        if let Some(slot) = data.get_mut(range) {
            slot.copy_from_slice(bytes);
        }
    }
    Account {
        lamports: 1_000_000_000,
        data,
        owner: PROGRAM_ID,
        executable: false,
        rent_epoch: 0,
    }
}

pub struct InitVault {
    pub admin: Address,
    pub admin_token_account: Address,
    pub pair: Pair,
}

impl InitVault {
    pub fn instruction(&self) -> Instruction {
        let token_program = spl_token_program_id();
        Instruction {
            program_id: PROGRAM_ID,
            accounts: vec![
                AccountMeta::new(self.admin, true),
                AccountMeta::new(self.pair.vault, true),
                AccountMeta::new_readonly(self.pair.authority, false),
                AccountMeta::new(self.pair.token_vault, false),
                AccountMeta::new_readonly(self.pair.token_mint, false),
                AccountMeta::new(self.pair.shares_mint, false),
                AccountMeta::new(self.admin_token_account, false),
                AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
                AccountMeta::new_readonly(SYSVAR_RENT_ID, false),
                AccountMeta::new_readonly(token_program, false),
                AccountMeta::new_readonly(token_program, false),
            ],
            data: discriminator("global:init_vault").to_vec(),
        }
    }
}

pub fn token_balance(rpc: &SolanaRpc, account: &Address) -> Result<u64> {
    let data = rpc
        .get_account(*account)?
        .ok_or_else(|| anyhow!("account {account} missing"))?
        .data;
    let bytes = data
        .get(TOKEN_ACCOUNT_AMOUNT_OFFSET..TOKEN_ACCOUNT_AMOUNT_OFFSET + 8)
        .ok_or_else(|| anyhow!("token account {account} too short"))?;
    Ok(u64::from_le_bytes(bytes.try_into()?))
}
