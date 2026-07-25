//! Client for the Squads smart-account program used by Zolana to gate protocol
//! authorities (protocol, forester, tree, zone) behind multisig vaults.
//!
//! Provides the program id, PDA derivations, and instruction builders
//! (`create_smart_account_ix`, `execute_sync_ix`) needed to create smart
//! accounts and execute an inner instruction whose CPI signer is a vault PDA.
//! The forester submits `batch_update_nullifier_tree` this way: the tree's
//! `forester_authority` is a vault, and `execute_sync_ix` has the smart-account
//! program CPI into the shielded pool with that vault as the signer.

use borsh::BorshSerialize;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

pub const SMART_ACCOUNT_PROGRAM_ID: Pubkey =
    solana_pubkey::pubkey!("SMRTzfY6DfH5ik3TKiyLFfXexV8uSG3d2UksSCYdunG");

const SEED_PREFIX: &[u8] = b"smart_account";
const SEED_PROGRAM_CONFIG: &[u8] = b"program_config";
const SEED_SETTINGS: &[u8] = b"settings";
const SEED_SMART_ACCOUNT: &[u8] = b"smart_account";

// Anchor discriminators: sha256("global:<fn_name>")[0..8]
const CREATE_SMART_ACCOUNT_DISCRIMINATOR: [u8; 8] = [197, 102, 253, 231, 77, 84, 50, 17];
const EXECUTE_TX_SYNC_V2_DISCRIMINATOR: [u8; 8] = [90, 81, 187, 81, 39, 70, 128, 78];

// ---------------------------------------------------------------------------
// PDA helpers
// ---------------------------------------------------------------------------

pub fn program_config_pda() -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[SEED_PREFIX, SEED_PROGRAM_CONFIG],
        &SMART_ACCOUNT_PROGRAM_ID,
    )
}

/// Deterministic treasury PDA the `ProgramConfig` references so
/// `create_smart_account` passes its treasury key check.
pub fn treasury_pda() -> Pubkey {
    let (pda, _) =
        Pubkey::find_program_address(&[SEED_PREFIX, b"treasury"], &SMART_ACCOUNT_PROGRAM_ID);
    pda
}

pub fn settings_pda(seed: u128) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[SEED_PREFIX, SEED_SETTINGS, &seed.to_le_bytes()],
        &SMART_ACCOUNT_PROGRAM_ID,
    )
}

/// The vault PDA that signs CPIs for `settings_key` at `account_index`. This is
/// the address stored on-chain as a protocol authority (e.g. `forester_authority`).
pub fn smart_account_pda(settings_key: &Pubkey, account_index: u8) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[
            SEED_PREFIX,
            settings_key.as_ref(),
            SEED_SMART_ACCOUNT,
            &[account_index],
        ],
        &SMART_ACCOUNT_PROGRAM_ID,
    )
}

// ---------------------------------------------------------------------------
// Borsh types mirroring the on-chain program
// ---------------------------------------------------------------------------

#[derive(BorshSerialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct Permissions {
    pub mask: u8,
}

impl Permissions {
    pub fn all() -> Self {
        Self { mask: 0b111 }
    }
}

#[derive(BorshSerialize, Clone, Debug, PartialEq, Eq)]
pub struct SmartAccountSigner {
    pub key: Pubkey,
    pub permissions: Permissions,
}

#[derive(BorshSerialize)]
struct CreateSmartAccountArgs {
    settings_authority: Option<Pubkey>,
    threshold: u16,
    signers: Vec<SmartAccountSigner>,
    time_lock: u32,
    rent_collector: Option<Pubkey>,
    memo: Option<String>,
}

#[derive(BorshSerialize)]
struct SyncTransactionArgs {
    account_index: u8,
    num_signers: u8,
    payload: SyncPayload,
}

#[derive(BorshSerialize)]
enum SyncPayload {
    Transaction(Vec<u8>),
}

// ---------------------------------------------------------------------------
// Instruction builders
// ---------------------------------------------------------------------------

/// Build the `createSmartAccount` instruction.
///
/// Pass `settings_authority: Some(pubkey)` for a controlled account whose key
/// management bypasses the threshold vote; `None` for an autonomous account.
pub fn create_smart_account_ix(
    creator: &Pubkey,
    treasury: &Pubkey,
    settings_seed: u128,
    settings_authority: Option<Pubkey>,
    signers: &[SmartAccountSigner],
    threshold: u16,
    time_lock: u32,
) -> Instruction {
    let (pc_pda, _) = program_config_pda();
    let (settings_key, _) = settings_pda(settings_seed);

    let args = CreateSmartAccountArgs {
        settings_authority,
        threshold,
        signers: signers.to_vec(),
        time_lock,
        rent_collector: None,
        memo: None,
    };

    let mut data = Vec::with_capacity(256);
    data.extend_from_slice(&CREATE_SMART_ACCOUNT_DISCRIMINATOR);
    args.serialize(&mut data)
        .expect("serialize CreateSmartAccountArgs");

    Instruction {
        program_id: SMART_ACCOUNT_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(pc_pda, false),
            AccountMeta::new(*treasury, false),
            AccountMeta::new(*creator, true),
            AccountMeta::new_readonly(Pubkey::default(), false),
            AccountMeta::new_readonly(SMART_ACCOUNT_PROGRAM_ID, false),
            AccountMeta::new(settings_key, false),
        ],
        data,
    }
}

/// Build the `executeTransactionSyncV2` instruction.
///
/// Wraps `inner_instructions` via CPI; the vault PDA signs as the CPI signer.
/// `signer_keys` are the threshold signers on the outer transaction.
pub fn execute_sync_ix(
    settings_key: &Pubkey,
    account_index: u8,
    signer_keys: &[Pubkey],
    inner_instructions: &[Instruction],
) -> Instruction {
    let (vault_pda, _) = smart_account_pda(settings_key, account_index);

    let (payload_bytes, cpi_account_metas) =
        compile_instructions_to_payload(inner_instructions, &vault_pda);

    let args = SyncTransactionArgs {
        account_index,
        num_signers: checked_u8(signer_keys.len(), "signer count"),
        payload: SyncPayload::Transaction(payload_bytes),
    };

    let mut data = Vec::with_capacity(512);
    data.extend_from_slice(&EXECUTE_TX_SYNC_V2_DISCRIMINATOR);
    args.serialize(&mut data)
        .expect("serialize SyncTransactionArgs");

    let mut accounts = vec![
        AccountMeta::new(*settings_key, false),
        AccountMeta::new_readonly(SMART_ACCOUNT_PROGRAM_ID, false),
    ];
    for key in signer_keys {
        accounts.push(AccountMeta::new_readonly(*key, true));
    }
    accounts.extend(cpi_account_metas);

    Instruction {
        program_id: SMART_ACCOUNT_PROGRAM_ID,
        accounts,
        data,
    }
}

// ---------------------------------------------------------------------------
// Payload compilation (internal)
// ---------------------------------------------------------------------------

/// Narrow a count or index into the single byte the payload encodes it as.
///
/// Truncating instead would compile a payload that reads correctly and names a
/// different account than the caller passed, so the wrap is refused. These
/// builders are infallible by signature and already panic on a failed
/// serialize, so the refusal takes the same form.
fn checked_u8(value: usize, what: &str) -> u8 {
    u8::try_from(value).unwrap_or_else(|_| panic!("{what} exceeds u8: {value}"))
}

fn compile_instructions_to_payload(
    instructions: &[Instruction],
    vault_pda: &Pubkey,
) -> (Vec<u8>, Vec<AccountMeta>) {
    let mut account_metas: Vec<AccountMeta> = Vec::new();
    let mut payload = Vec::new();

    {
        let mut ensure_key = |key: &Pubkey, is_writable: bool, is_signer: bool| -> u8 {
            if let Some((pos, meta)) = account_metas
                .iter_mut()
                .enumerate()
                .find(|(_, meta)| meta.pubkey == *key)
            {
                if is_writable && !meta.is_writable {
                    *meta = AccountMeta::new(meta.pubkey, meta.is_signer || is_signer);
                } else if is_signer && !meta.is_signer {
                    meta.is_signer = true;
                }
                checked_u8(pos, "compiled account count")
            } else {
                let idx = account_metas.len();
                if is_writable {
                    account_metas.push(AccountMeta::new(*key, is_signer));
                } else {
                    account_metas.push(AccountMeta::new_readonly(*key, is_signer));
                }
                checked_u8(idx, "compiled account count")
            }
        };

        ensure_key(vault_pda, true, false);

        for ix in instructions {
            ensure_key(&ix.program_id, false, false);
            for meta in &ix.accounts {
                ensure_key(&meta.pubkey, meta.is_writable, meta.is_signer);
            }
        }

        payload.push(checked_u8(instructions.len(), "inner instruction count"));

        for ix in instructions {
            let program_id_index = ensure_key(&ix.program_id, false, false);
            payload.push(program_id_index);

            payload.push(checked_u8(
                ix.accounts.len(),
                "inner instruction account count",
            ));
            for meta in &ix.accounts {
                let idx = ensure_key(&meta.pubkey, meta.is_writable, meta.is_signer);
                payload.push(idx);
            }

            let data_len = ix.data.len() as u16;
            payload.extend_from_slice(&data_len.to_le_bytes());
            payload.extend_from_slice(&ix.data);
        }
    }

    for meta in &mut account_metas {
        if meta.pubkey == *vault_pda {
            meta.is_signer = false;
        }
    }

    (payload, account_metas)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inner_with(accounts: Vec<Pubkey>) -> Instruction {
        Instruction {
            program_id: Pubkey::new_unique(),
            accounts: accounts
                .into_iter()
                .map(|key| AccountMeta::new_readonly(key, false))
                .collect(),
            data: Vec::new(),
        }
    }

    /// The payload names accounts by u8 index, so 256 is the full range and the
    /// 257th is the first that cannot be encoded. The TypeScript port pins the
    /// same two boundaries in `smart-account-client/test/boundaries.test.ts`.
    #[test]
    fn compiles_the_full_u8_index_range() {
        let vault = Pubkey::new_unique();
        // Plus the vault and the inner program id, which are compiled first.
        let keys: Vec<Pubkey> = (0..254).map(|_| Pubkey::new_unique()).collect();
        let (payload, metas) = compile_instructions_to_payload(&[inner_with(keys)], &vault);

        assert_eq!(metas.len(), 256);
        // The index run ends just before the u16 data length, and its last
        // entry must be 255 rather than a wrap to zero.
        assert_eq!(payload[payload.len() - 3], 255);
    }

    #[test]
    #[should_panic(expected = "compiled account count exceeds u8")]
    fn refuses_an_account_index_past_u8() {
        let vault = Pubkey::new_unique();
        let keys: Vec<Pubkey> = (0..255).map(|_| Pubkey::new_unique()).collect();
        compile_instructions_to_payload(&[inner_with(keys)], &vault);
    }
}
