//! Client for the Squads smart-account program used by Zolana to gate protocol
//! authorities (protocol, forester, tree, ring) behind multisig vaults.
//!
//! Provides the program id, PDA derivations, and instruction builders
//! (`create_smart_account_ix`, `execute_sync_ix`) needed to create smart
//! accounts and execute an inner instruction whose CPI signer is a vault PDA.
//! The forester submits `batch_update_nullifier_tree` this way: the tree's
//! `forester_authority` is a vault, and `execute_sync_ix` has the smart-account
//! program CPI into the shielded pool with that vault as the signer.

#[cfg(test)]
use borsh::BorshDeserialize;
use borsh::BorshSerialize;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

pub mod roles;
pub mod settings;

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

#[cfg_attr(test, derive(BorshDeserialize))]
#[derive(BorshSerialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct Permissions {
    pub mask: u8,
}

impl Permissions {
    pub fn all() -> Self {
        Self { mask: 0b111 }
    }
}

#[cfg_attr(test, derive(BorshDeserialize))]
#[derive(BorshSerialize, Clone, Debug, PartialEq, Eq)]
pub struct SmartAccountSigner {
    pub key: Pubkey,
    pub permissions: Permissions,
}

#[cfg_attr(test, derive(BorshDeserialize))]
#[derive(BorshSerialize)]
struct CreateSmartAccountArgs {
    settings_authority: Option<Pubkey>,
    threshold: u16,
    signers: Vec<SmartAccountSigner>,
    time_lock: u32,
    rent_collector: Option<Pubkey>,
    memo: Option<String>,
}

#[cfg_attr(test, derive(BorshDeserialize))]
#[derive(BorshSerialize)]
struct SyncTransactionArgs {
    account_index: u8,
    num_signers: u8,
    payload: SyncPayload,
}

#[cfg_attr(test, derive(BorshDeserialize))]
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

/// Build `createSmartAccount` using Zolana's threshold policy for `role`.
pub fn create_role_smart_account_ix(
    creator: &Pubkey,
    treasury: &Pubkey,
    settings_seed: u128,
    settings_authority: Option<Pubkey>,
    signers: &[SmartAccountSigner],
    role: roles::Role,
    time_lock: u32,
) -> Instruction {
    create_smart_account_ix(
        creator,
        treasury,
        settings_seed,
        settings_authority,
        signers,
        role.threshold(),
        time_lock,
    )
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
        num_signers: signer_keys.len() as u8,
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

pub fn execute_sync_each(
    settings_key: &Pubkey,
    account_index: u8,
    signer_keys: &[Pubkey],
    inner_instructions: &[Instruction],
) -> Vec<Instruction> {
    inner_instructions
        .iter()
        .map(|inner| {
            execute_sync_ix(
                settings_key,
                account_index,
                signer_keys,
                std::slice::from_ref(inner),
            )
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Payload compilation (internal)
// ---------------------------------------------------------------------------

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
                pos as u8
            } else {
                let idx = account_metas.len();
                if is_writable {
                    account_metas.push(AccountMeta::new(*key, is_signer));
                } else {
                    account_metas.push(AccountMeta::new_readonly(*key, is_signer));
                }
                idx as u8
            }
        };

        ensure_key(vault_pda, true, false);

        for ix in instructions {
            ensure_key(&ix.program_id, false, false);
            for meta in &ix.accounts {
                ensure_key(&meta.pubkey, meta.is_writable, meta.is_signer);
            }
        }

        payload.push(instructions.len() as u8);

        for ix in instructions {
            let program_id_index = ensure_key(&ix.program_id, false, false);
            payload.push(program_id_index);

            payload.push(ix.accounts.len() as u8);
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

    #[test]
    fn role_creation_instructions_encode_the_required_thresholds() {
        let creator = Pubkey::new_unique();
        let treasury = Pubkey::new_unique();
        let signers = [
            SmartAccountSigner {
                key: Pubkey::new_unique(),
                permissions: Permissions::all(),
            },
            SmartAccountSigner {
                key: Pubkey::new_unique(),
                permissions: Permissions::all(),
            },
        ];

        for role in roles::Role::ALL {
            let settings_authority =
                (role != roles::Role::Protocol).then_some(Pubkey::new_unique());
            let ix = create_role_smart_account_ix(
                &creator,
                &treasury,
                role.seed(0),
                settings_authority,
                &signers,
                role,
                0,
            );
            let serialized_args = ix
                .data
                .get(CREATE_SMART_ACCOUNT_DISCRIMINATOR.len()..)
                .expect("create instruction contains serialized arguments");
            let args = CreateSmartAccountArgs::try_from_slice(serialized_args)
                .expect("create instruction arguments decode");
            assert_eq!(
                args.threshold,
                role.threshold(),
                "{} threshold",
                role.label()
            );
        }
    }

    #[test]
    fn sync_instruction_declares_and_places_two_signers_first() {
        let settings = Pubkey::new_unique();
        let signer_keys = [Pubkey::new_unique(), Pubkey::new_unique()];
        let inner = Instruction {
            program_id: Pubkey::new_unique(),
            accounts: vec![AccountMeta::new_readonly(Pubkey::new_unique(), false)],
            data: vec![1, 2, 3],
        };

        let ix = execute_sync_ix(&settings, 0, &signer_keys, &[inner]);
        let serialized_args = ix
            .data
            .get(EXECUTE_TX_SYNC_V2_DISCRIMINATOR.len()..)
            .expect("sync instruction contains serialized arguments");
        let args = SyncTransactionArgs::try_from_slice(serialized_args)
            .expect("sync instruction arguments decode");
        assert_eq!(args.num_signers, 2);
        let expected_signer_accounts = signer_keys.map(|key| AccountMeta::new_readonly(key, true));
        assert_eq!(
            ix.accounts.get(2..4),
            Some(expected_signer_accounts.as_slice())
        );
    }
}
