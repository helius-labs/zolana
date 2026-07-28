use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::{
    instruction::{
        instruction_data::deposit::{DepositAssetKind, DepositEntry, DepositIxData},
        tag,
    },
    pda,
};
use zolana_program_test::{ProgramTestError, ZolanaProgramTest};

pub use zolana_test_utils::backend::LiteSvmPoolBackend as Pool;

pub fn sol_deposit_accounts(
    rpc: &ZolanaProgramTest,
    tree: Pubkey,
    depositor: Pubkey,
) -> Vec<AccountMeta> {
    vec![
        AccountMeta::new(tree, false),
        AccountMeta::new(depositor, true),
        AccountMeta::new_readonly(Pubkey::default(), false),
        AccountMeta::new(pda::sol_interface(), false),
        AccountMeta::new_readonly(rpc.program_id, false),
    ]
}

pub fn raw_sol_deposit(
    rpc: &mut ZolanaProgramTest,
    depositor: &Keypair,
    accounts: Vec<AccountMeta>,
) -> Result<(), ProgramTestError> {
    let deposit = ZolanaProgramTest::sol_shield_data(1_000_000, [8u8; 32], [8u8; 32]);
    let ix_data = DepositIxData {
        assets: vec![DepositAssetKind::Sol],
        deposits: vec![DepositEntry {
            asset_index: 0,
            view_tag: deposit.view_tag,
            owner: deposit.owner,
            blinding: deposit.blinding,
            amount: deposit.amount,
            utxo_data: deposit.utxo_data,
            memo: deposit.memo,
        }],
    };
    let mut data = vec![tag::DEPOSIT];
    data.extend_from_slice(&ix_data.serialize().expect("serialize deposit data"));
    let ix = Instruction {
        program_id: rpc.program_id,
        accounts,
        data,
    };
    rpc.create_and_send_default_payer_transaction(&[ix], &[depositor])
        .map(|_| ())
}

/// Settlement account metas for one SOL asset group, in the program's parse
/// order (system program placeholder, then the SOL interface PDA).
pub fn sol_group_accounts() -> Vec<AccountMeta> {
    vec![
        AccountMeta::new_readonly(Pubkey::default(), false),
        AccountMeta::new(pda::sol_interface(), false),
    ]
}

/// Settlement account metas for one SPL asset group, in the program's parse
/// order (token program, mint, funding token account, vault, registry).
pub fn spl_group_accounts(mint: Pubkey, user_token: Pubkey) -> Vec<AccountMeta> {
    vec![
        AccountMeta::new_readonly(ZolanaProgramTest::token_program_id(), false),
        AccountMeta::new_readonly(mint, false),
        AccountMeta::new(user_token, false),
        AccountMeta::new(pda::spl_asset_vault(&mint), false),
        AccountMeta::new_readonly(pda::spl_asset_registry(&mint), false),
    ]
}

/// Full SPL `deposit` account metas (tree, depositor, then the SPL asset
/// group and the program itself) for hand-built deposit instructions.
pub fn spl_accounts(
    tree: Pubkey,
    depositor: Pubkey,
    user_token: Pubkey,
    mint: Pubkey,
) -> Vec<AccountMeta> {
    vec![
        AccountMeta::new(tree, false),
        AccountMeta::new(depositor, true),
        AccountMeta::new_readonly(ZolanaProgramTest::token_program_id(), false),
        AccountMeta::new_readonly(mint, false),
        AccountMeta::new(user_token, false),
        AccountMeta::new(pda::spl_asset_vault(&mint), false),
        AccountMeta::new_readonly(pda::spl_asset_registry(&mint), false),
        AccountMeta::new_readonly(zolana_interface::PROGRAM_ID_PUBKEY, false),
    ]
}

/// Send hand-built batch instruction data against a caller-supplied account
/// layout, so a test can violate an instruction-data invariant the `Deposit`
/// builder never produces.
pub fn raw_deposit_batch(
    rpc: &mut ZolanaProgramTest,
    tree: Pubkey,
    depositor: &Keypair,
    assets: Vec<DepositAssetKind>,
    deposits: Vec<DepositEntry>,
    groups: Vec<Vec<AccountMeta>>,
) -> Result<(), ProgramTestError> {
    let mut data = vec![tag::DEPOSIT];
    data.extend_from_slice(
        &DepositIxData { assets, deposits }
            .serialize()
            .expect("proofless ix data serialization is infallible"),
    );
    let mut accounts = vec![
        AccountMeta::new(tree, false),
        AccountMeta::new(depositor.pubkey(), true),
    ];
    for group in groups {
        accounts.extend(group);
    }
    accounts.push(AccountMeta::new_readonly(rpc.program_id, false));
    let ix = Instruction {
        program_id: rpc.program_id,
        accounts,
        data,
    };
    rpc.create_and_send_default_payer_transaction(&[ix], &[depositor])
        .map(|_| ())
}

pub fn register_mint(pool: &mut Pool) -> (Pubkey, Pubkey, Pubkey) {
    let mint = pool.rpc.create_mint().expect("create mint");
    pool.rpc
        .ensure_asset_counter(&pool.authority)
        .expect("create asset counter");
    let (registry, vault) = pool
        .rpc
        .create_spl_interface(&pool.authority, &mint)
        .expect("create SPL interface");
    (mint, registry, vault)
}

pub fn spl_depositor(pool: &mut Pool, mint: Pubkey, amount: u64) -> (Keypair, Pubkey) {
    let depositor = pool.funded_signer(1_000_000_000);
    let token = pool
        .rpc
        .create_token_account(&mint, &depositor.pubkey())
        .expect("create token account");
    pool.rpc
        .mint_to(&mint, &token, amount)
        .expect("mint tokens");
    (depositor, token)
}
