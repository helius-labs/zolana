use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::{instruction::tag, pda};
use zolana_program_test::{ProgramTestError, ZolanaProgramTest};

use crate::common::{program_test, tree_account_size};

pub struct Pool {
    pub rpc: ZolanaProgramTest,
    pub authority: Keypair,
    pub tree: Keypair,
}

impl Pool {
    pub fn initialized() -> Self {
        let mut rpc = program_test();
        let authority = Keypair::new();
        rpc.create_protocol_config(&authority)
            .expect("create protocol config");
        let tree = rpc
            .create_tree(tree_account_size(), &authority)
            .expect("create pool tree");
        Self {
            rpc,
            authority,
            tree,
        }
    }

    pub fn funded_signer(&mut self, lamports: u64) -> Keypair {
        let signer = Keypair::new();
        self.rpc
            .airdrop(&signer.pubkey(), lamports)
            .expect("fund signer");
        signer
    }
}

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
        AccountMeta::new(depositor, false),
        AccountMeta::new_readonly(rpc.program_id, false),
    ]
}

pub fn raw_sol_deposit(
    rpc: &mut ZolanaProgramTest,
    depositor: &Keypair,
    accounts: Vec<AccountMeta>,
) -> Result<(), ProgramTestError> {
    let mut data = vec![tag::DEPOSIT];
    data.extend_from_slice(
        &ZolanaProgramTest::sol_shield_data(1_000_000, [8u8; 32], [8u8; 31])
            .serialize()
            .expect("serialize deposit data"),
    );
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
