use anyhow::{anyhow, Result};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{ComputeBudgetConfig, Rpc, SolanaRpc};
use zolana_interface::{
    pda::{self, spl_token_program_id},
    state::SplAssetRegistry,
};
use zolana_keypair::{ShieldedKeypair, SigningKey};
use zolana_program::instruction::CreateSplInterface;
use zolana_program_test::{
    fixture,
    instructions::system_create_account_ix,
    localnet::{FixtureLocalnet, LocalnetPaths, LocalnetPorts},
    workspace_path,
};
use zolana_test_utils::wallet::{
    create_associated_token_account, sync_wallet, Deposit, DepositParams, Wallet,
};
use zolana_transaction::AssetRegistry;

use crate::{
    kvault::{self, InitVault, VaultAccounts},
    market_maker::MarketMaker,
};

pub const FEE_BPS: u64 = 30;
pub const USER_SHIELD_USDC: u64 = 100_000_000;
pub const MARKET_MAKER_PUBLIC_USDC: u64 = 500_000_000;
const COMPUTE_UNIT_LIMIT: u32 = 1_400_000;

pub struct TestEnv {
    pub localnet: FixtureLocalnet,
    pub user: TestWallet,
    pub market_maker: MarketMaker,
    pub usdc_mint: Address,
    pub vault: VaultAccounts,
}

pub struct TestWallet {
    pub wallet: Wallet,
    pub keypair: ShieldedKeypair,
}

impl std::ops::Deref for TestWallet {
    type Target = Wallet;
    fn deref(&self) -> &Self::Target {
        &self.wallet
    }
}

impl std::ops::DerefMut for TestWallet {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.wallet
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Holdings {
    pub usdc: u64,
    pub shares: u64,
}

impl TestWallet {
    fn new(actor: u8, assets: &AssetRegistry) -> Result<Self> {
        let solana = fixture::actor(actor);
        let seed: [u8; 32] = solana
            .to_bytes()
            .get(..32)
            .ok_or_else(|| anyhow!("ed25519 keypair without a seed"))?
            .try_into()?;
        let keypair = ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&seed))?;
        let wallet = Wallet::new(keypair.shielded_address()?, assets.clone())
            .map_err(|e| anyhow!("wallet of actor {actor}: {e:?}"))?;
        Ok(Self { wallet, keypair })
    }

    pub fn address(&self) -> Address {
        self.keypair.pubkey()
    }

    pub fn sync(&mut self, localnet: &FixtureLocalnet) -> Result<()> {
        sync_wallet(&mut self.wallet, &self.keypair, localnet.client.indexer())
            .map_err(|e| anyhow!("sync wallet {}: {e:?}", self.keypair.pubkey()))?;
        Ok(())
    }

    pub fn holdings(&self, vault: &VaultAccounts) -> Result<Holdings> {
        Ok(Holdings {
            usdc: self.balance(vault.token_mint, None)?.amount,
            shares: self.balance(vault.shares_mint, None)?.amount,
        })
    }

    pub fn shield(
        &mut self,
        localnet: &FixtureLocalnet,
        mint: Address,
        amount: u64,
    ) -> Result<Signature> {
        let token_account = pda::associated_token_address(&self.address(), &mint);
        let signature = Deposit::new(DepositParams {
            recipient: &self.keypair.shielded_address()?,
            asset: mint,
            amount,
            spl_token_account: Some(token_account),
            spl_token_program: Some(spl_token_program_id()),
            memo: None,
        })?
        .send(
            localnet.client.rpc(),
            &self.keypair,
            localnet.tree,
            &self.keypair,
        )?;
        localnet
            .client
            .confirm_private_transaction_sync(signature)
            .map_err(|e| anyhow!("index shield of {amount} {mint}: {e:?}"))?;
        self.sync(localnet)?;
        Ok(signature)
    }
}

pub fn send(
    rpc: &SolanaRpc,
    instructions: &[Instruction],
    payer: &dyn Signer,
    signers: &[&dyn Signer],
) -> Result<Signature> {
    Ok(rpc.create_and_send_transaction(
        instructions,
        payer.pubkey(),
        signers,
        ComputeBudgetConfig::new(COMPUTE_UNIT_LIMIT),
    )?)
}

pub fn compute_units(rpc: &SolanaRpc, signature: &Signature) -> Result<u64> {
    let confirmed = rpc.fetch_confirmed_transaction(signature)?;
    let meta = confirmed
        .transaction
        .meta
        .ok_or_else(|| anyhow!("transaction {signature} has no metadata"))?;
    Option::<u64>::from(meta.compute_units_consumed)
        .ok_or_else(|| anyhow!("transaction {signature} reports no compute units"))
}

fn token_transfer_ix(
    source: &Address,
    destination: &Address,
    authority: &Address,
    amount: u64,
) -> Instruction {
    let mut data = vec![3u8];
    data.extend_from_slice(&amount.to_le_bytes());
    Instruction {
        program_id: spl_token_program_id(),
        accounts: vec![
            AccountMeta::new(*source, false),
            AccountMeta::new(*destination, false),
            AccountMeta::new_readonly(*authority, true),
        ],
        data,
    }
}

fn create_vault(
    localnet: &FixtureLocalnet,
    payer: &Keypair,
    usdc_mint: Address,
) -> Result<VaultAccounts> {
    let rpc = localnet.client.rpc();
    let vault_keypair = Keypair::new();
    let vault = VaultAccounts::new(vault_keypair.pubkey(), usdc_mint);
    let rent = rpc.get_minimum_balance_for_rent_exemption(kvault::VAULT_STATE_SIZE)?;
    let create = system_create_account_ix(
        &payer.pubkey(),
        &vault.vault,
        rent,
        kvault::VAULT_STATE_SIZE as u64,
        &kvault::PROGRAM_ID,
    );
    let init = InitVault {
        admin: payer.pubkey(),
        admin_token_account: fixture::payer_token_account(),
        accounts: vault,
    }
    .instruction();
    send(rpc, &[create, init], payer, &[payer, &vault_keypair])?;
    Ok(vault)
}

fn register_share_mint(
    localnet: &FixtureLocalnet,
    payer: &Keypair,
    share_mint: Address,
) -> Result<u64> {
    let rpc = localnet.client.rpc();
    let ix = CreateSplInterface {
        authority: payer.pubkey(),
        mint: share_mint,
        token_program: spl_token_program_id(),
    }
    .instruction();
    send(rpc, &[ix], payer, &[payer])?;
    let registry = pda::spl_asset_registry(&share_mint);
    let data = rpc
        .get_account(registry)?
        .ok_or_else(|| anyhow!("share mint registry {registry} missing"))?
        .data;
    Ok(SplAssetRegistry::from_account_bytes(&data)
        .map_err(|e| anyhow!("share mint registry {registry}: {e:?}"))?
        .asset_id)
}

pub fn setup(test: u16) -> Result<TestEnv> {
    let payer = fixture::payer();
    let localnet = FixtureLocalnet::start_with_accounts(
        "zolana-kamino-vault",
        LocalnetPorts::for_test(test)?,
        vec![
            (
                kvault::PROGRAM_ID,
                workspace_path("target/deploy/kamino_vault.so"),
            ),
            (
                kvault::KLEND_PROGRAM_ID,
                workspace_path("target/deploy/kamino_lending.so"),
            ),
        ],
        vec![(
            kvault::global_config(),
            kvault::global_config_account(&payer.pubkey()),
        )],
        &LocalnetPaths::workspace(),
    )?;
    let rpc = localnet.client.rpc();
    let usdc_mint = fixture::spl_mint();
    let vault = create_vault(&localnet, &payer, usdc_mint)?;
    let share_asset_id = register_share_mint(&localnet, &payer, vault.shares_mint)?;

    let mut assets = AssetRegistry::default();
    assets.insert(fixture::SPL_ASSET_ID, usdc_mint)?;
    assets.insert(share_asset_id, vault.shares_mint)?;
    let mut user = TestWallet::new(1, &assets)?;
    let mut market_maker = TestWallet::new(0, &assets)?;

    for mint in [usdc_mint, vault.shares_mint] {
        create_associated_token_account(rpc, &payer, &market_maker.address(), &mint)?;
    }
    send(
        rpc,
        &[token_transfer_ix(
            &fixture::payer_token_account(),
            &pda::associated_token_address(&market_maker.address(), &usdc_mint),
            &payer.pubkey(),
            MARKET_MAKER_PUBLIC_USDC,
        )],
        &payer,
        &[&payer],
    )?;

    let user_deposit = Deposit::new(DepositParams {
        recipient: &user.keypair.shielded_address()?,
        asset: usdc_mint,
        amount: USER_SHIELD_USDC,
        spl_token_account: Some(fixture::payer_token_account()),
        spl_token_program: Some(spl_token_program_id()),
        memo: None,
    })?
    .send(rpc, &payer, localnet.tree, &payer)?;
    localnet
        .client
        .confirm_private_transaction_sync(user_deposit)
        .map_err(|e| anyhow!("index user deposit: {e:?}"))?;
    user.sync(&localnet)?;
    market_maker.sync(&localnet)?;

    Ok(TestEnv {
        localnet,
        user,
        market_maker: MarketMaker {
            trader: market_maker,
            fee_bps: FEE_BPS,
        },
        usdc_mint,
        vault,
    })
}
