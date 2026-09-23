use anyhow::{anyhow, Result};
use solana_address::Address;
use solana_instruction::Instruction;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{ComputeBudgetConfig, Rpc, SolanaRpc};
use zolana_keypair::{ShieldedKeypair, SigningKey};
use zolana_program_test::{
    fixture,
    localnet::{FixtureLocalnet, LocalnetPaths, LocalnetPorts},
};
use zolana_transaction::{AssetRegistry, SOL_MINT};
use zolana_wallet::{sync_wallet, Deposit, DepositParams, Wallet};

// The whole per-transaction budget: the settlement verifies an SPP proof.
const TRANSACT_COMPUTE_UNIT_LIMIT: u32 = 1_400_000;

pub const SELL_SOL: u64 = 250_000_000;
pub const BUY_USDC: u64 = 100_000_000;
pub const MAKER_SHIELD_SOL: u64 = SELL_SOL;
pub const TAKER_SHIELD_USDC: u64 = BUY_USDC;

pub struct TestEnv {
    /// The localnet with its client and default tree. Dropping it stops the
    /// validator, so it lives as long as the test.
    pub localnet: FixtureLocalnet,
    pub maker: TestWallet,
    pub taker: TestWallet,
    pub usdc_mint: Address,
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

/// Boot the localnet of test number `test` ([`LocalnetPorts::for_test`]); tests
/// running in parallel take distinct numbers.
pub fn setup(test: u16) -> Result<TestEnv> {
    let localnet = FixtureLocalnet::start(
        "zolana-rfq",
        LocalnetPorts::for_test(test)?,
        vec![],
        &LocalnetPaths::workspace(),
    )?;
    let payer = fixture::payer();

    let usdc_mint = fixture::spl_mint();
    let mut assets = AssetRegistry::default();
    assets.insert(fixture::SPL_ASSET_ID, usdc_mint)?;
    let usdc_funding = fixture::payer_token_account();

    let maker_solana_keypair = fixture::actor(0);
    let maker_seed: [u8; 32] = maker_solana_keypair.to_bytes()[..32]
        .try_into()
        .expect("ed25519 seed is the first 32 bytes");
    let maker_shielded_keypair =
        ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&maker_seed))?;

    let taker_solana_keypair = fixture::actor(1);
    let taker_seed: [u8; 32] = taker_solana_keypair.to_bytes()[..32]
        .try_into()
        .expect("ed25519 seed is the first 32 bytes");
    let taker_shielded_keypair =
        ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&taker_seed))?;

    let maker_deposit = Deposit::new(DepositParams {
        recipient: &maker_shielded_keypair.shielded_address()?,
        asset: SOL_MINT,
        amount: MAKER_SHIELD_SOL,
        spl_token_account: None,
        spl_token_program: Some(zolana_interface::pda::spl_token_program_id()),
        memo: None,
    })?
    .send(&localnet.client, &payer, localnet.tree, &payer)?;
    let taker_deposit = Deposit::new(DepositParams {
        recipient: &taker_shielded_keypair.shielded_address()?,
        asset: usdc_mint,
        amount: TAKER_SHIELD_USDC,
        spl_token_account: Some(usdc_funding),
        spl_token_program: Some(zolana_interface::pda::spl_token_program_id()),
        memo: None,
    })?
    .send(&localnet.client, &payer, localnet.tree, &payer)?;
    // The wallets sync from Photon, so wait until both deposits are indexed.
    for deposit in [maker_deposit, taker_deposit] {
        localnet
            .client
            .confirm_private_transaction_sync(deposit)
            .map_err(|e| anyhow!("index deposit {deposit}: {e:?}"))?;
    }

    let maker_address = maker_shielded_keypair
        .shielded_address()
        .map_err(|e| anyhow!("maker address: {e:?}"))?;
    let taker_address = taker_shielded_keypair
        .shielded_address()
        .map_err(|e| anyhow!("taker address: {e:?}"))?;

    let mut maker_wallet =
        Wallet::new(maker_address, assets.clone()).map_err(|e| anyhow!("maker wallet: {e:?}"))?;
    sync_wallet(&mut maker_wallet, &maker_shielded_keypair, &localnet.client)
        .map_err(|e| anyhow!("sync maker deposit: {e:?}"))?;

    let mut taker_wallet =
        Wallet::new(taker_address, assets.clone()).map_err(|e| anyhow!("taker wallet: {e:?}"))?;
    sync_wallet(&mut taker_wallet, &taker_shielded_keypair, &localnet.client)
        .map_err(|e| anyhow!("sync taker deposit: {e:?}"))?;

    Ok(TestEnv {
        localnet,
        maker: TestWallet {
            wallet: maker_wallet,
            keypair: maker_shielded_keypair,
        },
        taker: TestWallet {
            wallet: taker_wallet,
            keypair: taker_shielded_keypair,
        },
        usdc_mint,
    })
}

// Submit the maker/taker co-signed settlement as a transaction **v1** message:
// its 4096-byte limit is what holds an RFQ transact, which no longer fits a
// 1232-byte legacy packet. v1 has no address lookup table, and it carries the
// compute ceilings in the message header rather than in a compute-budget
// instruction. An unset ceiling means zero, not a default, so both are written.
pub fn send_cosigned(
    rpc: &SolanaRpc,
    payer: &dyn Signer,
    cosigner: &dyn Signer,
    ix: Instruction,
) -> Result<Signature> {
    Ok(rpc.create_and_send_transaction(
        std::slice::from_ref(&ix),
        payer.pubkey(),
        &[payer, cosigner],
        ComputeBudgetConfig::new(TRANSACT_COMPUTE_UNIT_LIMIT),
    )?)
}
