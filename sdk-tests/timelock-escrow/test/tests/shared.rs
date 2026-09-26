use anyhow::{anyhow, Result};
use solana_instruction::Instruction;
use solana_signature::Signature;
use solana_signer::Signer;
use timelock_escrow_sdk::{
    escrow_authority,
    state::{Funding, FundingUtxo},
    zk_program::NewProgramUtxo,
};
use zolana_client::{ComputeBudgetConfig, Rpc, SolanaRpc};
use zolana_keypair::{ShieldedKeypair, SigningKey};
use zolana_program::instruction::DepositAsset;
use zolana_program_test::{
    fixture,
    localnet::{FixtureLocalnet, LocalnetPaths, LocalnetPorts},
    workspace_path,
};
use zolana_test_utils::test_validator_asserts::wait_for_indexed_utxo;
use zolana_transaction::{AssetRegistry, Mint};
use zolana_wallet::Wallet;

const TRANSACT_COMPUTE_UNIT_LIMIT: u32 = 1_400_000;

pub const SHIELD_AMOUNT: u64 = 500_000_000;
pub const LOCK_AMOUNT: u64 = 300_000_000;
pub const UNLOCK_TIMESTAMP: u64 = 1_000_000;
pub const SPP_RELAYER_DEADLINE: u64 = 2_000_000_000;

pub struct TestEnv {
    pub localnet: FixtureLocalnet,
    pub creator: TestWallet,
    pub funding: FundingUtxo,
    pub funding_leaf_index: u64,
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

pub fn setup(test: u16) -> Result<TestEnv> {
    let localnet = FixtureLocalnet::start(
        "timelock-escrow",
        LocalnetPorts::for_test(test)?,
        vec![(
            timelock_escrow_program::ID,
            workspace_path("target/deploy/timelock_escrow_program.so"),
        )],
        &LocalnetPaths::workspace(),
    )?;
    let payer = fixture::payer();

    let creator_solana_keypair = fixture::actor(0);
    let creator_seed: [u8; 32] = creator_solana_keypair.to_bytes()[..32]
        .try_into()
        .expect("ed25519 seed is the first 32 bytes");
    let creator_keypair =
        ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&creator_seed))?;

    let creator_address = creator_keypair.shielded_address()?;
    let funding = NewProgramUtxo::new(
        escrow_authority(),
        Funding {
            creator: creator_address,
        },
        Mint::SOL,
        SHIELD_AMOUNT,
        creator_keypair.viewing_pubkey(),
    );
    let funding_deposit = funding.deposit(DepositAsset::Sol)?;
    let funding_signature = zolana_wallet::actions::deposit(
        &localnet.client,
        &payer,
        localnet.tree,
        &payer,
        &funding_deposit,
    )?;
    let indexed_funding = wait_for_indexed_utxo(
        &localnet.client,
        funding_deposit.view_tag,
        funding_signature,
    );
    let deposited = indexed_funding
        .output_slot
        .proofless_output()
        .ok_or_else(|| anyhow!("indexed funding deposit is not a proofless UTXO"))?;
    let funding = funding.created(deposited.blinding, localnet.tree_id);
    assert_eq!(
        (funding.hash()?, deposited.amount),
        (
            indexed_funding.output_slot.output_context.hash,
            SHIELD_AMOUNT
        )
    );

    let creator_wallet = Wallet::new(creator_address, AssetRegistry::default())
        .map_err(|e| anyhow!("creator wallet: {e:?}"))?;

    Ok(TestEnv {
        localnet,
        creator: TestWallet {
            wallet: creator_wallet,
            keypair: creator_keypair,
        },
        funding,
        funding_leaf_index: indexed_funding.output_slot.output_context.leaf_index,
    })
}

pub fn send(rpc: &SolanaRpc, payer: &dyn Signer, ix: Instruction) -> Result<Signature> {
    Ok(rpc.create_and_send_transaction(
        std::slice::from_ref(&ix),
        payer.pubkey(),
        &[payer],
        ComputeBudgetConfig::new(TRANSACT_COMPUTE_UNIT_LIMIT),
    )?)
}
