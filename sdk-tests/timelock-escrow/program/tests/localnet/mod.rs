use anyhow::{anyhow, Result};
use solana_instruction::Instruction;
use solana_signer::Signer;
use timelock_escrow_program::circuits::escrow_authority;
use zolana_client::{ComputeBudgetConfig, IndexerRpcConfig, Rpc};
use zolana_keypair::ShieldedKeypair;
use zolana_program::instruction::{AssetDeposit, Deposit, DepositAsset};
use zolana_program_test::{
    fixture,
    localnet::{FixtureLocalnet, LocalnetPaths, LocalnetPorts},
    workspace_path,
};
use zolana_transaction::ShieldedTransaction;

const TRANSACT_COMPUTE_UNIT_LIMIT: u32 = 1_400_000;

pub const DEPOSITS: [u64; 2] = [250_000_000, 250_000_000];
pub const LOCK_AMOUNT: u64 = 300_000_000;
pub const UNLOCK_TIMESTAMP: u64 = 1_000_000;

pub struct TestEnv {
    pub localnet: FixtureLocalnet,
    pub creator: ShieldedKeypair,
    pub deposit_slot: u64,
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
    let creator = ShieldedKeypair::from_keypair(&fixture::actor(0))?;
    let address = creator.shielded_address()?;
    let deposits = DEPOSITS
        .into_iter()
        .map(|amount| {
            Ok(AssetDeposit {
                asset: DepositAsset::Sol,
                view_tag: address.confidential_view_tag()?,
                owner: address.owner_hash()?,
                amount,
                memo: None,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let deposit = Deposit {
        tree: localnet.tree,
        depositor: payer.pubkey(),
        deposits,
    }
    .instruction()?;
    let deposit_slot = send(&localnet, &payer, deposit)?;
    Ok(TestEnv {
        localnet,
        creator,
        deposit_slot,
    })
}

pub fn creator_transactions(
    localnet: &FixtureLocalnet,
    creator: &ShieldedKeypair,
    slot: u64,
) -> Result<Vec<ShieldedTransaction>> {
    Ok(localnet
        .client
        .get_shielded_transactions_by_tags(
            vec![
                creator.shielded_address()?.confidential_view_tag()?,
                escrow_authority(&creator.pubkey()).owner_tag(),
            ],
            None,
            Some(50),
            Some(IndexerRpcConfig::at_slot(slot)),
        )?
        .transactions)
}

pub fn send(
    localnet: &FixtureLocalnet,
    signer: &dyn Signer,
    instruction: Instruction,
) -> Result<u64> {
    let signature = localnet.client.create_and_send_transaction(
        &[instruction],
        signer.pubkey(),
        &[signer],
        ComputeBudgetConfig::new(TRANSACT_COMPUTE_UNIT_LIMIT),
    )?;
    localnet
        .client
        .get_signature_statuses(vec![signature])?
        .first()
        .and_then(|status| status.as_ref())
        .map(|status| status.slot)
        .ok_or_else(|| anyhow!("no status for {signature} after confirmation"))
}
