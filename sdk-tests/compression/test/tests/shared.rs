use anyhow::{anyhow, Result};
use solana_address::Address;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{ComputeBudgetConfig, Rpc};
use zolana_program_test::{
    fixture,
    localnet::{FixtureLocalnet, LocalnetPorts},
    workspace_path,
};
use zolana_tree::TreeAccount;

pub const TRANSACT_CU_LIMIT: u32 = 1_400_000;

pub struct Environment {
    /// The localnet with its client and default tree. Dropping it stops the
    /// validator, so it lives as long as the test.
    pub localnet: FixtureLocalnet,
    /// Funded fee payer and the compressed account's authority.
    pub authority: Keypair,
}

/// Boot the localnet of test number `test` ([`LocalnetPorts::for_test`]); tests
/// running in parallel take distinct numbers.
pub fn setup(test: u16) -> Result<Environment> {
    let localnet = FixtureLocalnet::start(
        "zolana-compression",
        LocalnetPorts::for_test(test)?,
        vec![(
            compression_example_program::ID,
            workspace_path("target/deploy/compression_example_program.so"),
        )],
    )?;
    Ok(Environment {
        localnet,
        authority: fixture::actor(0),
    })
}

pub fn tree_root(rpc: &impl Rpc, tree: Address) -> Result<(u16, [u8; 32])> {
    let mut data = rpc
        .get_account(tree)?
        .ok_or_else(|| anyhow!("tree account {tree} is missing"))?
        .data;
    let mut account = TreeAccount::from_bytes(&mut data, tree.to_bytes())
        .map_err(|error| anyhow!("load tree: {error:?}"))?;
    let index = account.utxo_tree().current_root_index();
    let root = account
        .get_utxo_tree_root(index)
        .map_err(|error| anyhow!("read state root: {error:?}"))?;
    Ok((index, root))
}

pub fn send(
    env: &Environment,
    instruction: Instruction,
    cu_price: Option<u64>,
) -> Result<Signature> {
    send_from(env, instruction, &env.authority, cu_price)
}

/// Submit as a transaction **v1** message, whose 4096-byte limit holds a
/// proof-carrying compression instruction. The compute ceilings live in the
/// message header instead of in a compute-budget instruction. A `cu_price` also
/// makes an otherwise identical message distinct, which is what the replay
/// negatives rely on.
pub fn send_from(
    env: &Environment,
    instruction: Instruction,
    payer: &dyn Signer,
    cu_price: Option<u64>,
) -> Result<Signature> {
    let budget = ComputeBudgetConfig::new(TRANSACT_CU_LIMIT);
    let budget = match cu_price {
        Some(price) => budget.with_compute_unit_price(price),
        None => budget,
    };
    Ok(env.localnet.client.create_and_send_transaction(
        std::slice::from_ref(&instruction),
        payer.pubkey(),
        &[payer],
        budget,
    )?)
}
