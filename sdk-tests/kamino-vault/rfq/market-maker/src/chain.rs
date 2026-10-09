use anyhow::{anyhow, Result};
use solana_address::Address;
use solana_instruction::Instruction;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{ComputeBudgetConfig, Rpc, SolanaRpc};
use zolana_interface::pda::{self, spl_token_program_id};
use zolana_keypair::ShieldedKeypair;
use zolana_program_test::localnet::FixtureLocalnet;
use zolana_test_utils::wallet::{Deposit, DepositParams};

const COMPUTE_UNIT_LIMIT: u32 = 1_400_000;

pub(crate) fn blocking<R>(work: impl FnOnce() -> R) -> R {
    match tokio::runtime::Handle::try_current() {
        Ok(_) => tokio::task::block_in_place(work),
        Err(_) => work(),
    }
}

pub(crate) fn send(
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

pub(crate) fn shield_deposit(
    localnet: &FixtureLocalnet,
    keypair: &ShieldedKeypair,
    mint: Address,
    amount: u64,
) -> Result<Signature> {
    let token_account = pda::associated_token_address(&keypair.pubkey(), &mint);
    let signature = Deposit::new(DepositParams {
        recipient: &keypair.shielded_address()?,
        asset: mint,
        amount,
        spl_token_account: Some(token_account),
        spl_token_program: Some(spl_token_program_id()),
        memo: None,
    })?
    .send(localnet.client.rpc(), keypair, localnet.tree, keypair)?;
    localnet
        .client
        .confirm_private_transaction_sync(signature)
        .map_err(|e| anyhow!("index shield of {amount} {mint}: {e:?}"))?;
    Ok(signature)
}
