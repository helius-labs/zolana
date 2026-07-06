use anyhow::{anyhow, Result};
use cucumber::{given, then};
use solana_signer::Signer;
use zolana_client::{CreateDeposit, Deposit as DepositAction};
use zolana_transaction::{Data, Utxo, SOL_MINT};

use crate::SwapWorld;

impl SwapWorld {
    pub(crate) fn deposit_sol(&mut self, name: &str, amount: u64) -> Result<()> {
        self.ensure_actor(name)?;
        let payer = self.payer.insecure_clone();
        let tree = self.tree;
        let actor_pubkey = self.actor(name).solana_keypair.pubkey();
        self.rpc.airdrop(&actor_pubkey, 1_000_000_000)?;
        let recipient = self.actor(name).shielded_keypair.shielded_address()?;

        let deposit = DepositAction::new(CreateDeposit {
            recipient: &recipient,
            asset: SOL_MINT,
            amount,
            spl_token_account: None,
            memo: None,
        })?;
        deposit.send(&self.rpc, &payer, tree, &payer)?;

        self.wait_for_merkle_proof(deposit.utxo_hash)?;

        let blinding = deposit.data.blinding;
        let owner = self.actor(name).shielded_keypair.signing_pubkey();
        let utxo = Utxo {
            owner,
            asset: SOL_MINT,
            amount,
            blinding,
            zone_program_id: None,
            data: Data::default(),
        };
        self.actor_mut(name).spendable.push(utxo);
        Ok(())
    }

    pub(crate) fn spendable_sol(&self, name: &str) -> u64 {
        self.actor(name)
            .spendable
            .iter()
            .filter(|u| u.asset == SOL_MINT)
            .map(|u| u.amount)
            .sum()
    }
}

#[given(expr = "the maker {word} shields {int} lamports of SOL")]
fn maker_shields(world: &mut SwapWorld, name: String, amount: i64) {
    world
        .deposit_sol(&name, amount as u64)
        .expect("maker shield");
}

#[then(expr = "{word} holds a spendable {int} lamport SOL UTXO")]
fn holds_spendable(world: &mut SwapWorld, name: String, amount: i64) {
    let total = world.spendable_sol(&name);
    assert_eq!(
        total, amount as u64,
        "{name} spendable SOL must equal the shielded amount"
    );
    let _ = world
        .actor(&name)
        .spendable
        .iter()
        .find(|u| u.asset == SOL_MINT && u.amount == amount as u64)
        .ok_or_else(|| anyhow!("{name} has no spendable SOL utxo of {amount}"))
        .expect("spendable utxo recorded");
}
