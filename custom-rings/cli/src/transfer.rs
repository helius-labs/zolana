//! The demo the operator CLI runs: two ring deposits for a fresh sender, one
//! audited confidential transfer to a fresh recipient, then the auditor's view
//! of it read back from the ring RPC.

use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use custom_ring_sdk::{ring_deposit_sol, send_v0_with_lookup_table, AuditedTransfer};
use solana_address::Address;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{ProverClient, Rpc, SolanaRpc, ZolanaIndexer};
use zolana_keypair::{P256Pubkey, ShieldedKeypair};
use zolana_transaction::{instructions::transact::SppProofOutputUtxo, AssetRegistry, SOL_MINT};

/// Lamports the sender receives for its lookup table rent and fees.
const SENDER_FEE_BUDGET: u64 = 20_000_000;
const INDEXER_TIMEOUT: Duration = Duration::from_secs(120);
const POLL_INTERVAL: Duration = Duration::from_millis(500);

pub struct DemoTransfer<'a> {
    pub rpc: &'a SolanaRpc,
    pub indexer: &'a ZolanaIndexer,
    pub prover: &'a ProverClient,
    /// Pays the deposits and funds the sender for its own transaction. The
    /// sender pays and signs the transact itself: with a separate fee payer
    /// the second signature and static key push the audited transact past the
    /// 1232-byte packet even behind a lookup table.
    pub payer: &'a dyn Signer,
    pub tree: Address,
    pub auditor_pk: P256Pubkey,
    /// Lamports the recipient receives. The sender is funded with twice that
    /// through two ring deposits, so the change output is the same amount.
    pub amount: u64,
}

pub struct TransferReceipt {
    pub sender: ShieldedKeypair,
    pub recipient: ShieldedKeypair,
    pub deposits: Vec<Signature>,
    pub transact: Signature,
}

impl DemoTransfer<'_> {
    pub fn run(self) -> Result<TransferReceipt> {
        let sender = ShieldedKeypair::new_ed25519()?;
        let recipient = ShieldedKeypair::new_ed25519()?;

        let mut inputs = Vec::with_capacity(2);
        let mut deposits = Vec::with_capacity(2);
        for _ in 0..2 {
            let (signature, utxo) =
                ring_deposit_sol(self.rpc, self.payer, &sender, self.tree, self.amount)?;
            inputs.push(utxo);
            deposits.push(signature);
        }
        let fee = solana_system_interface::instruction::transfer(
            &self.payer.pubkey(),
            &sender.pubkey(),
            SENDER_FEE_BUDGET,
        );
        self.rpc
            .create_and_send_transaction(&[fee], self.payer.pubkey(), &[self.payer])?;

        let proven = AuditedTransfer {
            indexer: self.indexer,
            spp_prover: self.prover,
            sender: &sender,
            inputs,
            outputs: vec![
                SppProofOutputUtxo::new(SOL_MINT, self.amount, sender.shielded_address()?)?,
                SppProofOutputUtxo::new(SOL_MINT, self.amount, recipient.shielded_address()?)?,
            ],
            tree: self.tree,
            auditor_pk: self.auditor_pk,
            assets: &AssetRegistry::default(),
        }
        .prove()?;
        let ix = proven.instruction(sender.pubkey(), self.tree)?;
        let transact = send_v0_with_lookup_table(self.rpc, &sender, &[], ix)?;

        Ok(TransferReceipt {
            sender,
            recipient,
            deposits,
            transact,
        })
    }
}

/// Poll `probe` until it yields a value or the indexer timeout passes.
pub fn wait_for<T>(label: &str, mut probe: impl FnMut() -> Result<Option<T>>) -> Result<T> {
    let deadline = Instant::now() + INDEXER_TIMEOUT;
    let mut last_error = None;
    while Instant::now() < deadline {
        match probe() {
            Ok(Some(value)) => return Ok(value),
            Ok(None) => {}
            Err(error) => last_error = Some(error),
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    Err(match last_error {
        Some(error) => error.context(format!("timed out waiting for {label}")),
        None => anyhow!("timed out waiting for {label}"),
    })
}

/// Block until the indexer serves `signature`.
pub fn wait_for_indexed_transaction<I: Rpc>(indexer: &I, signature: Signature) -> Result<()> {
    wait_for("indexed transaction", || {
        let response = indexer.get_shielded_transactions_by_signature(signature, None)?;
        Ok(response.transactions.into_iter().next().map(|_| ()))
    })
    .with_context(|| format!("transaction {signature}"))
}
