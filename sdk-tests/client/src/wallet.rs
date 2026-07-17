use std::str::FromStr;

use anyhow::{anyhow, Result};
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{
    sync_wallet_with_config, LocalWalletAuthority, ProverClient, Rpc, SolanaRpc, SyncWalletConfig,
    ZolanaClient,
};
use zolana_interface::{
    instruction::{Deposit, Transact, TransactIxData, TransactSolWithdrawal, TransactWithdrawal},
    DEFAULT_TREE_ADDRESS,
};
use zolana_keypair::{random_blinding, ShieldedAddress, ShieldedKeypair};
use zolana_transaction::{
    instructions::transact::{ConfidentialTransfer, SppProofInputs, WithdrawalTarget},
    AssetRegistry, Wallet, SOL_MINT,
};

use crate::select_inputs;

const TRANSACT_CU_LIMIT: u32 = 1_400_000;

/// Whether a send method syncs the wallet before returning. `Confirm` blocks until
/// the indexer has caught up to the send time (read-your-writes), reusing the
/// carried `SyncWalletConfig`'s retry/backoff; its `wait_for_indexer` is forced on
/// for each confirm.
#[derive(Clone, Copy, Debug)]
pub enum Confirmation {
    Skip,
    Confirm(SyncWalletConfig),
}

impl Default for Confirmation {
    fn default() -> Self {
        Self::Confirm(SyncWalletConfig::default())
    }
}

pub struct TestWallet {
    pub wallet: Wallet,
    pub keypair: ShieldedKeypair,
    pub tree: Pubkey,
    confirmation: Confirmation,
}

impl TestWallet {
    pub fn new(keypair: ShieldedKeypair, assets: AssetRegistry) -> Result<Self> {
        let wallet = Wallet::new(keypair.shielded_address()?, assets)
            .map_err(|e| anyhow!("wallet: {e:?}"))?;
        let tree = Pubkey::from_str(DEFAULT_TREE_ADDRESS)
            .map_err(|e| anyhow!("default pool tree address: {e}"))?;
        Ok(Self {
            wallet,
            keypair,
            tree,
            confirmation: Confirmation::default(),
        })
    }

    pub fn with_tree(mut self, tree: Pubkey) -> Self {
        self.tree = tree;
        self
    }

    pub fn with_confirmation(mut self, confirmation: Confirmation) -> Self {
        self.confirmation = confirmation;
        self
    }

    pub fn funding(&self) -> Result<Keypair> {
        Ok(self.keypair.to_solana_keypair()?)
    }

    pub fn solana_pubkey(&self) -> Result<Pubkey> {
        Ok(self.funding()?.pubkey())
    }

    pub fn address(&self) -> Result<ShieldedAddress> {
        Ok(self.keypair.shielded_address()?)
    }

    pub fn authority(&self) -> Result<LocalWalletAuthority<'_>> {
        Ok(LocalWalletAuthority::new(
            self.solana_pubkey()?,
            &self.keypair,
        ))
    }

    pub fn sync<I: Rpc>(&mut self, indexer: &I) -> Result<()> {
        self.sync_with_config(indexer, SyncWalletConfig::new())
    }

    pub fn sync_with_config<I: Rpc>(&mut self, indexer: &I, config: SyncWalletConfig) -> Result<()> {
        let authority = LocalWalletAuthority::new(self.solana_pubkey()?, &self.keypair);
        sync_wallet_with_config(&mut self.wallet, &authority, indexer, config)?;
        Ok(())
    }

    pub fn deposit(&mut self, client: &ZolanaClient<SolanaRpc>, amount: u64) -> Result<Signature> {
        let funding = self.funding()?;
        let recipient = self.address()?;
        let instruction = Deposit {
            tree: self.tree,
            depositor: funding.pubkey(),
            spl: None,
            view_tag: recipient.viewing_pubkey.x(),
            owner: recipient.owner_hash()?,
            blinding: random_blinding(),
            public_amount: Some(amount),
            utxo_data: None,
            memo: None,
        }
        .instruction();
        let signature =
            client.create_and_send_transaction(&[instruction], funding.pubkey(), &[&funding])?;
        self.confirm(client)?;
        Ok(signature)
    }

    pub fn transfer(
        &mut self,
        client: &ZolanaClient<SolanaRpc>,
        prover: &ProverClient,
        recipient: &ShieldedAddress,
        amount: u64,
    ) -> Result<Signature> {
        let inputs = select_inputs(&self.wallet, &self.keypair, SOL_MINT, amount)?;
        let funding = self.funding()?;
        let mut transfer = ConfidentialTransfer::new(self.address()?, inputs, funding.pubkey());
        transfer.send(recipient, SOL_MINT, amount)?;
        let proof_inputs = transfer.sign(&self.keypair, &self.wallet.registry)?;
        let data = self.prove(client, prover, proof_inputs)?;
        let signature = self.submit_transact(client, &funding, self.tree, None, data)?;
        self.confirm(client)?;
        Ok(signature)
    }

    pub fn withdraw(
        &mut self,
        client: &ZolanaClient<SolanaRpc>,
        prover: &ProverClient,
        recipient: Pubkey,
        amount: u64,
    ) -> Result<Signature> {
        let inputs = select_inputs(&self.wallet, &self.keypair, SOL_MINT, amount)?;
        let funding = self.funding()?;
        let mut transfer = ConfidentialTransfer::new(self.address()?, inputs, funding.pubkey());
        transfer.withdraw(
            SOL_MINT,
            amount,
            WithdrawalTarget::Sol {
                user_sol_account: recipient,
            },
        )?;
        let proof_inputs = transfer.sign(&self.keypair, &self.wallet.registry)?;
        let data = self.prove(client, prover, proof_inputs)?;
        let withdrawal = Some(TransactWithdrawal::Sol(TransactSolWithdrawal { recipient }));
        let signature = self.submit_transact(client, &funding, self.tree, withdrawal, data)?;
        self.confirm(client)?;
        Ok(signature)
    }

    fn confirm(&mut self, client: &ZolanaClient<SolanaRpc>) -> Result<()> {
        let Confirmation::Confirm(config) = self.confirmation else {
            return Ok(());
        };
        let config = SyncWalletConfig {
            wait_for_indexer: true,
            ..config
        };
        self.sync_with_config(client, config)
    }

    fn prove(
        &self,
        client: &ZolanaClient<SolanaRpc>,
        prover: &ProverClient,
        proof_inputs: SppProofInputs,
    ) -> Result<TransactIxData> {
        let commitments = proof_inputs.input_utxo_hashes()?;
        let spend_proofs = client.get_input_merkle_proofs(&commitments, None)?;
        Ok(prover.prove_transact(proof_inputs, &spend_proofs)?)
    }

    fn submit_transact(
        &self,
        client: &ZolanaClient<SolanaRpc>,
        funding: &Keypair,
        tree: Pubkey,
        withdrawal: Option<TransactWithdrawal>,
        data: TransactIxData,
    ) -> Result<Signature> {
        let instruction = Transact {
            payer: funding.pubkey(),
            tree,
            withdrawal,
            data,
        }
        .instruction();
        let compute_budget = ComputeBudgetInstruction::set_compute_unit_limit(TRANSACT_CU_LIMIT);
        let signature = client.create_and_send_transaction(
            &[compute_budget, instruction],
            funding.pubkey(),
            &[funding],
        )?;
        client.confirm_private_transaction_sync(signature)?;
        Ok(signature)
    }
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
