use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_event::SplTransfer;
use zolana_interface::instruction::{AssetDeposit, Deposit};
use zolana_keypair::PublicKey;
use zolana_transaction::Utxo;

use zolana_event::general_event_from_indexed;

use crate::{
    deposit_outputs_from_event, single_deposit_view, DepositOutput, ProgramTestError,
    ZolanaProgramTest,
};

/// Result of a batched deposit: every appended output in slot order, plus the
/// event's per-asset public SPL transfers (one entry per settled asset).
pub struct DepositBatch {
    pub outputs: Vec<DepositOutput>,
    pub spl_transfers: Vec<SplTransfer>,
}

impl ZolanaProgramTest {
    pub fn deposit(
        &mut self,
        tree: &Pubkey,
        depositor: &Keypair,
        deposit: &AssetDeposit,
    ) -> Result<DepositOutput, ProgramTestError> {
        let ix = Deposit {
            tree: *tree,
            depositor: depositor.pubkey(),
            deposits: vec![deposit.clone()],
        }
        .instruction()?;
        self.send_deposit_ix(ix, depositor)
    }

    /// Send a batched deposit. Fails unless the transaction emitted exactly one
    /// deposit event, which is the batch's defining property.
    pub fn deposit_batch(
        &mut self,
        tree: &Pubkey,
        depositor: &Keypair,
        deposits: Vec<AssetDeposit>,
    ) -> Result<DepositBatch, ProgramTestError> {
        let ix = Deposit {
            tree: *tree,
            depositor: depositor.pubkey(),
            deposits,
        }
        .instruction()?;
        let outcome = self.create_and_send_default_payer_transaction(&[ix], &[depositor])?;
        let Some(event) = outcome.events.first() else {
            return Err(ProgramTestError::Event(
                "no proofless deposit event emitted by transaction".into(),
            ));
        };
        if outcome.events.len() != 1 {
            return Err(ProgramTestError::Event(format!(
                "expected one deposit event, transaction emitted {}",
                outcome.events.len()
            )));
        }
        let general_event = general_event_from_indexed(event).map_err(|err| {
            ProgramTestError::Event(format!("batch deposit event decode failed: {err:?}"))
        })?;
        Ok(DepositBatch {
            outputs: deposit_outputs_from_event(event)?,
            spl_transfers: general_event.spl_transfers.clone(),
        })
    }

    pub fn deposit_with_accounts(
        &mut self,
        accounts: Vec<AccountMeta>,
        depositor: &Keypair,
        deposit: &AssetDeposit,
    ) -> Result<DepositOutput, ProgramTestError> {
        let mut ix = Deposit {
            tree: Pubkey::default(),
            depositor: depositor.pubkey(),
            deposits: vec![deposit.clone()],
        }
        .instruction()?;
        ix.program_id = self.program_id;
        ix.accounts = accounts;
        self.send_deposit_ix(ix, depositor)
    }

    pub(crate) fn send_deposit_ix(
        &mut self,
        ix: Instruction,
        depositor: &Keypair,
    ) -> Result<DepositOutput, ProgramTestError> {
        let outcome = self.create_and_send_default_payer_transaction(&[ix], &[depositor])?;
        single_deposit_view(&outcome.events)
    }

    pub fn deposit_sol(
        &mut self,
        tree: &Pubkey,
        depositor: &Keypair,
        lamports: u64,
        owner: [u8; 32],
    ) -> Result<DepositOutput, ProgramTestError> {
        let deposit = Self::sol_shield_data(lamports, owner);
        self.deposit(tree, depositor, &deposit)
    }

    /// The spendable [`Utxo`] for a deposit this backend just sent, read back
    /// from the test indexer. A proofless deposit's output is plaintext, so the
    /// derived blinding comes with the indexed record; `owner` is the
    /// recipient's shielded signing key, committed to only as a hash.
    pub fn indexed_deposit_utxo(
        &self,
        deposit: &DepositOutput,
        owner: PublicKey,
    ) -> Result<Utxo, ProgramTestError> {
        Ok(self.indexer().deposit_utxo(&deposit.utxo_hash, owner)?)
    }
}
