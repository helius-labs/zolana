use solana_account::{Account, ReadableAccount};
use solana_address::Address;
use solana_hash::Hash;
use solana_instruction::Instruction;
use solana_keypair::Signer;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_transaction::versioned::VersionedTransaction;
use zolana_client::{
    compile_v1_message, sign_versioned_transaction, ClientError, ComputeBudgetConfig, Rpc,
};

use crate::{
    events::{index_events, indexed_events_from_meta, IndexedEvent},
    AccountSnapshot, AccountTransition, InstructionTrace, ProgramTestError, TransactionOutcome,
    TransactionTrace, ZolanaProgramTest,
};

#[derive(Debug)]
pub struct IndexedTransaction {
    pub signature: Signature,
    pub events: Vec<IndexedEvent>,
}

impl ZolanaProgramTest {
    /// Build, sign, send, and index a transaction against the litesvm backend
    /// on the budget a legacy transaction of this length used to receive
    /// implicitly, so callers that never asked for one keep the ceiling they
    /// already had.
    pub fn create_and_send_transaction(
        &mut self,
        ixs: &[Instruction],
        payer: &Pubkey,
        signers: &[&dyn Signer],
    ) -> Result<IndexedTransaction, ProgramTestError> {
        self.create_and_send_transaction_with_budget(
            ixs,
            payer,
            signers,
            ComputeBudgetConfig::for_instruction_count(ixs.len()),
        )
    }

    /// [`Self::create_and_send_transaction`] with an explicit compute ceiling,
    /// for the proof paths 200k per instruction cannot reach.
    ///
    /// v1 carries the ceiling in the message header, so raising it must not go
    /// through a compute-budget instruction: that would buy nothing and still
    /// shift every instruction index a rejection assertion names.
    pub fn create_and_send_transaction_with_budget(
        &mut self,
        ixs: &[Instruction],
        payer: &Pubkey,
        signers: &[&dyn Signer],
        compute_budget: ComputeBudgetConfig,
    ) -> Result<IndexedTransaction, ProgramTestError> {
        // Each helper call represents a fresh RPC submission. LiteSVM otherwise
        // deduplicates repeated instructions signed over the same blockhash.
        self.svm.expire_blockhash();
        let blockhash = self.svm.latest_blockhash();
        let message = compile_v1_message(payer, ixs, blockhash, compute_budget)?;
        self.send_indexed(sign_versioned_transaction(message, signers)?)
    }

    fn send_indexed(
        &mut self,
        transaction: VersionedTransaction,
    ) -> Result<IndexedTransaction, ProgramTestError> {
        let signature = transaction
            .signatures
            .first()
            .copied()
            .ok_or_else(|| ProgramTestError::Rpc("transaction has no signatures".into()))?;
        let message = transaction.message.clone();
        let account_keys = message.static_account_keys();
        // A compiled index is data the message carries, not a bound the type
        // system proves, so a malformed transaction surfaces as a harness error
        // instead of a panic while the trace is being built.
        let key_at = |index: u8| -> Result<Pubkey, ProgramTestError> {
            account_keys.get(usize::from(index)).copied().ok_or(
                ProgramTestError::AccountIndexOutOfRange {
                    index,
                    keys: account_keys.len(),
                },
            )
        };
        let instructions: Vec<InstructionTrace> = message
            .instructions()
            .iter()
            .map(|compiled| {
                Ok(InstructionTrace {
                    program_id: key_at(compiled.program_id_index)?,
                    accounts: compiled
                        .accounts
                        .iter()
                        .map(|index| key_at(*index))
                        .collect::<Result<Vec<_>, ProgramTestError>>()?,
                    data_len: compiled.data.len(),
                    discriminator: compiled.data.iter().take(8).copied().collect(),
                })
            })
            .collect::<Result<Vec<_>, ProgramTestError>>()?;
        let before: Vec<_> = account_keys
            .iter()
            .map(|address| {
                (
                    *address,
                    self.svm
                        .get_account(address)
                        .map(AccountSnapshot::from_account),
                )
            })
            .collect();
        let result = self.svm.send_transaction(transaction);
        let (logs, compute_units_consumed, outcome) = match &result {
            Ok(meta) => (
                meta.logs.clone(),
                meta.compute_units_consumed,
                TransactionOutcome::Succeeded,
            ),
            Err(failure) => (
                failure.meta.logs.clone(),
                failure.meta.compute_units_consumed,
                TransactionOutcome::Failed(failure.err.clone()),
            ),
        };
        let accounts = before
            .into_iter()
            .map(|(address, before)| AccountTransition {
                address,
                before,
                after: self
                    .svm
                    .get_account(&address)
                    .map(AccountSnapshot::from_account),
            })
            .collect();
        self.transaction_traces.push(TransactionTrace {
            signature,
            instructions,
            accounts,
            logs,
            compute_units_consumed,
            outcome,
        });
        let meta = result?;
        let events = indexed_events_from_meta(
            self.program_id,
            message.static_account_keys(),
            message.instructions(),
            &meta,
        )?;
        index_events(&mut self.indexer, &events, signature)?;
        Ok(IndexedTransaction { signature, events })
    }
}

impl Rpc for ZolanaProgramTest {
    fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
        let pubkey = Pubkey::new_from_array(address.to_bytes());
        Ok(self.svm.get_account(&pubkey))
    }

    fn get_program_accounts(
        &self,
        program_id: Address,
    ) -> Result<Vec<(Address, Account)>, ClientError> {
        // litesvm has no native get_program_accounts; enumerate the account
        // store and filter by owner, reusing `get_account` for the
        // AccountSharedData -> Account conversion already used above.
        let matches: Vec<Address> = self
            .svm
            .accounts_db()
            .inner
            .iter()
            .filter(|(_, account)| account.owner().to_bytes() == program_id.to_bytes())
            .map(|(address, _)| *address)
            .collect();
        Ok(matches
            .into_iter()
            .filter_map(|address| {
                let pubkey = Pubkey::new_from_array(address.to_bytes());
                self.svm
                    .get_account(&pubkey)
                    .map(|account| (address, account))
            })
            .collect())
    }

    fn get_minimum_balance_for_rent_exemption(&self, data_len: usize) -> Result<u64, ClientError> {
        Ok(self.svm.minimum_balance_for_rent_exemption(data_len))
    }

    fn get_latest_blockhash(&self) -> Result<(Hash, u64), ClientError> {
        Ok((self.svm.latest_blockhash(), 0))
    }
}
