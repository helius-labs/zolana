use solana_account::Account;
use solana_address::Address;
use solana_clock::Clock;
use solana_hash::Hash;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_transaction::Transaction;
use zolana_client::{ClientError, Rpc};

use crate::{
    events::{index_events, indexed_events_from_meta, IndexedEvent},
    logging::{log_failed_transaction, log_transaction},
    ProgramTestError, ZolanaProgramTest,
};

#[derive(Debug)]
pub struct IndexedTransaction {
    pub signature: Signature,
    pub events: Vec<IndexedEvent>,
}

impl ZolanaProgramTest {
    /// Build, sign, send, and index a transaction against the litesvm backend.
    pub fn create_and_send_transaction(
        &mut self,
        ixs: &[Instruction],
        payer: &Pubkey,
        signers: &[&Keypair],
    ) -> Result<IndexedTransaction, ProgramTestError> {
        let blockhash = self.svm.latest_blockhash();
        let message = Message::new(ixs, Some(payer));
        let transaction = Transaction::new(signers, message, blockhash);
        self.send_indexed(transaction)
    }

    fn send_indexed(
        &mut self,
        transaction: Transaction,
    ) -> Result<IndexedTransaction, ProgramTestError> {
        let signature = transaction
            .signatures
            .first()
            .copied()
            .ok_or_else(|| ProgramTestError::Rpc("transaction has no signatures".into()))?;
        let message = transaction.message.clone();
        let slot = self.svm.get_sysvar::<Clock>().slot;
        let meta = match self.svm.send_transaction(transaction) {
            Ok(meta) => meta,
            Err(err) => {
                log_failed_transaction(self.program_id, slot, &message, &err);
                return Err(ProgramTestError::Litesvm(format!(
                    "send_transaction: {err:?}"
                )));
            }
        };
        let events = indexed_events_from_meta(self.program_id, &message.account_keys, &meta)?;
        index_events(&mut self.indexer, &events)?;
        log_transaction(self.program_id, slot, &message, &meta, &events);
        Ok(IndexedTransaction { signature, events })
    }
}

impl Rpc for ZolanaProgramTest {
    fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
        let pubkey = Pubkey::new_from_array(address.to_bytes());
        Ok(self.svm.get_account(&pubkey))
    }

    fn get_minimum_balance_for_rent_exemption(&self, data_len: usize) -> Result<u64, ClientError> {
        Ok(self.svm.minimum_balance_for_rent_exemption(data_len))
    }

    fn get_latest_blockhash(&self) -> Result<(Hash, u64), ClientError> {
        Ok((self.svm.latest_blockhash(), 0))
    }
}
