use litesvm::{types::TransactionMetadata, LiteSVM};
use solana_clock::Clock;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_transaction::Transaction;

use crate::{
    events::{index_events, indexed_events_from_meta, IndexedEvent},
    logging::{log_failed_transaction, log_transaction},
    PoolIndexer, RigError,
};

pub struct IndexedTransaction {
    pub meta: TransactionMetadata,
    pub events: Vec<IndexedEvent>,
}

pub struct LiteSvmRpc<'a> {
    svm: &'a mut LiteSVM,
    indexer: &'a mut PoolIndexer,
    shielded_pool_program_id: Pubkey,
}

impl<'a> LiteSvmRpc<'a> {
    pub fn new(
        svm: &'a mut LiteSVM,
        indexer: &'a mut PoolIndexer,
        shielded_pool_program_id: Pubkey,
    ) -> Self {
        Self {
            svm,
            indexer,
            shielded_pool_program_id,
        }
    }

    pub fn send_instructions(
        &mut self,
        ixs: &[Instruction],
        signers: &[&Keypair],
        payer: &Pubkey,
    ) -> Result<IndexedTransaction, RigError> {
        let blockhash = self.svm.latest_blockhash();
        let message = Message::new(ixs, Some(payer));
        let transaction = Transaction::new(signers, message, blockhash);
        self.send_transaction(transaction)
    }

    pub fn send_transaction(
        &mut self,
        transaction: Transaction,
    ) -> Result<IndexedTransaction, RigError> {
        let message = transaction.message.clone();
        let slot = self.svm.get_sysvar::<Clock>().slot;
        let meta = match self.svm.send_transaction(transaction) {
            Ok(meta) => meta,
            Err(err) => {
                log_failed_transaction(self.shielded_pool_program_id, slot, &message, &err);
                return Err(RigError::Litesvm(format!("send_transaction: {err:?}")));
            }
        };
        let events =
            indexed_events_from_meta(self.shielded_pool_program_id, &message.account_keys, &meta)?;
        index_events(self.indexer, &events)?;
        log_transaction(
            self.shielded_pool_program_id,
            slot,
            &message,
            &meta,
            &events,
        );
        Ok(IndexedTransaction { meta, events })
    }
}
