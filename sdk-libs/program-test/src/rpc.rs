use litesvm::{types::TransactionMetadata, LiteSVM};
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_transaction::Transaction;
use zolana_interface::instruction::{tag, ProoflessShieldEvent};

use crate::{
    logging::{log_failed_transaction, log_transaction},
    PoolIndexer, RigError,
};

#[derive(Clone, Debug)]
pub enum IndexedEvent {
    ProoflessShield(ProoflessShieldEvent),
    Unknown { data: Vec<u8> },
}

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
        let account_keys = message.account_keys.clone();
        let transaction = Transaction::new(signers, message, blockhash);
        self.send_transaction(transaction, &account_keys)
    }

    pub fn send_transaction(
        &mut self,
        transaction: Transaction,
        account_keys: &[Pubkey],
    ) -> Result<IndexedTransaction, RigError> {
        let message = transaction.message.clone();
        let meta = match self.svm.send_transaction(transaction) {
            Ok(meta) => meta,
            Err(err) => {
                log_failed_transaction(self.shielded_pool_program_id, &message, &err);
                return Err(RigError::Litesvm(format!("send_transaction: {err:?}")));
            }
        };
        let events = indexed_events_from_meta(self.shielded_pool_program_id, account_keys, &meta)?;
        for event in &events {
            match event {
                IndexedEvent::ProoflessShield(event) => {
                    self.indexer.record_proofless_shield(event)?;
                }
                IndexedEvent::Unknown { .. } => {}
            }
        }
        log_transaction(self.shielded_pool_program_id, &message, &meta, &events);
        Ok(IndexedTransaction { meta, events })
    }
}

pub fn indexed_events_from_meta(
    shielded_pool_program_id: Pubkey,
    account_keys: &[Pubkey],
    meta: &TransactionMetadata,
) -> Result<Vec<IndexedEvent>, RigError> {
    let mut events = Vec::new();
    for inner in meta.inner_instructions.iter().flatten() {
        let compiled = &inner.instruction;
        let program = account_keys
            .get(compiled.program_id_index as usize)
            .copied()
            .unwrap_or_default();
        if program == shielded_pool_program_id && compiled.data.first() == Some(&tag::EMIT_EVENT) {
            let payload = &compiled.data[1..];
            let event =
                match <ProoflessShieldEvent as borsh::BorshDeserialize>::try_from_slice(payload) {
                    Ok(event) => IndexedEvent::ProoflessShield(event),
                    Err(_) => IndexedEvent::Unknown {
                        data: payload.to_vec(),
                    },
                };
            events.push(event);
        }
    }
    Ok(events)
}
