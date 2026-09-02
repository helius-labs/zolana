use std::time::Duration;

use solana_address_lookup_table_interface::instruction::{
    create_lookup_table, extend_lookup_table,
};
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::Instruction;
use solana_message::{v0, AddressLookupTableAccount, Message, VersionedMessage};
use solana_rpc_client_api::client_error::Error as RpcError;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::{versioned::VersionedTransaction, Transaction};
use thiserror::Error;
use zolana_client::SolanaRpc;

use crate::lookup_table::{lookup_table_addresses, TRANSACT_COMPUTE_UNIT_LIMIT};

const SLOT_POLL_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Debug, Error)]
pub enum SendV0Error {
    #[error("lookup table setup failed")]
    Setup(#[source] RpcError),
    #[error("slot query failed")]
    Slot(#[source] RpcError),
    #[error("blockhash query failed")]
    Blockhash(#[source] RpcError),
    #[error("v0 message compile failed")]
    Compile(#[from] solana_message::CompileError),
    #[error("v0 signing failed")]
    Sign(#[from] solana_signer::SignerError),
    #[error("v0 send failed")]
    Send(#[source] RpcError),
}

/// The payer funds a throwaway lookup table, the custom-ring transact does not fit a legacy packet.
#[must_use]
pub struct V0WithLookupTable<'a> {
    pub payer: &'a dyn Signer,
    pub signers: &'a [&'a dyn Signer],
    pub instruction: Instruction,
}

impl V0WithLookupTable<'_> {
    pub fn send(self, rpc: &SolanaRpc) -> Result<Signature, SendV0Error> {
        let tx = self.build(rpc)?;
        rpc.client()
            .send_and_confirm_transaction(&tx)
            .map_err(SendV0Error::Send)
    }

    pub fn build(self, rpc: &SolanaRpc) -> Result<VersionedTransaction, SendV0Error> {
        let Self {
            payer,
            signers,
            instruction,
        } = self;
        let compute = ComputeBudgetInstruction::set_compute_unit_limit(TRANSACT_COMPUTE_UNIT_LIMIT);
        let addresses = lookup_table_addresses(&instruction, compute.program_id);
        let client = rpc.client();
        let recent_slot = client.get_slot().map_err(SendV0Error::Slot)?;
        wait_past_slot(rpc, recent_slot)?;
        let (create, table_address) =
            create_lookup_table(payer.pubkey(), payer.pubkey(), recent_slot);
        let extend = extend_lookup_table(
            table_address,
            payer.pubkey(),
            Some(payer.pubkey()),
            addresses.clone(),
        );
        let blockhash = client
            .get_latest_blockhash()
            .map_err(SendV0Error::Blockhash)?;
        let setup = Transaction::new(
            &[payer],
            Message::new(&[create, extend], Some(&payer.pubkey())),
            blockhash,
        );
        client
            .send_and_confirm_transaction(&setup)
            .map_err(SendV0Error::Setup)?;
        let extended_slot = client.get_slot().map_err(SendV0Error::Slot)?;
        wait_past_slot(rpc, extended_slot)?;
        let table = AddressLookupTableAccount {
            key: table_address,
            addresses,
        };
        let blockhash = client
            .get_latest_blockhash()
            .map_err(SendV0Error::Blockhash)?;
        let message = v0::Message::try_compile(
            &payer.pubkey(),
            &[compute, instruction],
            std::slice::from_ref(&table),
            blockhash,
        )?;
        let mut all_signers: Vec<&dyn Signer> = vec![payer];
        all_signers.extend(signers.iter().copied());
        Ok(VersionedTransaction::try_new(
            VersionedMessage::V0(message),
            &all_signers,
        )?)
    }
}

/// A lookup table resolves only from the slot after the one it was written in.
fn wait_past_slot(rpc: &SolanaRpc, slot: u64) -> Result<(), SendV0Error> {
    loop {
        let tip = rpc.client().get_slot().map_err(SendV0Error::Slot)?;
        if tip > slot {
            return Ok(());
        }
        std::thread::sleep(SLOT_POLL_INTERVAL);
    }
}
