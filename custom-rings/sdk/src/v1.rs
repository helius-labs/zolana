use solana_instruction::Instruction;
use solana_rpc_client_api::client_error::Error as RpcError;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;
use thiserror::Error;
use zolana_client::{
    compile_v1_message, sign_versioned_transaction, ClientError, ComputeBudgetConfig, SolanaRpc,
};

use crate::budget::TRANSACT_COMPUTE_UNIT_LIMIT;

#[derive(Debug, Error)]
pub enum SendV1Error {
    #[error("blockhash query failed")]
    Blockhash(#[source] RpcError),
    #[error("v1 message build failed")]
    Build(#[from] Box<ClientError>),
    #[error("v1 send failed")]
    Send(#[source] RpcError),
}

/// A custom-ring transact does not fit a legacy packet, so it goes out as a
/// transaction **v1** message, whose limit is 4096 bytes. v1 has no address
/// lookup table and carries its compute ceilings in the message header, so no
/// compute-budget instruction rides along.
#[must_use]
pub struct TransactV1<'a> {
    pub payer: &'a dyn Signer,
    pub signers: &'a [&'a dyn Signer],
    pub instruction: Instruction,
}

impl TransactV1<'_> {
    pub fn send(self, rpc: &SolanaRpc) -> Result<Signature, SendV1Error> {
        let tx = self.build(rpc)?;
        rpc.client()
            .send_and_confirm_transaction(&tx)
            .map_err(SendV1Error::Send)
    }

    pub fn build(self, rpc: &SolanaRpc) -> Result<VersionedTransaction, SendV1Error> {
        let Self {
            payer,
            signers,
            instruction,
        } = self;
        let blockhash = rpc
            .client()
            .get_latest_blockhash()
            .map_err(SendV1Error::Blockhash)?;
        let message = compile_v1_message(
            &payer.pubkey(),
            std::slice::from_ref(&instruction),
            blockhash,
            ComputeBudgetConfig::new(TRANSACT_COMPUTE_UNIT_LIMIT),
        )
        .map_err(Box::new)?;
        let mut all_signers: Vec<&dyn Signer> = vec![payer];
        all_signers.extend(signers.iter().copied());
        Ok(sign_versioned_transaction(message, &all_signers).map_err(Box::new)?)
    }
}
