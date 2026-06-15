//! Generic blocking Solana RPC backend.
//!
//! Wraps a `solana_rpc_client::RpcClient` and implements [`Rpc`] over
//! it. This backend carries no shielded-pool indexing knowledge; callers that
//! need indexed events build that on top using the raw client.

use std::{
    thread::sleep,
    time::{Duration, Instant},
};

use solana_address::Address;
use solana_account::Account;
use solana_commitment_config::CommitmentConfig;
use solana_hash::Hash;
use solana_pubkey::Pubkey;
use solana_rpc_client::rpc_client::RpcClient;
use solana_signature::Signature;
use solana_transaction::Transaction;

use crate::error::ClientError;
use crate::rpc::Rpc;

fn pubkey_from_address(address: &Address) -> Pubkey {
    Pubkey::new_from_array(address.to_bytes())
}

pub struct SolanaRpc {
    client: RpcClient,
    confirmation_timeout: Duration,
}

impl SolanaRpc {
    pub fn new(url: impl Into<String>) -> Self {
        Self::with_client(RpcClient::new_with_commitment(
            url.into(),
            CommitmentConfig::confirmed(),
        ))
    }

    pub fn with_client(client: RpcClient) -> Self {
        Self {
            client,
            confirmation_timeout: Duration::from_secs(30),
        }
    }

    pub fn client(&self) -> &RpcClient {
        &self.client
    }

    pub fn assert_executable(&self, program_id: &Pubkey) -> Result<(), ClientError> {
        let account = self
            .client
            .get_account(program_id)
            .map_err(|err| ClientError::Rpc(format!("get_account {program_id}: {err}")))?;
        if !account.executable {
            return Err(ClientError::Rpc(format!(
                "program is not executable: {program_id}"
            )));
        }
        Ok(())
    }

    pub fn airdrop(&mut self, pubkey: &Pubkey, lamports: u64) -> Result<Signature, ClientError> {
        let signature = self
            .client
            .request_airdrop(pubkey, lamports)
            .map_err(|err| ClientError::Rpc(format!("request_airdrop {pubkey}: {err}")))?;
        self.wait_for_signature(&signature)?;
        Ok(signature)
    }

    fn wait_for_signature(&self, signature: &Signature) -> Result<(), ClientError> {
        let started = Instant::now();
        while started.elapsed() < self.confirmation_timeout {
            let confirmed = self
                .client
                .confirm_transaction(signature)
                .map_err(|err| ClientError::Rpc(format!("confirm_transaction {signature}: {err}")))?;
            if confirmed {
                return Ok(());
            }
            sleep(Duration::from_millis(250));
        }
        Err(ClientError::Rpc(format!(
            "signature not confirmed: {signature}"
        )))
    }
}

impl Rpc for SolanaRpc {
    fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
        let pubkey = pubkey_from_address(&address);
        match self.client.get_account(&pubkey) {
            Ok(account) => Ok(Some(account)),
            Err(err) => Err(ClientError::Rpc(format!("get_account {pubkey}: {err}"))),
        }
    }

    fn get_minimum_balance_for_rent_exemption(
        &self,
        data_len: usize,
    ) -> Result<u64, ClientError> {
        self.client
            .get_minimum_balance_for_rent_exemption(data_len)
            .map_err(|err| {
                ClientError::Rpc(format!(
                    "get_minimum_balance_for_rent_exemption {data_len}: {err}"
                ))
            })
    }

    fn get_latest_blockhash(&self) -> Result<(Hash, u64), ClientError> {
        let blockhash = self
            .client
            .get_latest_blockhash()
            .map_err(|err| ClientError::Rpc(format!("get_latest_blockhash: {err}")))?;
        Ok((blockhash, 0))
    }

    fn send_transaction(&self, transaction: &Transaction) -> Result<Signature, ClientError> {
        self.client
            .send_and_confirm_transaction(transaction)
            .map_err(|err| ClientError::Rpc(format!("send_transaction: {err}")))
    }
}
