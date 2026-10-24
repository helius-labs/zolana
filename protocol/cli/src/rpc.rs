use anyhow::{bail, Result};
use solana_account::Account;
use solana_address::Address;
use solana_commitment_config::CommitmentConfig;
use solana_instruction::Instruction;
use solana_rpc_client::rpc_client::RpcClient;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_protocol_transaction::{compile_message, sign_transaction, ComputeBudgetConfig};

pub struct SolanaRpc(RpcClient);
impl SolanaRpc {
    pub fn new(url: String) -> Self {
        Self(RpcClient::new_with_commitment(
            url,
            CommitmentConfig::confirmed(),
        ))
    }
    pub fn get_minimum_balance_for_rent_exemption(&self, size: usize) -> Result<u64> {
        Ok(self.0.get_minimum_balance_for_rent_exemption(size)?)
    }
    pub fn get_account(&self, address: Address) -> Result<Option<Account>> {
        Ok(self
            .0
            .get_account_with_commitment(&address, CommitmentConfig::confirmed())?
            .value)
    }
    pub fn assert_executable(&self, address: &Address) -> Result<()> {
        if !self.0.get_account(address)?.executable {
            bail!("program is not executable: {address}");
        }
        Ok(())
    }
    pub fn airdrop(&mut self, address: &Address, lamports: u64) -> Result<Signature> {
        let signature = self.0.request_airdrop(address, lamports)?;
        self.0.poll_for_signature_confirmation(&signature, 1)?;
        Ok(signature)
    }
    pub fn create_and_send_transaction(
        &self,
        instructions: &[Instruction],
        payer: Address,
        signers: &[&dyn Signer],
        budget: ComputeBudgetConfig,
    ) -> Result<Signature> {
        let message =
            compile_message(&payer, instructions, self.0.get_latest_blockhash()?, budget)?;
        Ok(self
            .0
            .send_and_confirm_transaction(&sign_transaction(message, signers)?)?)
    }
}
