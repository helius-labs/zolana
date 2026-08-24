use anyhow::{anyhow, Result};
use solana_address::Address;
use zolana_transaction::{
    instructions::{transact::SppProofInputs, types::SppProofInputUtxo},
    Utxo, WalletUtxo,
};

use crate::{
    account_pda,
    shared::{external_data, zero_nullifier_key},
    state::{AccountState, AccountUtxo},
};

pub struct UpdateProofInputParams {
    pub authority: Address,
    pub current: WalletUtxo,
    pub new_value: u64,
    pub output_seed: [u8; 32],
}

pub struct UpdateTransfer {
    pub spp_proof_inputs: SppProofInputs,
    pub old_value: u64,
    pub old_blinding: [u8; 32],
    pub output: Utxo,
    pub output_hash: [u8; 32],
    pub input_nullifier: [u8; 32],
}

impl UpdateProofInputParams {
    pub fn to_proof_inputs(&self) -> Result<UpdateTransfer> {
        let pda = account_pda(&self.authority);
        let current_data = self
            .current
            .utxo
            .data
            .utxo_data()
            .ok_or_else(|| anyhow!("current UTXO has no state data"))?;
        let current_state = AccountState::decode(current_data)?;
        let account_utxo = AccountUtxo {
            pda,
            state: AccountState {
                address: current_state.address,
                authority: self.authority.to_bytes(),
                value: self.new_value,
            },
            output_seed: self.output_seed,
        };
        let output = account_utxo.output_utxo()?;
        let payload = account_utxo.plaintext_payload()?;
        let output_hash = output.hash()?;
        let external = external_data(output_hash, &pda, payload);
        let input = SppProofInputUtxo::new(self.current.utxo.clone(), zero_nullifier_key())
            .with_data_hash(
                self.current
                    .data_hash
                    .ok_or_else(|| anyhow!("missing current data hash"))?,
            );
        let spp_proof_inputs =
            SppProofInputs::new(vec![input], vec![output], external, self.authority);
        Ok(UpdateTransfer {
            spp_proof_inputs,
            old_value: current_state.value,
            old_blinding: self.current.utxo.blinding,
            output: account_utxo.utxo(),
            output_hash,
            input_nullifier: self.current.nullifier,
        })
    }
}
