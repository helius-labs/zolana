use anyhow::{anyhow, Result};
use solana_address::Address;
use zolana_transaction::{
    instructions::{transact::SppProofInputs, types::SppProofInputUtxo},
    Utxo, WalletUtxo,
};

use crate::{
    account_pda,
    shared::{external_data, zero_nullifier_key},
    state::{decode_state, AccountState, AccountUtxo},
};

pub struct UpdateProofInputParams {
    pub authority: Address,
    pub current: WalletUtxo,
    pub new_value: u64,
}

pub struct UpdateCompressedAccount {
    pub spp_proof_inputs: SppProofInputs,
    pub old_value: u64,
    pub version: u64,
    pub output: Utxo,
    pub output_hash: [u8; 32],
    pub input_nullifier: [u8; 32],
}

impl UpdateProofInputParams {
    pub fn to_proof_inputs(&self) -> Result<UpdateCompressedAccount> {
        let pda = account_pda(&self.authority);
        let current_data = self
            .current
            .utxo
            .data
            .utxo_data()
            .ok_or_else(|| anyhow!("current UTXO has no state data"))?;
        let current_state = decode_state(current_data)?;
        if self.current.utxo.blinding != current_state.blinding() {
            return Err(anyhow!("current UTXO blinding does not match the version"));
        }
        let account_utxo = AccountUtxo {
            pda,
            state: AccountState {
                address: current_state.address,
                authority: self.authority.to_bytes(),
                value: self.new_value,
                version: current_state
                    .version
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("account version overflow"))?,
            },
        };
        let output = account_utxo.output_utxo()?;
        let payload = account_utxo.output_data()?;
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
        Ok(UpdateCompressedAccount {
            spp_proof_inputs,
            old_value: current_state.value,
            version: current_state.version,
            output: account_utxo.utxo()?,
            output_hash,
            input_nullifier: self.current.nullifier,
        })
    }
}
