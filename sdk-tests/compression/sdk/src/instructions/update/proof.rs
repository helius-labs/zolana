use anyhow::{anyhow, Result};
use solana_address::Address;
use zolana_program::compression::{
    CompressedAccount, CompressedAccountMeta, PdaOwner, ACCOUNT_BLINDING_SEED,
};
use zolana_transaction::{
    instructions::transact::SppProofInputs, utxo::SppProofInputUtxo, Utxo, WalletUtxo,
};

use crate::{
    account_pda, err,
    shared::{external_data, ProgramTransaction, UNPROVEN_TREE_CONTEXT},
    state::{decode_state, AccountUtxo},
};

pub struct UpdateProofInputParams {
    pub authority: Address,
    pub current: WalletUtxo,
    pub new_value: u64,
    /// Raw id of the tree the new state is appended to, which may differ from
    /// the tree `current` is spent from.
    pub output_tree_id: u16,
}

pub struct UpdateCompressedAccount {
    pub spp_proof_inputs: SppProofInputs,
    /// The current UTXO's meta. Its root indexes are placeholders until the
    /// transaction is proven, which picks the roots.
    pub meta: CompressedAccountMeta,
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
        if self.current.utxo.blinding != current_state.blinding {
            return Err(anyhow!("current UTXO blinding does not match its state"));
        }
        let version = current_state
            .version
            .checked_add(1)
            .ok_or_else(|| anyhow!("account version overflow"))?;
        let owner = PdaOwner::new(&pda).map_err(err)?;
        let meta = CompressedAccountMeta {
            address: current_state.address,
            blinding: current_state.blinding,
            tree_context: UNPROVEN_TREE_CONTEXT,
        };
        let mut account = CompressedAccount::new_mut(
            &owner,
            &meta,
            current_state.clone(),
            self.current.tree_id(),
        )
        .map_err(err)?;
        if *account.input_nullifier() != self.current.nullifier {
            return Err(anyhow!("current UTXO nullifier does not match its state"));
        }
        account.value = self.new_value;
        account.version = version;
        let program = ProgramTransaction::build(&pda, account, self.output_tree_id)?;
        let external = external_data(program.output_hash, &pda, program.output_data.clone());
        let account_utxo = AccountUtxo {
            pda,
            state: program.state,
        };
        let output = account_utxo.output_utxo()?;
        let output_hash = program.output_hash;
        if output.hash(self.output_tree_id)? != output_hash {
            return Err(anyhow!("client output does not match the program's output"));
        }
        self.current
            .data_hash
            .ok_or_else(|| anyhow!("missing current data hash"))?;
        let input = SppProofInputUtxo::from(&self.current);
        let spp_proof_inputs = SppProofInputs {
            input_utxos: vec![input],
            output_utxos: vec![output],
            external_data: external,
            payer: self.authority,
            blinding_seed: ACCOUNT_BLINDING_SEED,
            output_tree_id: self.output_tree_id,
            cache_accounts: Default::default(),
            program_signers: Vec::new(),
        };
        Ok(UpdateCompressedAccount {
            spp_proof_inputs,
            meta,
            old_value: current_state.value,
            version: current_state.version,
            output: account_utxo.utxo()?,
            output_hash,
            input_nullifier: self.current.nullifier,
        })
    }
}
