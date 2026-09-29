use anyhow::{anyhow, bail, Result};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use timelock_escrow_program::spp::{ProvenOutput, ProvenTransact};
use zolana_interface::{
    instruction::instruction_data::transact::{InputUtxo, OwnerTag, TransactIxData},
    pda, PROGRAM_ID_PUBKEY,
};
use zolana_program::instruction::transact_nullifier_pda_accounts;

use super::BuiltTransaction;

#[derive(Clone)]
pub struct ProvenTransaction<const IN: usize, const OUT: usize> {
    built: BuiltTransaction<IN, OUT>,
    ix: TransactIxData,
}

impl<const IN: usize, const OUT: usize> BuiltTransaction<IN, OUT> {
    pub fn accept(self, ix: TransactIxData) -> Result<ProvenTransaction<IN, OUT>> {
        if ix.private_tx_hash != *self.private_tx_hash() {
            bail!("the SPP proof binds another private tx hash than the built transaction");
        }
        if ix.inputs.len() != IN || ix.outputs.len() != OUT {
            bail!(
                "the SPP proof is {}x{}, the built transaction {IN}x{OUT}",
                ix.inputs.len(),
                ix.outputs.len()
            );
        }
        for (slot, (input, nullifier)) in ix.inputs.iter().zip(self.input_nullifiers()).enumerate()
        {
            if input.nullifier_hash != *nullifier {
                bail!("input slot {slot}: the SPP proof spends another nullifier");
            }
        }
        let external_data = self.external_data();
        if ix.expiry_unix_ts != external_data.expiry_unix_ts {
            bail!("the SPP proof carries another expiry than the built transaction");
        }
        if ix.tx_viewing_pk != external_data.tx_viewing_pk || ix.salt != external_data.salt {
            bail!(
                "the SPP proof carries another encryption key or salt than the built transaction"
            );
        }
        for (slot, (output, built)) in ix.outputs.iter().zip(&external_data.outputs).enumerate() {
            if output.utxo_hash != built.utxo_hash {
                bail!("output slot {slot}: the SPP proof appends another utxo");
            }
            if output.data != built.data {
                bail!("output slot {slot}: the SPP proof publishes another ciphertext");
            }
        }
        Ok(ProvenTransaction { built: self, ix })
    }
}

impl<const IN: usize, const OUT: usize> ProvenTransaction<IN, OUT> {
    pub fn built(&self) -> &BuiltTransaction<IN, OUT> {
        &self.built
    }

    pub fn ix_data(&self) -> &TransactIxData {
        &self.ix
    }

    pub fn transact(&self, owner_tags: [[u8; 32]; OUT]) -> Result<ProvenTransact<IN, OUT>> {
        let ix = &self.ix;
        if ix.circuit != ProvenTransact::<IN, OUT>::CIRCUIT {
            bail!(
                "the SPP proof uses circuit {:?}, the program sets {:?}",
                ix.circuit,
                ProvenTransact::<IN, OUT>::CIRCUIT
            );
        }
        if !ix.interface_transfers.is_empty() {
            bail!("the program sets no interface transfers");
        }
        if ix.data_hash.is_some() || ix.ring_data_hash.is_some() {
            bail!("the program sets no transaction data hashes");
        }
        if !ix.messages.is_empty() {
            bail!("the program sets no messages");
        }
        for (slot, (output, owner_tag)) in ix.outputs.iter().zip(owner_tags.iter()).enumerate() {
            if output.owner_tag != OwnerTag::Inline(*owner_tag) {
                bail!(
                    "output slot {slot}: the SPP proof tags {:?}, the program assigns {:?}",
                    output.owner_tag,
                    Address::new_from_array(*owner_tag)
                );
            }
        }
        let inputs: [InputUtxo; IN] = ix
            .inputs
            .clone()
            .try_into()
            .map_err(|_| anyhow!("the SPP proof does not have {IN} inputs"))?;
        let outputs: [ProvenOutput; OUT] = ix
            .outputs
            .iter()
            .map(|output| ProvenOutput {
                utxo_hash: output.utxo_hash,
                data: output.data.clone(),
            })
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| anyhow!("the SPP proof does not have {OUT} outputs"))?;
        let transact = ProvenTransact {
            proof: ix.proof,
            private_tx_hash: ix.private_tx_hash,
            expiry_unix_ts: ix.expiry_unix_ts,
            tx_viewing_pk: ix.tx_viewing_pk,
            salt: ix.salt,
            inputs,
            tree_contexts: ix.tree_contexts.clone(),
            outputs,
        };
        if transact.clone().into_ix_data(owner_tags) != *ix {
            bail!("the program would build another transact than the SPP proof");
        }
        Ok(transact)
    }

    pub fn spp_accounts(&self, program_signers: &[Address]) -> Result<Vec<AccountMeta>> {
        let owner_signers = self.built.owner_signers()?;
        if program_signers != owner_signers.as_slice() {
            bail!(
                "the SPP proof commits to the owner signers {owner_signers:?}, the instruction passes {program_signers:?}"
            );
        }
        let input_trees: Vec<Address> = self
            .built
            .input_tree_ids()
            .into_iter()
            .map(pda::tree)
            .collect();
        if input_trees.len() != self.ix.tree_contexts.len() {
            bail!(
                "the SPP proof declares {} input trees, the inputs spend from {}",
                self.ix.tree_contexts.len(),
                input_trees.len()
            );
        }
        if let Some(input) = self
            .ix
            .inputs
            .iter()
            .find(|input| usize::from(input.tree_index) >= input_trees.len())
        {
            bail!("an input selects tree index {}", input.tree_index);
        }
        let mut accounts = vec![
            AccountMeta::new(*self.built.payer(), true),
            AccountMeta::new(pda::tree(self.built.output_tree_id()), false),
            AccountMeta::new_readonly(PROGRAM_ID_PUBKEY, false),
            AccountMeta::new_readonly(Address::default(), false),
        ];
        accounts.extend(
            input_trees
                .iter()
                .map(|input_tree| AccountMeta::new(*input_tree, false)),
        );
        accounts.extend(transact_nullifier_pda_accounts(
            &input_trees,
            self.ix.inputs.iter(),
        ));
        accounts.extend(
            program_signers
                .iter()
                .map(|signer| AccountMeta::new_readonly(*signer, false)),
        );
        Ok(accounts)
    }
}

pub fn program_instruction(
    program_id: Address,
    tag: u8,
    data: &[u8],
    accounts: Vec<AccountMeta>,
) -> Instruction {
    let mut instruction_data = Vec::with_capacity(1 + data.len());
    instruction_data.push(tag);
    instruction_data.extend_from_slice(data);
    Instruction {
        program_id,
        accounts,
        data: instruction_data,
    }
}
