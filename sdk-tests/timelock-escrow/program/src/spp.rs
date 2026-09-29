use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};
use zolana_interface::{
    instruction::instruction_data::transact::{
        CircuitId, InputUtxo, OwnerTag, TransactIxData, TransactOutput, TransactProof, TreeContext,
    },
    N_PUBLIC_SLOTS,
};

#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct ProvenOutput {
    pub utxo_hash: [u8; 32],
    #[wincode(with = "Option<containers::Vec<u8, FixIntLen<u16>>>")]
    pub data: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct ProvenTransact<const IN: usize, const OUT: usize> {
    pub proof: TransactProof,
    pub private_tx_hash: [u8; 32],
    pub expiry_unix_ts: u64,
    pub tx_viewing_pk: [u8; 33],
    pub salt: [u8; 16],
    pub inputs: [InputUtxo; IN],
    #[wincode(with = "containers::Vec<TreeContext, FixIntLen<u8>>")]
    pub tree_contexts: Vec<TreeContext>,
    pub outputs: [ProvenOutput; OUT],
}

impl<const IN: usize, const OUT: usize> ProvenTransact<IN, OUT> {
    pub const CIRCUIT: CircuitId =
        CircuitId::ConfidentialEddsa(IN as u8, OUT as u8, N_PUBLIC_SLOTS as u8);

    pub fn into_ix_data(self, owner_tags: [[u8; 32]; OUT]) -> TransactIxData {
        let outputs = self
            .outputs
            .into_iter()
            .zip(owner_tags)
            .map(|(output, owner_tag)| TransactOutput {
                utxo_hash: output.utxo_hash,
                owner_tag: OwnerTag::Inline(owner_tag),
                data: output.data,
            })
            .collect();
        TransactIxData {
            expiry_unix_ts: self.expiry_unix_ts,
            tx_viewing_pk: self.tx_viewing_pk,
            salt: self.salt,
            interface_transfers: Vec::new(),
            data_hash: None,
            ring_data_hash: None,
            outputs,
            messages: Vec::new(),
            private_tx_hash: self.private_tx_hash,
            circuit: Self::CIRCUIT,
            proof: self.proof,
            inputs: self.inputs.to_vec(),
            tree_contexts: self.tree_contexts,
        }
    }
}
