use serde::Serialize;
use solana_address::Address;
use tsify::Tsify;
use spr_interface::instruction::instruction_data::transact::OwnerTag as TransactOwnerTag;
use spr_keypair::{serde_helpers::bytes::ByteArray, ShieldedAddress};
use spr_transaction::{
    instructions::transact::{self, SettlementTransfer},
    utxo::SppProofInputUtxo,
    SppProofOutputUtxo, WalletUtxo,
};

use crate::ClientError;
use crate::client::transaction::fail;

#[derive(Serialize, Tsify)]
#[serde(rename_all = "camelCase")]
pub struct ProgramProof {
    #[tsify(type = "[Uint8Array]")]
    pub public_inputs: [ByteArray<32>; 1],
    pub compressed_proof: crate::CompressedProof,
}

#[derive(Serialize, Tsify)]
#[serde(rename_all = "camelCase")]
#[tsify(hashmap_as_object, large_number_types_as_bigints)]
pub struct ProgramTransaction {
    pub finalized_tx: FinalizedTransaction,
    #[tsify(type = "Record<string, string>")]
    pub proof_inputs: std::collections::BTreeMap<String, String>,
    #[serde(with = "spr_keypair::serde_helpers::bytes")]
    #[tsify(type = "Uint8Array")]
    pub public_hash: [u8; 32],
}

impl TryFrom<&crate::ProgramTransaction> for ProgramTransaction {
    type Error = ClientError;

    fn try_from(transaction: &crate::ProgramTransaction) -> Result<Self, ClientError> {
        Ok(Self {
            finalized_tx: FinalizedTransaction::try_from(&transaction.finalized)?,
            proof_inputs: transaction.proof_inputs.encoded(),
            public_hash: transaction.public_hash,
        })
    }
}

#[derive(Serialize, Tsify)]
#[serde(rename_all = "camelCase")]
pub struct FinalizedTransaction {
    pub input_utxos: Vec<SppProofInputUtxo>,
    pub output_utxos: Vec<SppProofOutputUtxo>,
    #[tsify(type = "Uint8Array[]")]
    pub output_hashes: Vec<ByteArray<32>>,
    pub owner_tags: Vec<ResolvedOwnerTag>,
    pub interface_transfers: Vec<SettlementTransfer>,
    #[serde(with = "spr_keypair::serde_helpers::bytes")]
    #[tsify(type = "Uint8Array")]
    pub first_nullifier: [u8; 32],
    #[serde(with = "spr_keypair::serde_helpers::bytes")]
    #[tsify(type = "Uint8Array")]
    pub blinding_seed: [u8; 32],
    #[serde(with = "spr_keypair::serde_helpers::bytes")]
    #[tsify(type = "Uint8Array")]
    pub private_tx_blinding: [u8; 32],
    #[serde(with = "spr_keypair::serde_helpers::bytes")]
    #[tsify(type = "Uint8Array")]
    pub padding_independent_private_tx_hash: [u8; 32],
    pub output_tree_id: u16,
    #[serde(with = "spr_keypair::serde_helpers::address")]
    #[tsify(type = "string")]
    pub payer: Address,
    pub sender: ShieldedAddress,
}

impl TryFrom<&transact::FinalizedTransaction> for FinalizedTransaction {
    type Error = ClientError;

    fn try_from(finalized: &transact::FinalizedTransaction) -> Result<Self, ClientError> {
        Ok(Self {
            input_utxos: finalized.input_utxos().to_vec(),
            output_utxos: finalized.output_utxos().to_vec(),
            output_hashes: finalized
                .output_hashes()
                .map_err(fail)?
                .into_iter()
                .map(ByteArray::new)
                .collect(),
            owner_tags: finalized
                .owner_tags()
                .iter()
                .map(ResolvedOwnerTag::from)
                .collect(),
            interface_transfers: finalized.interface_transfers().to_vec(),
            first_nullifier: finalized
                .first_nullifier()
                .map_err(fail)?,
            blinding_seed: *finalized.blinding_seed(),
            private_tx_blinding: finalized
                .private_tx_blinding()
                .map_err(fail)?,
            padding_independent_private_tx_hash: finalized
                .padding_independent_private_tx_hash()
                .map_err(fail)?,
            output_tree_id: finalized.output_tree_id(),
            payer: finalized.payer(),
            sender: *finalized.sender(),
        })
    }
}

#[derive(Serialize, Tsify)]
#[tsify(large_number_types_as_bigints)]
pub struct DataUtxo<T> {
    pub utxo: WalletUtxo,
    pub data: T,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tsify(optional)]
    #[tsify(type = "Uint8Array")]
    pub address: Option<ByteArray<32>>,
}

impl<T> From<crate::DataUtxo<T>> for DataUtxo<T> {
    fn from(data_utxo: crate::DataUtxo<T>) -> Self {
        Self {
            utxo: data_utxo.utxo,
            data: data_utxo.data,
            address: data_utxo.address.map(ByteArray::new),
        }
    }
}

#[derive(Serialize, Tsify)]
pub struct ResolvedOwnerTag {
    pub tag: OwnerTag,
    #[serde(with = "spr_keypair::serde_helpers::bytes")]
    #[tsify(type = "Uint8Array")]
    pub resolved: [u8; 32],
}

impl From<&transact::ResolvedOwnerTag> for ResolvedOwnerTag {
    fn from(owner_tag: &transact::ResolvedOwnerTag) -> Self {
        Self {
            tag: match owner_tag.tag {
                TransactOwnerTag::Inline(value) => OwnerTag::Inline { value },
                TransactOwnerTag::Account(index) => OwnerTag::Account { index },
            },
            resolved: owner_tag.resolved,
        }
    }
}

#[derive(Serialize, Tsify)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum OwnerTag {
    Inline {
        #[serde(with = "spr_keypair::serde_helpers::bytes")]
        #[tsify(type = "Uint8Array")]
        value: [u8; 32],
    },
    Account {
        index: u8,
    },
}
