use serde::{Deserialize, Serialize};
use solana_address::Address;
use tsify::Tsify;
use zolana_interface::instruction::instruction_data::transact::OwnerTag as TransactOwnerTag;
use zolana_keypair::{serde_helpers::bytes::ByteArray, ShieldedAddress};
use zolana_transaction::{
    instructions::transact::{self, SettlementTransfer},
    utxo::SppProofInputUtxo,
    SppProofOutputUtxo,
};

use crate::{ProofResult, RelationError};

#[derive(Serialize, Tsify)]
#[serde(rename_all = "camelCase")]
pub struct ProgramTransaction {
    pub finalized_tx: FinalizedTransaction,
    #[serde(with = "zolana_keypair::serde_helpers::bytes")]
    #[tsify(type = "Uint8Array")]
    pub proof_inputs: Vec<u8>,
    #[serde(with = "zolana_keypair::serde_helpers::bytes")]
    #[tsify(type = "Uint8Array")]
    pub public_hash: [u8; 32],
}

impl TryFrom<&crate::ProgramTransaction> for ProgramTransaction {
    type Error = RelationError;

    fn try_from(transaction: &crate::ProgramTransaction) -> Result<Self, RelationError> {
        Ok(Self {
            finalized_tx: FinalizedTransaction::try_from(&transaction.finalized)?,
            proof_inputs: transaction.proof_inputs.to_bytes()?,
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
    #[serde(with = "zolana_keypair::serde_helpers::bytes")]
    #[tsify(type = "Uint8Array")]
    pub first_nullifier: [u8; 32],
    #[serde(with = "zolana_keypair::serde_helpers::bytes")]
    #[tsify(type = "Uint8Array")]
    pub blinding_seed: [u8; 32],
    #[serde(with = "zolana_keypair::serde_helpers::bytes")]
    #[tsify(type = "Uint8Array")]
    pub private_tx_blinding: [u8; 32],
    #[serde(with = "zolana_keypair::serde_helpers::bytes")]
    #[tsify(type = "Uint8Array")]
    pub padding_independent_private_tx_hash: [u8; 32],
    pub output_tree_id: u16,
    #[serde(with = "zolana_keypair::serde_helpers::address")]
    #[tsify(type = "string")]
    pub payer: Address,
    pub sender: ShieldedAddress,
    pub padding_owner: ShieldedAddress,
}

impl TryFrom<&transact::FinalizedTransaction> for FinalizedTransaction {
    type Error = RelationError;

    fn try_from(finalized: &transact::FinalizedTransaction) -> Result<Self, RelationError> {
        Ok(Self {
            input_utxos: finalized.input_utxos().to_vec(),
            output_utxos: finalized.output_utxos().to_vec(),
            output_hashes: finalized
                .output_hashes()
                .map_err(RelationError::spp)?
                .into_iter()
                .map(ByteArray::new)
                .collect(),
            owner_tags: finalized
                .owner_tags()
                .iter()
                .map(ResolvedOwnerTag::from)
                .collect(),
            interface_transfers: finalized.interface_transfers().to_vec(),
            first_nullifier: finalized.first_nullifier().map_err(RelationError::spp)?,
            blinding_seed: *finalized.blinding_seed(),
            private_tx_blinding: finalized
                .private_tx_blinding()
                .map_err(RelationError::spp)?,
            padding_independent_private_tx_hash: finalized
                .padding_independent_private_tx_hash()
                .map_err(RelationError::spp)?,
            output_tree_id: finalized.output_tree_id(),
            payer: finalized.payer(),
            sender: *finalized.sender(),
            padding_owner: *finalized.padding_owner(),
        })
    }
}

#[derive(Serialize, Tsify)]
pub struct ResolvedOwnerTag {
    pub tag: OwnerTag,
    #[serde(with = "zolana_keypair::serde_helpers::bytes")]
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
        #[serde(with = "zolana_keypair::serde_helpers::bytes")]
        #[tsify(type = "Uint8Array")]
        value: [u8; 32],
    },
    Account {
        index: u8,
    },
}

#[derive(Serialize, Deserialize, Tsify)]
#[serde(rename_all = "camelCase")]
pub struct ProgramProof {
    pub proof: Groth16Proof,
    pub compressed_proof: CompressedGroth16Proof,
    #[serde(with = "zolana_keypair::serde_helpers::bytes")]
    #[tsify(type = "Uint8Array")]
    pub public_hash: [u8; 32],
}

impl TryFrom<&ProofResult> for ProgramProof {
    type Error = RelationError;

    fn try_from(result: &ProofResult) -> Result<Self, RelationError> {
        let compressed = result.compressed()?;
        Ok(Self {
            proof: Groth16Proof {
                a: result.proof.a,
                b: result.proof.b,
                c: result.proof.c,
            },
            compressed_proof: CompressedGroth16Proof {
                a: compressed.a,
                b: compressed.b,
                c: compressed.c,
            },
            public_hash: result.public_hash,
        })
    }
}

#[derive(Serialize, Deserialize, Tsify)]
pub struct Groth16Proof {
    #[serde(with = "zolana_keypair::serde_helpers::bytes")]
    #[tsify(type = "Uint8Array")]
    pub a: [u8; 64],
    #[serde(with = "zolana_keypair::serde_helpers::bytes")]
    #[tsify(type = "Uint8Array")]
    pub b: [u8; 128],
    #[serde(with = "zolana_keypair::serde_helpers::bytes")]
    #[tsify(type = "Uint8Array")]
    pub c: [u8; 64],
}

#[derive(Serialize, Deserialize, Tsify)]
pub struct CompressedGroth16Proof {
    #[serde(with = "zolana_keypair::serde_helpers::bytes")]
    #[tsify(type = "Uint8Array")]
    pub a: [u8; 32],
    #[serde(with = "zolana_keypair::serde_helpers::bytes")]
    #[tsify(type = "Uint8Array")]
    pub b: [u8; 64],
    #[serde(with = "zolana_keypair::serde_helpers::bytes")]
    #[tsify(type = "Uint8Array")]
    pub c: [u8; 32],
}
