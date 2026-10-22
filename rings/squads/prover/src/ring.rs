use std::collections::HashMap;

use zolana_gnark_ffi_prover::{decimal, ProofInputMap};

use crate::{prove, CircuitId, Error, Result, SquadsProof};

/// Supported `(n_inputs, n_outputs)` shapes: the `(1, 1)` withdrawal and the
/// `(2, 2)` transfer.
pub const RING_SUPPORTED_SHAPES: [(u8, u8); 2] = [(1, 1), (2, 2)];

/// One transaction slot (`ringutils.Utxo`), every value a 32-byte big-endian
/// field element.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RingUtxoProofInput {
    pub domain: [u8; 32],
    pub tree_id: [u8; 32],
    pub owner_hash: [u8; 32],
    pub asset: [u8; 32],
    pub amount: [u8; 32],
    pub blinding: [u8; 32],
    pub program_data_hash: [u8; 32],
    pub ring_data_hash: [u8; 32],
    pub ring_program_id: [u8; 32],
}

/// The sender's viewing key account. `shared_viewing_secret_key` is the
/// raw 32-byte X25519 secret.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SenderProofInput {
    pub owner: [u8; 32],
    pub shared_viewing_secret_key_commitment: [u8; 32],
    pub nullifier_pubkey: [u8; 32],
    pub nullifier_secret: [u8; 32],
    pub shared_viewing_secret_key: [u8; 32],
}

/// A transfer's recipient; all zero on the withdrawal shape. `viewing_pubkey`
/// is the tagged canonical X25519 public key `0x04 || u`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientProofInput {
    pub owner: [u8; 32],
    pub nullifier_pubkey: [u8; 32],
    pub viewing_pubkey: [u8; 33],
}

impl Default for RecipientProofInput {
    fn default() -> Self {
        Self {
            owner: [0u8; 32],
            nullifier_pubkey: [0u8; 32],
            viewing_pubkey: [0u8; 33],
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProposalProofInput {
    pub amount: [u8; 32],
    pub recipient: [u8; 32],
    pub blinding: [u8; 32],
    pub public_amount: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RingProofInputs {
    pub inputs: Vec<RingUtxoProofInput>,
    pub outputs: Vec<RingUtxoProofInput>,
    pub external_data_hash: [u8; 32],
    pub sender: SenderProofInput,
    pub recipient: RecipientProofInput,
    pub proposal: ProposalProofInput,
    pub enable_proposal_hash: bool,
    pub public_amount: [u8; 32],
    pub public_input_hash: [u8; 32],
}

impl RingProofInputs {
    pub fn circuit(&self) -> Result<CircuitId> {
        match (self.inputs.len(), self.outputs.len()) {
            (1, 1) => Ok(CircuitId::Ring1x1),
            (2, 2) => Ok(CircuitId::Ring2x2),
            (inputs, outputs) => Err(Error::UnsupportedShape(inputs, outputs)),
        }
    }

    fn witness(&self) -> ProofInputMap {
        let mut map = HashMap::new();
        for (slots, name) in [(&self.inputs, "Inputs"), (&self.outputs, "Outputs")] {
            for (index, utxo) in slots.iter().enumerate() {
                utxo_entries(&mut map, &format!("Transaction_{name}_{index}"), utxo);
            }
        }
        let enable_proposal_hash = if self.enable_proposal_hash { 1 } else { 0 };
        let scalars: [(&str, &[u8; 32]); 13] = [
            ("Transaction_ExternalDataHash", &self.external_data_hash),
            ("Sender_Account_Public_Owner", &self.sender.owner),
            (
                "Sender_Account_Public_SharedViewingSecretKeyCommitment",
                &self.sender.shared_viewing_secret_key_commitment,
            ),
            (
                "Sender_Account_Public_NullifierPubkey",
                &self.sender.nullifier_pubkey,
            ),
            (
                "Sender_Account_Private_NullifierSecret",
                &self.sender.nullifier_secret,
            ),
            ("Recipient_Owner", &self.recipient.owner),
            (
                "Recipient_NullifierPubkey",
                &self.recipient.nullifier_pubkey,
            ),
            ("Proposal_Amount", &self.proposal.amount),
            ("Proposal_Recipient", &self.proposal.recipient),
            ("Proposal_Blinding", &self.proposal.blinding),
            ("Proposal_PublicAmount", &self.proposal.public_amount),
            ("PublicAmount", &self.public_amount),
            ("PublicInputHash", &self.public_input_hash),
        ];
        for (key, value) in scalars {
            map.insert(key.to_string(), vec![decimal(value)]);
        }
        map.insert(
            "EnableProposalHash".to_string(),
            vec![enable_proposal_hash.to_string()],
        );
        map.insert(
            "Sender_Account_Private_SharedViewingSecretKey".to_string(),
            self.sender
                .shared_viewing_secret_key
                .iter()
                .map(u8::to_string)
                .collect(),
        );
        map.insert(
            "Recipient_ViewingPubkey".to_string(),
            self.recipient
                .viewing_pubkey
                .iter()
                .map(u8::to_string)
                .collect(),
        );
        map
    }

    pub fn prove(&self) -> Result<SquadsProof> {
        prove(self.circuit()?, &self.witness())
    }
}

fn utxo_entries(map: &mut ProofInputMap, prefix: &str, utxo: &RingUtxoProofInput) {
    let fields: [(&str, &[u8; 32]); 9] = [
        ("Domain", &utxo.domain),
        ("TreeID", &utxo.tree_id),
        ("OwnerHash", &utxo.owner_hash),
        ("Asset", &utxo.asset),
        ("Amount", &utxo.amount),
        ("Blinding", &utxo.blinding),
        ("ProgramDataHash", &utxo.program_data_hash),
        ("RingDataHash", &utxo.ring_data_hash),
        ("RingProgramID", &utxo.ring_program_id),
    ];
    for (field, value) in fields {
        map.insert(format!("{prefix}_{field}"), vec![decimal(value)]);
    }
}
