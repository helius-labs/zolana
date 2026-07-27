use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{tag, TransactIxData, TransactProof},
    PROGRAM_ID_PUBKEY,
};

/// Hetero hub: foreign policy proof + pure-shielded transact (tag 54).
pub struct ComposeTransact {
    pub foreign_vk: Pubkey,
    pub payer: Pubkey,
    pub input_tree: Pubkey,
    pub output_tree: Pubkey,
    pub signers: Vec<Pubkey>,
    pub foreign_public_input: [u8; 32],
    pub foreign_proof: TransactProof,
    pub transact: TransactIxData,
}

impl ComposeTransact {
    pub fn instruction(&self) -> Instruction {
        assert!(
            self.transact.interface_transfers.is_empty(),
            "compose_transact is pure shielded only"
        );
        let body = self
            .transact
            .serialize()
            .expect("transact serialization is infallible");
        let mut data = Vec::with_capacity(1 + 160 + body.len());
        data.push(tag::COMPOSE_TRANSACT);
        data.extend_from_slice(&self.foreign_public_input);
        data.extend_from_slice(&self.foreign_proof.a);
        data.extend_from_slice(&self.foreign_proof.b);
        data.extend_from_slice(&self.foreign_proof.c);
        data.extend_from_slice(&body);

        let mut accounts = vec![
            AccountMeta::new_readonly(self.foreign_vk, false),
            AccountMeta::new(self.payer, true),
            AccountMeta::new(self.input_tree, false),
            AccountMeta::new(self.output_tree, false),
            AccountMeta::new_readonly(Pubkey::default(), false),
        ];
        for s in &self.signers {
            accounts.push(AccountMeta::new_readonly(*s, true));
        }
        accounts.push(AccountMeta::new_readonly(PROGRAM_ID_PUBKEY, false));
        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts,
            data,
        }
    }
}

/// Build `compose_transact` instruction data (with tag).
pub fn compose_transact_ix_data(
    foreign_public_input: &[u8; 32],
    proof_a: &[u8; 32],
    proof_b: &[u8; 64],
    proof_c: &[u8; 32],
    transact_bytes: &[u8],
) -> Vec<u8> {
    let mut data = Vec::with_capacity(1 + 160 + transact_bytes.len());
    data.push(tag::COMPOSE_TRANSACT);
    data.extend_from_slice(foreign_public_input);
    data.extend_from_slice(proof_a);
    data.extend_from_slice(proof_b);
    data.extend_from_slice(proof_c);
    data.extend_from_slice(transact_bytes);
    data
}
