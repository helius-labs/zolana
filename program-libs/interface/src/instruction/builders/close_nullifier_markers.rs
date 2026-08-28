use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{
        builders::transact::nullifier_marker_accounts, encode_instruction, tag,
        CloseNullifierMarkersData,
    },
    PROGRAM_ID_PUBKEY,
};

pub struct CloseNullifierMarkers {
    pub tree: Pubkey,
    pub nullifiers: Vec<[u8; 32]>,
}

impl CloseNullifierMarkers {
    pub fn instruction(&self) -> Instruction {
        let data = CloseNullifierMarkersData {
            nullifiers: self.nullifiers.clone(),
        };

        let mut accounts = vec![AccountMeta::new(self.tree, false)];
        accounts.extend(nullifier_marker_accounts(
            &self.tree,
            self.nullifiers.iter(),
        ));

        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts,
            data: encode_instruction(tag::CLOSE_NULLIFIER_MARKERS, &data),
        }
    }
}
