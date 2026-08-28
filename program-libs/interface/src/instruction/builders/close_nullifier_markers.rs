use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{
        builders::transact::append_nullifier_marker_accounts, encode_instruction, tag,
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
        append_nullifier_marker_accounts(&mut accounts, &self.tree, self.nullifiers.iter());

        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts,
            data: encode_instruction(tag::CLOSE_NULLIFIER_MARKERS, &data),
        }
    }
}

#[cfg(test)]
mod tests {
    use borsh::BorshDeserialize;

    use super::*;
    use crate::pda;

    #[test]
    fn tree_then_one_writable_marker_per_nullifier() {
        let tree = Pubkey::new_unique();
        let nullifiers = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        let builder = CloseNullifierMarkers {
            tree,
            nullifiers: nullifiers.clone(),
        };

        let ix = builder.instruction();
        assert_eq!(ix.program_id, PROGRAM_ID_PUBKEY);
        assert_eq!(ix.data.first(), Some(&tag::CLOSE_NULLIFIER_MARKERS));
        let decoded = CloseNullifierMarkersData::try_from_slice(&ix.data[1..]).unwrap();
        assert_eq!(decoded, CloseNullifierMarkersData { nullifiers });

        let expected: Vec<AccountMeta> = std::iter::once(AccountMeta::new(tree, false))
            .chain(builder.nullifiers.iter().map(|nullifier| {
                AccountMeta::new(pda::nullifier_marker(&tree, nullifier).0, false)
            }))
            .collect();
        assert_eq!(ix.accounts, expected);
        assert_eq!(ix.accounts.len(), 4);
        assert!(ix
            .accounts
            .iter()
            .all(|meta| meta.is_writable && !meta.is_signer));
    }

    #[test]
    fn empty_nullifiers_yields_only_the_tree() {
        let tree = Pubkey::new_unique();
        let ix = CloseNullifierMarkers {
            tree,
            nullifiers: Vec::new(),
        }
        .instruction();
        assert_eq!(ix.accounts, vec![AccountMeta::new(tree, false)]);
    }
}
