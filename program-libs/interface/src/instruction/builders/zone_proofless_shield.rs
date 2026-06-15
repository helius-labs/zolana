use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use super::sol_interface_pda;
use crate::{
    instruction::{tag, ZoneProoflessShieldIxData},
    SHIELDED_POOL_PROGRAM_ID,
};

impl ZoneProoflessShieldIxData {
    pub fn instruction(
        &self,
        zone_program_id: Pubkey,
        zone_auth: Pubkey,
        tree: Pubkey,
        depositor: Pubkey,
    ) -> Instruction {
        self.build_instruction(zone_program_id, zone_auth, tree, depositor, false)
    }

    pub fn cpi_instruction(
        &self,
        zone_auth: Pubkey,
        tree: Pubkey,
        depositor: Pubkey,
    ) -> Instruction {
        self.build_instruction(
            Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
            zone_auth,
            tree,
            depositor,
            true,
        )
    }

    fn build_instruction(
        &self,
        program_id: Pubkey,
        zone_auth: Pubkey,
        tree: Pubkey,
        depositor: Pubkey,
        zone_auth_signer: bool,
    ) -> Instruction {
        let mut data = vec![tag::ZONE_PROOFLESS_SHIELD];
        data.extend_from_slice(
            &self
                .serialize()
                .expect("zone proofless ix data serialization is infallible"),
        );

        Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(tree, false),
                AccountMeta::new(depositor, true),
                AccountMeta::new_readonly(zone_auth, zone_auth_signer),
                AccountMeta::new_readonly(Pubkey::default(), false),
                AccountMeta::new(sol_interface_pda(), false),
                AccountMeta::new(depositor, false),
                AccountMeta::new_readonly(Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID), false),
            ],
            data,
        }
    }
}
