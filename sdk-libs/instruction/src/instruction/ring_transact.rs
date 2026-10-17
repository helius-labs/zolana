use alloc::{vec, vec::Vec};
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use zolana_interface::{
    instruction::{tag, TransactIxData},
    pda, PROGRAM_ID_PUBKEY,
};

use super::transact::{
    append_cache_accounts, append_interface_transfer_accounts, transact_nullifier_pda_accounts,
    TransactInterfaceTransferAccounts,
};

/// Builder for the `ring_transact` instruction, the confidential policy-ring analog
/// of [`super::transact::Transact`]. The account layout mirrors the program
/// loader (`RingTransactAccounts::validate_and_parse`): `payer`, `output_tree`,
/// the SPP and System Program accounts, the `RingConfig` account (the ring's
/// `ring_auth` PDA), one input tree per declared tree context, then one writable nullifier PDA per input (in
/// `inputs` order), owner signers, then optional settlement accounts.
pub struct RingTransact {
    pub payer: Pubkey,
    /// One tree per `data.tree_contexts` entry, in the same order.
    pub input_trees: Vec<Pubkey>,
    pub output_tree: Pubkey,
    /// Calling ring program; its `RingConfig` (canonical `ring_auth` PDA) signs.
    pub ring_program_id: Pubkey,
    pub owner_signers: Vec<Pubkey>,
    pub interface_transfer_accounts: Vec<TransactInterfaceTransferAccounts>,
    pub data: TransactIxData,
}

impl RingTransact {
    /// Instruction sent to the ring program, which CPIs into SPP. The `ring_auth`
    /// PDA is not a transaction-level signer; the ring program signs for it in its
    /// CPI.
    pub fn instruction(&self) -> Instruction {
        self.build_instruction(self.ring_program_id, false)
    }

    /// The SPP instruction a ring program constructs for its own CPI: program id
    /// is SPP and the `ring_auth` PDA is passed as a signer.
    pub fn cpi_instruction(&self) -> Instruction {
        self.build_instruction(PROGRAM_ID_PUBKEY, true)
    }

    pub fn cpi_instruction_with_caches(
        &self,
        read_cache: Option<Pubkey>,
        write_cache: Option<(Pubkey, Pubkey)>,
    ) -> Instruction {
        let mut instruction = self.cpi_instruction();
        append_cache_accounts(&mut instruction.accounts, read_cache, write_cache);
        instruction
    }

    pub fn instruction_with_cache_read(&self, cache: Pubkey) -> Instruction {
        let mut instruction = self.instruction();
        append_cache_accounts(&mut instruction.accounts, Some(cache), None);
        instruction
    }

    pub fn instruction_with_cache_write(&self, cache: Pubkey, writer: Pubkey) -> Instruction {
        let mut instruction = self.instruction();
        append_cache_accounts(&mut instruction.accounts, None, Some((cache, writer)));
        instruction
    }

    pub fn instruction_with_caches(
        &self,
        read_cache: Pubkey,
        write_cache: Pubkey,
        writer: Pubkey,
    ) -> Instruction {
        let mut instruction = self.instruction();
        append_cache_accounts(
            &mut instruction.accounts,
            Some(read_cache),
            Some((write_cache, writer)),
        );
        instruction
    }

    fn build_instruction(&self, program_id: Pubkey, auth_signer: bool) -> Instruction {
        let ring_config = pda::ring_auth(&self.ring_program_id).0;

        let mut instruction_data = vec![tag::RING_TRANSACT];
        instruction_data.extend_from_slice(
            &self
                .data
                .serialize()
                .expect("shielded-pool instruction serialization is infallible"),
        );

        let mut accounts = vec![
            AccountMeta::new(self.payer, true),
            AccountMeta::new(self.output_tree, false),
            AccountMeta::new_readonly(PROGRAM_ID_PUBKEY, false),
            AccountMeta::new_readonly(Pubkey::default(), false),
            AccountMeta::new_readonly(ring_config, auth_signer),
        ];
        accounts.extend(
            self.input_trees
                .iter()
                .map(|input_tree| AccountMeta::new(*input_tree, false)),
        );
        accounts.extend(transact_nullifier_pda_accounts(
            &self.input_trees,
            self.data.inputs.iter(),
        ));
        accounts.extend(
            self.owner_signers
                .iter()
                .copied()
                .map(|signer| AccountMeta::new_readonly(signer, true)),
        );
        append_interface_transfer_accounts(
            &mut accounts,
            &self.data.interface_transfers,
            &self.interface_transfer_accounts,
        );
        Instruction {
            program_id,
            accounts,
            data: instruction_data,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zolana_interface::instruction::instruction_data::transact::{
        CircuitId, TransactProof, TreeContext,
    };

    fn builder() -> RingTransact {
        RingTransact {
            payer: Pubkey::new_unique(),
            input_trees: vec![Pubkey::new_unique()],
            output_tree: Pubkey::new_unique(),
            ring_program_id: Pubkey::new_unique(),
            owner_signers: Vec::new(),
            interface_transfer_accounts: Vec::new(),
            data: TransactIxData {
                proof: TransactProof::zeroed(),
                expiry_unix_ts: u64::MAX,
                private_tx_hash: [0u8; 32],
                circuit: CircuitId::RingEddsa(0, 0, 3),
                tx_viewing_pk: [0u8; 33],
                salt: [0u8; 16],
                inputs: Vec::new(),
                interface_transfers: Vec::new(),
                data_hash: None,
                ring_data_hash: None,
                outputs: Vec::new(),
                messages: Vec::new(),
                tree_contexts: vec![TreeContext {
                    utxo_tree_root_index: 0,
                    nullifier_tree_root_index: 0,
                }],
            },
        }
    }

    #[test]
    fn cache_write_targets_the_ring_program_with_writable_cache_then_writer() {
        let builder = builder();
        let cache = Pubkey::new_unique();
        let writer = Pubkey::new_unique();
        let ix = builder.instruction_with_cache_write(cache, writer);
        let mut expected = builder.instruction().accounts;
        expected.push(AccountMeta::new(cache, false));
        expected.push(AccountMeta::new_readonly(writer, true));
        assert_eq!(ix.program_id, builder.ring_program_id);
        assert_eq!(ix.accounts, expected);
    }

    #[test]
    fn cache_read_targets_the_ring_program_with_read_only_cache() {
        let builder = builder();
        let cache = Pubkey::new_unique();
        let ix = builder.instruction_with_cache_read(cache);
        let mut expected = builder.instruction().accounts;
        expected.push(AccountMeta::new_readonly(cache, false));
        assert_eq!(ix.program_id, builder.ring_program_id);
        assert_eq!(ix.accounts, expected);
    }

    #[test]
    fn caches_forward_through_the_ring_program_and_its_cpi() {
        let builder = builder();
        let read_cache = Pubkey::new_unique();
        let write_cache = Pubkey::new_unique();
        let writer = Pubkey::new_unique();
        let tail = [
            AccountMeta::new_readonly(read_cache, false),
            AccountMeta::new(write_cache, false),
            AccountMeta::new_readonly(writer, true),
        ];
        let ix = builder.instruction_with_caches(read_cache, write_cache, writer);
        let mut expected = builder.instruction().accounts;
        expected.extend(tail.clone());
        assert_eq!(ix.program_id, builder.ring_program_id);
        assert_eq!(ix.accounts, expected);

        let cpi =
            builder.cpi_instruction_with_caches(Some(read_cache), Some((write_cache, writer)));
        let mut expected = builder.cpi_instruction().accounts;
        expected.extend(tail);
        assert_eq!(cpi.program_id, PROGRAM_ID_PUBKEY);
        assert_eq!(cpi.accounts, expected);
    }
}
