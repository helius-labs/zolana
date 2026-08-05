use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{
        builders::transact::append_interface_transfer_accounts,
        instruction_data::aggregate_transact::AggregateTransactIxData, tag,
        TransactInterfaceTransferAccounts,
    },
    pda, PROGRAM_ID_PUBKEY,
};

/// Builder for `aggregate_transact`.
///
/// Each leg gets its own account run. The run is `payer`, `input_tree`,
/// `output_tree`, the SPP and System Program accounts, the `RingConfig`
/// account, then the leg's owner signers and settlement account groups. The
/// program splits the list by the counts in the data, so the order here must
/// match the leg order.
pub struct AggregateTransact {
    pub payer: Pubkey,
    pub input_tree: Pubkey,
    pub output_tree: Pubkey,
    /// One entry per leg, in leg order. Ignored on the confidential rail,
    /// which has no ring config account.
    pub ring_program_ids: Vec<Pubkey>,
    /// Owner signers per leg, in leg order.
    pub owner_signers: Vec<Vec<Pubkey>>,
    /// Settlement account groups per leg, in leg order.
    pub interface_transfer_accounts: Vec<Vec<TransactInterfaceTransferAccounts>>,
    pub data: AggregateTransactIxData,
}

impl AggregateTransact {
    /// Instruction sent to the ring program, which CPIs into SPP. The
    /// confidential rail has no ring program, so it goes straight to SPP.
    pub fn instruction(&self) -> Instruction {
        if !self.data.circuit.kind.is_ring() {
            return self.build_instruction(PROGRAM_ID_PUBKEY, false);
        }
        self.build_instruction(
            *self
                .ring_program_ids
                .first()
                .expect("aggregate batch has at least one leg"),
            false,
        )
    }

    /// The SPP instruction a ring program constructs for its own CPI.
    pub fn cpi_instruction(&self) -> Instruction {
        self.build_instruction(PROGRAM_ID_PUBKEY, true)
    }

    /// Data with `leg_account_counts` filled, and the SPP account list. A
    /// calling program needs both to forward a batch under its own accounts.
    pub fn cpi_parts(&self) -> (AggregateTransactIxData, Vec<AccountMeta>) {
        self.resolve(true)
    }

    fn build_instruction(&self, program_id: Pubkey, auth_signer: bool) -> Instruction {
        let (data, accounts) = self.resolve(auth_signer);

        let mut instruction_data = vec![tag::AGGREGATE_TRANSACT];
        instruction_data.extend_from_slice(
            &data
                .serialize()
                .expect("shielded-pool instruction serialization is infallible"),
        );

        Instruction {
            program_id,
            accounts,
            data: instruction_data,
        }
    }

    fn resolve(&self, auth_signer: bool) -> (AggregateTransactIxData, Vec<AccountMeta>) {
        assert_eq!(
            self.ring_program_ids.len(),
            self.data.legs.len(),
            "one ring program id per leg"
        );
        assert_eq!(
            self.owner_signers.len(),
            self.data.legs.len(),
            "one owner signer group per leg"
        );
        assert_eq!(
            self.interface_transfer_accounts.len(),
            self.data.legs.len(),
            "one settlement account group per leg"
        );

        let mut data = self.data.clone();
        let mut accounts = Vec::new();
        data.leg_account_counts = Vec::with_capacity(self.ring_program_ids.len());

        for (index, ring_program_id) in self.ring_program_ids.iter().enumerate() {
            let before = accounts.len();
            accounts.extend([
                AccountMeta::new(self.payer, true),
                AccountMeta::new(self.input_tree, false),
                AccountMeta::new(self.output_tree, false),
                AccountMeta::new_readonly(PROGRAM_ID_PUBKEY, false),
                AccountMeta::new_readonly(Pubkey::default(), false),
            ]);
            if self.data.circuit.kind.is_ring() {
                accounts.push(AccountMeta::new_readonly(
                    pda::ring_auth(ring_program_id).0,
                    auth_signer,
                ));
            }
            accounts.extend(
                self.owner_signers[index]
                    .iter()
                    .copied()
                    .map(|signer| AccountMeta::new_readonly(signer, true)),
            );
            append_interface_transfer_accounts(
                &mut accounts,
                &data.legs[index].interface_transfers,
                &self.interface_transfer_accounts[index],
            );
            data.leg_account_counts.push(
                u8::try_from(accounts.len() - before)
                    .expect("a leg fits its account count in a u8"),
            );
        }

        (data, accounts)
    }
}
