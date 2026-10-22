//! `full_withdrawal` (tag 10) instruction builder (spec: squads
//! `full_withdrawal`).

use solana_instruction::{AccountMeta, Instruction};

use crate::{
    instruction::{tag, FullWithdrawalIxData},
    PROGRAM_ID_PUBKEY,
};

/// Builder for the `full_withdrawal` instruction: the escape-hatch exit.
///
/// The accounts are exactly the SPP `ring_transact` account list, forwarded
/// unchanged. There is no co-signer and no ring proof; the forwarded SPP proof
/// authorizes the exit (Ed25519 UTXO ownership), and the SPP payer is only a fee
/// payer.
pub struct FullWithdrawal {
    pub spp_accounts: Vec<AccountMeta>,
    pub data: FullWithdrawalIxData,
}

impl FullWithdrawal {
    pub fn instruction(&self) -> Instruction {
        let mut instruction_data = vec![tag::FULL_WITHDRAWAL];
        instruction_data.extend_from_slice(
            &self
                .data
                .serialize()
                .expect("squads-ring instruction serialization is infallible"),
        );

        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts: self.spp_accounts.clone(),
            data: instruction_data,
        }
    }
}
