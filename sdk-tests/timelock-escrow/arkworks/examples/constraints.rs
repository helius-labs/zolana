#[path = "../tests/shared/mod.rs"]
mod shared;

use shared::{escrow_utxo, keypair, token_input, token_inputs, TREE_ID};
use timelock_escrow_arkworks::{
    Escrow, EscrowPrivateInputs, EscrowPublicInputs, EscrowTerms, Withdraw, WithdrawPrivateInputs,
    WithdrawPublicInputs,
};
use timelock_escrow_sdk::escrow_authority;
use zk_program_sdk::{ArkworksCircuit, Owner, TxContext};
use zolana_hasher::primitives::solana_owner_identity;

fn main() {
    let creator = keypair(5);
    let address = creator.shielded_address().expect("creator address");
    let first = token_input(&creator, 600, 0);
    let escrow = Escrow {
        private: EscrowPrivateInputs {
            tx_context: TxContext::new(first.nullifier, TREE_ID, address),
            token_utxos_asset_a: token_inputs([first, token_input(&creator, 400, 1)]),
            unlock: 1_700_000_000,
            amount: 250,
        },
        public: EscrowPublicInputs {
            escrow_owner: escrow_authority()
                .address(address.viewing_pubkey)
                .expect("escrow owner"),
        },
    };
    let escrow_input = escrow_utxo(&creator, 250, 1_700_000_000);
    let withdraw = Withdraw {
        private: WithdrawPrivateInputs {
            tx_context: TxContext::new(escrow_input.nullifier, TREE_ID, address),
            escrow: escrow_input,
            terms: EscrowTerms {
                creator: Owner::try_from(&address).expect("creator owner"),
                unlock: 1_700_000_000,
            },
        },
        public: WithdrawPublicInputs {
            unlock: 1_700_000_000,
            owner_identity: solana_owner_identity(
                address.solana_address().expect("creator").as_array(),
            )
            .expect("owner identity"),
        },
    };

    println!(
        "escrow: {} constraints",
        ArkworksCircuit::new(escrow)
            .and_then(|circuit| circuit.check_constraints())
            .expect("escrow constraints")
    );
    println!(
        "withdraw: {} constraints",
        ArkworksCircuit::new(withdraw)
            .and_then(|circuit| circuit.check_constraints())
            .expect("withdraw constraints")
    );
}
