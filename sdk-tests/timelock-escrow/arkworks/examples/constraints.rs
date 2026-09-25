#[path = "../tests/shared/mod.rs"]
mod shared;

use circuit_lib::ArkworksCircuit;
use shared::{escrow_utxo, keypair, token_input, TREE_ID};
use timelock_escrow_arkworks::client::{self, EscrowTerms};

fn main() {
    let creator = keypair(5);
    let address = creator.shielded_address().expect("creator address");
    let escrow = client::Escrow {
        creator: address,
        token_utxos_asset_a: [token_input(&creator, 600, 0), token_input(&creator, 400, 1)],
        amount: 250,
        unlock: 1_700_000_000,
        payer: address.solana_address().expect("payer"),
        output_tree_id: TREE_ID,
    }
    .build(&creator)
    .expect("escrow transaction");
    let withdraw = client::Withdraw {
        creator: address,
        escrow: escrow_utxo(&creator, 250, 1_700_000_000),
        terms: EscrowTerms {
            creator: address.owner_hash().expect("creator owner hash"),
            unlock: 1_700_000_000,
        },
        payer: address.solana_address().expect("payer"),
        output_tree_id: TREE_ID,
    }
    .build(&creator)
    .expect("withdraw transaction");

    for (name, constraints) in [
        (
            "escrow",
            ArkworksCircuit::new(escrow.proof_inputs).and_then(|c| c.check_constraints()),
        ),
        (
            "withdraw",
            ArkworksCircuit::new(withdraw.proof_inputs).and_then(|c| c.check_constraints()),
        ),
    ] {
        println!("{name}: {} constraints", constraints.expect("constraints"));
    }
}
