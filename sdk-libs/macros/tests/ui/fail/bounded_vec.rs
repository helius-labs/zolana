use zolana_program::{
    circuit::{CircuitType, PublicInputs},
    conversion::ProofInput,
};
use zolana_transaction::WalletUtxo;

#[derive(ProofInput)]
struct Unbounded {
    utxos: Vec<WalletUtxo>,
}

#[derive(ProofInput)]
struct BoundedScalar {
    #[max_len(2)]
    amount: u64,
}

#[derive(ProofInput)]
struct MinimumOnScalar {
    #[min_len(1)]
    amount: u64,
}

#[derive(ProofInput)]
struct BoundedTwice {
    #[max_len(2)]
    #[max_len(3)]
    utxos: Vec<WalletUtxo>,
}

#[derive(CircuitType)]
struct BoundedState {
    #[max_len(2)]
    utxos: Vec<WalletUtxo>,
}

#[derive(PublicInputs)]
struct BoundedPublicInputs {
    #[max_len(2)]
    utxos: Vec<WalletUtxo>,
}

fn main() {}
