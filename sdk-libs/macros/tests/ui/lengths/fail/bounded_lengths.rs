use spr_program::conversion::{Allocator, ProofInput};
use spr_transaction::WalletUtxo;

#[derive(ProofInput)]
struct MinimumAboveMaximum {
    #[min_len(3)]
    #[max_len(2)]
    utxos: Vec<WalletUtxo>,
}

fn main() {
    let short = MinimumAboveMaximum { utxos: Vec::new() }.instantiate(&Allocator::native());
    let _ = short.is_ok();
}
