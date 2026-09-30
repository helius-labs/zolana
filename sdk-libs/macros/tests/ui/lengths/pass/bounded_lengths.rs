use zolana_program::conversion::{Allocator, ProofInput};
use zolana_transaction::WalletUtxo;

#[derive(ProofInput)]
struct Exact {
    #[min_len(2)]
    #[max_len(2)]
    utxos: Vec<WalletUtxo>,
}

#[derive(ProofInput)]
struct Optional {
    #[min_len(0)]
    #[max_len(2)]
    utxos: Vec<WalletUtxo>,
}

fn main() {
    let allocator = Allocator::native();
    let utxo = WalletUtxo::dummy(0).expect("dummy utxo");
    let exact = Exact {
        utxos: vec![utxo.clone(), utxo],
    };
    assert!(exact.instantiate(&allocator).is_ok());
    let optional = Optional { utxos: Vec::new() };
    assert!(optional.instantiate(&allocator).is_ok());
}
