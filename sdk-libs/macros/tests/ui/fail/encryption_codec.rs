use borsh::{BorshDeserialize, BorshSerialize};
use spr_program::circuit::UtxoState;

#[derive(Clone, BorshSerialize, BorshDeserialize, UtxoState)]
struct SkippedState {
    #[borsh(skip)]
    value: u64,
}

#[derive(UtxoState)]
#[utxo_state(unknown)]
struct UnknownOption {
    value: u64,
}

#[derive(UtxoState)]
#[utxo_state(custom_codec, custom_codec)]
struct DuplicateOption {
    value: u64,
}

#[derive(UtxoState)]
#[utxo_state(custom_codec = true)]
struct OptionWithValue {
    value: u64,
}

#[derive(UtxoState)]
struct FieldOption {
    #[utxo_state(custom_codec)]
    value: u64,
}

#[derive(UtxoState)]
#[utxo_state()]
struct EmptyOption {
    value: u64,
}

fn main() {}
