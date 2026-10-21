use borsh::{BorshDeserialize, BorshSerialize};
use zolana_program::{circuit::UtxoState, Bytes};

#[derive(Clone, BorshSerialize, BorshDeserialize, UtxoState)]
struct ShortBytes {
    data: Bytes<16>,
}

#[derive(Clone, BorshSerialize, BorshDeserialize, UtxoState)]
struct LongBytes {
    data: Bytes<33>,
}

fn main() {}
