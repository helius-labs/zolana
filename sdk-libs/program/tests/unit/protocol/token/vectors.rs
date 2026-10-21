use solana_address::Address;
use zolana_transaction::Mint;

use super::fixtures::{spend, Spend, AS_GIVEN};
use crate::protocol::{
    data::state::Counter,
    transaction::wallets::{blinding, dummy, token_input, Spent, SENDER, STRANGER, USDC},
};

pub type Named<T> = Vec<(&'static str, T)>;

pub fn sol(amount: u64, leaf_index: u64) -> zolana_transaction::WalletUtxo {
    token_input(SENDER, Mint::SOL, amount, leaf_index)
}

pub fn usdc(amount: u64, leaf_index: u64) -> zolana_transaction::WalletUtxo {
    token_input(SENDER, USDC, amount, leaf_index)
}

pub fn with_state(leaf_index: u64) -> zolana_transaction::WalletUtxo {
    let state = Counter { count: 1 };
    Spent::token(SENDER, Mint::SOL, 5, leaf_index)
        .with_state(state.bytes(), state.native_hash())
        .wallet_utxo()
}

pub fn in_a_ring(leaf_index: u64) -> zolana_transaction::WalletUtxo {
    Spent::token(SENDER, Mint::SOL, 5, leaf_index)
        .with_ring(blinding(22), Address::new_from_array([23u8; 32]))
        .wallet_utxo()
}

pub fn ones() -> Named<Spend<1, AS_GIVEN>> {
    vec![
        ("one 300 SOL input", spend([sol(300, 0)])),
        ("one 2^64 - 1 USDC input", spend([usdc(u64::MAX, 1)])),
        ("one empty SOL input", spend([sol(0, 2)])),
    ]
}

pub fn twos() -> Named<Spend<2, AS_GIVEN>> {
    vec![
        ("300 + 200 SOL", spend([sol(300, 0), sol(200, 1)])),
        (
            "2^64 - 1 USDC and a dummy",
            spend([usdc(u64::MAX, 0), dummy()]),
        ),
    ]
}

pub fn threes() -> Named<Spend<3, AS_GIVEN>> {
    vec![
        (
            "7 SOL and two dummies",
            spend([sol(7, 0), dummy(), dummy()]),
        ),
        (
            "1 + 2 USDC and a dummy",
            spend([usdc(1, 0), usdc(2, 1), dummy()]),
        ),
    ]
}

pub fn a_dummy_first() -> Spend<2, AS_GIVEN> {
    spend([dummy(), sol(5, 0)])
}

pub fn sol_then_usdc() -> Spend<2, AS_GIVEN> {
    spend([sol(5, 0), usdc(5, 1)])
}

pub fn sender_then_stranger() -> Spend<2, AS_GIVEN> {
    spend([sol(5, 0), token_input(STRANGER, Mint::SOL, 5, 1)])
}

pub fn max_plus_max() -> Spend<2, AS_GIVEN> {
    spend([usdc(u64::MAX, 0), usdc(u64::MAX, 1)])
}
