use solana_address::Address;
use zolana_transaction::{Mint, WalletUtxo};

use super::{
    fixtures::{held, Burned, Held},
    state::Counter,
};
use crate::protocol::transaction::{
    fixtures::NoFields,
    vectors::tx_context,
    wallets::{blinding, dummy, token_input, Spent, ACCOUNT, SENDER, USDC},
};

pub type Named<T> = Vec<(&'static str, T)>;

pub fn counter(mint: Mint, amount: u64, count: u64, leaf_index: u64) -> WalletUtxo {
    let state = Counter { count };
    Spent::token(SENDER, mint, amount, leaf_index)
        .with_state(state.bytes(), state.native_hash())
        .wallet_utxo()
}

pub fn holds() -> Named<Held<false>> {
    vec![
        (
            "a counter at 5 holding 300 SOL",
            held(counter(Mint::SOL, 300, 5, 0), Counter { count: 5 }),
        ),
        (
            "a counter at 2^64 - 1 holding 2^64 - 1 USDC",
            held(
                counter(USDC, u64::MAX, u64::MAX, 1),
                Counter { count: u64::MAX },
            ),
        ),
        (
            "an empty counter at 0",
            held(counter(Mint::SOL, 0, 0, 2), Counter { count: 0 }),
        ),
    ]
}

pub fn another_state() -> Held<false> {
    held(counter(Mint::SOL, 300, 5, 0), Counter { count: 6 })
}

pub fn a_token_input() -> Held<false> {
    held(token_input(SENDER, Mint::SOL, 300, 0), Counter { count: 0 })
}

pub fn a_ring_input() -> Held<false> {
    let state = Counter { count: 5 };
    held(
        Spent::token(SENDER, Mint::SOL, 300, 0)
            .with_state(state.bytes(), state.native_hash())
            .with_ring(blinding(22), Address::new_from_array([23u8; 32]))
            .wallet_utxo(),
        state,
    )
}

pub fn a_dummy_input() -> Held<false> {
    let mut fixture = held(counter(Mint::SOL, 0, 0, 0), Counter { count: 0 });
    fixture.input = dummy();
    fixture
}

pub fn burned<const ALL: bool>(amount: u64) -> Burned<ALL> {
    Burned {
        tx_context: tx_context(Some(0)),
        input: counter(Mint::SOL, amount, 5, 0),
        state: Counter { count: 5 },
        account: ACCOUNT,
        public: NoFields,
    }
}
