use zk_program_sdk::TxContext;
use zolana_transaction::Mint;

use super::{
    fixtures::{Forgotten, Fund, NoFields, Payment, Recipient, Refresh, Settle, Swept, Unspent},
    wallets::{
        address, dummy, token_input, Spent, ACCOUNT, RECIPIENT, SEED, SENDER, TREE_ID, USDC,
    },
};
use crate::protocol::data::state::Counter;

pub type Named<T> = Vec<(&'static str, T)>;

pub fn tx_context(output_tree_id: Option<u16>) -> TxContext {
    TxContext::new()
        .with_blinding_seed(SEED)
        .with_output_tree_id(output_tree_id)
}

pub fn refresh(spent: Spent, output_tree_id: Option<u16>) -> Refresh {
    Refresh {
        tx_context: tx_context(output_tree_id),
        tokens: [spent.wallet_utxo()],
        public: NoFields,
    }
}

pub fn refreshes() -> Named<Refresh> {
    vec![
        (
            "300 SOL into tree 0",
            refresh(Spent::token(SENDER, Mint::SOL, 300, 0), Some(0)),
        ),
        (
            "u64::MAX USDC into tree 2",
            refresh(Spent::token(SENDER, USDC, u64::MAX, 1), Some(2)),
        ),
        (
            "5 SOL into the first input's latest tree 7",
            refresh(
                Spent::token(SENDER, Mint::SOL, 5, 2).with_latest_tree_id(Some(7)),
                None,
            ),
        ),
        (
            "5 SOL into tree 2 over the first input's latest tree 7",
            refresh(
                Spent::token(SENDER, Mint::SOL, 5, 2).with_latest_tree_id(Some(7)),
                Some(2),
            ),
        ),
    ]
}

pub fn payment(mint: Mint, amounts: [u64; 2], amount: u64) -> Payment {
    Payment {
        tx_context: tx_context(Some(TREE_ID)),
        tokens: [
            token_input(SENDER, mint, amounts[0], 0),
            token_input(SENDER, mint, amounts[1], 1),
            dummy(),
        ],
        amount,
        public: Recipient {
            recipient: address(RECIPIENT),
        },
    }
}

pub fn payments() -> Named<Payment> {
    vec![
        (
            "300 + 200 SOL pays 400",
            payment(Mint::SOL, [300, 200], 400),
        ),
        ("1 + 2 USDC pays 3", payment(USDC, [1, 2], 3)),
        ("7 + 0 SOL pays 0", payment(Mint::SOL, [7, 0], 0)),
    ]
}

pub fn fund(tokens: u64, held: u64, count: u64, amount: u64) -> Fund {
    let state = Counter { count };
    Fund {
        tx_context: tx_context(Some(0)),
        tokens: [token_input(SENDER, Mint::SOL, tokens, 0)],
        counter: Spent::token(SENDER, Mint::SOL, held, 1)
            .with_state(state.bytes(), state.data_hash())
            .wallet_utxo(),
        state,
        amount,
        public: NoFields,
    }
}

pub fn funds() -> Named<Fund> {
    vec![
        (
            "300 SOL funds a counter at 5 with 100",
            fund(300, 0, 5, 100),
        ),
        (
            "40 SOL moves all 40 into a counter holding 2",
            fund(40, 2, 0, 40),
        ),
    ]
}

pub fn settle(mint: Mint, amount: u64, deposit: u64, withdraw: u64) -> Settle {
    Settle {
        tx_context: tx_context(Some(0)),
        tokens: [token_input(SENDER, mint, amount, 0)],
        deposit,
        withdraw,
        account: ACCOUNT,
        public: NoFields,
    }
}

pub fn settles() -> Named<Settle> {
    vec![
        (
            "300 SOL deposits 50 and withdraws 120",
            settle(Mint::SOL, 300, 50, 120),
        ),
        (
            "9 USDC deposits 1 and withdraws all 10",
            settle(USDC, 9, 1, 10),
        ),
    ]
}

pub fn swept<const ALL: bool>(amount: u64) -> Swept<ALL> {
    Swept {
        tx_context: tx_context(Some(0)),
        tokens: [token_input(SENDER, Mint::SOL, amount, 0)],
        account: ACCOUNT,
        public: NoFields,
    }
}

pub fn forgotten() -> Forgotten {
    Forgotten {
        tx_context: tx_context(Some(0)),
        tokens: [token_input(SENDER, Mint::SOL, 300, 0)],
        amount: 100,
        public: Recipient {
            recipient: address(RECIPIENT),
        },
    }
}

pub fn unspent() -> Unspent {
    Unspent {
        tx_context: tx_context(Some(0)),
        owner: address(SENDER),
        deposit: 10,
        account: ACCOUNT,
        public: NoFields,
    }
}
