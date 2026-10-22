use zolana_hasher::{primitives::right_align, Hasher, Poseidon};
use zolana_program::{
    circuit::{CheckedTransaction, Circuit, ConfidentialTransaction, DataUtxo, UniqueDataUtxo},
    conversion::ProofInput,
    hasher::{unique_data_hash, CLOSED_DATA_HASH_DOMAIN},
    CircuitError, TxContext, ZkProgramCircuit,
};
use zolana_transaction::{Mint, WalletUtxo};

use super::{
    fixtures::{CLOSE_LEAVES, COMMITS},
    state::Counter,
};
use crate::{
    harness::fixture::{check_constraints, native},
    protocol::transaction::{
        fixtures::NoFields,
        vectors::tx_context,
        wallets::{address, Spent, PAYER, SENDER},
    },
};

const DATA: usize = 0;
const HASHED: usize = 1;
const UNIQUE: usize = 2;
const OPEN: usize = 0;
const CLOSE: usize = 1;
const BURN: usize = 2;
const CLOSE_BURN: usize = 3;
const BURN_CLOSE: usize = 4;
const ADDRESS: [u8; 32] = {
    let mut address = [0; 32];
    address[31] = 42;
    address
};

#[derive(Clone, Debug, ProofInput)]
struct Lifecycle<const KIND: usize, const MODE: usize> {
    tx_context: TxContext,
    input: WalletUtxo,
    address: [u8; 32],
    state: Counter,
    hash: [u8; 32],
    public: NoFields,
}

impl<const KIND: usize, const MODE: usize> Circuit for LifecycleCircuit<KIND, MODE> {
    type Output = CheckedTransaction;

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        let transaction = ConfidentialTransaction::new(&self.tx_context, &self.public);
        let transaction = match KIND {
            UNIQUE => {
                let state = UniqueDataUtxo::new_mut(&self.input, &self.address, &self.state)?;
                let state = match MODE {
                    CLOSE => state.close(),
                    BURN => state.burn(),
                    CLOSE_BURN => state.close().burn(),
                    BURN_CLOSE => state.burn().close(),
                    _ => state,
                };
                transaction.with(state)
            }
            HASHED => {
                let state = DataUtxo::new_mut_with_hash(&self.input, &self.hash)?;
                let state = if MODE == CLOSE { state.close() } else { state };
                transaction.with(state)
            }
            _ => {
                let state = DataUtxo::new_mut(&self.input, &self.state)?;
                let state = if MODE == CLOSE { state.close() } else { state };
                transaction.with(state)
            }
        };
        transaction.check()
    }
}

fn fixture<const KIND: usize, const MODE: usize>(amount: u64) -> Lifecycle<KIND, MODE> {
    let state = Counter { count: 5 };
    let hash = state.native_hash();
    let data_hash = match KIND {
        UNIQUE => unique_data_hash(&ADDRESS, &hash).expect("unique state hash"),
        HASHED => hash,
        _ => state.data_hash(),
    };
    Lifecycle {
        tx_context: tx_context(Some(0)),
        input: Spent::token(SENDER, Mint::SOL, amount, 0)
            .with_state(state.bytes(), data_hash)
            .wallet_utxo(),
        address: ADDRESS,
        state,
        hash,
        public: NoFields,
    }
}

fn outputs<const KIND: usize, const MODE: usize>(
    amount: u64,
) -> Vec<(u64, [u8; 32], Option<Vec<u8>>)> {
    fixture::<KIND, MODE>(amount)
        .create_finalized_transaction(&address(SENDER), PAYER)
        .expect("finalized transaction")
        .output_utxos()
        .iter()
        .filter_map(|output| {
            output
                .data_hash
                .map(|hash| (output.amount, hash, output.data.utxo_data().map(Vec::from)))
        })
        .collect()
}

#[test]
fn builders_preserve_state_outputs_or_select_closure_and_burning() {
    let state = Counter { count: 5 };
    let tombstone = Poseidon::hashv(&[
        &right_align(&CLOSED_DATA_HASH_DOMAIN.to_be_bytes()),
        &ADDRESS,
    ])
    .expect("tombstone hash");
    assert_eq!(
        [
            outputs::<DATA, OPEN>(300),
            outputs::<DATA, CLOSE>(0),
            outputs::<HASHED, OPEN>(300),
            outputs::<HASHED, CLOSE>(0),
            outputs::<UNIQUE, CLOSE>(0),
            outputs::<UNIQUE, BURN>(0),
            outputs::<UNIQUE, CLOSE_BURN>(0),
            outputs::<UNIQUE, BURN_CLOSE>(0),
        ],
        [
            vec![(300, state.data_hash(), Some(state.bytes()))],
            vec![],
            vec![(300, state.native_hash(), None)],
            vec![],
            vec![(0, tombstone, None)],
            vec![],
            vec![],
            vec![(0, tombstone, None)],
        ],
        "open state retains its output; the last unique-state builder selects tombstone or no output"
    );
}

fn checks<const KIND: usize, const MODE: usize>(
    amount: u64,
) -> Result<(), (&'static str, Option<usize>, Option<&'static str>)> {
    check_constraints(&fixture::<KIND, MODE>(amount)).map(|_| ())
}

#[test]
fn the_state_lifecycle_modes_satisfy_r1cs() {
    assert_eq!(
        [
            checks::<DATA, CLOSE>(0),
            checks::<HASHED, OPEN>(300),
            checks::<HASHED, CLOSE>(0),
            checks::<UNIQUE, CLOSE>(0),
            checks::<UNIQUE, BURN>(0),
            checks::<UNIQUE, CLOSE_BURN>(0),
            checks::<UNIQUE, BURN_CLOSE>(0),
        ],
        [Ok(()); 7],
        "the builder-selected output mode is also used during constraint synthesis"
    );
}

fn refusal<const KIND: usize, const MODE: usize>(
) -> Result<(), (&'static str, Option<&'static str>)> {
    native(&fixture::<KIND, MODE>(1)).map_err(|error| (error.0, error.1))
}

#[test]
fn closure_and_burning_reject_a_remaining_balance() {
    let error = Err(("CircuitError.RuleBroken", Some(CLOSE_LEAVES)));
    assert_eq!(
        [
            refusal::<DATA, CLOSE>(),
            refusal::<HASHED, CLOSE>(),
            refusal::<UNIQUE, CLOSE>(),
            refusal::<UNIQUE, BURN>(),
        ],
        [error; 4],
        "closing or burning state requires an empty final balance"
    );
}

#[test]
fn raw_hash_inputs_must_match_the_committed_state() {
    let mut state = fixture::<HASHED, OPEN>(300);
    state.hash[31] ^= 1;
    assert_eq!(
        native(&state).map_err(|error| (error.0, error.1)),
        Err(("CircuitError.RuleBroken", Some(COMMITS))),
        "new_mut_with_hash must check the supplied hash against the input commitment"
    );
}
