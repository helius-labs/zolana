use solana_address::Address;
use zk_program_sdk::{
    circuit::{
        checked_utxo_data, Assert, CircuitVar, ConfidentialTransaction, Constraints, DataUtxo,
        Field, UtxoTrait,
    },
    conversion::ProofInput,
    CircuitError, TxContext,
};
use zolana_hasher::primitives::hash_bytes;
use zolana_keypair::{hash::owner_hash, ShieldedAddress};
use zolana_transaction::{Mint, WalletUtxo};

use super::state::{Counter, CounterState};
use crate::{
    harness::fixture::{rule_broken, Refusal},
    protocol::transaction::{fixtures::NoFields, wallets::field_of},
};

pub const COUNT: &str = "the count is the native state's";
pub const BALANCE: &str = "the balance is the input's native amount";
pub const OWNER: &str = "the owner is the input's native owner";
pub const ASSET: &str = "the asset is the input's native asset";
pub const FILE: &str = file!();

pub const COMMITS: &str = "the input does not commit to its program state";
pub const RING: &str = "the utxo is in a ring";
pub const NOT_SPENDABLE: &str = "the utxo is not a spendable utxo";
pub const CLOSE_LEAVES: &str = "a closed data utxo leaves a balance";

pub const fn broken(rule: &'static str) -> Refusal {
    rule_broken(rule, FILE)
}

/// `DataUtxo::new_mut`, or `new_close` when `CLOSE`, of the input and its
/// state, then the count, the balance, the owner hash and the asset hash
/// asserted equal to the native values.
#[derive(Clone, Debug, ProofInput)]
pub struct Held<const CLOSE: bool> {
    pub input: WalletUtxo,
    pub state: Counter,
    pub count: Field,
    pub balance: Field,
    pub owner_hash: Field,
    pub asset_hash: Field,
}

impl<const CLOSE: bool> Constraints for HeldCircuit<CLOSE> {
    fn constraints(&self) -> Result<(), CircuitError> {
        let counter = if CLOSE {
            DataUtxo::new_close(&self.input, &self.state)?
        } else {
            DataUtxo::new_mut(&self.input, &self.state)?
        };
        CircuitVar::from(counter.count.clone()).assert_equal(&self.count, COUNT)?;
        CircuitVar::from(counter.amount()?).assert_equal(&self.balance, BALANCE)?;
        counter
            .owner()
            .hash()?
            .assert_equal(&self.owner_hash, OWNER)?;
        counter
            .asset()
            .hash()?
            .assert_equal(&self.asset_hash, ASSET)
    }
}

pub fn held<const CLOSE: bool>(input: WalletUtxo, state: Counter) -> Held<CLOSE> {
    Held {
        count: Field::from(state.count),
        balance: Field::from(input.utxo.amount),
        owner_hash: field_of(
            &owner_hash(&input.utxo.owner, &input.nullifier_pubkey).expect("owner hash"),
        ),
        asset_hash: field_of(&hash_bytes(input.utxo.asset.asset.as_array()).expect("asset hash")),
        input,
        state,
    }
}

/// `DataUtxo::<CounterState>::new_init`: a zero count and balance under the
/// given owner and asset.
#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Fresh {
    pub owner: ShieldedAddress,
    pub mint: Mint,
    pub count: Field,
    pub balance: Field,
    pub owner_hash: Field,
    pub asset_hash: Field,
}

impl Constraints for FreshCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        let counter = DataUtxo::<CounterState>::new_init(&self.owner).with_asset(&self.mint)?;
        CircuitVar::from(counter.count.clone()).assert_equal(&self.count, COUNT)?;
        CircuitVar::from(counter.amount()?).assert_equal(&self.balance, BALANCE)?;
        counter
            .owner()
            .hash()?
            .assert_equal(&self.owner_hash, OWNER)?;
        counter
            .asset()
            .hash()?
            .assert_equal(&self.asset_hash, ASSET)
    }
}

pub fn fresh(owner: ShieldedAddress, mint: Mint) -> Fresh {
    Fresh {
        owner,
        mint,
        count: Field::from(0u64),
        balance: Field::from(0u64),
        owner_hash: field_of(&owner.owner_hash().expect("owner hash")),
        asset_hash: field_of(&hash_bytes(mint.asset.as_array()).expect("asset hash")),
    }
}

/// `checked_utxo_data` of a proof-input state.
#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Encoded {
    pub state: Counter,
}

impl Constraints for EncodedCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        checked_utxo_data(&self.state).map(|_| ())
    }
}

/// A closed data input in a transaction: its balance is withdrawn whole when
/// `ALL`, and otherwise left in the closed UTXO.
#[derive(Clone, Debug, ProofInput)]
pub struct Closed<const ALL: bool> {
    pub tx_context: TxContext,
    pub input: WalletUtxo,
    pub state: Counter,
    pub account: Address,
    pub public: NoFields,
}

impl<const ALL: bool> Constraints for ClosedCircuit<ALL> {
    fn constraints(&self) -> Result<(), CircuitError> {
        let mut counter = DataUtxo::new_close(&self.input, &self.state)?;
        if ALL {
            let _ = counter.withdraw_all(&self.account)?;
        }
        ConfidentialTransaction::new(&self.tx_context, &self.public)
            .with_data_utxo(counter)
            .check()
            .map(|_| ())
    }
}
