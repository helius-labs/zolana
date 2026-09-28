use solana_address::Address;
use zk_program_sdk::{
    circuit::{
        constant, Assert, Asset, Balance, Bytes, CircuitVar, Constraints, DataHash, DataUtxo,
        Field, Owner, TokenUtxo, Uint, Utxo,
    },
    conversion::ProofInput,
    CircuitError,
};
use zolana_hasher::primitives::hash_bytes;
use zolana_interface::UTXO_DOMAIN;
use zolana_keypair::ShieldedAddress;
use zolana_transaction::Mint;

use super::vectors::Vector;
use crate::{
    harness::fixture::{rule_broken, Refusal, Visit, Visited},
    protocol::{
        data::state::CounterState,
        transaction::wallets::{address, field_of, ACCOUNT, RECIPIENT, SENDER},
    },
};

pub const BALANCES: &str = "the balances are the native balances";
pub const WITHDRAWN: &str = "withdraw_all returns the native balance";
pub const OWNER_HASH: &str = "the owner hash is the native one";
pub const ASSET_HASH: &str = "the asset hash is the native one";
pub const FILE: &str = file!();

pub const ANOTHER_ASSET: &str = "the destination holds another asset";
pub const TRANSFER_EXCEEDS: &str = "the transfer exceeds the balance";
pub const WITHDRAWAL_EXCEEDS: &str = "the withdrawal exceeds the balance";
pub const NONZERO: &str = "a public transfer moves a nonzero amount";
pub const BALANCE_FITS: &str = "the balance does not fit in 64 bits";

pub const fn broken(rule: &'static str) -> Refusal {
    rule_broken(rule, FILE)
}

pub const TOKEN: usize = 0;
pub const DATA: usize = 1;

pub const TRANSFER: usize = 0;
pub const TRANSFER_ALL: usize = 1;
pub const WITHDRAW: usize = 2;
pub const WITHDRAW_ALL: usize = 3;
pub const BALANCE_READ: usize = 4;

/// Constant deposits reach the accumulator's structural width limit without
/// allocating unrelated owner, asset or input range-check variables.
#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Oversized<const OP: usize>;

impl<const OP: usize> Constraints for OversizedCircuit<OP> {
    fn constraints(&self) -> Result<(), CircuitError> {
        oversized_operation(OP).1
    }
}

/// Return the actual operation line separately from its error so the regression
/// can detect a caller chain stopping anywhere inside the production SDK.
pub fn oversized_operation(op: usize) -> (u32, Result<(), CircuitError>) {
    let account = Bytes::constant(ACCOUNT.as_array());
    let amount = Uint::<64>::constant(1).expect("one fits in an amount");
    let mut holder = TokenUtxo::new_init(&Owner::default(), &Asset::sol());
    for _ in 0..191 {
        holder.deposit(&amount, &account).expect("nonzero deposit");
    }
    match op {
        BALANCE_READ => {
            let line = line!() + 1;
            let result = holder.balance();
            (line, result.map(drop))
        }
        WITHDRAW_ALL => {
            let line = line!() + 1;
            let result = holder.withdraw_all(&account);
            (line, result.map(drop))
        }
        WITHDRAW => {
            let line = line!() + 1;
            let result = holder.withdraw(&amount, &account);
            (line, result)
        }
        TRANSFER => {
            let mut destination = TokenUtxo::new_init(&Owner::default(), &holder.asset());
            let line = line!() + 1;
            let result = holder.transfer(&mut destination, &amount);
            (line, result)
        }
        _ => unreachable!("oversized fixture operation"),
    }
}

/// Binds `new_init(owner, asset)` of a `TokenUtxo` or a
/// `DataUtxo<CounterState>` to `holder`, so one body runs against either.
macro_rules! with_holder {
    ($kind:expr, $owner:expr, $asset:expr, |$holder:ident| $body:expr) => {
        match $kind {
            TOKEN => {
                let $holder = TokenUtxo::new_init($owner, $asset);
                $body
            }
            _ => {
                let $holder = DataUtxo::<CounterState>::new_init($owner, $asset);
                $body
            }
        }
    };
}

/// The source takes one deposit, then runs `OP` against a destination built
/// with the source's own `asset()` (`OWN_ASSET`) or with `held`; both final
/// balances are asserted equal to the native ones.
#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Ledger<
    const SOURCE: usize,
    const DESTINATION: usize,
    const OP: usize,
    const OWN_ASSET: bool,
> {
    pub owner: ShieldedAddress,
    pub recipient: ShieldedAddress,
    pub mint: Mint,
    pub held: Mint,
    pub account: Address,
    pub deposit: u64,
    pub amount: u64,
    pub balances: [Field; 2],
}

impl<const SOURCE: usize, const DESTINATION: usize, const OP: usize, const OWN_ASSET: bool>
    LedgerCircuit<SOURCE, DESTINATION, OP, OWN_ASSET>
{
    #[track_caller]
    fn run(
        &self,
        source: &mut impl Balance,
        destination: &mut impl Balance,
    ) -> Result<(), CircuitError> {
        source.deposit(&self.deposit, &self.account)?;
        match OP {
            TRANSFER => source.transfer(destination, &self.amount)?,
            TRANSFER_ALL => source.transfer_all(destination)?,
            WITHDRAW => source.withdraw(&self.amount, &self.account)?,
            _ => source
                .withdraw_all(&self.account)?
                .assert_equal(&self.amount, WITHDRAWN)?,
        }
        let [source_balance, destination_balance] = &self.balances;
        CircuitVar::from(source.balance()?).assert_equal(source_balance, BALANCES)?;
        CircuitVar::from(destination.balance()?).assert_equal(destination_balance, BALANCES)
    }
}

impl<const SOURCE: usize, const DESTINATION: usize, const OP: usize, const OWN_ASSET: bool>
    Constraints for LedgerCircuit<SOURCE, DESTINATION, OP, OWN_ASSET>
{
    fn constraints(&self) -> Result<(), CircuitError> {
        with_holder!(SOURCE, &self.owner, &self.mint, |source| {
            let mut source = source;
            let asset = if OWN_ASSET {
                source.asset()
            } else {
                self.held.clone()
            };
            with_holder!(DESTINATION, &self.recipient, &asset, |destination| {
                let mut destination = destination;
                self.run(&mut source, &mut destination)
            })
        })
    }
}

/// `owner()` and `asset()` of a new holder, hashed and asserted equal to the
/// native owner hash and `hash_bytes(mint)`.
#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Accessors<const KIND: usize> {
    pub owner: ShieldedAddress,
    pub mint: Mint,
    pub owner_hash: Field,
    pub asset_hash: Field,
}

impl<const KIND: usize> Constraints for AccessorsCircuit<KIND> {
    fn constraints(&self) -> Result<(), CircuitError> {
        with_holder!(KIND, &self.owner, &self.mint, |holder| {
            holder
                .owner()
                .hash()?
                .assert_equal(&self.owner_hash, OWNER_HASH)?;
            holder
                .asset()
                .hash()?
                .assert_equal(&self.asset_hash, ASSET_HASH)
        })
    }
}

/// `K` deposits into a new token holder, then `balance()` (or `withdraw_all`
/// when `ALL`) asserted equal to `balance`.
#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Deposits<const K: usize, const ALL: bool> {
    pub owner: ShieldedAddress,
    pub mint: Mint,
    pub account: Address,
    pub amounts: [u64; K],
    pub balance: Field,
}

impl<const K: usize, const ALL: bool> Constraints for DepositsCircuit<K, ALL> {
    fn constraints(&self) -> Result<(), CircuitError> {
        let mut holder = TokenUtxo::new_init(&self.owner, &self.mint);
        for amount in &self.amounts {
            holder.deposit(amount, &self.account)?;
        }
        if ALL {
            CircuitVar::from(holder.withdraw_all(&self.account)?)
                .assert_equal(&self.balance, WITHDRAWN)
        } else {
            CircuitVar::from(holder.balance()?).assert_equal(&self.balance, BALANCES)
        }
    }
}

/// A withdrawal or a transfer from a new holder without any deposit.
#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Empty<const OP: usize> {
    pub owner: ShieldedAddress,
    pub mint: Mint,
    pub account: Address,
    pub amount: u64,
}

impl<const OP: usize> Constraints for EmptyCircuit<OP> {
    fn constraints(&self) -> Result<(), CircuitError> {
        let mut holder = TokenUtxo::new_init(&self.owner, &self.mint);
        match OP {
            WITHDRAW => holder.withdraw(&self.amount, &self.account),
            _ => holder.withdraw_all(&self.account).map(|_| ()),
        }
    }
}

pub fn spendable_constant() -> Utxo {
    let mut utxo = Utxo::default();
    utxo.domain = constant(u64::from(UTXO_DOMAIN));
    utxo
}

/// A transfer from a funded token holder into a burned `DESTINATION`: a
/// `TokenUtxo::new_burn` or a `DataUtxo::new_burn` of a constant input.
#[derive(Clone, Copy, Debug, ProofInput)]
pub struct IntoBurned<const DESTINATION: usize, const ALL: bool> {
    pub owner: ShieldedAddress,
    pub account: Address,
    pub deposit: u64,
    pub amount: u64,
}

impl<const DESTINATION: usize, const ALL: bool> IntoBurnedCircuit<DESTINATION, ALL> {
    #[track_caller]
    fn into(&self, destination: &mut impl Balance) -> Result<(), CircuitError> {
        let mut source = TokenUtxo::new_init(&self.owner, &Asset::sol());
        source.deposit(&self.deposit, &self.account)?;
        if ALL {
            source.transfer_all(destination)
        } else {
            source.transfer(destination, &self.amount)
        }
    }
}

impl<const DESTINATION: usize, const ALL: bool> Constraints
    for IntoBurnedCircuit<DESTINATION, ALL>
{
    fn constraints(&self) -> Result<(), CircuitError> {
        let input = spendable_constant();
        match DESTINATION {
            TOKEN => self.into(&mut TokenUtxo::new_burn(&[input])?),
            _ => {
                let state = CounterState::default();
                let mut input = input;
                input.data_hash = state.hash()?;
                self.into(&mut DataUtxo::new_burn(&input, &state)?)
            }
        }
    }
}

pub fn ledger<const S: usize, const D: usize, const OP: usize, const OWN: bool>(
    held: Mint,
    vector: &Vector,
) -> Ledger<S, D, OP, OWN> {
    Ledger {
        owner: address(SENDER),
        recipient: address(RECIPIENT),
        mint: Mint::SOL,
        held,
        account: ACCOUNT,
        deposit: vector.deposit,
        amount: vector.amount,
        balances: vector.balances.map(Field::from),
    }
}

pub const PAIRS: [&str; 4] = [
    "token -> token",
    "token -> data",
    "data -> token",
    "data -> data",
];
pub const SOURCES: [&str; 2] = ["token", "data"];

/// `OP` from every source holder into every destination holder.
pub fn pairs<const OP: usize, V: Visit>(visitor: &V, vector: &Vector) -> Visited<V::Output> {
    PAIRS
        .into_iter()
        .zip([
            visitor.visit(&ledger::<TOKEN, TOKEN, OP, true>(Mint::SOL, vector)),
            visitor.visit(&ledger::<TOKEN, DATA, OP, true>(Mint::SOL, vector)),
            visitor.visit(&ledger::<DATA, TOKEN, OP, true>(Mint::SOL, vector)),
            visitor.visit(&ledger::<DATA, DATA, OP, true>(Mint::SOL, vector)),
        ])
        .collect()
}

/// `OP` from every source holder; the destination is a token holder.
pub fn sources<const OP: usize, V: Visit>(visitor: &V, vector: &Vector) -> Visited<V::Output> {
    SOURCES
        .into_iter()
        .zip([
            visitor.visit(&ledger::<TOKEN, TOKEN, OP, true>(Mint::SOL, vector)),
            visitor.visit(&ledger::<DATA, TOKEN, OP, true>(Mint::SOL, vector)),
        ])
        .collect()
}

pub fn deposits<const K: usize, const ALL: bool>(
    amounts: [u64; K],
    balance: u64,
) -> Deposits<K, ALL> {
    Deposits {
        owner: address(SENDER),
        mint: Mint::SOL,
        account: ACCOUNT,
        amounts,
        balance: Field::from(balance),
    }
}

pub fn into_burned<const DESTINATION: usize, const ALL: bool>() -> IntoBurned<DESTINATION, ALL> {
    IntoBurned {
        owner: address(SENDER),
        account: ACCOUNT,
        deposit: 5,
        amount: 1,
    }
}

pub fn accessors<const KIND: usize>(owner: u8, mint: Mint) -> Accessors<KIND> {
    let address = address(owner);
    Accessors {
        owner: address,
        mint,
        owner_hash: field_of(&address.owner_hash().expect("owner hash")),
        asset_hash: field_of(&hash_bytes(mint.asset.as_array()).expect("asset hash")),
    }
}

/// The ledger arithmetic alone: a constant owner, asset and account, so the
/// only rows are the amounts' range checks and the ledger's own rules.
#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Arithmetic {
    pub deposit: u64,
    pub amount: u64,
    pub balances: [Field; 2],
}

impl Constraints for ArithmeticCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        let account = Bytes::constant(ACCOUNT.as_array());
        let mut source = TokenUtxo::new_init(&Owner::default(), &Asset::sol());
        let mut destination = TokenUtxo::new_init(&Owner::default(), &source.asset());
        source.deposit(&self.deposit, &account)?;
        source.transfer(&mut destination, &self.amount)?;
        let [source_balance, destination_balance] = &self.balances;
        CircuitVar::from(source.balance()?).assert_equal(source_balance, BALANCES)?;
        CircuitVar::from(destination.balance()?).assert_equal(destination_balance, BALANCES)
    }
}

pub fn arithmetic(vector: &Vector) -> Arithmetic {
    Arithmetic {
        deposit: vector.deposit,
        amount: vector.amount,
        balances: vector.balances.map(Field::from),
    }
}
