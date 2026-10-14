use solana_address::Address;
use zolana_keypair::ShieldedAddress;
use zolana_program::{
    circuit::{
        poseidon, Assert, CheckedTransaction, Circuit, CircuitType, CircuitVar,
        ConfidentialTransaction, Constraints, DataUtxo, Field, PublicInputs, TokenUtxos, Uint,
        UtxoTrait,
    },
    conversion::{Allocator, Placeholder, ProofInput},
    CircuitError, TxContext,
};
use zolana_transaction::WalletUtxo;

use super::reference::{Expected, Reference};
use crate::{
    harness::fixture::{rule_broken, Refusal},
    protocol::data::state::{Counter, CounterState},
};

pub const PRIVATE_TX_HASH: &str = "the private transaction hash is the native one";
pub const TRANSACTION_HASH: &str = "the transaction hash is the native one";
pub const PUBLIC_HASH: &str = "the public hash is the native one";
pub const FILE: &str = file!();

pub const LEAVES: &str = "value leaves the transaction: a utxo was not added";
pub const NO_INPUT: &str = "a transaction spends at least one input";
pub const NO_TREE: &str =
    "the first input reports no latest tree and the transaction sets no output tree";
pub const COUNTER_OVERFLOWS: &str = "the counter overflows";

pub const fn broken(rule: &'static str) -> Refusal {
    rule_broken(rule, FILE)
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct NoFields;

impl PublicInputs for NoFieldsCircuit {
    fn hash(&self, transaction_hash: &CircuitVar) -> Result<CircuitVar, CircuitError> {
        poseidon(std::slice::from_ref(transaction_hash))
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Recipient {
    pub recipient: ShieldedAddress,
}

impl PublicInputs for RecipientCircuit {
    fn hash(&self, transaction_hash: &CircuitVar) -> Result<CircuitVar, CircuitError> {
        poseidon(&[self.recipient.hash()?, transaction_hash.clone()])
    }
}

/// One input, one output: the whole input comes back as the change.
#[derive(Clone, Debug, ProofInput)]
pub struct Refresh {
    pub tx_context: TxContext,
    pub tokens: [WalletUtxo; 1],
    pub public: NoFields,
}

impl Circuit for RefreshCircuit {
    fn circuit(&self) -> Result<CheckedTransaction, CircuitError> {
        let tokens = TokenUtxos::new_mut(&self.tokens)?;
        ConfidentialTransaction::new(&self.tx_context, &self.public)
            .with_token_utxos(tokens)
            .check()
    }
}

/// Three input slots, the last a dummy, and a payment to a recipient.
#[derive(Clone, Debug, ProofInput)]
pub struct Payment {
    pub tx_context: TxContext,
    pub tokens: [WalletUtxo; 3],
    pub amount: u64,
    pub public: Recipient,
}

impl Circuit for PaymentCircuit {
    fn circuit(&self) -> Result<CheckedTransaction, CircuitError> {
        let mut tokens = TokenUtxos::new_mut(&self.tokens)?;
        let mut payment = TokenUtxos::new_init(&self.public.recipient, &tokens.asset());
        tokens.transfer(&mut payment, &self.amount)?;
        ConfidentialTransaction::new(&self.tx_context, &self.public)
            .with_token_utxos(tokens)
            .with_token_utxos(payment)
            .check()
    }
}

/// A token input funds a data input whose counter goes up by one.
#[derive(Clone, Debug, ProofInput)]
pub struct Fund {
    pub tx_context: TxContext,
    pub tokens: [WalletUtxo; 1],
    pub counter: WalletUtxo,
    pub state: Counter,
    pub amount: u64,
    pub public: NoFields,
}

impl Circuit for FundCircuit {
    fn circuit(&self) -> Result<CheckedTransaction, CircuitError> {
        let mut tokens = TokenUtxos::new_mut(&self.tokens)?;
        let mut counter = DataUtxo::new_mut(&self.counter, &self.state)?;
        counter.count = counter
            .count
            .checked_add(&Uint::constant(1)?, COUNTER_OVERFLOWS)?;
        tokens.transfer(&mut counter, &self.amount)?;
        ConfidentialTransaction::new(&self.tx_context, &self.public)
            .with_token_utxos(tokens)
            .with_data_utxo(counter)
            .check()
    }
}

/// A deposit and a withdrawal on one token input: two public transfers.
#[derive(Clone, Debug, ProofInput)]
pub struct Settle {
    pub tx_context: TxContext,
    pub tokens: [WalletUtxo; 1],
    pub deposit: u64,
    pub withdraw: u64,
    pub account: Address,
    pub public: NoFields,
}

impl Circuit for SettleCircuit {
    fn circuit(&self) -> Result<CheckedTransaction, CircuitError> {
        let mut tokens = TokenUtxos::new_mut(&self.tokens)?;
        tokens.deposit(&self.deposit, &self.account)?;
        tokens.withdraw(&self.withdraw, &self.account)?;
        ConfidentialTransaction::new(&self.tx_context, &self.public)
            .with_token_utxos(tokens)
            .check()
    }
}

/// A payment whose destination is never added to the transaction.
#[derive(Clone, Debug, ProofInput)]
pub struct Forgotten {
    pub tx_context: TxContext,
    pub tokens: [WalletUtxo; 1],
    pub amount: u64,
    pub public: Recipient,
}

impl Circuit for ForgottenCircuit {
    fn circuit(&self) -> Result<CheckedTransaction, CircuitError> {
        let mut tokens = TokenUtxos::new_mut(&self.tokens)?;
        let mut payment = TokenUtxos::new_init(&self.public.recipient, &tokens.asset());
        tokens.transfer(&mut payment, &self.amount)?;
        ConfidentialTransaction::new(&self.tx_context, &self.public)
            .with_token_utxos(tokens)
            .check()
    }
}

/// A new data UTXO funded by a deposit alone: the transaction spends nothing.
#[derive(Clone, Debug, ProofInput)]
pub struct Unspent {
    pub tx_context: TxContext,
    pub owner: ShieldedAddress,
    pub deposit: u64,
    pub account: Address,
    pub public: NoFields,
}

impl Circuit for UnspentCircuit {
    fn circuit(&self) -> Result<CheckedTransaction, CircuitError> {
        let mut counter = DataUtxo::<CounterState>::new_init(&self.owner);
        counter.deposit(&self.deposit, &self.account)?;
        ConfidentialTransaction::new(&self.tx_context, &self.public)
            .with_data_utxo(counter)
            .check()
    }
}

/// A closed token input: its balance is withdrawn whole when `ALL`, and
/// otherwise left in the closed UTXO.
#[derive(Clone, Debug, ProofInput)]
pub struct Swept<const ALL: bool> {
    pub tx_context: TxContext,
    pub tokens: [WalletUtxo; 1],
    pub account: Address,
    pub public: NoFields,
}

impl<const ALL: bool> Circuit for SweptCircuit<ALL> {
    fn circuit(&self) -> Result<CheckedTransaction, CircuitError> {
        let mut tokens = TokenUtxos::new_close(&self.tokens)?;
        if ALL {
            let _ = tokens.withdraw_all(&self.account)?;
        }
        ConfidentialTransaction::new(&self.tx_context, &self.public)
            .with_token_utxos(tokens)
            .check()
    }
}

/// The native reference an honest proof of `self` must reproduce.
pub trait Shape: ProofInput<Circuit: Circuit> + Placeholder + Clone + std::fmt::Debug {
    fn reference(&self) -> Reference;
}

/// A constraint-only fixture: `program` builds its transaction and `check`s it,
/// then every hash the check returns is asserted equal to `expected`, the
/// value the native `zolana-transaction` builder computes.
#[derive(Clone, Debug)]
pub struct Asserted<P> {
    pub program: P,
    pub expected: Expected,
}

impl<P: Shape> Asserted<P> {
    pub fn honest(program: P) -> Self {
        Self {
            expected: program.reference().expected(),
            program,
        }
    }
}

pub struct AssertedCircuit<C> {
    pub program: C,
    pub expected: [CircuitVar; 3],
}

impl<C> CircuitType for AssertedCircuit<C> {}

impl<P: ProofInput> ProofInput for Asserted<P> {
    type Circuit = AssertedCircuit<P::Circuit>;

    fn instantiate(&self, allocator: &Allocator) -> Result<Self::Circuit, CircuitError> {
        Ok(AssertedCircuit {
            program: self.program.instantiate(allocator)?,
            expected: self.expected.fields().instantiate(allocator)?,
        })
    }
}

impl<P: Placeholder> Placeholder for Asserted<P> {
    fn placeholder() -> Result<Self, CircuitError> {
        Ok(Self {
            program: P::placeholder()?,
            expected: Expected::default(),
        })
    }
}

impl<C: Circuit> AssertedCircuit<C> {
    pub fn checked(&self) -> Result<CheckedTransaction, CircuitError> {
        self.program.circuit()
    }
}

impl<C: Circuit> Constraints for AssertedCircuit<C> {
    fn constraints(&self) -> Result<(), CircuitError> {
        let checked = self.checked()?;
        let [private_tx_hash, transaction_hash, public_hash] = &self.expected;
        checked
            .private_tx_hash()
            .assert_equal(private_tx_hash, PRIVATE_TX_HASH)?;
        checked
            .transaction_hash()
            .assert_equal(transaction_hash, TRANSACTION_HASH)?;
        checked.public_hash().assert_equal(public_hash, PUBLIC_HASH)
    }
}

/// A program's transaction checked alone, without a native reference.
#[derive(Clone, Debug)]
pub struct Checked<P> {
    pub program: P,
}

pub struct CheckedCircuit<C> {
    pub program: C,
}

impl<C> CircuitType for CheckedCircuit<C> {}

impl<P: ProofInput> ProofInput for Checked<P> {
    type Circuit = CheckedCircuit<P::Circuit>;

    fn instantiate(&self, allocator: &Allocator) -> Result<Self::Circuit, CircuitError> {
        Ok(CheckedCircuit {
            program: self.program.instantiate(allocator)?,
        })
    }
}

impl<P: Placeholder> Placeholder for Checked<P> {
    fn placeholder() -> Result<Self, CircuitError> {
        Ok(Self {
            program: P::placeholder()?,
        })
    }
}

impl<C: Circuit> Constraints for CheckedCircuit<C> {
    fn constraints(&self) -> Result<(), CircuitError> {
        self.program.circuit().map(|_| ())
    }
}

impl Expected {
    pub fn fields(&self) -> [Field; 3] {
        [
            self.private_tx_hash,
            self.transaction_hash,
            self.public_hash,
        ]
    }
}
