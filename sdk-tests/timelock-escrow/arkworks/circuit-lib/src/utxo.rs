use core::ops::{Deref, DerefMut};

use ark_r1cs_std::{eq::EqGadget, select::CondSelectGadget};
use zolana_hasher::primitives::hash_bytes;
use zolana_interface::{DUMMY_DOMAIN, UTXO_DOMAIN};

use crate::{
    circuit_var::assert_equal_unless, constant, convert::var, poseidon, zero, Allocator, Assert,
    CircuitVar, ProofInput, RelationError,
};

#[derive(Clone, Debug)]
pub struct Utxo {
    pub domain: CircuitVar,
    pub owner: CircuitVar,
    pub asset: CircuitVar,
    pub amount: CircuitVar,
    pub blinding: CircuitVar,
    pub data_hash: CircuitVar,
    pub ring_data_hash: CircuitVar,
    pub ring_program_id: CircuitVar,
    pub tree_id: CircuitVar,
}

impl Default for Utxo {
    fn default() -> Self {
        Self {
            domain: zero(),
            owner: zero(),
            asset: zero(),
            amount: zero(),
            blinding: zero(),
            data_hash: zero(),
            ring_data_hash: zero(),
            ring_program_id: zero(),
            tree_id: zero(),
        }
    }
}

impl Utxo {
    pub fn dummy() -> Self {
        Self {
            domain: constant(u64::from(DUMMY_DOMAIN)),
            ..Self::default()
        }
    }

    pub fn hash(&self) -> Result<CircuitVar, RelationError> {
        let ring = poseidon(&[self.ring_data_hash.clone(), self.ring_program_id.clone()])?;
        let owner = poseidon(&[self.owner.clone(), self.blinding.clone()])?;
        poseidon(&[
            self.domain.clone(),
            self.tree_id.clone(),
            self.asset.clone(),
            self.amount.clone(),
            self.data_hash.clone(),
            ring,
            owner,
        ])
    }

    fn assert_default_ring(&self) -> Result<(), RelationError> {
        self.ring_data_hash
            .assert_equal(&zero(), "the utxo is in a ring")?;
        self.ring_program_id
            .assert_equal(&zero(), "the utxo is in a ring")
    }
}

impl ProofInput for Utxo {
    type Circuit = Utxo;

    fn instantiate(&self, allocator: &Allocator) -> Result<Utxo, RelationError> {
        Ok(Self {
            domain: self.domain.instantiate(allocator)?,
            owner: self.owner.instantiate(allocator)?,
            asset: self.asset.instantiate(allocator)?,
            amount: self.amount.instantiate(allocator)?,
            blinding: self.blinding.instantiate(allocator)?,
            data_hash: self.data_hash.instantiate(allocator)?,
            ring_data_hash: self.ring_data_hash.instantiate(allocator)?,
            ring_program_id: self.ring_program_id.instantiate(allocator)?,
            tree_id: self.tree_id.instantiate(allocator)?,
        })
    }
}

pub(crate) fn sol_asset() -> Result<CircuitVar, RelationError> {
    var(
        &hash_bytes(zolana_transaction::Mint::SOL.asset.as_array())?,
        "the SOL asset",
    )
}

fn utxo_domain() -> CircuitVar {
    constant(u64::from(UTXO_DOMAIN))
}

pub trait DataHash {
    fn hash(&self) -> Result<CircuitVar, RelationError>;
}

impl DataHash for CircuitVar {
    fn hash(&self) -> Result<CircuitVar, RelationError> {
        Ok(self.clone())
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Output {
    pub(crate) owner: CircuitVar,
    pub(crate) asset: CircuitVar,
    pub(crate) amount: CircuitVar,
    pub(crate) data_hash: CircuitVar,
}

#[must_use]
#[derive(Clone, Debug)]
pub struct OutputTokenUtxo {
    owner: CircuitVar,
    asset: CircuitVar,
    amount: CircuitVar,
}

impl OutputTokenUtxo {
    pub fn owner(&self) -> &CircuitVar {
        &self.owner
    }

    pub fn asset(&self) -> &CircuitVar {
        &self.asset
    }

    pub fn amount(&self) -> &CircuitVar {
        &self.amount
    }

    pub(crate) fn output(&self) -> Output {
        Output {
            owner: self.owner.clone(),
            asset: self.asset.clone(),
            amount: self.amount.clone(),
            data_hash: zero(),
        }
    }
}

#[derive(Clone, Debug)]
enum DataLifecycle {
    Init,
    Mut(CircuitVar),
    Burn(CircuitVar),
}

#[must_use]
#[derive(Clone, Debug)]
pub struct DataUtxo<S> {
    owner: CircuitVar,
    asset: CircuitVar,
    amount: CircuitVar,
    unpaid: CircuitVar,
    state: S,
    lifecycle: DataLifecycle,
}

impl<S: DataHash> DataUtxo<S> {
    pub fn new_init(owner: &CircuitVar) -> Result<Self, RelationError>
    where
        S: Default,
    {
        Ok(Self {
            owner: owner.clone(),
            asset: sol_asset()?,
            amount: zero(),
            unpaid: zero(),
            state: S::default(),
            lifecycle: DataLifecycle::Init,
        })
    }

    pub fn from_output_utxo(output: OutputTokenUtxo) -> Result<Self, RelationError>
    where
        S: Default,
    {
        Ok(Self {
            owner: output.owner,
            asset: output.asset,
            amount: output.amount,
            unpaid: zero(),
            state: S::default(),
            lifecycle: DataLifecycle::Init,
        })
    }

    pub fn new_mut(input: &Utxo, state: S) -> Result<Self, RelationError> {
        let input_hash = Self::spent_input(input, &state)?;
        Ok(Self::from_input(
            input,
            state,
            DataLifecycle::Mut(input_hash),
        ))
    }

    pub fn new_burn(input: &Utxo, state: S) -> Result<Self, RelationError> {
        let input_hash = Self::spent_input(input, &state)?;
        Ok(Self::from_input(
            input,
            state,
            DataLifecycle::Burn(input_hash),
        ))
    }

    pub fn owner(&self) -> &CircuitVar {
        &self.owner
    }

    pub fn asset(&self) -> &CircuitVar {
        &self.asset
    }

    pub fn amount(&self) -> &CircuitVar {
        &self.amount
    }

    pub fn transfer(
        &mut self,
        recipient: &CircuitVar,
        amount: CircuitVar,
    ) -> Result<OutputTokenUtxo, RelationError> {
        match self.lifecycle {
            DataLifecycle::Burn(_) => {
                self.unpaid -= &amount;
                Ok(OutputTokenUtxo {
                    owner: recipient.clone(),
                    asset: self.asset.clone(),
                    amount,
                })
            }
            _ => Err(RelationError::Violated(
                "only a burned data utxo transfers its value",
            )),
        }
    }

    pub(crate) fn input_hash(&self) -> Option<CircuitVar> {
        match &self.lifecycle {
            DataLifecycle::Mut(input_hash) | DataLifecycle::Burn(input_hash) => {
                Some(input_hash.clone())
            }
            DataLifecycle::Init => None,
        }
    }

    pub(crate) fn output(&self) -> Result<Option<Output>, RelationError> {
        if let DataLifecycle::Burn(_) = self.lifecycle {
            self.unpaid
                .assert_equal(&zero(), "a burned data utxo leaves value unpaid")?;
            return Ok(None);
        }
        Ok(Some(Output {
            owner: self.owner.clone(),
            asset: self.asset.clone(),
            amount: self.amount.clone(),
            data_hash: self.state.hash()?,
        }))
    }

    fn spent_input(input: &Utxo, state: &S) -> Result<CircuitVar, RelationError> {
        input
            .domain
            .assert_equal(&utxo_domain(), "the utxo is not a spendable utxo")?;
        input.assert_default_ring()?;
        input.data_hash.assert_equal(
            &state.hash()?,
            "the input does not commit to its program state",
        )?;
        input.hash()
    }

    fn from_input(input: &Utxo, state: S, lifecycle: DataLifecycle) -> Self {
        Self {
            owner: input.owner.clone(),
            asset: input.asset.clone(),
            amount: input.amount.clone(),
            unpaid: input.amount.clone(),
            state,
            lifecycle,
        }
    }
}

impl<S> Deref for DataUtxo<S> {
    type Target = S;

    fn deref(&self) -> &S {
        &self.state
    }
}

impl<S> DerefMut for DataUtxo<S> {
    fn deref_mut(&mut self) -> &mut S {
        &mut self.state
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TokenLifecycle {
    Init,
    Mut,
    Burn,
}

#[must_use]
#[derive(Clone, Debug)]
pub struct TokenUtxo<const N: usize> {
    owner: CircuitVar,
    asset: CircuitVar,
    input_hashes: Vec<CircuitVar>,
    balance: CircuitVar,
    lifecycle: TokenLifecycle,
}

impl TokenUtxo<0> {
    pub fn new_init(owner: &CircuitVar, asset: &CircuitVar) -> Self {
        Self {
            owner: owner.clone(),
            asset: asset.clone(),
            input_hashes: Vec::new(),
            balance: zero(),
            lifecycle: TokenLifecycle::Init,
        }
    }
}

impl<const N: usize> TokenUtxo<N> {
    pub fn new_mut(inputs: [Utxo; N]) -> Result<Self, RelationError> {
        Self::spend(inputs, TokenLifecycle::Mut)
    }

    pub fn new_burn(inputs: [Utxo; N]) -> Result<Self, RelationError> {
        Self::spend(inputs, TokenLifecycle::Burn)
    }

    pub fn owner(&self) -> &CircuitVar {
        &self.owner
    }

    pub fn asset(&self) -> &CircuitVar {
        &self.asset
    }

    pub fn balance(&self) -> &CircuitVar {
        &self.balance
    }

    pub fn transfer(&mut self, recipient: &CircuitVar, amount: CircuitVar) -> OutputTokenUtxo {
        self.balance -= &amount;
        OutputTokenUtxo {
            owner: recipient.clone(),
            asset: self.asset.clone(),
            amount,
        }
    }

    pub fn deposit(&mut self, amount: &CircuitVar) {
        self.balance += amount;
    }

    pub fn withdraw(&mut self, amount: &CircuitVar) {
        self.balance -= amount;
    }

    pub(crate) fn input_hashes(&self) -> &[CircuitVar] {
        &self.input_hashes
    }

    pub(crate) fn change(&self) -> Result<Option<Output>, RelationError> {
        match self.lifecycle {
            TokenLifecycle::Init | TokenLifecycle::Mut => Ok(Some(Output {
                owner: self.owner.clone(),
                asset: self.asset.clone(),
                amount: self.balance.clone(),
                data_hash: zero(),
            })),
            TokenLifecycle::Burn => {
                self.balance
                    .assert_equal(&zero(), "a burned token utxo leaves a balance")?;
                Ok(None)
            }
        }
    }

    fn spend(inputs: [Utxo; N], lifecycle: TokenLifecycle) -> Result<Self, RelationError> {
        let first = inputs.first().ok_or(RelationError::Violated(
            "a token utxo spends at least one input",
        ))?;
        first
            .domain
            .assert_equal(&utxo_domain(), "the first input of a token utxo is a dummy")?;
        let mut balance = zero();
        let mut input_hashes = Vec::with_capacity(N);
        for (index, input) in inputs.iter().enumerate() {
            let dummy = input.domain.is_eq(&constant(u64::from(DUMMY_DOMAIN)))?;
            input.assert_default_ring()?;
            input
                .data_hash
                .assert_equal(&zero(), "the input carries program state")?;
            if index > 0 {
                assert_equal_unless(
                    &input.domain,
                    &utxo_domain(),
                    &dummy,
                    "the utxo is not a spendable utxo",
                )?;
                assert_equal_unless(
                    &input.asset,
                    &first.asset,
                    &dummy,
                    "the inputs hold different assets",
                )?;
                assert_equal_unless(
                    &input.owner,
                    &first.owner,
                    &dummy,
                    "the inputs belong to different owners",
                )?;
            }
            balance += CircuitVar::conditionally_select(&dummy, &zero(), &input.amount)?;
            input_hashes.push(CircuitVar::conditionally_select(
                &dummy,
                &zero(),
                &input.hash()?,
            )?);
        }
        Ok(Self {
            owner: first.owner.clone(),
            asset: first.asset.clone(),
            input_hashes,
            balance,
            lifecycle,
        })
    }
}
