use core::ops::{Deref, DerefMut};

use anyhow::{anyhow, bail, Result};
use zolana_client::ProofInputUtxo;
use zolana_keypair::{hash::owner_hash, ShieldedAddress};
use zolana_transaction::{utxo::SppProofInputUtxo, Mint, SppProofOutputUtxo};

use crate::{
    convert::{to_bytes, utxo},
    DataHash, Utxo,
};

pub trait State {
    type Circuit: DataHash;

    fn circuit_state(&self) -> Result<Self::Circuit>;

    fn utxo_data(&self) -> Vec<u8>;

    fn data_hash(&self) -> Result<[u8; 32]> {
        Ok(to_bytes(&self.circuit_state()?.hash()?)?)
    }
}

#[must_use]
#[derive(Clone, Debug)]
pub struct OutputTokenUtxo {
    owner: ShieldedAddress,
    asset: Mint,
    amount: u64,
}

impl OutputTokenUtxo {
    pub fn owner(&self) -> &ShieldedAddress {
        &self.owner
    }

    pub fn asset(&self) -> Mint {
        self.asset
    }

    pub fn amount(&self) -> u64 {
        self.amount
    }

    pub(crate) fn output(&self) -> Result<SppProofOutputUtxo> {
        Ok(SppProofOutputUtxo::new(
            self.asset,
            self.amount,
            self.owner,
        )?)
    }
}

#[derive(Clone)]
enum DataLifecycle {
    Init,
    Mut(SppProofInputUtxo),
    Burn(SppProofInputUtxo),
}

#[must_use]
#[derive(Clone)]
pub struct DataUtxo<S> {
    owner: Option<ShieldedAddress>,
    asset: Mint,
    amount: u64,
    unpaid: u64,
    state: S,
    lifecycle: DataLifecycle,
}

impl<S: State> DataUtxo<S> {
    pub fn new_init(owner: ShieldedAddress) -> Self
    where
        S: Default,
    {
        Self {
            owner: Some(owner),
            asset: Mint::SOL,
            amount: 0,
            unpaid: 0,
            state: S::default(),
            lifecycle: DataLifecycle::Init,
        }
    }

    pub fn from_output_utxo(output: OutputTokenUtxo) -> Result<Self>
    where
        S: Default,
    {
        Ok(Self {
            owner: Some(output.owner),
            asset: output.asset,
            amount: output.amount,
            unpaid: 0,
            state: S::default(),
            lifecycle: DataLifecycle::Init,
        })
    }

    pub fn new_mut(owner: ShieldedAddress, input: SppProofInputUtxo, state: S) -> Result<Self> {
        if !owned_by(&input, &owner)? {
            bail!("the data utxo belongs to another owner");
        }
        Self::spend(Some(owner), input, state, DataLifecycle::Mut)
    }

    pub fn new_burn(input: SppProofInputUtxo, state: S) -> Result<Self> {
        Self::spend(None, input, state, DataLifecycle::Burn)
    }

    pub fn asset(&self) -> Mint {
        self.asset
    }

    pub fn amount(&self) -> u64 {
        self.amount
    }

    pub fn transfer(&mut self, recipient: ShieldedAddress, amount: u64) -> Result<OutputTokenUtxo> {
        match self.lifecycle {
            DataLifecycle::Burn(_) => {
                self.unpaid = self
                    .unpaid
                    .checked_sub(amount)
                    .ok_or_else(|| anyhow!("the transfers exceed the data utxo value"))?;
                Ok(OutputTokenUtxo {
                    owner: recipient,
                    asset: self.asset,
                    amount,
                })
            }
            _ => bail!("only a burned data utxo transfers its value"),
        }
    }

    pub fn circuit_input(&self) -> Result<Option<Utxo>> {
        self.input()
            .map(|input| Ok(utxo(&ProofInputUtxo::try_from(input)?)?))
            .transpose()
    }

    pub(crate) fn input(&self) -> Option<&SppProofInputUtxo> {
        match &self.lifecycle {
            DataLifecycle::Mut(input) | DataLifecycle::Burn(input) => Some(input),
            DataLifecycle::Init => None,
        }
    }

    pub(crate) fn output(&self) -> Result<Option<SppProofOutputUtxo>> {
        if let DataLifecycle::Burn(_) = self.lifecycle {
            if self.unpaid != 0 {
                bail!("a burned data utxo leaves value unpaid");
            }
            return Ok(None);
        }
        let owner = self
            .owner
            .ok_or_else(|| anyhow!("a data utxo output needs an owner"))?;
        Ok(Some(
            SppProofOutputUtxo::new(self.asset, self.amount, owner)?
                .with_utxo_data(self.state.utxo_data(), self.state.data_hash()?),
        ))
    }

    fn spend(
        owner: Option<ShieldedAddress>,
        input: SppProofInputUtxo,
        state: S,
        lifecycle: fn(SppProofInputUtxo) -> DataLifecycle,
    ) -> Result<Self> {
        if input.is_dummy()
            || input.utxo.ring_program_id.is_some()
            || input.ring_data_hash.is_some()
        {
            bail!("a data utxo spends a real utxo outside any ring");
        }
        if input.data_hash != Some(state.data_hash()?) {
            bail!("the input does not commit to its program state");
        }
        Ok(Self {
            owner,
            asset: input.utxo.asset,
            amount: input.utxo.amount,
            unpaid: input.utxo.amount,
            state,
            lifecycle: lifecycle(input),
        })
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
#[derive(Clone)]
pub struct TokenUtxo<const N: usize> {
    owner: ShieldedAddress,
    asset: Mint,
    inputs: Vec<SppProofInputUtxo>,
    balance: u64,
    lifecycle: TokenLifecycle,
}

impl TokenUtxo<0> {
    pub fn new_init(owner: ShieldedAddress, asset: Mint) -> Self {
        Self {
            owner,
            asset,
            inputs: Vec::new(),
            balance: 0,
            lifecycle: TokenLifecycle::Init,
        }
    }
}

impl<const N: usize> TokenUtxo<N> {
    pub fn new_mut(owner: ShieldedAddress, inputs: [SppProofInputUtxo; N]) -> Result<Self> {
        Self::spend(owner, inputs, TokenLifecycle::Mut)
    }

    pub fn new_burn(owner: ShieldedAddress, inputs: [SppProofInputUtxo; N]) -> Result<Self> {
        Self::spend(owner, inputs, TokenLifecycle::Burn)
    }

    pub fn owner(&self) -> &ShieldedAddress {
        &self.owner
    }

    pub fn asset(&self) -> Mint {
        self.asset
    }

    pub fn balance(&self) -> u64 {
        self.balance
    }

    pub fn transfer(&mut self, recipient: ShieldedAddress, amount: u64) -> Result<OutputTokenUtxo> {
        self.balance = self
            .balance
            .checked_sub(amount)
            .ok_or_else(|| anyhow!("the transfers exceed the token balance"))?;
        Ok(OutputTokenUtxo {
            owner: recipient,
            asset: self.asset,
            amount,
        })
    }

    pub fn deposit(&mut self, amount: u64) -> Result<()> {
        self.balance = self
            .balance
            .checked_add(amount)
            .ok_or_else(|| anyhow!("the deposit overflows the token balance"))?;
        Ok(())
    }

    pub fn withdraw(&mut self, amount: u64) -> Result<()> {
        self.balance = self
            .balance
            .checked_sub(amount)
            .ok_or_else(|| anyhow!("the withdrawal exceeds the token balance"))?;
        Ok(())
    }

    pub fn circuit_inputs(&self) -> Result<[Utxo; N]> {
        let inputs = self
            .inputs
            .iter()
            .map(|input| {
                if input.is_dummy() {
                    Ok(Utxo::dummy())
                } else {
                    Ok(utxo(&ProofInputUtxo::try_from(input)?)?)
                }
            })
            .collect::<Result<Vec<_>>>()?;
        inputs
            .try_into()
            .map_err(|_| anyhow!("a token utxo holds exactly {N} inputs"))
    }

    pub(crate) fn inputs(&self) -> &[SppProofInputUtxo] {
        &self.inputs
    }

    pub(crate) fn change(&self) -> Result<Option<SppProofOutputUtxo>> {
        match self.lifecycle {
            TokenLifecycle::Init | TokenLifecycle::Mut => Ok(Some(SppProofOutputUtxo::new(
                self.asset,
                self.balance,
                self.owner,
            )?)),
            TokenLifecycle::Burn if self.balance == 0 => Ok(None),
            TokenLifecycle::Burn => bail!("a burned token utxo leaves a balance"),
        }
    }

    fn spend(
        owner: ShieldedAddress,
        inputs: [SppProofInputUtxo; N],
        lifecycle: TokenLifecycle,
    ) -> Result<Self> {
        let first = inputs
            .first()
            .ok_or_else(|| anyhow!("a token utxo spends at least one input"))?;
        if first.is_dummy() {
            bail!("the first input of a token utxo is a dummy");
        }
        let asset = first.utxo.asset;
        let mut balance = 0u64;
        for input in inputs.iter().filter(|input| !input.is_dummy()) {
            if !owned_by(input, &owner)? {
                bail!("the inputs belong to different owners");
            }
            if input.utxo.asset != asset {
                bail!("the inputs hold different assets");
            }
            if input.data_hash.is_some()
                || input.utxo.ring_program_id.is_some()
                || input.ring_data_hash.is_some()
            {
                bail!("a token input carries program state or a ring");
            }
            balance = balance
                .checked_add(input.utxo.amount)
                .ok_or_else(|| anyhow!("the inputs overflow the token balance"))?;
        }
        Ok(Self {
            owner,
            asset,
            inputs: inputs.into(),
            balance,
            lifecycle,
        })
    }
}

fn owned_by(input: &SppProofInputUtxo, owner: &ShieldedAddress) -> Result<bool> {
    Ok(owner_hash(&input.utxo.owner, &input.nullifier_pubkey)? == owner.owner_hash()?)
}
