use core::ops::{Deref, DerefMut};

use super::{utxo_domain, Amount, Balance, HasBalance, Output, SpentInput, Utxo, UtxoTrait};
use crate::{
    circuit::{
        constant, labels::Scope, poseidon, zero, Assert, Bool, Bytes, CircuitVar, HashBytes,
        PublicTransfer, SolanaAddress, Uint, UtxoOwner,
    },
    conversion::{to_bytes, FromCircuit},
    hasher::{DataHasher, CLOSED_DATA_HASH_DOMAIN, DATA_HASH_DOMAIN, UNIQUE_DATA_HASH_DOMAIN},
    CircuitError, EncryptionCodec, ProtocolCircuitErrorKind,
};

const CLOSED_LEAVES_BALANCE: &str = "a closed data utxo leaves a balance";

pub trait DataHash {
    fn hash(&self) -> Result<CircuitVar, CircuitError>;
}

pub trait UtxoData: DataHash + Sized {
    type Client: FromCircuit<Circuit = Self> + EncryptionCodec + DataHasher;

    fn utxo_data(&self) -> Result<Vec<u8>, CircuitError> {
        let client = Self::Client::from_circuit(self)?;
        let state_hash = DataHasher::hash(&client)?;
        if state_hash != to_bytes(&DataHash::hash(self)?)? {
            return Err(ProtocolCircuitErrorKind::DataHashMismatch.into());
        }
        let encoded = client
            .serialize_for_encryption()
            .map_err(ProtocolCircuitErrorKind::StateEncoding)?;
        let reconstructed = Self::Client::deserialize_after_decryption(&encoded)
            .map_err(ProtocolCircuitErrorKind::StateEncoding)?;
        if DataHasher::hash(&reconstructed)? != state_hash {
            return Err(ProtocolCircuitErrorKind::StateRoundTripMismatch.into());
        }
        Ok(encoded)
    }
}

impl DataHash for CircuitVar {
    fn hash(&self) -> Result<CircuitVar, CircuitError> {
        Ok(self.clone())
    }
}

impl DataHash for Bool {
    fn hash(&self) -> Result<CircuitVar, CircuitError> {
        Ok(self.var())
    }
}

impl<const BITS: usize> DataHash for Uint<BITS> {
    fn hash(&self) -> Result<CircuitVar, CircuitError> {
        Ok(self.var())
    }
}

impl DataHash for UtxoOwner {
    fn hash(&self) -> Result<CircuitVar, CircuitError> {
        UtxoOwner::hash(self)
    }
}

impl DataHash for spr_keypair::circuit::ShieldedAddressCircuit {
    fn hash(&self) -> Result<CircuitVar, CircuitError> {
        spr_keypair::circuit::ShieldedAddressCircuit::hash(self)
    }
}

// Match the native ToByteArray implementation's fixed state byte width.
impl DataHash for Bytes<32> {
    fn hash(&self) -> Result<CircuitVar, CircuitError> {
        self.hash_bytes()
    }
}

impl DataHash for SolanaAddress {
    fn hash(&self) -> Result<CircuitVar, CircuitError> {
        self.hash_bytes()
    }
}

impl<T: DataHash, const N: usize> DataHash for [T; N] {
    fn hash(&self) -> Result<CircuitVar, CircuitError> {
        poseidon(
            &self
                .iter()
                .map(DataHash::hash)
                .collect::<Result<Vec<_>, _>>()?,
        )
    }
}

#[derive(Clone, Debug)]
pub(super) enum OutputState {
    Default,
    Closed(CircuitVar),
    None,
}

#[must_use]
#[derive(Debug)]
pub struct DataUtxo<S> {
    balance: Balance,
    state: S,
    address: Option<CircuitVar>,
    spent: Option<SpentInput>,
    output_state: OutputState,
    unwrapped_data_hash: bool,
}

impl<S> HasBalance for DataUtxo<S> {
    fn balance(&self) -> &Balance {
        &self.balance
    }

    fn balance_mut(&mut self) -> &mut Balance {
        &mut self.balance
    }

    fn is_closed(&self) -> bool {
        !matches!(self.output_state, OutputState::Default)
    }
}

impl<S: Default> DataUtxo<S> {
    pub fn new_init(owner: &UtxoOwner) -> Self {
        Self::fresh(owner, S::default(), None)
    }
}

impl<S: DataHash + Clone> DataUtxo<S> {
    #[track_caller]
    pub fn new_mut(input: &Utxo, state: &S) -> Result<Self, CircuitError> {
        Self::spend(input, state.clone(), None)
    }
}

impl<S: DataHash> DataUtxo<S> {
    #[track_caller]
    pub(super) fn spend(
        input: &Utxo,
        state: S,
        address: Option<CircuitVar>,
    ) -> Result<Self, CircuitError> {
        Self::spend_with_hash(input, state, address, false)
    }

    #[track_caller]
    fn spend_with_hash(
        input: &Utxo,
        state: S,
        address: Option<CircuitVar>,
        unwrapped_data_hash: bool,
    ) -> Result<Self, CircuitError> {
        let _scope = Scope::open(&input.domain.cs(), "a data utxo's input");
        input
            .domain
            .assert_equal(&utxo_domain(), "the utxo is not a spendable utxo")?;
        input.assert_default_ring()?;
        input.data_hash.assert_equal(
            &if unwrapped_data_hash {
                state.hash()?
            } else {
                data_hash(address.as_ref(), &state)?
            },
            "the input does not commit to its program state",
        )?;
        Ok(Self {
            balance: Balance::new(
                input.owner.clone(),
                input.asset.clone(),
                Amount::from(&input.amount),
            ),
            state,
            address,
            // The domain check above already excludes dummies.
            spent: Some(
                input.spent(input.hash_with(&input.owner.hash()?, &input.asset.hash_bytes()?)?),
            ),
            output_state: OutputState::Default,
            unwrapped_data_hash,
        })
    }
}

impl<S> DataUtxo<S> {
    /// Requires a final balance of zero and produces no output.
    /// Transfers into the UTXO are rejected after it is closed.
    pub fn close(self) -> Self {
        self.with_output_state(OutputState::None)
    }

    pub(super) fn with_output_state(mut self, output_state: OutputState) -> Self {
        self.output_state = output_state;
        self
    }

    pub(super) fn fresh(owner: &UtxoOwner, state: S, address: Option<CircuitVar>) -> Self {
        Self {
            balance: Balance::new(
                owner.clone(),
                SolanaAddress::constant(&spr_transaction::SOL_MINT),
                Amount::zero(),
            ),
            state,
            address,
            spent: None,
            output_state: OutputState::Default,
            unwrapped_data_hash: false,
        }
    }

    #[track_caller]
    pub fn with_asset(mut self, asset: &SolanaAddress) -> Result<Self, CircuitError> {
        if self.spent.is_some() || !self.balance.is_untouched() {
            return Err(ProtocolCircuitErrorKind::AssetOfUsedUtxo.into());
        }
        self.balance.set_asset(asset);
        Ok(self)
    }

    pub(crate) fn spent_input(&self) -> Option<SpentInput> {
        self.spent.clone()
    }

    pub(crate) fn public_transfers(&self) -> &[PublicTransfer] {
        self.balance.public_transfers()
    }

    pub(crate) fn transferred(&self) -> &CircuitVar {
        self.balance.transferred()
    }
}

impl<S: DataHash> DataUtxo<S> {
    #[track_caller]
    pub(crate) fn output(&self) -> Result<Option<Output>, CircuitError> {
        let balance = self.balance.amount_var();
        let data_hash = match &self.output_state {
            OutputState::Default => {
                if self.unwrapped_data_hash {
                    self.state.hash()?
                } else {
                    data_hash(self.address.as_ref(), &self.state)?
                }
            }
            OutputState::Closed(address) => {
                balance.assert_equal(&zero(), CLOSED_LEAVES_BALANCE)?;
                poseidon(&[
                    constant(u64::from(CLOSED_DATA_HASH_DOMAIN)),
                    address.clone(),
                ])?
            }
            OutputState::None => {
                balance.assert_equal(&zero(), CLOSED_LEAVES_BALANCE)?;
                return Ok(None);
            }
        };
        Ok(Some(Output {
            owner: self.owner(),
            asset: self.asset(),
            amount: self.balance.output_amount()?,
            data_hash,
            data: None,
            empty_if_zero: false,
        }))
    }
}

#[track_caller]
fn data_hash<S: DataHash>(
    address: Option<&CircuitVar>,
    state: &S,
) -> Result<CircuitVar, CircuitError> {
    match address {
        None => poseidon(&[constant(u64::from(DATA_HASH_DOMAIN)), state.hash()?]),
        Some(address) => poseidon(&[
            constant(u64::from(UNIQUE_DATA_HASH_DOMAIN)),
            address.clone(),
            state.hash()?,
        ]),
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

impl DataUtxo<CircuitVar> {
    /// A state commitment whose plaintext is transported separately, without a
    /// DATA wrapper or an attached state payload. The application owns its hash domain.
    pub fn new_init_with_hash(owner: &UtxoOwner, data_hash: &CircuitVar) -> Self {
        let mut utxo = Self::fresh(owner, data_hash.clone(), None);
        utxo.unwrapped_data_hash = true;
        utxo
    }

    /// Spends a state commitment without a DATA wrapper or an attached state payload.
    #[track_caller]
    pub fn new_mut_with_hash(input: &Utxo, data_hash: &CircuitVar) -> Result<Self, CircuitError> {
        Self::spend_with_hash(input, data_hash.clone(), None, true)
    }
}
