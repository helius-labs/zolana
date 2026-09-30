//! Program states for the data-UTXO fixtures: `Counter`, whose client hash
//! agrees with its circuit hash, and `Skewed`, whose client hash does not.

use borsh::{BorshDeserialize, BorshSerialize};
use zolana_program::{
    circuit::{poseidon, CircuitType, CircuitVar, DataHash, Uint, UtxoData},
    conversion::{Allocator, FromCircuit, Placeholder, ProofInput},
    hasher::{data_hash, DataHasher, Hasher, HasherError, Poseidon, ToByteArray},
    CircuitError,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Counter {
    pub count: u64,
}

#[derive(Clone, Debug)]
pub struct CounterState {
    pub count: Uint<64>,
}

impl Counter {
    pub fn bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("counter bytes")
    }

    pub fn native_hash(&self) -> [u8; 32] {
        DataHasher::hash::<Poseidon>(self).expect("counter hash")
    }

    pub fn data_hash(&self) -> [u8; 32] {
        data_hash(&self.native_hash()).expect("counter data hash")
    }
}

impl CircuitType for CounterState {}

impl Default for CounterState {
    fn default() -> Self {
        Self {
            count: Uint::zero(),
        }
    }
}

impl DataHash for CounterState {
    fn hash(&self) -> Result<CircuitVar, CircuitError> {
        poseidon(&[self.count.clone().into()])
    }
}

impl UtxoData for CounterState {
    type Client = Counter;
}

impl ProofInput for Counter {
    type Circuit = CounterState;

    fn instantiate(&self, allocator: &Allocator) -> Result<CounterState, CircuitError> {
        Ok(CounterState {
            count: self.count.instantiate(allocator)?,
        })
    }
}

impl FromCircuit for Counter {
    fn from_circuit(circuit: &CounterState) -> Result<Self, CircuitError> {
        Ok(Self {
            count: u64::from_circuit(&circuit.count)?,
        })
    }
}

impl Placeholder for Counter {
    fn placeholder() -> Result<Self, CircuitError> {
        Ok(Self { count: 0 })
    }
}

impl DataHasher for Counter {
    fn hash<H: Hasher>(&self) -> Result<[u8; 32], HasherError> {
        H::hashv(&[self.count.to_byte_array()?.as_slice()])
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Skewed {
    pub count: u64,
}

#[derive(Clone, Debug, Default)]
pub struct SkewedState {
    pub count: CounterState,
}

impl CircuitType for SkewedState {}

impl DataHash for SkewedState {
    fn hash(&self) -> Result<CircuitVar, CircuitError> {
        self.count.hash()
    }
}

impl UtxoData for SkewedState {
    type Client = Skewed;
}

impl ProofInput for Skewed {
    type Circuit = SkewedState;

    fn instantiate(&self, allocator: &Allocator) -> Result<SkewedState, CircuitError> {
        Ok(SkewedState {
            count: Counter { count: self.count }.instantiate(allocator)?,
        })
    }
}

impl FromCircuit for Skewed {
    fn from_circuit(circuit: &SkewedState) -> Result<Self, CircuitError> {
        Ok(Self {
            count: u64::from_circuit(&circuit.count.count)?,
        })
    }
}

impl Placeholder for Skewed {
    fn placeholder() -> Result<Self, CircuitError> {
        Ok(Self { count: 0 })
    }
}

impl DataHasher for Skewed {
    fn hash<H: Hasher>(&self) -> Result<[u8; 32], HasherError> {
        H::hashv(&[
            self.count.to_byte_array()?.as_slice(),
            self.count.to_byte_array()?.as_slice(),
        ])
    }
}
