//! The circuits, built on the host with the `circuits` feature.

use solana_address::Address;
use zolana_zk_dsl::{
    circuit::{
        constant, value, Assert, Circuit, CircuitType, CircuitVar, Field, Public, PublicHashOutput,
        PublicInputs,
    },
    conversion::{field, ProofInput},
    CircuitError, ZkCircuit,
};
use zolana_zk_gadgets::poseidon;

pub const RULE: &str = "the commitment hashes the point";

#[derive(Clone, Copy, Debug, PartialEq, Eq, CircuitType)]
pub struct Point {
    pub x: Field,
    pub y: Field,
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Opening {
    pub point: Point,
    pub commitment: Field,
}

impl Circuit for OpeningCircuit {
    type Output = ();

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        poseidon(&[self.point.x.clone(), self.point.y.clone()])?
            .assert_equal(&self.commitment, RULE)
    }
}

/// The commitment to a point, bound as the proof's one public input.
pub struct Commitment(CircuitVar);

impl PublicHashOutput for Commitment {
    fn public_hash(&self) -> &CircuitVar {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct PublicOpening {
    pub point: Point,
}

impl Circuit for PublicOpeningCircuit {
    type Output = Commitment;

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        Ok(Commitment(poseidon(&[
            self.point.x.clone(),
            self.point.y.clone(),
        ])?))
    }
}

pub const PAYOUT_RULE: &str = "the note commits to the paid amount and destination";

/// A note: an amount and a blinding, known only to its owner.
#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Note {
    pub amount: u64,
    pub blinding: Field,
}

/// What the verifier sees: the note commitment, the amount and where it goes.
/// The destination is 32 arbitrary bytes, so it takes two public inputs.
#[derive(Clone, Copy, Debug, PublicInputs)]
pub struct Payout {
    pub commitment: Field,
    pub amount: u64,
    pub destination: Address,
}

/// Proves that a payout opens a committed note.
#[derive(Clone, Copy, Debug, ZkCircuit)]
pub struct Withdrawal {
    pub private: Note,
    pub public: Payout,
}

impl Withdrawal {
    /// A note of 250 paid to a destination of seven bytes, with its commitment.
    pub fn example() -> Self {
        let destination = Address::new_from_array([7u8; 32]);
        let mut preimage = vec![constant(250u64), constant(99u64)];
        preimage.extend(
            zolana_zk_dsl::verifier::pack_be::<32, 2>(destination.as_array())
                .iter()
                .map(|chunk| {
                    constant(field(chunk, "a destination chunk").expect("below the modulus"))
                }),
        );
        let commitment = value(&poseidon(&preimage).expect("hash")).expect("constant");
        Self {
            private: Note {
                amount: 250,
                blinding: Field::from(99u64),
            },
            public: Payout {
                commitment,
                amount: 250,
                destination,
            },
        }
    }
}

impl Circuit for WithdrawalCircuit {
    type Output = Public<PayoutCircuit>;

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        let note = &self.private;
        let payout = &self.public;
        let mut preimage = vec![note.amount.var(), note.blinding.clone()];
        preimage.extend(payout.destination.packed());
        poseidon(&preimage)?.assert_equal(&payout.commitment, PAYOUT_RULE)?;
        note.amount.assert_equal(&payout.amount, PAYOUT_RULE)?;
        Ok(Public(payout.clone()))
    }
}
