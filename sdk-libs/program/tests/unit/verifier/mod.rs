mod layout;
mod public_hash;
mod render;
mod settlement;

use zolana_keypair::{ShieldedAddress, ShieldedKeypair, SigningKey};
use zolana_program::{
    circuit::PublicInputs,
    conversion::{to_bytes, var, Allocator, ProofInput},
};

pub const PRIVATE_TX_HASH: [u8; 32] = [0x0b; 32];

#[derive(Clone, PublicInputs)]
pub struct Settlement {
    pub amount: u64,
    pub paid: bool,
    pub recipient: ShieldedAddress,
    pub signers: [ShieldedAddress; 2],
    pub limits: [[u32; 2]; 2],
}

#[derive(Clone, PublicInputs)]
pub struct Unconditional;

pub fn address(seed: u8) -> ShieldedAddress {
    ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[seed; 32]))
        .expect("keypair")
        .shielded_address()
        .expect("shielded address")
}

pub fn owner_hash(address: &ShieldedAddress) -> [u8; 32] {
    address.owner_hash().expect("owner hash")
}

pub fn inputs() -> Settlement {
    Settlement {
        amount: 1_250_000,
        paid: true,
        recipient: address(6),
        signers: [address(7), address(8)],
        limits: [[10, 20], [u32::MAX, 0]],
    }
}

pub fn circuit_hash<P: ProofInput>(public_inputs: &P) -> [u8; 32]
where
    P::Circuit: PublicInputs,
{
    let circuit = public_inputs
        .instantiate(&Allocator::native())
        .expect("native instantiation");
    let transaction_hash = var(&PRIVATE_TX_HASH, "a private transaction hash").expect("field");
    to_bytes(&circuit.hash(&transaction_hash).expect("circuit hash")).expect("bytes")
}
