//! The on-chain public hash recomputes the circuit's `PublicInputs` hash from
//! the instruction's plain values.

use spr_keypair::{ShieldedKeypair, SigningKey};
use spr_program::circuit::PublicInputs;
use spr_program::verifier::{address_hash, public_hash, Field as Public, VerifyError};
use spr_program::{from_bytes, to_bytes, Field, InputRecords, ShieldedAddress};

#[derive(PublicInputs)]
pub struct Settlement {
    pub amount: u64,
    pub paid: bool,
    pub recipient: ShieldedAddress,
    pub commitment: Field,
}

const TRANSACTION_HASH: [u8; 32] = [0x0b; 32];

fn native_address(seed: u8) -> spr_keypair::ShieldedAddress {
    ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[seed; 32]))
        .unwrap()
        .shielded_address()
        .unwrap()
}

#[test]
fn the_on_chain_public_hash_equals_the_circuit_hash() {
    let native = native_address(6);
    let settlement = Settlement {
        amount: 1_250_000,
        paid: true,
        recipient: InputRecords::new().address(&native).unwrap(),
        commitment: Field::from(77u64),
    };
    let circuit = settlement
        .hash(&from_bytes(&TRANSACTION_HASH).unwrap())
        .unwrap();
    let recipient = address_hash(
        &native.owner_hash().unwrap(),
        native.viewing_pubkey.as_bytes(),
    )
    .unwrap();
    let commitment = to_bytes(&settlement.commitment);
    let on_chain = public_hash(
        &[
            Public::Integer(1_250_000),
            Public::Bool(true),
            Public::Hash(&recipient),
            Public::Hash(&commitment),
        ],
        &TRANSACTION_HASH,
    );
    assert_eq!(on_chain, Ok(to_bytes(&circuit)));
    assert_eq!(recipient, native.address_hash().unwrap());
    assert_eq!(to_bytes(&settlement.recipient.hash().unwrap()), recipient);
}

#[test]
fn a_viewing_key_change_changes_the_address_hash() {
    let native = native_address(6);
    let other_viewer = spr_keypair::ShieldedAddress {
        viewing_pubkey: native_address(7).viewing_pubkey,
        ..native
    };
    assert_ne!(
        address_hash(
            &native.owner_hash().unwrap(),
            native.viewing_pubkey.as_bytes()
        ),
        address_hash(
            &other_viewer.owner_hash().unwrap(),
            other_viewer.viewing_pubkey.as_bytes()
        )
    );
}

#[test]
fn values_outside_the_field_and_more_than_eleven_fields_are_refused() {
    let outside = [0xff; 32];
    let fields = [Public::Integer(1); 12];
    assert_eq!(
        [
            public_hash(&[Public::Hash(&outside)], &TRANSACTION_HASH),
            public_hash(&[], &outside),
            public_hash(&fields, &TRANSACTION_HASH),
            public_hash(&fields[..11], &TRANSACTION_HASH).map(|_| [0; 32]),
        ],
        [
            Err(VerifyError::PublicInputs),
            Err(VerifyError::PublicInputs),
            Err(VerifyError::PublicInputs),
            Ok([0; 32]),
        ]
    );
}

#[test]
fn verification_errors_map_to_distinct_program_errors() {
    use solana_program_error::ProgramError;
    assert_eq!(
        [
            ProgramError::from(VerifyError::PublicInputs),
            ProgramError::from(VerifyError::Proof)
        ],
        [
            ProgramError::InvalidInstructionData,
            ProgramError::InvalidArgument
        ]
    );
}
