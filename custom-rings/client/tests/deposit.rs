//! Decoding ring deposits out of indexed output slots.
//!
//! A deposit publishes its ring, asset and amount in the clear, so these slots
//! are built with the same encoder the shielded pool emits and read back
//! without any key.

use solana_address::Address;
use zolana_interface::output_data::{
    encode_encrypted_ring_deposit_output, EncryptedRingDepositData, EncryptedRingDepositOutput,
    OutputDataEncoding, ENCRYPTED_RING_DEPOSIT_SCHEME,
};
use zolana_ring_client::{ring_deposits_in, RingDeposit};
use zolana_transaction::SOL_MINT;

const RING: Address = Address::new_from_array([9u8; 32]);
const OTHER_RING: Address = Address::new_from_array([8u8; 32]);
const TOKEN_MINT: Address = Address::new_from_array([7u8; 32]);

fn deposit_payload(ring: Address, asset: Address, amount: u64) -> Vec<u8> {
    encode_encrypted_ring_deposit_output(EncryptedRingDepositOutput {
        owner_utxo_hash: [1u8; 32],
        asset: asset.to_bytes(),
        amount,
        data_hash: None,
        ring_program_id: ring.to_bytes(),
        ring_data_hash: [2u8; 32],
        encrypted: EncryptedRingDepositData {
            tx_viewing_pk: [3u8; 33],
            salt: [4u8; 16],
            ciphertext: vec![5u8; 8],
        },
    })
}

fn encrypted_payload(scheme: u8, body: &[u8]) -> Vec<u8> {
    let mut blob = vec![scheme];
    blob.extend_from_slice(body);
    borsh::to_vec(&OutputDataEncoding::Encrypted(blob)).expect("borsh output data")
}

/// Deposits keep the position they hold in the transaction, and the ring is
/// read from the payload rather than assumed from the query.
#[test]
fn deposits_of_the_ring_are_returned_in_slot_order() {
    let slots = vec![
        ([0x10; 32], deposit_payload(RING, SOL_MINT, 1_000)),
        ([0x11; 32], deposit_payload(OTHER_RING, SOL_MINT, 2_000)),
        ([0x12; 32], vec![0xff; 64]),
        ([0x13; 32], deposit_payload(RING, TOKEN_MINT, 42)),
    ];

    assert_eq!(
        ring_deposits_in(slots, RING),
        vec![
            RingDeposit {
                depositor: [0x10; 32],
                asset: SOL_MINT,
                amount: 1_000,
            },
            RingDeposit {
                depositor: [0x13; 32],
                asset: TOKEN_MINT,
                amount: 42,
            },
        ]
    );
}

/// The mint of an SPL deposit is published in the clear, so it comes back
/// without the auditor opening anything.
#[test]
fn an_spl_deposit_reports_its_mint() {
    let deposits = ring_deposits_in(
        vec![([0x20; 32], deposit_payload(RING, TOKEN_MINT, 7))],
        RING,
    );
    assert_eq!(
        deposits,
        vec![RingDeposit {
            depositor: [0x20; 32],
            asset: TOKEN_MINT,
            amount: 7,
        }]
    );
}

#[test]
fn slots_that_are_not_ring_deposits_are_dropped() {
    let valid = deposit_payload(RING, SOL_MINT, 5);
    let body = &valid[valid.len() - 8..];
    let payloads = [
        // Another encryption scheme under the same encrypted encoding.
        encrypted_payload(ENCRYPTED_RING_DEPOSIT_SCHEME + 1, body),
        // The scheme byte alone, with no deposit body behind it.
        encrypted_payload(ENCRYPTED_RING_DEPOSIT_SCHEME, &[]),
        // A deposit scheme whose Borsh body stops short.
        encrypted_payload(ENCRYPTED_RING_DEPOSIT_SCHEME, &valid[..16]),
        borsh::to_vec(&OutputDataEncoding::Encrypted(Vec::new())).expect("empty blob"),
        borsh::to_vec(&OutputDataEncoding::Plaintext(valid.clone())).expect("plaintext"),
        vec![0xff; 32],
        Vec::new(),
    ];
    for payload in payloads {
        assert_eq!(ring_deposits_in(vec![([0x30; 32], payload)], RING), vec![]);
    }
    assert_eq!(ring_deposits_in(Vec::new(), RING), vec![]);
}

/// Trailing bytes after the deposit body are not a deposit, so a slot cannot
/// smuggle anything past the decoder.
#[test]
fn a_deposit_body_with_trailing_bytes_is_dropped() {
    let mut payload = deposit_payload(RING, SOL_MINT, 5);
    let OutputDataEncoding::Encrypted(mut blob) =
        borsh::from_slice(&payload).expect("encrypted output")
    else {
        panic!("encrypted output")
    };
    blob.push(0);
    payload = borsh::to_vec(&OutputDataEncoding::Encrypted(blob)).expect("borsh output data");

    assert_eq!(ring_deposits_in(vec![([0x40; 32], payload)], RING), vec![]);
}
