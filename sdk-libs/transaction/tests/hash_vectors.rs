//! Byte-literal regression fixtures for every hash a transfer produces.
//!
//! Nothing hermetic covered these before: the proof-backed suites need
//! `--features proofs` and a running prover, so a refactor could change a
//! commitment, a nullifier or the signed message and no test in the default
//! suite would notice. Every expected value below is a hardcoded literal
//! captured from the implementation at the commit that added this file. None of
//! them is recomputed from the code under test, so a changed hash fails here.
//!
//! These fixtures assemble `SppProofInputs` through the public hash and encoding
//! APIs with fixed seeds, blindings, salt, and slot ordering. They pin low-level
//! commitment/encoding/message compatibility; they do not exercise the
//! `ConfidentialTransaction` builder's randomization, change, padding or ordering.
//!
//! Case A: one real input and one dummy, `IN2_OUT3`, output tree 0,
//! sender as fee payer (`Account(0)`).
//!
//! Case B: two real inputs in trees 3 and 1 with two dummies in tree 3,
//! `IN4_OUT4`, output tree 2, relayed fee payer (`Inline`).

use solana_address::Address;
use zolana_interface::instruction::instruction_data::transact::{OwnerTag, TransactOutput};
use zolana_keypair::{constants::SALT_LEN, hash::sha256, shielded::ShieldedKeypair, SigningKey};
use zolana_transaction::{
    instructions::transact::{ExternalData, PrivateTxHash, Shape, SppProofInputs},
    serialization::{
        confidential::{Confidential, ConfidentialEncode, ConfidentialOutputPlaintext},
        UtxoSerialization,
    },
    utxo::{
        derive_output_blinding_seed, derive_transact_output_blinding, SppProofInputUtxo,
        SppProofOutputUtxo,
    },
    Data, Mint, Utxo,
};

const SALT: [u8; SALT_LEN] = [0x5au8; SALT_LEN];
const BLINDING_SEED: [u8; 32] = blinding(0x42);
const SENDER_SEED: u8 = 7;
const RECIPIENT_SEED: u8 = 9;
const RELAYED_PAYER: [u8; 32] = [3u8; 32];

/// A fixed blinding whose leading byte is zero, so the 32 bytes are always below
/// the BN254 modulus and Poseidon accepts them.
const fn blinding(byte: u8) -> [u8; 32] {
    let mut out = [byte; 32];
    out[0] = 0;
    out
}

// ---------------------------------------------------------------------------
// Case A -- one real input, one dummy, shape IN2_OUT3, output tree 0.
// ---------------------------------------------------------------------------

const CASE_A_INPUT_0_HASH: [u8; 32] = [
    0x11, 0xb8, 0x0e, 0x57, 0xe9, 0xe8, 0x79, 0x73, 0x64, 0x8d, 0x04, 0x91, 0x95, 0xcb, 0x4a, 0x95,
    0xe7, 0x5a, 0x9b, 0x69, 0xaa, 0xc4, 0x5a, 0xbb, 0x9c, 0x4d, 0xa8, 0x1f, 0xee, 0xc4, 0x5f, 0x07,
];
const CASE_A_INPUT_0_NULLIFIER: [u8; 32] = [
    0x05, 0x17, 0x37, 0xd4, 0xaf, 0x5d, 0x70, 0xf1, 0xcc, 0xae, 0xee, 0xfc, 0xe2, 0x07, 0x74, 0x6e,
    0xfd, 0xe8, 0x65, 0x9f, 0xda, 0xba, 0x87, 0xe2, 0x13, 0x89, 0x15, 0x92, 0x01, 0x4f, 0xd9, 0x88,
];
/// Slot 1 is the dummy: it still has a hash and a nullifier of its own, because
/// the circuit proves nullifier non-inclusion for every slot.
const CASE_A_INPUT_1_HASH: [u8; 32] = [
    0x2a, 0x56, 0xf1, 0xf4, 0x77, 0xbd, 0x23, 0xd3, 0xfd, 0xc5, 0x2b, 0xaa, 0xdf, 0x64, 0x21, 0xf3,
    0xf2, 0xbb, 0x6e, 0x89, 0x51, 0xd0, 0x72, 0xb1, 0x85, 0xf5, 0x13, 0xd6, 0x7f, 0x0f, 0x4b, 0x07,
];
const CASE_A_INPUT_1_NULLIFIER: [u8; 32] = [
    0x21, 0x84, 0x02, 0xf3, 0x89, 0xcc, 0xb5, 0x4e, 0x99, 0x95, 0x9e, 0x94, 0x4e, 0x71, 0x8e, 0xc4,
    0xff, 0xa2, 0xb8, 0x70, 0xc1, 0x77, 0x69, 0xf2, 0xb7, 0x3e, 0x8e, 0xc9, 0x63, 0xba, 0x71, 0x63,
];
const CASE_A_FIRST_NULLIFIER: [u8; 32] = [
    0x05, 0x17, 0x37, 0xd4, 0xaf, 0x5d, 0x70, 0xf1, 0xcc, 0xae, 0xee, 0xfc, 0xe2, 0x07, 0x74, 0x6e,
    0xfd, 0xe8, 0x65, 0x9f, 0xda, 0xba, 0x87, 0xe2, 0x13, 0x89, 0x15, 0x92, 0x01, 0x4f, 0xd9, 0x88,
];
/// Slot 0 is the padding output that stands in for the absent SPL change: a real
/// zero-amount SOL output owned by the sender, with a real commitment.
const CASE_A_OUTPUT_0_COMMITMENT: [u8; 32] = [
    0x20, 0xcc, 0x3d, 0xde, 0x0d, 0x53, 0x98, 0x96, 0x0f, 0x53, 0x13, 0x36, 0x2d, 0x42, 0x73, 0xd4,
    0xe6, 0xe6, 0x31, 0x23, 0x8c, 0xfd, 0xbe, 0x0a, 0x35, 0x29, 0x97, 0xb0, 0xad, 0x65, 0x03, 0x95,
];
const CASE_A_OUTPUT_1_COMMITMENT: [u8; 32] = [
    0x10, 0xcd, 0x42, 0xef, 0x14, 0x78, 0x50, 0x21, 0x1f, 0xff, 0xcc, 0xf5, 0x82, 0x24, 0x05, 0x29,
    0xc2, 0xad, 0x01, 0xd3, 0x97, 0x7d, 0x11, 0x7b, 0x80, 0x2b, 0xc2, 0x87, 0xca, 0xc6, 0xcf, 0x96,
];
const CASE_A_OUTPUT_2_COMMITMENT: [u8; 32] = [
    0x24, 0xb1, 0x5a, 0xb2, 0x25, 0xba, 0xbb, 0x11, 0x3a, 0xd1, 0x45, 0xbe, 0xf0, 0x9d, 0x45, 0x4b,
    0xc1, 0xa1, 0xb3, 0x51, 0x81, 0x9c, 0x78, 0x63, 0x6a, 0xd2, 0x4d, 0x18, 0xec, 0xc9, 0x5e, 0x26,
];
const CASE_A_EXTERNAL_DATA_HASH: [u8; 32] = [
    0x00, 0xa0, 0xba, 0x84, 0xc8, 0xb4, 0x8c, 0x9d, 0xd4, 0x63, 0x66, 0xa3, 0x32, 0x7c, 0x3f, 0x10,
    0x93, 0x31, 0xd1, 0xe0, 0x7b, 0x96, 0xc1, 0x07, 0xa1, 0xd8, 0x4c, 0xb8, 0xe4, 0x57, 0x4d, 0xf3,
];
const CASE_A_PRIVATE_TX_BLINDING: [u8; 32] = [
    0x27, 0x7f, 0xcd, 0x43, 0x21, 0x50, 0x31, 0x7d, 0x6d, 0x85, 0x6d, 0xfe, 0x4c, 0x18, 0x71, 0xdc,
    0xac, 0xf7, 0xaa, 0x20, 0xcd, 0xde, 0x4e, 0x91, 0x7e, 0xfd, 0x83, 0x0b, 0x64, 0x56, 0xe7, 0xfd,
];
const CASE_A_PRIVATE_TX_HASH: [u8; 32] = [
    0x0e, 0xda, 0x88, 0xe8, 0x6d, 0xf7, 0x3d, 0x27, 0xbf, 0xc6, 0x4e, 0xec, 0xfe, 0xf1, 0x40, 0x69,
    0x16, 0x97, 0x5e, 0x8e, 0x83, 0xc4, 0x67, 0xf4, 0xc7, 0x30, 0x1b, 0xe1, 0xc8, 0x21, 0xb4, 0xe7,
];
const CASE_A_MESSAGE_HASH: [u8; 32] = [
    0x43, 0x37, 0x5d, 0x12, 0x74, 0x42, 0xd1, 0x2c, 0x61, 0xe0, 0xc9, 0xbe, 0x94, 0x1f, 0x82, 0x0f,
    0xe7, 0xa5, 0xaf, 0x30, 0xf5, 0x3d, 0x0e, 0x7c, 0xe2, 0xbb, 0xbe, 0x1e, 0x28, 0xae, 0x2d, 0x98,
];

// ---------------------------------------------------------------------------
// Case B -- two real inputs in two trees, two dummies, shape IN4_OUT4,
// output tree 2, relayed fee payer.
// ---------------------------------------------------------------------------

const CASE_B_INPUT_0_HASH: [u8; 32] = [
    0x0b, 0x62, 0xcd, 0xe1, 0x6b, 0xbd, 0x04, 0xc0, 0x31, 0xa6, 0xf2, 0x00, 0x77, 0x1b, 0x3b, 0x70,
    0x1e, 0x48, 0x31, 0xff, 0x34, 0x0e, 0x70, 0xa4, 0x32, 0x9f, 0x3d, 0x4c, 0x1c, 0xca, 0xb9, 0xad,
];
const CASE_B_INPUT_0_NULLIFIER: [u8; 32] = [
    0x20, 0x89, 0x30, 0x9c, 0x50, 0xba, 0x3a, 0x3d, 0x00, 0x61, 0x01, 0x93, 0x31, 0x63, 0x1a, 0x29,
    0xef, 0xb6, 0xb1, 0x90, 0x1e, 0xed, 0xfe, 0xf3, 0x3f, 0xe6, 0xb4, 0x9a, 0x34, 0x6c, 0x15, 0x38,
];
/// Slots 1 and 2 are fixed dummies in tree 3's contiguous run.
const CASE_B_INPUT_1_HASH: [u8; 32] = [
    0x13, 0x1c, 0x29, 0xf8, 0x3a, 0xda, 0x89, 0x8d, 0xe2, 0xef, 0x9e, 0xf9, 0x28, 0xd2, 0x5b, 0x22,
    0xe4, 0xfc, 0x99, 0xd9, 0x29, 0xef, 0x38, 0xc4, 0x29, 0xaa, 0x9e, 0x6a, 0xe5, 0x0c, 0x0e, 0x57,
];
const CASE_B_INPUT_1_NULLIFIER: [u8; 32] = [
    0x02, 0xb5, 0x38, 0xb1, 0xf0, 0xe4, 0x62, 0x1c, 0x7c, 0xc9, 0x60, 0x1f, 0xab, 0x53, 0xc0, 0x69,
    0xc1, 0xec, 0x2e, 0xad, 0xd5, 0x77, 0x6b, 0x2a, 0x07, 0x04, 0xce, 0x7b, 0x08, 0x1d, 0x09, 0x11,
];
const CASE_B_INPUT_2_HASH: [u8; 32] = [
    0x04, 0xe6, 0x97, 0x32, 0xb3, 0xa5, 0x66, 0x9d, 0x68, 0xb7, 0x2f, 0x76, 0x24, 0x55, 0x1c, 0xd6,
    0x1a, 0x0d, 0x8d, 0xf1, 0xba, 0x93, 0xac, 0xe7, 0x38, 0xd1, 0x40, 0x0e, 0x36, 0x3d, 0x23, 0xb5,
];
const CASE_B_INPUT_2_NULLIFIER: [u8; 32] = [
    0x0f, 0x45, 0x7d, 0xac, 0x30, 0x25, 0x91, 0x30, 0xc9, 0x05, 0x97, 0xe1, 0x78, 0xff, 0xdb, 0xb2,
    0x5f, 0x2e, 0x7a, 0x6d, 0x2f, 0x47, 0x9f, 0xed, 0x0b, 0x8c, 0x88, 0x58, 0x98, 0xae, 0x7b, 0x0e,
];
/// Slot 3 is the tree-1 spend, explicitly placed after tree 3's padding.
const CASE_B_INPUT_3_HASH: [u8; 32] = [
    0x00, 0x37, 0x2d, 0x9f, 0x39, 0xc4, 0xba, 0x75, 0x32, 0x05, 0x3e, 0x22, 0xf8, 0x10, 0x4c, 0x7b,
    0x81, 0x06, 0x94, 0x2a, 0xc7, 0x9d, 0x3b, 0xee, 0x55, 0xf0, 0x67, 0xa6, 0x96, 0xcb, 0x82, 0x24,
];
const CASE_B_INPUT_3_NULLIFIER: [u8; 32] = [
    0x18, 0x64, 0x18, 0xe5, 0x04, 0xde, 0x21, 0x8f, 0x24, 0x83, 0xdf, 0x94, 0x0e, 0x5b, 0x11, 0xa6,
    0x77, 0x3a, 0x56, 0x6b, 0xf0, 0xff, 0x1b, 0xff, 0x2f, 0xf8, 0xa2, 0x62, 0xbd, 0x54, 0xc6, 0xd6,
];
const CASE_B_FIRST_NULLIFIER: [u8; 32] = [
    0x20, 0x89, 0x30, 0x9c, 0x50, 0xba, 0x3a, 0x3d, 0x00, 0x61, 0x01, 0x93, 0x31, 0x63, 0x1a, 0x29,
    0xef, 0xb6, 0xb1, 0x90, 0x1e, 0xed, 0xfe, 0xf3, 0x3f, 0xe6, 0xb4, 0x9a, 0x34, 0x6c, 0x15, 0x38,
];
/// Slot 0 is the padding output standing in for the absent SPL change.
const CASE_B_OUTPUT_0_COMMITMENT: [u8; 32] = [
    0x01, 0xca, 0x01, 0xd4, 0x94, 0x96, 0x89, 0x82, 0x0b, 0x69, 0x91, 0x66, 0x31, 0x48, 0x38, 0xd0,
    0x85, 0x03, 0x6e, 0x79, 0x01, 0x35, 0x00, 0x59, 0x97, 0xec, 0x69, 0x7a, 0x5f, 0x95, 0xaf, 0xee,
];
const CASE_B_OUTPUT_1_COMMITMENT: [u8; 32] = [
    0x2e, 0xa8, 0x74, 0x7e, 0x84, 0x68, 0x8f, 0x91, 0x4e, 0xc5, 0x30, 0x0f, 0xea, 0xb1, 0x9b, 0x71,
    0xba, 0x46, 0x76, 0x0b, 0xb5, 0xc1, 0xfb, 0x09, 0x76, 0xf5, 0x00, 0x95, 0xf8, 0xba, 0x7a, 0x7b,
];
const CASE_B_OUTPUT_2_COMMITMENT: [u8; 32] = [
    0x17, 0x48, 0x83, 0xf3, 0x3e, 0x8e, 0x83, 0xaa, 0x8e, 0x7f, 0xf3, 0x5b, 0x11, 0x31, 0xc3, 0xd4,
    0x8b, 0x29, 0xb8, 0xf7, 0xb9, 0x3d, 0x94, 0x29, 0x8a, 0xf7, 0x3d, 0x31, 0xa0, 0x15, 0x21, 0x2e,
];
/// Slot 3 is the padding output appended to fill `IN4_OUT4`.
const CASE_B_OUTPUT_3_COMMITMENT: [u8; 32] = [
    0x2c, 0x47, 0x12, 0xb5, 0xaa, 0x34, 0xa1, 0xdb, 0xb6, 0x59, 0x69, 0xc7, 0x19, 0x0a, 0x29, 0x10,
    0xa2, 0x8c, 0x76, 0xfe, 0x9d, 0x3a, 0x4b, 0x22, 0x4d, 0x4a, 0x9d, 0xd2, 0x9c, 0x27, 0x12, 0xeb,
];
const CASE_B_EXTERNAL_DATA_HASH: [u8; 32] = [
    0x00, 0x2c, 0xf3, 0x99, 0xdd, 0xda, 0xc5, 0x5b, 0x06, 0x72, 0x3d, 0x2a, 0x22, 0x4c, 0x3c, 0x15,
    0x70, 0x8e, 0x63, 0x9a, 0x9b, 0x62, 0x99, 0x06, 0x58, 0x10, 0xb3, 0x94, 0x61, 0xe9, 0xc1, 0x9c,
];
const CASE_B_PRIVATE_TX_BLINDING: [u8; 32] = [
    0x08, 0xf3, 0x82, 0x64, 0xc4, 0xc4, 0xf7, 0x91, 0xb8, 0x41, 0xd5, 0x5f, 0xa6, 0xa4, 0x8c, 0xe9,
    0x81, 0x60, 0x9c, 0x14, 0x1e, 0x22, 0x39, 0x39, 0xe4, 0x6d, 0x14, 0xe1, 0x77, 0x4f, 0x00, 0x78,
];
const CASE_B_PRIVATE_TX_HASH: [u8; 32] = [
    0x01, 0x25, 0xa5, 0xbd, 0xf4, 0x3c, 0xd6, 0x04, 0x5a, 0xd5, 0xa3, 0x9b, 0x5f, 0x04, 0xe7, 0x0e,
    0x0d, 0x2c, 0x6a, 0xe5, 0xa1, 0xaa, 0x7e, 0xf6, 0xb6, 0x36, 0x41, 0xcb, 0xba, 0xb3, 0xb3, 0x0f,
];
const CASE_B_MESSAGE_HASH: [u8; 32] = [
    0xfb, 0x5f, 0xe7, 0x1a, 0xaf, 0x8c, 0x31, 0x07, 0x6f, 0x81, 0xe6, 0xd5, 0xdb, 0x4f, 0x27, 0xdf,
    0xc3, 0xab, 0x97, 0x91, 0xe9, 0x2e, 0x13, 0x85, 0xd2, 0x57, 0x84, 0x94, 0x03, 0xd9, 0x16, 0xa7,
];

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn keypair(seed: u8) -> ShieldedKeypair {
    ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[seed; 32])).expect("keypair")
}

fn ed25519_address(keypair: &ShieldedKeypair) -> Address {
    Address::new_from_array(keypair.signing_pubkey().as_ed25519().expect("ed25519 key"))
}

fn real_input(
    keypair: &ShieldedKeypair,
    amount: u64,
    blinding: [u8; 32],
    tree_id: u16,
) -> SppProofInputUtxo {
    let utxo = Utxo {
        owner: keypair.signing_pubkey(),
        asset: Mint::SOL,
        amount,
        blinding,
        ring_program_id: None,
        data: Data::default(),
    };
    let nullifier_pubkey = keypair
        .shielded_address()
        .expect("address")
        .nullifier_pubkey;
    let utxo_hash = utxo
        .hash(&nullifier_pubkey, &[0; 32], &[0; 32], tree_id)
        .expect("hash");
    let nullifier = keypair.nullifier(&utxo_hash, &blinding).expect("nullifier");
    SppProofInputUtxo {
        utxo,
        nullifier_pubkey,
        utxo_hash,
        nullifier,
        data_hash: None,
        ring_data_hash: None,
        tree_id,
        leaf_index: 0,
    }
}

/// Fixed dummy commitments keep the fixture independent of OS randomness.
fn fixed_dummy(blinding: [u8; 32], tree_id: u16) -> SppProofInputUtxo {
    SppProofInputUtxo::dummy_with_blinding(blinding, tree_id).expect("dummy")
}

struct Fixture {
    /// Inputs in the fixture's explicit contiguous tree order.
    inputs: Vec<SppProofInputUtxo>,
    first_nullifier: [u8; 32],
    /// Declared input trees, in first-use order.
    input_tree_ids: Vec<u16>,
    shape: Shape,
    output_commitments: Vec<[u8; 32]>,
    output_amounts: Vec<u64>,
    output_is_dummy: Vec<bool>,
    proof_inputs: SppProofInputs,
}

impl Fixture {
    fn input_hashes(&self) -> Vec<[u8; 32]> {
        self.inputs.iter().map(|input| input.hash()).collect()
    }

    fn input_nullifiers(&self) -> Vec<[u8; 32]> {
        self.inputs.iter().map(|input| input.nullifier()).collect()
    }

    fn input_tree_ids_per_slot(&self) -> Vec<u16> {
        self.inputs.iter().map(|input| input.tree_id).collect()
    }

    fn external_data_hash(&self) -> [u8; 32] {
        self.proof_inputs
            .external_data
            .hash()
            .expect("external data hash")
    }

    fn private_tx_blinding(&self) -> [u8; 32] {
        self.proof_inputs
            .private_tx_blinding()
            .expect("private tx blinding")
    }

    /// The input vector `message_hash` builds: a dummy contributes `[0u8; 32]`.
    fn input_hashes_with_dummies_zeroed(&self) -> Vec<[u8; 32]> {
        self.inputs
            .iter()
            .map(|input| {
                if input.is_dummy() {
                    [0u8; 32]
                } else {
                    input.hash()
                }
            })
            .collect()
    }

    /// The counterfactual output vector: zero-amount padding slots treated the
    /// way dummy inputs are. `message_hash` does not do this.
    fn output_hashes_with_padding_zeroed(&self) -> Vec<[u8; 32]> {
        self.output_amounts
            .iter()
            .zip(self.output_commitments.iter())
            .map(
                |(amount, commitment)| {
                    if *amount == 0 {
                        [0u8; 32]
                    } else {
                        *commitment
                    }
                },
            )
            .collect()
    }

    fn private_tx_hash(&self, input_hashes: &[[u8; 32]], output_hashes: &[[u8; 32]]) -> [u8; 32] {
        PrivateTxHash::new(
            input_hashes,
            output_hashes,
            &self.external_data_hash(),
            &self.private_tx_blinding(),
        )
        .hash()
        .expect("private tx hash")
    }
}

fn build(
    inputs: Vec<SppProofInputUtxo>,
    payer: Address,
    shape: Shape,
    output_tree_id: u16,
    recipient_amount: u64,
) -> Fixture {
    let sender = keypair(SENDER_SEED);
    let recipient = keypair(RECIPIENT_SEED);
    let sender_address = sender.shielded_address().expect("sender address");
    let recipient_address = recipient.shielded_address().expect("recipient address");
    let first_nullifier = inputs.first().expect("input").nullifier();
    let mut input_tree_ids = Vec::new();
    for input in &inputs {
        if !input.is_dummy() && !input_tree_ids.contains(&input.tree_id) {
            input_tree_ids.push(input.tree_id);
        }
    }
    let input_amount = inputs
        .iter()
        .try_fold(0u64, |total, input| total.checked_add(input.utxo.amount))
        .expect("fixture input total");
    let change = input_amount
        .checked_sub(recipient_amount)
        .expect("funded fixture");
    // Preserve the original vectors' explicit output layout. This is not a
    // model or test of the production builder's current output selection.
    let mut amounts = vec![0, change, recipient_amount];
    amounts.resize(shape.n_outputs(), 0);
    let output_blinding_seed = derive_output_blinding_seed(&first_nullifier, &BLINDING_SEED)
        .expect("output blinding seed");
    let tx = sender
        .get_transaction_viewing_key(&first_nullifier)
        .expect("viewing key");
    let mut output_utxos = Vec::new();
    let mut outputs = Vec::new();
    let mut resolved_owner_tags = Vec::new();
    for (index, amount) in amounts.into_iter().enumerate() {
        let owner = if index == 2 {
            recipient_address
        } else {
            sender_address
        };
        let slot_index = u32::try_from(index).expect("slot index");
        let blinding =
            derive_transact_output_blinding(&first_nullifier, &output_blinding_seed, slot_index)
                .expect("output blinding");
        let resolved = owner
            .signing_pubkey
            .confidential_view_tag()
            .expect("view tag");
        let output = SppProofOutputUtxo {
            asset: Mint::SOL,
            amount,
            blinding,
            owner_address: Some(owner),
            owner_tag: Some(resolved),
            ..Default::default()
        };
        let message = Confidential::encode_plaintext(
            &ConfidentialOutputPlaintext {
                asset_id: Mint::SOL.asset_id,
                amount,
                blinding,
                ring_program_id: None,
                data: Data::default(),
            },
            resolved,
            &ConfidentialEncode {
                tx: tx.clone(),
                recipient_pubkey: owner.viewing_pubkey,
                salt: SALT,
                slot_index,
            },
        )
        .expect("encrypt output");
        assert_eq!(message.view_tag, resolved);
        let owner_tag = if index != 2 && payer == ed25519_address(&sender) {
            OwnerTag::Account(0)
        } else {
            OwnerTag::Inline(resolved)
        };
        outputs.push(TransactOutput {
            utxo_hash: output.hash(output_tree_id).expect("commitment"),
            owner_tag,
            data: Some(message.data),
        });
        resolved_owner_tags.push(resolved);
        output_utxos.push(output);
    }
    let proof_inputs = SppProofInputs {
        input_utxos: inputs,
        output_utxos,
        blinding_seed: BLINDING_SEED,
        output_tree_id,
        external_data: ExternalData::new(
            *tx.pubkey().as_bytes(),
            SALT,
            outputs,
            resolved_owner_tags,
            vec![],
        ),
        payer,
    };
    assert_eq!(proof_inputs.check_shape().expect("fixture shape"), shape);
    let first_nullifier = proof_inputs.first_nullifier().expect("first nullifier");
    let inputs = proof_inputs.input_utxos.clone();
    let output_commitments = proof_inputs
        .external_data
        .outputs
        .iter()
        .map(|output| output.utxo_hash)
        .collect();
    let output_amounts = proof_inputs
        .output_utxos
        .iter()
        .map(|out| out.amount)
        .collect();
    let output_is_dummy = proof_inputs
        .output_utxos
        .iter()
        .map(|out| out.is_dummy())
        .collect();

    Fixture {
        inputs,
        first_nullifier,
        input_tree_ids,
        shape,
        output_commitments,
        output_amounts,
        output_is_dummy,
        proof_inputs,
    }
}

fn case_a() -> Fixture {
    let sender = keypair(SENDER_SEED);
    build(
        vec![
            real_input(&sender, 10, blinding(0xa1), 0),
            fixed_dummy(blinding(0xd1), 0),
        ],
        ed25519_address(&sender),
        Shape::IN2_OUT3,
        0,
        4,
    )
}

fn case_b() -> Fixture {
    let sender = keypair(SENDER_SEED);
    build(
        vec![
            real_input(&sender, 6, blinding(0xb1), 3),
            fixed_dummy(blinding(0xd2), 3),
            fixed_dummy(blinding(0xd3), 3),
            real_input(&sender, 5, blinding(0xb2), 1),
        ],
        Address::new_from_array(RELAYED_PAYER),
        Shape::IN4_OUT4,
        2,
        4,
    )
}

// ---------------------------------------------------------------------------
// 1. Input commitments and nullifiers
// ---------------------------------------------------------------------------

#[test]
fn case_a_input_utxo_hashes() {
    let hashes = case_a().input_hashes();
    assert_eq!(hashes.len(), 2);
    assert_eq!(hashes.first(), Some(&CASE_A_INPUT_0_HASH));
    assert_eq!(hashes.get(1), Some(&CASE_A_INPUT_1_HASH));
}

#[test]
fn case_a_input_nullifiers() {
    let nullifiers = case_a().input_nullifiers();
    assert_eq!(nullifiers.len(), 2);
    assert_eq!(nullifiers.first(), Some(&CASE_A_INPUT_0_NULLIFIER));
    assert_eq!(nullifiers.get(1), Some(&CASE_A_INPUT_1_NULLIFIER));
}

#[test]
fn case_b_input_utxo_hashes() {
    let hashes = case_b().input_hashes();
    assert_eq!(hashes.len(), 4);
    assert_eq!(hashes.first(), Some(&CASE_B_INPUT_0_HASH));
    assert_eq!(hashes.get(1), Some(&CASE_B_INPUT_1_HASH));
    assert_eq!(hashes.get(2), Some(&CASE_B_INPUT_2_HASH));
    assert_eq!(hashes.get(3), Some(&CASE_B_INPUT_3_HASH));
}

#[test]
fn case_b_input_nullifiers() {
    let nullifiers = case_b().input_nullifiers();
    assert_eq!(nullifiers.len(), 4);
    assert_eq!(nullifiers.first(), Some(&CASE_B_INPUT_0_NULLIFIER));
    assert_eq!(nullifiers.get(1), Some(&CASE_B_INPUT_1_NULLIFIER));
    assert_eq!(nullifiers.get(2), Some(&CASE_B_INPUT_2_NULLIFIER));
    assert_eq!(nullifiers.get(3), Some(&CASE_B_INPUT_3_NULLIFIER));
}

// ---------------------------------------------------------------------------
// 2. First nullifier -- seeds every output blinding and the viewing key
// ---------------------------------------------------------------------------

#[test]
fn case_a_first_nullifier() {
    assert_eq!(case_a().first_nullifier, CASE_A_FIRST_NULLIFIER);
}

#[test]
fn case_b_first_nullifier() {
    assert_eq!(case_b().first_nullifier, CASE_B_FIRST_NULLIFIER);
}

// ---------------------------------------------------------------------------
// 3. Output commitments, every slot
// ---------------------------------------------------------------------------

#[test]
fn case_a_output_commitments() {
    let fixture = case_a();
    assert_eq!(fixture.shape, Shape::IN2_OUT3);
    assert_eq!(fixture.output_amounts, vec![0, 6, 4]);
    let commitments = &fixture.output_commitments;
    assert_eq!(commitments.len(), 3);
    assert_eq!(commitments.first(), Some(&CASE_A_OUTPUT_0_COMMITMENT));
    assert_eq!(commitments.get(1), Some(&CASE_A_OUTPUT_1_COMMITMENT));
    assert_eq!(commitments.get(2), Some(&CASE_A_OUTPUT_2_COMMITMENT));
}

#[test]
fn case_b_output_commitments() {
    let fixture = case_b();
    assert_eq!(fixture.shape, Shape::IN4_OUT4);
    assert_eq!(fixture.output_amounts, vec![0, 7, 4, 0]);
    let commitments = &fixture.output_commitments;
    assert_eq!(commitments.len(), 4);
    assert_eq!(commitments.first(), Some(&CASE_B_OUTPUT_0_COMMITMENT));
    assert_eq!(commitments.get(1), Some(&CASE_B_OUTPUT_1_COMMITMENT));
    assert_eq!(commitments.get(2), Some(&CASE_B_OUTPUT_2_COMMITMENT));
    assert_eq!(commitments.get(3), Some(&CASE_B_OUTPUT_3_COMMITMENT));
}

// ---------------------------------------------------------------------------
// 4. Fixture input tree order accepted by proof inputs
// ---------------------------------------------------------------------------

#[test]
fn case_a_input_tree_order() {
    let fixture = case_a();
    assert_eq!(fixture.input_tree_ids, vec![0]);
    assert_eq!(fixture.input_tree_ids_per_slot(), vec![0, 0]);
}

/// The fixture declares trees 3 then 1 and explicitly places both dummies in
/// tree 3's contiguous run. This does not assert builder regrouping behavior.
#[test]
fn case_b_input_tree_order() {
    let fixture = case_b();
    assert_eq!(fixture.input_tree_ids, vec![3, 1]);
    assert_eq!(fixture.input_tree_ids_per_slot(), vec![3, 3, 3, 1]);
    assert_eq!(
        fixture
            .inputs
            .iter()
            .map(|input| input.is_dummy())
            .collect::<Vec<_>>(),
        vec![false, true, true, false]
    );
}

// ---------------------------------------------------------------------------
// 5. External data hash of the encrypted transfer
// ---------------------------------------------------------------------------

#[test]
fn case_a_external_data_hash() {
    assert_eq!(case_a().external_data_hash(), CASE_A_EXTERNAL_DATA_HASH);
}

#[test]
fn case_b_external_data_hash() {
    assert_eq!(case_b().external_data_hash(), CASE_B_EXTERNAL_DATA_HASH);
}

// ---------------------------------------------------------------------------
// 6. Private transaction hash
// ---------------------------------------------------------------------------

#[test]
fn case_a_private_tx_hash() {
    let fixture = case_a();
    assert_eq!(fixture.private_tx_blinding(), CASE_A_PRIVATE_TX_BLINDING);
    let hash = fixture.private_tx_hash(
        &fixture.input_hashes_with_dummies_zeroed(),
        &fixture.output_commitments,
    );
    assert_eq!(hash, CASE_A_PRIVATE_TX_HASH);
}

#[test]
fn case_b_private_tx_hash() {
    let fixture = case_b();
    assert_eq!(fixture.private_tx_blinding(), CASE_B_PRIVATE_TX_BLINDING);
    let hash = fixture.private_tx_hash(
        &fixture.input_hashes_with_dummies_zeroed(),
        &fixture.output_commitments,
    );
    assert_eq!(hash, CASE_B_PRIVATE_TX_HASH);
}

// ---------------------------------------------------------------------------
// 7. Message hash -- sha256 of the private transaction hash
// ---------------------------------------------------------------------------

#[test]
fn case_a_message_hash() {
    let fixture = case_a();
    assert_eq!(
        fixture.proof_inputs.message_hash().expect("message hash"),
        CASE_A_MESSAGE_HASH
    );
    assert_eq!(sha256(&CASE_A_PRIVATE_TX_HASH), CASE_A_MESSAGE_HASH);
}

#[test]
fn case_b_message_hash() {
    let fixture = case_b();
    assert_eq!(
        fixture.proof_inputs.message_hash().expect("message hash"),
        CASE_B_MESSAGE_HASH
    );
    assert_eq!(sha256(&CASE_B_PRIVATE_TX_HASH), CASE_B_MESSAGE_HASH);
}

// ---------------------------------------------------------------------------
// The asymmetry the next refactor is most likely to erase
// ---------------------------------------------------------------------------

/// The two padded sides are not symmetric, and conflating them is the silent
/// break this file exists to catch.
///
/// A dummy INPUT contributes `[0u8; 32]` to the hashed vector: it is a slot that
/// provably carries nothing, and `message_hash` zeroes it to match what the
/// circuit hashes.
///
/// A padding OUTPUT contributes its real commitment. Since c6aa28953 a pad is a
/// genuine zero-amount SOL output owned by the sender, so `SppProofOutputUtxo::
/// is_dummy()` (owner is `None`) is false for it and `message_hash` hashes the
/// commitment it actually publishes. Zeroing it -- the obvious "symmetry" fix --
/// changes the signed message without changing a single visible field.
#[test]
fn a_padding_output_contributes_its_real_hash_while_a_dummy_input_contributes_zero() {
    for fixture in [case_a(), case_b()] {
        let (message_hash, private_tx_hash) = if fixture.shape == Shape::IN2_OUT3 {
            (CASE_A_MESSAGE_HASH, CASE_A_PRIVATE_TX_HASH)
        } else {
            (CASE_B_MESSAGE_HASH, CASE_B_PRIVATE_TX_HASH)
        };

        // Padding outputs are zero-amount but never dummies: they are real
        // sender-owned outputs and publish a real commitment.
        assert!(fixture.output_amounts.contains(&0));
        assert!(fixture.output_is_dummy.iter().all(|dummy| !dummy));
        assert!(fixture
            .output_commitments
            .iter()
            .all(|commitment| *commitment != [0u8; 32]));
        // Dummy inputs exist and are recognized as such.
        assert!(fixture.inputs.iter().any(|input| input.is_dummy()));

        // What the transfer actually hashes: dummy inputs zeroed, every output
        // slot at its real commitment.
        let actual = fixture.private_tx_hash(
            &fixture.input_hashes_with_dummies_zeroed(),
            &fixture.output_commitments,
        );
        assert_eq!(actual, private_tx_hash);
        assert_eq!(sha256(&actual), message_hash);
        assert_eq!(
            fixture.proof_inputs.message_hash().expect("message hash"),
            message_hash
        );

        // Zeroing the padding outputs too -- treating both padded sides alike --
        // produces a different signed message.
        let padding_outputs_zeroed = fixture.private_tx_hash(
            &fixture.input_hashes_with_dummies_zeroed(),
            &fixture.output_hashes_with_padding_zeroed(),
        );
        assert_ne!(padding_outputs_zeroed, private_tx_hash);
        assert_ne!(sha256(&padding_outputs_zeroed), message_hash);

        // The mirror image: hashing a dummy input at its real commitment
        // instead of zero also diverges.
        let dummy_inputs_at_real_hashes =
            fixture.private_tx_hash(&fixture.input_hashes(), &fixture.output_commitments);
        assert_ne!(dummy_inputs_at_real_hashes, private_tx_hash);
        assert_ne!(sha256(&dummy_inputs_at_real_hashes), message_hash);
    }
}
