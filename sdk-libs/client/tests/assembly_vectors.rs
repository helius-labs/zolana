//! Byte-literal regression fixtures for the transact witness assembly.
//!
//! Witness assembly is pure computation: `assemble` and [`TransferProver::build`]
//! derive every hash and public input from the values they are handed, and only
//! `ProverClient::prove_transfer` needs the prover server. So this target is
//! hermetic and carries no `proofs` feature gate.
//!
//! One fixture transaction is built with no randomness at all -- fixed-seed
//! keypairs, a fixed blinding seed, a fixed encryption salt, a fixed Merkle
//! witness -- and every hash it produces is hardcoded below. The literals were
//! captured by running the assembly and are never recomputed here: an assertion
//! that derived its own expected value would pin nothing.
//!
//! What is pinned, and where each value comes from:
//!
//! - `AssembledTransfer::public_input_hash`, the single field element the proof
//!   commits to.
//! - `TransactIxData::private_tx_hash`, the value the `Transact` instruction
//!   publishes on chain.
//! - `assemble_inputs`: every entry of `input_hashes` and `nullifiers`,
//!   including the dummy slot.
//! - `assemble_outputs`: `output_hashes` and `private_tx_output_hashes`
//!   separately, because they are not the same vector.
//! - `SppProofInputs::message_hash()` (zolana-transaction) against `sha256` of
//!   the `private_tx_hash` zolana-client assembled, the cross-crate agreement
//!   `validate_authorization` depends on.
//!
//! `assemble_inputs` and `assemble_outputs` are `pub(crate)` in a `pub(crate)`
//! module, so an integration test cannot call them. Their vectors are pinned
//! through the public surface instead: `TransferProofResult` carries
//! `nullifiers` and `output_hashes` verbatim, the per-slot witness carries each
//! commitment and `is_dummy` flag, and
//! `pinned_input_and_output_vectors_rebuild_the_pinned_private_tx_hash` ties the
//! two vectors the result type does not expose -- `input_hashes` and
//! `private_tx_output_hashes` -- to the pinned `private_tx_hash`.

#[path = "common/encryption.rs"]
mod encryption_fixture;
#[path = "common/input.rs"]
mod input_fixture;
#[path = "common/blindings.rs"]
mod output_blindings;
#[path = "common/transfer.rs"]
mod transfer_fixture;

use crate::{
    encryption_fixture::finalized_transaction, input_fixture::wallet_utxo,
    transfer_fixture::transfer_prover,
};
use num_bigint::BigUint;
use solana_address::Address;
use zolana_client::{
    assemble, prover::field::be, MerkleContext, MerkleProof, NonInclusionProof, ProofAuthority,
    SpendProof, TransferProofResult, NULLIFIER_TREE_HEIGHT, STATE_TREE_HEIGHT,
};
use zolana_interface::instruction::instruction_data::transact::{TransactIxData, TransactProof};
use zolana_keypair::{hash::sha256, ShieldedKeypair, SigningKey};
use zolana_transaction::instructions::transact::SppProofInputs;
use zolana_transaction::utxo::SppProofInputUtxo;
use zolana_transaction::{
    instructions::transact::PrivateTxHash, Data, Mint, SppProofOutputUtxo, Utxo,
};

// ---------------------------------------------------------------------------
// Fixture inputs. Everything that would otherwise be random is fixed here.
// ---------------------------------------------------------------------------

const SENDER_SEED: u8 = 0x11;
const RECIPIENT_SEED: u8 = 0x22;
/// Not tree 0: a non-zero id is hashed into every commitment and every tree
/// slot, so it exposes any drift in how the tree id is folded in.
const TREE_ID: u16 = 3;
const SALT: [u8; 16] = [0x5a; 16];
const INPUT_AMOUNT: u64 = 10;
const SEND_AMOUNT: u64 = 4;
/// Published owner tag of the hand-built dummy output slot.
const DUMMY_OUTPUT_TAG: [u8; 32] = [0x6d; 32];

// ---------------------------------------------------------------------------
// Captured values: the padded transfer (2 inputs, 3 outputs).
// ---------------------------------------------------------------------------

const PUBLIC_INPUT_HASH: [u8; 32] = [
    0x18, 0x8f, 0x7b, 0x64, 0x18, 0xf1, 0x87, 0xde, 0x27, 0x6e, 0x41, 0xb6, 0x5c, 0x26, 0x95, 0x05,
    0x63, 0x0f, 0x13, 0xe8, 0x09, 0x7e, 0xd7, 0x2b, 0xa7, 0xf1, 0x8e, 0x06, 0x39, 0x8d, 0x37, 0x41,
];

const PRIVATE_TX_HASH: [u8; 32] = [
    0x1e, 0xa5, 0xb0, 0xae, 0xcf, 0x30, 0x3d, 0x1b, 0x76, 0xd6, 0x42, 0x01, 0xe7, 0xf4, 0xff, 0xf0,
    0x7c, 0xb0, 0xd4, 0xc9, 0xe3, 0xdd, 0xb7, 0x70, 0x64, 0xf6, 0xfd, 0x0c, 0x98, 0xb4, 0x39, 0xf7,
];

/// `sha256(PRIVATE_TX_HASH)`, the digest the P-256 rail signs and
/// `SppProofInputs::message_hash()` returns.
const MESSAGE_HASH: [u8; 32] = [
    0x8c, 0xb8, 0x88, 0x85, 0x13, 0xd4, 0x11, 0xb1, 0xb9, 0x1d, 0x23, 0xb6, 0x55, 0x5f, 0xab, 0x48,
    0x90, 0x0f, 0x7a, 0xd1, 0x81, 0x90, 0xbc, 0xf8, 0xe2, 0x66, 0x18, 0x64, 0x62, 0x64, 0x2d, 0x82,
];

const EXTERNAL_DATA_HASH: [u8; 32] = [
    0x00, 0xf2, 0xc8, 0x33, 0xa8, 0x2b, 0x29, 0xb5, 0x6b, 0xc3, 0xa3, 0xa4, 0x5f, 0x66, 0xf3, 0xbe,
    0xeb, 0x55, 0xc1, 0x4c, 0xae, 0xa1, 0x99, 0x04, 0x49, 0xda, 0xd1, 0xfa, 0x56, 0xea, 0x47, 0x14,
];

const PRIVATE_TX_BLINDING: [u8; 32] = [
    0x2f, 0x0d, 0x46, 0x00, 0xb7, 0x3f, 0xf5, 0x8f, 0x7b, 0x09, 0x96, 0xb4, 0x48, 0x43, 0xa6, 0xe9,
    0xb9, 0x10, 0x1e, 0xdd, 0x02, 0x49, 0x7a, 0x15, 0xbc, 0x08, 0xa0, 0x80, 0x04, 0xe2, 0x94, 0x41,
];

/// Commitment of the one real input, slot 0.
const REAL_INPUT_COMMITMENT: [u8; 32] = [
    0x0c, 0x79, 0x3f, 0xff, 0x49, 0xf0, 0x58, 0xa9, 0xcb, 0xc2, 0x7b, 0xec, 0xb3, 0xd3, 0x0c, 0x86,
    0xb4, 0x88, 0xc7, 0xa5, 0x0a, 0x2a, 0x75, 0x0a, 0x12, 0x3f, 0xa4, 0xa2, 0xf7, 0x6d, 0x95, 0x2a,
];

/// Commitment the padding slot carries *in the witness*. It is deliberately not
/// what slot 1 of [`INPUT_HASHES`] holds: the witness needs a real-looking
/// commitment, the private-tx hash chain gets zero.
const DUMMY_INPUT_COMMITMENT: [u8; 32] = [
    0x2a, 0xb9, 0x4f, 0x6b, 0xa9, 0xf9, 0x4c, 0x9a, 0xe5, 0xb8, 0x90, 0x50, 0x98, 0x03, 0x89, 0x09,
    0xa5, 0xf1, 0xde, 0x47, 0xfc, 0xc4, 0xe6, 0x77, 0xea, 0x30, 0x34, 0x26, 0xbe, 0x36, 0x38, 0x3d,
];

/// `assemble_inputs` -> `AssembledInputs::input_hashes`. Slot 1 is the padding
/// input, which contributes zero.
const INPUT_HASHES: [[u8; 32]; 2] = [REAL_INPUT_COMMITMENT, [0u8; 32]];

/// `assemble_inputs` -> `AssembledInputs::nullifiers`. Slot 1 is the padding
/// input's own nullifier, taken over a zero nullifier secret.
const NULLIFIERS: [[u8; 32]; 2] = [
    [
        0x06, 0x3a, 0x63, 0x05, 0x85, 0xec, 0xb0, 0x50, 0x14, 0x4d, 0x76, 0xef, 0xb6, 0xe5, 0xea,
        0xaf, 0xdd, 0xc5, 0x23, 0x01, 0x7b, 0xd7, 0xbf, 0x84, 0x27, 0x52, 0x8a, 0x7e, 0xd8, 0x21,
        0x8f, 0x6b,
    ],
    [
        0x26, 0x61, 0x31, 0x01, 0x61, 0xab, 0x2b, 0xc5, 0xd2, 0x37, 0x6d, 0x26, 0xc0, 0x90, 0x61,
        0xce, 0x05, 0x31, 0x30, 0x80, 0xb0, 0x36, 0x15, 0x3b, 0x4d, 0xaf, 0x88, 0xa6, 0x01, 0xb7,
        0xf5, 0x61,
    ],
];

/// Slot 0 is the transfer's padding output, slot 1 the sender's SOL change,
/// slot 2 the recipient.
const OUTPUT_HASHES: [[u8; 32]; 3] = [
    [
        0x10, 0xb2, 0x72, 0xdf, 0xfb, 0xcf, 0xfc, 0x4b, 0xe9, 0x5f, 0x54, 0xd7, 0x90, 0x25, 0xc4,
        0x17, 0x21, 0x12, 0xa9, 0x4b, 0x9a, 0x96, 0xf5, 0x10, 0x49, 0x87, 0x51, 0x1b, 0xcb, 0xc3,
        0x5d, 0xe2,
    ],
    [
        0x19, 0x67, 0xfb, 0xc6, 0xc9, 0x2b, 0x8d, 0x71, 0x9e, 0xc2, 0x23, 0x1f, 0x0d, 0xa9, 0x89,
        0xcc, 0x2d, 0x87, 0xb3, 0xc4, 0x11, 0xb7, 0x84, 0x63, 0x82, 0x4e, 0x70, 0xc9, 0x9e, 0x53,
        0x73, 0xd0,
    ],
    [
        0x04, 0x6c, 0x16, 0x21, 0x00, 0x1d, 0xb8, 0x19, 0xb0, 0xb8, 0x4b, 0x02, 0x6a, 0x0e, 0x23,
        0xb9, 0x5e, 0x89, 0xd7, 0x37, 0x70, 0x9c, 0xbc, 0xf8, 0x38, 0x51, 0x86, 0x8b, 0xa4, 0x47,
        0x59, 0x65,
    ],
];

/// `assemble_outputs` -> `AssembledOutputs::private_tx_output_hashes` for the
/// padded transfer. Identical to [`OUTPUT_HASHES`] because no slot of a
/// transfer is a dummy output any more -- the padding slot is a real
/// sender-owned output. See
/// `transfer_padding_output_is_not_a_dummy_so_both_output_vectors_carry_its_real_hash`.
const PRIVATE_TX_OUTPUT_HASHES: [[u8; 32]; 3] = OUTPUT_HASHES;

/// Witness `is_dummy` flag per output slot: no dummy in a padded transfer.
const OUTPUT_IS_DUMMY: [u8; 3] = [0, 0, 0];

/// Both inputs are spent from the one declared tree.
const INPUT_TREE_INDEXES: [u8; 2] = [0, 0];

// ---------------------------------------------------------------------------
// Captured values: the same transaction with slot 0 replaced by a real dummy
// output (`owner_address == None`), the only way the two output vectors part.
// ---------------------------------------------------------------------------

const DUMMY_OUTPUT_PUBLIC_INPUT_HASH: [u8; 32] = [
    0x11, 0x21, 0x26, 0x91, 0xaf, 0xf6, 0xc1, 0x95, 0x02, 0x13, 0x48, 0x9e, 0x95, 0xb2, 0xf0, 0x29,
    0xf6, 0x45, 0x28, 0xd9, 0x2f, 0xd7, 0xb9, 0xe9, 0x8b, 0xef, 0xff, 0xe4, 0x73, 0x6c, 0xed, 0xe9,
];

const DUMMY_OUTPUT_PRIVATE_TX_HASH: [u8; 32] = [
    0x28, 0x45, 0x2d, 0x41, 0x22, 0xf1, 0x53, 0x66, 0x0a, 0xf2, 0x01, 0x90, 0xdf, 0x28, 0xa5, 0x64,
    0x5b, 0x93, 0x5b, 0x7a, 0x5c, 0x3c, 0x70, 0x94, 0x31, 0x2d, 0xa9, 0x28, 0x41, 0xcd, 0x3b, 0x66,
];

const DUMMY_OUTPUT_MESSAGE_HASH: [u8; 32] = [
    0x74, 0x4f, 0xcb, 0x19, 0xd3, 0x5b, 0x09, 0xc7, 0xf0, 0x89, 0x34, 0x98, 0x00, 0x9b, 0x37, 0xfe,
    0x9e, 0x3b, 0x6a, 0xcb, 0x05, 0xa0, 0x9f, 0xa4, 0xb3, 0x90, 0xd9, 0x39, 0x4e, 0x8d, 0x19, 0x11,
];

/// The dummy slot's own commitment: a real hash, published like any other.
const DUMMY_OUTPUT_COMMITMENT: [u8; 32] = [
    0x1f, 0x22, 0xe6, 0x12, 0x01, 0x7e, 0x76, 0x04, 0x77, 0xdf, 0x7c, 0x8f, 0xb4, 0xc4, 0xe7, 0x42,
    0xc4, 0xd8, 0xb7, 0xbe, 0x83, 0x3c, 0xd0, 0xa6, 0xec, 0x53, 0xcc, 0x6e, 0x5f, 0x06, 0x4f, 0x68,
];

const DUMMY_OUTPUT_OUTPUT_HASHES: [[u8; 32]; 3] =
    [DUMMY_OUTPUT_COMMITMENT, OUTPUT_HASHES[1], OUTPUT_HASHES[2]];

const DUMMY_OUTPUT_PRIVATE_TX_OUTPUT_HASHES: [[u8; 32]; 3] =
    [[0u8; 32], OUTPUT_HASHES[1], OUTPUT_HASHES[2]];

const DUMMY_OUTPUT_IS_DUMMY: [u8; 3] = [1, 0, 0];

// ---------------------------------------------------------------------------
// Fixture construction.
// ---------------------------------------------------------------------------

/// A 32-byte value that is always a valid BN254 field element: the top byte is
/// zero, so it is below the modulus whatever `byte` is.
fn field_bytes(byte: u8) -> [u8; 32] {
    core::array::from_fn(|index| if index == 0 { 0 } else { byte })
}

fn keypair(seed: u8) -> ShieldedKeypair {
    ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[seed; 32]))
        .expect("fixed-seed Ed25519 keypair")
}

/// A padded 2-in/3-out transfer with every source of randomness replaced by a
/// constant: fixed-seed sender and recipient, a fixed blinding seed, an
/// explicit padding input with a fixed blinding, and a fixed encryption salt
/// handed to `ConfidentialTransaction::encrypt` so the ciphertexts -- and
/// therefore the external-data hash -- are reproducible.
fn transfer_fixture() -> SppProofInputs {
    let sender = keypair(SENDER_SEED);
    let recipient = keypair(RECIPIENT_SEED);
    let payer = Address::new_from_array(
        sender
            .signing_pubkey()
            .as_ed25519()
            .expect("sender Ed25519 pubkey"),
    );

    let real_input = wallet_utxo(
        Utxo {
            owner: sender.signing_pubkey(),
            asset: Mint::SOL,
            amount: INPUT_AMOUNT,
            blinding: field_bytes(0x31),
            ring_program_id: None,
            data: Data::default(),
        },
        &sender.nullifier_key,
        TREE_ID,
        7,
        None,
        None,
    )
    .into();
    let dummy_input = SppProofInputUtxo::dummy_with_blinding(field_bytes(0x32), TREE_ID).unwrap();
    let output = |owner: &ShieldedKeypair, amount| {
        SppProofOutputUtxo::new(Mint::SOL, amount, owner.shielded_address().unwrap()).unwrap()
    };
    finalized_transaction(
        vec![real_input, dummy_input],
        vec![
            output(&sender, 0),
            output(&sender, INPUT_AMOUNT - SEND_AMOUNT),
            output(&recipient, SEND_AMOUNT),
        ],
        &sender,
        payer,
        TREE_ID,
        field_bytes(0x41),
        SALT,
    )
}

/// [`transfer_fixture`] with the padding output slot replaced by an ownerless
/// dummy. It keeps the padding slot's blinding, so the derived blindings the
/// circuit re-derives still validate.
fn dummy_output_fixture() -> SppProofInputs {
    let mut proof_inputs = transfer_fixture();
    let blinding = proof_inputs
        .output_utxos
        .first()
        .expect("padding output slot")
        .blinding;
    if let Some(slot) = proof_inputs.output_utxos.first_mut() {
        *slot = SppProofOutputUtxo {
            blinding,
            owner_address: None,
            owner_tag: Some(DUMMY_OUTPUT_TAG),
            ..Default::default()
        };
    }
    proof_inputs
}

/// A fixed state-inclusion and nullifier-non-inclusion witness. It never
/// reaches a commitment or a nullifier, but its roots and root indices do reach
/// the tree slots folded into the public input hash.
fn spend_proof() -> SpendProof {
    let context = MerkleContext {
        tree_type: 1,
        tree: zolana_interface::pda::tree(TREE_ID),
    };
    SpendProof {
        state: MerkleProof {
            leaf: REAL_INPUT_COMMITMENT,
            merkle_context: context.clone(),
            path: vec![field_bytes(0x53); STATE_TREE_HEIGHT],
            leaf_index: 7,
            root: field_bytes(0x54),
            root_seq: 11,
            root_index: 5,
        },
        nullifier: NonInclusionProof {
            leaf: NULLIFIERS[0],
            merkle_context: context,
            path: vec![field_bytes(0x56); NULLIFIER_TREE_HEIGHT],
            low_element: field_bytes(0x57),
            low_element_index: 3,
            high_element: field_bytes(0x58),
            high_element_index: 4,
            root: field_bytes(0x59),
            root_seq: 13,
            root_index: 9,
        },
    }
}

/// Everything one assembly pass exposes publicly. `assemble` and `into_prover`
/// run the same builder, so both views describe one transaction.
struct Assembled {
    public_input_hash: [u8; 32],
    ix: TransactIxData,
    witness: TransferProofResult,
}

fn assemble_fixture(proof_inputs: &SppProofInputs) -> Assembled {
    let proofs = [spend_proof()];
    let mut dummy = proofs[0].nullifier.clone();
    dummy.leaf = NULLIFIERS[1];
    let sender = keypair(SENDER_SEED);
    let assembled = assemble(proof_inputs.clone(), &proofs, &[dummy.clone()]).expect("assemble");
    let public_input_hash = assembled.public_input_hash;
    let ix = assembled.with_proof(TransactProof::zeroed());
    let mut witness = transfer_prover(proof_inputs.clone(), &proofs, &[dummy])
        .build()
        .expect("witness");
    // What the prover actually receives: assembly leaves the sender's own input
    // without its nullifier secret, and the sender's authority fills it in --
    // rejecting any input whose nullifier that secret does not derive.
    sender
        .complete_inputs(&mut witness.inputs.inputs)
        .expect("complete the witness");

    Assembled {
        public_input_hash,
        ix,
        witness,
    }
}

/// Per-slot `(is_dummy, commitment)` of the witness outputs. `is_dummy` decides
/// which of the two output vectors a slot's hash lands in, so both are read
/// together.
fn witness_output_slots(witness: &TransferProofResult) -> Vec<(BigUint, BigUint)> {
    witness
        .inputs
        .outputs
        .iter()
        .map(|output| (output.is_dummy.clone(), output.hash.clone()))
        .collect()
}

fn expected_output_slots(is_dummy: &[u8], hashes: &[[u8; 32]]) -> Vec<(BigUint, BigUint)> {
    is_dummy
        .iter()
        .zip(hashes.iter())
        .map(|(flag, hash)| (BigUint::from(*flag), be(hash)))
        .collect()
}

// ---------------------------------------------------------------------------
// Fixture identity. If these drift, every hash below drifts with them, so they
// are pinned first to keep a fixture change from reading as an assembly change.
// ---------------------------------------------------------------------------

#[test]
fn fixture_external_data_and_private_tx_blinding_are_pinned() {
    let proof_inputs = transfer_fixture();

    assert_eq!(
        proof_inputs
            .external_data
            .hash()
            .expect("external data hash"),
        EXTERNAL_DATA_HASH
    );
    assert_eq!(
        proof_inputs
            .private_tx_blinding()
            .expect("private tx blinding"),
        PRIVATE_TX_BLINDING
    );
}

// ---------------------------------------------------------------------------
// The two published values.
// ---------------------------------------------------------------------------

#[test]
fn assembled_public_input_hash_is_pinned() {
    let assembled = assemble_fixture(&transfer_fixture());

    assert_eq!(assembled.public_input_hash, PUBLIC_INPUT_HASH);
    // The witness handed to the prover carries the same element.
    assert_eq!(assembled.witness.public_input_hash, PUBLIC_INPUT_HASH);
    assert_eq!(
        assembled.witness.inputs.public_input_hash,
        be(&PUBLIC_INPUT_HASH)
    );
}

#[test]
fn private_tx_hash_published_by_transact_ix_data_is_pinned() {
    let assembled = assemble_fixture(&transfer_fixture());

    assert_eq!(assembled.ix.private_tx_hash, PRIVATE_TX_HASH);
    assert_eq!(assembled.witness.private_tx_hash, PRIVATE_TX_HASH);
    assert_eq!(
        assembled.witness.inputs.private_tx_hash,
        be(&PRIVATE_TX_HASH)
    );
}

// ---------------------------------------------------------------------------
// assemble_inputs.
// ---------------------------------------------------------------------------

#[test]
fn assembled_input_commitments_and_nullifiers_are_pinned() {
    let assembled = assemble_fixture(&transfer_fixture());

    assert_eq!(
        assembled.witness.nullifiers.as_slice(),
        NULLIFIERS.as_slice()
    );

    let published: Vec<[u8; 32]> = assembled
        .ix
        .inputs
        .iter()
        .map(|input| input.nullifier_hash)
        .collect();
    assert_eq!(published.as_slice(), NULLIFIERS.as_slice());

    let tree_indexes: Vec<u8> = assembled
        .ix
        .inputs
        .iter()
        .map(|input| input.tree_index)
        .collect();
    assert_eq!(tree_indexes.as_slice(), INPUT_TREE_INDEXES.as_slice());
    assert_eq!(
        assembled.witness.input_tree_indexes.as_slice(),
        INPUT_TREE_INDEXES.as_slice()
    );

    let commitments: Vec<[u8; 32]> = assembled
        .witness
        .inputs
        .inputs
        .iter()
        .map(|input| input.utxo.hash().expect("witness input commitment"))
        .collect();
    assert_eq!(
        commitments.as_slice(),
        [REAL_INPUT_COMMITMENT, DUMMY_INPUT_COMMITMENT].as_slice()
    );
}

/// The padding slot is the one place the witness and the private-tx hash chain
/// disagree on purpose: the witness carries a real-looking commitment so the
/// slot is indistinguishable, while `input_hashes` contributes zero. Its
/// nullifier is taken over the all-zero nullifier secret `new_dummy` installs.
#[test]
fn dummy_input_slot_contributes_zero_to_the_hash_chain_and_nullifies_under_a_zero_secret() {
    let assembled = assemble_fixture(&transfer_fixture());

    let dummy = assembled
        .witness
        .inputs
        .inputs
        .get(1)
        .expect("padding input slot");

    assert_eq!(dummy.is_dummy, BigUint::from(1u8));
    // Completion leaves it here: a padding slot's secret is genuinely zero and
    // public, so it arrives complete and no authority touches it.
    assert_eq!(dummy.nullifier_secret, Some(BigUint::ZERO));
    assert_eq!(
        dummy.utxo.hash().expect("padding commitment"),
        DUMMY_INPUT_COMMITMENT
    );
    assert_eq!(dummy.nullifier, be(NULLIFIERS.get(1).expect("slot 1")));

    // What the slot puts into `assemble_inputs`' `input_hashes`, which is not
    // the commitment above.
    assert_eq!(INPUT_HASHES.get(1), Some(&[0u8; 32]));
}

// ---------------------------------------------------------------------------
// assemble_outputs: the two vectors, separately.
// ---------------------------------------------------------------------------

/// `output_hashes` always holds a slot's real commitment;
/// `private_tx_output_hashes` holds zero for a slot whose
/// `SppProofOutputUtxo::is_dummy()` is true. Since a transfer's padding output
/// became a real sender-owned output, no slot of a padded transfer is a dummy
/// and the two vectors are equal here -- which is exactly why checking only one
/// of them proves nothing. The dummy case is pinned by
/// `a_dummy_output_slot_zeroes_only_the_private_tx_output_hash`.
#[test]
fn transfer_padding_output_is_not_a_dummy_so_both_output_vectors_carry_its_real_hash() {
    let assembled = assemble_fixture(&transfer_fixture());

    assert_eq!(
        assembled.witness.output_hashes.as_slice(),
        OUTPUT_HASHES.as_slice()
    );
    assert_eq!(
        witness_output_slots(&assembled.witness),
        expected_output_slots(&OUTPUT_IS_DUMMY, &OUTPUT_HASHES)
    );

    // Slot 0 is the padding output. It carries a real commitment in both
    // vectors, and the vectors coincide only because of that.
    assert_eq!(OUTPUT_IS_DUMMY.first(), Some(&0));
    assert_eq!(
        PRIVATE_TX_OUTPUT_HASHES.first(),
        OUTPUT_HASHES.first(),
        "the padding slot is a real sender-owned output"
    );
}

/// The same transaction with slot 0 made ownerless. `output_hashes` still
/// publishes its commitment -- the vector must not leak which slots are
/// padding -- while `private_tx_output_hashes` zeroes it, which moves the
/// private-tx hash and the public input hash.
#[test]
fn a_dummy_output_slot_zeroes_only_the_private_tx_output_hash() {
    let assembled = assemble_fixture(&dummy_output_fixture());

    assert_eq!(
        assembled.witness.output_hashes.as_slice(),
        DUMMY_OUTPUT_OUTPUT_HASHES.as_slice()
    );
    assert_eq!(
        witness_output_slots(&assembled.witness),
        expected_output_slots(&DUMMY_OUTPUT_IS_DUMMY, &DUMMY_OUTPUT_OUTPUT_HASHES)
    );
    assert_eq!(
        DUMMY_OUTPUT_PRIVATE_TX_OUTPUT_HASHES.first(),
        Some(&[0u8; 32])
    );

    assert_eq!(assembled.ix.private_tx_hash, DUMMY_OUTPUT_PRIVATE_TX_HASH);
    assert_eq!(assembled.public_input_hash, DUMMY_OUTPUT_PUBLIC_INPUT_HASH);
    // The published commitments are unchanged from the padded transfer except
    // in slot 0, and the private-tx hash moved: proof the zeroing is real.
    assert_ne!(DUMMY_OUTPUT_PRIVATE_TX_HASH, PRIVATE_TX_HASH);
}

// ---------------------------------------------------------------------------
// The vectors `TransferProofResult` does not expose.
// ---------------------------------------------------------------------------

/// `assemble_inputs`' `input_hashes` and `assemble_outputs`'
/// `private_tx_output_hashes` never leave the assembly, so they are pinned by
/// the value they feed. Every argument here is a literal, so the check is a
/// pin, not a recomputation: if the assembly starts folding different values
/// into `PrivateTxHash`, the pinned `private_tx_hash` stops matching what the
/// assembly emits and the tests above fail; if the literals below are edited
/// without the assembly changing, this test fails instead.
#[test]
fn pinned_input_and_output_vectors_rebuild_the_pinned_private_tx_hash() {
    let rebuilt = PrivateTxHash::new(
        &INPUT_HASHES,
        &PRIVATE_TX_OUTPUT_HASHES,
        &EXTERNAL_DATA_HASH,
        &PRIVATE_TX_BLINDING,
    )
    .hash()
    .expect("private tx hash");
    assert_eq!(rebuilt, PRIVATE_TX_HASH);

    let rebuilt_with_dummy_output = PrivateTxHash::new(
        &INPUT_HASHES,
        &DUMMY_OUTPUT_PRIVATE_TX_OUTPUT_HASHES,
        &EXTERNAL_DATA_HASH,
        &PRIVATE_TX_BLINDING,
    )
    .hash()
    .expect("private tx hash");
    assert_eq!(rebuilt_with_dummy_output, DUMMY_OUTPUT_PRIVATE_TX_HASH);
}

// ---------------------------------------------------------------------------
// Cross-crate agreement.
// ---------------------------------------------------------------------------

/// `SppProofInputs::message_hash()` in zolana-transaction and the digest
/// `RingTransferP256Prover::build` derives from the assembled `private_tx_hash`
/// must stay bit-identical: `validate_authorization` checks a signature against
/// the second and the wallet signs the first.
#[test]
fn message_hash_equals_sha256_of_the_assembled_private_tx_hash() {
    let proof_inputs = transfer_fixture();
    let assembled = assemble_fixture(&proof_inputs);

    assert_eq!(
        proof_inputs.message_hash().expect("message hash"),
        MESSAGE_HASH
    );
    assert_eq!(sha256(&assembled.ix.private_tx_hash), MESSAGE_HASH);

    let dummy_output_inputs = dummy_output_fixture();
    let dummy_output_assembled = assemble_fixture(&dummy_output_inputs);

    assert_eq!(
        dummy_output_inputs.message_hash().expect("message hash"),
        DUMMY_OUTPUT_MESSAGE_HASH
    );
    assert_eq!(
        sha256(&dummy_output_assembled.ix.private_tx_hash),
        DUMMY_OUTPUT_MESSAGE_HASH
    );
}
