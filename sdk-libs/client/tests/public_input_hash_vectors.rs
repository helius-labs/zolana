//! Known-answer vectors for the transfer and merge public input hashes, the
//! values the TS SDK pins against `test-vectors/public_input_hash.json`.
//!
//! Transfers go through [`PublicInputs::hash`], the function the provers use.
//! Merge has no standalone hash function, so its vector rebuilds the element
//! list `MergeProver::build` hashes from the same interface helpers. Wide and
//! compact shapes are the point: the nullifier, output and owner chains fold to
//! the right, and only a chain longer than one Poseidon group tells a right
//! fold from a left one.

use serde::{Deserialize, Serialize};
use zolana_client::{PublicInputs, PublicTransfers};
use zolana_hasher::hash_chain::create_hash_chain_4_from_slice;
use zolana_hasher::zero_suffix_hash_chain::create_padded_right_hash_chain_4;
use zolana_interface::{
    instruction::instruction_data::{MergeMaskNonces, MERGE_MASK_SEED_LEN},
    tree_slot::{tree_id_field, tree_slots_hash_chain, TreeSlot},
    INPUT_TREES, N_PUBLIC_SLOTS,
};

const PUBLIC_INPUT_HASH_VECTORS_JSON: &str =
    include_str!("../../../test-vectors/public_input_hash.json");

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct PublicInputHashVectors {
    description: String,
    transfers: Vec<TransferVector>,
    merges: Vec<MergeVector>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct TreeSlotVector {
    id: u16,
    utxo_root: String,
    nullifier_root: String,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct TransferVector {
    name: String,
    nullifiers: Vec<String>,
    output_hashes: Vec<String>,
    output_tree_id: u16,
    private_tx_hash: String,
    external_data_hash: String,
    public_assets: Vec<String>,
    public_amounts: Vec<String>,
    ring_program_id: String,
    input_flags: String,
    signer_pk_hashes: Vec<String>,
    output_owner_pk_hashes: Option<Vec<String>>,
    cached_inputs: Vec<String>,
    tree_slots: Vec<TreeSlotVector>,
    public_input_hash: String,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct MergeVector {
    name: String,
    nullifiers: Vec<String>,
    output_hash: String,
    output_tree_id: u16,
    private_tx_hash: String,
    external_data_hash: String,
    masked_amount: String,
    masked_mint: Vec<String>,
    mask_seed: String,
    amount_mask_nonce: String,
    mint_mask_nonce: String,
    owner_pk_hash: String,
    nullifier_pk: String,
    tree_slots: Vec<TreeSlotVector>,
    public_input_hash: String,
}

fn field(value: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    if let Some((_, tail)) = out.split_last_chunk_mut::<4>() {
        *tail = value.to_be_bytes();
    }
    out
}

fn fields(values: &[u32]) -> Vec<[u8; 32]> {
    values.iter().copied().map(field).collect()
}

/// `sent` followed by zeros up to `width`: a compact padded slot vector.
fn padded(sent: &[u32], width: usize) -> Vec<[u8; 32]> {
    let mut values = fields(sent);
    values.resize(width, [0u8; 32]);
    values
}

fn hex(value: &[u8; 32]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hexes(values: &[[u8; 32]]) -> Vec<String> {
    values.iter().map(hex).collect()
}

fn array<const N: usize>(values: &[u32]) -> [[u8; 32]; N] {
    fields(values).try_into().unwrap()
}

/// The populated slot's `(tree id, utxo root, nullifier root)`; the remaining
/// slots are unused, the layout a single-tree spend publishes.
const INPUT_TREE: (u16, u32, u32) = (1, 71, 72);

fn tree_slot_layout() -> [(u16, [u8; 32], [u8; 32]); INPUT_TREES] {
    let (id, utxo_root, nullifier_root) = INPUT_TREE;
    core::array::from_fn(|index| {
        if index == 0 {
            (id, field(utxo_root), field(nullifier_root))
        } else {
            (0, [0u8; 32], [0u8; 32])
        }
    })
}

fn tree_slots() -> [TreeSlot; INPUT_TREES] {
    tree_slot_layout()
        .map(|(id, utxo_root, nullifier_root)| TreeSlot::new(id, utxo_root, nullifier_root))
}

fn tree_slot_vectors() -> Vec<TreeSlotVector> {
    tree_slot_layout()
        .iter()
        .map(|(id, utxo_root, nullifier_root)| TreeSlotVector {
            id: *id,
            utxo_root: hex(utxo_root),
            nullifier_root: hex(nullifier_root),
        })
        .collect()
}

struct TransferCase<'a> {
    name: &'a str,
    nullifiers: Vec<[u8; 32]>,
    output_hashes: Vec<[u8; 32]>,
    output_owner_pk_hashes: Option<Vec<[u8; 32]>>,
    signer_pk_hashes: Vec<[u8; 32]>,
}

impl TransferCase<'_> {
    fn vector(self) -> TransferVector {
        let output_tree_id = 1u16;
        let private_tx = field(61);
        let external_data_hash = field(62);
        let public_transfers = PublicTransfers {
            assets: array::<N_PUBLIC_SLOTS>(&[51, 53, 55]),
            amounts: array::<N_PUBLIC_SLOTS>(&[52, 54, 56]),
        };
        let ring_program_id = field(63);
        let input_flags = field(1);
        let cached_inputs = [field(64), field(65)];
        let slots = tree_slots();
        let public_input_hash = PublicInputs {
            nullifiers: &self.nullifiers,
            output_hashes: &self.output_hashes,
            tree_slots: &slots,
            output_tree_id,
            private_tx: &private_tx,
            external_data_hash: &external_data_hash,
            public_transfers: &public_transfers,
            ring_program_id: &ring_program_id,
            input_flags: &input_flags,
            signer_pk_hashes: &self.signer_pk_hashes,
            output_owner_pk_hashes: self.output_owner_pk_hashes.as_deref(),
            cached_inputs,
        }
        .hash()
        .unwrap();
        TransferVector {
            name: self.name.to_string(),
            nullifiers: hexes(&self.nullifiers),
            output_hashes: hexes(&self.output_hashes),
            output_tree_id,
            private_tx_hash: hex(&private_tx),
            external_data_hash: hex(&external_data_hash),
            public_assets: hexes(&public_transfers.assets),
            public_amounts: hexes(&public_transfers.amounts),
            ring_program_id: hex(&ring_program_id),
            input_flags: hex(&input_flags),
            signer_pk_hashes: hexes(&self.signer_pk_hashes),
            output_owner_pk_hashes: self.output_owner_pk_hashes.as_deref().map(hexes),
            cached_inputs: hexes(&cached_inputs),
            tree_slots: tree_slot_vectors(),
            public_input_hash: hex(&public_input_hash),
        }
    }
}

fn merge_vector(name: &str, nullifiers: Vec<[u8; 32]>) -> MergeVector {
    let output_hash = field(81);
    let output_tree_id = 1u16;
    let private_tx = field(82);
    let external_data_hash = field(83);
    let owner_pk_hash = field(84);
    let nullifier_pk = field(85);
    let masked_amount = field(86);
    let masked_mint = [field(87), field(88)];
    let mask_seed = [0x59u8; MERGE_MASK_SEED_LEN];
    let nonces = MergeMaskNonces::derive(&mask_seed).unwrap();
    let [masked_mint_prefix, masked_mint_last] = masked_mint;
    // The element order `MergeProver::build` hashes; the 1 is the dummy-input
    // policy merge always publishes, and the two nonces are the ones SPP
    // derives from the mask seed.
    let public_input_hash = create_hash_chain_4_from_slice(&[
        create_padded_right_hash_chain_4(&nullifiers, nullifiers.len()).unwrap(),
        output_hash,
        tree_slots_hash_chain(&tree_slots()).unwrap(),
        tree_id_field(output_tree_id),
        private_tx,
        external_data_hash,
        field(1),
        masked_amount,
        masked_mint_prefix,
        masked_mint_last,
        nonces.amount,
        nonces.mint,
        owner_pk_hash,
        nullifier_pk,
    ])
    .unwrap();
    MergeVector {
        name: name.to_string(),
        nullifiers: hexes(&nullifiers),
        output_hash: hex(&output_hash),
        output_tree_id,
        private_tx_hash: hex(&private_tx),
        external_data_hash: hex(&external_data_hash),
        masked_amount: hex(&masked_amount),
        masked_mint: hexes(&masked_mint),
        mask_seed: mask_seed.iter().map(|byte| format!("{byte:02x}")).collect(),
        amount_mask_nonce: hex(&nonces.amount),
        mint_mask_nonce: hex(&nonces.mint),
        owner_pk_hash: hex(&owner_pk_hash),
        nullifier_pk: hex(&nullifier_pk),
        tree_slots: tree_slot_vectors(),
        public_input_hash: hex(&public_input_hash),
    }
}

fn compute_vectors() -> PublicInputHashVectors {
    let wide_nullifiers: Vec<u32> = (101..=136).collect();
    let wide_merge: Vec<u32> = (301..=336).collect();
    let transfers = vec![
        TransferCase {
            name: "full_2x3",
            nullifiers: fields(&[11, 12]),
            output_hashes: fields(&[21, 22, 23]),
            output_owner_pk_hashes: Some(fields(&[31, 32, 33])),
            signer_pk_hashes: fields(&[41, 0, 0]),
        },
        TransferCase {
            name: "compact_2x3",
            nullifiers: padded(&[11], 2),
            output_hashes: padded(&[21], 3),
            output_owner_pk_hashes: Some(fields(&[31])),
            signer_pk_hashes: fields(&[41, 0, 0]),
        },
        TransferCase {
            name: "full_36x2",
            nullifiers: fields(&wide_nullifiers),
            output_hashes: fields(&[21, 22]),
            output_owner_pk_hashes: Some(fields(&[31, 32])),
            signer_pk_hashes: fields(&[41, 42, 0, 0]),
        },
        TransferCase {
            name: "compact_36x2",
            nullifiers: padded(&[101], 36),
            output_hashes: padded(&[21], 2),
            output_owner_pk_hashes: Some(fields(&[31])),
            signer_pk_hashes: fields(&[41, 42, 0, 0]),
        },
        TransferCase {
            name: "compact_5x4_without_owner_chain",
            nullifiers: padded(&[11, 12], 5),
            output_hashes: padded(&[21, 22], 4),
            output_owner_pk_hashes: None,
            signer_pk_hashes: fields(&[41, 0, 0, 0, 0, 0]),
        },
    ]
    .into_iter()
    .map(TransferCase::vector)
    .collect();
    let merges = vec![
        merge_vector("full_8", fields(&[201, 202, 203, 204, 205, 206, 207, 208])),
        merge_vector("compact_8", padded(&[201, 202, 203], 8)),
        merge_vector("full_36", fields(&wide_merge)),
        merge_vector(
            "compact_36",
            padded(&[301, 302, 303, 304, 305, 306, 307, 308, 309], 36),
        ),
    ];
    PublicInputHashVectors {
        description: "Known-answer vectors for the transfer and merge public input hashes. \
                      Every value is a 32-byte big-endian hex string except a merge's 31-byte mask_seed, \
                      from which SPP derives amount_mask_nonce and mint_mask_nonce; nullifier, output hash and \
                      owner lists span the circuit width, with 0 for compact padding, and a \
                      published owner list shorter than the outputs is padded with 0. Transfers \
                      are zolana_client::PublicInputs::hash; merges hash the MergeProver::build \
                      element order. Produced by sdk-libs/client/tests/public_input_hash_vectors.rs \
                      print_public_input_hash_vectors: cargo test -p zolana-client --test \
                      public_input_hash_vectors print_public_input_hash_vectors -- --ignored \
                      --nocapture"
            .to_string(),
        transfers,
        merges,
    }
}

fn committed() -> PublicInputHashVectors {
    serde_json::from_str(PUBLIC_INPUT_HASH_VECTORS_JSON).unwrap()
}

#[test]
fn committed_public_input_hash_vectors_match() {
    assert_eq!(committed(), compute_vectors());
}

#[test]
#[ignore = "regenerates test-vectors/public_input_hash.json; run with --nocapture and commit the output"]
fn print_public_input_hash_vectors() {
    println!(
        "{}",
        serde_json::to_string_pretty(&compute_vectors()).unwrap()
    );
}
