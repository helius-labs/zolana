//! Circuit golden-vector KATs for the transact public-input assembly, moved
//! out of the program crate (`transact/verify.rs::circuit_vector_tests`). Pins
//! the program's public-input assembly and field encodings to the committed Go
//! circuit golden vectors (`prover/server/prover-test/spp/testdata/*.json`,
//! consumed Go-side by `protocol/public_inputs_test.go` and
//! `prover/transaction/field_derivation_test.go`) without invoking Go. The
//! vectors are regenerated Go-side; a change there must re-pin here in the
//! same commit.
//!
//! The vectors' `external_data_hash` entry is NOT consumed: it pins the Go
//! prover-test's own preimage helper (with `sender_view_tag`), whose Rust
//! counterpart is the interface's `ExternalDataPreimage` with its own parity
//! vector and injectivity tests.

use std::{fs, path::Path};

use serde_json::Value;
use shielded_pool_program::testing::{
    amount_field, solana_owner_identity, TransactProof, TransactProofInputs,
};
use zolana_hasher::{
    hash_chain::{create_hash_chain_from_slice, create_right_hash_chain_from_slice},
    primitives::hash_bytes,
};
use zolana_interface::{
    instruction::instruction_data::transact::{
        CircuitId, InputUtxo, OwnerTag, TransactIxData, TransactIxDataRef, TransactOutput,
        TransactProof as ProofData,
    },
    merge_utils::owner_proof_input_hash_compressed,
    tree_slot::{tree_id_field, tree_slots_hash_chain, TreeSlot},
    INPUT_TREES, N_PUBLIC_SLOTS, SOL_ASSET_FIELD,
};

fn vector(name: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../prover/server/prover-test/spp/testdata")
        .join(name);
    let bytes = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    serde_json::from_str(&bytes).expect("parse golden vector json")
}

/// Decode a `0x…` field-element string into right-aligned 32 bytes.
fn fe(value: &Value) -> [u8; 32] {
    let text = value.as_str().expect("field element is a string");
    let digits = text
        .strip_prefix("0x")
        .expect("field element has 0x prefix");
    let padded = format!("{digits:0>64}");
    let mut out = [0u8; 32];
    for (slot, chunk) in out.iter_mut().zip(padded.as_bytes().chunks(2)) {
        let text = core::str::from_utf8(chunk).expect("hex chunk");
        *slot = u8::from_str_radix(text, 16).expect("hex byte");
    }
    out
}

fn fe_at(vector: &Value, key: &str) -> [u8; 32] {
    fe(vector
        .get(key)
        .unwrap_or_else(|| panic!("vector key {key}")))
}

fn fe_list(vector: &Value, key: &str) -> Vec<[u8; 32]> {
    vector
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("vector list {key}"))
        .iter()
        .map(fe)
        .collect()
}

/// Decode a `0x…` byte string of exactly `N` bytes (no field padding).
fn bytes<const N: usize>(value: &Value) -> [u8; N] {
    let text = value.as_str().expect("byte string");
    let digits = text.strip_prefix("0x").expect("byte string has 0x prefix");
    assert_eq!(digits.len(), N * 2, "byte string is {N} bytes");
    let mut out = [0u8; N];
    for (slot, chunk) in out.iter_mut().zip(digits.as_bytes().chunks(2)) {
        let text = core::str::from_utf8(chunk).expect("hex chunk");
        *slot = u8::from_str_radix(text, 16).expect("hex byte");
    }
    out
}

/// The vector's fixed-width `tree_slots` array: `INPUT_TREES` entries of
/// `{id, utxo_root, nullifier_root}`, unused slots all zero at the end.
fn tree_slots(vector: &Value) -> [TreeSlot; INPUT_TREES] {
    let entries = vector
        .get("tree_slots")
        .and_then(Value::as_array)
        .expect("vector tree_slots");
    assert_eq!(entries.len(), INPUT_TREES, "vector publishes every slot");
    core::array::from_fn(|index| {
        let entry = entries.get(index).expect("tree slot");
        TreeSlot {
            id: fe_at(entry, "id"),
            utxo_root: fe_at(entry, "utxo_root"),
            nullifier_root: fe_at(entry, "nullifier_root"),
        }
    })
}

/// Test-local clone of the Go `protocol.PublicInputHash` ordering
/// (public_inputs.go), built from the program's own primitives.
/// `public_slot_amounts` are the already-encoded field elements and
/// `signer_pk_hashes` is the payer-first run already zero-padded to the
/// variant's width (a one-element run right-folds to itself).
struct GoAssembly<'a> {
    nullifiers: &'a [[u8; 32]],
    output_hashes: &'a [[u8; 32]],
    /// Every slot, populated first and all-zero at the end; they enter the
    /// preimage as one right-folded element.
    tree_slots: &'a [TreeSlot; INPUT_TREES],
    /// `tree_id_field` of the tree every output is appended to.
    output_tree_id: [u8; 32],
    private_tx_hash: [u8; 32],
    external_data_hash: [u8; 32],
    public_slot_assets: &'a [[u8; 32]],
    public_slot_amounts: &'a [[u8; 32]],
    ring_program_id: [u8; 32],
    signer_pk_hashes: &'a [[u8; 32]],
    allow_dummy_inputs: [u8; 32],
    output_owner_pk_hashes: Option<&'a [[u8; 32]]>,
}

impl GoAssembly<'_> {
    fn hash(&self) -> [u8; 32] {
        let mut fields = vec![
            create_hash_chain_from_slice(self.nullifiers).expect("nullifier chain"),
            create_hash_chain_from_slice(self.output_hashes).expect("output chain"),
            tree_slots_hash_chain(self.tree_slots).expect("tree slot chain"),
            self.output_tree_id,
            self.private_tx_hash,
            self.external_data_hash,
        ];
        for (asset, amount) in self
            .public_slot_assets
            .iter()
            .zip(self.public_slot_amounts.iter())
        {
            fields.push(*asset);
            fields.push(*amount);
        }
        fields.extend_from_slice(&[
            self.ring_program_id,
            create_right_hash_chain_from_slice(self.signer_pk_hashes).expect("signer chain"),
            self.allow_dummy_inputs,
        ]);
        if let Some(output_owner_pk_hashes) = self.output_owner_pk_hashes {
            fields.push(
                create_hash_chain_from_slice(output_owner_pk_hashes).expect("output owner chain"),
            );
        }
        create_hash_chain_from_slice(&fields).expect("public input hash chain")
    }
}

/// The committed known-answer vector reproduces through the Go assembly
/// ordering built from the program's own hash primitives (the Go test pins
/// the confidential rail: `Confidential: true`, `RingAuthority: false`).
#[test]
pub fn public_input_hash_vector_pins_the_confidential_rail_assembly() {
    let vector = vector("public_input_hash_vector.json");
    let nullifiers = fe_list(&vector, "nullifiers");
    let output_hashes = fe_list(&vector, "output_utxo_hashes");
    let slots = tree_slots(&vector);
    let public_slot_assets = fe_list(&vector, "public_assets");
    let public_slot_amounts = fe_list(&vector, "public_amounts");
    let signer_pk_hashes = fe_list(&vector, "signer_pk_hashes");
    let output_owner_pk_hashes = fe_list(&vector, "output_owner_pk_hashes");
    let assembled = GoAssembly {
        nullifiers: &nullifiers,
        output_hashes: &output_hashes,
        tree_slots: &slots,
        output_tree_id: fe_at(&vector, "output_tree_id"),
        private_tx_hash: fe_at(&vector, "private_tx_hash"),
        external_data_hash: fe_at(&vector, "external_data_hash"),
        public_slot_assets: &public_slot_assets,
        public_slot_amounts: &public_slot_amounts,
        ring_program_id: fe_at(&vector, "ring_program_id"),
        signer_pk_hashes: &signer_pk_hashes,
        allow_dummy_inputs: fe_at(&vector, "allow_dummy_inputs"),
        output_owner_pk_hashes: Some(&output_owner_pk_hashes),
    }
    .hash();
    assert_eq!(assembled, fe_at(&vector, "public_input_hash"));
}

fn small_fe(tag: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    if let Some(last) = out.last_mut() {
        *last = tag;
    }
    out
}

fn ix_data(circuit: CircuitId) -> TransactIxData {
    TransactIxData {
        expiry_unix_ts: 7,
        private_tx_hash: small_fe(0x51),
        circuit,
        tx_viewing_pk: [4u8; 33],
        salt: [6u8; 16],
        proof: ProofData::zeroed(),
        inputs: (1..=2)
            .map(|tag| InputUtxo {
                nullifier_hash: small_fe(tag),
                nullifier_tree_root_index: 0,
                utxo_tree_root_index: 0,
            })
            .collect(),
        interface_transfers: vec![],
        data_hash: None,
        ring_data_hash: None,
        outputs: (11..=13)
            .map(|tag| TransactOutput {
                utxo_hash: small_fe(tag),
                owner_tag: OwnerTag::Inline(small_fe(tag)),
                data: None,
            })
            .collect(),
        messages: vec![],
    }
}

fn derived_inputs(unique_signers: u8) -> TransactProofInputs {
    let mut derived =
        TransactProofInputs::new(CircuitId::ConfidentialEddsa(2, 3, N_PUBLIC_SLOTS as u8));
    derived.external_data_hash = small_fe(0x62);
    derived.ring_program_id = small_fe(0x64);
    derived.allow_dummy_inputs = small_fe(1);
    derived.public_slot_amounts = [801, -901, 0];
    derived.unique_owner_signer_count = unique_signers;
    // SPP proves against exactly one input tree, so only slot 0 is populated.
    derived.tree_slot = TreeSlot::new(0x0d, small_fe(0x20), small_fe(0x30));
    derived.output_tree_id = tree_id_field(0x0e);
    for (index, signer) in derived.signer_pk_hashes.iter_mut().enumerate() {
        *signer = small_fe(0x40 + index as u8);
    }
    for (index, owner) in derived.output_owner_pk_hashes.iter_mut().enumerate() {
        *owner = small_fe(0x70 + index as u8);
    }
    for (index, asset) in derived.public_slot_assets.iter_mut().enumerate() {
        *asset = small_fe(0x80 + index as u8);
    }
    derived
}

/// The real `public_input_hash` agrees with the vector-pinned Go ordering for
/// every circuit selector, with the public transfer slots interleaved as
/// `(asset, amount)`, the payer-first signer run right-folded at the variant's
/// width (input-signing rails: `n_in + 1`; the authority rail: a bare payer
/// element), and the output-owner-chain appendix selected by the variant.
#[test]
fn program_assembly_matches_the_go_ordering_on_every_variant() {
    for (circuit, signer_width, unique_signers, binds_output_owners) in [
        (CircuitId::ConfidentialEddsa(2, 3, 3), 3usize, 2u8, true),
        (CircuitId::RingEddsa(2, 3, 3), 3, 2, true),
        (CircuitId::RingAuthority(2, 3, 3), 1, 1, false),
    ] {
        let owned = ix_data(circuit);
        let bytes = owned.serialize().expect("serialize transact ix");
        let ix = TransactIxDataRef::from_bytes(&bytes).expect("parse transact ix");
        let derived = derived_inputs(unique_signers);
        let proof = TransactProof::new(&ix, &derived);

        let nullifiers: Vec<[u8; 32]> = owned
            .inputs
            .iter()
            .map(|input| input.nullifier_hash)
            .collect();
        let output_hashes: Vec<[u8; 32]> = owned
            .outputs
            .iter()
            .map(|output| output.utxo_hash)
            .collect();
        let slot_amount_fields: Vec<[u8; 32]> = derived
            .public_slot_amounts
            .iter()
            .map(|amount| amount_field(*amount).expect("slot amount field"))
            .collect();
        // The program right-folds the unique signer prefix with zero padding
        // out to the variant width; mirror that padded run here.
        let mut signer_run: Vec<[u8; 32]> = derived
            .signer_pk_hashes
            .get(..usize::from(unique_signers))
            .expect("unique signers")
            .to_vec();
        signer_run.resize(signer_width, [0u8; 32]);
        let mut slots = [TreeSlot::ZERO; INPUT_TREES];
        if let Some(slot_0) = slots.first_mut() {
            *slot_0 = derived.tree_slot;
        }
        let clone = GoAssembly {
            nullifiers: &nullifiers,
            output_hashes: &output_hashes,
            tree_slots: &slots,
            output_tree_id: derived.output_tree_id,
            private_tx_hash: owned.private_tx_hash,
            external_data_hash: derived.external_data_hash,
            public_slot_assets: derived
                .public_slot_assets
                .get(..N_PUBLIC_SLOTS)
                .expect("slot assets"),
            public_slot_amounts: &slot_amount_fields,
            ring_program_id: derived.ring_program_id,
            signer_pk_hashes: &signer_run,
            allow_dummy_inputs: derived.allow_dummy_inputs,
            output_owner_pk_hashes: binds_output_owners.then_some(
                derived
                    .output_owner_pk_hashes
                    .get(..3)
                    .expect("output owners"),
            ),
        };
        assert_eq!(
            proof.public_input_hash().expect("assembly"),
            clone.hash(),
            "{circuit:?}"
        );
    }
}

/// The field-derivation vector pins `solana_pk_hash`, the signed public
/// movement encoding (`amount_field` over the aggregated `i128` net), and
/// the interface-transfer → public-slot aggregation (deposits positive,
/// withdrawals negative, first-seen asset order, zero-net groups dropped).
#[test]
fn field_derivation_vector_pins_the_shared_encodings() {
    let vector = vector("field_derivation_vector.json");

    let solana = vector.get("solana_pk_hash").expect("solana_pk_hash entry");
    assert_eq!(
        solana_owner_identity(&fe_at(solana, "pubkey")).expect("solana owner identity"),
        fe_at(solana, "hash")
    );

    // The P256 owner identity is tagged and taken over the x-coordinate only,
    // so the vector's SEC1-compressed key and its odd-parity twin agree.
    let p256 = vector
        .get("p256_owner_pk_hash")
        .expect("p256_owner_pk_hash entry");
    let compressed: [u8; 33] = bytes(p256.get("compressed_pubkey").expect("compressed_pubkey"));
    assert_eq!(
        owner_proof_input_hash_compressed(&compressed).expect("p256 owner identity"),
        fe_at(p256, "hash")
    );

    for entry in vector
        .get("negative_u64")
        .and_then(Value::as_array)
        .expect("negative_u64 entries")
    {
        let amount = entry.get("amount").and_then(Value::as_u64).expect("amount");
        assert_eq!(
            amount_field(-i128::from(amount)).expect("negative amount field"),
            fe(entry.get("field").expect("field")),
            "negative amount {amount}"
        );
    }

    for entry in vector
        .get("public_slots")
        .and_then(Value::as_array)
        .expect("public_slots entries")
    {
        let name = entry.get("name").and_then(Value::as_str).expect("name");
        let mut slot_assets = [[0u8; 32]; N_PUBLIC_SLOTS];
        let mut slot_amounts = [0i128; N_PUBLIC_SLOTS];
        let mut used_slots = 0usize;
        for transfer in entry
            .get("interface_transfers")
            .and_then(Value::as_array)
            .expect("interface transfers")
        {
            let is_spl = transfer
                .get("is_spl")
                .and_then(Value::as_bool)
                .expect("is_spl");
            let is_deposit = transfer
                .get("is_deposit")
                .and_then(Value::as_bool)
                .expect("is_deposit");
            let amount = transfer
                .get("amount")
                .and_then(Value::as_u64)
                .expect("amount");
            let signed = if is_deposit {
                i128::from(amount)
            } else {
                -i128::from(amount)
            };
            let asset = if is_spl {
                hash_bytes(&fe(transfer.get("asset").expect("asset"))).expect("spl asset field")
            } else {
                SOL_ASSET_FIELD
            };
            match slot_assets[..used_slots]
                .iter()
                .position(|slot_asset| *slot_asset == asset)
            {
                Some(i) => slot_amounts[i] += signed,
                None => {
                    *slot_assets
                        .get_mut(used_slots)
                        .expect("vector declares more distinct assets than N_PUBLIC_SLOTS") = asset;
                    *slot_amounts
                        .get_mut(used_slots)
                        .expect("vector declares more distinct assets than N_PUBLIC_SLOTS") =
                        signed;
                    used_slots += 1;
                }
            }
        }
        // The Go derivation drops zero-net groups and compacts the slots.
        let mut compacted = [0i128; N_PUBLIC_SLOTS];
        let mut slot = 0usize;
        for amount in slot_amounts.into_iter().take(used_slots) {
            if amount != 0 {
                *compacted
                    .get_mut(slot)
                    .expect("vector yields more non-zero net slots than N_PUBLIC_SLOTS") = amount;
                slot += 1;
            }
        }
        let expected: Vec<[u8; 32]> = entry
            .get("slot_amounts")
            .and_then(Value::as_array)
            .expect("slot amounts")
            .iter()
            .map(fe)
            .collect();
        for (index, want) in expected.iter().enumerate() {
            let got = compacted
                .get(index)
                .copied()
                .expect("vector slot_amounts longer than the compacted slots");
            assert_eq!(
                amount_field(got).expect("slot amount field"),
                *want,
                "{name} slot {index}"
            );
        }
    }
}
