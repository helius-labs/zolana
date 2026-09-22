//! A spend whose inputs come from two pool trees, assembled end to end.
//!
//! Hermetic, like `assembly_vectors`: assembly is pure computation over the
//! values it is handed, so nothing here needs a prover server or an indexer.
//!
//! The circuit, `SppProofInputs` and `TreeSlot[INPUT_TREES]` have always
//! supported several input trees, but the client could not reach the path: the
//! witness fetch took one tree account and assembly keyed its slots by that
//! account. With the raw tree id as the only tree an input names, a two-tree
//! spend is reachable through the ordinary client types, and this pins what it
//! produces:
//!
//! - one tree slot per tree, in the order the inputs declare them;
//! - each input's `tree_index` selecting its own tree's slot;
//! - `tree_ids` and `input_tree_ids` parallel to `tree_contexts`, which is what
//!   the `Transact` builder derives its ordered `input_trees` accounts from.
//!
//! The ids run 5 then 3, descending on purpose: a declaration order that
//! happens to be sorted would hide any accidental reordering.

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
use solana_address::Address;
use zolana_client::{
    assemble, prover::field::be, MerkleContext, MerkleProof, NonInclusionProof, SpendProof,
    TransferProofResult, NULLIFIER_TREE_HEIGHT, STATE_TREE_HEIGHT,
};
use zolana_interface::{
    instruction::instruction_data::transact::{TransactIxData, TransactProof, TreeContext},
    pda,
};
use zolana_keypair::{ShieldedKeypair, SigningKey};
use zolana_transaction::instructions::transact::SppProofInputs;
use zolana_transaction::{Data, Mint, SppProofOutputUtxo, Utxo};

const SENDER_SEED: u8 = 0x11;
const RECIPIENT_SEED: u8 = 0x22;
const SALT: [u8; 16] = [0x5a; 16];
const INPUT_AMOUNT: u64 = 10;
const SEND_AMOUNT: u64 = 4;

/// The two input trees, in declaration order.
const FIRST_TREE_ID: u16 = 5;
const SECOND_TREE_ID: u16 = 3;
/// Outputs go to a third tree, so nothing can pass by reusing an input's id.
const OUTPUT_TREE_ID: u16 = 7;

/// A 32-byte value that is always a valid BN254 field element.
fn field_bytes(byte: u8) -> [u8; 32] {
    core::array::from_fn(|index| if index == 0 { 0 } else { byte })
}

fn keypair(seed: u8) -> ShieldedKeypair {
    ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[seed; 32]))
        .expect("fixed-seed Ed25519 keypair")
}

/// Two real inputs owned by one sender, the first published in
/// [`FIRST_TREE_ID`] and the second in [`SECOND_TREE_ID`]. Both slots are real,
/// so no padding is appended and the tree runs stay unbroken.
fn two_tree_fixture() -> SppProofInputs {
    let sender = keypair(SENDER_SEED);
    let recipient = keypair(RECIPIENT_SEED);
    let payer = Address::new_from_array(
        sender
            .signing_pubkey()
            .as_ed25519()
            .expect("sender Ed25519 pubkey"),
    );

    let input_in = |tree_id: u16, blinding: u8| {
        wallet_utxo(
            Utxo {
                owner: sender.signing_pubkey(),
                asset: Mint::SOL,
                amount: INPUT_AMOUNT,
                blinding: field_bytes(blinding),
                ring_program_id: None,
                data: Data::default(),
            },
            &sender.nullifier_key,
            tree_id,
            7,
            None,
            None,
        )
        .into()
    };
    let output = |owner: &ShieldedKeypair, amount| {
        SppProofOutputUtxo::new(Mint::SOL, amount, owner.shielded_address().unwrap()).unwrap()
    };
    finalized_transaction(
        vec![
            input_in(FIRST_TREE_ID, 0x31),
            input_in(SECOND_TREE_ID, 0x32),
        ],
        vec![
            output(&recipient, SEND_AMOUNT),
            output(&sender, 2 * INPUT_AMOUNT - SEND_AMOUNT),
            output(&sender, 0),
        ],
        &sender,
        payer,
        OUTPUT_TREE_ID,
        field_bytes(0x41),
        SALT,
    )
}

/// The witness one tree's inputs are proven against: distinct roots and root
/// indexes per tree, so a slot that took the wrong tree's roots is visible.
fn spend_proof(tree_id: u16, root: u8, root_index: u16, nullifier_root: u8) -> SpendProof {
    let context = MerkleContext {
        tree_type: 1,
        tree: pda::tree(tree_id),
    };
    SpendProof {
        state: MerkleProof {
            leaf: field_bytes(0x52),
            merkle_context: context.clone(),
            path: vec![field_bytes(0x53); STATE_TREE_HEIGHT],
            leaf_index: 7,
            root: field_bytes(root),
            root_seq: 11,
            root_index,
        },
        nullifier: NonInclusionProof {
            leaf: field_bytes(0x55),
            merkle_context: context,
            path: vec![field_bytes(0x56); NULLIFIER_TREE_HEIGHT],
            low_element: field_bytes(0x57),
            low_element_index: 3,
            high_element: field_bytes(0x58),
            high_element_index: 4,
            root: field_bytes(nullifier_root),
            root_seq: 13,
            root_index: root_index.saturating_add(20),
        },
    }
}

fn spend_proofs() -> [SpendProof; 2] {
    let tx = two_tree_fixture();
    let mut proofs = [
        spend_proof(FIRST_TREE_ID, 0x61, 5, 0x71),
        spend_proof(SECOND_TREE_ID, 0x62, 6, 0x72),
    ];
    for (proof, input) in proofs.iter_mut().zip(&tx.input_utxos) {
        proof.state.leaf = input.utxo_hash;
        proof.nullifier.leaf = input.nullifier;
    }
    proofs
}

fn witness() -> TransferProofResult {
    transfer_prover(two_tree_fixture(), &spend_proofs(), &[])
        .build()
        .expect("witness")
}

fn instruction_data() -> (Vec<u16>, TransactIxData) {
    let assembled = assemble(two_tree_fixture(), &spend_proofs(), &[]).expect("assemble");
    let tree_ids = assembled.input_tree_ids.clone();
    (tree_ids, assembled.with_proof(TransactProof::zeroed()))
}

#[test]
fn two_input_trees_fill_two_slots_in_declaration_order() {
    let witness = witness();

    assert_eq!(witness.tree_ids, vec![FIRST_TREE_ID, SECOND_TREE_ID]);

    let slots = &witness.inputs.tree_slots;
    let populated: Vec<(u16, [u8; 32], [u8; 32])> =
        vec![(FIRST_TREE_ID, 0x61, 0x71), (SECOND_TREE_ID, 0x62, 0x72)]
            .into_iter()
            .map(|(id, utxo_root, nullifier_root)| {
                (id, field_bytes(utxo_root), field_bytes(nullifier_root))
            })
            .collect();

    for (slot, (id, utxo_root, nullifier_root)) in slots.iter().zip(&populated) {
        assert_eq!(
            slot.id,
            be(&zolana_interface::tree_slot::tree_id_field(*id))
        );
        assert_eq!(slot.utxo_root, be(utxo_root));
        assert_eq!(slot.nullifier_root, be(nullifier_root));
    }
    // Every slot the two trees do not occupy stays zero.
    for slot in slots.iter().skip(populated.len()) {
        assert_eq!(slot.id, be(&[0u8; 32]));
        assert_eq!(slot.utxo_root, be(&[0u8; 32]));
        assert_eq!(slot.nullifier_root, be(&[0u8; 32]));
    }
}

#[test]
fn each_input_selects_its_own_trees_slot() {
    let witness = witness();

    assert_eq!(witness.input_tree_indexes, vec![0, 1]);

    let selected: Vec<u32> = witness
        .inputs
        .inputs
        .iter()
        .map(|input| {
            u32::try_from(&input.tree_slot).expect("a tree slot index fits the slot count")
        })
        .collect();
    assert_eq!(selected, vec![0, 1]);
}

#[test]
fn tree_contexts_carry_each_trees_own_root_indexes() {
    let witness = witness();

    assert_eq!(
        witness.tree_contexts,
        vec![
            TreeContext {
                utxo_tree_root_index: 5,
                nullifier_tree_root_index: 25,
            },
            TreeContext {
                utxo_tree_root_index: 6,
                nullifier_tree_root_index: 26,
            },
        ]
    );
}

/// The `Transact` builder takes one tree account per `tree_contexts` entry, in
/// the same order, and the assembled ids are the only thing that list can be
/// derived from.
#[test]
fn the_assembled_ids_are_parallel_to_the_published_tree_contexts() {
    let (tree_ids, ix) = instruction_data();

    assert_eq!(tree_ids, vec![FIRST_TREE_ID, SECOND_TREE_ID]);
    assert_eq!(ix.tree_contexts.len(), tree_ids.len());
    // The accounts the builder is handed. Two ids must derive two distinct
    // accounts, or the program would resolve both runs from one tree.
    let accounts: Vec<_> = tree_ids.iter().copied().map(pda::tree).collect();
    assert_eq!(accounts.len(), 2);
    assert_ne!(accounts.first(), accounts.last());

    let published: Vec<u8> = ix.inputs.iter().map(|input| input.tree_index).collect();
    assert_eq!(published, vec![0, 1]);
}
