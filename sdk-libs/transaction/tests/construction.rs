//! Behavioral invariants for the public wallet transaction builder.
mod common;

use borsh::BorshDeserialize;
use common::{keypair, wallet_utxo};
use solana_address::Address;
use std::cell::RefCell;
use zolana_event::OutputDataEncoding;
use zolana_interface::{
    instruction::instruction_data::transact::OwnerTag, MAX_INPUT_TREES, N_PUBLIC_SLOTS,
};
use zolana_keypair::{
    NullifierKey, P256Pubkey, PublicKey, ShieldedAddress, ShieldedKeypair, SigningKey, ViewingKey,
};
use zolana_transaction::{
    instructions::transact::{
        canonical_shape, inputs_require_p256, pad_input_utxos, resolve_shape,
        validate_input_tree_order, ConfidentialTransaction, PublicTransferRequest,
        SettlementTarget, Shape, SppProofInputs, SppProofOutputUtxo,
    },
    keys::{DecryptRequest, DeriveRequest, ShieldedKeys, TransactionKeyRequest},
    serialization::confidential::Confidential,
    utxo::{derive_output_blinding_seed, derive_transact_output_blinding, SppProofInputUtxo},
    AssetRegistry, Data, DataRecord, DecodeCx, EncryptedScheme, Mint, TransactionError as E,
    UtxoSerialization, WalletUtxo,
};

fn payer(owner: &ShieldedKeypair) -> Address {
    owner.shielded_address().unwrap().solana_address().unwrap()
}
fn mint(id: u8) -> Mint {
    Mint {
        asset: Address::new_from_array([id; 32]),
        asset_id: u64::from(id),
    }
}
fn builder(owner: &ShieldedKeypair, amount: u64) -> ConfidentialTransaction {
    ConfidentialTransaction::new(
        vec![wallet_utxo(owner, Mint::SOL, amount, 7, 1)],
        payer(owner),
    )
    .unwrap()
}
fn error<T>(result: Result<T, E>, expected: E) {
    assert_eq!(result.err(), Some(expected));
}
fn rehash(note: &mut WalletUtxo) {
    note.utxo_hash = note
        .utxo
        .hash(
            &note.nullifier_pubkey,
            &note.data_hash.unwrap_or_default(),
            &note.ring_data_hash.unwrap_or_default(),
            note.tree_id,
        )
        .unwrap();
}
fn dummy(owner: &ShieldedKeypair, tree: u16) -> WalletUtxo {
    let d = SppProofInputUtxo::dummy_with_blinding([0; 32], tree).unwrap();
    WalletUtxo {
        utxo: d.utxo,
        nullifier_pubkey: d.nullifier_pubkey,
        utxo_hash: d.utxo_hash,
        nullifier: d.nullifier,
        data_hash: d.data_hash,
        ring_data_hash: d.ring_data_hash,
        tree_id: tree,
        leaf_index: 0,
        ..wallet_utxo(owner, Mint::SOL, 0, tree, 1)
    }
}
#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    inputs: Vec<WalletUtxo>,
    outputs: Vec<SppProofOutputUtxo>,
    transfers: Vec<PublicTransferRequest>,
    payer: Address,
    seed: [u8; 32],
    first: [u8; 32],
    trees: Vec<u16>,
    output_tree: u16,
    p256: bool,
}
fn snapshot(tx: &ConfidentialTransaction) -> Snapshot {
    Snapshot {
        inputs: tx.inputs().to_vec(),
        outputs: tx.outputs().to_vec(),
        transfers: tx.public_transfers().to_vec(),
        payer: tx.payer(),
        seed: *tx.blinding_seed(),
        first: *tx.first_nullifier(),
        trees: tx.input_tree_ids().to_vec(),
        output_tree: tx.output_tree_id(),
        p256: tx.requires_p256_owner().unwrap(),
    }
}
fn unchanged_failure(
    tx: &mut ConfidentialTransaction,
    shape: Shape,
    sender: &ShieldedAddress,
    expected: E,
) {
    let before = snapshot(tx);
    error(tx.pad_utxos(shape, sender), expected);
    assert_eq!(snapshot(tx), before);
}
fn assert_input(actual: &SppProofInputUtxo, expected: &SppProofInputUtxo) {
    assert_eq!(actual.utxo, expected.utxo);
    assert_eq!(actual.nullifier_pubkey, expected.nullifier_pubkey);
    assert_eq!(actual.utxo_hash, expected.utxo_hash);
    assert_eq!(actual.nullifier, expected.nullifier);
    assert_eq!(actual.data_hash, expected.data_hash);
    assert_eq!(actual.ring_data_hash, expected.ring_data_hash);
    assert_eq!(actual.tree_id, expected.tree_id);
    assert_eq!(actual.leaf_index, expected.leaf_index);
}

#[test]
fn constructor_rejects_missing_and_dummy_first_inputs() {
    let owner = keypair(1);
    error(
        ConfidentialTransaction::new(vec![], payer(&owner)),
        E::NoInputs,
    );
    error(
        ConfidentialTransaction::new(
            vec![dummy(&owner, 7), wallet_utxo(&owner, Mint::SOL, 1, 7, 1)],
            payer(&owner),
        ),
        E::DummyInFirstInputSlot,
    );
}

#[test]
fn constructor_binds_every_committed_input_field_at_each_position() {
    let owner = keypair(1);
    let other = keypair(2);
    let good = wallet_utxo(&owner, Mint::SOL, 42, 7, 1);
    // Every mutation remains validly encoded, isolating commitment validation.
    type Mutation = Box<dyn Fn(&mut WalletUtxo)>;
    let mutations: Vec<Mutation> = vec![
        Box::new(|n| n.utxo.amount += 1),
        Box::new(|n| n.utxo.asset = mint(2)),
        Box::new(|n| n.utxo.blinding = [1; 32]),
        Box::new(|n| n.tree_id += 1),
        Box::new(|n| n.nullifier_pubkey = [1; 32]),
        Box::new(|n| n.data_hash = Some([1; 32])),
        Box::new(|n| n.ring_data_hash = Some([1; 32])),
        Box::new(|n| n.utxo.ring_program_id = Some(Address::new_from_array([5; 32]))),
        Box::new(move |n| n.utxo.owner = other.signing_pubkey()),
        Box::new(|n| n.utxo_hash = [1; 32]),
    ];
    for mutate in mutations {
        for index in 0..2 {
            let mut notes = vec![good.clone(), good.clone()];
            mutate(notes.get_mut(index).unwrap());
            error(
                ConfidentialTransaction::new(notes, payer(&owner)),
                E::InputCommitmentMismatch { index },
            );
        }
    }
    let mut metadata = good;
    metadata.utxo.data = Data::new(vec![DataRecord::Memo(vec![8])]);
    metadata.leaf_index = 900;
    let tx = ConfidentialTransaction::new(vec![metadata.clone()], payer(&owner)).unwrap();
    assert_eq!(tx.inputs(), [metadata]);
}

#[test]
fn constructor_requires_preimage_hashes_but_accepts_hash_only_inputs() {
    let owner = keypair(1);
    for index in 0..2 {
        for ring in [false, true] {
            let mut notes = vec![wallet_utxo(&owner, Mint::SOL, 10, 7, 1); 2];
            let note = notes.get_mut(index).unwrap();
            note.utxo.data = Data::new(vec![if ring {
                DataRecord::RingData(vec![4])
            } else {
                DataRecord::UtxoData(vec![4])
            }]);
            if ring {
                note.utxo.ring_program_id = Some(Address::new_from_array([6; 32]));
            }
            error(
                ConfidentialTransaction::new(notes.clone(), payer(&owner)),
                if ring {
                    E::MissingInputRingDataHash { index }
                } else {
                    E::MissingInputDataHash { index }
                },
            );
            let note = notes.get_mut(index).unwrap();
            if ring {
                note.ring_data_hash = Some([1; 32]);
            } else {
                note.data_hash = Some([1; 32]);
            }
            rehash(note);
            assert!(ConfidentialTransaction::new(notes.clone(), payer(&owner)).is_ok());
            notes.get_mut(index).unwrap().utxo.data = Data::default();
            assert!(ConfidentialTransaction::new(notes, payer(&owner)).is_ok());
        }
    }
}

#[test]
fn constructor_enforces_declared_contiguous_trees_and_preserves_input_order() {
    let owner = keypair(1);
    let ordered = vec![
        wallet_utxo(&owner, Mint::SOL, 1, 9, 1),
        dummy(&owner, 9),
        wallet_utxo(&owner, Mint::SOL, 2, 4, 2),
        dummy(&owner, 4),
    ];
    let tx = ConfidentialTransaction::new(ordered.clone(), payer(&owner)).unwrap();
    assert_eq!(tx.inputs(), ordered);
    assert_eq!(tx.input_tree_ids(), [9, 4]);
    assert_eq!(*tx.first_nullifier(), ordered.first().unwrap().nullifier);
    let mut interleaved = ordered;
    interleaved.push(dummy(&owner, 9));
    let expected = E::InterleavedInputTrees {
        index: 4,
        tree_id: 9,
    };
    error(
        validate_input_tree_order(interleaved.iter().map(|n| n.tree_id)),
        expected.clone(),
    );
    error(
        ConfidentialTransaction::new(interleaved, payer(&owner)),
        expected,
    );
    error(
        ConfidentialTransaction::new(
            vec![wallet_utxo(&owner, Mint::SOL, 1, 9, 1), dummy(&owner, 3)],
            payer(&owner),
        ),
        E::PaddingInUndeclaredTree {
            index: 1,
            tree_id: 3,
        },
    );
    let notes: Vec<_> = (0..=MAX_INPUT_TREES)
        .map(|tree| wallet_utxo(&owner, Mint::SOL, 1, tree as u16, tree as u8))
        .collect();
    assert!(ConfidentialTransaction::new(
        notes.iter().take(MAX_INPUT_TREES).cloned().collect(),
        payer(&owner)
    )
    .is_ok());
    error(
        ConfidentialTransaction::new(notes, payer(&owner)),
        E::TooManyInputTrees {
            got: MAX_INPUT_TREES + 1,
            max: MAX_INPUT_TREES,
        },
    );
}

#[test]
fn padding_extends_last_tree_without_touching_existing_inputs() {
    let owner = keypair(1);
    let mut inputs: Vec<_> = [
        wallet_utxo(&owner, Mint::SOL, 1, 9, 1),
        dummy(&owner, 9),
        wallet_utxo(&owner, Mint::SOL, 2, 4, 2),
    ]
    .iter()
    .map(SppProofInputUtxo::from)
    .collect();
    let prefix = inputs.clone();
    pad_input_utxos(&mut inputs, Shape::IN5_OUT3).unwrap();
    for (actual, expected) in inputs.iter().zip(&prefix) {
        assert_input(actual, expected);
    }
    for pad in inputs.iter().skip(prefix.len()) {
        assert!(pad.is_dummy());
        assert_eq!(pad.tree_id, 4);
        assert_eq!(pad.utxo.amount, 0);
        assert_eq!(
            pad.utxo_hash,
            SppProofInputUtxo::dummy_with_blinding(pad.utxo.blinding, 4)
                .unwrap()
                .utxo_hash
        );
        assert_ne!(
            pad.utxo_hash,
            SppProofInputUtxo::dummy_with_blinding(pad.utxo.blinding, 9)
                .unwrap()
                .utxo_hash
        );
        assert_eq!(
            pad.nullifier,
            NullifierKey::from_secret([0; 31])
                .nullifier(&pad.utxo_hash, &pad.utxo.blinding)
                .unwrap()
        );
    }
    let full = inputs.clone();
    pad_input_utxos(&mut inputs, Shape::IN5_OUT3).unwrap();
    for (a, b) in inputs.iter().zip(&full) {
        assert_input(a, b);
    }
    error(
        pad_input_utxos(&mut inputs, Shape::IN1_OUT1),
        E::TooManyInputs { got: 5, max: 1 },
    );
    error(pad_input_utxos(&mut vec![], Shape::IN1_OUT1), E::NoInputs);
    error(
        pad_input_utxos(
            &mut vec![SppProofInputUtxo::dummy(0).unwrap()],
            Shape::IN1_OUT1,
        ),
        E::NoInputs,
    );
    let mut many = (0..=MAX_INPUT_TREES)
        .map(|t| SppProofInputUtxo::from(wallet_utxo(&owner, Mint::SOL, 1, t as u16, t as u8)))
        .collect();
    error(
        pad_input_utxos(&mut many, Shape::IN36_OUT2),
        E::TooManyInputTrees {
            got: MAX_INPUT_TREES + 1,
            max: MAX_INPUT_TREES,
        },
    );
}

#[test]
fn shape_selection_boundaries_and_explicit_consolidation() {
    // Literal expected order is independent of the selector's iterator.
    let shapes = [
        Shape::IN1_OUT1,
        Shape::IN1_OUT2,
        Shape::IN2_OUT2,
        Shape::IN2_OUT3,
        Shape::IN3_OUT3,
        Shape::IN4_OUT3,
        Shape::IN4_OUT4,
        Shape::IN5_OUT3,
        Shape::IN5_OUT4,
        Shape::IN1_OUT8,
    ];
    for n_in in 0..=37 {
        for n_out in 0..=9 {
            let expected = shapes
                .iter()
                .copied()
                .find(|s| n_in <= s.n_inputs() && n_out <= s.n_outputs())
                .ok_or(E::UnsupportedShape { n_in, n_out });
            assert_eq!(canonical_shape(n_in, n_out), expected);
        }
    }
    error(
        resolve_shape(Some(Shape::new(2, 1)), 1, 1),
        E::UnsupportedShape { n_in: 2, n_out: 1 },
    );
    error(
        resolve_shape(Some(Shape::IN1_OUT2), 2, 1),
        E::TooManyInputs { got: 2, max: 1 },
    );
    error(
        resolve_shape(Some(Shape::IN1_OUT1), 1, 2),
        E::TooManyOutputsForShape { got: 2, max: 1 },
    );
    assert_eq!(
        resolve_shape(Some(Shape::IN36_OUT2), 6, 1).unwrap(),
        Shape::IN36_OUT2
    );
    let owner = keypair(1);
    let sender = owner.shielded_address().unwrap();
    let notes: Vec<_> = (1..=6)
        .map(|n| wallet_utxo(&owner, Mint::SOL, 1, 7, n))
        .collect();
    error(
        ConfidentialTransaction::new(notes.clone(), payer(&owner))
            .unwrap()
            .encrypt(&owner),
        E::UnsupportedShape { n_in: 6, n_out: 1 },
    );
    let mut tx = ConfidentialTransaction::new(notes, payer(&owner)).unwrap();
    tx.pad_utxos(Shape::IN36_OUT2, &sender).unwrap();
    let mut proof = tx.encrypt(&owner).unwrap();
    assert_eq!(proof.check_shape().unwrap(), Shape::IN36_OUT2);
    assert_eq!(proof.input_utxos.len(), 36);
    assert_eq!(
        proof
            .output_utxos
            .iter()
            .map(|o| o.amount)
            .collect::<Vec<_>>(),
        [6, 0]
    );
    proof.output_utxos.pop();
    error(
        proof.check_shape(),
        E::UnsupportedShape { n_in: 36, n_out: 1 },
    );
    proof.input_utxos.get_mut(1).unwrap().tree_id = 9;
    let expected = E::InterleavedInputTrees {
        index: 2,
        tree_id: 7,
    };
    error(proof.check_shape(), expected.clone());
    error(proof.message_hash(), expected.clone());
    error(proof.input_utxo_hashes(), expected);
}

#[test]
fn failed_padding_is_atomic_and_repairable_without_losing_configuration() {
    let owner = keypair(1);
    let sender = owner.shielded_address().unwrap();
    let mut tx = builder(&owner, 5).with_output_tree_id(19).unwrap();
    tx.transfer_sol(&sender, 3).unwrap();
    unchanged_failure(
        &mut tx,
        Shape::new(2, 1),
        &sender,
        E::UnsupportedShape { n_in: 2, n_out: 1 },
    );
    unchanged_failure(
        &mut tx,
        Shape::IN1_OUT1,
        &sender,
        E::TooManyOutputsForShape { got: 2, max: 1 },
    );
    tx.pad_utxos(Shape::IN1_OUT2, &sender).unwrap();
    assert_eq!(
        tx.outputs().iter().map(|o| o.amount).collect::<Vec<_>>(),
        [3, 2]
    );
    let notes = vec![
        wallet_utxo(&owner, Mint::SOL, 2, 7, 1),
        wallet_utxo(&owner, Mint::SOL, 3, 7, 2),
    ];
    let mut tx = ConfidentialTransaction::new(notes, payer(&owner)).unwrap();
    unchanged_failure(
        &mut tx,
        Shape::IN1_OUT1,
        &sender,
        E::TooManyInputs { got: 2, max: 1 },
    );
    tx.pad_utxos(Shape::IN2_OUT2, &sender).unwrap();
    for public in [false, true] {
        let mut tx = builder(&owner, 5);
        if public {
            tx.withdraw_sol(6, payer(&owner)).unwrap();
        } else {
            tx.transfer_sol(&sender, 6).unwrap();
        }
        unchanged_failure(
            &mut tx,
            Shape::IN1_OUT2,
            &sender,
            E::InsufficientBalance {
                requested: 1,
                available: 0,
            },
        );
        tx.deposit_sol(2, payer(&owner)).unwrap();
        tx.pad_utxos(Shape::IN1_OUT2, &sender).unwrap();
        assert_eq!(
            tx.outputs().iter().map(|o| o.amount).sum::<u64>(),
            if public { 1 } else { 7 }
        );
    }
    let notes = vec![
        wallet_utxo(&owner, Mint::SOL, u64::MAX, 7, 1),
        wallet_utxo(&owner, Mint::SOL, 1, 7, 2),
    ];
    let mut tx = ConfidentialTransaction::new(notes, payer(&owner)).unwrap();
    unchanged_failure(
        &mut tx,
        Shape::IN2_OUT2,
        &sender,
        E::SelectedBalanceOverflow,
    );
    tx.transfer_sol(&sender, 1).unwrap();
    tx.pad_utxos(Shape::IN2_OUT2, &sender).unwrap();
    assert_eq!(
        tx.outputs().iter().map(|o| o.amount).collect::<Vec<_>>(),
        [1, u64::MAX]
    );
}

#[test]
fn asset_limit_ignores_zero_private_slots_and_failure_retains_configurability() {
    let owner = keypair(1);
    let sender = owner.shielded_address().unwrap();
    assert_eq!(N_PUBLIC_SLOTS, 3);
    let notes = vec![
        wallet_utxo(&owner, Mint::SOL, 1, 7, 1),
        wallet_utxo(&owner, mint(2), 1, 7, 2),
        wallet_utxo(&owner, mint(3), 1, 7, 3),
    ];
    let mut tx = ConfidentialTransaction::new(notes.clone(), payer(&owner)).unwrap();
    tx.add_output_utxo(SppProofOutputUtxo::new(mint(4), 0, sender).unwrap())
        .unwrap();
    tx.pad_utxos(Shape::IN4_OUT4, &sender).unwrap();
    assert_eq!(
        tx.outputs()
            .iter()
            .map(|o| (o.asset, o.amount))
            .collect::<Vec<_>>(),
        [(mint(4), 0), (Mint::SOL, 1), (mint(2), 1), (mint(3), 1)]
    );
    let mut excessive = notes;
    excessive.push(wallet_utxo(&owner, mint(4), 1, 7, 4));
    let mut tx = ConfidentialTransaction::new(excessive, payer(&owner)).unwrap();
    unchanged_failure(
        &mut tx,
        Shape::IN4_OUT4,
        &sender,
        E::TooManyAssets { got: 4, max: 3 },
    );
    tx.transfer_sol(&sender, 1).unwrap();
    assert_eq!(tx.outputs().len(), 1);
    let mut zero_input = vec![wallet_utxo(&owner, Mint::SOL, 1, 7, 1)];
    zero_input.extend((2..=5).map(|id| wallet_utxo(&owner, mint(id), 0, 7, id)));
    let mut tx = ConfidentialTransaction::new(zero_input, payer(&owner)).unwrap();
    tx.pad_utxos(Shape::IN5_OUT3, &sender).unwrap();
    assert_eq!(
        tx.outputs().iter().map(|o| o.amount).collect::<Vec<_>>(),
        [1, 0, 0]
    );
}

#[test]
fn explicit_output_fields_survive_padding_and_change_uses_asset_first_use_order() {
    let owner = keypair(1);
    let recipient = keypair(2);
    let sender = owner.shielded_address().unwrap();
    let address = recipient.shielded_address().unwrap();
    let mut tx =
        ConfidentialTransaction::new(vec![wallet_utxo(&owner, mint(2), 8, 7, 1)], payer(&owner))
            .unwrap();
    let output = SppProofOutputUtxo::new(Mint::SOL, 3, address)
        .unwrap()
        .with_memo(b"invoice".to_vec());
    tx.add_output_utxo(output.clone()).unwrap();
    tx.deposit_sol(5, payer(&owner)).unwrap();
    tx.deposit(mint(3), 4, payer(&owner)).unwrap();
    tx.pad_utxos(Shape::IN4_OUT4, &sender).unwrap();
    assert_eq!(tx.outputs().first(), Some(&output));
    let change = tx.outputs().iter().skip(1);
    for (actual, (asset, amount)) in change.zip([(mint(2), 8), (Mint::SOL, 2), (mint(3), 4)]) {
        assert_eq!(
            actual,
            &SppProofOutputUtxo {
                asset,
                amount,
                owner_address: Some(sender),
                ..Default::default()
            }
        );
    }
    let mut full = builder(&owner, 5);
    full.transfer_sol(&address, 5).unwrap();
    full.pad_utxos(Shape::IN1_OUT2, &sender).unwrap();
    let padding = full.outputs().get(1).unwrap();
    assert_eq!(
        padding,
        &SppProofOutputUtxo {
            asset: Mint::SOL,
            amount: 0,
            blinding: padding.blinding, // Padding randomness has no fixed value.
            owner_address: Some(sender),
            owner_tag: Some(sender.confidential_view_tag().unwrap()),
            ..Default::default()
        }
    );
    assert!(!padding.is_dummy());
    let mut max = builder(&owner, u64::MAX);
    max.pad_utxos(Shape::IN1_OUT1, &sender).unwrap();
    assert_eq!(max.outputs().first().unwrap().amount, u64::MAX);
}

#[test]
fn padded_builder_rejects_every_mutator_and_remains_encryptable() {
    let owner = keypair(1);
    let sender = owner.shielded_address().unwrap();
    let mut tx =
        ConfidentialTransaction::new(vec![wallet_utxo(&owner, mint(2), 5, 7, 1)], payer(&owner))
            .unwrap();
    tx.pad_utxos(Shape::IN1_OUT2, &sender).unwrap();
    let before = snapshot(&tx);
    error(
        tx.pad_utxos(Shape::IN1_OUT2, &sender),
        E::OutputUtxosAlreadyPadded,
    );
    error(
        tx.add_output_utxo(SppProofOutputUtxo::new(Mint::SOL, 1, sender).unwrap()),
        E::OutputUtxosAlreadyPadded,
    );
    error(tx.transfer_sol(&sender, 1), E::OutputUtxosAlreadyPadded);
    error(
        tx.transfer(&sender, mint(2).asset, 1),
        E::OutputUtxosAlreadyPadded,
    );
    error(
        tx.transfer_with_ring(&sender, Mint::SOL, 1, None),
        E::OutputUtxosAlreadyPadded,
    );
    error(
        tx.deposit_sol(1, payer(&owner)),
        E::OutputUtxosAlreadyPadded,
    );
    error(
        tx.withdraw_sol(1, payer(&owner)),
        E::OutputUtxosAlreadyPadded,
    );
    error(
        tx.deposit(mint(2), 1, payer(&owner)),
        E::OutputUtxosAlreadyPadded,
    );
    error(
        tx.withdraw(mint(2).asset, 1, payer(&owner)),
        E::OutputUtxosAlreadyPadded,
    );
    error(
        tx.settle(
            Mint::SOL,
            true,
            1,
            SettlementTarget::Sol {
                user_sol_account: payer(&owner),
            },
        ),
        E::OutputUtxosAlreadyPadded,
    );
    assert_eq!(snapshot(&tx), before);
    assert_eq!(
        tx.encrypt(&owner).unwrap().check_shape().unwrap(),
        Shape::IN1_OUT2
    );
    let mut tx = builder(&owner, 1);
    tx.pad_utxos(Shape::IN1_OUT1, &sender).unwrap();
    error(tx.with_output_tree_id(4), E::OutputUtxosAlreadyPadded);
}

// Assert both readers recover independently expected fields and the resulting
// Utxo reproduces the published commitment (not merely its own serialization).
fn assert_recovery(
    proof: &SppProofInputs,
    tx_key: &ViewingKey,
    readers: &[&ShieldedKeypair],
    expected: &[(Mint, u64, ShieldedAddress, Option<Address>, Data)],
) {
    assert_eq!(proof.output_utxos.len(), expected.len());
    assert_eq!(proof.external_data.outputs.len(), expected.len());
    let registry = AssetRegistry::new([(2, mint(2).asset), (3, mint(3).asset)]).unwrap();
    let seed = derive_output_blinding_seed(&proof.first_nullifier().unwrap(), &proof.blinding_seed)
        .unwrap();
    for (index, ((published, output), (asset, amount, address, ring, data))) in proof
        .external_data
        .outputs
        .iter()
        .zip(&proof.output_utxos)
        .zip(expected)
        .enumerate()
    {
        let bytes = published.data.as_ref().unwrap();
        let OutputDataEncoding::Encrypted(blob) =
            OutputDataEncoding::try_from_slice(bytes).unwrap()
        else {
            panic!("encrypted output")
        };
        let (scheme, body) = blob.split_first().unwrap();
        assert_eq!(
            *scheme,
            if ring.is_some() {
                EncryptedScheme::RingConfidential
            } else {
                EncryptedScheme::Confidential
            }
            .as_byte()
        );
        assert_eq!(
            Confidential::embedded_viewing_pk(body).unwrap(),
            address.viewing_pubkey
        );
        let reader = readers
            .iter()
            .find(|r| r.viewing_pubkey() == address.viewing_pubkey)
            .unwrap();
        let recovered = Confidential::decode(
            body,
            &DecodeCx {
                viewing_key: &reader.viewing_key,
                tx_viewing_pk: Some(
                    P256Pubkey::from_bytes(proof.external_data.tx_viewing_pk).unwrap(),
                ),
                salt: Some(proof.external_data.salt),
                slot_index: index as u32,
                first_nullifier: Some(proof.first_nullifier().unwrap()),
            },
        )
        .unwrap();
        assert_eq!(
            recovered,
            Confidential::decrypt_with_tx_key(tx_key, body, proof.external_data.salt, index as u32)
                .unwrap()
        );
        let blinding =
            derive_transact_output_blinding(&proof.first_nullifier().unwrap(), &seed, index as u32)
                .unwrap();
        assert_eq!(
            (
                recovered.asset_id,
                recovered.amount,
                recovered.blinding,
                recovered.ring_program_id,
                &recovered.data
            ),
            (asset.asset_id, *amount, blinding, *ring, data)
        );
        assert_eq!(
            (
                output.asset,
                output.amount,
                output.owner_address,
                output.ring_program_id,
                &output.data,
                output.blinding
            ),
            (*asset, *amount, Some(*address), *ring, data, blinding)
        );
        let note = recovered
            .into_utxo(address.signing_pubkey, &registry)
            .unwrap();
        assert_eq!(
            published.utxo_hash,
            note.hash(
                &address.nullifier_pubkey,
                &output.data_hash.unwrap_or_default(),
                &output.ring_data_hash.unwrap_or_default(),
                proof.output_tree_id
            )
            .unwrap()
        );
        assert_eq!(
            proof.external_data.resolved_owner_tags.get(index),
            Some(&address.confidential_view_tag().unwrap())
        );
    }
}

#[test]
fn generated_sol_and_spl_operations_conserve_each_mint_and_recover_every_output() {
    let owner = keypair(1);
    let recipient = keypair(2);
    let sender = owner.shielded_address().unwrap();
    let receiver = recipient.shielded_address().unwrap();
    // 24 reproducible operation combinations, two mints, two input trees and
    // both automatic/manual finalization. Arithmetic is a separate u128 ledger.
    for case in 0..24u64 {
        let sol_in = 20 + case;
        let spl_in = 40 + case;
        let deposit = 1 + case % 7;
        let withdrawal = 1 + case % 5;
        let transfer = if case % 3 == 0 {
            sol_in + deposit - withdrawal
        } else {
            1 + case % 11
        };
        let spl_deposit = 1 + case % 3;
        let spl_withdrawal = 1 + case % 2;
        let spl_transfer = if case % 4 == 0 {
            spl_in + spl_deposit - spl_withdrawal
        } else {
            1 + case % 13
        };
        let inputs = vec![
            wallet_utxo(&owner, Mint::SOL, sol_in, 9, 1),
            wallet_utxo(&owner, mint(2), spl_in, 4, 2),
        ];
        let first = inputs.first().unwrap().nullifier;
        let tx_key = owner
            .viewing_key
            .get_transaction_viewing_key(&first)
            .unwrap();
        let mut tx = ConfidentialTransaction::new(inputs.clone(), payer(&owner))
            .unwrap()
            .with_output_tree_id(12)
            .unwrap();
        if case % 2 == 0 {
            tx.deposit_sol(deposit, payer(&owner)).unwrap();
            tx.withdraw_sol(withdrawal, payer(&owner)).unwrap();
        } else {
            tx.withdraw_sol(withdrawal, payer(&owner)).unwrap();
            tx.deposit_sol(deposit, payer(&owner)).unwrap();
        }
        tx.deposit(mint(2), spl_deposit, payer(&owner)).unwrap();
        tx.withdraw(mint(2).asset, spl_withdrawal, payer(&owner))
            .unwrap();
        tx.transfer_sol(&receiver, transfer).unwrap();
        tx.transfer(&receiver, mint(2).asset, spl_transfer).unwrap();
        let sol_change = sol_in + deposit - withdrawal - transfer;
        let spl_change = spl_in + spl_deposit - spl_withdrawal - spl_transfer;
        let mut expected = vec![
            (Mint::SOL, transfer, receiver, None, Data::default()),
            (mint(2), spl_transfer, receiver, None, Data::default()),
        ];
        if sol_change > 0 {
            expected.push((Mint::SOL, sol_change, sender, None, Data::default()));
        }
        if spl_change > 0 {
            expected.push((mint(2), spl_change, sender, None, Data::default()));
        }
        let expected_shape = if case % 2 == 0 {
            Shape::IN4_OUT4
        } else {
            match expected.len() {
                2 => Shape::IN2_OUT2,
                3 => Shape::IN2_OUT3,
                4 => Shape::IN4_OUT4,
                _ => unreachable!(),
            }
        };
        if case % 2 == 0 {
            tx.pad_utxos(expected_shape, &sender).unwrap();
        }
        while expected.len() < expected_shape.n_outputs() {
            expected.push((Mint::SOL, 0, sender, None, Data::default()));
        }
        let proof = tx.encrypt(&owner).unwrap();
        assert_eq!(proof.check_shape().unwrap(), expected_shape);
        assert_eq!(proof.output_tree_id, 12);
        for (actual, original) in proof.input_utxos.iter().zip(&inputs) {
            assert_input(actual, &SppProofInputUtxo::from(original));
        }
        assert!(proof
            .input_utxos
            .iter()
            .skip(2)
            .all(|i| i.is_dummy() && i.tree_id == 4));
        for (asset, available) in [
            (
                Mint::SOL,
                u128::from(sol_in) + u128::from(deposit) - u128::from(withdrawal),
            ),
            (
                mint(2),
                u128::from(spl_in) + u128::from(spl_deposit) - u128::from(spl_withdrawal),
            ),
        ] {
            let actual: u128 = proof
                .output_utxos
                .iter()
                .filter(|o| o.asset.asset == asset.asset)
                .map(|o| u128::from(o.amount))
                .sum();
            assert_eq!(actual, available, "case {case}, mint {asset:?}");
        }
        assert_eq!(proof.external_data.interface_transfers.len(), 4);
        assert_eq!(
            proof
                .external_data
                .interface_transfers
                .iter()
                .map(|t| (t.is_deposit(), t.amount()))
                .collect::<Vec<_>>(),
            if case % 2 == 0 {
                vec![
                    (true, deposit),
                    (false, withdrawal),
                    (true, spl_deposit),
                    (false, spl_withdrawal),
                ]
            } else {
                vec![
                    (false, withdrawal),
                    (true, deposit),
                    (true, spl_deposit),
                    (false, spl_withdrawal),
                ]
            }
        );
        assert_recovery(&proof, &tx_key, &[&owner, &recipient], &expected);
    }
}

#[test]
fn mixed_rings_and_relayed_owner_tags_match_recovered_owners() {
    let owner = keypair(1);
    let recipient = keypair(2);
    let sender = owner.shielded_address().unwrap();
    let receiver = recipient.shielded_address().unwrap();
    let ring = Address::new_from_array([42; 32]);
    let other_ring = Address::new_from_array([43; 32]);
    for relayed in [false, true] {
        let input = wallet_utxo(&owner, Mint::SOL, 10, 7, 1);
        let key = owner
            .viewing_key
            .get_transaction_viewing_key(&input.nullifier)
            .unwrap();
        let mut tx = ConfidentialTransaction::new_with_ring(
            vec![input],
            if relayed {
                Address::new_from_array([99; 32])
            } else {
                payer(&owner)
            },
            ring,
        )
        .unwrap();
        tx.transfer_sol(&receiver, 2).unwrap();
        tx.transfer_with_ring(&receiver, Mint::SOL, 3, None)
            .unwrap();
        tx.transfer_with_ring(&receiver, Mint::SOL, 1, Some(other_ring))
            .unwrap();
        tx.pad_utxos(Shape::IN1_OUT8, &sender).unwrap();
        let proof = tx.encrypt(&owner).unwrap();
        let mut expected = vec![
            (Mint::SOL, 2, receiver, Some(ring), Data::default()),
            (Mint::SOL, 3, receiver, None, Data::default()),
            (Mint::SOL, 1, receiver, Some(other_ring), Data::default()),
            (Mint::SOL, 4, sender, Some(ring), Data::default()),
        ];
        expected.extend((0..4).map(|_| (Mint::SOL, 0, sender, Some(ring), Data::default())));
        assert_recovery(&proof, &key, &[&owner, &recipient], &expected);
        for output in proof.external_data.outputs.iter().take(3) {
            assert_eq!(
                output.owner_tag,
                OwnerTag::Inline(receiver.confidential_view_tag().unwrap())
            );
        }
        for output in proof.external_data.outputs.iter().skip(3) {
            assert_eq!(
                output.owner_tag,
                if relayed {
                    OwnerTag::Inline(sender.confidential_view_tag().unwrap())
                } else {
                    OwnerTag::Account(0)
                }
            );
        }
    }
    let mut tx = builder(&owner, 1);
    tx.add_output_utxo(SppProofOutputUtxo::default()).unwrap();
    error(tx.encrypt(&owner), E::OutputWithoutOwner { slot_index: 0 });
}

#[test]
fn p256_requires_custom_sender_ring_and_cannot_use_transfer_convenience_apis() {
    let owner = keypair(1);
    let p256 =
        ShieldedKeypair::from_keypair(SigningKey::from_p256_bytes(&[3; 32]).unwrap()).unwrap();
    let sender = p256.shielded_address().unwrap();
    let input = wallet_utxo(&p256, Mint::SOL, 10, 7, 1);
    let tx = ConfidentialTransaction::new(vec![input.clone()], payer(&owner)).unwrap();
    assert!(tx.requires_p256_owner().unwrap());
    error(tx.encrypt(&p256), E::P256TransactUnsupported);
    let key = p256
        .viewing_key
        .get_transaction_viewing_key(&input.nullifier)
        .unwrap();
    let ring = Address::new_from_array([42; 32]);
    let proof = ConfidentialTransaction::new_with_ring(vec![input], payer(&owner), ring)
        .unwrap()
        .encrypt(&p256)
        .unwrap();
    assert_eq!(
        proof.external_data.outputs.first().unwrap().owner_tag,
        OwnerTag::Inline(sender.confidential_view_tag().unwrap())
    );
    assert_recovery(
        &proof,
        &key,
        &[&p256],
        &[(Mint::SOL, 10, sender, Some(ring), Data::default())],
    );
    let mut tx =
        ConfidentialTransaction::new(vec![wallet_utxo(&owner, mint(2), 10, 7, 1)], payer(&owner))
            .unwrap();
    let before = snapshot(&tx);
    error(tx.transfer_sol(&sender, 1), E::P256TransactUnsupported);
    error(
        tx.transfer(&sender, mint(2).asset, 1),
        E::P256TransactUnsupported,
    );
    error(
        tx.transfer_with_ring(&sender, Mint::SOL, 1, Some(ring)),
        E::P256TransactUnsupported,
    );
    assert_eq!(snapshot(&tx), before);
    assert!(!inputs_require_p256(&[]).unwrap());
    assert!(!inputs_require_p256(&[SppProofInputUtxo::dummy(7).unwrap()]).unwrap());
    for first_p256 in [true, false] {
        let p = SppProofInputUtxo::from(wallet_utxo(&p256, Mint::SOL, 1, 7, 2));
        let ed = SppProofInputUtxo::from(wallet_utxo(&owner, Mint::SOL, 1, 7, 1));
        assert!(inputs_require_p256(&if first_p256 { vec![p, ed] } else { vec![ed, p] }).unwrap());
        let notes = if first_p256 {
            vec![
                wallet_utxo(&p256, Mint::SOL, 1, 7, 2),
                wallet_utxo(&owner, Mint::SOL, 1, 7, 1),
            ]
        } else {
            vec![
                wallet_utxo(&owner, Mint::SOL, 1, 7, 1),
                wallet_utxo(&p256, Mint::SOL, 1, 7, 2),
            ]
        };
        assert!(ConfidentialTransaction::new(notes, payer(&owner))
            .unwrap()
            .requires_p256_owner()
            .unwrap());
    }
    assert!(!builder(&owner, 1).requires_p256_owner().unwrap());
}

struct RecordingKeys {
    address: ShieldedAddress,
    key: ViewingKey,
    requests: RefCell<Vec<TransactionKeyRequest>>,
    address_error: bool,
    key_error: bool,
    empty: bool,
}
impl ShieldedKeys for RecordingKeys {
    fn address(&self) -> Result<ShieldedAddress, E> {
        if self.address_error {
            Err(E::AuthorityViewingKeyMismatch)
        } else {
            Ok(self.address)
        }
    }
    fn viewing_public_keys(&self) -> Vec<P256Pubkey> {
        panic!("builder does not enumerate viewing keys")
    }
    fn decrypt(&self, _requests: &[DecryptRequest<'_>]) -> Result<Vec<Vec<u8>>, E> {
        panic!("builder does not decrypt")
    }
    fn derive(&self, _requests: &[DeriveRequest]) -> Result<Vec<[u8; 32]>, E> {
        panic!("builder does not derive nullifiers")
    }
    fn transaction_keys(&self, requests: &[TransactionKeyRequest]) -> Result<Vec<ViewingKey>, E> {
        self.requests.borrow_mut().extend_from_slice(requests);
        if self.key_error {
            Err(E::UnknownViewingKey)
        } else if self.empty {
            Ok(vec![])
        } else {
            Ok(vec![self.key.clone()])
        }
    }
}

#[test]
fn key_holder_errors_and_empty_response_propagate_and_requests_use_first_input() {
    let owner = keypair(1);
    let sender = owner.shielded_address().unwrap();
    let recipient = keypair(2);
    let receiver = recipient.shielded_address().unwrap();
    let mut keys = RecordingKeys {
        address: sender,
        key: recipient.viewing_key.clone(),
        requests: RefCell::new(vec![]),
        address_error: true,
        key_error: false,
        empty: false,
    };
    error(
        builder(&owner, 3).encrypt(&keys),
        E::AuthorityViewingKeyMismatch,
    );
    assert!(keys.requests.borrow().is_empty());
    keys.address_error = false;
    keys.key_error = true;
    error(builder(&owner, 3).encrypt(&keys), E::UnknownViewingKey);
    keys.key_error = false;
    keys.empty = true;
    error(
        builder(&owner, 3).encrypt(&keys),
        E::IncompleteDerivation { got: 0, want: 1 },
    );
    keys.empty = false;
    keys.requests.borrow_mut().clear();
    let input = wallet_utxo(&owner, Mint::SOL, 3, 7, 1);
    let first = input.nullifier;
    let mut tx = ConfidentialTransaction::new(vec![input.clone()], payer(&owner)).unwrap();
    tx.transfer_sol(&receiver, 2).unwrap();
    let proof = tx.encrypt(&keys).unwrap();
    assert_eq!(
        *keys.requests.borrow(),
        [TransactionKeyRequest {
            viewing_pubkey: sender.viewing_pubkey,
            first_nullifier: first
        }]
    );
    assert_eq!(
        proof.external_data.tx_viewing_pk,
        *keys.key.pubkey().as_bytes()
    );
    assert_ne!(
        keys.key.pubkey(),
        owner
            .viewing_key
            .get_transaction_viewing_key(&first)
            .unwrap()
            .pubkey()
    );
    let expected = [
        (Mint::SOL, 2, receiver, None, Data::default()),
        (Mint::SOL, 1, sender, None, Data::default()),
    ];
    assert_recovery(&proof, &keys.key, &[&owner, &recipient], &expected);
    let mut explicit = ConfidentialTransaction::new(vec![input], payer(&owner)).unwrap();
    explicit.transfer_sol(&receiver, 2).unwrap();
    let explicit = explicit
        .encrypt_with_viewing_key(&sender, &keys.key)
        .unwrap();
    assert_eq!(
        explicit.external_data.tx_viewing_pk,
        proof.external_data.tx_viewing_pk
    );
    assert_eq!(
        explicit.check_shape().unwrap(),
        proof.check_shape().unwrap()
    );
    assert_recovery(&explicit, &keys.key, &[&owner, &recipient], &expected);
    for (a, b) in proof.input_utxos.iter().zip(&explicit.input_utxos) {
        assert_input(a, b);
    }
}

#[test]
fn pda_sender_owner_tags_resolve_for_self_paid_and_relayed_transactions() {
    let owner = keypair(1);
    let pda = Address::new_from_array([88; 32]);
    let sender = ShieldedAddress::for_pda(
        &pda,
        owner.shielded_address().unwrap().nullifier_pubkey,
        owner.viewing_pubkey(),
    );
    for self_paid in [true, false] {
        let mut input = wallet_utxo(&owner, Mint::SOL, 3, 7, 1);
        input.utxo.owner = PublicKey::from_pda(&pda);
        rehash(&mut input);
        let key = owner
            .viewing_key
            .get_transaction_viewing_key(&input.nullifier)
            .unwrap();
        let tx =
            ConfidentialTransaction::new(vec![input], if self_paid { pda } else { payer(&owner) })
                .unwrap();
        let proof = tx.encrypt_with_viewing_key(&sender, &key).unwrap();
        assert_eq!(
            proof.external_data.outputs.first().unwrap().owner_tag,
            if self_paid {
                OwnerTag::Account(0)
            } else {
                OwnerTag::Inline(pda.to_bytes())
            }
        );
        assert_recovery(
            &proof,
            &key,
            &[&owner],
            &[(Mint::SOL, 3, sender, None, Data::default())],
        );
    }
}

#[test]
fn builder_automatically_selects_every_supported_nonconsolidation_boundary() {
    let owner = keypair(1);
    let sender = owner.shielded_address().unwrap();
    for shape in [
        Shape::IN1_OUT1,
        Shape::IN1_OUT2,
        Shape::IN2_OUT2,
        Shape::IN2_OUT3,
        Shape::IN3_OUT3,
        Shape::IN4_OUT3,
        Shape::IN4_OUT4,
        Shape::IN5_OUT3,
        Shape::IN5_OUT4,
        Shape::IN1_OUT8,
    ] {
        let inputs = (0..shape.n_inputs())
            .map(|n| wallet_utxo(&owner, Mint::SOL, 10, 7, n as u8))
            .collect();
        let mut tx = ConfidentialTransaction::new(inputs, payer(&owner)).unwrap();
        for _ in 1..shape.n_outputs() {
            tx.transfer_sol(&sender, 1).unwrap();
        }
        let proof = tx.encrypt(&owner).unwrap();
        assert_eq!(proof.check_shape().unwrap(), shape);
        assert_eq!(
            proof
                .output_utxos
                .iter()
                .map(|o| u128::from(o.amount))
                .sum::<u128>(),
            10 * shape.n_inputs() as u128
        );
        assert!(proof
            .output_utxos
            .iter()
            .take(shape.n_outputs() - 1)
            .all(|o| o.amount == 1));
        assert_eq!(
            proof.output_utxos.last().unwrap().amount,
            10 * shape.n_inputs() as u64 - (shape.n_outputs() - 1) as u64
        );
    }
}

#[test]
fn encrypted_explicit_data_and_memo_survive_with_their_commitment_hashes() {
    let owner = keypair(1);
    let recipient = keypair(2);
    let address = recipient.shielded_address().unwrap();
    let ring = Address::new_from_array([55; 32]);
    let mut tx = builder(&owner, 5).with_output_tree_id(31).unwrap();
    let key = owner
        .viewing_key
        .get_transaction_viewing_key(tx.first_nullifier())
        .unwrap();
    let explicit = SppProofOutputUtxo::new(Mint::SOL, 5, address)
        .unwrap()
        .with_ring_data(ring, vec![1, 2], [1; 32])
        .with_utxo_data(vec![3, 4], [2; 32])
        .with_memo(b"receipt".to_vec());
    tx.add_output_utxo(explicit.clone()).unwrap();
    tx.pad_utxos(Shape::IN1_OUT1, &owner.shielded_address().unwrap())
        .unwrap();
    assert_eq!(tx.outputs(), std::slice::from_ref(&explicit));
    let proof = tx.encrypt(&owner).unwrap();
    assert_ne!(
        proof.output_utxos.first().unwrap().blinding,
        explicit.blinding
    );
    assert_eq!(proof.output_utxos.first().unwrap().data_hash, Some([2; 32]));
    assert_eq!(
        proof.output_utxos.first().unwrap().ring_data_hash,
        Some([1; 32])
    );
    assert_recovery(
        &proof,
        &key,
        &[&owner, &recipient],
        &[(
            Mint::SOL,
            5,
            address,
            Some(ring),
            Data::new(vec![
                DataRecord::RingData(vec![1, 2]),
                DataRecord::UtxoData(vec![3, 4]),
                DataRecord::Memo(b"receipt".to_vec()),
            ]),
        )],
    );
}

#[test]
fn another_mints_surplus_cannot_fund_private_or_public_spl_deficits() {
    let owner = keypair(1);
    let sender = owner.shielded_address().unwrap();
    for public in [false, true] {
        let inputs = vec![
            wallet_utxo(&owner, Mint::SOL, 100, 7, 1),
            wallet_utxo(&owner, mint(2), 4, 7, 2),
        ];
        let mut tx = ConfidentialTransaction::new(inputs, payer(&owner)).unwrap();
        if public {
            tx.withdraw(mint(2).asset, 5, payer(&owner)).unwrap();
        } else {
            tx.transfer(&sender, mint(2).asset, 5).unwrap();
        }
        unchanged_failure(
            &mut tx,
            Shape::IN3_OUT3,
            &sender,
            E::InsufficientBalance {
                requested: 1,
                available: 0,
            },
        );
        tx.deposit(mint(2), 1, payer(&owner)).unwrap();
        tx.pad_utxos(Shape::IN3_OUT3, &sender).unwrap();
        let expected = if public {
            vec![(Mint::SOL, 100), (Mint::SOL, 0), (Mint::SOL, 0)]
        } else {
            vec![(mint(2), 5), (Mint::SOL, 100), (Mint::SOL, 0)]
        };
        assert_eq!(
            tx.outputs()
                .iter()
                .map(|o| (o.asset, o.amount))
                .collect::<Vec<_>>(),
            expected
        );
    }
}
