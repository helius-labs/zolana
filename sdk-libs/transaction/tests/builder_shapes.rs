//! Every builder-reachable proof shape builds and signs.
//!
//! The prover and on-chain verifier serve the ten shapes listed in
//! [`SUPPORTED_SHAPES`]; `sdk-libs/client/tests/transfer_dummy.rs` proves each
//! against its committed verifying key. This is the cheaper builder-side
//! counterpart: it drives a real [`Transaction`] through assembly + signing for
//! every shape (no prover server), padding a single real input and the
//! sender-change slots up to the target dimensions, and asserts the resulting
//! [`SignedTransaction`] has the expected `(n_inputs, n_outputs)`.
//!
//! Run with: `cargo test -p zolana-transaction --test builder_shapes`

use zolana_keypair::ShieldedKeypair;
use zolana_transaction::{
    error::TransactionError,
    instructions::{
        transact::{
            canonical_shape, Shape, SignedTransaction, Transaction, SENDER_SLOT_COUNT,
            SUPPORTED_SHAPES,
        },
        types::SpendUtxo,
    },
    AssetRegistry, Data, Utxo, SOL_MINT,
};

/// A single Solana-owned input the signing keypair can spend, with a distinct
/// blinding so repeated inputs carry distinct nullifiers.
fn real_input(keypair: &ShieldedKeypair, amount: u64, seed: u8) -> SpendUtxo {
    let utxo = Utxo {
        owner: keypair.signing_pubkey(),
        asset: SOL_MINT,
        amount,
        blinding: [seed; 31],
        zone_program_id: None,
        data: Data::default(),
    };
    SpendUtxo::from_keypair(utxo, keypair)
}

/// Sign a change-only transfer with `n_in` real inputs and no recipients,
/// declaring `shape` so the builder pads inputs and sender-change slots up to
/// its dimensions.
fn sign_padded(shape: Shape, n_in: usize) -> Result<SignedTransaction, TransactionError> {
    let sender = ShieldedKeypair::new().unwrap();
    let inputs = (0..n_in)
        .map(|i| real_input(&sender, 1_000, (i + 1) as u8))
        .collect();
    let tx = Transaction::new(
        sender.shielded_address().unwrap(),
        inputs,
        Default::default(),
    )
    .with_shape(shape);
    tx.sign(&sender, &AssetRegistry::default())
}

/// The `(1, 1)` prover shape the builder cannot emit; every other supported
/// shape has at least [`SENDER_SLOT_COUNT`] outputs.
fn is_builder_reachable(shape: &Shape) -> bool {
    shape.n_outputs >= SENDER_SLOT_COUNT
}

/// Each builder-reachable shape: one real input padded up to the shape, signed,
/// with the padded input and output counts matching the declared dimensions.
#[test]
fn each_supported_shape_pads_and_signs() {
    for shape in SUPPORTED_SHAPES.iter().filter(|s| is_builder_reachable(s)) {
        let signed = sign_padded(*shape, 1)
            .unwrap_or_else(|e| panic!("shape {shape:?} should build and sign: {e:?}"));
        assert_eq!(signed.shape, *shape, "recorded shape for {shape:?}");
        assert_eq!(
            signed.inputs.len(),
            shape.n_inputs,
            "inputs padded to n_inputs for {shape:?}"
        );
        assert_eq!(
            signed.outputs.len(),
            shape.n_outputs,
            "outputs padded to n_outputs for {shape:?}"
        );
    }
}

/// Each builder-reachable shape built from `n_inputs` real inputs plus
/// `n_outputs - SENDER_SLOT_COUNT` real recipients resolves (undeclared) to
/// exactly that shape, exercising [`canonical_shape`]'s smallest-fit selection
/// and the real recipient-encoding path across shapes.
#[test]
fn canonical_shape_selects_smallest_fit_and_signs() {
    for shape in SUPPORTED_SHAPES.iter().filter(|s| is_builder_reachable(s)) {
        let sender = ShieldedKeypair::new().unwrap();
        let inputs = (0..shape.n_inputs)
            .map(|i| real_input(&sender, 1_000, (i + 1) as u8))
            .collect();
        let mut tx = Transaction::new(
            sender.shielded_address().unwrap(),
            inputs,
            Default::default(),
        );
        let recipients: Vec<ShieldedKeypair> = (0..shape.n_outputs - SENDER_SLOT_COUNT)
            .map(|_| ShieldedKeypair::new().unwrap())
            .collect();
        for recipient in &recipients {
            tx.send(&recipient.shielded_address().unwrap(), SOL_MINT, 10)
                .unwrap();
        }

        let signed = tx
            .sign(&sender, &AssetRegistry::default())
            .unwrap_or_else(|e| panic!("shape {shape:?} should build and sign: {e:?}"));
        assert_eq!(
            signed.shape, *shape,
            "canonical shape resolves to smallest fit for {shape:?}"
        );
        assert_eq!(signed.inputs.len(), shape.n_inputs);
        assert_eq!(signed.outputs.len(), shape.n_outputs);
    }
}

/// The `(1, 1)` shape is a real prover shape (`canonical_shape` names it for a
/// single-output request) but is unreachable through the builder: a lone-input
/// change-only transfer keeps both sender-change slots and resolves to `(1, 2)`,
/// and declaring `(1, 1)` explicitly is rejected because two outputs exceed it.
#[test]
fn one_by_one_shape_is_unreachable_through_builder() {
    assert_eq!(canonical_shape(1, 1).unwrap(), Shape::new(1, 1));

    let resolved = sign_padded(canonical_shape(1, 2).unwrap(), 1).expect("change-only transfer");
    assert_eq!(resolved.shape, Shape::new(1, 2));

    match sign_padded(Shape::new(1, 1), 1) {
        Err(TransactionError::TooManyOutputsForShape { got, max }) => {
            assert_eq!((got, max), (2, 1));
        }
        Err(other) => panic!("declaring (1, 1) rejected with wrong error: {other:?}"),
        Ok(_) => panic!("declaring (1, 1) must be rejected"),
    }
}
