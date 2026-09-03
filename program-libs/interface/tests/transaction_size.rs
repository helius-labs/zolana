//! What actually fits a transaction, per shape.
//!
//! The large consolidation shape exists because transaction v1 raises the limit
//! to 4 KB. That headroom is not generous: the shape was sized against a custom
//! ring carrying its own accounts, data and a second signer, which is the
//! tightest consumer. Pin both directions here, so neither a shape change nor a
//! ciphertext-length change can quietly push it over without a failing test.
//!
//! `cargo run -p xtask -- max-shape [OUTPUT_DATA_LEN]` searches the same space
//! interactively.

use solana_hash::Hash;
use solana_instruction::{AccountMeta, Instruction};
use solana_message::v1;
use solana_pubkey::Pubkey;
use zolana_interface::instruction::instruction_data::merge_transact::MERGE_SUPPORTED_INPUT_COUNTS;
use zolana_interface::instruction::instruction_data::transact::CircuitId;
use zolana_interface::instruction::{
    tag, InputUtxo, OwnerTag, TransactIxBound, TransactIxData, TransactIxTail, TransactOutput,
    TransactProof,
};
use zolana_interface::shape::Shape;
use zolana_interface::{N_PUBLIC_SLOTS, SHIELDED_POOL_PROGRAM_ID};

/// Today's recipient ciphertext. The spec-target encoding is smaller (48 B), so
/// budgeting against this is the conservative choice: a shape that fits here
/// keeps fitting when ciphertexts shrink.
const RECIPIENT_CIPHERTEXT_LEN: usize = 131;

/// A custom ring adds a signing ring config, the ring program's own id, its own
/// accounts, and its own instruction data on top of a bare `transact`.
const CUSTOM_RING_EXTRA_ACCOUNTS: usize = 6;
const CUSTOM_RING_EXTRA_DATA: usize = 256;

fn ix_data(n_in: usize, n_out: usize, output_data_len: usize) -> Vec<u8> {
    let data = TransactIxData {
        bound: TransactIxBound {
            expiry_unix_ts: u64::MAX,
            tx_viewing_pk: [0u8; 33],
            salt: [0u8; 16],
            interface_transfers: Vec::new(),
            outputs: (0..n_out)
                .map(|_| TransactOutput {
                    utxo_hash: [0u8; 32],
                    owner_tag: OwnerTag::Inline([0u8; 32]),
                    data: (output_data_len > 0).then(|| vec![0u8; output_data_len]),
                })
                .collect(),
            messages: Vec::new(),
        },
        tail: TransactIxTail {
            circuit: CircuitId::ConfidentialEddsa(n_in as u8, n_out as u8, N_PUBLIC_SLOTS as u8),
            proof: TransactProof {
                a: [0u8; 32],
                b: [0u8; 64],
                c: [0u8; 32],
            },
            private_tx_hash: [0u8; 32],
            inputs: (0..n_in)
                .map(|_| InputUtxo {
                    nullifier_hash: [0u8; 32],
                    nullifier_tree_root_index: 0,
                    utxo_tree_root_index: 0,
                })
                .collect(),
            data_hash: None,
            ring_data_hash: None,
        },
    };
    let mut bytes = vec![tag::TRANSACT];
    bytes.extend_from_slice(&data.serialize().expect("serialize transact ix data"));
    bytes
}

/// Serialized v1 transaction size and address count, or `None` if it does not
/// fit either v1 limit.
fn v1_fit(
    n_in: usize,
    n_out: usize,
    output_data_len: usize,
    extra_accounts: usize,
    extra_data: usize,
    signatures: usize,
) -> Option<(usize, usize)> {
    let payer = Pubkey::new_unique();
    // payer, input tree, output tree, pool, system, then one nullifier PDA per
    // input, then whatever the rail adds.
    let mut metas = vec![
        AccountMeta::new(payer, true),
        AccountMeta::new(Pubkey::new_unique(), false),
        AccountMeta::new(Pubkey::new_unique(), false),
        AccountMeta::new_readonly(Pubkey::from(SHIELDED_POOL_PROGRAM_ID), false),
        AccountMeta::new_readonly(Pubkey::default(), false),
    ];
    for _ in 0..n_in + extra_accounts {
        metas.push(AccountMeta::new(Pubkey::new_unique(), false));
    }
    let mut data = ix_data(n_in, n_out, output_data_len);
    data.extend(std::iter::repeat_n(0u8, extra_data));

    let message = v1::Message::try_compile(
        &payer,
        &[Instruction {
            program_id: Pubkey::from(SHIELDED_POOL_PROGRAM_ID),
            accounts: metas,
            data,
        }],
        Hash::default(),
    )
    .ok()?;
    // version prefix byte + compact signature count + 64 bytes per signature
    let total = message.size() + 1 + 1 + 64 * signatures;
    let addresses = message.account_keys.len();
    (total <= v1::MAX_TRANSACTION_SIZE && addresses <= usize::from(v1::MAX_ADDRESSES))
        .then_some((total, addresses))
}

/// The consolidation shape must fit the tightest path it is meant to serve, and
/// the next size up must not -- otherwise the shape was chosen with slack that
/// nobody measured.
#[test]
fn the_consolidation_shape_fits_a_custom_ring_and_the_next_size_does_not() {
    let n_in = Shape::IN36_OUT2.n_inputs();
    let n_out = Shape::IN36_OUT2.n_outputs();

    let (bytes, addresses) = v1_fit(
        n_in,
        n_out,
        RECIPIENT_CIPHERTEXT_LEN,
        CUSTOM_RING_EXTRA_ACCOUNTS,
        CUSTOM_RING_EXTRA_DATA,
        2,
    )
    .expect("the consolidation shape must fit a two-signer custom ring");
    assert!(
        bytes <= v1::MAX_TRANSACTION_SIZE,
        "{bytes} bytes exceeds the v1 limit"
    );
    assert!(
        addresses <= usize::from(v1::MAX_ADDRESSES),
        "{addresses} addresses exceeds the v1 limit"
    );

    // The measured ceiling on this path is 38 inputs, so the chosen shape keeps
    // two inputs of headroom. Pin the ceiling itself: if 39 ever fits, something
    // shrank and the shape can be revisited; if 38 stops fitting, the headroom
    // is gone and the shape is now marginal.
    const MEASURED_CEILING: usize = 38;
    assert!(
        n_in < MEASURED_CEILING,
        "the chosen shape should keep headroom below the ceiling"
    );
    assert!(
        v1_fit(
            MEASURED_CEILING,
            n_out,
            RECIPIENT_CIPHERTEXT_LEN,
            CUSTOM_RING_EXTRA_ACCOUNTS,
            CUSTOM_RING_EXTRA_DATA,
            2,
        )
        .is_some(),
        "{MEASURED_CEILING} inputs should still fit; the headroom has shrunk"
    );
    assert!(
        v1_fit(
            MEASURED_CEILING + 1,
            n_out,
            RECIPIENT_CIPHERTEXT_LEN,
            CUSTOM_RING_EXTRA_ACCOUNTS,
            CUSTOM_RING_EXTRA_DATA,
            2,
        )
        .is_none(),
        "{} inputs unexpectedly fits; re-measure the ceiling",
        MEASURED_CEILING + 1
    );
}

/// Legacy and v0 cap at 1232 bytes, and this shape's instruction data alone
/// exceeds that. An address lookup table cannot rescue it, so v1 is not a
/// preference here, it is the only format that works.
#[test]
fn the_consolidation_shape_cannot_be_sent_as_a_legacy_transaction() {
    const PACKET_DATA_SIZE: usize = 1232;
    let data = ix_data(
        Shape::IN36_OUT2.n_inputs(),
        Shape::IN36_OUT2.n_outputs(),
        RECIPIENT_CIPHERTEXT_LEN,
    );
    assert!(
        data.len() > PACKET_DATA_SIZE,
        "instruction data is {} bytes; if it now fits a legacy packet the v1 \
         requirement should be re-examined",
        data.len()
    );
}

/// Serialized v1 transaction size and address count for a merge, or `None` if
/// it does not fit either v1 limit.
///
/// Unlike the transact helper this builds the real instruction through the
/// builders, so the `merge_ring` rows count the extra `ring_config` account, the
/// ring program's own address, and the 32-byte `output_ring_data_hash` rather
/// than modelling them. Every large-shape transaction carries a compute budget
/// instruction, so it is inside the budget here.
fn merge_v1_fit(
    ring: bool,
    n_in: usize,
    extra_accounts: usize,
    extra_data: usize,
    signatures: usize,
) -> Option<(usize, usize)> {
    use zolana_interface::instruction::{
        builders::{MergeRing, MergeTransact},
        instruction_data::merge_transact::MergeProof,
        MergeTransactIxData,
    };

    let payer = Pubkey::new_unique();
    let input_tree = Pubkey::new_unique();
    let data = MergeTransactIxData {
        expiry_unix_ts: u64::MAX,
        proof: MergeProof::zeroed(),
        output_utxo_hash: [0u8; 32],
        eddsa_owner: false,
        private_tx_hash: [0u8; 32],
        nullifiers: (0..n_in).map(|i| [i as u8; 32]).collect(),
        utxo_tree_root_index: vec![0; n_in],
        nullifier_tree_root_index: vec![0; n_in],
    };
    let mut instruction = if ring {
        MergeRing {
            input_tree,
            output_tree: Pubkey::new_unique(),
            ring_program_id: Pubkey::new_unique(),
            payer,
            data,
            output_ring_data_hash: [0u8; 32],
        }
        .instruction()
    } else {
        MergeTransact {
            input_tree,
            output_tree: Pubkey::new_unique(),
            payer,
            user_record: Pubkey::new_unique(),
            data,
        }
        .instruction()
    };
    for _ in 0..extra_accounts {
        instruction
            .accounts
            .push(AccountMeta::new(Pubkey::new_unique(), false));
    }
    instruction
        .data
        .extend(std::iter::repeat_n(0u8, extra_data));

    let compute_budget = Instruction {
        program_id: Pubkey::from_str_const("ComputeBudget111111111111111111111111111111"),
        accounts: Vec::new(),
        data: [vec![2u8], 1_400_000u32.to_le_bytes().to_vec()].concat(),
    };
    let message =
        v1::Message::try_compile(&payer, &[compute_budget, instruction], Hash::default()).ok()?;
    let total = message.size() + 1 + 1 + 64 * signatures;
    let addresses = message.account_keys.len();
    (total <= v1::MAX_TRANSACTION_SIZE && addresses <= usize::from(v1::MAX_ADDRESSES))
        .then_some((total, addresses))
}

/// The large merge shape is sized against `merge_ring` under a custom ring with
/// a second signer, which is the tightest merge path, and it must keep headroom
/// below the measured ceiling there.
#[test]
fn the_large_merge_shape_fits_a_custom_ring_and_the_next_size_does_not() {
    const LARGE_MERGE_INPUTS: usize = 36;
    // Measured ceiling on the tightest merge path. Pinning it both ways means a
    // layout change that eats the headroom fails here rather than in the field.
    // Merge sits higher than transact's 38 because it has one output and carries
    // no recipient ciphertext.
    const MEASURED_CEILING: usize = 42;

    assert!(
        MERGE_SUPPORTED_INPUT_COUNTS.contains(&LARGE_MERGE_INPUTS),
        "the large merge shape must be a supported input count"
    );
    let (bytes, addresses) = merge_v1_fit(
        true,
        LARGE_MERGE_INPUTS,
        CUSTOM_RING_EXTRA_ACCOUNTS,
        CUSTOM_RING_EXTRA_DATA,
        2,
    )
    .expect("the large merge shape must fit a two-signer custom ring");
    assert!(
        bytes <= v1::MAX_TRANSACTION_SIZE,
        "{bytes} bytes exceeds the v1 limit"
    );
    assert!(
        addresses <= usize::from(v1::MAX_ADDRESSES),
        "{addresses} addresses exceeds the v1 limit"
    );
    const {
        assert!(
            LARGE_MERGE_INPUTS < MEASURED_CEILING,
            "the chosen shape should keep headroom below the ceiling"
        )
    };
    assert!(
        merge_v1_fit(
            true,
            MEASURED_CEILING,
            CUSTOM_RING_EXTRA_ACCOUNTS,
            CUSTOM_RING_EXTRA_DATA,
            2,
        )
        .is_some(),
        "{MEASURED_CEILING} inputs should still fit; the headroom has shrunk"
    );
    assert!(
        merge_v1_fit(
            true,
            MEASURED_CEILING + 1,
            CUSTOM_RING_EXTRA_ACCOUNTS,
            CUSTOM_RING_EXTRA_DATA,
            2,
        )
        .is_none(),
        "{} inputs unexpectedly fits; re-measure the ceiling",
        MEASURED_CEILING + 1
    );
}

/// Every supported merge shape must fit the plain `merge_transact` rail too, not
/// just the ring rail it was sized against.
#[test]
fn every_supported_merge_shape_fits_a_plain_merge() {
    for n_in in MERGE_SUPPORTED_INPUT_COUNTS {
        assert!(
            merge_v1_fit(false, n_in, 0, 0, 1).is_some(),
            "{n_in}-input merge does not fit a plain merge_transact"
        );
    }
}

/// Every automatic shape stays comfortably inside a plain transact, so nothing
/// in the default path depends on v1.
#[test]
fn the_automatic_shapes_still_fit_a_legacy_sized_budget() {
    const PACKET_DATA_SIZE: usize = 1232;
    for shape in zolana_interface::shape::SPP_AUTO_SHAPES {
        let data = ix_data(shape.n_inputs(), shape.n_outputs(), 0);
        assert!(
            data.len() <= PACKET_DATA_SIZE,
            "{}x{} instruction data is {} bytes",
            shape.n_inputs(),
            shape.n_outputs(),
            data.len()
        );
    }
}
