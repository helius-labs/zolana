//! Measure instruction packet sizes for batch vs legacy builders.
//! Writes filled cells into CU_MATRIX.md. CU cells for full e2e paths that
//! already have BENCHMARK.md numbers are copied from those measured tables;
//! batch full-path CU stays blank until `just bench-batch-*` SBF runs.

use std::{fs, path::PathBuf};

use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::{AccountMeta, Instruction};
use solana_message::{v0, AddressLookupTableAccount, Message, VersionedMessage};
use solana_pubkey::Pubkey;
use solana_transaction::{versioned::VersionedTransaction, Transaction};
use zolana_interface::instruction::{
    BatchTransact, BatchUpdateNullifierTree, BatchUpdateNullifierTreeData,
    BatchUpdateNullifierTreeMany, ComposeTransact, CompressedProof, Transact, TransactIxData,
    TransactProof,
};
use zolana_interface::instruction::instruction_data::transact::CircuitId;

fn empty_transact() -> TransactIxData {
    TransactIxData {
        proof: TransactProof::zeroed(),
        expiry_unix_ts: u64::MAX,
        private_tx_hash: [1u8; 32],
        circuit: CircuitId::ConfidentialEddsa(2, 2, 3), // public asset slots = 3
        tx_viewing_pk: [2u8; 33],
        salt: [3u8; 16],
        inputs: vec![],
        interface_transfers: vec![],
        data_hash: None,
        zone_data_hash: None,
        outputs: vec![],
        messages: vec![],
    }
}

fn nullifier_update() -> BatchUpdateNullifierTreeData {
    BatchUpdateNullifierTreeData {
        new_root: [4u8; 32],
        old_root: [5u8; 32],
        zkp_batch_index: 0,
        compressed_proof: CompressedProof {
            a: [6u8; 32],
            b: [7u8; 64],
            c: [8u8; 32],
        },
    }
}

struct Sizes {
    data: usize,
    accounts: usize,
    legacy: usize,
    v0_alt: usize,
}

fn measure(ix: &Instruction, payer: &Pubkey) -> Sizes {
    let compute = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let message = Message::new(&[compute.clone(), ix.clone()], Some(payer));
    let legacy = bincode::serialize(&Transaction::new_unsigned(message))
        .expect("serialize legacy")
        .len();

    let alt = AddressLookupTableAccount {
        key: solana_address::Address::new_from_array([250u8; 32]),
        addresses: ix
            .accounts
            .iter()
            .filter(|meta| !meta.is_signer)
            .map(|meta| solana_address::Address::new_from_array(meta.pubkey.to_bytes()))
            .chain(std::iter::once(solana_address::Address::new_from_array(
                ix.program_id.to_bytes(),
            )))
            .collect(),
    };
    let v0_message = v0::Message::try_compile(
        payer,
        &[compute, ix.clone()],
        std::slice::from_ref(&alt),
        Default::default(),
    )
    .expect("compile v0");
    let versioned = VersionedMessage::V0(v0_message);
    let signature_count = versioned.header().num_required_signatures as usize;
    let tx = VersionedTransaction {
        signatures: vec![Default::default(); signature_count],
        message: versioned,
    };
    let v0_alt = bincode::serialize(&tx).expect("serialize v0").len();
    Sizes {
        data: ix.data.len(),
        accounts: ix.accounts.len(),
        legacy,
        v0_alt,
    }
}

fn cell(n: usize) -> String {
    n.to_string()
}

fn limit_for(bytes: usize) -> &'static str {
    if bytes <= 1232 {
        "1232"
    } else if bytes <= 4096 {
        "4096-sim"
    } else {
        "over"
    }
}

#[test]
fn measure_and_write_cu_matrix() {
    let payer = Pubkey::new_unique();
    let tree = Pubkey::new_unique();
    let foreign_vk = Pubkey::new_unique();
    let t = empty_transact();

    // --- SPP builders ---
    let transact_ix = Transact {
        payer,
        input_tree: tree,
        output_tree: tree,
        interface_transfer_accounts: vec![],
        data: t.clone(),
    }
    .instruction();
    let s_transact = measure(&transact_ix, &payer);

    let batch_n2 = BatchTransact {
        payer,
        input_tree: tree,
        output_tree: tree,
        signers: vec![],
        entries: vec![t.clone(), t.clone()],
    }
    .instruction();
    let s_batch2 = measure(&batch_n2, &payer);

    let batch_n4 = BatchTransact {
        payer,
        input_tree: tree,
        output_tree: tree,
        signers: vec![],
        entries: vec![t.clone(), t.clone(), t.clone(), t.clone()],
    }
    .instruction();
    let s_batch4 = measure(&batch_n4, &payer);

    let compose = ComposeTransact {
        foreign_vk,
        payer,
        input_tree: tree,
        output_tree: tree,
        signers: vec![],
        foreign_public_input: [9u8; 32],
        foreign_proof: TransactProof::zeroed(),
        transact: t.clone(),
    }
    .instruction();
    let s_compose = measure(&compose, &payer);

    let null_one = BatchUpdateNullifierTree {
        authority: payer,
        tree,
        reimbursement_recipient: payer,
        new_root: [1u8; 32],
        old_root: [2u8; 32],
        zkp_batch_index: 0,
        compressed_proof_a: [3u8; 32],
        compressed_proof_b: [4u8; 64],
        compressed_proof_c: [5u8; 32],
    }
    .instruction();
    let s_null1 = measure(&null_one, &payer);

    let null_many2 = BatchUpdateNullifierTreeMany {
        authority: payer,
        tree,
        reimbursement_recipient: payer,
        updates: vec![nullifier_update(), nullifier_update()],
    }
    .instruction();
    let s_null2 = measure(&null_many2, &payer);

    let null_many4 = BatchUpdateNullifierTreeMany {
        authority: payer,
        tree,
        reimbursement_recipient: payer,
        updates: vec![
            nullifier_update(),
            nullifier_update(),
            nullifier_update(),
            nullifier_update(),
        ],
    }
    .instruction();
    let s_null4 = measure(&null_many4, &payer);

    let null_many8 = BatchUpdateNullifierTreeMany {
        authority: payer,
        tree,
        reimbursement_recipient: payer,
        updates: (0..8).map(|_| nullifier_update()).collect(),
    }
    .instruction();
    let s_null8 = measure(&null_many8, &payer);

    let null_many16 = BatchUpdateNullifierTreeMany {
        authority: payer,
        tree,
        reimbursement_recipient: payer,
        updates: (0..16).map(|_| nullifier_update()).collect(),
    }
    .instruction();
    let s_null16 = measure(&null_many16, &payer);

    // Swap-like outer ix sizes: policy proof (128) + wincode(transact) + tag.
    // Mirror the make/take/cancel layout with dummy bodies for delta vs batch.
    let make_proof = [10u8; 128];
    let take_body = {
        let mut d = make_proof.to_vec();
        d.extend_from_slice(&t.serialize().unwrap());
        d
    };
    let make_legacy = Instruction {
        program_id: Pubkey::new_unique(),
        accounts: vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(payer, true),
            AccountMeta::new(tree, false),
            AccountMeta::new(tree, false),
            AccountMeta::new_readonly(Pubkey::default(), false),
            AccountMeta::new_readonly(Pubkey::new_unique(), false),
            AccountMeta::new_readonly(Pubkey::new_unique(), false),
        ],
        data: {
            let mut d = vec![2u8];
            d.extend_from_slice(&take_body);
            d
        },
    };
    let make_batch = Instruction {
        program_id: make_legacy.program_id,
        accounts: {
            let mut a = make_legacy.accounts.clone();
            a.insert(1, AccountMeta::new_readonly(foreign_vk, false));
            a
        },
        data: {
            let mut d = vec![6u8];
            d.extend_from_slice(&take_body);
            d
        },
    };
    let s_make = measure(&make_legacy, &payer);
    let s_make_b = measure(&make_batch, &payer);

    // Account-only delta from make-shaped legacy → batch (+foreign_vk).
    let d_leg = s_make_b.legacy.saturating_sub(s_make.legacy);
    let d_v0 = s_make_b.v0_alt.saturating_sub(s_make.v0_alt);

    // Legacy CU + sizes from committed BENCHMARK.md (mollusk, measured).
    // Batch app sizes = legacy + measured foreign_vk account delta.
    let make_b_l = 1124 + d_leg;
    let make_b_v = 1098 + d_v0;
    let take_b_l = 1056 + d_leg;
    let take_b_v = 999 + d_v0;
    let cancel_b_l = 871 + d_leg;
    let cancel_b_v = 814 + d_v0;
    let create_b_l = 1294 + d_leg;
    let create_b_v = 1175 + d_v0;
    let settle_b_l = 1221 + d_leg;
    let settle_b_v = 1071 + d_v0;
    let escrow_b_l = 1026 + d_leg;
    let escrow_b_v = 1000 + d_v0;
    let withdraw_b_l = 871 + d_leg;
    let withdraw_b_v = 814 + d_v0;

    let md = format!(
        r#"# BN254 batch verify — measured CU only

Every CU and byte cell comes from a measured run (mollusk `BENCHMARK.md` or this
test's builder serialization). **No invented CU.**

Packet limits: **1232** (today) and **4096** (SIMD-0296 size sim).

## Syscall pin

Agave `5134c411` — `program-runtime/src/execution_budget.rs` MSM / pairing_check costs.

## How cells were filled

| Column | Source |
| --- | --- |
| CU (legacy app) | Existing `just bench-*` mollusk tables |
| Bytes (forester / BatchTransact / Compose) | This test: full builder serialize |
| Bytes (app batch twins) | Legacy BENCHMARK size + measured +foreign_vk account delta |
| CU (batch full path) | blank until SBF dual benches with batch syscalls |
| take_ve batch | n/a (standard Groth16 only on batch rail) |

Account delta measured here: legacy_tx +{d_leg}, v0+ALT +{d_v0}.

## Table

| Use case | Incarnation | N | CU | Bytes legacy | Bytes v0+ALT | Limit |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| RFQ | legacy | 1 | 155148 | 959 | 964 | 1232 |
| Forester | legacy ×1 | 1 | | {null1_l} | {null1_v} | {null1_lim} |
| Forester | batch many | 2 | | {null2_l} | {null2_v} | {null2_lim} |
| Forester | batch many | 4 | | {null4_l} | {null4_v} | {null4_lim} |
| Forester | batch many | 8 | | {null8_l} | {null8_v} | {null8_lim} |
| Forester | batch many | 16 | | {null16_l} | {null16_v} | {null16_lim} |
| Transact | legacy | 1 | 155148 | 959 | 964 | 1232 |
| BatchTransact | batch | 2 | | {bt2_l} | {bt2_v} | {bt2_lim} |
| BatchTransact | batch | 4 | | {bt4_l} | {bt4_v} | {bt4_lim} |
| ComposeTransact | batch | 2 | | {co_l} | {co_v} | {co_lim} |
| Swap make | legacy | 2 | 258987 | 1124 | 1098 | 1232 |
| Swap make | batch | 2 | | {make_b_l} | {make_b_v} | {make_b_lim} |
| Swap take | legacy | 2 | 261268 | 1056 | 999 | 1232 |
| Swap take | batch | 2 | | {take_b_l} | {take_b_v} | {take_b_lim} |
| Swap cancel | legacy | 2 | 252641 | 871 | 814 | 1232 |
| Swap cancel | batch | 2 | | {cancel_b_l} | {cancel_b_v} | {cancel_b_lim} |
| Swap take_ve | legacy | 2 | 395782 | | | 1232 |
| Swap take_ve | batch | — | n/a | n/a | n/a | n/a |
| Create escrow | legacy | 2 | 271556 | 1294 | 1175 | 1232 |
| Create escrow | batch | 2 | | {create_b_l} | {create_b_v} | {create_b_lim} |
| Settle | legacy | 2 | 269638 | 1221 | 1071 | 1232 |
| Settle | batch | 2 | | {settle_b_l} | {settle_b_v} | {settle_b_lim} |
| Escrow | legacy | 2 | 257763 | 1026 | 1000 | 1232 |
| Escrow | batch | 2 | | {escrow_b_l} | {escrow_b_v} | {escrow_b_lim} |
| Withdraw | legacy | 2 | 252567 | 871 | 814 | 1232 |
| Withdraw | batch | 2 | | {withdraw_b_l} | {withdraw_b_v} | {withdraw_b_lim} |

### Builder size detail (empty pure-shielded body; relative deltas hold)

| Builder | Ix data | Accounts | Legacy tx | v0+ALT |
| --- | ---: | ---: | ---: | ---: |
| Transact | {tr_d} | {tr_a} | {tr_l} | {tr_v} |
| BatchTransact N=2 | {bt2_d} | {bt2_a} | {bt2_l} | {bt2_v} |
| BatchTransact N=4 | {bt4_d} | {bt4_a} | {bt4_l} | {bt4_v} |
| ComposeTransact | {co_d} | {co_a} | {co_l} | {co_v} |
| NullifierTree ×1 | {null1_d} | {null1_a} | {null1_l} | {null1_v} |
| NullifierTreeMany N=2 | {null2_d} | {null2_a} | {null2_l} | {null2_v} |
| NullifierTreeMany N=4 | {null4_d} | {null4_a} | {null4_l} | {null4_v} |
| NullifierTreeMany N=8 | {null8_d} | {null8_a} | {null8_l} | {null8_v} |
| NullifierTreeMany N=16 | {null16_d} | {null16_a} | {null16_l} | {null16_v} |
| Swap make-shaped legacy | {mk_d} | {mk_a} | {mk_l} | {mk_v} |
| Swap make-shaped batch | {mkb_d} | {mkb_a} | {mkb_l} | {mkb_v} |

Regenerate: `cargo test -p zolana-groth16-batch --test matrix_measure -- --nocapture`
"#,
        null1_l = cell(s_null1.legacy),
        null1_v = cell(s_null1.v0_alt),
        null1_lim = limit_for(s_null1.legacy.min(s_null1.v0_alt)),
        null2_l = cell(s_null2.legacy),
        null2_v = cell(s_null2.v0_alt),
        null2_lim = limit_for(s_null2.legacy.min(s_null2.v0_alt)),
        null4_l = cell(s_null4.legacy),
        null4_v = cell(s_null4.v0_alt),
        null4_lim = limit_for(s_null4.legacy.min(s_null4.v0_alt)),
        null8_l = cell(s_null8.legacy),
        null8_v = cell(s_null8.v0_alt),
        null8_lim = limit_for(s_null8.v0_alt),
        null16_l = cell(s_null16.legacy),
        null16_v = cell(s_null16.v0_alt),
        null16_lim = limit_for(s_null16.v0_alt),
        tr_l = cell(s_transact.legacy),
        tr_v = cell(s_transact.v0_alt),
        tr_d = cell(s_transact.data),
        tr_a = cell(s_transact.accounts),
        bt2_l = cell(s_batch2.legacy),
        bt2_v = cell(s_batch2.v0_alt),
        bt2_lim = limit_for(s_batch2.v0_alt),
        bt2_d = cell(s_batch2.data),
        bt2_a = cell(s_batch2.accounts),
        bt4_l = cell(s_batch4.legacy),
        bt4_v = cell(s_batch4.v0_alt),
        bt4_lim = limit_for(s_batch4.v0_alt),
        bt4_d = cell(s_batch4.data),
        bt4_a = cell(s_batch4.accounts),
        co_l = cell(s_compose.legacy),
        co_v = cell(s_compose.v0_alt),
        co_lim = limit_for(s_compose.legacy.min(s_compose.v0_alt)),
        co_d = cell(s_compose.data),
        co_a = cell(s_compose.accounts),
        null1_d = cell(s_null1.data),
        null1_a = cell(s_null1.accounts),
        null2_d = cell(s_null2.data),
        null2_a = cell(s_null2.accounts),
        null4_d = cell(s_null4.data),
        null4_a = cell(s_null4.accounts),
        null8_d = cell(s_null8.data),
        null8_a = cell(s_null8.accounts),
        null16_d = cell(s_null16.data),
        null16_a = cell(s_null16.accounts),
        mk_d = cell(s_make.data),
        mk_a = cell(s_make.accounts),
        mk_l = cell(s_make.legacy),
        mk_v = cell(s_make.v0_alt),
        mkb_d = cell(s_make_b.data),
        mkb_a = cell(s_make_b.accounts),
        mkb_l = cell(s_make_b.legacy),
        mkb_v = cell(s_make_b.v0_alt),
        make_b_l = cell(make_b_l),
        make_b_v = cell(make_b_v),
        make_b_lim = limit_for(make_b_v),
        take_b_l = cell(take_b_l),
        take_b_v = cell(take_b_v),
        take_b_lim = limit_for(take_b_v),
        cancel_b_l = cell(cancel_b_l),
        cancel_b_v = cell(cancel_b_v),
        cancel_b_lim = limit_for(cancel_b_v),
        create_b_l = cell(create_b_l),
        create_b_v = cell(create_b_v),
        create_b_lim = limit_for(create_b_v),
        settle_b_l = cell(settle_b_l),
        settle_b_v = cell(settle_b_v),
        settle_b_lim = limit_for(settle_b_v),
        escrow_b_l = cell(escrow_b_l),
        escrow_b_v = cell(escrow_b_v),
        escrow_b_lim = limit_for(escrow_b_v),
        withdraw_b_l = cell(withdraw_b_l),
        withdraw_b_v = cell(withdraw_b_v),
        withdraw_b_lim = limit_for(withdraw_b_v),
        d_leg = d_leg,
        d_v0 = d_v0,
    );

    let out = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("CU_MATRIX.md");
    fs::write(&out, md).expect("write CU_MATRIX.md");
    println!("wrote {}", out.display());
    println!(
        "nullifier many N=2 legacy={} v0={} | N=16 legacy={} v0={}",
        s_null2.legacy, s_null2.v0_alt, s_null16.legacy, s_null16.v0_alt
    );
    println!(
        "batch_transact N=2 legacy={} v0={} | N=4 legacy={} v0={}",
        s_batch2.legacy, s_batch2.v0_alt, s_batch4.legacy, s_batch4.v0_alt
    );
    println!(
        "make-shaped legacy v0={} batch v0={} (delta accounts +1)",
        s_make.v0_alt, s_make_b.v0_alt
    );
}
