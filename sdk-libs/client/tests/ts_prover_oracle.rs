//! Rust-side oracle for the TypeScript prover-assembly parity tests.
//!
//! `sdk-libs/ts/fixtures/client/prover-shapes-v1.json` already pins twenty
//! single-rail shapes, but every one of them is built the same way: one real
//! input in slot 0, trailing dummies, SOL-only public amounts. That leaves the
//! branches where the two languages could most plausibly disagree untested --
//! the SPL asset field, a dummy sitting between two real inputs, and a
//! transaction whose real inputs are owned by keys on different signature
//! schemes.
//!
//! This test builds those cases through the production `assemble` and writes the
//! result to `sdk-libs/ts/client/test/oracles/prover-edge-cases-v1.json`, which
//! `sdk-libs/ts/client/test/vectors/prover-edge-cases.test.ts` reproduces from
//! the same seeds. Regenerate with
//! `ZOLANA_UPDATE_TS_ORACLES=1 cargo test -p zolana-client --test ts_prover_oracle`.
//!
//! Run with: `cargo test -p zolana-client --test ts_prover_oracle`

use std::path::PathBuf;

use serde_json::{json, Value};
use solana_address::Address;
use zolana_client::{
    assemble, MerkleContext, MerkleProof, NonInclusionProof, ProverInputs, SpendProof,
};
use zolana_interface::instruction::instruction_data::transact::{
    OwnerTag, TransactOutput, TransactProof,
};
use zolana_keypair::{
    NullifierKey, PublicKey, ShieldedKeypair, SigningKey, ViewingKey,
};
use zolana_transaction::{
    derive_blinding,
    instructions::{
        transact::{ExternalData, SppProofInputs, SppProofOutputUtxo},
        types::SppProofInputUtxo,
    },
    Data, Utxo, SOL_MINT,
};

/// Shared with `sdk-libs/ts/client/test/helpers/prover-vectors.ts`; the two
/// languages must derive identical key material from them.
const P256_SECRET: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7,
];
const ED25519_SECRET: [u8; 32] = [31; 32];
const VIEWING_SEED: [u8; 32] = [32; 32];
const BLINDING_SEED: [u8; 31] = [33; 31];
const SPL_MINT: [u8; 32] = [9; 32];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn field_byte(value: u8) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[31] = value;
    bytes
}

fn keypair(p256: bool) -> ShieldedKeypair {
    let signing = if p256 {
        SigningKey::from_bytes(&P256_SECRET).expect("p256 signing key")
    } else {
        SigningKey::from_ed25519(&ED25519_SECRET)
    };
    ShieldedKeypair::from_keys(
        signing,
        ViewingKey::from_seed(&VIEWING_SEED, u32::from(p256)).expect("viewing key"),
    )
    .expect("shielded keypair")
}

fn real_input(keypair: &ShieldedKeypair, asset: Address, position: u8) -> SppProofInputUtxo {
    SppProofInputUtxo::new(
        Utxo {
            owner: keypair.signing_pubkey(),
            asset,
            amount: 100,
            blinding: derive_blinding(&BLINDING_SEED, position),
            zone_program_id: None,
            data: Data::default(),
        },
        keypair,
    )
}

fn dummy_input(position: u8) -> SppProofInputUtxo {
    SppProofInputUtxo {
        utxo: Utxo {
            owner: PublicKey::zeroed(),
            asset: SOL_MINT,
            amount: 0,
            blinding: derive_blinding(&BLINDING_SEED, position),
            zone_program_id: None,
            data: Data::default(),
        },
        nullifier_key: NullifierKey::from_secret([0; 31]),
        data_hash: None,
        zone_data_hash: None,
    }
}

fn real_output(keypair: &ShieldedKeypair, asset: Address, position: u8) -> SppProofOutputUtxo {
    SppProofOutputUtxo {
        owner_address: Some(keypair.shielded_address().expect("shielded address")),
        owner_tag: Some(
            keypair
                .signing_pubkey()
                .confidential_view_tag()
                .expect("view tag"),
        ),
        asset,
        amount: 100,
        blinding: derive_blinding(&BLINDING_SEED, position),
        ..Default::default()
    }
}

fn dummy_output(position: u8) -> SppProofOutputUtxo {
    SppProofOutputUtxo {
        blinding: derive_blinding(&BLINDING_SEED, position),
        owner_tag: Some([position; 32]),
        ..Default::default()
    }
}

/// The payer hash the TypeScript helper produces: sha256 of 32 `44` bytes with
/// the leading byte cleared so the value is a BN254 field element.
fn payer() -> Address {
    Address::new_from_array([44; 32])
}

struct Case {
    name: &'static str,
    inputs: Vec<SppProofInputUtxo>,
    outputs: Vec<SppProofOutputUtxo>,
    /// `Some(asset)` withdraws 5 of an SPL asset, `None` withdraws 5 lamports.
    spl_withdrawal: Option<Address>,
    /// Sign with the P256 keypair (the transaction carries a P256-owned input).
    p256: bool,
}

fn external_data(case: &Case) -> ExternalData {
    let resolved_tags = case
        .outputs
        .iter()
        .map(|output| output.owner_tag.expect("oracle output owner tag"))
        .collect::<Vec<_>>();
    let wire_outputs = case
        .outputs
        .iter()
        .zip(&resolved_tags)
        .map(|(output, tag)| TransactOutput {
            utxo_hash: output.hash().expect("output hash"),
            owner_tag: OwnerTag::Inline(*tag),
            data: Some(vec![1, 2, 3]),
        })
        .collect::<Vec<_>>();
    let external = ExternalData::new([41; 33], [42; 16], wire_outputs, resolved_tags, vec![]);
    match case.spl_withdrawal {
        Some(asset) => external
            .with_public_spl(-5, asset, Address::new_from_array([8; 32]))
            .expect("public spl leg"),
        None => external
            .with_public_sol(-5, Address::new_from_array([43; 32]))
            .expect("public sol leg"),
    }
}

fn spend_proofs(inputs: &SppProofInputs) -> Vec<SpendProof> {
    let tree = Address::new_from_array([45; 32]);
    inputs
        .input_utxo_hashes()
        .expect("input contexts")
        .iter()
        .enumerate()
        .map(|(index, context)| SpendProof {
            state: MerkleProof {
                leaf: context.utxo_hash,
                merkle_context: MerkleContext { tree_type: 1, tree },
                path: vec![field_byte(46 + index as u8); 32],
                leaf_index: index as u64,
                root: field_byte(47),
                root_seq: 48,
                root_index: 49 + index as u16,
            },
            nullifier: NonInclusionProof {
                leaf: context.nullifier,
                merkle_context: MerkleContext { tree_type: 2, tree },
                path: vec![field_byte(50 + index as u8); 40],
                low_element: field_byte(51),
                low_element_index: 0,
                high_element: field_byte(52),
                high_element_index: 1,
                root: field_byte(53),
                root_seq: 54,
                root_index: 55 + index as u16,
            },
        })
        .collect()
}

fn cases() -> Vec<Case> {
    let eddsa = keypair(false);
    let p256 = keypair(true);
    let spl = Address::new_from_array(SPL_MINT);
    vec![
        // The one branch of `public_amounts` the shape fixture never reaches:
        // a nonzero public SPL leg, which makes `public_spl_asset_pubkey` the
        // hash of an asset the client has to find by scanning the transaction.
        Case {
            name: "eddsa-public-spl-2-3",
            inputs: vec![real_input(&eddsa, spl, 0), dummy_input(1)],
            outputs: vec![
                real_output(&eddsa, spl, 64),
                dummy_output(65),
                dummy_output(66),
            ],
            spl_withdrawal: Some(spl),
            p256: false,
        },
        // A dummy between two real inputs on different rails. The per-slot
        // signer index, the dummy's mirrored roots, and the per-input owner
        // field all take their non-trivial branch here.
        Case {
            name: "mixed-interior-dummy-eddsa-first-3-3",
            inputs: vec![
                real_input(&eddsa, SOL_MINT, 0),
                dummy_input(1),
                real_input(&p256, SOL_MINT, 2),
            ],
            outputs: vec![
                real_output(&p256, SOL_MINT, 64),
                dummy_output(65),
                dummy_output(66),
            ],
            spl_withdrawal: None,
            p256: true,
        },
        // The same shape with the rails swapped, so the inherited dummy signer
        // is the P256 sentinel rather than the ed25519 default.
        Case {
            name: "mixed-interior-dummy-p256-first-3-3",
            inputs: vec![
                real_input(&p256, SOL_MINT, 0),
                dummy_input(1),
                real_input(&eddsa, SOL_MINT, 2),
            ],
            outputs: vec![
                real_output(&p256, SOL_MINT, 64),
                dummy_output(65),
                dummy_output(66),
            ],
            spl_withdrawal: None,
            p256: true,
        },
        // Two real P256 inputs under one signature, with the SPL leg on top, so
        // the shared signing field is written into two input slots at once.
        Case {
            name: "p256-two-real-inputs-public-spl-2-2",
            inputs: vec![real_input(&p256, spl, 0), real_input(&p256, spl, 3)],
            outputs: vec![real_output(&p256, spl, 64), dummy_output(65)],
            spl_withdrawal: Some(spl),
            p256: true,
        },
    ]
}

fn case_json(case: &Case) -> Value {
    let signer = keypair(case.p256);
    let external = external_data(case);
    let mut proof_inputs = SppProofInputs::new(
        case.inputs.clone(),
        case.outputs.clone(),
        external,
        payer(),
    );
    if case.p256 {
        proof_inputs.sign_p256(&signer).expect("p256 signature");
    }
    let proofs = spend_proofs(&proof_inputs);
    let assembled = assemble(proof_inputs.clone(), &proofs).expect("assemble oracle case");
    let ix = assemble(proof_inputs, &proofs)
        .expect("assemble oracle case")
        .with_proof(TransactProof::zeroed_eddsa());

    json!({
        "name": case.name,
        "publicInputHashBytes": hex(&assembled.public_input_hash),
        "proverInputs": prover_inputs_json(&assembled.prover_inputs),
        "eddsaSignerIndexes": ix.inputs.iter().map(|input| input.eddsa_signer_index).collect::<Vec<_>>(),
        "nullifierBytes": ix.inputs.iter().map(|input| hex(&input.nullifier_hash)).collect::<Vec<_>>(),
        "rootIndexes": ix
            .inputs
            .iter()
            .map(|input| json!([input.utxo_tree_root_index, input.nullifier_tree_root_index]))
            .collect::<Vec<_>>(),
        "transactIxBytes": hex(&ix.serialize().expect("serialize transact instruction data")),
    })
}

fn prover_inputs_json(inputs: &ProverInputs) -> Value {
    match inputs {
        ProverInputs::Eddsa(value) => json!({
            "rail": "eddsa",
            "inputs": value.inputs.iter().map(transfer_input_json).collect::<Vec<_>>(),
            "outputs": value.outputs.iter().map(transfer_output_json).collect::<Vec<_>>(),
            "externalDataHash": value.external_data_hash.to_string(),
            "privateTxHash": value.private_tx_hash.to_string(),
            "publicInputHash": value.public_input_hash.to_string(),
            "publicSolAmount": value.public_sol_amount.to_string(),
            "publicSplAmount": value.public_spl_amount.to_string(),
            "publicSplAssetPubkey": value.public_spl_asset_pubkey.to_string(),
            "zoneProgramId": value.zone_program_id.to_string(),
            "payerPubkeyHash": value.payer_pubkey_hash.to_string()
        }),
        ProverInputs::P256(value) => json!({
            "rail": "p256",
            "inputs": value.inputs.iter().map(transfer_input_json).collect::<Vec<_>>(),
            "outputs": value.outputs.iter().map(transfer_output_json).collect::<Vec<_>>(),
            "externalDataHash": value.external_data_hash.to_string(),
            "privateTxHash": value.private_tx_hash.to_string(),
            "publicInputHash": value.public_input_hash.to_string(),
            "p256PubX": value.p256_pub_x.to_string(),
            "p256PubY": value.p256_pub_y.to_string(),
            "p256SigR": value.p256_sig_r.to_string(),
            "p256SigS": value.p256_sig_s.to_string(),
            "p256MessageHashLow": value.p256_message_hash_low.to_string(),
            "p256MessageHashHigh": value.p256_message_hash_high.to_string(),
            "p256SigningPkField": value.p256_signing_pk_field.to_string(),
            "publicSolAmount": value.public_sol_amount.to_string(),
            "publicSplAmount": value.public_spl_amount.to_string(),
            "publicSplAssetPubkey": value.public_spl_asset_pubkey.to_string(),
            "zoneProgramId": value.zone_program_id.to_string(),
            "payerPubkeyHash": value.payer_pubkey_hash.to_string()
        }),
    }
}

fn transfer_input_json(input: &zolana_client::TransferInput) -> Value {
    json!({
        "isDummy": input.is_dummy.to_string(),
        "statePathElements": input.state_path_elements.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "statePathIndex": input.state_path_index.to_string(),
        "nullifierLowValue": input.nullifier_low_value.to_string(),
        "nullifierNextValue": input.nullifier_next_value.to_string(),
        "nullifierLowPathElements": input.nullifier_low_path_elements.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "nullifierLowPathIndex": input.nullifier_low_path_index.to_string(),
        "utxoTreeRoot": input.utxo_tree_root.to_string(),
        "nullifierTreeRoot": input.nullifier_tree_root.to_string(),
        "nullifier": input.nullifier.to_string(),
        "ownerPkHash": input.owner_pk_hash.to_string(),
        "nullifierSecret": input.nullifier_secret.to_string(),
        "utxo": proof_utxo_json(&input.utxo)
    })
}

fn transfer_output_json(output: &zolana_client::TransferOutput) -> Value {
    json!({
        "isDummy": output.is_dummy.to_string(),
        "hash": output.hash.to_string(),
        "ownerPkHash": output.owner_pk_hash.to_string(),
        "nullifierPk": output.nullifier_pk.to_string(),
        "utxo": proof_utxo_json(&output.utxo)
    })
}

fn proof_utxo_json(utxo: &zolana_transaction::ProofInputUtxo) -> Value {
    json!({
        "domainBytes": hex(&utxo.domain),
        "ownerHashBytes": hex(&utxo.owner_hash),
        "assetBytes": hex(&utxo.asset),
        "amountBytes": hex(&utxo.amount),
        "blindingBytes": hex(&utxo.blinding),
        "dataHashBytes": hex(&utxo.data_hash),
        "zoneDataHashBytes": hex(&utxo.zone_data_hash),
        "zoneProgramIdBytes": hex(&utxo.zone_program_id)
    })
}

fn oracle_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../ts/client/test/oracles/prover-edge-cases-v1.json")
}

#[test]
fn ts_prover_edge_case_oracle_is_current() {
    let oracle = json!({
        "inputs": {
            "blindingSeedBytes": hex(&BLINDING_SEED),
            "ed25519SecretBytes": hex(&ED25519_SECRET),
            "p256SecretBytes": hex(&P256_SECRET),
            "splMintBytes": hex(&SPL_MINT),
            "testOnlySecret": true,
            "viewingSeedBytes": hex(&VIEWING_SEED)
        },
        "expected": {"cases": cases().iter().map(case_json).collect::<Vec<_>>()}
    });
    let rendered = format!("{}\n", serde_json::to_string_pretty(&oracle).expect("render"));

    let path = oracle_path();
    let current = std::fs::read_to_string(&path).unwrap_or_default();
    if current == rendered {
        return;
    }
    std::fs::create_dir_all(path.parent().expect("oracle directory")).expect("create oracle dir");
    std::fs::write(&path, &rendered).expect("write oracle");
    assert!(
        std::env::var_os("ZOLANA_UPDATE_TS_ORACLES").is_some(),
        "{} was stale and has been rewritten; commit it",
        path.display()
    );
}
