//! Rust-side oracle for the TypeScript zone prover parity tests (rows C13, C14,
//! and C18).
//!
//! The three zone rails differ from the confidential rails in two places only,
//! and both are silent when wrong. They drop the confidential appendix, so the
//! public-input preimage is shorter, and they put the zone's field where the
//! confidential rail puts zero. A proof built over a wrong or zero zone field
//! still proves something; it is just bound to the wrong zone, or to nothing.
//! Nothing in a request body makes that visible, which is why the evidence here
//! is exact request bytes rather than a reading of both implementations.
//!
//! Every supported shape is emitted for each rail, and every named intermediate
//! that feeds the public-input chain is emitted alongside it, so a failing final
//! hash names the element that diverged instead of only reporting that something
//! did.
//!
//! The serializers are `pub(crate)`, so this generator lives inside the crate
//! rather than under `xtask/src/bin/`.
//!
//! Regenerate with
//! `ZOLANA_UPDATE_TS_ORACLES=1 cargo test -p zolana-client --lib ts_zone_oracle`.

use std::path::PathBuf;

use serde_json::{json, Value};
use solana_address::Address;
use zolana_hasher::hash_chain::create_hash_chain_from_slice;
use zolana_interface::shape::SPP_SUPPORTED_SHAPES;
use zolana_keypair::{
    hash::hash_field, NullifierKey, PublicKey, ShieldedKeypair, SigningKey, ViewingKey,
};
use zolana_transaction::{
    derive_blinding,
    instructions::{
        transact::{ExternalData, SppProofInputs, SppProofOutputUtxo},
        types::SppProofInputUtxo,
    },
    utxo::program_id_field,
    Data, Utxo, SOL_MINT,
};

use crate::{
    prover::{
        json::{to_json_p256_zone, to_json_zone, to_json_zone_authority},
        transact::{
            p256_and_eddsa::{P256Owner, PublicAmounts},
            witness::attach_input_proofs,
            zone_eddsa::ZoneTransferProver,
            zone_p256::ZoneTransferP256Prover,
        },
        zone_authority::ZoneAuthorityProver,
        TransferInputs, TransferP256Inputs,
    },
    MerkleContext, MerkleProof, NonInclusionProof, SpendProof,
};

/// Shared with `sdk-libs/ts/client/test/vectors/zone-oracle.test.ts`; the two
/// languages must derive identical key material and blindings from them.
const P256_SECRET: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7,
];
const ED25519_SECRET: [u8; 32] = [61; 32];
const VIEWING_SEED: [u8; 32] = [62; 32];
const BLINDING_SEED: [u8; 31] = [63; 31];
const ZONE_PROGRAM: [u8; 32] = [64; 32];
/// A second zone, used only to show that the binding moves the public input.
const OTHER_ZONE: [u8; 32] = [65; 32];
const PAYER: [u8; 32] = [66; 32];
const TREE: [u8; 32] = [67; 32];
const USER_SOL_ACCOUNT: [u8; 32] = [68; 32];
const INPUT_AMOUNT: u64 = 100;

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

fn zone() -> Address {
    Address::new_from_array(ZONE_PROGRAM)
}

/// A zone-owned input. Every real UTXO on a zone rail carries the zone.
fn real_input(keypair: &ShieldedKeypair, position: u8) -> SppProofInputUtxo {
    SppProofInputUtxo::new(
        Utxo {
            owner: keypair.signing_pubkey(),
            asset: SOL_MINT,
            amount: INPUT_AMOUNT,
            blinding: derive_blinding(&BLINDING_SEED, position),
            zone_program_id: Some(zone()),
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

/// Zone outputs are anonymous: they carry a derived view tag and no shielded
/// address, so `assemble_outputs` folds `hash_field(owner_tag)` rather than the
/// owner's signing-key field.
fn zone_output(position: u8, amount: u64) -> SppProofOutputUtxo {
    SppProofOutputUtxo {
        owner_address: None,
        owner_tag: Some(field_byte(position)),
        asset: SOL_MINT,
        amount,
        blinding: derive_blinding(&BLINDING_SEED, position),
        zone_program_id: Some(zone()),
        ..Default::default()
    }
}

fn dummy_output(position: u8) -> SppProofOutputUtxo {
    SppProofOutputUtxo {
        blinding: derive_blinding(&BLINDING_SEED, position),
        owner_tag: Some(field_byte(position)),
        zone_program_id: Some(zone()),
        ..Default::default()
    }
}

fn external_data(outputs: &[SppProofOutputUtxo]) -> ExternalData {
    let tags = outputs
        .iter()
        .map(|output| output.owner_tag.expect("zone output tag"))
        .collect::<Vec<_>>();
    let wire = outputs
        .iter()
        .zip(&tags)
        .map(|(output, tag)| {
            zolana_interface::instruction::instruction_data::transact::TransactOutput {
                utxo_hash: output.hash().expect("output hash"),
                owner_tag:
                    zolana_interface::instruction::instruction_data::transact::OwnerTag::Inline(
                        *tag,
                    ),
                data: Some(vec![1, 2, 3]),
            }
        })
        .collect::<Vec<_>>();
    ExternalData::new([71; 33], [72; 16], wire, tags, vec![])
        .with_public_sol(-5, Address::new_from_array(USER_SOL_ACCOUNT))
        .expect("public sol leg")
}

fn spend_proofs(inputs: &SppProofInputs) -> Vec<SpendProof> {
    let tree = Address::new_from_array(TREE);
    inputs
        .input_utxo_hashes()
        .expect("input contexts")
        .iter()
        .enumerate()
        .map(|(index, context)| SpendProof {
            state: MerkleProof {
                leaf: context.utxo_hash,
                merkle_context: MerkleContext { tree_type: 1, tree },
                path: vec![field_byte(73 + index as u8); 32],
                leaf_index: index as u64,
                root: field_byte(74 + index as u8),
                root_seq: 75,
                root_index: 76 + index as u16,
            },
            nullifier: NonInclusionProof {
                leaf: context.nullifier,
                merkle_context: MerkleContext { tree_type: 2, tree },
                path: vec![field_byte(77 + index as u8); 40],
                low_element: field_byte(78),
                low_element_index: index as u64,
                high_element: field_byte(79),
                high_element_index: index as u64 + 1,
                root: field_byte(80 + index as u8),
                root_seq: 81,
                root_index: 82 + index as u16,
            },
        })
        .collect()
}

/// One real input in slot 0, one more real input when the shape allows it, and
/// dummies for the rest, so both the real and the mirrored-dummy paths appear in
/// every shape wide enough to hold them.
fn proof_inputs(keypair: &ShieldedKeypair, inputs: usize, outputs: usize) -> SppProofInputs {
    let real = if inputs >= 2 { 2 } else { 1 };
    let input_utxos = (0..inputs)
        .map(|index| {
            if index < real {
                real_input(keypair, index as u8)
            } else {
                dummy_input(index as u8)
            }
        })
        .collect::<Vec<_>>();
    let total = INPUT_AMOUNT * real as u64;
    let output_utxos = (0..outputs)
        .map(|index| {
            if index == 0 {
                zone_output(32 + index as u8, total)
            } else {
                dummy_output(32 + index as u8)
            }
        })
        .collect::<Vec<_>>();
    let external = external_data(&output_utxos);
    SppProofInputs::new(
        input_utxos,
        output_utxos,
        external,
        Address::new_from_array(PAYER),
    )
}

fn amounts(inputs: &SppProofInputs) -> PublicAmounts {
    let value = inputs.public_amounts().expect("public amounts");
    PublicAmounts {
        sol: value.sol,
        spl: value.spl,
        asset: value.asset,
    }
}

fn p256_owner(keypair: &ShieldedKeypair, inputs: &mut SppProofInputs) -> P256Owner {
    inputs.sign_p256(keypair).expect("p256 signature");
    let signature = inputs.p256_signature.expect("p256 signature bytes");
    let mut sig_r = [0u8; 32];
    let mut sig_s = [0u8; 32];
    sig_r.copy_from_slice(&signature[..32]);
    sig_s.copy_from_slice(&signature[32..]);
    P256Owner {
        pubkey: keypair.signing_pubkey().as_p256().expect("p256 pubkey"),
        sig_r,
        sig_s,
    }
}

/// The named intermediates that feed the public-input chain, in Rust's order.
/// A TypeScript failure compares these first, so the report names the element
/// that diverged rather than only the final hash.
fn chain_json(
    inputs: &TransferInputs,
    nullifiers: &[[u8; 32]],
    output_hashes: &[[u8; 32]],
) -> Value {
    json!({
        "nullifierChain": hex(&create_hash_chain_from_slice(nullifiers).expect("nullifier chain")),
        "outputHashChain": hex(&create_hash_chain_from_slice(output_hashes).expect("output chain")),
        "externalDataHash": inputs.external_data_hash.to_string(),
        "privateTxHash": inputs.private_tx_hash.to_string(),
        "publicSolAmount": inputs.public_sol_amount.to_string(),
        "publicSplAmount": inputs.public_spl_amount.to_string(),
        "publicSplAssetPubkey": inputs.public_spl_asset_pubkey.to_string(),
        "zoneProgramId": inputs.zone_program_id.to_string(),
        "payerPubkeyHash": inputs.payer_pubkey_hash.to_string(),
        "publicInputHash": inputs.public_input_hash.to_string(),
        "inputOwnerPkHashes": inputs
            .inputs
            .iter()
            .map(|input| input.owner_pk_hash.to_string())
            .collect::<Vec<_>>(),
        "outputOwnerPkHashes": inputs
            .outputs
            .iter()
            .map(|output| output.owner_pk_hash.to_string())
            .collect::<Vec<_>>(),
    })
}

fn p256_chain_json(
    inputs: &TransferP256Inputs,
    nullifiers: &[[u8; 32]],
    output_hashes: &[[u8; 32]],
) -> Value {
    json!({
        "nullifierChain": hex(&create_hash_chain_from_slice(nullifiers).expect("nullifier chain")),
        "outputHashChain": hex(&create_hash_chain_from_slice(output_hashes).expect("output chain")),
        "externalDataHash": inputs.external_data_hash.to_string(),
        "privateTxHash": inputs.private_tx_hash.to_string(),
        "p256MessageHashLow": inputs.p256_message_hash_low.to_string(),
        "p256MessageHashHigh": inputs.p256_message_hash_high.to_string(),
        "p256SigningPkField": inputs.p256_signing_pk_field.to_string(),
        "publicSolAmount": inputs.public_sol_amount.to_string(),
        "publicSplAmount": inputs.public_spl_amount.to_string(),
        "publicSplAssetPubkey": inputs.public_spl_asset_pubkey.to_string(),
        "zoneProgramId": inputs.zone_program_id.to_string(),
        "payerPubkeyHash": inputs.payer_pubkey_hash.to_string(),
        "publicInputHash": inputs.public_input_hash.to_string(),
        "inputOwnerPkHashes": inputs
            .inputs
            .iter()
            .map(|input| input.owner_pk_hash.to_string())
            .collect::<Vec<_>>(),
    })
}

fn zone_case(shape: (usize, usize)) -> Value {
    let owner = keypair(false);
    let inputs = proof_inputs(&owner, shape.0, shape.1);
    let proofs = spend_proofs(&inputs);
    let spends =
        attach_input_proofs(inputs.input_utxos.clone(), &proofs).expect("attach input proofs");
    let result = ZoneTransferProver {
        inputs: spends,
        outputs: inputs.output_utxos.clone(),
        external_data: inputs.external_data.clone(),
        public_amounts: amounts(&inputs),
        payer_pubkey_hash: inputs.payer_pubkey_hash,
        zone_program_id: Some(zone()),
        shape: None,
    }
    .build()
    .expect("zone eddsa proof");
    json!({
        "shape": {"inputs": shape.0, "outputs": shape.1},
        "requestBodyJson": to_json_zone(&result.inputs),
        "publicInputHashBytes": hex(&result.public_input_hash),
        "privateTxHashBytes": hex(&result.private_tx_hash),
        "nullifierBytes": result.nullifiers.iter().map(|n| hex(n)).collect::<Vec<_>>(),
        "outputHashBytes": result.output_hashes.iter().map(|h| hex(h)).collect::<Vec<_>>(),
        "inputRootIndices": result
            .input_root_indices
            .iter()
            .map(|(utxo, nullifier)| json!([utxo, nullifier]))
            .collect::<Vec<_>>(),
        "chain": chain_json(&result.inputs, &result.nullifiers, &result.output_hashes),
    })
}

fn zone_p256_case(shape: (usize, usize)) -> Value {
    let owner = keypair(true);
    let mut inputs = proof_inputs(&owner, shape.0, shape.1);
    let p256 = p256_owner(&owner, &mut inputs);
    let proofs = spend_proofs(&inputs);
    let spends =
        attach_input_proofs(inputs.input_utxos.clone(), &proofs).expect("attach input proofs");
    let result = ZoneTransferP256Prover {
        inputs: spends,
        outputs: inputs.output_utxos.clone(),
        external_data: inputs.external_data.clone(),
        public_amounts: amounts(&inputs),
        payer_pubkey_hash: inputs.payer_pubkey_hash,
        p256_owner: p256,
        zone_program_id: Some(zone()),
        shape: None,
    }
    .build()
    .expect("zone p256 proof");
    json!({
        "shape": {"inputs": shape.0, "outputs": shape.1},
        "requestBodyJson": to_json_p256_zone(&result.inputs),
        "publicInputHashBytes": hex(&result.public_input_hash),
        "privateTxHashBytes": hex(&result.private_tx_hash),
        "nullifierBytes": result.nullifiers.iter().map(|n| hex(n)).collect::<Vec<_>>(),
        "outputHashBytes": result.output_hashes.iter().map(|h| hex(h)).collect::<Vec<_>>(),
        "inputRootIndices": result
            .input_root_indices
            .iter()
            .map(|(utxo, nullifier)| json!([utxo, nullifier]))
            .collect::<Vec<_>>(),
        "p256SigningPkFieldBytes": hex(&result.p256_signing_pk_field),
        "p256SigningPkXBytes": hex(&result.p256_signing_pk_x),
        "chain": p256_chain_json(&result.inputs, &result.nullifiers, &result.output_hashes),
    })
}

fn zone_authority_case(shape: (usize, usize)) -> Value {
    let owner = keypair(false);
    let inputs = proof_inputs(&owner, shape.0, shape.1);
    let proofs = spend_proofs(&inputs);
    let spends =
        attach_input_proofs(inputs.input_utxos.clone(), &proofs).expect("attach input proofs");
    let result = ZoneAuthorityProver {
        inputs: spends,
        outputs: inputs.output_utxos.clone(),
        external_data: inputs.external_data.clone(),
        public_amounts: amounts(&inputs),
        payer_pubkey_hash: inputs.payer_pubkey_hash,
        zone_program_id: Some(zone()),
        shape: None,
    }
    .build()
    .expect("zone authority proof");
    json!({
        "shape": {"inputs": shape.0, "outputs": shape.1},
        "requestBodyJson": to_json_zone_authority(&result.inputs),
        "publicInputHashBytes": hex(&result.public_input_hash),
        "privateTxHashBytes": hex(&result.private_tx_hash),
        "nullifierBytes": result.nullifiers.iter().map(|n| hex(n)).collect::<Vec<_>>(),
        "outputHashBytes": result.output_hashes.iter().map(|h| hex(h)).collect::<Vec<_>>(),
        "inputRootIndices": result
            .input_root_indices
            .iter()
            .map(|(utxo, nullifier)| json!([utxo, nullifier]))
            .collect::<Vec<_>>(),
        "chain": chain_json(&result.inputs, &result.nullifiers, &result.output_hashes),
    })
}

/// The same 2x2 zone transfer under a different zone. Only the binding changes,
/// so a public input hash that does not move would mean the zone field never
/// reached the chain.
fn other_zone_case() -> Value {
    let owner = keypair(false);
    let inputs = proof_inputs(&owner, 2, 2);
    let proofs = spend_proofs(&inputs);
    let spends =
        attach_input_proofs(inputs.input_utxos.clone(), &proofs).expect("attach input proofs");
    let other = Address::new_from_array(OTHER_ZONE);
    let result = ZoneTransferProver {
        inputs: spends,
        outputs: inputs.output_utxos.clone(),
        external_data: inputs.external_data.clone(),
        public_amounts: amounts(&inputs),
        payer_pubkey_hash: inputs.payer_pubkey_hash,
        zone_program_id: Some(other),
        shape: None,
    }
    .build()
    .expect("other zone proof");
    json!({
        "zoneProgramIdBytes": hex(&OTHER_ZONE),
        "zoneFieldBytes": hex(&program_id_field(&Some(other)).expect("zone field")),
        "publicInputHashBytes": hex(&result.public_input_hash),
    })
}

fn shapes() -> Vec<(usize, usize)> {
    SPP_SUPPORTED_SHAPES
        .iter()
        .map(|shape| (shape.n_inputs(), shape.n_outputs()))
        .collect()
}

fn oracle_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../ts/client/test/oracles/zone-v1.json")
}

#[test]
fn ts_zone_oracle_is_current() {
    let oracle = json!({
        "inputs": {
            "blindingSeedBytes": hex(&BLINDING_SEED),
            "ed25519SecretBytes": hex(&ED25519_SECRET),
            "p256SecretBytes": hex(&P256_SECRET),
            "viewingSeedBytes": hex(&VIEWING_SEED),
            "zoneProgramIdBytes": hex(&ZONE_PROGRAM),
            "payerBytes": hex(&PAYER),
            "treeBytes": hex(&TREE),
            "userSolAccountBytes": hex(&USER_SOL_ACCOUNT),
            "inputAmount": INPUT_AMOUNT,
            "testOnlySecret": true,
        },
        "expected": {
            "zoneFieldBytes": hex(&program_id_field(&Some(zone())).expect("zone field")),
            "payerPubkeyHashBytes": hex(&proof_inputs(&keypair(false), 1, 1).payer_pubkey_hash),
            // Rust's `hash_field(&[0; 32])`, the P256 message element every
            // ed25519 rail carries. Pinned so a TypeScript port that folds a
            // literal zero instead is caught at the element rather than the
            // final hash.
            "zeroP256MessageElementBytes": hex(&hash_field(&[0u8; 32]).expect("zero element")),
            "transferZone": shapes().into_iter().map(zone_case).collect::<Vec<_>>(),
            "transferP256Zone": shapes().into_iter().map(zone_p256_case).collect::<Vec<_>>(),
            "transferZoneAuthority": shapes()
                .into_iter()
                .map(zone_authority_case)
                .collect::<Vec<_>>(),
            "otherZone": other_zone_case(),
        }
    });
    let rendered = format!(
        "{}\n",
        serde_json::to_string_pretty(&oracle).expect("render")
    );
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
