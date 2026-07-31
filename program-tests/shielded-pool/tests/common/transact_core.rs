//! Shared test helpers for shielded-pool `transact` proof wiring.

use anyhow::{anyhow, Result};
use groth16_solana::groth16::Groth16Verifier;
use num_bigint::BigUint;
use zolana_client::{
    prover::field::be, spawn_prover, Proof, ProofCompressed, ProofInputUtxo, ProverClient,
    TransferInput, TransferInputs, TransferOutput,
};
use zolana_hasher::hash_chain::{create_hash_chain_from_slice, create_right_hash_chain_from_slice};
use zolana_hasher::primitives::hash_bytes;
use zolana_interface::{
    instruction::{
        instruction_data::transact::{
            CircuitId, ExternalDataHash, InputUtxo, InterfaceTransfer, OwnerTag,
            ResolvedInterfaceTransfer, ResolvedOutput, TransactIxData, TransactOutput,
            TransactProof,
        },
        tag,
    },
    verifying_keys::transfer_confidential_2_3,
    N_PUBLIC_SLOTS, SOL_ASSET_FIELD,
};
use zolana_transaction::SppProofOutputUtxo;

pub fn start_prover() -> Result<()> {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        std::env::set_var(
            "ZOLANA_PROVER_KEYS_DIR",
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../prover/server/proving-keys"
            ),
        );
    });
    spawn_prover()?;
    Ok(())
}

/// A field element holding `value` in its low 8 bytes (big-endian).
pub fn fe(value: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&value.to_be_bytes());
    out
}

pub fn pack_proof(proof: &Proof) -> Result<TransactProof> {
    Ok(ProofCompressed::try_from(*proof)?.to_transact_proof())
}

/// Mirror of the confidential `TransactProof::public_input_hash` on the eddsa
/// rail. The common chain is followed by
/// `HashChain(output_owner_pk_hashes)`. Mirrors the client
/// `PublicInputs::hash()` exactly. Public transfer slots interleave as
/// `(asset, amount)` and idle slots are `(0, 0)`.
#[allow(clippy::too_many_arguments)]
pub fn public_input_hash(
    nullifiers: &[[u8; 32]],
    output_hashes: &[[u8; 32]],
    utxo_roots: &[[u8; 32]],
    nullifier_tree_roots: &[[u8; 32]],
    private_tx: &[u8; 32],
    external_data_hash: &[u8; 32],
    public_slot_assets: &[[u8; 32]; N_PUBLIC_SLOTS],
    public_slot_amounts: &[[u8; 32]; N_PUBLIC_SLOTS],
    payer_pk_hash: &[u8; 32],
    input_owner_pk_hashes: &[[u8; 32]],
    output_owner_pk_hashes: &[[u8; 32]],
) -> [u8; 32] {
    let zero = [0u8; 32];
    let one = fe(1);
    let mut chain = vec![
        create_hash_chain_from_slice(nullifiers).expect("nullifier chain"),
        create_hash_chain_from_slice(output_hashes).expect("output chain"),
        create_hash_chain_from_slice(utxo_roots).expect("utxo root chain"),
        create_hash_chain_from_slice(nullifier_tree_roots).expect("nullifier root chain"),
        *private_tx,
        *external_data_hash,
    ];
    for (asset, amount) in public_slot_assets.iter().zip(public_slot_amounts.iter()) {
        chain.push(*asset);
        chain.push(*amount);
    }
    let mut signer_pk_hashes = vec![[0u8; 32]; input_owner_pk_hashes.len() + 1];
    signer_pk_hashes[0] = *payer_pk_hash;
    let mut seen = vec![*payer_pk_hash];
    let mut next = 1;
    for owner in input_owner_pk_hashes {
        if *owner == zero || seen.contains(owner) {
            continue;
        }
        seen.push(*owner);
        signer_pk_hashes[next] = *owner;
        next += 1;
    }
    chain.extend_from_slice(&[
        zero,
        create_right_hash_chain_from_slice(&signer_pk_hashes).expect("signer chain"),
        one,
        create_hash_chain_from_slice(output_owner_pk_hashes).expect("output owner chain"),
    ]);
    create_hash_chain_from_slice(&chain).expect("public input hash")
}

pub type PublicSlots = ([[u8; 32]; N_PUBLIC_SLOTS], [[u8; 32]; N_PUBLIC_SLOTS]);

#[allow(dead_code)]
pub fn sol_public_slots(amount: [u8; 32]) -> PublicSlots {
    let zero = [0u8; 32];
    let mut assets = [zero; N_PUBLIC_SLOTS];
    let mut amounts = [zero; N_PUBLIC_SLOTS];
    if amount != zero {
        *assets.first_mut().expect("public slot exists") = SOL_ASSET_FIELD;
        *amounts.first_mut().expect("public slot exists") = amount;
    }
    (assets, amounts)
}

pub fn spl_public_slots(amount: [u8; 32], mint: &[u8; 32]) -> Result<PublicSlots> {
    let zero = [0u8; 32];
    let mut assets = [zero; N_PUBLIC_SLOTS];
    let mut amounts = [zero; N_PUBLIC_SLOTS];
    if amount != zero {
        *assets.first_mut().expect("public slot exists") =
            hash_bytes(mint).map_err(|e| anyhow!("public SPL asset field: {e:?}"))?;
        *amounts.first_mut().expect("public slot exists") = amount;
    }
    Ok((assets, amounts))
}

/// Per-output owner `pk_field` the program reconstructs as
/// `hash_bytes(resolved_owner_tag)`, one per output position. Mirrors the
/// program's `resolve_output_owner_tags`: each output carries its own inline or
/// account-based owner tag.
pub fn output_owner_pk_hashes(outputs: &[TransactOutput]) -> Result<Vec<[u8; 32]>> {
    outputs
        .iter()
        .map(|output| {
            let resolved = output
                .into_resolved(|_| None)
                .map_err(|e| anyhow!("resolve owner tag: {e:?}"))?;
            hash_bytes(&resolved.owner_tag).map_err(|e| anyhow!("owner pk field: {e:?}"))
        })
        .collect()
}

/// Build the `transact` output slots from parallel utxo-hash and owner-view-tag
/// vectors: each output carries an `Inline` owner tag equal to its view tag and
/// no ciphertext, so `hash_bytes(view_tag)` is the OWNER public input the circuit
/// binds that output to. The two slices must have equal length; extra entries in
/// either are dropped.
pub fn inline_outputs(
    output_utxo_hashes: &[[u8; 32]],
    view_tags: &[[u8; 32]],
) -> Vec<TransactOutput> {
    output_utxo_hashes
        .iter()
        .zip(view_tags.iter())
        .map(|(utxo_hash, view_tag)| TransactOutput {
            utxo_hash: *utxo_hash,
            owner_tag: OwnerTag::Inline(*view_tag),
            data: None,
        })
        .collect()
}

/// Resolve every output's owner tag against the transaction context (`Inline`
/// tags resolve to themselves), producing the `ResolvedOutput` slice
/// [`ExternalDataHash`] hashes. Mirrors the program's per-output resolution so
/// the client and program agree on the hash preimage.
pub fn resolve_outputs(ix: &TransactIxData) -> Result<Vec<ResolvedOutput<'_>>> {
    ix.outputs
        .iter()
        .map(|output| {
            output
                .into_resolved(|_| None)
                .map_err(|e| anyhow!("resolve owner tag: {e:?}"))
        })
        .collect()
}

/// Stamp the confidential owner tag onto each witness output. `owner_pk_hashes[i]`
/// is the program's `hash_bytes(view_tag[i])` (so the public output-owner chain
/// matches), and `nullifier_pks[i]` is the real output's nullifier pubkey from
/// which the circuit recomputes `owner_hash` (zero for a dummy, whose owner the
/// circuit leaves unconstrained).
pub fn set_output_owner_tags(
    outputs: &mut [TransferOutput],
    owner_pk_hashes: &[[u8; 32]],
    nullifier_pks: &[[u8; 32]],
) {
    for ((output, owner), nullifier_pk) in outputs
        .iter_mut()
        .zip(owner_pk_hashes.iter())
        .zip(nullifier_pks.iter())
    {
        output.owner_pk_hash = be(owner);
        output.nullifier_pk = be(nullifier_pk);
    }
}

pub fn eddsa_input_utxo(nullifier_hash: [u8; 32], utxo_tree_root_index: u16) -> InputUtxo {
    InputUtxo {
        nullifier_hash,
        nullifier_tree_root_index: 0,
        utxo_tree_root_index,
    }
}

pub fn new_transact_ix_data(
    inputs: Vec<InputUtxo>,
    interface_transfers: Vec<InterfaceTransfer>,
    outputs: Vec<TransactOutput>,
) -> TransactIxData {
    let circuit = CircuitId::ConfidentialEddsa(
        inputs.len() as u8,
        outputs.len() as u8,
        N_PUBLIC_SLOTS as u8,
    );
    TransactIxData {
        proof: TransactProof::zeroed(),
        expiry_unix_ts: u64::MAX,
        private_tx_hash: [0u8; 32],
        circuit,
        inputs,
        interface_transfers,
        data_hash: None,
        zone_data_hash: None,
        tx_viewing_pk: [0u8; 33],
        salt: [0u8; 16],
        outputs,
        messages: Vec::new(),
    }
}

pub fn external_data_hash(
    transact_ix_data: &TransactIxData,
    interface_transfers: &[ResolvedInterfaceTransfer],
) -> Result<[u8; 32]> {
    let outputs = resolve_outputs(transact_ix_data)?;
    Ok(ExternalDataHash {
        spp_instruction_discriminator: tag::TRANSACT,
        expiry_unix_ts: transact_ix_data.expiry_unix_ts,
        interface_transfers,
        data_hash: None,
        zone_data_hash: None,
        tx_viewing_pk: &transact_ix_data.tx_viewing_pk,
        salt: &transact_ix_data.salt,
        outputs: &outputs,
        messages: &transact_ix_data.messages,
    }
    .hash()?)
}

/// A dummy output (`owner_hash = 0`) over a chosen `blinding`, assembled exactly as
/// the production prover does (`assemble_outputs`): it gets a real `utxo_hash` that
/// the program appends to the tree and the proof commits via the public output
/// chain, while contributing `0` to `private_tx_hash`. Returns the witness output
/// and that hash so callers can wire both consistently.
pub fn dummy_transfer_output(blinding: &[u8; 31]) -> Result<(TransferOutput, [u8; 32])> {
    let mut field_blinding = [0u8; 32];
    field_blinding[1..].copy_from_slice(blinding);
    let output = SppProofOutputUtxo {
        blinding: field_blinding,
        ..Default::default()
    };
    let hash = output
        .hash()
        .map_err(|e| anyhow!("dummy output hash: {e:?}"))?;
    let utxo =
        ProofInputUtxo::try_from(&output).map_err(|e| anyhow!("dummy output utxo: {e:?}"))?;
    let zero = [0u8; 32];
    Ok((
        TransferOutput {
            utxo,
            is_dummy: be(&fe(1)),
            hash: be(&hash),
            // Patched by `set_output_owner_tags` once the per-output view_tag
            // mapping is known; a dummy's nullifier_pk stays 0 (unconstrained).
            owner_pk_hash: be(&zero),
            nullifier_pk: be(&zero),
        },
        hash,
    ))
}

pub struct TransferProverInputsArgs {
    pub inputs: Vec<TransferInput>,
    pub outputs: Vec<TransferOutput>,
    pub external_data_hash: [u8; 32],
    pub private_tx_hash: [u8; 32],
    pub public_slot_assets: [[u8; 32]; N_PUBLIC_SLOTS],
    pub public_slot_amounts: [[u8; 32]; N_PUBLIC_SLOTS],
    pub payer_pk_hash: [u8; 32],
    pub public_input_hash: [u8; 32],
}

pub fn build_transfer_prover_inputs(args: TransferProverInputsArgs) -> TransferInputs {
    let zero = [0u8; 32];
    let signer_count = args.inputs.len();
    let payer_pk_hash = be(&args.payer_pk_hash);
    let mut signer_pk_hashes = vec![BigUint::from(0u8); signer_count + 1];
    signer_pk_hashes[0] = payer_pk_hash.clone();
    let mut seen = vec![payer_pk_hash.clone()];
    let mut next = 1;
    for input in &args.inputs {
        let owner = &input.owner_pk_hash;
        if owner == &BigUint::from(0u8) || seen.contains(owner) {
            continue;
        }
        seen.push(owner.clone());
        signer_pk_hashes[next] = owner.clone();
        next += 1;
    }
    let published_output_owner_pk_hashes = args
        .outputs
        .iter()
        .map(|output| output.owner_pk_hash.clone())
        .collect();
    TransferInputs {
        inputs: args.inputs,
        outputs: args.outputs,
        external_data_hash: be(&args.external_data_hash),
        private_tx_hash: be(&args.private_tx_hash),
        public_assets: args.public_slot_assets.map(|asset| be(&asset)),
        public_amounts: args.public_slot_amounts.map(|amount| be(&amount)),
        zone_program_id: be(&zero),
        signer_pk_hashes,
        allow_dummy_inputs: be(&fe(1)),
        published_output_owner_pk_hashes,
        public_input_hash: be(&args.public_input_hash),
    }
}

pub fn prove_and_verify_transfer(
    prover_inputs: &TransferInputs,
    public_input_hash: [u8; 32],
    label: &str,
) -> Result<TransactProof> {
    let proof = ProverClient::local().prove_transfer(prover_inputs)?;
    let public_inputs = [public_input_hash];
    let mut verifier = Groth16Verifier::new(
        &proof.a,
        &proof.b,
        &proof.c,
        &public_inputs,
        &transfer_confidential_2_3::VERIFYINGKEY,
    )
    .map_err(|err| anyhow!("construct {label} verifier: {err:?}"))?;
    verifier
        .verify()
        .map_err(|err| anyhow!("verify {label} proof: {err:?}"))?;
    pack_proof(&proof)
}
