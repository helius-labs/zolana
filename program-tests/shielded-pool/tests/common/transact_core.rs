//! Shared test helpers for shielded-pool `transact` proof wiring.

use anyhow::{anyhow, Result};
use groth16_solana::groth16::Groth16Verifier;
use zolana_client::{
    prover::field::be, spawn_prover, Proof, ProofCompressed, ProofInputUtxo, ProverClient,
    TransferInput, TransferInputs, TransferOutput, NULLIFIER_TREE_HEIGHT, STATE_TREE_HEIGHT,
};
use zolana_hasher::hash_chain::create_hash_chain_from_slice;
use zolana_interface::{
    instruction::{
        instruction_data::transact::{
            ExternalDataHash, InputUtxo, OwnerTag, ResolvedOutput, TransactIxData, TransactOutput,
            TransactProof,
        },
        tag,
    },
    verifying_keys::transfer_confidential_2_3,
};
use zolana_keypair::hash::hash_field;
use zolana_transaction::OutputUtxo;

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
/// rail. The 14-element anonymous chain is followed by the two confidential
/// elements: `[14] HashChain(output_owner_pk_hashes)` and `[15]
/// p256_signing_pk_field` (zero on the eddsa rail). Mirrors the client
/// `PublicInputs::hash()` exactly.
#[allow(clippy::too_many_arguments)]
pub fn public_input_hash(
    nullifiers: &[[u8; 32]],
    output_hashes: &[[u8; 32]],
    utxo_roots: &[[u8; 32]],
    nullifier_tree_roots: &[[u8; 32]],
    private_tx: &[u8; 32],
    external_data_hash: &[u8; 32],
    public_sol_amount: &[u8; 32],
    payer_pubkey_hash: &[u8; 32],
    input_owner_pk_hashes: &[[u8; 32]],
    output_owner_pk_hashes: &[[u8; 32]],
    p256_signing_pk_field: &[u8; 32],
) -> [u8; 32] {
    let zero = [0u8; 32];
    let chain = [
        create_hash_chain_from_slice(nullifiers).expect("nullifier chain"),
        create_hash_chain_from_slice(output_hashes).expect("output chain"),
        create_hash_chain_from_slice(utxo_roots).expect("utxo root chain"),
        create_hash_chain_from_slice(nullifier_tree_roots).expect("nullifier root chain"),
        *private_tx,
        hash_field(&zero).expect("p256 message field"),
        *external_data_hash,
        *public_sol_amount,
        zero, // public_spl_amount
        zero, // public_spl_asset_pubkey
        zero, // zone_program_id
        *payer_pubkey_hash,
        create_hash_chain_from_slice(input_owner_pk_hashes).expect("input owner chain"),
        create_hash_chain_from_slice(output_owner_pk_hashes).expect("output owner chain"),
        *p256_signing_pk_field,
    ];
    create_hash_chain_from_slice(&chain).expect("public input hash")
}

/// Per-output owner `pk_field` the program reconstructs as
/// `hash_field(resolved_owner_tag)`, one per output position. Mirrors the
/// program's `resolve_output_owner_tags`: each output carries its own owner tag,
/// resolved here against the transaction's `p256_signing_pk_x`. Tests build
/// `Inline` tags, for which resolution is the identity, and pass `None`.
pub fn output_owner_pk_hashes(
    outputs: &[TransactOutput],
    p256_signing_pk_x: Option<&[u8; 32]>,
) -> Result<Vec<[u8; 32]>> {
    outputs
        .iter()
        .map(|output| {
            let resolved = output
                .resolved(p256_signing_pk_x, |_| None)
                .map_err(|e| anyhow!("resolve owner tag: {e:?}"))?;
            hash_field(&resolved.owner_tag).map_err(|e| anyhow!("owner pk field: {e:?}"))
        })
        .collect()
}

/// Build the `transact` output slots from parallel utxo-hash and owner-view-tag
/// vectors: each output carries an `Inline` owner tag equal to its view tag and
/// no ciphertext, so `hash_field(view_tag)` is the OWNER public input the circuit
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
                .resolved(ix.p256_signing_pk_x.as_ref(), |_| None)
                .map_err(|e| anyhow!("resolve owner tag: {e:?}"))
        })
        .collect()
}

/// Stamp the confidential owner tag onto each witness output. `owner_pk_hashes[i]`
/// is the program's `hash_field(view_tag[i])` (so the public output-owner chain
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

/// One circuit-dummy input carrying a chosen nullifier plus the real tree roots
/// and signer owner hash.
pub fn dummy_input(
    nullifier: &[u8; 32],
    roots: ([u8; 32], [u8; 32]),
    owner_hash: &[u8; 32],
) -> TransferInput {
    let (utxo_root, nullifier_root) = roots;
    let zero = [0u8; 32];
    TransferInput {
        // A circuit-dummy input carries a chosen `nullifier`; the circuit skips its
        // ownership/inclusion/nullifier-derivation checks, so an all-zero utxo slot
        // satisfies the padding constraints (amount, owner, data_hash zero).
        utxo: ProofInputUtxo::default(),
        is_dummy: be(&fe(1)),
        state_path_elements: vec![be(&zero); STATE_TREE_HEIGHT],
        state_path_index: be(&zero),
        nullifier_low_value: be(&zero),
        nullifier_next_value: be(&zero),
        nullifier_low_path_elements: vec![be(&zero); NULLIFIER_TREE_HEIGHT],
        nullifier_low_path_index: be(&zero),
        utxo_tree_root: be(&utxo_root),
        nullifier_tree_root: be(&nullifier_root),
        nullifier: be(nullifier),
        owner_pk_hash: be(owner_hash),
        nullifier_secret: be(&zero),
    }
}

pub fn eddsa_input_utxo(nullifier_hash: [u8; 32], utxo_tree_root_index: u16) -> InputUtxo {
    InputUtxo {
        nullifier_hash,
        nullifier_tree_root_index: 0,
        utxo_tree_root_index,
        tree_index: 0,
        eddsa_signer_index: 0,
    }
}

pub fn new_transact_ix_data(
    inputs: Vec<InputUtxo>,
    public_sol_amount: Option<i64>,
    outputs: Vec<TransactOutput>,
    p256_signing_pk_x: Option<[u8; 32]>,
) -> TransactIxData {
    TransactIxData {
        proof: TransactProof::zeroed_eddsa(),
        expiry_unix_ts: u64::MAX,
        relayer_fee: 0,
        private_tx_hash: [0u8; 32],
        p256_signing_pk_x,
        inputs,
        public_sol_amount,
        public_spl_amount: None,
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
    user_sol_account: &[u8; 32],
) -> Result<[u8; 32]> {
    let zero = [0u8; 32];
    let outputs = resolve_outputs(transact_ix_data)?;
    Ok(ExternalDataHash {
        spp_instruction_discriminator: tag::TRANSACT,
        expiry_unix_ts: transact_ix_data.expiry_unix_ts,
        relayer_fee: transact_ix_data.relayer_fee,
        public_sol_amount: transact_ix_data.public_sol_amount,
        public_spl_amount: transact_ix_data.public_spl_amount,
        user_sol_account,
        user_spl_token_account: &zero,
        spl_token_interface: &zero,
        data_hash: None,
        zone_data_hash: None,
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
    let output = OutputUtxo {
        blinding: *blinding,
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
    pub public_sol_amount: [u8; 32],
    pub payer_pubkey_hash: [u8; 32],
    pub public_input_hash: [u8; 32],
}

pub fn build_transfer_prover_inputs(args: TransferProverInputsArgs) -> TransferInputs {
    let zero = [0u8; 32];
    TransferInputs {
        inputs: args.inputs,
        outputs: args.outputs,
        external_data_hash: be(&args.external_data_hash),
        private_tx_hash: be(&args.private_tx_hash),
        public_sol_amount: be(&args.public_sol_amount),
        public_spl_amount: be(&zero),
        public_spl_asset_pubkey: be(&zero),
        zone_program_id: be(&zero),
        payer_pubkey_hash: be(&args.payer_pubkey_hash),
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
