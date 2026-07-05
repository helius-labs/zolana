//! Zone-proof witness builder and prover glue (gated under the `prover` feature).
//!
//! Mirrors the squads zone circuit
//! `prover/server/circuits/squads/zone/{circuit.go,view_key.go,sender.go,
//! recipient.go,proposal.go}` and the shared gadgets in
//! `prover/server/circuits/zone-utils/{poseidon_kdf.go,p256/*}` and
//! `prover/server/circuits/{spp_transaction/*,gadget/*,verifiable-encryption/aes/*}`
//! byte-for-byte.
//!
//! Given the sender's viewing secret key, the input/output UTXOs, the recipient's
//! viewing pubkey (transfer only), an optional proposal, and the public amount,
//! this builds the sender and recipient AES-CTR ciphertexts, derives the
//! change blinding via the Poseidon KDF chain, recomputes every UTXO/account hash
//! and the public-input hash, serialises the `squads-zone` JSON request, requests a
//! Groth16 proof from the prover server, and returns the 192-byte compressed proof
//! plus the computed public-input hash and published artefacts.
//!
//! The Go prover assigns every field verbatim and the circuit asserts that the
//! supplied `PublicInputHash` equals the chain it recomputes (witness.go:59,
//! circuit.go:112), so the host computation here must match the circuit exactly or
//! proving fails outright.

use num_bigint::BigUint;
use p256::{
    elliptic_curve::{ops::Reduce, sec1::ToEncodedPoint},
    ProjectivePoint, PublicKey, Scalar, SecretKey, U256,
};
use serde::Serialize;
use zolana_hasher::{Hasher, Poseidon};
use zolana_keypair::P256Pubkey;

use crate::prover::{
    error::SquadsProverError,
    proof::gnark_json_to_transact_bytes,
    server::send_prove_request,
    shared_viewing_key::{ctr_apply_pub, derive_shared_secret_pub, key_schedule_pub, pack33},
};

/// Supported `(n_inputs, n_outputs)` shapes. MUST mirror the prover's
/// `transferSupportedShapes`-equivalent zone shapes and the program's
/// `select_zone_vk`: transfer `(2, 2)` and withdrawal `(1, 1)`.
pub const ZONE_SUPPORTED_SHAPES: [(u8, u8); 2] = [(1, 1), (2, 2)];

/// A single UTXO as the prover witnesses it. `owner_key_hash` and
/// `nullifier_pubkey` reconstruct the output's `owner_hash =
/// Poseidon(owner_key_hash, nullifier_pubkey)` (transaction `OwnerHashGadget`).
/// All scalar fields are 32-byte big-endian field elements.
#[derive(Clone)]
pub struct ZoneUtxo {
    /// Owner key hash (the `Owner` half of `OwnerHashGadget`).
    pub owner_key_hash: [u8; 32],
    /// Nullifier pubkey bound into `owner_hash`.
    pub nullifier_pubkey: [u8; 32],
    pub asset: [u8; 32],
    /// `u64` amount as a field element (big-endian, only low 8 bytes used).
    pub amount: u64,
    pub blinding: [u8; 32],
    pub program_data_hash: [u8; 32],
    pub zone_data_hash: [u8; 32],
    pub zone_program_id: [u8; 32],
    /// Marks an unused input slot. A dummy contributes `[0u8; 32]` to the
    /// `private_tx_hash` input fold (matching the SPP circuits' `IsDummy`
    /// convention) and the circuit pins its amount to 0. `inputs[0]` can never
    /// be a dummy: its nullifier seeds the `tx_viewing_sk` KDF.
    pub is_dummy: bool,
}

/// The recipient of a transfer. The prover holds no recipient secret, so only the
/// recipient's public account identity and viewing pubkey are provided.
#[derive(Clone)]
pub struct ZoneRecipient {
    pub owner_key_hash: [u8; 32],
    pub nullifier_pubkey: [u8; 32],
    pub viewing_pubkey: P256Pubkey,
}

/// An optional proposal commitment bound into the proof.
#[derive(Clone)]
pub struct ZoneProposal {
    pub amount: [u8; 32],
    pub recipient: [u8; 32],
    pub blinding: [u8; 32],
    pub public_amount: [u8; 32],
}

/// Inputs to a zone proof.
pub struct ZoneWitness {
    /// The sender's shared viewing secret key (a P-256 scalar). Drives the change
    /// blinding KDF chain and the sender/recipient ciphertext keys.
    pub viewing_secret_key: SecretKey,
    /// The sender's nullifier secret (a BN254-range field element).
    pub nullifier_secret: [u8; 32],

    /// Spent input UTXOs (at least one; `Inputs[0]` seeds the KDF chain).
    pub inputs: Vec<ZoneUtxo>,
    /// Output UTXOs. `Outputs[0]` is the sender change; for a transfer
    /// `Outputs[1]` is the recipient output.
    pub outputs: Vec<ZoneUtxo>,
    /// External data hash folded into `private_tx_hash`.
    pub external_data_hash: [u8; 32],

    /// Present iff this is a transfer (2 outputs); `None` for a withdrawal.
    pub recipient: Option<ZoneRecipient>,

    /// The proposal commitment (enabled iff `Some`).
    pub proposal: Option<ZoneProposal>,

    /// The public withdrawn amount (0 for a transfer).
    pub public_amount: [u8; 32],
}

/// The published artefacts and proof of a zone proof.
pub struct ZoneProofResult {
    /// The 192-byte compressed Groth16 proof (BSB22 layout, commitment included).
    pub proof: [u8; 192],
    /// The public-input hash the circuit constrains and the program recomputes.
    pub public_input_hash: [u8; 32],
    /// `Transaction.Hash` bound into the public-input chain; the caller passes
    /// this verbatim as `TransactIxData.private_tx_hash` so the program recomputes
    /// the same chain.
    pub private_tx_hash: [u8; 32],
    /// `Poseidon(skLow, skHigh)` viewing-key commitment; equals the sender viewing
    /// key account's `shared_viewing_key_commitment` the program reads.
    pub commitment: [u8; 32],
    /// `Poseidon(amount, recipient, blinding, public_amount)` of the bound
    /// proposal, or `0` when no proposal. The caller stores this as the
    /// `Proposal.proposal_hash` that `execute_proposal` reads as the zone-proof
    /// public input.
    pub proposal_hash: [u8; 32],
    /// Sender ciphertext (40 bytes: amount 8 || asset 32).
    pub sender_ciphertext: Vec<u8>,
    /// Recipient ciphertext (71 bytes: amount 8 || asset 32 || blinding 31), empty
    /// for a withdrawal.
    pub recipient_ciphertext: Vec<u8>,
    /// The derived change blinding (must equal `Outputs[0].blinding`).
    pub change_blinding: [u8; 32],
    /// Compressed ephemeral `tx_viewing_pk = tx_viewing_sk · G` (transfer only).
    pub tx_viewing_pk: Option<[u8; 33]>,
}

// ---- field-element helpers ------------------------------------------------

fn fe_hex(bytes: &[u8; 32]) -> String {
    format!("0x{}", BigUint::from_bytes_be(bytes).to_str_radix(16))
}

/// A `u64` zero-padded (right-aligned big-endian) into a field element.
fn right_align_u64(x: u64) -> [u8; 32] {
    let mut fe = [0u8; 32];
    fe[24..32].copy_from_slice(&x.to_be_bytes());
    fe
}

/// A label (a short ASCII string) zero-padded (right-aligned big-endian) into
/// a field element, matching Go's `new(big.Int).SetBytes([]byte(label))`.
fn right_align_label(label: &[u8]) -> [u8; 32] {
    let mut fe = [0u8; 32];
    let start = 32 - label.len();
    fe[start..].copy_from_slice(label);
    fe
}

fn poseidon(inputs: &[&[u8]]) -> Result<[u8; 32], SquadsProverError> {
    Poseidon::hashv(inputs).map_err(|_| SquadsProverError::Poseidon)
}

/// `gadget.HashChain` (hashchain.go): `acc = Poseidon(acc, next)`, empty = 0.
fn hash_chain(items: &[[u8; 32]]) -> Result<[u8; 32], SquadsProverError> {
    let mut iter = items.iter();
    let Some(first) = iter.next() else {
        return Ok([0u8; 32]);
    };
    let mut acc = *first;
    for item in iter {
        acc = poseidon(&[&acc, item])?;
    }
    Ok(acc)
}

/// `Poseidon(PackBytesBE(ciphertext, 16))`: each 16-byte chunk (the last may be
/// shorter) is a right-aligned big-endian field element (sender.go:103 /
/// recipient.go:66).
fn ciphertext_hash(ciphertext: &[u8]) -> Result<[u8; 32], SquadsProverError> {
    let chunks: Vec<[u8; 32]> = ciphertext
        .chunks(16)
        .map(|c| {
            let mut fe = [0u8; 32];
            fe[32 - c.len()..32].copy_from_slice(c);
            fe
        })
        .collect();
    let refs: Vec<&[u8]> = chunks.iter().map(|c| c.as_slice()).collect();
    poseidon(&refs)
}

// ---- domain separators (poseidon_kdf.go / sender.go) ----------------------

/// `KdfDomainSep = "TSPP/kdf"` prepended to every KDF step (poseidon_kdf.go:26).
fn kdf_sep() -> [u8; 32] {
    right_align_label(b"TSPP/kdf")
}

/// One keyed KDF step: `Poseidon(KdfDomainSep, inputs...)` (poseidon_kdf.go:31).
fn poseidon_kdf(inputs: &[&[u8]]) -> Result<[u8; 32], SquadsProverError> {
    let sep = kdf_sep();
    let mut all: Vec<&[u8]> = Vec::with_capacity(inputs.len() + 1);
    all.push(&sep);
    all.extend_from_slice(inputs);
    poseidon(&all)
}

// ---- UTXO / account hashing (utxo.go, view_key.go, recipient.go) ----------

/// `OwnerHashGadget`: `Poseidon(owner_key_hash, nullifier_pubkey)` (proof_gadgets/
/// inputs.go `OwnerHashGadget`).
fn owner_hash(
    owner_key_hash: &[u8; 32],
    nullifier_pubkey: &[u8; 32],
) -> Result<[u8; 32], SquadsProverError> {
    poseidon(&[owner_key_hash, nullifier_pubkey])
}

/// `UtxoHashCircuit` (spp_transaction/utxo.go `UtxoCircuitFields::DefineGadget`):
/// `Poseidon(UtxoDomain, asset, amount, data_hash, Poseidon(zone_data_hash,
/// zone_program_id), Poseidon(owner_hash, blinding))`. The fields here are
/// pre-encoded field elements, so the fold is replicated structurally
/// (`zolana_transaction::utxo::utxo_hash` is the same fold over raw
/// address-typed inputs).
fn utxo_hash(u: &ZoneUtxo) -> Result<[u8; 32], SquadsProverError> {
    let owner = owner_hash(&u.owner_key_hash, &u.nullifier_pubkey)?;
    let inner = poseidon(&[&owner, &u.blinding])?;
    let zone_hash = poseidon(&[&u.zone_data_hash, &u.zone_program_id])?;
    let domain = right_align_u64(1); // UtxoDomain
    let amount = right_align_u64(u.amount);
    poseidon(&[
        &domain,
        &u.asset,
        &amount,
        &u.program_data_hash,
        &zone_hash,
        &inner,
    ])
}

/// `Transaction.Hash` (transaction.go): the shared SPP fold `Poseidon(
/// HashChain(inputs), HashChain(outputs), HashChain(addresses),
/// external_data_hash)` with one all-zero address hash per input (the zone
/// circuit hardcodes them to zero; only the SPP rail creates addresses).
/// Delegates to the canonical implementation in `zolana-transaction`.
fn private_tx_hash(
    input_hashes: &[[u8; 32]],
    output_hashes: &[[u8; 32]],
    external_data_hash: &[u8; 32],
) -> Result<[u8; 32], SquadsProverError> {
    zolana_transaction::instructions::transact::private_tx_hash(
        input_hashes,
        output_hashes,
        &zolana_transaction::instructions::transact::no_address_hashes(input_hashes.len()),
        external_data_hash,
    )
    .map_err(|_| SquadsProverError::Poseidon)
}

/// `PublicViewingKeyAccount.Hash` (view_key.go:22): `Poseidon(owner, commitment,
/// nullifier_pubkey)`.
fn sender_account_hash(
    owner_key_hash: &[u8; 32],
    commitment: &[u8; 32],
    nullifier_pubkey: &[u8; 32],
) -> Result<[u8; 32], SquadsProverError> {
    poseidon(&[owner_key_hash, commitment, nullifier_pubkey])
}

/// `Recipient.Hash` (recipient.go:32): `Poseidon(owner, vpk_lo, vpk_hi,
/// nullifier_pubkey)` where `(vpk_lo, vpk_hi) = Pack33To2FE(compressed_vpk)`.
fn recipient_account_hash(
    owner_key_hash: &[u8; 32],
    viewing_pk_comp: &[u8; 33],
    nullifier_pubkey: &[u8; 32],
) -> Result<[u8; 32], SquadsProverError> {
    let (lo, hi) = pack33(viewing_pk_comp);
    poseidon(&[owner_key_hash, &lo, &hi, nullifier_pubkey])
}

/// `(sk_low, sk_high, commitment)` from [`viewing_commitment`].
type ViewingCommitment = ([u8; 32], [u8; 32], [u8; 32]);

/// `Poseidon(skLow, skHigh)` viewing-key commitment (view_key.go:64). `skLow` /
/// `skHigh` are the low / high 128 bits of the canonical scalar, i.e. the byte
/// split of the 32-byte big-endian scalar at byte 16.
fn viewing_commitment(viewing_sk_be: &[u8; 32]) -> Result<ViewingCommitment, SquadsProverError> {
    let (high_bytes, low_bytes) = viewing_sk_be.split_at(16);
    let mut sk_low = [0u8; 32];
    let mut sk_high = [0u8; 32];
    sk_low[16..].copy_from_slice(low_bytes);
    sk_high[16..].copy_from_slice(high_bytes);
    let commitment = poseidon(&[&sk_low, &sk_high])?;
    Ok((sk_low, sk_high, commitment))
}

// ---- ephemeral key / P-256 ------------------------------------------------

/// Interpret a 32-byte big-endian field element as a P-256 scalar, reducing modulo
/// the curve order (matching gnark's `bytesToEmulatedFr` + scalar mul). BN254
/// field elements are < 2^254 < the P-256 order, so this never wraps in practice.
fn scalar_from_fe(fe: &[u8; 32]) -> Scalar {
    Reduce::<U256>::reduce_bytes(fe.into())
}

/// Compressed `scalar · G` (the ephemeral tx_viewing_pk).
fn scalar_mul_generator_compressed(scalar: &Scalar) -> [u8; 33] {
    let point = ProjectivePoint::GENERATOR * scalar;
    let affine = point.to_affine();
    let encoded = affine.to_encoded_point(true);
    let mut out = [0u8; 33];
    out.copy_from_slice(encoded.as_bytes());
    out
}

/// ECDH x-coordinate of `scalar · recipient_pub` (recipient.go ECDH).
fn ecdh_x(scalar: &Scalar, recipient: &PublicKey) -> Result<[u8; 32], SquadsProverError> {
    let point = ProjectivePoint::from(recipient.as_affine()) * scalar;
    let affine = point.to_affine();
    let encoded = affine.to_encoded_point(false);
    let x = encoded.x().ok_or(SquadsProverError::InvalidPubkey)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(x.as_slice());
    Ok(out)
}

/// The 65-byte uncompressed SEC1 encoding (0x04 || x || y) of a P-256 pubkey.
fn uncompressed_65(pk: &P256Pubkey) -> Result<[u8; 65], SquadsProverError> {
    let p = pk.to_p256().map_err(|_| SquadsProverError::InvalidPubkey)?;
    let encoded = p.to_encoded_point(false);
    let bytes = encoded.as_bytes();
    if bytes.len() != 65 {
        return Err(SquadsProverError::InvalidPubkey);
    }
    let mut out = [0u8; 65];
    out.copy_from_slice(bytes);
    Ok(out)
}

/// Validate the recipient point lies on the curve and return its `PublicKey`.
/// `to_p256` parses the compressed SEC1 bytes, rejecting off-curve points.
fn recipient_public_key(pk: &P256Pubkey) -> Result<PublicKey, SquadsProverError> {
    pk.to_p256().map_err(|_| SquadsProverError::InvalidPubkey)
}

// ---- request JSON (marshal.go) --------------------------------------------

#[derive(Serialize)]
struct UtxoJson {
    #[serde(rename = "ownerHash")]
    owner_hash: String,
    asset: String,
    amount: String,
    blinding: String,
    #[serde(rename = "programDataHash")]
    program_data_hash: String,
    #[serde(rename = "zoneDataHash")]
    zone_data_hash: String,
    #[serde(rename = "zoneProgramId")]
    zone_program_id: String,
}

#[derive(Serialize)]
struct SenderJson {
    owner: String,
    #[serde(rename = "sharedViewingSecretKeyCommitment")]
    shared_viewing_secret_key_commitment: String,
    #[serde(rename = "nullifierPubkey")]
    nullifier_pubkey: String,
    #[serde(rename = "nullifierSecret")]
    nullifier_secret: String,
    #[serde(rename = "sharedViewingSecretKey")]
    shared_viewing_secret_key: String,
}

#[derive(Serialize)]
struct RecipientJson {
    owner: String,
    #[serde(rename = "nullifierPubkey")]
    nullifier_pubkey: String,
    #[serde(rename = "viewingPubkey")]
    viewing_pubkey: Vec<String>,
}

#[derive(Serialize)]
struct ProposalJson {
    amount: String,
    recipient: String,
    blinding: String,
    #[serde(rename = "publicAmount")]
    public_amount: String,
}

#[derive(Serialize)]
struct ZoneRequestJson {
    #[serde(rename = "circuitType")]
    circuit_type: String,
    #[serde(rename = "nInputs")]
    n_inputs: u32,
    #[serde(rename = "nOutputs")]
    n_outputs: u32,
    inputs: Vec<UtxoJson>,
    #[serde(rename = "inputsDummy", skip_serializing_if = "Vec::is_empty")]
    inputs_dummy: Vec<String>,
    outputs: Vec<UtxoJson>,
    #[serde(rename = "externalDataHash")]
    external_data_hash: String,
    sender: SenderJson,
    recipient: RecipientJson,
    proposal: ProposalJson,
    #[serde(rename = "enableProposalHash")]
    enable_proposal_hash: String,
    #[serde(rename = "publicAmount")]
    public_amount: String,
    #[serde(rename = "publicInputHash")]
    public_input_hash: String,
}

fn utxo_json(u: &ZoneUtxo) -> UtxoJson {
    UtxoJson {
        owner_hash: fe_hex(
            &owner_hash(&u.owner_key_hash, &u.nullifier_pubkey).unwrap_or([0u8; 32]),
        ),
        asset: fe_hex(&u.asset),
        amount: fe_hex(&right_align_u64(u.amount)),
        blinding: fe_hex(&u.blinding),
        program_data_hash: fe_hex(&u.program_data_hash),
        zone_data_hash: fe_hex(&u.zone_data_hash),
        zone_program_id: fe_hex(&u.zone_program_id),
    }
}

/// The sender's `tx_viewing_sk` KDF chain (sender.go:37-49): derived from the
/// viewing secret key, the nullifier secret, and the first input UTXO. It seeds
/// both the change blinding and the sender ciphertext key, so both
/// [`derive_change_blinding`] and [`derive_sender_artifacts`] share this fold.
fn tx_viewing_sk_chain(
    viewing_secret_key: &SecretKey,
    nullifier_secret: &[u8; 32],
    first_input: &ZoneUtxo,
) -> Result<[u8; 32], SquadsProverError> {
    let viewing_sk_be: [u8; 32] = {
        let mut b = [0u8; 32];
        b.copy_from_slice(viewing_secret_key.to_bytes().as_slice());
        b
    };
    let (sk_low, sk_high, _commitment) = viewing_commitment(&viewing_sk_be)?;

    let first_input_hash = utxo_hash(first_input)?;
    let first_nullifier = poseidon(&[&first_input_hash, &first_input.blinding, nullifier_secret])?;

    let view_root = poseidon_kdf(&[&sk_low, &sk_high])?;
    let tx_viewing_secret = poseidon_kdf(&[&view_root, &right_align_label(b"TSPP/tx_viewing")])?;
    poseidon_kdf(&[&tx_viewing_secret, &first_nullifier])
}

/// The change-blinding KDF step, masked to its low 248 bits (top byte of the
/// 32-byte BE encoding zeroed). SPP's `OutputUtxo` blinding is 31 bytes and the
/// circuit applies the same in-circuit mask (sender.go), so the zone and SPP
/// folds agree on the change output for any deposit blinding.
fn masked_change_blinding(tx_viewing_sk: &[u8; 32]) -> Result<[u8; 32], SquadsProverError> {
    let mut blinding = poseidon_kdf(&[tx_viewing_sk, &right_align_label(b"blinding")])?;
    blinding[0] = 0;
    Ok(blinding)
}

/// Derive the change blinding for the sender output from the viewing secret key,
/// nullifier secret, and the first input UTXO -- the value `Outputs[0].blinding`
/// MUST equal (sender.go). The result is the KDF output masked to its low 248
/// bits, so its top byte is always zero and it round-trips SPP's 31-byte
/// `OutputUtxo` blinding. Exposed so callers can construct a consistent sender
/// change output before proving.
pub fn derive_change_blinding(
    viewing_secret_key: &SecretKey,
    nullifier_secret: &[u8; 32],
    first_input: &ZoneUtxo,
) -> Result<[u8; 32], SquadsProverError> {
    let tx_viewing_sk = tx_viewing_sk_chain(viewing_secret_key, nullifier_secret, first_input)?;
    masked_change_blinding(&tx_viewing_sk)
}

/// The sender-change artefacts a withdrawal/transfer commits to BEFORE proving:
/// the derived change blinding and the 40-byte sender ciphertext (`amount || asset`
/// under AES-CTR keyed by `tx_viewing_sk`). Both are pure, deterministic functions
/// of the sender secrets and the first input, so the caller can build the shared
/// `external_data` (which folds the sender ciphertext and the change output hash)
/// before requesting either proof. [`ZoneWitness::prove`] recomputes the identical
/// values internally, so the two always agree.
pub struct SenderArtifacts {
    pub change_blinding: [u8; 32],
    pub sender_ciphertext: Vec<u8>,
}

/// Compute [`SenderArtifacts`] for a sender change output of `change_amount` of
/// `change_asset` (the already-encoded asset field element).
pub fn derive_sender_artifacts(
    viewing_secret_key: &SecretKey,
    nullifier_secret: &[u8; 32],
    first_input: &ZoneUtxo,
    change_amount: u64,
    change_asset: &[u8; 32],
) -> Result<SenderArtifacts, SquadsProverError> {
    let tx_viewing_sk = tx_viewing_sk_chain(viewing_secret_key, nullifier_secret, first_input)?;
    let change_blinding = masked_change_blinding(&tx_viewing_sk)?;

    let (sender_key, sender_nonce) = key_schedule_pub(&tx_viewing_sk)?;
    let mut sender_ciphertext = Vec::with_capacity(40);
    sender_ciphertext.extend_from_slice(&change_amount.to_be_bytes());
    sender_ciphertext.extend_from_slice(change_asset);
    ctr_apply_pub(&sender_key, &sender_nonce, &mut sender_ciphertext);
    Ok(SenderArtifacts {
        change_blinding,
        sender_ciphertext,
    })
}

/// Decrypt a 40-byte sender-change ciphertext (`amount(8) || asset(32)`) a
/// withdrawal/transfer committed to via [`derive_sender_artifacts`] /
/// [`derive_transfer_artifacts`]. Unlike the recipient slot, the change slot is
/// AES-CTR keyed DIRECTLY by `tx_viewing_sk` (no ECDH ephemeral), so recovering it
/// needs only the sender secrets and the transaction's first input UTXO -- the same
/// [`tx_viewing_sk_chain`] seed the artefacts used. CTR is symmetric, so applying
/// the keystream to the ciphertext yields the plaintext. Returns `(amount,
/// asset_field_element, change_blinding)`; a wrong `first_input` yields garbage, so
/// the caller validates `asset_field_element` against its known assets.
pub fn decrypt_sender_change(
    viewing_secret_key: &SecretKey,
    nullifier_secret: &[u8; 32],
    first_input: &ZoneUtxo,
    ciphertext: &[u8],
) -> Result<(u64, [u8; 32], [u8; 32]), SquadsProverError> {
    if ciphertext.len() != 40 {
        return Err(SquadsProverError::InvalidProofEncoding);
    }
    let tx_viewing_sk = tx_viewing_sk_chain(viewing_secret_key, nullifier_secret, first_input)?;
    let change_blinding = masked_change_blinding(&tx_viewing_sk)?;

    let (sender_key, sender_nonce) = key_schedule_pub(&tx_viewing_sk)?;
    let mut plaintext = ciphertext.to_vec();
    ctr_apply_pub(&sender_key, &sender_nonce, &mut plaintext);

    let amount_bytes: [u8; 8] = plaintext
        .get(..8)
        .ok_or(SquadsProverError::InvalidProofEncoding)?
        .try_into()
        .map_err(|_| SquadsProverError::InvalidProofEncoding)?;
    let asset: [u8; 32] = plaintext
        .get(8..40)
        .ok_or(SquadsProverError::InvalidProofEncoding)?
        .try_into()
        .map_err(|_| SquadsProverError::InvalidProofEncoding)?;
    Ok((u64::from_be_bytes(amount_bytes), asset, change_blinding))
}

/// The transfer artefacts a `(2, 2)` transfer commits to BEFORE proving: the
/// derived sender change blinding, the 40-byte sender ciphertext, the ephemeral
/// `tx_viewing_pk`, and the 71-byte recipient ciphertext (`amount || asset ||
/// blinding`) AES-CTR keyed by the sender<->recipient ECDH shared secret. All are
/// pure, deterministic functions of the sender secrets, the first input, and the
/// recipient viewing pubkey, so the caller can build the shared `external_data`
/// (which folds both ciphertexts and both output hashes) before requesting either
/// proof. [`ZoneWitness::prove`] recomputes the identical values internally, so the
/// two always agree.
pub struct TransferArtifacts {
    pub change_blinding: [u8; 32],
    pub sender_ciphertext: Vec<u8>,
    pub tx_viewing_pk: [u8; 33],
    pub recipient_ciphertext: Vec<u8>,
}

/// Compute [`TransferArtifacts`] for a `(2, 2)` transfer: a sender change output of
/// `change_amount` and a recipient output of `transferred_amount` (asset field
/// elements are the already-encoded values). `recipient_blinding` is the 32-byte
/// field element the recipient output uses; its top byte must be zero (the circuit
/// transmits only its low 31 bytes).
#[allow(clippy::too_many_arguments)]
pub fn derive_transfer_artifacts(
    viewing_secret_key: &SecretKey,
    nullifier_secret: &[u8; 32],
    first_input: &ZoneUtxo,
    change_amount: u64,
    change_asset: &[u8; 32],
    recipient_viewing_pubkey: &P256Pubkey,
    transferred_amount: u64,
    transferred_asset: &[u8; 32],
    recipient_blinding: &[u8; 32],
) -> Result<TransferArtifacts, SquadsProverError> {
    if recipient_blinding[0] != 0 {
        return Err(SquadsProverError::BlindingMismatch);
    }
    let tx_viewing_sk = tx_viewing_sk_chain(viewing_secret_key, nullifier_secret, first_input)?;
    let change_blinding = masked_change_blinding(&tx_viewing_sk)?;

    // Sender change ciphertext: tx_viewing_sk is used directly as the shared secret.
    let (sender_key, sender_nonce) = key_schedule_pub(&tx_viewing_sk)?;
    let mut sender_ciphertext = Vec::with_capacity(40);
    sender_ciphertext.extend_from_slice(&change_amount.to_be_bytes());
    sender_ciphertext.extend_from_slice(change_asset);
    ctr_apply_pub(&sender_key, &sender_nonce, &mut sender_ciphertext);

    // Ephemeral tx_viewing_pk = tx_viewing_sk . G, then the recipient ECDH secret.
    let scalar = scalar_from_fe(&tx_viewing_sk);
    let tx_viewing_pk = scalar_mul_generator_compressed(&scalar);
    let recipient_pk = recipient_public_key(recipient_viewing_pubkey)?;
    let rpk_comp = *recipient_viewing_pubkey.as_bytes();
    let dh = ecdh_x(&scalar, &recipient_pk)?;
    let shared_secret = derive_shared_secret_pub(&dh, &tx_viewing_pk, &rpk_comp)?;
    let (rec_key, rec_nonce) = key_schedule_pub(&shared_secret)?;
    let mut recipient_ciphertext = Vec::with_capacity(71);
    recipient_ciphertext.extend_from_slice(&transferred_amount.to_be_bytes());
    recipient_ciphertext.extend_from_slice(transferred_asset);
    recipient_ciphertext.extend_from_slice(&recipient_blinding[1..32]);
    ctr_apply_pub(&rec_key, &rec_nonce, &mut recipient_ciphertext);

    Ok(TransferArtifacts {
        change_blinding,
        sender_ciphertext,
        tx_viewing_pk,
        recipient_ciphertext,
    })
}

impl ZoneWitness {
    /// Build the witness, request a proof from the prover at `server_address`, and
    /// return the proof and computed public-input hash.
    pub fn prove(self, server_address: &str) -> Result<ZoneProofResult, SquadsProverError> {
        let n_inputs = self.inputs.len();
        let n_outputs = self.outputs.len();
        let shape = (n_inputs as u8, n_outputs as u8);
        if !ZONE_SUPPORTED_SHAPES.contains(&shape) {
            return Err(SquadsProverError::UnsupportedShape(n_inputs, n_outputs));
        }
        if self.inputs.is_empty() {
            return Err(SquadsProverError::UnsupportedShape(n_inputs, n_outputs));
        }
        let has_recipient = n_outputs == 2;
        if has_recipient != self.recipient.is_some() {
            return Err(SquadsProverError::UnsupportedShape(n_inputs, n_outputs));
        }
        if self.inputs.first().is_some_and(|input| input.is_dummy) {
            return Err(SquadsProverError::DummyFirstInput);
        }

        // Sender output is Outputs[0].
        let sender_output = self.outputs.first().ok_or(SquadsProverError::Poseidon)?;

        // --- private_tx_hash (transaction.go) ---
        // A dummy slot contributes [0u8; 32], matching the circuit's
        // Select(dummy, 0, hash) and the SPP-side fold over the same hashes.
        let input_hashes: Vec<[u8; 32]> = self
            .inputs
            .iter()
            .map(|input| {
                if input.is_dummy {
                    Ok([0u8; 32])
                } else {
                    utxo_hash(input)
                }
            })
            .collect::<Result<_, _>>()?;
        let output_hashes: Vec<[u8; 32]> = self
            .outputs
            .iter()
            .map(utxo_hash)
            .collect::<Result<_, _>>()?;
        let priv_tx_hash =
            private_tx_hash(&input_hashes, &output_hashes, &self.external_data_hash)?;

        // --- sender viewing-key commitment (view_key.go) ---
        let viewing_sk_be: [u8; 32] = {
            let mut b = [0u8; 32];
            b.copy_from_slice(self.viewing_secret_key.to_bytes().as_slice());
            b
        };
        let (_sk_low, _sk_high, commitment) = viewing_commitment(&viewing_sk_be)?;

        // --- tx_viewing_sk KDF chain (sender.go:37-49) ---
        let first_input = self.inputs.first().ok_or(SquadsProverError::Poseidon)?;
        let tx_viewing_sk = tx_viewing_sk_chain(
            &self.viewing_secret_key,
            &self.nullifier_secret,
            first_input,
        )?;

        // change blinding = low 248 bits of PoseidonKDF(tx_viewing_sk, "blinding")
        // (sender.go); mirrors the circuit constraint on Outputs[0].
        let change_blinding = masked_change_blinding(&tx_viewing_sk)?;
        if change_blinding != sender_output.blinding {
            return Err(SquadsProverError::BlindingMismatch);
        }

        // --- sender ciphertext (sender.go:92-103) ---
        // KeySchedule(tx_viewing_sk, nil, 0): tx_viewing_sk IS the shared secret.
        let (sender_key, sender_nonce) = key_schedule_pub(&tx_viewing_sk)?;
        let mut sender_plaintext = Vec::with_capacity(40);
        sender_plaintext.extend_from_slice(&sender_output.amount.to_be_bytes());
        sender_plaintext.extend_from_slice(&sender_output.asset);
        let mut sender_ciphertext = sender_plaintext.clone();
        ctr_apply_pub(&sender_key, &sender_nonce, &mut sender_ciphertext);
        let sender_ciphertext_hash = ciphertext_hash(&sender_ciphertext)?;

        let sender_account = sender_account_hash(
            &sender_output.owner_key_hash,
            &commitment,
            &sender_output.nullifier_pubkey,
        )?;

        // --- public input chain (circuit.go:90-112) ---
        let mut chain: Vec<[u8; 32]> = vec![
            priv_tx_hash,
            self.public_amount,
            sender_account,
            sender_ciphertext_hash,
        ];

        // --- recipient (transfer only) ---
        let mut recipient_ciphertext = Vec::new();
        let mut tx_viewing_pk_out: Option<[u8; 33]> = None;
        if let Some(recipient) = &self.recipient {
            let recipient_output = self.outputs.get(1).ok_or(SquadsProverError::Poseidon)?;

            // tx_viewing_pk = tx_viewing_sk · G (compressed). circuit.go:100-103.
            let scalar = scalar_from_fe(&tx_viewing_sk);
            let tx_viewing_pk_comp = scalar_mul_generator_compressed(&scalar);
            tx_viewing_pk_out = Some(tx_viewing_pk_comp);
            let (tx_pk_lo, tx_pk_hi) = pack33(&tx_viewing_pk_comp);

            // recipient ECDH shared secret (recipient.go:58-62).
            let recipient_pk = recipient_public_key(&recipient.viewing_pubkey)?;
            let rpk_comp = *recipient.viewing_pubkey.as_bytes();
            let dh = ecdh_x(&scalar, &recipient_pk)?;
            let shared_secret = derive_shared_secret_pub(&dh, &tx_viewing_pk_comp, &rpk_comp)?;
            let (rec_key, rec_nonce) = key_schedule_pub(&shared_secret)?;

            // recipient plaintext: amount(8) || asset(32) || blinding(31).
            let mut rec_plaintext = Vec::with_capacity(71);
            rec_plaintext.extend_from_slice(&recipient_output.amount.to_be_bytes());
            rec_plaintext.extend_from_slice(&recipient_output.asset);
            // blinding is a 32-byte BE field element; the circuit encodes its low
            // 31 bytes (FieldToBytesBE(blinding, 31)). BN254 elements are < 2^248,
            // so the top byte is always zero -- assert it to avoid silent loss.
            if recipient_output.blinding[0] != 0 {
                return Err(SquadsProverError::BlindingMismatch);
            }
            rec_plaintext.extend_from_slice(&recipient_output.blinding[1..32]);
            recipient_ciphertext = rec_plaintext.clone();
            ctr_apply_pub(&rec_key, &rec_nonce, &mut recipient_ciphertext);
            let recipient_ciphertext_hash = ciphertext_hash(&recipient_ciphertext)?;

            let recipient_account = recipient_account_hash(
                &recipient.owner_key_hash,
                &rpk_comp,
                &recipient.nullifier_pubkey,
            )?;

            chain.push(tx_pk_lo);
            chain.push(tx_pk_hi);
            chain.push(recipient_account);
            chain.push(recipient_ciphertext_hash);
        }

        // --- proposal hash (proposal.go:17) ---
        let proposal_hash = match &self.proposal {
            Some(p) => poseidon(&[&p.amount, &p.recipient, &p.blinding, &p.public_amount])?,
            None => [0u8; 32],
        };
        chain.push(proposal_hash);

        let public_input_hash = hash_chain(&chain)?;

        // --- request ---
        let request = self.build_request(
            n_inputs as u32,
            n_outputs as u32,
            &commitment,
            &viewing_sk_be,
            &public_input_hash,
        )?;
        let proof_json = send_prove_request(server_address, &request)?;
        let proof = gnark_json_to_transact_bytes(&proof_json)?;

        Ok(ZoneProofResult {
            proof,
            public_input_hash,
            private_tx_hash: priv_tx_hash,
            commitment,
            proposal_hash,
            sender_ciphertext,
            recipient_ciphertext,
            change_blinding,
            tx_viewing_pk: tx_viewing_pk_out,
        })
    }

    fn build_request(
        &self,
        n_inputs: u32,
        n_outputs: u32,
        commitment: &[u8; 32],
        viewing_sk_be: &[u8; 32],
        public_input_hash: &[u8; 32],
    ) -> Result<String, SquadsProverError> {
        let inputs: Vec<UtxoJson> = self.inputs.iter().map(utxo_json).collect();
        // Dummy flags for inputs[1..] (marshal.go `inputsDummy`), one 0/1 field
        // element per slot; inputs[0] is structurally real.
        let inputs_dummy: Vec<String> = self
            .inputs
            .iter()
            .skip(1)
            .map(|input| fe_hex(&right_align_u64(u64::from(input.is_dummy))))
            .collect();
        let outputs: Vec<UtxoJson> = self.outputs.iter().map(utxo_json).collect();

        let sender_output = self.outputs.first().ok_or(SquadsProverError::Poseidon)?;
        let sender = SenderJson {
            owner: fe_hex(&sender_output.owner_key_hash),
            shared_viewing_secret_key_commitment: fe_hex(commitment),
            nullifier_pubkey: fe_hex(&sender_output.nullifier_pubkey),
            nullifier_secret: fe_hex(&self.nullifier_secret),
            shared_viewing_secret_key: fe_hex(viewing_sk_be),
        };

        // The recipient is assigned even on the withdrawal shape (gnark requires
        // every signal): zero owner/nullifier and an all-zero 65-byte pubkey.
        let recipient = match &self.recipient {
            Some(r) => {
                let uncompressed = uncompressed_65(&r.viewing_pubkey)?;
                RecipientJson {
                    owner: fe_hex(&r.owner_key_hash),
                    nullifier_pubkey: fe_hex(&r.nullifier_pubkey),
                    viewing_pubkey: uncompressed.iter().map(|b| format!("0x{b:x}")).collect(),
                }
            }
            None => RecipientJson {
                owner: fe_hex(&[0u8; 32]),
                nullifier_pubkey: fe_hex(&[0u8; 32]),
                viewing_pubkey: vec![fe_hex(&[0u8; 32]); 65],
            },
        };

        let (proposal, enable) = match &self.proposal {
            Some(p) => (
                ProposalJson {
                    amount: fe_hex(&p.amount),
                    recipient: fe_hex(&p.recipient),
                    blinding: fe_hex(&p.blinding),
                    public_amount: fe_hex(&p.public_amount),
                },
                fe_hex(&right_align_u64(1)),
            ),
            None => (
                ProposalJson {
                    amount: fe_hex(&[0u8; 32]),
                    recipient: fe_hex(&[0u8; 32]),
                    blinding: fe_hex(&[0u8; 32]),
                    public_amount: fe_hex(&[0u8; 32]),
                },
                fe_hex(&[0u8; 32]),
            ),
        };

        let json = ZoneRequestJson {
            circuit_type: "squads-zone".to_string(),
            n_inputs,
            n_outputs,
            inputs,
            inputs_dummy,
            outputs,
            external_data_hash: fe_hex(&self.external_data_hash),
            sender,
            recipient,
            proposal,
            enable_proposal_hash: enable,
            public_amount: fe_hex(&self.public_amount),
            public_input_hash: fe_hex(public_input_hash),
        };
        serde_json::to_string(&json)
            .map_err(|e| SquadsProverError::ProofParse(format!("request serialization: {e}")))
    }
}
