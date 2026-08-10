//! Ring-proof input builder and prover glue (gated under the `prover` feature).
//!
//! Mirrors the squads ring circuit
//! `prover/server/circuits/squads/ring/{circuit.go,view_key.go,sender.go,
//! recipient.go,proposal.go}` and the shared gadgets in
//! `prover/server/circuits/ring-utils/{poseidon_kdf.go,p256/*}` and
//! `prover/server/circuits/{spp_transaction/*,gadget/*,verifiable-encryption/aes/*}`
//! byte-for-byte.
//!
//! Given the sender's viewing secret key, the input/output UTXOs, the recipient's
//! viewing pubkey (transfer only), an optional proposal, and the public amount,
//! this builds the sender and recipient AES-CTR ciphertexts, derives the
//! change blinding via the Poseidon KDF chain, recomputes every UTXO/account hash
//! and the public-input hash, serialises the `squads-ring` JSON request, requests a
//! Groth16 proof from the prover server, and returns the 192-byte compressed proof
//! plus the computed public-input hash and published artefacts.
//!
//! The Go prover assigns every field verbatim and the circuit asserts that the
//! supplied `PublicInputHash` equals the chain it recomputes (witness.go:59,
//! circuit.go:112), so the host computation here must match the circuit exactly or
//! proving fails outright.

use p256::{PublicKey, SecretKey};
use serde::Serialize;
use zolana_hasher::{Hasher, Poseidon};
use zolana_keypair::P256Pubkey;

use crate::{
    crypto::{
        self, ecdh_x, fe_from_u64, scalar_from_fe, scalar_mul_generator_compressed, uncompressed_65,
    },
    proposal::{proposal_commitment_hash, proposal_hash_fields, ProposalOperation},
    prover::{
        error::SquadsProverError,
        proof::{gnark_json_to_recursion_proof, gnark_json_to_transact_bytes, RecursionProof},
        server::{fe_hex, send_prove_request},
        shared_viewing_key::{
            ciphertext_hash, ctr_apply_pub, derive_shared_secret_pub, hash_chain, key_schedule_pub,
            pack33,
        },
    },
};

pub use zolana_squads_interface::circuits::RING_SUPPORTED_SHAPES;

/// A single UTXO as the prover witnesses it. `owner_key_hash` and
/// `nullifier_pubkey` reconstruct the output's `owner_hash =
/// Poseidon(owner_key_hash, nullifier_pubkey)` (transaction `OwnerHashGadget`).
/// All scalar fields are 32-byte big-endian field elements.
#[derive(Clone)]
pub struct RingUtxo {
    /// Owner key hash (the `Owner` half of `OwnerHashGadget`).
    pub owner_key_hash: [u8; 32],
    /// Nullifier pubkey bound into `owner_hash`.
    pub nullifier_pubkey: [u8; 32],
    pub asset: [u8; 32],
    /// `u64` amount as a field element (big-endian, only low 8 bytes used).
    pub amount: u64,
    pub blinding: [u8; 32],
    pub program_data_hash: [u8; 32],
    pub ring_data_hash: [u8; 32],
    pub ring_program_id: [u8; 32],
    /// Marks an unused input slot. A dummy contributes `[0u8; 32]` to the
    /// `private_tx_hash` input fold (matching the SPP circuits' `IsDummy`
    /// convention) and the circuit pins its amount to 0. `inputs[0]` can never
    /// be a dummy: its nullifier seeds the `tx_viewing_sk` KDF.
    pub is_dummy: bool,
}

/// The recipient of a transfer. The prover holds no recipient secret, so only the
/// recipient's public account identity and viewing pubkey are provided.
#[derive(Clone)]
pub struct RingRecipient {
    pub owner_key_hash: [u8; 32],
    pub nullifier_pubkey: [u8; 32],
    pub viewing_pubkey: P256Pubkey,
}

/// An optional proposal commitment bound into the proof.
#[derive(Clone)]
pub struct RingProposal {
    pub amount: [u8; 32],
    pub recipient: [u8; 32],
    /// `hash_bytes(asset mint)`, constrained against every real input/output.
    pub asset: [u8; 32],
    /// Transfer: recipient VKA owner field. Withdrawal: `hash_bytes` of the
    /// public SOL/SPL destination checked by the program.
    pub destination: [u8; 32],
    pub blinding: [u8; 32],
    pub public_amount: [u8; 32],
}

/// Inputs to a ring proof.
pub struct RingProofInputs {
    /// The sender's shared viewing secret key (a P-256 scalar). Drives the change
    /// blinding KDF chain and the sender/recipient ciphertext keys.
    pub viewing_secret_key: SecretKey,
    /// The sender's nullifier secret (a BN254-range field element).
    pub nullifier_secret: [u8; 32],

    /// Spent input UTXOs. At least one is required, and `Inputs[0]` seeds the KDF
    /// chain.
    pub inputs: Vec<RingUtxo>,
    /// Output UTXOs. `Outputs[0]` is the sender change. For a transfer,
    /// `Outputs[1]` is the recipient output.
    pub outputs: Vec<RingUtxo>,
    /// External data hash folded into `private_tx_hash`.
    pub external_data_hash: [u8; 32],

    /// Present iff this is a transfer (2 outputs). `None` for a withdrawal.
    pub recipient: Option<RingRecipient>,

    /// The proposal commitment (enabled iff `Some`).
    pub proposal: Option<RingProposal>,

    /// The public withdrawn amount (0 for a transfer).
    pub public_amount: [u8; 32],
}

/// The published artefacts and proof of a ring proof.
pub struct RingProofResult {
    /// The 192-byte compressed Groth16 proof (BSB22 layout, commitment included).
    pub proof: [u8; 192],
    /// The public-input hash the circuit constrains and the program recomputes.
    pub public_input_hash: [u8; 32],
    /// `Transaction.Hash` bound into the public-input chain. The caller passes this
    /// verbatim as `TransactIxData.private_tx_hash` so the program recomputes the
    /// same chain.
    pub private_tx_hash: [u8; 32],
    /// `Poseidon(skLow, skHigh)` viewing-key commitment. It equals the sender viewing
    /// key account's `shared_viewing_key_commitment` the program reads.
    pub commitment: [u8; 32],
    /// Domain-separated v2 commitment of the private proposal core plus its
    /// operation, asset, and destination, or `0` when no proposal. The program
    /// recomputes it from the proposal record and execution accounts.
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
    /// The chain `public_input_hash` folds, in order. A fold binds this to the
    /// proof, so a leg cannot restate the spend it proved.
    pub public_input_chain: Vec<[u8; 32]>,
    /// The same proof in the form a fold's recursive verifier reads.
    pub recursion_proof: RecursionProof,
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

/// `OwnerHashGadget`: `Poseidon(owner_key_hash, nullifier_pubkey)` (proof_gadgets/
/// inputs.go `OwnerHashGadget`).
fn owner_hash(
    owner_key_hash: &[u8; 32],
    nullifier_pubkey: &[u8; 32],
) -> Result<[u8; 32], SquadsProverError> {
    poseidon(&[owner_key_hash, nullifier_pubkey])
}

/// `UtxoHashCircuit` (spp_transaction/utxo.go `UtxoCircuitFields::DefineGadget`):
/// `Poseidon(UtxoDomain, asset, amount, data_hash, Poseidon(ring_data_hash,
/// ring_program_id), Poseidon(owner_hash, blinding))`. The fields here are
/// pre-encoded field elements, so the fold is replicated structurally
/// (`zolana_transaction::utxo::utxo_hash` is the same fold over raw
/// address-typed inputs).
fn utxo_hash(u: &RingUtxo) -> Result<[u8; 32], SquadsProverError> {
    let owner = owner_hash(&u.owner_key_hash, &u.nullifier_pubkey)?;
    let inner = poseidon(&[&owner, &u.blinding])?;
    let ring_hash = poseidon(&[&u.ring_data_hash, &u.ring_program_id])?;
    let domain = fe_from_u64(u64::from(zolana_interface::UTXO_DOMAIN));
    let amount = fe_from_u64(u.amount);
    poseidon(&[
        &domain,
        &u.asset,
        &amount,
        &u.program_data_hash,
        &ring_hash,
        &inner,
    ])
}

/// `Transaction.Hash` (transaction.go): the shared SPP fold `Poseidon(
/// HashChain(inputs), HashChain(outputs), HashChain(addresses),
/// external_data_hash)` with one all-zero address hash per input (the ring
/// circuit hardcodes them to zero, and only the SPP rail creates addresses).
/// Delegates to the canonical implementation in `zolana-transaction`.
fn private_tx_hash(
    input_hashes: &[[u8; 32]],
    output_hashes: &[[u8; 32]],
    external_data_hash: &[u8; 32],
) -> Result<[u8; 32], SquadsProverError> {
    zolana_transaction::instructions::transact::PrivateTxHash::new(
        input_hashes,
        output_hashes,
        external_data_hash,
    )
    .hash()
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

/// `Poseidon(skLow, skHigh)` viewing-key commitment (view_key.go:64), with the
/// limbs the witness also carries.
fn viewing_commitment(viewing_sk_be: &[u8; 32]) -> Result<ViewingCommitment, SquadsProverError> {
    let (sk_low, sk_high) = crypto::field_limbs(viewing_sk_be);
    Ok((sk_low, sk_high, crypto::hash_field(viewing_sk_be)?))
}

/// Validate the recipient point lies on the curve and return its `PublicKey`.
fn recipient_public_key(pk: &P256Pubkey) -> Result<PublicKey, SquadsProverError> {
    pk.to_p256().map_err(|_| SquadsProverError::InvalidPubkey)
}

#[derive(Serialize)]
struct UtxoJson {
    #[serde(rename = "ownerHash")]
    owner_hash: String,
    asset: String,
    amount: String,
    blinding: String,
    #[serde(rename = "programDataHash")]
    program_data_hash: String,
    #[serde(rename = "ringDataHash")]
    ring_data_hash: String,
    #[serde(rename = "ringProgramId")]
    ring_program_id: String,
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
    asset: String,
    destination: String,
    blinding: String,
    #[serde(rename = "publicAmount")]
    public_amount: String,
}

#[derive(Serialize)]
struct RingRequestJson {
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

fn utxo_json(u: &RingUtxo) -> Result<UtxoJson, SquadsProverError> {
    Ok(UtxoJson {
        owner_hash: fe_hex(&owner_hash(&u.owner_key_hash, &u.nullifier_pubkey)?),
        asset: fe_hex(&u.asset),
        amount: fe_hex(&fe_from_u64(u.amount)),
        blinding: fe_hex(&u.blinding),
        program_data_hash: fe_hex(&u.program_data_hash),
        ring_data_hash: fe_hex(&u.ring_data_hash),
        ring_program_id: fe_hex(&u.ring_program_id),
    })
}

/// The sender's `tx_viewing_sk` KDF chain (sender.go:37-49): derived from the
/// viewing secret key, the nullifier secret, and the first input UTXO. It seeds
/// both the change blinding and the sender ciphertext key, so both
/// [`derive_change_blinding`] and [`derive_sender_artifacts`] share this fold.
fn tx_viewing_sk_chain(
    viewing_secret_key: &SecretKey,
    nullifier_secret: &[u8; 32],
    first_input: &RingUtxo,
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
/// 32-byte BE encoding zeroed). SPP's `SppProofOutputUtxo` blinding is 31 bytes and the
/// circuit applies the same in-circuit mask (sender.go), so the ring and SPP
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
/// `SppProofOutputUtxo` blinding. Exposed so callers can construct a consistent sender
/// change output before proving.
pub fn derive_change_blinding(
    viewing_secret_key: &SecretKey,
    nullifier_secret: &[u8; 32],
    first_input: &RingUtxo,
) -> Result<[u8; 32], SquadsProverError> {
    let tx_viewing_sk = tx_viewing_sk_chain(viewing_secret_key, nullifier_secret, first_input)?;
    masked_change_blinding(&tx_viewing_sk)
}

/// The sender-change artefacts a withdrawal/transfer commits to BEFORE proving:
/// the derived change blinding and the 40-byte sender ciphertext (`amount || asset`
/// under AES-CTR keyed by `tx_viewing_sk`). Both are pure, deterministic functions
/// of the sender secrets and the first input, so the caller can build the shared
/// `external_data` (which folds the sender ciphertext and the change output hash)
/// before requesting either proof. [`RingProofInputs::prove`] recomputes the identical
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
    first_input: &RingUtxo,
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
/// [`TransferOutputs::derive`]. Unlike the recipient slot, the change slot is
/// AES-CTR keyed DIRECTLY by `tx_viewing_sk` (no ECDH ephemeral), so recovering it
/// needs only the sender secrets and the transaction's first input UTXO -- the same
/// [`tx_viewing_sk_chain`] seed the artefacts used. CTR is symmetric, so applying
/// the keystream to the ciphertext yields the plaintext. Returns `(amount,
/// asset_field_element, change_blinding)`. A wrong `first_input` yields garbage, so
/// the caller validates `asset_field_element` against its known assets.
pub fn decrypt_sender_change(
    viewing_secret_key: &SecretKey,
    nullifier_secret: &[u8; 32],
    first_input: &RingUtxo,
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

/// The transfer artefacts a `(2, 2)` transfer commits to BEFORE proving. The
/// derived change blinding, the 40-byte sender ciphertext, the ephemeral
/// `tx_viewing_pk`, and the 71-byte recipient ciphertext (`amount || asset ||
/// blinding`) AES-CTR keyed by the sender<->recipient ECDH shared secret. Pure
/// functions of the sender secrets, the first input, and the recipient viewing
/// pubkey, like [`SenderArtifacts`].
pub struct TransferArtifacts {
    pub change_blinding: [u8; 32],
    pub sender_ciphertext: Vec<u8>,
    pub tx_viewing_pk: [u8; 33],
    pub recipient_ciphertext: Vec<u8>,
}

/// The two plaintext outputs of a `(2, 2)` transfer. Asset values are the
/// already-encoded field elements.
pub struct TransferOutputs<'a> {
    /// The sender change amount.
    pub change_amount: u64,
    /// The change output's asset.
    pub change_asset: &'a [u8; 32],
    /// The recipient's shared viewing public key, the ECDH peer for the recipient
    /// ciphertext.
    pub recipient_viewing_pubkey: &'a P256Pubkey,
    /// The amount the recipient output carries.
    pub transferred_amount: u64,
    /// The recipient output's asset.
    pub transferred_asset: &'a [u8; 32],
    /// The blinding the recipient output uses. Its top byte must be zero, because
    /// the circuit transmits only its low 31 bytes.
    pub recipient_blinding: &'a [u8; 32],
}

impl TransferOutputs<'_> {
    /// Compute the [`TransferArtifacts`] for these outputs under the sender secrets
    /// and the transaction's `first_input`, which together seed the KDF chain.
    pub fn derive(
        self,
        viewing_secret_key: &SecretKey,
        nullifier_secret: &[u8; 32],
        first_input: &RingUtxo,
    ) -> Result<TransferArtifacts, SquadsProverError> {
        if self.recipient_blinding[0] != 0 {
            return Err(SquadsProverError::BlindingMismatch);
        }
        let tx_viewing_sk = tx_viewing_sk_chain(viewing_secret_key, nullifier_secret, first_input)?;
        let change_blinding = masked_change_blinding(&tx_viewing_sk)?;

        let (sender_key, sender_nonce) = key_schedule_pub(&tx_viewing_sk)?;
        let mut sender_ciphertext = Vec::with_capacity(40);
        sender_ciphertext.extend_from_slice(&self.change_amount.to_be_bytes());
        sender_ciphertext.extend_from_slice(self.change_asset);
        ctr_apply_pub(&sender_key, &sender_nonce, &mut sender_ciphertext);

        let scalar = scalar_from_fe(&tx_viewing_sk);
        let tx_viewing_pk = scalar_mul_generator_compressed(&scalar);
        let recipient_pk = recipient_public_key(self.recipient_viewing_pubkey)?;
        let rpk_comp = *self.recipient_viewing_pubkey.as_bytes();
        let dh = ecdh_x(&scalar, &recipient_pk)?;
        let shared_secret = derive_shared_secret_pub(&dh, &tx_viewing_pk, &rpk_comp)?;
        let (rec_key, rec_nonce) = key_schedule_pub(&shared_secret)?;
        let mut recipient_ciphertext = Vec::with_capacity(71);
        recipient_ciphertext.extend_from_slice(&self.transferred_amount.to_be_bytes());
        recipient_ciphertext.extend_from_slice(self.transferred_asset);
        recipient_ciphertext.extend_from_slice(&self.recipient_blinding[1..32]);
        ctr_apply_pub(&rec_key, &rec_nonce, &mut recipient_ciphertext);

        Ok(TransferArtifacts {
            change_blinding,
            sender_ciphertext,
            tx_viewing_pk,
            recipient_ciphertext,
        })
    }
}

impl RingProofInputs {
    /// Assemble the inputs, request a proof from the prover at `server_address`, and
    /// return the proof and computed public-input hash.
    pub fn prove(self, server_address: &str) -> Result<RingProofResult, SquadsProverError> {
        let n_inputs = self.inputs.len();
        let n_outputs = self.outputs.len();
        let unsupported = || SquadsProverError::UnsupportedShape(n_inputs, n_outputs);
        let shape = (
            u8::try_from(n_inputs).map_err(|_| unsupported())?,
            u8::try_from(n_outputs).map_err(|_| unsupported())?,
        );
        if !RING_SUPPORTED_SHAPES.contains(&shape) {
            return Err(unsupported());
        }
        if self.inputs.is_empty() {
            return Err(unsupported());
        }
        let has_recipient = n_outputs == 2;
        if has_recipient != self.recipient.is_some() {
            return Err(unsupported());
        }
        if self.inputs.first().is_some_and(|input| input.is_dummy) {
            return Err(SquadsProverError::DummyFirstInput);
        }

        let sender_output = self.outputs.first().ok_or(SquadsProverError::MissingSlot)?;

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

        let viewing_sk_be: [u8; 32] = {
            let mut b = [0u8; 32];
            b.copy_from_slice(self.viewing_secret_key.to_bytes().as_slice());
            b
        };
        let (_sk_low, _sk_high, commitment) = viewing_commitment(&viewing_sk_be)?;

        let first_input = self.inputs.first().ok_or(SquadsProverError::MissingSlot)?;
        let tx_viewing_sk = tx_viewing_sk_chain(
            &self.viewing_secret_key,
            &self.nullifier_secret,
            first_input,
        )?;

        let change_blinding = masked_change_blinding(&tx_viewing_sk)?;
        if change_blinding != sender_output.blinding {
            return Err(SquadsProverError::BlindingMismatch);
        }

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

        // The chain order binds the statement and must match circuit.go:90-112.
        let mut chain: Vec<[u8; 32]> = vec![
            priv_tx_hash,
            self.public_amount,
            sender_account,
            sender_ciphertext_hash,
        ];

        let mut recipient_ciphertext = Vec::new();
        let mut tx_viewing_pk_out: Option<[u8; 33]> = None;
        if let Some(recipient) = &self.recipient {
            let recipient_output = self.outputs.get(1).ok_or(SquadsProverError::MissingSlot)?;

            let scalar = scalar_from_fe(&tx_viewing_sk);
            let tx_viewing_pk_comp = scalar_mul_generator_compressed(&scalar);
            tx_viewing_pk_out = Some(tx_viewing_pk_comp);
            let (tx_pk_lo, tx_pk_hi) = pack33(&tx_viewing_pk_comp);

            let recipient_pk = recipient_public_key(&recipient.viewing_pubkey)?;
            let rpk_comp = *recipient.viewing_pubkey.as_bytes();
            let dh = ecdh_x(&scalar, &recipient_pk)?;
            let shared_secret = derive_shared_secret_pub(&dh, &tx_viewing_pk_comp, &rpk_comp)?;
            let (rec_key, rec_nonce) = key_schedule_pub(&shared_secret)?;

            let mut rec_plaintext = Vec::with_capacity(71);
            rec_plaintext.extend_from_slice(&recipient_output.amount.to_be_bytes());
            rec_plaintext.extend_from_slice(&recipient_output.asset);
            // The circuit encodes only the low 31 bytes (FieldToBytesBE(blinding,
            // 31)). BN254 elements are < 2^248, so the top byte is always zero.
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

        let operation = if self.recipient.is_some() {
            ProposalOperation::Transfer
        } else {
            ProposalOperation::Withdrawal
        };
        let proposal_hash = match &self.proposal {
            Some(p) => {
                let private_core = proposal_hash_fields(
                    operation,
                    &p.amount,
                    &p.recipient,
                    &p.blinding,
                    &p.public_amount,
                )
                .map_err(|_| SquadsProverError::Poseidon)?;
                proposal_commitment_hash(operation, &private_core, &p.asset, &p.destination)
                    .map_err(|_| SquadsProverError::Poseidon)?
            }
            None => [0u8; 32],
        };
        chain.push(proposal_hash);

        let public_input_hash = hash_chain(&chain)?;

        let request = self.build_request(
            u32::from(shape.0),
            u32::from(shape.1),
            &commitment,
            &viewing_sk_be,
            &public_input_hash,
        )?;
        let proof_json = send_prove_request(server_address, &request)?;
        let proof = gnark_json_to_transact_bytes(&proof_json)?;
        let recursion_proof = gnark_json_to_recursion_proof(&proof_json)?;

        Ok(RingProofResult {
            proof,
            public_input_hash,
            public_input_chain: chain,
            recursion_proof,
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
        let inputs: Vec<UtxoJson> = self
            .inputs
            .iter()
            .map(utxo_json)
            .collect::<Result<_, _>>()?;
        let inputs_dummy: Vec<String> = self
            .inputs
            .iter()
            .skip(1)
            .map(|input| fe_hex(&fe_from_u64(u64::from(input.is_dummy))))
            .collect();
        let outputs: Vec<UtxoJson> = self
            .outputs
            .iter()
            .map(utxo_json)
            .collect::<Result<_, _>>()?;

        let sender_output = self.outputs.first().ok_or(SquadsProverError::MissingSlot)?;
        let sender = SenderJson {
            owner: fe_hex(&sender_output.owner_key_hash),
            shared_viewing_secret_key_commitment: fe_hex(commitment),
            nullifier_pubkey: fe_hex(&sender_output.nullifier_pubkey),
            nullifier_secret: fe_hex(&self.nullifier_secret),
            shared_viewing_secret_key: fe_hex(viewing_sk_be),
        };

        // gnark requires every signal, so the withdrawal shape still assigns a
        // zeroed recipient.
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
                    asset: fe_hex(&p.asset),
                    destination: fe_hex(&p.destination),
                    blinding: fe_hex(&p.blinding),
                    public_amount: fe_hex(&p.public_amount),
                },
                fe_hex(&fe_from_u64(1)),
            ),
            None => (
                ProposalJson {
                    amount: fe_hex(&[0u8; 32]),
                    recipient: fe_hex(&[0u8; 32]),
                    asset: fe_hex(&[0u8; 32]),
                    destination: fe_hex(&[0u8; 32]),
                    blinding: fe_hex(&[0u8; 32]),
                    public_amount: fe_hex(&[0u8; 32]),
                },
                fe_hex(&[0u8; 32]),
            ),
        };

        let json = RingRequestJson {
            circuit_type: "squads-ring".to_string(),
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
            .map_err(|e| SquadsProverError::RequestSerialize(format!("{e}")))
    }
}
