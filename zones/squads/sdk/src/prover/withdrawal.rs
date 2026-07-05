//! Paired zone + SPP-rail withdrawal proof builder (gated under the `prover`
//! feature).
//!
//! A squads withdrawal forwards TWO proofs that must agree on one shared
//! `private_tx_hash`:
//! 1. the squads ZONE proof (this crate's [`ZoneWitness`]), verified on-chain by
//!    the squads program, and
//! 2. the SPP zone-rail proof ([`ZoneTransferP256Prover`], `transfer_p256_zone`),
//!    verified on-chain by SPP after the zone-auth-signed CPI.
//!
//! Consistency is achieved by construction: this builder computes ONE
//! [`ExternalData`] (the settlement recipient/vault, the change output hash, and
//! the sender ciphertext all folded into `external_data_hash`) and feeds the SAME
//! hash into both proofs, and encodes the squads [`ZoneUtxo`] fields so its
//! `utxo_hash` fold matches SPP's [`Utxo`]/[`OutputUtxo`] fold exactly (asset via
//! `hash_field`, blinding right-aligned into 32 bytes, `zone_program_id` via
//! `hash_field`, owner via `Poseidon(owner_pk_field, nullifier_pubkey)`). The
//! builder then cross-checks that the two provers produced the same
//! `private_tx_hash`, nullifier, and change hash.
//!
//! The change blinding is a pure function of the sender secrets and the first
//! input ([`derive_change_blinding`](super::zone::derive_change_blinding)),
//! masked to its low 248 bits on both sides
//! (the circuit and the Rust derivation), so its top byte is always zero and it
//! round-trips SPP's 31-byte `OutputUtxo` blinding for any deposit blinding.

use p256::SecretKey;
use zolana_client::{
    Proof, ProofCompressed, ProverClient, PublicAmounts, Shape, SpendProof, TransferSpendInput,
    ZoneTransferP256Prover,
};
use zolana_interface::instruction::{
    instruction_data::transact::OutputCiphertext, tag::ZONE_TRANSACT,
};
use zolana_keypair::{
    hash::{hash_field, sha256},
    NullifierKey, P256Pubkey, PublicKey, ShieldedAddress, SigningKey,
};
use zolana_transaction::{
    instructions::transact::signed_transaction::{asset_field, signed_to_field},
    Address, Data, ExternalData, OutputUtxo, Utxo,
};

use zolana_squads_interface::SQUADS_ZONE_PROGRAM_ID;

use crate::prover::{
    error::SquadsProverError,
    zone::{derive_sender_artifacts, ZoneProposal, ZoneUtxo, ZoneWitness},
};

/// The deterministic P256 identity behind a squads viewing key account: the
/// secrets needed to spend a zone UTXO owned by that account.
#[derive(Clone)]
pub struct SquadsIdentity {
    /// P256 owner (signing) key; signs the SPP spend over `sha256(private_tx_hash)`.
    pub owner_secret: SecretKey,
    /// Nullifier secret (31 bytes); `NullifierKey.pubkey()` == the VKA's
    /// `nullifier_pubkey`.
    pub nullifier_secret: [u8; 31],
    /// P256 viewing key; the zone circuit's shared viewing secret key.
    pub viewing_secret: SecretKey,
}

/// One deposited zone UTXO to spend, plus its Photon inclusion / non-inclusion
/// proofs fetched by the caller.
pub struct SquadsWithdrawalInput {
    /// The asset mint (`SOL_MINT` for a SOL withdrawal).
    pub asset: Address,
    /// The full deposited amount held in the UTXO.
    pub amount: u64,
    /// The 31-byte deposit blinding.
    pub blinding: [u8; 31],
    /// State-inclusion + nullifier-non-inclusion proofs for the deposited UTXO.
    pub spend_proof: SpendProof,
}

/// Everything the paired-proof builder needs for a `(1, 1)` withdrawal.
pub struct SquadsWithdrawalRequest {
    pub identity: SquadsIdentity,
    pub input: SquadsWithdrawalInput,
    /// The public amount to withdraw out of the pool. `change = input.amount -
    /// withdrawn` stays as a zone UTXO.
    pub withdrawn: u64,
    /// SPL rail when true (settles `public_spl_amount`), native SOL otherwise.
    pub is_spl: bool,
    /// The external SOL recipient (SOL rail) or `Address::default()` (SPL rail).
    pub user_sol_account: Address,
    /// The recipient's SPL token account (SPL rail) or `Address::default()`.
    pub user_spl_token: Address,
    /// The pool's per-mint SPL vault (SPL rail) or `Address::default()`.
    pub spl_token_interface: Address,
    /// Sha256-BE of the SPP payer address (the squads `payer` account SPP sees).
    pub payer_pubkey_hash: [u8; 32],
    /// Transaction expiry (folded into `external_data_hash`).
    pub expiry_unix_ts: u64,
    /// Per-transaction salt (forwarded to SPP; not bound by `external_data_hash`).
    pub salt: [u8; 16],
    /// The sender-change output ciphertext view tag (forwarded, folded into
    /// `external_data_hash` via the output ciphertext).
    pub sender_view_tag: [u8; 32],
    /// A bound proposal for `execute_proposal`; `None` for a sync `transact`.
    pub proposal: Option<ZoneProposal>,
    /// The prover server URL.
    pub prover_url: String,
}

/// The paired proofs and every field the caller needs to assemble the squads
/// `TransactIxData` / `ExecuteProposalIxData`.
pub struct SquadsWithdrawalProof {
    /// The 192-byte squads zone proof.
    pub zone_proof: [u8; 192],
    /// The 192-byte SPP zone-rail proof, forwarded to SPP.
    pub spp_proof: [u8; 192],
    /// The shared `private_tx_hash` both proofs bind.
    pub private_tx_hash: [u8; 32],
    /// The proposal commitment (0 for a sync `transact`); stored as the
    /// `Proposal.proposal_hash` for `execute_proposal`.
    pub proposal_hash: [u8; 32],
    /// The change output UTXO hash appended to the tree.
    pub change_utxo_hash: [u8; 32],
    /// The spent input's nullifier.
    pub nullifier: [u8; 32],
    /// The spent input's UTXO hash.
    pub input_utxo_hash: [u8; 32],
    /// The spent input's UTXO-tree root-cache index.
    pub utxo_root_index: u16,
    /// The spent input's nullifier-tree root-cache index.
    pub nullifier_root_index: u16,
    /// The 40-byte sender-change ciphertext (`amount || asset`).
    pub sender_ciphertext: [u8; 40],
    /// The derived change blinding (32 bytes; top byte zero).
    pub change_blinding: [u8; 32],
}

/// The rail-agnostic field encodings a squads identity contributes to both proofs.
pub(crate) struct IdentityEncodings {
    pub(crate) owner_p256: P256Pubkey,
    pub(crate) owner_public: PublicKey,
    pub(crate) owner_pk_field: [u8; 32],
    pub(crate) nullifier_key: NullifierKey,
    pub(crate) nullifier_pk: [u8; 32],
    pub(crate) viewing_pubkey: P256Pubkey,
    pub(crate) nullifier_secret_32: [u8; 32],
}

pub(crate) fn identity_encodings(
    identity: &SquadsIdentity,
) -> Result<IdentityEncodings, SquadsProverError> {
    let owner_p256 = P256Pubkey::from_p256(&identity.owner_secret.public_key());
    probe_encodings(
        owner_p256,
        &identity.nullifier_secret,
        &identity.viewing_secret,
    )
}

/// The rail-agnostic field encodings from the sender's *public* owner key plus its
/// spend secrets, with no owner secret. Used by the externalized-signing probe
/// (the sender signs `private_tx_hash` off-box); [`identity_encodings`] delegates
/// here after deriving the owner pubkey from the owner secret.
pub(crate) fn probe_encodings(
    owner_p256: P256Pubkey,
    nullifier_secret: &[u8; 31],
    viewing_secret: &SecretKey,
) -> Result<IdentityEncodings, SquadsProverError> {
    let owner_public = PublicKey::from_p256(&owner_p256);
    let owner_pk_field = owner_public
        .owner_pk_field()
        .map_err(|_| SquadsProverError::InvalidPubkey)?;
    let nullifier_key = NullifierKey::from_secret(*nullifier_secret);
    let nullifier_pk = nullifier_key
        .pubkey()
        .map_err(|_| SquadsProverError::Poseidon)?;
    let viewing_pubkey = P256Pubkey::from_p256(&viewing_secret.public_key());
    let nullifier_secret_32 = right_align_31(nullifier_secret);
    Ok(IdentityEncodings {
        owner_p256,
        owner_public,
        owner_pk_field,
        nullifier_key,
        nullifier_pk,
        viewing_pubkey,
        nullifier_secret_32,
    })
}

/// The spend commitment of one deposited zone UTXO: its leaf `utxo_hash` (to fetch
/// a Photon merkle proof) and its `nullifier` (to fetch a non-inclusion proof).
/// The caller fetches both proofs, then hands them to [`prove_squads_withdrawal`].
pub fn squads_input_commitment(
    identity: &SquadsIdentity,
    asset: Address,
    amount: u64,
    blinding: &[u8; 31],
) -> Result<([u8; 32], [u8; 32]), SquadsProverError> {
    let enc = identity_encodings(identity)?;
    let squads_address = Address::new_from_array(SQUADS_ZONE_PROGRAM_ID);
    let utxo = Utxo {
        owner: enc.owner_public,
        asset,
        amount,
        blinding: *blinding,
        zone_program_id: Some(squads_address),
        data: Data::default(),
    };
    let utxo_hash = utxo
        .hash(&enc.nullifier_pk, &[0u8; 32], &[0u8; 32])
        .map_err(|_| SquadsProverError::Poseidon)?;
    let nullifier = enc
        .nullifier_key
        .nullifier(&utxo_hash, blinding)
        .map_err(|_| SquadsProverError::Poseidon)?;
    Ok((utxo_hash, nullifier))
}

/// A probed withdrawal: every signature-independent step is done (the change
/// output, the shared external data, and the SPP witness whose `private_tx_hash`
/// the owner must sign). [`ProbedWithdrawal::finalize`] takes the P256 ECDSA
/// signature over `sha256(private_tx_hash)` and produces the paired proofs. The
/// probe itself needs no owner secret, so signing can be externalized.
pub struct ProbedWithdrawal {
    /// The shared `private_tx_hash`; the owner signs `sha256(private_tx_hash)`.
    pub private_tx_hash: [u8; 32],
    // Deferred zone-proof witness (the server call happens in `finalize`).
    viewing_secret: SecretKey,
    nullifier_secret_32: [u8; 32],
    input_zone_utxo: ZoneUtxo,
    change_zone_utxo: ZoneUtxo,
    external_data_hash: [u8; 32],
    public_amount: [u8; 32],
    proposal: Option<ZoneProposal>,
    // Deferred SPP zone-rail witness.
    spend_input: TransferSpendInput,
    change_spp_utxo: OutputUtxo,
    external_data: ExternalData,
    public_amounts: PublicAmounts,
    payer_pubkey_hash: [u8; 32],
    owner_p256: P256Pubkey,
    squads_address: Address,
    prover_url: String,
    // Reconstructed result fields cross-checked against the proofs.
    change_utxo_hash: [u8; 32],
    nullifier: [u8; 32],
    input_utxo_hash: [u8; 32],
    sender_ciphertext: [u8; 40],
    change_blinding: [u8; 32],
}

/// The signature-independent inputs to a `(1, 1)` withdrawal probe: the sender's
/// owner *public* key plus its spend secrets, and the withdrawal parameters. The
/// owner secret is never needed here (the owner signs `private_tx_hash` externally).
pub struct SquadsWithdrawalProbe {
    /// The sender's P256 owner *public* key (signs `sha256(private_tx_hash)` off-box).
    pub owner_pubkey: P256Pubkey,
    /// Nullifier secret (31 bytes).
    pub nullifier_secret: [u8; 31],
    /// P256 viewing key; the zone circuit's shared viewing secret key.
    pub viewing_secret: SecretKey,
    pub input: SquadsWithdrawalInput,
    /// The public amount to withdraw out of the pool.
    pub withdrawn: u64,
    /// SPL rail when true (settles `public_spl_amount`), native SOL otherwise.
    pub is_spl: bool,
    pub user_sol_account: Address,
    pub user_spl_token: Address,
    pub spl_token_interface: Address,
    pub payer_pubkey_hash: [u8; 32],
    pub expiry_unix_ts: u64,
    pub salt: [u8; 16],
    pub sender_view_tag: [u8; 32],
    pub proposal: Option<ZoneProposal>,
    pub prover_url: String,
}

/// Probe a `(1, 1)` squads withdrawal: run every local (server-free,
/// signature-free) step and return the [`ProbedWithdrawal`] carrying the
/// `private_tx_hash` the owner signs.
pub fn probe_squads_withdrawal(
    probe: SquadsWithdrawalProbe,
) -> Result<ProbedWithdrawal, SquadsProverError> {
    let squads_address = Address::new_from_array(SQUADS_ZONE_PROGRAM_ID);

    // --- identity encodings (from the owner PUBLIC key; no owner secret) ---
    let IdentityEncodings {
        owner_p256,
        owner_public,
        owner_pk_field,
        nullifier_key,
        nullifier_pk,
        viewing_pubkey,
        nullifier_secret_32,
    } = probe_encodings(
        probe.owner_pubkey,
        &probe.nullifier_secret,
        &probe.viewing_secret,
    )?;
    let asset_fe = asset_field(&probe.input.asset).map_err(|_| SquadsProverError::Poseidon)?;
    let zone_program_field =
        hash_field(&SQUADS_ZONE_PROGRAM_ID).map_err(|_| SquadsProverError::Poseidon)?;

    let change_amount = probe
        .input
        .amount
        .checked_sub(probe.withdrawn)
        .ok_or(SquadsProverError::InvalidAmount)?;

    // --- input UTXO, both representations ---
    let input_zone_utxo = ZoneUtxo {
        owner_key_hash: owner_pk_field,
        nullifier_pubkey: nullifier_pk,
        asset: asset_fe,
        amount: probe.input.amount,
        blinding: right_align_31(&probe.input.blinding),
        program_data_hash: [0u8; 32],
        zone_data_hash: [0u8; 32],
        zone_program_id: zone_program_field,
        is_dummy: false,
    };
    let input_spp_utxo = Utxo {
        owner: owner_public,
        asset: probe.input.asset,
        amount: probe.input.amount,
        blinding: probe.input.blinding,
        zone_program_id: Some(squads_address),
        data: Data::default(),
    };
    let input_utxo_hash = input_spp_utxo
        .hash(&nullifier_pk, &[0u8; 32], &[0u8; 32])
        .map_err(|_| SquadsProverError::Poseidon)?;
    let nullifier = nullifier_key
        .nullifier(&input_utxo_hash, &probe.input.blinding)
        .map_err(|_| SquadsProverError::Poseidon)?;

    // --- sender-change artefacts (change blinding + sender ciphertext) ---
    let artifacts = derive_sender_artifacts(
        &probe.viewing_secret,
        &nullifier_secret_32,
        &input_zone_utxo,
        change_amount,
        &asset_fe,
    )?;
    let change_blinding = artifacts.change_blinding;
    let sender_ciphertext: [u8; 40] = artifacts
        .sender_ciphertext
        .as_slice()
        .try_into()
        .map_err(|_| SquadsProverError::InvalidAmount)?;
    let change_blinding_31 = blinding_low_31(&change_blinding);

    // --- change UTXO, both representations ---
    let change_zone_utxo = ZoneUtxo {
        owner_key_hash: owner_pk_field,
        nullifier_pubkey: nullifier_pk,
        asset: asset_fe,
        amount: change_amount,
        blinding: change_blinding,
        program_data_hash: [0u8; 32],
        zone_data_hash: [0u8; 32],
        zone_program_id: zone_program_field,
        is_dummy: false,
    };
    let change_spp_utxo = OutputUtxo {
        asset: probe.input.asset,
        amount: change_amount,
        blinding: change_blinding_31,
        zone_program_id: Some(squads_address),
        zone_data_hash: None,
        data_hash: None,
        owner_address: Some(ShieldedAddress {
            signing_pubkey: owner_public,
            nullifier_pubkey: nullifier_pk,
            viewing_pubkey,
        }),
        owner_tag: None,
        data: Data::default(),
    };
    let change_utxo_hash = change_spp_utxo
        .hash()
        .map_err(|_| SquadsProverError::Poseidon)?;

    // --- shared external data (folded into both proofs) ---
    let signed = i64::try_from(probe.withdrawn).map_err(|_| SquadsProverError::InvalidAmount)?;
    let negative = signed
        .checked_neg()
        .ok_or(SquadsProverError::InvalidAmount)?;
    let (public_sol_amount, public_spl_amount) = if probe.is_spl {
        (None, Some(negative))
    } else {
        (Some(negative), None)
    };
    let external_data = ExternalData {
        instruction_discriminator: ZONE_TRANSACT,
        expiry_unix_ts: probe.expiry_unix_ts,
        relayer_fee: 0,
        public_sol_amount,
        public_spl_amount,
        user_sol_account: probe.user_sol_account,
        user_spl_token: probe.user_spl_token,
        spl_token_interface: probe.spl_token_interface,
        data_hash: None,
        zone_data_hash: None,
        tx_viewing_pk: [0u8; 33],
        salt: probe.salt,
        output_utxo_hashes: vec![change_utxo_hash],
        output_ciphertexts: vec![OutputCiphertext {
            view_tag: probe.sender_view_tag,
            data: sender_ciphertext.to_vec(),
        }],
    };
    let external_data_hash = external_data
        .hash()
        .map_err(|_| SquadsProverError::Poseidon)?;

    let public_amount = right_align_u64(probe.withdrawn);
    let public_amounts = PublicAmounts {
        sol: if probe.is_spl {
            [0u8; 32]
        } else {
            signed_to_field(i128::from(negative))
        },
        spl: if probe.is_spl {
            signed_to_field(i128::from(negative))
        } else {
            [0u8; 32]
        },
        asset: if probe.is_spl { asset_fe } else { [0u8; 32] },
    };
    let spend_input = TransferSpendInput {
        utxo: input_spp_utxo,
        nullifier_key: nullifier_key.clone(),
        data_hash: None,
        zone_data_hash: None,
        proof: Some(probe.input.spend_proof),
    };

    // The unsigned SPP witness fixes `private_tx_hash` (signature-independent).
    let unsigned = build_spp_prover(
        &spend_input,
        &change_spp_utxo,
        &external_data,
        &public_amounts,
        probe.payer_pubkey_hash,
        owner_p256,
        [0u8; 32],
        [0u8; 32],
        squads_address,
    )
    .build()
    .map_err(spp_err)?;

    Ok(ProbedWithdrawal {
        private_tx_hash: unsigned.private_tx_hash,
        viewing_secret: probe.viewing_secret,
        nullifier_secret_32,
        input_zone_utxo,
        change_zone_utxo,
        external_data_hash,
        public_amount,
        proposal: probe.proposal,
        spend_input,
        change_spp_utxo,
        external_data,
        public_amounts,
        payer_pubkey_hash: probe.payer_pubkey_hash,
        owner_p256,
        squads_address,
        prover_url: probe.prover_url,
        change_utxo_hash,
        nullifier,
        input_utxo_hash,
        sender_ciphertext,
        change_blinding,
    })
}

impl ProbedWithdrawal {
    /// Finalize with the owner's P256 ECDSA signature `(sig_r, sig_s)` over
    /// `sha256(private_tx_hash)`: prove the squads zone rail, prove the signed SPP
    /// zone rail, and assemble the paired [`SquadsWithdrawalProof`]. Cross-checks
    /// that the two proofs agree on `private_tx_hash`, nullifier, and change hash.
    pub fn finalize(
        self,
        sig_r: [u8; 32],
        sig_s: [u8; 32],
    ) -> Result<SquadsWithdrawalProof, SquadsProverError> {
        // --- squads zone proof (signature-independent) ---
        let zone_result = ZoneWitness {
            viewing_secret_key: self.viewing_secret.clone(),
            nullifier_secret: self.nullifier_secret_32,
            inputs: vec![self.input_zone_utxo.clone()],
            outputs: vec![self.change_zone_utxo.clone()],
            external_data_hash: self.external_data_hash,
            recipient: None,
            proposal: self.proposal.clone(),
            public_amount: self.public_amount,
        }
        .prove(&self.prover_url)?;
        if zone_result.change_blinding != self.change_blinding {
            return Err(SquadsProverError::BlindingMismatch);
        }
        if zone_result.sender_ciphertext != self.sender_ciphertext {
            return Err(SquadsProverError::BlindingMismatch);
        }

        // --- SPP zone-rail proof (P256), now signed ---
        let final_prover = build_spp_prover(
            &self.spend_input,
            &self.change_spp_utxo,
            &self.external_data,
            &self.public_amounts,
            self.payer_pubkey_hash,
            self.owner_p256,
            sig_r,
            sig_s,
            self.squads_address,
        )
        .build()
        .map_err(spp_err)?;
        let spp_proof_raw = ProverClient::new(self.prover_url.clone())
            .prove_transfer_p256_zone(&final_prover.inputs)
            .map_err(spp_err)?;
        let spp_proof = pack_proof(&spp_proof_raw)?;

        // --- cross-checks: the two proofs MUST agree ---
        if zone_result.private_tx_hash != final_prover.private_tx_hash {
            return Err(SquadsProverError::ProofParse(format!(
                "private_tx_hash mismatch: zone {:?} vs spp {:?}",
                zone_result.private_tx_hash, final_prover.private_tx_hash
            )));
        }
        if final_prover.nullifiers.first().copied() != Some(self.nullifier) {
            return Err(SquadsProverError::ProofParse(
                "SPP nullifier does not match the reconstructed nullifier".to_string(),
            ));
        }
        if final_prover.output_hashes.first().copied() != Some(self.change_utxo_hash) {
            return Err(SquadsProverError::ProofParse(
                "SPP change output hash does not match the reconstructed hash".to_string(),
            ));
        }
        let &(utxo_root_index, nullifier_root_index) = final_prover
            .input_root_indices
            .first()
            .ok_or(SquadsProverError::Poseidon)?;

        Ok(SquadsWithdrawalProof {
            zone_proof: zone_result.proof,
            spp_proof,
            private_tx_hash: zone_result.private_tx_hash,
            proposal_hash: zone_result.proposal_hash,
            change_utxo_hash: self.change_utxo_hash,
            nullifier: self.nullifier,
            input_utxo_hash: self.input_utxo_hash,
            utxo_root_index,
            nullifier_root_index,
            sender_ciphertext: self.sender_ciphertext,
            change_blinding: self.change_blinding,
        })
    }

    /// The `private_tx_hash` of the SPP witness rebuilt with `(sig_r, sig_s)`,
    /// without contacting the prover server. Exposed for offline tests to confirm
    /// the finalize step rebuilds the identical (signature-independent)
    /// `private_tx_hash` the probe returned.
    #[cfg(test)]
    pub(crate) fn spp_private_tx_hash_for_test(
        &self,
        sig_r: [u8; 32],
        sig_s: [u8; 32],
    ) -> Result<[u8; 32], SquadsProverError> {
        Ok(build_spp_prover(
            &self.spend_input,
            &self.change_spp_utxo,
            &self.external_data,
            &self.public_amounts,
            self.payer_pubkey_hash,
            self.owner_p256,
            sig_r,
            sig_s,
            self.squads_address,
        )
        .build()
        .map_err(spp_err)?
        .private_tx_hash)
    }
}

/// Build the paired zone + SPP-rail proofs for a `(1, 1)` squads withdrawal. A
/// thin wrapper over [`probe_squads_withdrawal`] + [`ProbedWithdrawal::finalize`]:
/// it probes with the owner's public key, signs `sha256(private_tx_hash)` with the
/// held owner secret, and finalizes. Behaviour is identical to the pre-split
/// one-shot builder.
pub fn prove_squads_withdrawal(
    req: SquadsWithdrawalRequest,
) -> Result<SquadsWithdrawalProof, SquadsProverError> {
    let owner_secret = req.identity.owner_secret.clone();
    let owner_pubkey = P256Pubkey::from_p256(&owner_secret.public_key());
    let probed = probe_squads_withdrawal(SquadsWithdrawalProbe {
        owner_pubkey,
        nullifier_secret: req.identity.nullifier_secret,
        viewing_secret: req.identity.viewing_secret,
        input: req.input,
        withdrawn: req.withdrawn,
        is_spl: req.is_spl,
        user_sol_account: req.user_sol_account,
        user_spl_token: req.user_spl_token,
        spl_token_interface: req.spl_token_interface,
        payer_pubkey_hash: req.payer_pubkey_hash,
        expiry_unix_ts: req.expiry_unix_ts,
        salt: req.salt,
        sender_view_tag: req.sender_view_tag,
        proposal: req.proposal,
        prover_url: req.prover_url,
    })?;
    let signature = SigningKey::from_bytes(&secret_bytes(&owner_secret))
        .map_err(|_| SquadsProverError::InvalidPubkey)?
        .sign(&sha256(&probed.private_tx_hash));
    let (sig_r, sig_s) = split_signature(&signature)?;
    probed.finalize(sig_r, sig_s)
}

#[allow(clippy::too_many_arguments)]
fn build_spp_prover(
    spend_input: &TransferSpendInput,
    change: &OutputUtxo,
    external_data: &ExternalData,
    public_amounts: &PublicAmounts,
    payer_pubkey_hash: [u8; 32],
    owner_p256: P256Pubkey,
    sig_r: [u8; 32],
    sig_s: [u8; 32],
    zone: Address,
) -> ZoneTransferP256Prover {
    ZoneTransferP256Prover {
        inputs: vec![spend_input.clone()],
        outputs: vec![change.clone()],
        external_data: external_data.clone(),
        public_amounts: public_amounts.clone(),
        payer_pubkey_hash,
        p256_owner: zolana_client::P256Owner {
            pubkey: owner_p256,
            sig_r,
            sig_s,
        },
        zone_program_id: Some(zone),
        shape: Some(Shape::new(1, 1)),
    }
}

pub(crate) fn spp_err(e: zolana_client::ClientError) -> SquadsProverError {
    SquadsProverError::ProofParse(format!("SPP zone-rail prover: {e}"))
}

/// Pack a BSB22-committed Groth16 proof into the 192-byte layout SPP reads:
/// `a || b || c || commitment || commitment_pok`.
pub(crate) fn pack_proof(proof: &Proof) -> Result<[u8; 192], SquadsProverError> {
    let compressed = ProofCompressed::try_from(*proof)
        .map_err(|e| SquadsProverError::ProofParse(format!("compress SPP proof: {e}")))?;
    let mut out = [0u8; 192];
    out.get_mut(0..32)
        .ok_or(SquadsProverError::InvalidProofEncoding)?
        .copy_from_slice(&compressed.a);
    out.get_mut(32..96)
        .ok_or(SquadsProverError::InvalidProofEncoding)?
        .copy_from_slice(&compressed.b);
    out.get_mut(96..128)
        .ok_or(SquadsProverError::InvalidProofEncoding)?
        .copy_from_slice(&compressed.c);
    let commitment = compressed
        .commitment
        .ok_or(SquadsProverError::InvalidProofEncoding)?;
    out.get_mut(128..160)
        .ok_or(SquadsProverError::InvalidProofEncoding)?
        .copy_from_slice(&commitment.commitment);
    out.get_mut(160..192)
        .ok_or(SquadsProverError::InvalidProofEncoding)?
        .copy_from_slice(&commitment.commitment_pok);
    Ok(out)
}

pub(crate) fn split_signature(sig: &[u8; 64]) -> Result<([u8; 32], [u8; 32]), SquadsProverError> {
    let r: [u8; 32] = sig
        .get(..32)
        .ok_or(SquadsProverError::InvalidProofEncoding)?
        .try_into()
        .map_err(|_| SquadsProverError::InvalidProofEncoding)?;
    let s: [u8; 32] = sig
        .get(32..)
        .ok_or(SquadsProverError::InvalidProofEncoding)?
        .try_into()
        .map_err(|_| SquadsProverError::InvalidProofEncoding)?;
    Ok((r, s))
}

pub(crate) fn secret_bytes(secret: &SecretKey) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(secret.to_bytes().as_slice());
    out
}

/// Right-align a 31-byte value into a 32-byte field element (leading zero byte).
pub(crate) fn right_align_31(bytes: &[u8; 31]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[1..32].copy_from_slice(bytes);
    out
}

/// The low 31 bytes of a 32-byte field element (its top byte must be zero).
pub(crate) fn blinding_low_31(fe: &[u8; 32]) -> [u8; 31] {
    let mut out = [0u8; 31];
    out.copy_from_slice(&fe[1..32]);
    out
}

/// A `u64` right-aligned (big-endian) into a 32-byte field element.
pub(crate) fn right_align_u64(x: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&x.to_be_bytes());
    out
}
