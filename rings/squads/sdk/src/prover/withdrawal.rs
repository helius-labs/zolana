//! Paired ring + SPP-rail withdrawal proof builder (gated under the `prover`
//! feature).
//!
//! A squads withdrawal forwards TWO proofs that must agree on one shared
//! `private_tx_hash`:
//! 1. the squads RING proof (this crate's [`RingProofInputs`]), verified on-chain by
//!    the squads program, and
//! 2. the SPP ring-rail proof ([`RingTransferP256Prover`], `transfer_p256_ring`),
//!    verified on-chain by SPP after the ring-auth-signed CPI.
//!
//! Consistency is achieved by construction: this builder computes ONE
//! [`ExternalData`] (the settlement recipient/vault, the change output hash, and
//! the sender ciphertext all folded into `external_data_hash`) and feeds the SAME
//! hash into both proofs, and encodes the squads [`RingUtxo`] fields so its
//! `utxo_hash` fold matches SPP's [`Utxo`]/[`SppProofOutputUtxo`] fold exactly (asset via
//! `hash_field`, blinding right-aligned into 32 bytes, `ring_program_id` via
//! `hash_field`, owner via `Poseidon(owner_pk_field, nullifier_pubkey)`). The
//! builder then cross-checks that the two provers produced the same
//! `private_tx_hash`, nullifier, and change hash.
//!
//! The change blinding is a pure function of the sender secrets and the first
//! input ([`derive_change_blinding`](super::ring::derive_change_blinding)),
//! masked to its low 248 bits on both sides
//! (the circuit and the Rust derivation), so its top byte is always zero and it
//! round-trips SPP's 31-byte `SppProofOutputUtxo` blinding for any deposit blinding.

use p256::SecretKey;
use zolana_client::{
    Proof, ProofCompressed, ProverClient, PublicTransfers, RingTransferP256Prover, Shape,
    SpendProof, TransferSpendInput,
};
use zolana_interface::instruction::{
    instruction_data::transact::{OwnerTag, TransactOutput},
    tag::RING_TRANSACT,
};
use zolana_keypair::{
    hash::sha256, NullifierKey, P256Pubkey, PublicKey, ShieldedAddress, SigningKey,
};
use zolana_transaction::{
    instructions::transact::asset_field, Address, Data, ExternalData, SppProofOutputUtxo, Utxo,
};

use zolana_squads_interface::SQUADS_RING_PROGRAM_ID;

use crate::prover::{
    error::SquadsProverError,
    ring::{derive_sender_artifacts, RingProofInputs, RingProposal, RingUtxo},
    shared_viewing_key::{
        hash_field, withdrawal_public_transfers, withdrawal_transfer, WithdrawalDestination,
    },
};

/// The deterministic P256 identity behind a squads viewing key account: the
/// secrets needed to spend a ring UTXO owned by that account.
#[derive(Clone)]
pub struct SquadsIdentity {
    /// P256 owner (signing) key. It signs the SPP spend over `sha256(private_tx_hash)`.
    pub owner_secret: SecretKey,
    /// Nullifier secret (31 bytes). `NullifierKey.pubkey()` == the VKA's
    /// `nullifier_pubkey`.
    pub nullifier_secret: [u8; 31],
    /// P256 viewing key. It is the ring circuit's shared viewing secret key.
    pub viewing_secret: SecretKey,
}

/// One deposited ring UTXO to spend, plus its Photon inclusion / non-inclusion
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
    /// withdrawn` stays as a ring UTXO.
    pub withdrawn: u64,
    /// The public destination, which also selects the settlement rail.
    pub destination: WithdrawalDestination,
    /// Settled mint. It is bound into the interface transfer SPP recomputes.
    pub asset: Address,
    /// Sha256-BE of the SPP payer address (the squads `payer` account SPP sees).
    pub payer_pubkey_hash: [u8; 32],
    /// Transaction expiry (folded into `external_data_hash`).
    pub expiry_unix_ts: u64,
    /// Per-transaction salt. It is forwarded to SPP and is not bound by
    /// `external_data_hash`.
    pub salt: [u8; 16],
    /// The sender-change output ciphertext view tag (forwarded, folded into
    /// `external_data_hash` via the output ciphertext).
    pub sender_view_tag: [u8; 32],
    /// A bound proposal for `execute_proposal`. `None` for a sync `transact`.
    pub proposal: Option<RingProposal>,
    /// The prover server URL.
    pub prover_url: String,
}

/// The paired proofs and every field the caller needs to assemble the squads
/// `TransactIxData` / `ExecuteProposalIxData`.
pub struct SquadsWithdrawalProof {
    /// The 192-byte squads ring proof.
    pub ring_proof: [u8; 192],
    /// The 192-byte SPP ring-rail proof, forwarded to SPP.
    pub spp_proof: [u8; 192],
    /// The shared `private_tx_hash` both proofs bind.
    pub private_tx_hash: [u8; 32],
    /// The proposal commitment (0 for a sync `transact`). It is stored as the
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
    /// The derived change blinding (32 bytes, top byte zero).
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

/// The rail-agnostic field encodings from the sender's *public* owner key plus
/// its spend secrets. No owner secret is needed, so signing can stay external.
pub(crate) fn probe_encodings(
    owner_p256: P256Pubkey,
    nullifier_secret: &[u8; 31],
    viewing_secret: &SecretKey,
) -> Result<IdentityEncodings, SquadsProverError> {
    let owner_public = PublicKey::from_p256(&owner_p256);
    let owner_pk_field = owner_public
        .owner_proof_input_hash()
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

/// The spend commitment of one deposited ring UTXO: its leaf `utxo_hash` (to fetch
/// a Photon merkle proof) and its `nullifier` (to fetch a non-inclusion proof).
/// The caller fetches both proofs, then hands them to [`prove_squads_withdrawal`].
pub fn squads_input_commitment(
    identity: &SquadsIdentity,
    asset: Address,
    amount: u64,
    blinding: &[u8; 31],
) -> Result<([u8; 32], [u8; 32]), SquadsProverError> {
    let enc = identity_encodings(identity)?;
    let squads_address = Address::new_from_array(SQUADS_RING_PROGRAM_ID);
    let utxo = Utxo {
        owner: enc.owner_public,
        asset,
        amount,
        blinding: right_align_31(blinding),
        ring_program_id: Some(squads_address),
        data: Data::default(),
    };
    let utxo_hash = utxo
        .hash(&enc.nullifier_pk, &[0u8; 32], &[0u8; 32])
        .map_err(|_| SquadsProverError::Poseidon)?;
    let nullifier = enc
        .nullifier_key
        .nullifier(&utxo_hash, &right_align_31(blinding))
        .map_err(|_| SquadsProverError::Poseidon)?;
    Ok((utxo_hash, nullifier))
}

/// A probed withdrawal: every signature-independent step is done (the change
/// output, the shared external data, and the SPP witness whose `private_tx_hash`
/// the owner must sign). [`ProbedWithdrawal::finalize`] takes the P256 ECDSA
/// signature over `sha256(private_tx_hash)` and produces the paired proofs. The
/// probe itself needs no owner secret, so signing can be externalized.
pub struct ProbedWithdrawal {
    /// The shared `private_tx_hash`. The owner signs `sha256(private_tx_hash)`.
    pub private_tx_hash: [u8; 32],
    viewing_secret: SecretKey,
    nullifier_secret_32: [u8; 32],
    input_ring_utxo: RingUtxo,
    change_ring_utxo: RingUtxo,
    external_data_hash: [u8; 32],
    public_amount: [u8; 32],
    proposal: Option<RingProposal>,
    spend_input: TransferSpendInput,
    change_spp_utxo: SppProofOutputUtxo,
    external_data: ExternalData,
    public_amounts: PublicTransfers,
    payer_pubkey_hash: [u8; 32],
    owner_p256: P256Pubkey,
    squads_address: Address,
    prover_url: String,
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
    /// P256 viewing key. It is the ring circuit's shared viewing secret key.
    pub viewing_secret: SecretKey,
    pub input: SquadsWithdrawalInput,
    /// The public amount to withdraw out of the pool.
    pub withdrawn: u64,
    /// The public destination, which also selects the settlement rail.
    pub destination: WithdrawalDestination,
    /// Settled mint. It is bound into the interface transfer SPP recomputes.
    pub asset: Address,
    pub payer_pubkey_hash: [u8; 32],
    pub expiry_unix_ts: u64,
    pub salt: [u8; 16],
    pub sender_view_tag: [u8; 32],
    pub proposal: Option<RingProposal>,
    pub prover_url: String,
}

/// Probe a `(1, 1)` squads withdrawal: run every local (server-free,
/// signature-free) step and return the [`ProbedWithdrawal`] carrying the
/// `private_tx_hash` the owner signs.
pub fn probe_squads_withdrawal(
    probe: SquadsWithdrawalProbe,
) -> Result<ProbedWithdrawal, SquadsProverError> {
    let squads_address = Address::new_from_array(SQUADS_RING_PROGRAM_ID);

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
    let ring_program_field =
        hash_field(&SQUADS_RING_PROGRAM_ID).map_err(|_| SquadsProverError::Poseidon)?;

    let change_amount = probe
        .input
        .amount
        .checked_sub(probe.withdrawn)
        .ok_or(SquadsProverError::InvalidAmount)?;

    let input_ring_utxo = RingUtxo {
        owner_key_hash: owner_pk_field,
        nullifier_pubkey: nullifier_pk,
        asset: asset_fe,
        amount: probe.input.amount,
        blinding: right_align_31(&probe.input.blinding),
        program_data_hash: [0u8; 32],
        ring_data_hash: [0u8; 32],
        ring_program_id: ring_program_field,
        is_dummy: false,
    };
    let input_spp_utxo = Utxo {
        owner: owner_public,
        asset: probe.input.asset,
        amount: probe.input.amount,
        blinding: right_align_31(&probe.input.blinding),
        ring_program_id: Some(squads_address),
        data: Data::default(),
    };
    let input_utxo_hash = input_spp_utxo
        .hash(&nullifier_pk, &[0u8; 32], &[0u8; 32])
        .map_err(|_| SquadsProverError::Poseidon)?;
    let nullifier = nullifier_key
        .nullifier(&input_utxo_hash, &right_align_31(&probe.input.blinding))
        .map_err(|_| SquadsProverError::Poseidon)?;

    let artifacts = derive_sender_artifacts(
        &probe.viewing_secret,
        &nullifier_secret_32,
        &input_ring_utxo,
        change_amount,
        &asset_fe,
    )?;
    let change_blinding = artifacts.change_blinding;
    let sender_ciphertext: [u8; 40] = artifacts
        .sender_ciphertext
        .as_slice()
        .try_into()
        .map_err(|_| SquadsProverError::InvalidProofEncoding)?;
    let change_blinding_31 = low_31(&change_blinding);

    let change_ring_utxo = RingUtxo {
        owner_key_hash: owner_pk_field,
        nullifier_pubkey: nullifier_pk,
        asset: asset_fe,
        amount: change_amount,
        blinding: change_blinding,
        program_data_hash: [0u8; 32],
        ring_data_hash: [0u8; 32],
        ring_program_id: ring_program_field,
        is_dummy: false,
    };
    let change_spp_utxo = SppProofOutputUtxo {
        asset: probe.input.asset,
        amount: change_amount,
        blinding: right_align_31(&change_blinding_31),
        ring_program_id: Some(squads_address),
        ring_data_hash: None,
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

    let mut external_data = ExternalData::new(
        [0u8; 33],
        probe.salt,
        vec![TransactOutput {
            utxo_hash: change_utxo_hash,
            owner_tag: OwnerTag::Inline(probe.sender_view_tag),
            data: Some(sender_ciphertext.to_vec()),
        }],
        vec![probe.sender_view_tag],
        Vec::new(),
    );
    external_data.instruction_discriminator = RING_TRANSACT;
    external_data.expiry_unix_ts = probe.expiry_unix_ts;
    let external_data = external_data
        .with_interface_transfer(withdrawal_transfer(
            probe.destination,
            probe.withdrawn,
            probe.asset,
        ))
        .map_err(|_| SquadsProverError::Poseidon)?;
    let external_data_hash = external_data
        .hash()
        .map_err(|_| SquadsProverError::Poseidon)?;

    let public_amount = fe_from_u64(probe.withdrawn);
    let public_amounts = withdrawal_public_transfers(probe.destination, probe.withdrawn, asset_fe)?;
    let spend_input = TransferSpendInput {
        utxo: input_spp_utxo,
        nullifier_key: nullifier_key.clone(),
        data_hash: None,
        ring_data_hash: None,
        proof: Some(probe.input.spend_proof),
        nullifier_proof: None,
    };

    let private_tx_hash = SppRingSpend {
        spend_inputs: core::slice::from_ref(&spend_input),
        outputs: core::slice::from_ref(&change_spp_utxo),
        external_data: &external_data,
        public_amounts: &public_amounts,
        payer_pubkey_hash: probe.payer_pubkey_hash,
        owner_p256,
        ring: squads_address,
    }
    .unsigned()
    .private_tx_hash()
    .map_err(spp_err)?;

    Ok(ProbedWithdrawal {
        private_tx_hash,
        viewing_secret: probe.viewing_secret,
        nullifier_secret_32,
        input_ring_utxo,
        change_ring_utxo,
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
    fn spp_spend(&self) -> SppRingSpend<'_> {
        SppRingSpend {
            spend_inputs: core::slice::from_ref(&self.spend_input),
            outputs: core::slice::from_ref(&self.change_spp_utxo),
            external_data: &self.external_data,
            public_amounts: &self.public_amounts,
            payer_pubkey_hash: self.payer_pubkey_hash,
            owner_p256: self.owner_p256,
            ring: self.squads_address,
        }
    }

    /// Finalize with the owner's P256 ECDSA signature `(sig_r, sig_s)` over
    /// `sha256(private_tx_hash)`: prove the squads ring rail, prove the signed SPP
    /// ring rail, and assemble the paired [`SquadsWithdrawalProof`]. Cross-checks
    /// that the two proofs agree on `private_tx_hash`, nullifier, and change hash.
    pub fn finalize(
        self,
        sig_r: [u8; 32],
        sig_s: [u8; 32],
    ) -> Result<SquadsWithdrawalProof, SquadsProverError> {
        let ring_result = RingProofInputs {
            viewing_secret_key: self.viewing_secret.clone(),
            nullifier_secret: self.nullifier_secret_32,
            inputs: vec![self.input_ring_utxo.clone()],
            outputs: vec![self.change_ring_utxo.clone()],
            external_data_hash: self.external_data_hash,
            recipient: None,
            proposal: self.proposal.clone(),
            public_amount: self.public_amount,
        }
        .prove(&self.prover_url)?;
        if ring_result.change_blinding != self.change_blinding {
            return Err(SquadsProverError::BlindingMismatch);
        }
        if ring_result.sender_ciphertext != self.sender_ciphertext {
            return Err(SquadsProverError::BlindingMismatch);
        }

        let final_prover = self
            .spp_spend()
            .sign(sig_r, sig_s)
            .build()
            .map_err(spp_err)?;
        let spp_proof_raw = ProverClient::new(self.prover_url.clone())
            .prove_transfer_p256_ring(&final_prover.inputs)
            .map_err(spp_err)?;
        let spp_proof = pack_proof(&spp_proof_raw)?;

        if ring_result.private_tx_hash != final_prover.private_tx_hash {
            return Err(SquadsProverError::ProofValidation(format!(
                "private_tx_hash mismatch: ring {:?} vs spp {:?}",
                ring_result.private_tx_hash, final_prover.private_tx_hash
            )));
        }
        if final_prover.nullifiers.first().copied() != Some(self.nullifier) {
            return Err(SquadsProverError::ProofValidation(
                "SPP nullifier does not match the reconstructed nullifier".to_string(),
            ));
        }
        if final_prover.output_hashes.first().copied() != Some(self.change_utxo_hash) {
            return Err(SquadsProverError::ProofValidation(
                "SPP change output hash does not match the reconstructed hash".to_string(),
            ));
        }
        let &(utxo_root_index, nullifier_root_index) = final_prover
            .input_root_indices
            .first()
            .ok_or(SquadsProverError::MissingSlot)?;

        Ok(SquadsWithdrawalProof {
            ring_proof: ring_result.proof,
            spp_proof,
            private_tx_hash: ring_result.private_tx_hash,
            proposal_hash: ring_result.proposal_hash,
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
        Ok(self
            .spp_spend()
            .sign(sig_r, sig_s)
            .build()
            .map_err(spp_err)?
            .private_tx_hash)
    }
}

/// Build the paired ring + SPP-rail proofs for a `(1, 1)` squads withdrawal. A
/// thin wrapper over [`probe_squads_withdrawal`] + [`ProbedWithdrawal::finalize`]:
/// it probes with the owner's public key, signs `sha256(private_tx_hash)` with the
/// held owner secret, and finalizes.
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
        destination: req.destination,
        asset: req.asset,
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

/// The signature-independent inputs to the SPP ring-rail prover, shared by the
/// withdrawal and transfer builders. The proven shape is the input and output
/// counts, so both slices must already be padded to it.
pub(crate) struct SppRingSpend<'a> {
    pub(crate) spend_inputs: &'a [TransferSpendInput],
    pub(crate) outputs: &'a [SppProofOutputUtxo],
    pub(crate) external_data: &'a ExternalData,
    pub(crate) public_amounts: &'a PublicTransfers,
    pub(crate) payer_pubkey_hash: [u8; 32],
    pub(crate) owner_p256: P256Pubkey,
    pub(crate) ring: Address,
}

impl SppRingSpend<'_> {
    /// The prover carrying the owner's P256 ECDSA signature `(sig_r, sig_s)` over
    /// `sha256(private_tx_hash)`.
    pub(crate) fn sign(self, sig_r: [u8; 32], sig_s: [u8; 32]) -> RingTransferP256Prover {
        let shape = Shape::new(self.spend_inputs.len(), self.outputs.len());
        RingTransferP256Prover {
            inputs: self.spend_inputs.to_vec(),
            outputs: self.outputs.to_vec(),
            external_data: self.external_data.clone(),
            public_transfers: *self.public_amounts,
            signer_pk_hashes: signer_slots(self.payer_pubkey_hash, shape),
            allow_dummy_inputs: true,
            authorization: zolana_transaction::P256Signature {
                pubkey: self.owner_p256,
                sig_r,
                sig_s,
            },
            ring_program_id: Some(self.ring),
            shape: Some(shape),
        }
    }

    /// The prover with a zero signature. `private_tx_hash` is signature independent,
    /// so a probe reads it from this one before the owner signs.
    pub(crate) fn unsigned(self) -> RingTransferP256Prover {
        self.sign([0u8; 32], [0u8; 32])
    }
}

/// The circuit commits a fixed-width signer vector, payer in slot zero followed
/// by the non-payer input owners. A ring input is owned by the ring PDA and
/// proves ownership with P256, so it never signs and its slot stays zero. The
/// width must be `n_inputs + 1` or the witness binds a different statement than
/// the key proves.
pub(crate) fn signer_slots(payer_pubkey_hash: [u8; 32], shape: Shape) -> Vec<[u8; 32]> {
    let mut slots = vec![[0u8; 32]; shape.n_inputs() + 1];
    if let Some(payer_slot) = slots.first_mut() {
        *payer_slot = payer_pubkey_hash;
    }
    slots
}

pub(crate) fn spp_err(e: zolana_client::ClientError) -> SquadsProverError {
    SquadsProverError::ProverServer(format!("SPP ring-rail prover: {e}"))
}

/// Pack a BSB22-committed Groth16 proof into the 192-byte layout SPP reads:
/// `a || b || c || commitment || commitment_pok`.
pub(crate) fn pack_proof(proof: &Proof) -> Result<[u8; 192], SquadsProverError> {
    let compressed = ProofCompressed::try_from(*proof)
        .map_err(|e| SquadsProverError::ProofCompress(format!("SPP proof: {e}")))?;
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
pub(crate) fn low_31(fe: &[u8; 32]) -> [u8; 31] {
    let mut out = [0u8; 31];
    out.copy_from_slice(&fe[1..32]);
    out
}

/// A `u64` right-aligned (big-endian) into a 32-byte field element.
pub(crate) fn fe_from_u64(x: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&x.to_be_bytes());
    out
}
