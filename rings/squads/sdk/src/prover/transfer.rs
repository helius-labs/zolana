//! Paired zone + SPP-rail transfer proof builder (gated under the `prover`
//! feature).
//!
//! A squads transfer is a `(2, 2)` spend that keeps every lamport/token inside
//! the pool: the sender spends two deposited zone UTXOs into a sender-change
//! output and a recipient output, with `public_amount = 0` (no settlement). Like
//! [`prove_squads_withdrawal`](super::withdrawal::prove_squads_withdrawal) it
//! forwards TWO proofs that must agree on one shared `private_tx_hash`:
//! 1. the squads ZONE proof ([`ZoneProofInputs`] with a recipient), verified on-chain
//!    by the squads program, and
//! 2. the SPP zone-rail proof ([`RingTransferP256Prover`], `transfer_p256_zone`),
//!    verified on-chain by SPP after the zone-auth-signed CPI.
//!
//! Consistency is achieved by construction: one [`ExternalData`] (folding both
//! output hashes and both output ciphertexts) feeds both proofs, and both output
//! UTXOs are encoded so the squads [`ZoneUtxo`] fold matches SPP's [`SppProofOutputUtxo`]
//! fold exactly. The output order is fixed: `Outputs[0]` is the sender change,
//! `Outputs[1]` is the recipient. The sender-change and recipient ciphertexts and
//! the ephemeral `tx_viewing_pk` are derived deterministically (via
//! [`TransferOutputs::derive`]) before proving so they can be folded into the
//! shared external data. [`ZoneProofInputs::prove`] recomputes the identical values
//! and this builder cross-checks them.
//!
//! The sender-change blinding is a pure function of the sender secrets and the
//! first input ([`derive_change_blinding`](super::zone::derive_change_blinding)),
//! masked to its low 248 bits on both sides (the circuit and the Rust
//! derivation), so its top byte is always zero and it round-trips SPP's 31-byte
//! `SppProofOutputUtxo` blinding for any deposit blinding.

use p256::SecretKey;
use zolana_client::{ProverClient, PublicTransfers, SpendProof, TransferSpendInput};
use zolana_interface::instruction::{
    instruction_data::transact::{OwnerTag, TransactOutput},
    tag::RING_TRANSACT,
};
use zolana_keypair::{hash::sha256, P256Pubkey, PublicKey, ShieldedAddress, SigningKey};
use zolana_transaction::{
    instructions::transact::asset_field, Address, Data, ExternalData, SppProofOutputUtxo, Utxo,
};

use zolana_squads_interface::SQUADS_ZONE_PROGRAM_ID;

use crate::{
    crypto::{fe_from_u64, random_blinding_31, right_align_31},
    prover::{
        error::SquadsProverError,
        shared_viewing_key::hash_field,
        withdrawal::{
            pack_proof, probe_encodings, secret_bytes, split_signature, spp_err, IdentityEncodings,
            SppRingSpend, SquadsIdentity,
        },
        zone::{TransferOutputs, ZoneProofInputs, ZoneProposal, ZoneRecipient, ZoneUtxo},
    },
};

/// One deposited zone UTXO the sender spends, plus its Photon inclusion /
/// non-inclusion proofs. A `(2, 2)` transfer spends exactly two, which must share
/// one asset.
pub struct SquadsTransferInput {
    /// The asset mint (`SOL_MINT` for a SOL UTXO). Identical across both inputs.
    pub asset: Address,
    /// The deposited amount held in this UTXO.
    pub amount: u64,
    /// The 31-byte deposit blinding.
    pub blinding: [u8; 31],
    /// State-inclusion + nullifier-non-inclusion proofs for this UTXO.
    pub spend_proof: SpendProof,
}

/// The transfer recipient, addressed only by its public shielded identity (the
/// sender never holds a recipient secret). `owner_pk_field` is the recipient's
/// owner-identity field element (the zone `owner_key_hash` and, with the nullifier
/// pubkey, SPP's `owner_hash`) — read directly from the recipient's viewing-key
/// account `owner`, so the raw recipient signing key is never required.
pub struct SquadsTransferRecipient {
    pub owner_pk_field: [u8; 32],
    pub nullifier_pubkey: [u8; 32],
    pub viewing_pubkey: P256Pubkey,
}

/// Everything the paired-proof builder needs for a `(2, 2)` transfer.
pub struct SquadsTransferRequest {
    /// The sender's spendable identity.
    pub identity: SquadsIdentity,
    /// The two deposited inputs to spend (both the same asset).
    pub inputs: Vec<SquadsTransferInput>,
    /// The recipient's public shielded identity.
    pub recipient: SquadsTransferRecipient,
    /// Amount routed to the recipient. The change (`sum(inputs) - transferred`)
    /// stays as the sender's zone UTXO.
    pub transferred: u64,
    /// The 31-byte recipient-output blinding the sender picks and encrypts to the
    /// recipient (right-aligned into a 32-byte field element with a zero top byte).
    pub recipient_blinding: [u8; 31],
    /// Sha256-BE of the SPP payer address (the squads `payer` account SPP sees).
    pub payer_pubkey_hash: [u8; 32],
    /// Transaction expiry (folded into `external_data_hash`).
    pub expiry_unix_ts: u64,
    /// Per-transaction salt. Forwarded to SPP, not bound by `external_data_hash`.
    pub salt: [u8; 16],
    /// The sender-change output ciphertext view tag.
    pub sender_view_tag: [u8; 32],
    /// The recipient output ciphertext view tag.
    pub recipient_view_tag: [u8; 32],
    /// A bound proposal for `execute_proposal`. `None` for a sync `transact`.
    pub proposal: Option<ZoneProposal>,
    pub prover_url: String,
}

/// The paired proofs and every field the caller needs to assemble the squads
/// `TransactIxData` / `ExecuteProposalIxData` for a transfer. Outputs are ordered
/// `[change, recipient]` (sender change first).
pub struct SquadsTransferProof {
    /// The 192-byte squads zone proof.
    pub zone_proof: [u8; 192],
    /// The 192-byte SPP zone-rail proof, forwarded to SPP.
    pub spp_proof: [u8; 192],
    /// The shared `private_tx_hash` both proofs bind.
    pub private_tx_hash: [u8; 32],
    /// The proposal commitment (0 for a sync `transact`).
    pub proposal_hash: [u8; 32],
    /// The sender-change output UTXO hash (`output_utxo_hashes[0]`).
    pub change_utxo_hash: [u8; 32],
    /// The recipient output UTXO hash (`output_utxo_hashes[1]`).
    pub recipient_utxo_hash: [u8; 32],
    /// The sender change amount (`sum(inputs) - transferred`).
    pub change_amount: u64,
    /// The spent inputs' nullifiers, in input order.
    pub nullifiers: Vec<[u8; 32]>,
    /// The spent inputs' UTXO hashes, in input order.
    pub input_utxo_hashes: Vec<[u8; 32]>,
    /// Per input `(utxo_root_index, nullifier_root_index)`, in input order.
    pub input_root_indices: Vec<(u16, u16)>,
    /// The ephemeral `tx_viewing_pk` shared by both output ciphertexts.
    pub tx_viewing_pk: [u8; 33],
    /// The 40-byte sender-change ciphertext (`amount || asset`).
    pub sender_ciphertext: [u8; 40],
    /// The 71-byte recipient ciphertext (`amount || asset || blinding`).
    pub recipient_ciphertext: [u8; 71],
    /// The derived sender-change blinding, top byte zero.
    pub change_blinding: [u8; 32],
}

/// A probed transfer: every signature-independent step is done (both output
/// UTXOs, the shared external data, and the SPP witness whose `private_tx_hash`
/// the sender must sign). [`ProbedTransfer::finalize`] takes the P256 ECDSA
/// signature over `sha256(private_tx_hash)` and produces the paired proofs. The
/// probe itself needs no owner secret, so signing can be externalized.
pub struct ProbedTransfer {
    /// The shared `private_tx_hash`. The sender signs `sha256(private_tx_hash)`.
    pub private_tx_hash: [u8; 32],
    viewing_secret: SecretKey,
    nullifier_secret_32: [u8; 32],
    zone_inputs: Vec<ZoneUtxo>,
    zone_outputs: Vec<ZoneUtxo>,
    zone_recipient: ZoneRecipient,
    external_data_hash: [u8; 32],
    proposal: Option<ZoneProposal>,
    spend_inputs: Vec<TransferSpendInput>,
    outputs: Vec<SppProofOutputUtxo>,
    external_data: ExternalData,
    public_amounts: PublicTransfers,
    payer_pubkey_hash: [u8; 32],
    owner_p256: P256Pubkey,
    squads_address: Address,
    prover_url: String,
    change_utxo_hash: [u8; 32],
    recipient_utxo_hash: [u8; 32],
    change_amount: u64,
    nullifiers: Vec<[u8; 32]>,
    input_utxo_hashes: Vec<[u8; 32]>,
    tx_viewing_pk: [u8; 33],
    sender_ciphertext: [u8; 40],
    recipient_ciphertext: [u8; 71],
    change_blinding: [u8; 32],
}

/// The signature-independent inputs to a `(2, 2)` transfer probe: the sender's
/// owner *public* key plus its spend secrets, and the transfer parameters. The
/// owner secret is never needed here (the owner signs `private_tx_hash` externally).
pub struct SquadsTransferProbe {
    /// The sender's P256 owner *public* key (signs `sha256(private_tx_hash)` off-box).
    pub owner_pubkey: P256Pubkey,
    pub nullifier_secret: [u8; 31],
    /// The zone circuit's shared viewing secret key.
    pub viewing_secret: SecretKey,
    /// The two deposited inputs to spend (both the same asset).
    pub inputs: Vec<SquadsTransferInput>,
    /// The recipient's public shielded identity.
    pub recipient: SquadsTransferRecipient,
    /// Amount routed to the recipient. The change stays as the sender's zone UTXO.
    pub transferred: u64,
    /// The 31-byte recipient-output blinding.
    pub recipient_blinding: [u8; 31],
    pub payer_pubkey_hash: [u8; 32],
    pub expiry_unix_ts: u64,
    pub salt: [u8; 16],
    pub sender_view_tag: [u8; 32],
    pub recipient_view_tag: [u8; 32],
    pub proposal: Option<ZoneProposal>,
    pub prover_url: String,
}

/// Probe a `(2, 2)` squads transfer: run every local (server-free,
/// signature-free) step and return the [`ProbedTransfer`] carrying the
/// `private_tx_hash` the sender signs.
pub fn probe_squads_transfer(
    probe: SquadsTransferProbe,
) -> Result<ProbedTransfer, SquadsProverError> {
    let SquadsTransferProbe {
        owner_pubkey,
        nullifier_secret,
        viewing_secret,
        inputs,
        recipient,
        transferred,
        recipient_blinding,
        payer_pubkey_hash,
        expiry_unix_ts,
        salt,
        sender_view_tag,
        recipient_view_tag,
        proposal,
        prover_url,
    } = probe;

    let real_count = inputs.len();
    if !(1..=2).contains(&real_count) {
        return Err(SquadsProverError::UnsupportedShape(real_count, 2));
    }
    // A single real input is padded with one dummy so the circuit shape stays (2, 2).
    // The dummy folds `[0u8; 32]` into both proofs' `private_tx_hash`, its zone slot
    // is flagged `is_dummy` and its SPP slot carries no `SpendProof`. The single real
    // input MUST stay at index 0 (its nullifier seeds the KDF and the zone circuit
    // rejects a dummy first input).
    let dummy_blinding: Option<[u8; 31]> = (real_count == 1).then(random_blinding_31);
    let squads_address = Address::new_from_array(SQUADS_ZONE_PROGRAM_ID);

    let IdentityEncodings {
        owner_p256,
        owner_public,
        owner_pk_field,
        nullifier_key,
        nullifier_pk,
        viewing_pubkey,
        nullifier_secret_32,
    } = probe_encodings(owner_pubkey, &nullifier_secret, &viewing_secret)?;

    let asset = inputs
        .first()
        .ok_or(SquadsProverError::UnsupportedShape(0, 2))?
        .asset;
    if inputs.iter().any(|input| input.asset != asset) {
        return Err(SquadsProverError::InputAssetMismatch);
    }
    let asset_fe = asset_field(&asset).map_err(|_| SquadsProverError::Poseidon)?;
    let zone_program_field =
        hash_field(&SQUADS_ZONE_PROGRAM_ID).map_err(|_| SquadsProverError::Poseidon)?;

    let total_in = inputs
        .iter()
        .try_fold(0u64, |acc, input| acc.checked_add(input.amount))
        .ok_or(SquadsProverError::InvalidAmount)?;
    let change_amount = total_in
        .checked_sub(transferred)
        .ok_or(SquadsProverError::InvalidAmount)?;

    let recipient_owner_pk_field = recipient.owner_pk_field;
    let recipient_blinding_fe = right_align_31(&recipient_blinding);

    let input_zone_utxos: Vec<ZoneUtxo> = inputs
        .iter()
        .map(|input| ZoneUtxo {
            owner_key_hash: owner_pk_field,
            nullifier_pubkey: nullifier_pk,
            asset: asset_fe,
            amount: input.amount,
            blinding: right_align_31(&input.blinding),
            program_data_hash: [0u8; 32],
            ring_data_hash: [0u8; 32],
            ring_program_id: zone_program_field,
            is_dummy: false,
        })
        .collect();
    let input_spp_utxos: Vec<Utxo> = inputs
        .iter()
        .map(|input| Utxo {
            owner: owner_public,
            asset,
            amount: input.amount,
            blinding: right_align_31(&input.blinding),
            ring_program_id: Some(squads_address),
            data: Data::default(),
        })
        .collect();

    let mut input_utxo_hashes = Vec::with_capacity(2);
    let mut nullifiers = Vec::with_capacity(2);
    for (spp, input) in input_spp_utxos.iter().zip(inputs.iter()) {
        let utxo_hash = spp
            .hash(&nullifier_pk, &[0u8; 32], &[0u8; 32])
            .map_err(|_| SquadsProverError::Poseidon)?;
        let nullifier = nullifier_key
            .nullifier(&utxo_hash, &right_align_31(&input.blinding))
            .map_err(|_| SquadsProverError::Poseidon)?;
        input_utxo_hashes.push(utxo_hash);
        nullifiers.push(nullifier);
    }

    let first_input_zone = input_zone_utxos
        .first()
        .ok_or(SquadsProverError::MissingSlot)?;
    let artifacts = TransferOutputs {
        change_amount,
        change_asset: &asset_fe,
        recipient_viewing_pubkey: &recipient.viewing_pubkey,
        transferred_amount: transferred,
        transferred_asset: &asset_fe,
        recipient_blinding: &recipient_blinding_fe,
    }
    .derive(&viewing_secret, &nullifier_secret_32, first_input_zone)?;
    let change_blinding = artifacts.change_blinding;
    let sender_ciphertext: [u8; 40] = artifacts
        .sender_ciphertext
        .as_slice()
        .try_into()
        .map_err(|_| SquadsProverError::InvalidProofEncoding)?;
    let recipient_ciphertext: [u8; 71] = artifacts
        .recipient_ciphertext
        .as_slice()
        .try_into()
        .map_err(|_| SquadsProverError::InvalidProofEncoding)?;
    let tx_viewing_pk = artifacts.tx_viewing_pk;

    let mut zone_inputs = input_zone_utxos;
    if let Some(dummy_blinding) = dummy_blinding {
        zone_inputs.push(ZoneUtxo {
            owner_key_hash: [0u8; 32],
            nullifier_pubkey: [0u8; 32],
            asset: [0u8; 32],
            amount: 0,
            blinding: right_align_31(&dummy_blinding),
            program_data_hash: [0u8; 32],
            ring_data_hash: [0u8; 32],
            ring_program_id: [0u8; 32],
            is_dummy: true,
        });
    }

    let change_zone_utxo = ZoneUtxo {
        owner_key_hash: owner_pk_field,
        nullifier_pubkey: nullifier_pk,
        asset: asset_fe,
        amount: change_amount,
        blinding: change_blinding,
        program_data_hash: [0u8; 32],
        ring_data_hash: [0u8; 32],
        ring_program_id: zone_program_field,
        is_dummy: false,
    };
    let change_spp_utxo = SppProofOutputUtxo {
        asset,
        amount: change_amount,
        blinding: change_blinding,
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

    let recipient_zone_utxo = ZoneUtxo {
        owner_key_hash: recipient_owner_pk_field,
        nullifier_pubkey: recipient.nullifier_pubkey,
        asset: asset_fe,
        amount: transferred,
        blinding: recipient_blinding_fe,
        program_data_hash: [0u8; 32],
        ring_data_hash: [0u8; 32],
        ring_program_id: zone_program_field,
        is_dummy: false,
    };
    // The recipient's signing key is unknown. A synthetic PublicKey carrying the
    // recipient's owner_pk_field yields the identical owner_hash (and prover
    // owner-field) as the real key would, so the recipient output hashes and proves
    // the same without holding the raw recipient pubkey.
    let recipient_spp_utxo = SppProofOutputUtxo {
        asset,
        amount: transferred,
        blinding: recipient_blinding_fe,
        ring_program_id: Some(squads_address),
        ring_data_hash: None,
        data_hash: None,
        owner_address: Some(ShieldedAddress {
            signing_pubkey: PublicKey::from_owner_proof_input_hash(recipient_owner_pk_field),
            nullifier_pubkey: recipient.nullifier_pubkey,
            viewing_pubkey: recipient.viewing_pubkey,
        }),
        owner_tag: None,
        data: Data::default(),
    };
    let recipient_utxo_hash = recipient_spp_utxo
        .hash()
        .map_err(|_| SquadsProverError::Poseidon)?;

    let mut external_data = ExternalData::new(
        tx_viewing_pk,
        salt,
        vec![
            TransactOutput {
                utxo_hash: change_utxo_hash,
                owner_tag: OwnerTag::Inline(sender_view_tag),
                data: Some(sender_ciphertext.to_vec()),
            },
            TransactOutput {
                utxo_hash: recipient_utxo_hash,
                owner_tag: OwnerTag::Inline(recipient_view_tag),
                data: Some(recipient_ciphertext.to_vec()),
            },
        ],
        vec![sender_view_tag, recipient_view_tag],
        Vec::new(),
    );
    external_data.instruction_discriminator = RING_TRANSACT;
    external_data.expiry_unix_ts = expiry_unix_ts;
    let external_data_hash = external_data
        .hash()
        .map_err(|_| SquadsProverError::Poseidon)?;

    let zone_recipient = ZoneRecipient {
        owner_key_hash: recipient_owner_pk_field,
        nullifier_pubkey: recipient.nullifier_pubkey,
        viewing_pubkey: recipient.viewing_pubkey,
    };

    let public_amounts = PublicTransfers::default();
    let mut spend_inputs: Vec<TransferSpendInput> = input_spp_utxos
        .iter()
        .cloned()
        .zip(inputs)
        .map(|(utxo, input)| TransferSpendInput {
            utxo,
            nullifier_key: nullifier_key.clone(),
            data_hash: None,
            ring_data_hash: None,
            proof: Some(input.spend_proof),
            nullifier_proof: None,
        })
        .collect();
    if let Some(dummy_blinding) = dummy_blinding {
        // A proofless (dummy) SPP slot: only its blinding is read (it mirrors the first
        // real input's roots) and it folds a `[0u8; 32]` input hash. The shared
        // `dummy_blinding` keeps its zone and SPP slots consistent.
        spend_inputs.push(TransferSpendInput {
            utxo: Utxo {
                owner: owner_public,
                asset,
                amount: 0,
                blinding: right_align_31(&dummy_blinding),
                ring_program_id: Some(squads_address),
                data: Data::default(),
            },
            nullifier_key: nullifier_key.clone(),
            data_hash: None,
            ring_data_hash: None,
            proof: None,
            nullifier_proof: None,
        });
    }
    let outputs = vec![change_spp_utxo, recipient_spp_utxo];

    // The unsigned prover already fixes the digest the owner signs.
    let private_tx_hash = SppRingSpend {
        spend_inputs: &spend_inputs,
        outputs: &outputs,
        external_data: &external_data,
        public_amounts: &public_amounts,
        payer_pubkey_hash,
        owner_p256,
        zone: squads_address,
    }
    .unsigned()
    .private_tx_hash()
    .map_err(spp_err)?;

    Ok(ProbedTransfer {
        private_tx_hash,
        viewing_secret,
        nullifier_secret_32,
        zone_inputs,
        zone_outputs: vec![change_zone_utxo, recipient_zone_utxo],
        zone_recipient,
        external_data_hash,
        proposal,
        spend_inputs,
        outputs,
        external_data,
        public_amounts,
        payer_pubkey_hash,
        owner_p256,
        squads_address,
        prover_url,
        change_utxo_hash,
        recipient_utxo_hash,
        change_amount,
        nullifiers,
        input_utxo_hashes,
        tx_viewing_pk,
        sender_ciphertext,
        recipient_ciphertext,
        change_blinding,
    })
}

impl ProbedTransfer {
    fn spp_spend(&self) -> SppRingSpend<'_> {
        SppRingSpend {
            spend_inputs: &self.spend_inputs,
            outputs: &self.outputs,
            external_data: &self.external_data,
            public_amounts: &self.public_amounts,
            payer_pubkey_hash: self.payer_pubkey_hash,
            owner_p256: self.owner_p256,
            zone: self.squads_address,
        }
    }

    /// Finalize with the sender's P256 ECDSA signature `(sig_r, sig_s)` over
    /// `sha256(private_tx_hash)`: prove the squads zone rail, prove the signed SPP
    /// zone rail, and assemble the paired [`SquadsTransferProof`]. Cross-checks that
    /// the two proofs agree on `private_tx_hash`, nullifiers, and output hashes.
    pub fn finalize(
        self,
        sig_r: [u8; 32],
        sig_s: [u8; 32],
    ) -> Result<SquadsTransferProof, SquadsProverError> {
        let zone_result = ZoneProofInputs {
            viewing_secret_key: self.viewing_secret.clone(),
            nullifier_secret: self.nullifier_secret_32,
            inputs: self.zone_inputs.clone(),
            outputs: self.zone_outputs.clone(),
            external_data_hash: self.external_data_hash,
            recipient: Some(self.zone_recipient.clone()),
            proposal: self.proposal.clone(),
            public_amount: fe_from_u64(0),
        }
        .prove(&self.prover_url)?;
        if zone_result.change_blinding != self.change_blinding
            || zone_result.sender_ciphertext != self.sender_ciphertext
            || zone_result.recipient_ciphertext != self.recipient_ciphertext
            || zone_result.tx_viewing_pk != Some(self.tx_viewing_pk)
        {
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

        if zone_result.private_tx_hash != final_prover.private_tx_hash {
            return Err(SquadsProverError::ProofValidation(format!(
                "private_tx_hash mismatch: zone {:?} vs spp {:?}",
                zone_result.private_tx_hash, final_prover.private_tx_hash
            )));
        }
        // Only the real slots (0..real_count) are checked. A padded dummy's nullifier
        // comes from the SPP witness with no real spend to reconstruct against.
        let real_count = self.nullifiers.len();
        if final_prover.nullifiers.get(..real_count) != Some(self.nullifiers.as_slice()) {
            return Err(SquadsProverError::ProofValidation(
                "SPP nullifiers do not match the reconstructed nullifiers".to_string(),
            ));
        }
        if final_prover.output_hashes != vec![self.change_utxo_hash, self.recipient_utxo_hash] {
            return Err(SquadsProverError::ProofValidation(
                "SPP output hashes do not match the reconstructed hashes".to_string(),
            ));
        }

        Ok(SquadsTransferProof {
            zone_proof: zone_result.proof,
            spp_proof,
            private_tx_hash: zone_result.private_tx_hash,
            proposal_hash: zone_result.proposal_hash,
            change_utxo_hash: self.change_utxo_hash,
            recipient_utxo_hash: self.recipient_utxo_hash,
            change_amount: self.change_amount,
            // The full (2-slot) nullifier set, including any padded dummy, so the
            // caller's per-slot `InputContext` lines up with `input_root_indices`.
            nullifiers: final_prover.nullifiers,
            input_utxo_hashes: self.input_utxo_hashes,
            input_root_indices: final_prover.input_root_indices,
            tx_viewing_pk: self.tx_viewing_pk,
            sender_ciphertext: self.sender_ciphertext,
            recipient_ciphertext: self.recipient_ciphertext,
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

/// Build the paired zone + SPP-rail proofs for a `(2, 2)` squads transfer. A thin
/// wrapper over [`probe_squads_transfer`] + [`ProbedTransfer::finalize`] that
/// probes with the sender's public key and signs `sha256(private_tx_hash)` with
/// the held owner secret.
pub fn prove_squads_transfer(
    req: SquadsTransferRequest,
) -> Result<SquadsTransferProof, SquadsProverError> {
    let owner_secret = req.identity.owner_secret.clone();
    let owner_pubkey = P256Pubkey::from_p256(&owner_secret.public_key());
    let probed = probe_squads_transfer(SquadsTransferProbe {
        owner_pubkey,
        nullifier_secret: req.identity.nullifier_secret,
        viewing_secret: req.identity.viewing_secret,
        inputs: req.inputs,
        recipient: req.recipient,
        transferred: req.transferred,
        recipient_blinding: req.recipient_blinding,
        payer_pubkey_hash: req.payer_pubkey_hash,
        expiry_unix_ts: req.expiry_unix_ts,
        salt: req.salt,
        sender_view_tag: req.sender_view_tag,
        recipient_view_tag: req.recipient_view_tag,
        proposal: req.proposal,
        prover_url: req.prover_url,
    })?;
    let signature = SigningKey::from_bytes(&secret_bytes(&owner_secret))
        .map_err(|_| SquadsProverError::InvalidPubkey)?
        .sign(&sha256(&probed.private_tx_hash));
    let (sig_r, sig_s) = split_signature(&signature)?;
    probed.finalize(sig_r, sig_s)
}
