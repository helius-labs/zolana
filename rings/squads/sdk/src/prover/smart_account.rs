//! Paired zone + SPP zone-authority proof builders for a Squads-vault-owned
//! shielded account (gated under the `prover` feature).
//!
//! A smart-account owner is a Squads vault: an ed25519 `Address` with no shielded
//! signing key. Its shielded owner field is `owner_pk_field = hash_field(vault)`.
//! The vault cannot sign, so settlement uses the SPP zone-authority rail
//! (`zone_authority_transact`): the zone authorizes the spend via its `zone_config`
//! PDA and, for the async path, an approved proposal binds the operation. There is
//! NO P256/owner signature anywhere in these builders.
//!
//! Like the P256 builders ([`prove_squads_transfer`](super::transfer::prove_squads_transfer),
//! [`prove_squads_withdrawal`](super::withdrawal::prove_squads_withdrawal)) each
//! function forwards TWO proofs that must agree on one shared `private_tx_hash`:
//! 1. the squads ZONE proof ([`ZoneProofInputs`], keyed by the vault's
//!    `nullifier_secret` + `viewing_secret`, with `owner_key_hash` = the vault owner
//!    field), and
//! 2. the SPP zone-authority proof ([`RingAuthorityProver`], `zone_authority`), a
//!    vanilla Groth16 proof with no BSB22 commitment and no signature.
//!
//! Both provers fold the SAME [`ExternalData`] and the SAME input/output UTXOs into
//! `private_tx_hash(input_hashes, output_hashes, no_address_hashes(len),
//! external_data_hash)`, so the two hashes match by construction. Each builder
//! cross-checks that equality plus the reconstructed nullifiers and output hashes.
//!
//! The SPP zone-authority rail recomputes `external_data_hash` with the
//! `RING_AUTHORITY_TRANSACT` discriminator (that is the SPP instruction the zone
//! CPIs into), so the shared [`ExternalData`] uses that discriminator here -- the
//! one field that differs from the P256 builders.

use p256::SecretKey;
use zolana_client::{
    Proof, ProofCompressed, ProverClient, PublicTransfers, RingAuthorityProver, Shape,
    TransferSpendInput,
};
use zolana_interface::instruction::{
    instruction_data::transact::{OwnerTag, TransactOutput},
    tag::RING_AUTHORITY_TRANSACT,
};
use zolana_keypair::{NullifierKey, P256Pubkey, PublicKey, ShieldedAddress};
use zolana_transaction::{
    instructions::transact::asset_field, Address, Data, ExternalData, SppProofOutputUtxo, Utxo,
};

use zolana_squads_interface::SQUADS_ZONE_PROGRAM_ID;

use crate::{
    crypto::{fe_from_u64, low_31, random_blinding_31, right_align_31},
    prover::{
        error::SquadsProverError,
        shared_viewing_key::hash_field,
        shared_viewing_key::{
            withdrawal_public_transfers, withdrawal_transfer, WithdrawalDestination,
        },
        transfer::{SquadsTransferInput, SquadsTransferProof, SquadsTransferRecipient},
        withdrawal::{spp_err, SquadsWithdrawalInput, SquadsWithdrawalProof},
        zone::{
            derive_sender_artifacts, TransferOutputs, ZoneProofInputs, ZoneProposal, ZoneRecipient,
            ZoneUtxo,
        },
    },
};

/// A Squads-vault-owned shielded identity: the secrets needed to spend a zone UTXO
/// the vault owns. Unlike [`SquadsIdentity`](super::withdrawal::SquadsIdentity)
/// there is NO owner signing key -- the vault settles signatureless via the SPP
/// zone-authority rail. The shielded owner field is `hash_field(owner_vault)`.
#[derive(Clone)]
pub struct SquadsSmartAccountIdentity {
    /// The Squads vault (an ed25519 Solana pubkey).
    pub owner_vault: Address,
    /// `NullifierKey.pubkey()` must equal the VKA's `nullifier_pubkey`.
    pub nullifier_secret: [u8; 31],
    /// The zone circuit's shared viewing secret key.
    pub viewing_secret: SecretKey,
}

impl SquadsSmartAccountIdentity {
    /// The vault's shielded owner public key: an ed25519 [`PublicKey`] whose
    /// `owner_pk_field()` equals `hash_field(owner_vault)` and whose
    /// `confidential_view_tag()` is the 32-byte vault key.
    pub fn owner_public(&self) -> PublicKey {
        PublicKey::from_ed25519(&self.owner_vault.to_bytes())
    }

    /// The vault's shielded owner field element (`hash_field(owner_vault)`), used as
    /// the zone `owner_key_hash` and folded into SPP's `owner_hash`.
    pub fn owner_pk_field(&self) -> Result<[u8; 32], SquadsProverError> {
        self.owner_public()
            .owner_proof_input_hash()
            .map_err(|_| SquadsProverError::InvalidPubkey)
    }
}

/// The rail-agnostic field encodings a smart-account identity contributes to both
/// proofs. Mirrors [`IdentityEncodings`](super::withdrawal::IdentityEncodings)
/// minus the P256 owner (there is no owner signing key).
struct SmartAccountEncodings {
    owner_public: PublicKey,
    owner_pk_field: [u8; 32],
    nullifier_key: NullifierKey,
    nullifier_pk: [u8; 32],
    viewing_pubkey: P256Pubkey,
    nullifier_secret_32: [u8; 32],
}

fn smart_account_encodings(
    identity: &SquadsSmartAccountIdentity,
) -> Result<SmartAccountEncodings, SquadsProverError> {
    let owner_public = identity.owner_public();
    let owner_pk_field = identity.owner_pk_field()?;
    let nullifier_key = NullifierKey::from_secret(identity.nullifier_secret);
    let nullifier_pk = nullifier_key
        .pubkey()
        .map_err(|_| SquadsProverError::Poseidon)?;
    let viewing_pubkey = P256Pubkey::from_p256(&identity.viewing_secret.public_key());
    let nullifier_secret_32 = right_align_31(&identity.nullifier_secret);
    Ok(SmartAccountEncodings {
        owner_public,
        owner_pk_field,
        nullifier_key,
        nullifier_pk,
        viewing_pubkey,
        nullifier_secret_32,
    })
}

/// Everything the paired-proof builder needs for a `(2, 2)` smart-account transfer.
/// Mirrors [`SquadsTransferRequest`](super::transfer::SquadsTransferRequest) but
/// keyed by a signatureless [`SquadsSmartAccountIdentity`].
pub struct SquadsSmartAccountTransferRequest {
    /// The ring-authority circuit binds this fee payer as the single signer.
    pub payer_address: Address,
    pub identity: SquadsSmartAccountIdentity,
    /// The two deposited inputs to spend (both the same asset).
    pub inputs: Vec<SquadsTransferInput>,
    /// The recipient's public shielded identity (an ordinary P256 recipient).
    pub recipient: SquadsTransferRecipient,
    /// Amount routed to the recipient. The change stays as the vault's zone UTXO.
    pub transferred: u64,
    /// The 31-byte recipient-output blinding (right-aligned into a field element).
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

/// Everything the paired-proof builder needs for a `(1, 1)` smart-account
/// withdrawal. Mirrors
/// [`SquadsWithdrawalRequest`](super::withdrawal::SquadsWithdrawalRequest) but keyed
/// by a signatureless [`SquadsSmartAccountIdentity`].
pub struct SquadsSmartAccountWithdrawalRequest {
    pub identity: SquadsSmartAccountIdentity,
    pub input: SquadsWithdrawalInput,
    /// The public amount to withdraw out of the pool. `change = input.amount -
    /// withdrawn` stays as a zone UTXO.
    pub withdrawn: u64,
    /// The public destination, which also selects the settlement rail.
    pub destination: WithdrawalDestination,
    /// Settled mint. Bound into the interface transfer SPP recomputes.
    pub asset: Address,
    /// The ring-authority circuit binds this fee payer as the single signer.
    pub payer_address: Address,
    /// Sha256-BE of the SPP payer address (the squads `payer` account SPP sees).
    pub payer_pubkey_hash: [u8; 32],
    /// Transaction expiry (folded into `external_data_hash`).
    pub expiry_unix_ts: u64,
    /// Per-transaction salt. Forwarded to SPP, not bound by `external_data_hash`.
    pub salt: [u8; 16],
    /// The sender-change output ciphertext view tag.
    pub sender_view_tag: [u8; 32],
    /// A bound proposal for `execute_proposal`. `None` for a sync `transact`.
    pub proposal: Option<ZoneProposal>,
    pub prover_url: String,
}

/// Build the paired zone + SPP zone-authority proofs for a smart-account transfer.
/// The circuit shape is fixed `(2, 2)`. `inputs.len()` may be 1 or 2. A single real
/// input is paired with one synthesized dummy input so the shape holds: the dummy
/// contributes `[0u8; 32]` to both proofs' `private_tx_hash` folds, its zone slot is
/// flagged `is_dummy` (amount pinned to 0), and its SPP slot carries no `SpendProof`
/// (it mirrors the first real input's roots). The single real input MUST occupy
/// index 0 (its nullifier seeds the `tx_viewing_sk` KDF, and the zone circuit rejects
/// a dummy first input). The result reuses [`SquadsTransferProof`]. Its `spp_proof`
/// holds the 128-byte vanilla Groth16 proof in bytes `0..128` (bytes `128..192`
/// zero-padded), matching the on-chain `decompose_proof` `SmartAccount` branch.
pub fn prove_squads_smart_account_transfer(
    req: SquadsSmartAccountTransferRequest,
) -> Result<SquadsTransferProof, SquadsProverError> {
    let SquadsSmartAccountTransferRequest {
        identity,
        inputs,
        recipient,
        transferred,
        recipient_blinding,
        expiry_unix_ts,
        salt,
        sender_view_tag,
        recipient_view_tag,
        proposal,
        prover_url,
        ..
    } = req;

    let real_count = inputs.len();
    if !(1..=2).contains(&real_count) {
        return Err(SquadsProverError::UnsupportedShape(real_count, 2));
    }
    let dummy_blinding: Option<[u8; 31]> = (real_count == 1).then(random_blinding_31);
    let squads_address = Address::new_from_array(SQUADS_ZONE_PROGRAM_ID);

    let SmartAccountEncodings {
        owner_public,
        owner_pk_field,
        nullifier_key,
        nullifier_pk,
        viewing_pubkey,
        nullifier_secret_32,
    } = smart_account_encodings(&identity)?;

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
    .derive(
        &identity.viewing_secret,
        &nullifier_secret_32,
        first_input_zone,
    )?;
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
    external_data.instruction_discriminator = RING_AUTHORITY_TRANSACT;
    external_data.expiry_unix_ts = expiry_unix_ts;
    let external_data_hash = external_data
        .hash()
        .map_err(|_| SquadsProverError::Poseidon)?;

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
    let zone_result = ZoneProofInputs {
        viewing_secret_key: identity.viewing_secret.clone(),
        nullifier_secret: nullifier_secret_32,
        inputs: zone_inputs,
        outputs: vec![change_zone_utxo, recipient_zone_utxo],
        external_data_hash,
        recipient: Some(ZoneRecipient {
            owner_key_hash: recipient_owner_pk_field,
            nullifier_pubkey: recipient.nullifier_pubkey,
            viewing_pubkey: recipient.viewing_pubkey,
        }),
        proposal,
        public_amount: fe_from_u64(0),
    }
    .prove(&prover_url)?;
    if zone_result.change_blinding != change_blinding
        || zone_result.sender_ciphertext != artifacts.sender_ciphertext
        || zone_result.recipient_ciphertext != artifacts.recipient_ciphertext
        || zone_result.tx_viewing_pk != Some(tx_viewing_pk)
    {
        return Err(SquadsProverError::BlindingMismatch);
    }

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
        // A proofless (dummy) SPP slot: only its blinding is read (it mirrors the
        // first real input's roots), and it folds a [0u8; 32] input hash. The shared
        // dummy_blinding keeps its zone and SPP slots consistent.
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

    let zone_authority_result = RingAuthorityProver {
        inputs: spend_inputs,
        outputs,
        external_data,
        public_transfers: public_amounts,
        payer: req.payer_address,
        allow_dummy_inputs: true,
        ring_program_id: Some(squads_address),
        shape: Some(Shape::new(2, 2)),
    }
    .build()
    .map_err(spp_err)?;
    let spp_proof_raw = ProverClient::new(prover_url.clone())
        .prove_ring_authority(&zone_authority_result.inputs)
        .map_err(spp_err)?;
    let spp_proof = pack_vanilla_proof(&spp_proof_raw)?;

    if zone_result.private_tx_hash != zone_authority_result.private_tx_hash {
        return Err(SquadsProverError::ProofValidation(format!(
            "private_tx_hash mismatch: zone {:?} vs spp {:?}",
            zone_result.private_tx_hash, zone_authority_result.private_tx_hash
        )));
    }
    // Only the real slots (0..real_count) are checked. A padded dummy's nullifier
    // comes from the SPP witness with no real spend to reconstruct against.
    if zone_authority_result.nullifiers.get(..real_count) != Some(nullifiers.as_slice()) {
        return Err(SquadsProverError::ProofValidation(
            "SPP nullifiers do not match the reconstructed nullifiers".to_string(),
        ));
    }
    if zone_authority_result.output_hashes != vec![change_utxo_hash, recipient_utxo_hash] {
        return Err(SquadsProverError::ProofValidation(
            "SPP output hashes do not match the reconstructed hashes".to_string(),
        ));
    }

    Ok(SquadsTransferProof {
        zone_proof: zone_result.proof,
        spp_proof,
        private_tx_hash: zone_result.private_tx_hash,
        proposal_hash: zone_result.proposal_hash,
        change_utxo_hash,
        recipient_utxo_hash,
        change_amount,
        // The full (2-slot) nullifier set, including the padded dummy, so the caller's
        // per-slot InputContext lines up with `input_root_indices`.
        nullifiers: zone_authority_result.nullifiers,
        input_utxo_hashes,
        input_root_indices: zone_authority_result.input_root_indices,
        tx_viewing_pk,
        sender_ciphertext,
        recipient_ciphertext,
        change_blinding,
    })
}

/// Build the paired zone + SPP zone-authority proofs for a `(1, 1)` smart-account
/// withdrawal. The result reuses [`SquadsWithdrawalProof`]. Its `spp_proof` holds
/// the 128-byte vanilla Groth16 proof in bytes `0..128` (bytes `128..192`
/// zero-padded), matching the on-chain `decompose_proof` `SmartAccount` branch.
pub fn prove_squads_smart_account_withdrawal(
    req: SquadsSmartAccountWithdrawalRequest,
) -> Result<SquadsWithdrawalProof, SquadsProverError> {
    let squads_address = Address::new_from_array(SQUADS_ZONE_PROGRAM_ID);

    let SmartAccountEncodings {
        owner_public,
        owner_pk_field,
        nullifier_key,
        nullifier_pk,
        viewing_pubkey,
        nullifier_secret_32,
    } = smart_account_encodings(&req.identity)?;
    let asset_fe = asset_field(&req.input.asset).map_err(|_| SquadsProverError::Poseidon)?;
    let zone_program_field =
        hash_field(&SQUADS_ZONE_PROGRAM_ID).map_err(|_| SquadsProverError::Poseidon)?;

    let change_amount = req
        .input
        .amount
        .checked_sub(req.withdrawn)
        .ok_or(SquadsProverError::InvalidAmount)?;

    let input_zone_utxo = ZoneUtxo {
        owner_key_hash: owner_pk_field,
        nullifier_pubkey: nullifier_pk,
        asset: asset_fe,
        amount: req.input.amount,
        blinding: right_align_31(&req.input.blinding),
        program_data_hash: [0u8; 32],
        ring_data_hash: [0u8; 32],
        ring_program_id: zone_program_field,
        is_dummy: false,
    };
    let input_spp_utxo = Utxo {
        owner: owner_public,
        asset: req.input.asset,
        amount: req.input.amount,
        blinding: right_align_31(&req.input.blinding),
        ring_program_id: Some(squads_address),
        data: Data::default(),
    };
    let input_utxo_hash = input_spp_utxo
        .hash(&nullifier_pk, &[0u8; 32], &[0u8; 32])
        .map_err(|_| SquadsProverError::Poseidon)?;
    let nullifier = nullifier_key
        .nullifier(&input_utxo_hash, &right_align_31(&req.input.blinding))
        .map_err(|_| SquadsProverError::Poseidon)?;

    let artifacts = derive_sender_artifacts(
        &req.identity.viewing_secret,
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
        .map_err(|_| SquadsProverError::InvalidProofEncoding)?;
    let change_blinding_31 = low_31(&change_blinding);

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
        asset: req.input.asset,
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
        req.salt,
        vec![TransactOutput {
            utxo_hash: change_utxo_hash,
            owner_tag: OwnerTag::Inline(req.sender_view_tag),
            data: Some(sender_ciphertext.to_vec()),
        }],
        vec![req.sender_view_tag],
        Vec::new(),
    );
    external_data.instruction_discriminator = RING_AUTHORITY_TRANSACT;
    external_data.expiry_unix_ts = req.expiry_unix_ts;
    let external_data = external_data
        .with_interface_transfer(withdrawal_transfer(
            req.destination,
            req.withdrawn,
            req.asset,
        ))
        .map_err(|_| SquadsProverError::Poseidon)?;
    let external_data_hash = external_data
        .hash()
        .map_err(|_| SquadsProverError::Poseidon)?;

    let public_amount = fe_from_u64(req.withdrawn);
    let zone_result = ZoneProofInputs {
        viewing_secret_key: req.identity.viewing_secret.clone(),
        nullifier_secret: nullifier_secret_32,
        inputs: vec![input_zone_utxo],
        outputs: vec![change_zone_utxo],
        external_data_hash,
        recipient: None,
        proposal: req.proposal,
        public_amount,
    }
    .prove(&req.prover_url)?;
    if zone_result.change_blinding != change_blinding {
        return Err(SquadsProverError::BlindingMismatch);
    }
    if zone_result.sender_ciphertext != sender_ciphertext {
        return Err(SquadsProverError::BlindingMismatch);
    }

    let public_amounts = withdrawal_public_transfers(req.destination, req.withdrawn, asset_fe)?;
    let spend_input = TransferSpendInput {
        utxo: input_spp_utxo,
        nullifier_key: nullifier_key.clone(),
        data_hash: None,
        ring_data_hash: None,
        proof: Some(req.input.spend_proof),
        nullifier_proof: None,
    };

    let zone_authority_result = RingAuthorityProver {
        inputs: vec![spend_input],
        outputs: vec![change_spp_utxo],
        external_data,
        public_transfers: public_amounts,
        payer: req.payer_address,
        allow_dummy_inputs: true,
        ring_program_id: Some(squads_address),
        shape: Some(Shape::new(1, 1)),
    }
    .build()
    .map_err(spp_err)?;
    let spp_proof_raw = ProverClient::new(req.prover_url.clone())
        .prove_ring_authority(&zone_authority_result.inputs)
        .map_err(spp_err)?;
    let spp_proof = pack_vanilla_proof(&spp_proof_raw)?;

    if zone_result.private_tx_hash != zone_authority_result.private_tx_hash {
        return Err(SquadsProverError::ProofValidation(format!(
            "private_tx_hash mismatch: zone {:?} vs spp {:?}",
            zone_result.private_tx_hash, zone_authority_result.private_tx_hash
        )));
    }
    if zone_authority_result.nullifiers.first().copied() != Some(nullifier) {
        return Err(SquadsProverError::ProofValidation(
            "SPP nullifier does not match the reconstructed nullifier".to_string(),
        ));
    }
    if zone_authority_result.output_hashes.first().copied() != Some(change_utxo_hash) {
        return Err(SquadsProverError::ProofValidation(
            "SPP change output hash does not match the reconstructed hash".to_string(),
        ));
    }
    let &(utxo_root_index, nullifier_root_index) = zone_authority_result
        .input_root_indices
        .first()
        .ok_or(SquadsProverError::MissingSlot)?;

    Ok(SquadsWithdrawalProof {
        zone_proof: zone_result.proof,
        spp_proof,
        private_tx_hash: zone_result.private_tx_hash,
        proposal_hash: zone_result.proposal_hash,
        change_utxo_hash,
        nullifier,
        input_utxo_hash,
        utxo_root_index,
        nullifier_root_index,
        sender_ciphertext,
        change_blinding,
    })
}

/// Pack a vanilla (non-committed) Groth16 proof into the 192-byte layout SPP reads
/// for the zone-authority `SmartAccount` rail: `a || b || c` in bytes `0..128`, the
/// trailing `128..192` zero-padded. The on-chain `decompose_proof` reads only the
/// leading 128 bytes as `TransactProof::Eddsa`.
fn pack_vanilla_proof(proof: &Proof) -> Result<[u8; 192], SquadsProverError> {
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
    Ok(out)
}
