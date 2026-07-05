//! Builds the SPP `zone_transact` instruction data (tag-prefixed, wincode
//! serialized) the zone forwards via CPI. Transfer leg only: settlement (the
//! withdrawal leg) is not yet supported (see
//! `SquadsZoneError::ZoneSettlementNotImplemented` at call sites).

use zolana_interface::instruction::{
    tag::{ZONE_AUTHORITY_TRANSACT, ZONE_TRANSACT},
    InputUtxo, OutputCiphertext, TransactIxData as SppTransactIxData,
    TransactProof as SppTransactProof,
};
use zolana_squads_interface::{
    error::SquadsZoneError,
    instruction::instruction_data::{transact::InputContext, EncryptedUtxos},
    types::ProofBytes,
};

/// Mirrors `P256_OWNED_SIGNER` in the shielded-pool program
/// (`programs/shielded-pool/src/instructions/transact/verify.rs`) and in the
/// Rust prover client (`sdk-libs/client/src/prover/transact/witness.rs`):
/// a P256-owned input carries no per-input ed25519 signer index.
const P256_OWNED_SIGNER: u8 = 255;

/// A non-P256 `eddsa_signer_index` for the smart-account (zone-authority) rail.
/// `zone_authority_transact` skips the per-input signer check entirely, so the
/// value is unused there; it must only differ from `P256_OWNED_SIGNER` so SPP's
/// `is_p256()` stays false and the vanilla zone-authority verifying key is used.
const SMART_ACCOUNT_SIGNER_INDEX: u8 = 0;

/// Which SPP settlement rail the zone forwards a spend through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SppSettlementRail {
    /// Keypair/P256 owner: SPP `zone_transact` with a BSB22-committed P256 proof
    /// (the owner's P256 signature over `private_tx_hash` authorizes the spend).
    P256,
    /// Smart-account owner (a Squads vault, no signing key): SPP
    /// `zone_authority_transact` with a vanilla `Eddsa` proof and no owner
    /// signature; the zone authorizes via its `zone_config` PDA and (async) an
    /// approved proposal binds the operation.
    SmartAccount,
}

impl SppSettlementRail {
    /// The settlement rail for a sender viewing key account's `owner_kind`:
    /// smart-account owners settle signatureless via `zone_authority_transact`,
    /// keypair/P256 owners via the P256 `zone_transact`.
    pub fn for_owner_kind(owner_kind: u8) -> Self {
        if owner_kind == zolana_squads_interface::constants::OWNER_KIND_SMART_ACCOUNT {
            SppSettlementRail::SmartAccount
        } else {
            SppSettlementRail::P256
        }
    }

    fn tag(self) -> u8 {
        match self {
            SppSettlementRail::P256 => ZONE_TRANSACT,
            SppSettlementRail::SmartAccount => ZONE_AUTHORITY_TRANSACT,
        }
    }

    fn signer_index(self) -> u8 {
        match self {
            SppSettlementRail::P256 => P256_OWNED_SIGNER,
            SppSettlementRail::SmartAccount => SMART_ACCOUNT_SIGNER_INDEX,
        }
    }
}

/// Inputs needed to build SPP's `zone_transact` instruction data for a pure
/// transfer (no settlement): everything the zone's own `TransactIxData` /
/// `ExecuteProposalIxData` carries, minus the fields SPP computes itself
/// (`zone_program_id` from the CPI-signing `ZoneConfig`, `payer_pubkey_hash`
/// from the CPI's `payer` account).
pub struct SppZoneTransferParams<'a> {
    pub expiry_unix_ts: u64,
    pub private_tx_hash: [u8; 32],
    pub spp_proof: &'a ProofBytes,
    pub salt: [u8; 16],
    pub output_view_tags: &'a [[u8; 32]],
    pub output_utxo_hashes: &'a [[u8; 32]],
    pub input_contexts: &'a [InputContext],
    pub encrypted_utxos: &'a EncryptedUtxos,
    /// P256 (`zone_transact`) or smart-account (`zone_authority_transact`) rail.
    pub rail: SppSettlementRail,
}

/// Build the tag-prefixed, wincode-serialized SPP instruction data for a
/// transfer, on the P256 (`zone_transact`) or smart-account
/// (`zone_authority_transact`) rail. Every field SPP would otherwise read from
/// settlement accounts (`public_sol_amount`, `public_spl_amount`, `data_hash`,
/// `zone_data_hash`) is `None`, matching SPP's own zeroed values for a
/// settlement-less transact (`transact/processor.rs::settlement_accounts`).
pub fn build_spp_zone_transfer_data(
    params: SppZoneTransferParams<'_>,
) -> Result<Vec<u8>, SquadsZoneError> {
    let proof = decompose_proof(params.spp_proof, params.rail)?;
    let inputs = build_inputs(params.input_contexts, params.rail);
    let output_ciphertexts =
        build_output_ciphertexts(params.encrypted_utxos, params.output_view_tags)?;

    let ix_data = SppTransactIxData {
        expiry_unix_ts: params.expiry_unix_ts,
        relayer_fee: 0,
        private_tx_hash: params.private_tx_hash,
        p256_signing_pk_field: None,
        tx_viewing_pk: params.encrypted_utxos.tx_viewing_pk,
        salt: params.salt,
        proof,
        inputs,
        public_sol_amount: None,
        public_spl_amount: None,
        data_hash: None,
        zone_data_hash: None,
        output_utxo_hashes: params.output_utxo_hashes.to_vec(),
        output_ciphertexts,
    };

    let mut instruction_data = vec![params.rail.tag()];
    instruction_data.extend_from_slice(
        &ix_data
            .serialize()
            .expect("SPP TransactIxData serialization is infallible"),
    );
    Ok(instruction_data)
}

/// Inputs to build SPP's `zone_transact` instruction data for a withdrawal (a
/// `zone_transact` with a negative public amount). Same shape as
/// [`SppZoneTransferParams`] plus the settled `amount` and its rail; SPP folds
/// the recipient/vault settlement addresses into `external_data_hash` itself, so
/// `data_hash`/`zone_data_hash` stay `None` exactly as for a transfer.
pub struct SppZoneWithdrawalParams<'a> {
    pub expiry_unix_ts: u64,
    pub private_tx_hash: [u8; 32],
    pub spp_proof: &'a ProofBytes,
    pub salt: [u8; 16],
    pub output_view_tags: &'a [[u8; 32]],
    pub output_utxo_hashes: &'a [[u8; 32]],
    pub input_contexts: &'a [InputContext],
    pub encrypted_utxos: &'a EncryptedUtxos,
    /// Unsigned withdrawn amount; negated into SPP's signed public-amount field.
    pub amount: u64,
    /// SPL rail when true (sets `public_spl_amount`), native SOL otherwise
    /// (sets `public_sol_amount`).
    pub is_spl: bool,
    /// P256 (`zone_transact`) or smart-account (`zone_authority_transact`) rail.
    pub rail: SppSettlementRail,
}

/// Build the tag-prefixed, wincode-serialized SPP `zone_transact` instruction
/// data for a withdrawal. The withdrawn `amount` is negated into
/// `public_sol_amount` (SOL) or `public_spl_amount` (SPL); a withdrawal has a
/// single change output, so `output_ciphertexts` is just the sender bundle.
pub fn build_spp_zone_withdrawal_data(
    params: SppZoneWithdrawalParams<'_>,
) -> Result<Vec<u8>, SquadsZoneError> {
    let proof = decompose_proof(params.spp_proof, params.rail)?;
    let inputs = build_inputs(params.input_contexts, params.rail);
    let output_ciphertexts =
        build_output_ciphertexts(params.encrypted_utxos, params.output_view_tags)?;

    let signed = i64::try_from(params.amount).map_err(|_| SquadsZoneError::InvalidAmount)?;
    let negative = signed
        .checked_neg()
        .ok_or(SquadsZoneError::ArithmeticOverflow)?;
    let (public_sol_amount, public_spl_amount) = if params.is_spl {
        (None, Some(negative))
    } else {
        (Some(negative), None)
    };

    let ix_data = SppTransactIxData {
        expiry_unix_ts: params.expiry_unix_ts,
        relayer_fee: 0,
        private_tx_hash: params.private_tx_hash,
        p256_signing_pk_field: None,
        tx_viewing_pk: params.encrypted_utxos.tx_viewing_pk,
        salt: params.salt,
        proof,
        inputs,
        public_sol_amount,
        public_spl_amount,
        data_hash: None,
        zone_data_hash: None,
        output_utxo_hashes: params.output_utxo_hashes.to_vec(),
        output_ciphertexts,
    };

    let mut instruction_data = vec![params.rail.tag()];
    instruction_data.extend_from_slice(
        &ix_data
            .serialize()
            .expect("SPP TransactIxData serialization is infallible"),
    );
    Ok(instruction_data)
}

/// Decompose the zone's flat 192-byte forwarded proof into SPP's tagged proof
/// variant for `rail`. The P256 rail is BSB22-committed (all 192 bytes:
/// `a(0..32) || b(32..96) || c(96..128) || commitment(128..160) ||
/// commitment_pok(160..192)`); the smart-account rail is vanilla Groth16 (the
/// leading 128 bytes `a || b || c`, the trailing 64 zero-padded).
fn decompose_proof(
    bytes: &ProofBytes,
    rail: SppSettlementRail,
) -> Result<SppTransactProof, SquadsZoneError> {
    let err = SquadsZoneError::InvalidProofEncoding;
    let a: [u8; 32] = bytes.get(0..32).ok_or(err)?.try_into().map_err(|_| err)?;
    let b: [u8; 64] = bytes.get(32..96).ok_or(err)?.try_into().map_err(|_| err)?;
    let c: [u8; 32] = bytes.get(96..128).ok_or(err)?.try_into().map_err(|_| err)?;
    match rail {
        SppSettlementRail::SmartAccount => Ok(SppTransactProof::Eddsa { a, b, c }),
        SppSettlementRail::P256 => {
            let commitment: [u8; 32] = bytes
                .get(128..160)
                .ok_or(err)?
                .try_into()
                .map_err(|_| err)?;
            let commitment_pok: [u8; 32] = bytes
                .get(160..192)
                .ok_or(err)?
                .try_into()
                .map_err(|_| err)?;
            Ok(SppTransactProof::P256 {
                a,
                b,
                c,
                commitment,
                commitment_pok,
            })
        }
    }
}

fn build_inputs(input_contexts: &[InputContext], rail: SppSettlementRail) -> Vec<InputUtxo> {
    input_contexts
        .iter()
        .map(|ctx| InputUtxo {
            nullifier_hash: ctx.nullifier,
            nullifier_tree_root_index: ctx.nullifier_root_index,
            utxo_tree_root_index: ctx.utxo_root_index,
            tree_index: ctx.tree_index,
            eddsa_signer_index: rail.signer_index(),
        })
        .collect()
}

/// SPP's `output_ciphertexts` is `[sender bundle, then one per recipient]`
/// (spec `transact` `OutputCiphertext`); the zone's `EncryptedUtxos` already
/// carries exactly that data, just without a `view_tag` per slot, so
/// `output_view_tags` must have one entry per slot in the same order.
fn build_output_ciphertexts(
    encrypted_utxos: &EncryptedUtxos,
    output_view_tags: &[[u8; 32]],
) -> Result<Vec<OutputCiphertext>, SquadsZoneError> {
    let expected = 1 + encrypted_utxos.recipient_ciphertexts.len();
    if output_view_tags.len() != expected {
        return Err(SquadsZoneError::InvalidInstructionData);
    }
    let mut ciphertexts = Vec::with_capacity(expected);
    let sender_tag = output_view_tags
        .first()
        .ok_or(SquadsZoneError::InvalidInstructionData)?;
    ciphertexts.push(OutputCiphertext {
        view_tag: *sender_tag,
        data: encrypted_utxos.sender_ciphertext.to_vec(),
    });
    let recipient_tags = output_view_tags
        .get(1..)
        .ok_or(SquadsZoneError::InvalidInstructionData)?;
    for (recipient, tag) in encrypted_utxos
        .recipient_ciphertexts
        .iter()
        .zip(recipient_tags)
    {
        ciphertexts.push(OutputCiphertext {
            view_tag: *tag,
            data: recipient.to_vec(),
        });
    }
    Ok(ciphertexts)
}

#[cfg(test)]
mod tests {
    use zolana_interface::instruction::{tag, TransactIxData as SppTransactIxData};

    use super::*;

    fn sample_proof() -> ProofBytes {
        let mut bytes = [0u8; 192];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = i as u8;
        }
        bytes
    }

    fn sample_encrypted_utxos() -> EncryptedUtxos {
        EncryptedUtxos {
            tx_viewing_pk: [7u8; 33],
            sender_ciphertext: [8u8; 40],
            recipient_ciphertexts: vec![[9u8; 71]],
        }
    }

    /// Every field lands where SPP expects it: the proof decomposes into the
    /// exact byte ranges, `InputContext` fields rename 1:1 into `InputUtxo`
    /// with the P256 sentinel, and `output_ciphertexts` is `[sender bundle,
    /// recipient]` with the matching view tags -- verified by round-tripping
    /// through SPP's own `TransactIxData::deserialize`, not by re-deriving the
    /// serialized layout by hand.
    #[test]
    fn builds_expected_spp_ix_data() {
        let proof_bytes = sample_proof();
        let encrypted_utxos = sample_encrypted_utxos();
        let input_contexts = vec![InputContext {
            nullifier: [1u8; 32],
            tree_index: 3,
            utxo_root_index: 4,
            nullifier_root_index: 5,
        }];
        let output_view_tags = vec![[10u8; 32], [11u8; 32]];
        let output_utxo_hashes = vec![[12u8; 32], [13u8; 32]];

        let instruction_data = build_spp_zone_transfer_data(SppZoneTransferParams {
            expiry_unix_ts: 1_700_000_000,
            private_tx_hash: [6u8; 32],
            spp_proof: &proof_bytes,
            salt: [14u8; 16],
            output_view_tags: &output_view_tags,
            output_utxo_hashes: &output_utxo_hashes,
            input_contexts: &input_contexts,
            encrypted_utxos: &encrypted_utxos,
            rail: SppSettlementRail::P256,
        })
        .expect("build");

        assert_eq!(instruction_data.first().copied(), Some(tag::ZONE_TRANSACT));
        let parsed =
            SppTransactIxData::deserialize(instruction_data.get(1..).expect("tag-stripped bytes"))
                .expect("SPP must accept the constructed bytes");

        assert_eq!(parsed.expiry_unix_ts, 1_700_000_000);
        assert_eq!(parsed.relayer_fee, 0);
        assert_eq!(parsed.private_tx_hash, [6u8; 32]);
        assert_eq!(parsed.p256_signing_pk_field, None);
        assert_eq!(parsed.tx_viewing_pk, encrypted_utxos.tx_viewing_pk);
        assert_eq!(parsed.salt, [14u8; 16]);
        assert_eq!(
            parsed.proof,
            zolana_interface::instruction::TransactProof::P256 {
                a: proof_bytes.get(0..32).unwrap().try_into().unwrap(),
                b: proof_bytes.get(32..96).unwrap().try_into().unwrap(),
                c: proof_bytes.get(96..128).unwrap().try_into().unwrap(),
                commitment: proof_bytes.get(128..160).unwrap().try_into().unwrap(),
                commitment_pok: proof_bytes.get(160..192).unwrap().try_into().unwrap(),
            }
        );
        assert_eq!(parsed.inputs.len(), 1);
        let input = parsed.inputs.first().expect("one input");
        assert_eq!(input.nullifier_hash, [1u8; 32]);
        assert_eq!(input.nullifier_tree_root_index, 5);
        assert_eq!(input.utxo_tree_root_index, 4);
        assert_eq!(input.tree_index, 3);
        assert_eq!(input.eddsa_signer_index, P256_OWNED_SIGNER);
        assert_eq!(parsed.public_sol_amount, None);
        assert_eq!(parsed.public_spl_amount, None);
        assert_eq!(parsed.data_hash, None);
        assert_eq!(parsed.zone_data_hash, None);
        assert_eq!(parsed.output_utxo_hashes, output_utxo_hashes);
        assert_eq!(parsed.output_ciphertexts.len(), 2);
        let sender = parsed.output_ciphertexts.first().expect("sender slot");
        assert_eq!(sender.view_tag, [10u8; 32]);
        assert_eq!(sender.data, encrypted_utxos.sender_ciphertext.to_vec());
        let recipient = parsed.output_ciphertexts.get(1).expect("recipient slot");
        assert_eq!(recipient.view_tag, [11u8; 32]);
        assert_eq!(
            recipient.data,
            encrypted_utxos
                .recipient_ciphertexts
                .first()
                .expect("recipient")
                .to_vec()
        );
    }

    #[test]
    fn rejects_view_tag_count_mismatch() {
        let proof_bytes = sample_proof();
        let encrypted_utxos = sample_encrypted_utxos();
        let err = build_spp_zone_transfer_data(SppZoneTransferParams {
            expiry_unix_ts: 0,
            private_tx_hash: [0u8; 32],
            spp_proof: &proof_bytes,
            salt: [0u8; 16],
            // Only one tag for a sender+recipient (needs 2).
            output_view_tags: &[[0u8; 32]],
            output_utxo_hashes: &[],
            input_contexts: &[],
            encrypted_utxos: &encrypted_utxos,
            rail: SppSettlementRail::P256,
        })
        .expect_err("view-tag count mismatch must be rejected");
        assert_eq!(err, SquadsZoneError::InvalidInstructionData);
    }

    /// A SOL withdrawal negates the amount into `public_sol_amount` and leaves
    /// `public_spl_amount` unset; a withdrawal has a single (sender) output slot.
    #[test]
    fn builds_sol_withdrawal_ix_data() {
        let proof_bytes = sample_proof();
        let encrypted_utxos = EncryptedUtxos {
            tx_viewing_pk: [7u8; 33],
            sender_ciphertext: [8u8; 40],
            recipient_ciphertexts: vec![],
        };
        let input_contexts = vec![InputContext {
            nullifier: [1u8; 32],
            tree_index: 3,
            utxo_root_index: 4,
            nullifier_root_index: 5,
        }];

        let instruction_data = build_spp_zone_withdrawal_data(SppZoneWithdrawalParams {
            expiry_unix_ts: 1_700_000_000,
            private_tx_hash: [6u8; 32],
            spp_proof: &proof_bytes,
            salt: [14u8; 16],
            output_view_tags: &[[10u8; 32]],
            output_utxo_hashes: &[[12u8; 32]],
            input_contexts: &input_contexts,
            encrypted_utxos: &encrypted_utxos,
            amount: 700,
            is_spl: false,
            rail: SppSettlementRail::P256,
        })
        .expect("build");

        assert_eq!(instruction_data.first().copied(), Some(tag::ZONE_TRANSACT));
        let parsed =
            SppTransactIxData::deserialize(instruction_data.get(1..).expect("tag-stripped bytes"))
                .expect("SPP must accept the constructed bytes");
        assert_eq!(parsed.public_sol_amount, Some(-700));
        assert_eq!(parsed.public_spl_amount, None);
        assert_eq!(parsed.output_ciphertexts.len(), 1);
    }

    /// An SPL withdrawal negates the amount into `public_spl_amount`.
    #[test]
    fn builds_spl_withdrawal_ix_data() {
        let proof_bytes = sample_proof();
        let encrypted_utxos = EncryptedUtxos {
            tx_viewing_pk: [7u8; 33],
            sender_ciphertext: [8u8; 40],
            recipient_ciphertexts: vec![],
        };

        let instruction_data = build_spp_zone_withdrawal_data(SppZoneWithdrawalParams {
            expiry_unix_ts: 0,
            private_tx_hash: [0u8; 32],
            spp_proof: &proof_bytes,
            salt: [0u8; 16],
            output_view_tags: &[[10u8; 32]],
            output_utxo_hashes: &[[12u8; 32]],
            input_contexts: &[],
            encrypted_utxos: &encrypted_utxos,
            amount: 500,
            is_spl: true,
            rail: SppSettlementRail::P256,
        })
        .expect("build");

        let parsed =
            SppTransactIxData::deserialize(instruction_data.get(1..).expect("tag-stripped bytes"))
                .expect("SPP must accept the constructed bytes");
        assert_eq!(parsed.public_sol_amount, None);
        assert_eq!(parsed.public_spl_amount, Some(-500));
    }

    /// The smart-account rail tags `ZONE_AUTHORITY_TRANSACT`, emits a vanilla
    /// `Eddsa` proof (leading 128 bytes), and stamps a non-P256 signer index so
    /// SPP selects the zone-authority verifying key.
    #[test]
    fn builds_smart_account_transfer_ix_data() {
        let proof_bytes = sample_proof();
        let encrypted_utxos = sample_encrypted_utxos();
        let input_contexts = vec![InputContext {
            nullifier: [1u8; 32],
            tree_index: 3,
            utxo_root_index: 4,
            nullifier_root_index: 5,
        }];

        let instruction_data = build_spp_zone_transfer_data(SppZoneTransferParams {
            expiry_unix_ts: 1_700_000_000,
            private_tx_hash: [6u8; 32],
            spp_proof: &proof_bytes,
            salt: [14u8; 16],
            output_view_tags: &[[10u8; 32], [11u8; 32]],
            output_utxo_hashes: &[[12u8; 32], [13u8; 32]],
            input_contexts: &input_contexts,
            encrypted_utxos: &encrypted_utxos,
            rail: SppSettlementRail::SmartAccount,
        })
        .expect("build");

        assert_eq!(
            instruction_data.first().copied(),
            Some(tag::ZONE_AUTHORITY_TRANSACT)
        );
        let parsed =
            SppTransactIxData::deserialize(instruction_data.get(1..).expect("tag-stripped bytes"))
                .expect("SPP must accept the constructed bytes");
        assert_eq!(
            parsed.proof,
            zolana_interface::instruction::TransactProof::Eddsa {
                a: proof_bytes.get(0..32).unwrap().try_into().unwrap(),
                b: proof_bytes.get(32..96).unwrap().try_into().unwrap(),
                c: proof_bytes.get(96..128).unwrap().try_into().unwrap(),
            }
        );
        assert_eq!(
            parsed.inputs.first().expect("one input").eddsa_signer_index,
            SMART_ACCOUNT_SIGNER_INDEX
        );
    }
}
