//! Builds the SPP `ring_transact` instruction data (tag-prefixed, wincode
//! serialized) the zone forwards via CPI.

use zolana_interface::{
    instruction::{
        tag::{RING_AUTHORITY_TRANSACT, RING_TRANSACT},
        InputUtxo, InterfaceTransfer, OwnerTag, TransactIxData as SppTransactIxData,
        TransactOutput, TransactProof as SppTransactProof,
    },
    verifying_keys::{Bsb22Commitment, CircuitId, RingP256ProofData},
    N_PUBLIC_SLOTS,
};
use zolana_squads_interface::{
    error::SquadsZoneError,
    instruction::instruction_data::{transact::InputContext, EncryptedUtxos},
    state::viewing_key_account::OwnerKind,
    types::ProofBytes,
};

use crate::shared::withdrawal::WithdrawalSettlement;

/// Which SPP settlement rail the zone forwards a spend through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SppSettlementRail {
    /// Keypair/P256 owner: SPP `ring_transact` with a BSB22-committed P256 proof
    /// (the owner's P256 signature over `private_tx_hash` authorizes the spend).
    P256,
    /// Smart-account owner (a Squads vault, no signing key): SPP
    /// `ring_authority_transact` with a vanilla proof and no owner signature.
    /// The zone authorizes via its `zone_config` PDA and (async) an approved
    /// proposal binds the operation.
    SmartAccount,
}

impl SppSettlementRail {
    pub fn for_owner_kind(owner_kind: OwnerKind) -> Self {
        match owner_kind {
            OwnerKind::Keypair => SppSettlementRail::P256,
            OwnerKind::SmartAccount => SppSettlementRail::SmartAccount,
        }
    }

    fn tag(self) -> u8 {
        match self {
            SppSettlementRail::P256 => RING_TRANSACT,
            SppSettlementRail::SmartAccount => RING_AUTHORITY_TRANSACT,
        }
    }
}

/// Everything the zone's own `TransactIxData` / `ExecuteProposalIxData` carries,
/// minus the fields SPP computes itself (`ring_program_id` from the CPI-signing
/// `RingConfig`, `payer_pubkey_hash` from the CPI's `payer` account).
pub struct SppZoneTransferParams<'a> {
    pub expiry_unix_ts: u64,
    pub private_tx_hash: [u8; 32],
    pub spp_proof: &'a ProofBytes,
    pub salt: [u8; 16],
    pub output_view_tags: &'a [[u8; 32]],
    pub output_utxo_hashes: &'a [[u8; 32]],
    pub input_contexts: &'a [InputContext],
    pub encrypted_utxos: &'a EncryptedUtxos,
    pub rail: SppSettlementRail,
}

/// A transfer settles nothing, so it carries no interface transfers.
pub fn build_spp_zone_transfer_data(
    params: SppZoneTransferParams<'_>,
) -> Result<Vec<u8>, SquadsZoneError> {
    let outputs = build_outputs(
        params.encrypted_utxos,
        params.output_view_tags,
        params.output_utxo_hashes,
    )?;
    let ix_data = SppTransactIxData {
        expiry_unix_ts: params.expiry_unix_ts,
        private_tx_hash: params.private_tx_hash,
        circuit: circuit_id(
            params.spp_proof,
            params.rail,
            params.input_contexts.len(),
            outputs.len(),
        )?,
        tx_viewing_pk: params.encrypted_utxos.tx_viewing_pk,
        salt: params.salt,
        proof: decompose_proof(params.spp_proof)?,
        inputs: build_inputs(params.input_contexts),
        interface_transfers: Vec::new(),
        data_hash: None,
        ring_data_hash: None,
        outputs,
        messages: Vec::new(),
    };
    encode(params.rail, &ix_data)
}

/// Inputs to build SPP's `ring_transact` instruction data for a withdrawal.
/// Same shape as [`SppZoneTransferParams`] plus the settled `amount` and its
/// rail. SPP folds the recipient/vault settlement addresses into
/// `external_data_hash` itself, so `data_hash` and `ring_data_hash` stay `None`
/// exactly as for a transfer.
pub struct SppZoneWithdrawalParams<'a> {
    pub expiry_unix_ts: u64,
    pub private_tx_hash: [u8; 32],
    pub spp_proof: &'a ProofBytes,
    pub salt: [u8; 16],
    pub output_view_tags: &'a [[u8; 32]],
    pub output_utxo_hashes: &'a [[u8; 32]],
    pub input_contexts: &'a [InputContext],
    pub encrypted_utxos: &'a EncryptedUtxos,
    pub amount: u64,
    pub settlement: WithdrawalSettlement,
    pub rail: SppSettlementRail,
}

/// A withdrawal has a single change output, so `outputs` is just the sender
/// slot.
pub fn build_spp_zone_withdrawal_data(
    params: SppZoneWithdrawalParams<'_>,
) -> Result<Vec<u8>, SquadsZoneError> {
    let outputs = build_outputs(
        params.encrypted_utxos,
        params.output_view_tags,
        params.output_utxo_hashes,
    )?;
    let transfer = match params.settlement {
        WithdrawalSettlement::Spl { interface_bump } => InterfaceTransfer::SplWithdrawal {
            amount: params.amount,
            spl_interface_bump: interface_bump,
        },
        WithdrawalSettlement::Sol => InterfaceTransfer::SolWithdrawal {
            amount: params.amount,
        },
    };
    let ix_data = SppTransactIxData {
        expiry_unix_ts: params.expiry_unix_ts,
        private_tx_hash: params.private_tx_hash,
        circuit: circuit_id(
            params.spp_proof,
            params.rail,
            params.input_contexts.len(),
            outputs.len(),
        )?,
        tx_viewing_pk: params.encrypted_utxos.tx_viewing_pk,
        salt: params.salt,
        proof: decompose_proof(params.spp_proof)?,
        inputs: build_inputs(params.input_contexts),
        interface_transfers: vec![transfer],
        data_hash: None,
        ring_data_hash: None,
        outputs,
        messages: Vec::new(),
    };
    encode(params.rail, &ix_data)
}

fn encode(
    rail: SppSettlementRail,
    ix_data: &SppTransactIxData,
) -> Result<Vec<u8>, SquadsZoneError> {
    let mut instruction_data = vec![rail.tag()];
    instruction_data.extend_from_slice(
        &ix_data
            .serialize()
            .map_err(|_| SquadsZoneError::Serialization)?,
    );
    Ok(instruction_data)
}

/// The circuit selector SPP resolves its verifying key from. On the P256 rail it
/// also carries the BSB22 commitment, without which the committed proof cannot
/// be verified. `default_owner_tag` stays `None` because a zone spend proves
/// P256 ownership inside the ring, so publishing the x-coordinate would
/// deanonymize the owner.
fn circuit_id(
    bytes: &ProofBytes,
    rail: SppSettlementRail,
    n_inputs: usize,
    n_outputs: usize,
) -> Result<CircuitId, SquadsZoneError> {
    let err = SquadsZoneError::InvalidProofEncoding;
    let n_inputs = u8::try_from(n_inputs).map_err(|_| err)?;
    let n_outputs = u8::try_from(n_outputs).map_err(|_| err)?;
    let slots = N_PUBLIC_SLOTS as u8;
    match rail {
        SppSettlementRail::SmartAccount => Ok(CircuitId::RingAuthority(n_inputs, n_outputs, slots)),
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
            Ok(CircuitId::RingP256(
                n_inputs,
                n_outputs,
                slots,
                RingP256ProofData {
                    bsb22_commitment: Bsb22Commitment {
                        commitment,
                        commitment_pok,
                    },
                    default_owner_tag: None,
                },
            ))
        }
    }
}

/// Split the zone's flat 192-byte forwarded proof into SPP's Groth16 triple.
/// The trailing 64 bytes are the BSB22 commitment, which travels in the circuit
/// selector instead.
fn decompose_proof(bytes: &ProofBytes) -> Result<SppTransactProof, SquadsZoneError> {
    let err = SquadsZoneError::InvalidProofEncoding;
    Ok(SppTransactProof {
        a: bytes.get(0..32).ok_or(err)?.try_into().map_err(|_| err)?,
        b: bytes.get(32..96).ok_or(err)?.try_into().map_err(|_| err)?,
        c: bytes.get(96..128).ok_or(err)?.try_into().map_err(|_| err)?,
    })
}

fn build_inputs(input_contexts: &[InputContext]) -> Vec<InputUtxo> {
    input_contexts
        .iter()
        .map(|ctx| InputUtxo {
            nullifier_hash: ctx.nullifier,
            nullifier_tree_root_index: ctx.nullifier_root_index,
            utxo_tree_root_index: ctx.utxo_root_index,
        })
        .collect()
}

/// SPP's `outputs` is `[sender slot, then one per recipient]` in tree-append
/// order. The zone's `EncryptedUtxos` carries exactly that data without a view
/// tag or commitment per slot, so both must have one entry per slot in the same
/// order.
fn build_outputs(
    encrypted_utxos: &EncryptedUtxos,
    output_view_tags: &[[u8; 32]],
    output_utxo_hashes: &[[u8; 32]],
) -> Result<Vec<TransactOutput>, SquadsZoneError> {
    let expected = 1 + encrypted_utxos.recipient_ciphertexts.len();
    if output_view_tags.len() != expected || output_utxo_hashes.len() != expected {
        return Err(SquadsZoneError::InvalidInstructionData);
    }
    let ciphertexts = core::iter::once(encrypted_utxos.sender_ciphertext.to_vec()).chain(
        encrypted_utxos
            .recipient_ciphertexts
            .iter()
            .map(|recipient| recipient.to_vec()),
    );
    Ok(output_utxo_hashes
        .iter()
        .zip(output_view_tags)
        .zip(ciphertexts)
        .map(|((utxo_hash, view_tag), data)| TransactOutput {
            utxo_hash: *utxo_hash,
            owner_tag: OwnerTag::Inline(*view_tag),
            data: Some(data),
        })
        .collect())
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

        assert_eq!(instruction_data.first().copied(), Some(tag::RING_TRANSACT));
        let parsed =
            SppTransactIxData::deserialize(instruction_data.get(1..).expect("tag-stripped bytes"))
                .expect("SPP must accept the constructed bytes");

        assert_eq!(parsed.expiry_unix_ts, 1_700_000_000);
        assert_eq!(parsed.private_tx_hash, [6u8; 32]);
        assert_eq!(parsed.tx_viewing_pk, encrypted_utxos.tx_viewing_pk);
        assert_eq!(parsed.salt, [14u8; 16]);
        assert_eq!(
            parsed.proof,
            SppTransactProof {
                a: proof_bytes.get(0..32).unwrap().try_into().unwrap(),
                b: proof_bytes.get(32..96).unwrap().try_into().unwrap(),
                c: proof_bytes.get(96..128).unwrap().try_into().unwrap(),
            }
        );
        let CircuitId::RingP256(n_in, n_out, _, proof_data) = parsed.circuit else {
            panic!("P256 rail must select the RingP256 circuit");
        };
        assert_eq!((n_in, n_out), (1, 2));
        assert_eq!(
            proof_data.bsb22_commitment.commitment,
            <[u8; 32]>::try_from(proof_bytes.get(128..160).unwrap()).unwrap()
        );
        assert_eq!(
            proof_data.bsb22_commitment.commitment_pok,
            <[u8; 32]>::try_from(proof_bytes.get(160..192).unwrap()).unwrap()
        );
        assert_eq!(proof_data.default_owner_tag, None);
        assert_eq!(parsed.inputs.len(), 1);
        let input = parsed.inputs.first().expect("one input");
        assert_eq!(input.nullifier_hash, [1u8; 32]);
        assert_eq!(input.nullifier_tree_root_index, 5);
        assert_eq!(input.utxo_tree_root_index, 4);
        assert!(parsed.interface_transfers.is_empty());
        assert_eq!(parsed.data_hash, None);
        assert_eq!(parsed.ring_data_hash, None);
        assert_eq!(parsed.outputs.len(), 2);
        let sender = parsed.outputs.first().expect("sender slot");
        assert_eq!(sender.utxo_hash, [12u8; 32]);
        assert_eq!(sender.owner_tag, OwnerTag::Inline([10u8; 32]));
        assert_eq!(
            sender.data.as_deref(),
            Some(encrypted_utxos.sender_ciphertext.as_slice())
        );
        let recipient = parsed.outputs.get(1).expect("recipient slot");
        assert_eq!(recipient.utxo_hash, [13u8; 32]);
        assert_eq!(recipient.owner_tag, OwnerTag::Inline([11u8; 32]));
        assert_eq!(
            recipient.data.as_deref(),
            Some(
                encrypted_utxos
                    .recipient_ciphertexts
                    .first()
                    .expect("recipient")
                    .as_slice()
            )
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
            output_utxo_hashes: &[[0u8; 32]],
            input_contexts: &[],
            encrypted_utxos: &encrypted_utxos,
            rail: SppSettlementRail::P256,
        })
        .expect_err("view-tag count mismatch must be rejected");
        assert_eq!(err, SquadsZoneError::InvalidInstructionData);
    }

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
            settlement: WithdrawalSettlement::Sol,
            rail: SppSettlementRail::P256,
        })
        .expect("build");

        assert_eq!(instruction_data.first().copied(), Some(tag::RING_TRANSACT));
        let parsed =
            SppTransactIxData::deserialize(instruction_data.get(1..).expect("tag-stripped bytes"))
                .expect("SPP must accept the constructed bytes");
        assert_eq!(
            parsed.interface_transfers,
            vec![InterfaceTransfer::SolWithdrawal { amount: 700 }]
        );
        assert_eq!(parsed.outputs.len(), 1);
    }

    /// An SPL withdrawal carries the mint's interface bump so SPP can settle it.
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
            settlement: WithdrawalSettlement::Spl {
                interface_bump: 253,
            },
            rail: SppSettlementRail::P256,
        })
        .expect("build");

        let parsed =
            SppTransactIxData::deserialize(instruction_data.get(1..).expect("tag-stripped bytes"))
                .expect("SPP must accept the constructed bytes");
        assert_eq!(
            parsed.interface_transfers,
            vec![InterfaceTransfer::SplWithdrawal {
                amount: 500,
                spl_interface_bump: 253,
            }]
        );
    }

    /// The smart-account rail tags `RING_AUTHORITY_TRANSACT` and selects the
    /// signatureless ring-authority circuit, which carries no BSB22 commitment.
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
            Some(tag::RING_AUTHORITY_TRANSACT)
        );
        let parsed =
            SppTransactIxData::deserialize(instruction_data.get(1..).expect("tag-stripped bytes"))
                .expect("SPP must accept the constructed bytes");
        assert_eq!(
            parsed.proof,
            SppTransactProof {
                a: proof_bytes.get(0..32).unwrap().try_into().unwrap(),
                b: proof_bytes.get(32..96).unwrap().try_into().unwrap(),
                c: proof_bytes.get(96..128).unwrap().try_into().unwrap(),
            }
        );
        assert_eq!(
            parsed.circuit,
            CircuitId::RingAuthority(1, 2, N_PUBLIC_SLOTS as u8)
        );
    }
}
