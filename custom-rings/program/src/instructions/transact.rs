use custom_ring_interface::{
    AuditPublicInput, CustomRingTransactIxData, AUDIT_CIPHERTEXT_LEN, COMPRESSED_P256_KEY_LEN,
};
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_interface::instruction::{
    instruction_data::transact::{
        confidential_encrypted_output_body, ring_confidential_encrypted_output_body,
    },
    tag, CircuitId, MessageData,
};

use crate::{
    error::CustomRingError,
    instructions::{
        loader::{load_config, validate_spp_program},
        shared::cpi_spp_signed,
        verifier::{verify_groth16, CompressedGroth16Proof},
    },
};

/// Verifies the auditor key-encryption proof against the recomputed public-input
/// hash, then CPIs SPP `RING_TRANSACT` with the `ring_auth` PDA as signer.
///
/// Accounts: `[payer(w,s), config]` followed by SPP's own `RING_TRANSACT` list
/// (`payer, input_tree, output_tree, spp_program, system_program, ring_config,
/// owner signers, settlement accounts`), which is forwarded position for
/// position with only `ring_config` (this ring's `ring_auth` PDA) gaining a
/// signature.
#[inline(never)]
pub fn process_transact_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let mut iter = AccountIterator::new(accounts);
    iter.next_signer_mut("payer")?;
    let config_account = iter.next_account("config")?;

    let CustomRingTransactIxData { proof, transact } =
        wincode::deserialize_exact(data).map_err(|_| CustomRingError::InvalidInstructionData)?;

    // The forwarded list is taken before the expensive work so a malformed
    // account list costs no pairing.
    let spp_accounts = iter.remaining()?;
    validate_spp_program(spp_accounts)?;

    // The typed loader releases the account borrow before the CPI.
    let auditor_pubkey = load_config(program_id, config_account)?.auditor_pubkey;

    if !matches!(transact.circuit, CircuitId::RingEddsa(..)) {
        return Err(CustomRingError::UnsupportedCircuit.into());
    }
    if transact.outputs.iter().any(|output| {
        !output
            .data
            .as_deref()
            .is_some_and(is_valid_confidential_output)
    }) {
        return Err(CustomRingError::UnsupportedOutputScheme.into());
    }

    let view_tag: &[u8; 32] = auditor_pubkey
        .get(1..COMPRESSED_P256_KEY_LEN)
        .and_then(|tag| tag.try_into().ok())
        .ok_or(CustomRingError::InvalidAuditorPubkey)?;
    let message = select_auditor_message(&transact.messages, view_tag)?;
    verify_groth16(
        CompressedGroth16Proof {
            a: &proof.proof_a,
            b: &proof.proof_b,
            c: &proof.proof_c,
            commitment: &proof.commitment,
            commitment_pok: &proof.commitment_pok,
        },
        AuditPublicInput {
            private_tx_hash: &transact.private_tx_hash,
            tx_viewing_pk: &transact.tx_viewing_pk,
            auditor_pk: &auditor_pubkey,
            eph_pk: message.eph_pk,
            ciphertext: message.ciphertext,
        }
        .hash()
        .map_err(|_| CustomRingError::HashingFailed)?,
    )?;

    // Reserialized from the parsed struct rather than sliced out of `data`: the
    // proof is verified against the parsed payload, so the bytes SPP sees must be
    // the ones that were parsed.
    let transact_bytes = transact
        .serialize()
        .map_err(|_| CustomRingError::InvalidInstructionData)?;
    let mut instruction_data = Vec::with_capacity(1 + transact_bytes.len());
    instruction_data.push(tag::RING_TRANSACT);
    instruction_data.extend_from_slice(&transact_bytes);
    cpi_spp_signed(program_id, spp_accounts, &instruction_data)
}

/// The auditor message of a transaction: `eph_pk(33) || ciphertext(32)` split out
/// of the published message data.
struct AuditorMessageParts<'a> {
    eph_pk: &'a [u8; COMPRESSED_P256_KEY_LEN],
    ciphertext: &'a [u8; AUDIT_CIPHERTEXT_LEN],
}

/// Select the auditor message out of the transaction's published messages.
///
/// The ring's convention is: exactly one message carries the auditor view tag,
/// and it is the last one. Free-form messages before it stay allowed. Requiring
/// uniqueness and a fixed position leaves no room for a second, differently
/// tagged payload that an indexer or auditor might pick up instead of the proven
/// one -- the proof covers exactly one ciphertext, so exactly one message may
/// claim the auditor's tag.
fn select_auditor_message<'a>(
    messages: &'a [MessageData],
    view_tag: &[u8; 32],
) -> Result<AuditorMessageParts<'a>, ProgramError> {
    let (last, earlier) = messages
        .split_last()
        .ok_or(CustomRingError::MissingAuditorMessage)?;
    let tagged_earlier = earlier.iter().any(|message| &message.view_tag == view_tag);
    match (&last.view_tag == view_tag, tagged_earlier) {
        (true, false) => {}
        // No message claims the auditor tag at all.
        (false, false) => return Err(CustomRingError::MissingAuditorMessage.into()),
        // Either a second tagged message, or a tagged message that is not last.
        _ => return Err(CustomRingError::InvalidAuditorMessage.into()),
    }

    let (eph_pk, ciphertext) = last
        .data
        .split_at_checked(COMPRESSED_P256_KEY_LEN)
        .ok_or(CustomRingError::InvalidAuditorMessage)?;
    let eph_pk: &[u8; COMPRESSED_P256_KEY_LEN] = eph_pk
        .try_into()
        .map_err(|_| CustomRingError::InvalidAuditorMessage)?;
    let ciphertext: &[u8; AUDIT_CIPHERTEXT_LEN] = ciphertext
        .try_into()
        .map_err(|_| CustomRingError::InvalidAuditorMessage)?;
    Ok(AuditorMessageParts { eph_pk, ciphertext })
}

fn is_valid_confidential_output(data: &[u8]) -> bool {
    let Some(body) = confidential_encrypted_output_body(data)
        .or_else(|| ring_confidential_encrypted_output_body(data))
    else {
        return false;
    };
    let Some((key, ciphertext)) = body.split_at_checked(COMPRESSED_P256_KEY_LEN) else {
        return false;
    };
    matches!(key.first(), Some(2 | 3)) && !ciphertext.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use custom_ring_interface::{pack33_to_2fe, AUDITOR_MESSAGE_LEN};
    use zolana_interface::merge_utils::ciphertext_hash;

    /// Fixture of the circuit's Go test
    /// (`prover/server/circuits/custom_ring/audit/circuit_test.go`, scalars
    /// 0x11/0x22/0x33) and of the SDK's cross-language vectors
    /// (`custom-rings/sdk/tests/go_vectors.rs`). The compressed keys and the
    /// ciphertext are the values Go printed and the Go test feeds to the compiled
    /// circuit; `PUBLIC_INPUT_HASH` and `CT_HASH` were computed with the same
    /// iden3 Poseidon implementation the in-circuit gadget links its constants
    /// from, over that fixture. Because `PRIVATE_TX_HASH` is that test's
    /// `PrivateTxHash` too, `PUBLIC_INPUT_HASH` is exactly the public input the
    /// Go test solves the compiled circuit against.
    const TX_PK: &str = "0268737cf1d852483220d399b5321261d5e9e90d8214dc62b4f7e4d0fee955c5d5";
    const EPH_PK: &str = "038bd43dcdaea72a1db879b1ca6faac09593fd17893d22eeef926b5c1c245a133c";
    const AUDITOR_PK: &str = "039dc51b59006b13f143944d4e432db7c032241ceb3698a6cc0cdabadf29b71dec";
    const CIPHERTEXT: &str = "6de7c18c3c3676ca517647a25df33a7150ace3e07b410bc296fac11b1355382b";
    /// `big.NewInt(0xabcdef)` as a 32-byte big-endian field element, the Go
    /// fixture's `PrivateTxHash`.
    const PRIVATE_TX_HASH: &str =
        "0000000000000000000000000000000000000000000000000000000000abcdef";

    const TX_PK_LO: &str = "000268737cf1d852483220d399b5321261d5e9e90d8214dc62b4f7e4d0fee955";
    const TX_PK_HI: &str = "000000000000000000000000000000000000000000000000000000000000c5d5";
    const CT_HASH: &str = "1384dccfd224d268a2028165de1523e911e276a676568086166a3b782afdbada";
    const PUBLIC_INPUT_HASH: &str =
        "18bf7563a64675c110ae7d408b973c98005afac6d06b8ae177f4435d7e6e020b";

    fn bytes<const N: usize>(hex_str: &str) -> [u8; N] {
        let decoded = hex::decode(hex_str).expect("valid hex");
        <[u8; N]>::try_from(decoded.as_slice()).expect("expected byte length")
    }

    #[test]
    fn pack33_to_2fe_matches_go() {
        assert_eq!(
            pack33_to_2fe(&bytes::<33>(TX_PK)),
            custom_ring_interface::FieldPair {
                lo: bytes::<32>(TX_PK_LO),
                hi: bytes::<32>(TX_PK_HI),
            }
        );
    }

    /// Chain element 8: `ciphertext_hash` must equal the circuit's
    /// `gadget.HashBytes` over the same 32 bytes.
    #[test]
    fn ciphertext_hash_matches_go_hash_bytes() {
        assert_eq!(
            ciphertext_hash(&bytes::<32>(CIPHERTEXT)).expect("hash bytes"),
            bytes::<32>(CT_HASH)
        );
    }

    /// The gate that keeps the program and the circuit on the same statement: the
    /// full eight-element chain over the Go fixture must produce the exact public
    /// input the Go side computed and the circuit was solved against. A reordered
    /// or differently packed chain element changes this value.
    #[test]
    fn public_input_hash_matches_go_fixture() {
        let hash = AuditPublicInput {
            private_tx_hash: &bytes::<32>(PRIVATE_TX_HASH),
            tx_viewing_pk: &bytes::<33>(TX_PK),
            auditor_pk: &bytes::<33>(AUDITOR_PK),
            eph_pk: &bytes::<33>(EPH_PK),
            ciphertext: &bytes::<32>(CIPHERTEXT),
        }
        .hash()
        .expect("public input hash");
        assert_eq!(hash, bytes::<32>(PUBLIC_INPUT_HASH));
    }

    fn message(view_tag: [u8; 32], len: usize) -> MessageData {
        MessageData {
            view_tag,
            data: vec![9u8; len],
        }
    }

    fn auditor_view_tag() -> [u8; 32] {
        let key = bytes::<33>(AUDITOR_PK);
        let mut tag = [0u8; 32];
        tag.copy_from_slice(&key[1..33]);
        tag
    }

    fn select_err(messages: &[MessageData]) -> ProgramError {
        select_auditor_message(messages, &auditor_view_tag())
            .err()
            .expect("selection must fail")
    }

    #[test]
    fn auditor_message_selection_enforces_unique_last_message() {
        let tag = auditor_view_tag();
        let other = [1u8; 32];

        let valid = vec![message(other, 4), message(tag, AUDITOR_MESSAGE_LEN)];
        let parts = select_auditor_message(&valid, &tag).expect("valid selection");
        assert_eq!(
            parts.eph_pk.len() + parts.ciphertext.len(),
            AUDITOR_MESSAGE_LEN
        );

        let missing = ProgramError::Custom(CustomRingError::MissingAuditorMessage as u32);
        let invalid = ProgramError::Custom(CustomRingError::InvalidAuditorMessage as u32);
        assert_eq!(select_err(&[]), missing);
        assert_eq!(select_err(&[message(other, AUDITOR_MESSAGE_LEN)]), missing);
        assert_eq!(
            select_err(&[message(tag, AUDITOR_MESSAGE_LEN), message(other, 4)]),
            invalid
        );
        assert_eq!(
            select_err(&[
                message(tag, AUDITOR_MESSAGE_LEN),
                message(tag, AUDITOR_MESSAGE_LEN)
            ]),
            invalid
        );
        assert_eq!(
            select_err(&[message(tag, AUDITOR_MESSAGE_LEN - 1)]),
            invalid
        );
        assert_eq!(
            select_err(&[message(tag, AUDITOR_MESSAGE_LEN + 1)]),
            invalid
        );
    }
}
