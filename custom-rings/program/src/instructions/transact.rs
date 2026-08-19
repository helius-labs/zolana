use pinocchio::{error::ProgramError, AccountView, ProgramResult};
use wincode::{SchemaRead, SchemaWrite};
use zolana_account_checks::AccountIterator;
use zolana_hasher::hash_chain::create_hash_chain_from_slice;
use zolana_interface::{
    instruction::{tag, CircuitId, MessageData, TransactIxData},
    merge_utils::ciphertext_hash,
};

use crate::{
    error::CustomRingError,
    instructions::{
        approve_transact::{check_approval, APPROVAL_SIZE},
        loader::{load_config, validate_spp_program},
        policy::check_transact,
        shared::{cpi_spp_signed, pack33_to_2fe},
        verifier::{verify_groth16, CompressedGroth16Proof},
    },
    state::TRANSACT_APPROVAL,
};

/// SEC1-compressed public key length.
const COMPRESSED_PUBKEY_LEN: usize = 33;

fn is_approval_account(account: &AccountView) -> bool {
    account.owned_by(&crate::ID)
        && account.data_len() == APPROVAL_SIZE
        && account
            .try_borrow()
            .is_ok_and(|data| data.first() == Some(&TRANSACT_APPROVAL))
}
/// AES-256-CTR ciphertext of the 32-byte transaction viewing secret key.
const CIPHERTEXT_LEN: usize = 32;
/// `eph_pk_compressed(33) || ciphertext(32)`.
pub const AUDITOR_MESSAGE_LEN: usize = COMPRESSED_PUBKEY_LEN + CIPHERTEXT_LEN;

/// Groth16 proof of the `auditor_key_encryption` circuit. The circuit's emulated
/// P256 arithmetic adds one BSB22 commitment, so the commitment and its
/// proof-of-knowledge are not optional here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct AuditProof {
    pub proof_a: [u8; 32],
    pub proof_b: [u8; 64],
    pub proof_c: [u8; 32],
    pub commitment: [u8; 32],
    pub commitment_pok: [u8; 32],
}

/// Wire format of tag 3: the ring's own proof followed by the SPP payload this
/// ring forwards verbatim.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct CustomRingTransactIxData {
    pub proof: AuditProof,
    pub transact: TransactIxData,
}

/// Inputs of the auditor circuit's single public input.
///
/// The chain order is pinned by the circuit's package comment
/// (`custom-rings/prover/circuits/auditor_key_encryption/circuit.go`) and is
/// numbered 1..8 there; [`AuditPublicInput::hash`] mirrors it element for
/// element. Recomputing the hash on-chain from values the program itself trusts
/// -- `private_tx_hash` and `tx_viewing_pk` from the forwarded SPP payload, the
/// auditor key from the ring config account, the ephemeral key and ciphertext
/// from the published message -- is what binds the proof to this transaction: a
/// proof for any other transaction, viewing key, auditor, or ciphertext hashes
/// to a different public input and fails verification.
pub struct AuditPublicInput<'a> {
    pub private_tx_hash: &'a [u8; 32],
    pub tx_viewing_pk: &'a [u8; COMPRESSED_PUBKEY_LEN],
    pub auditor_pk: &'a [u8; COMPRESSED_PUBKEY_LEN],
    pub eph_pk: &'a [u8; COMPRESSED_PUBKEY_LEN],
    pub ciphertext: &'a [u8; CIPHERTEXT_LEN],
}

impl AuditPublicInput<'_> {
    /// `HashChain([private_tx_hash, tx_pk_lo, tx_pk_hi, auditor_lo, auditor_hi,
    /// eph_lo, eph_hi, ct_hash])`.
    ///
    /// `create_hash_chain_from_slice` is the Rust twin of the circuit's
    /// `gadget.HashChain`, and `ciphertext_hash` (i.e. `hash_bytes`, 31-byte
    /// big-endian chunking) the twin of its `gadget.HashBytes`. This is the one
    /// canonical implementation: the SDK builds its proof inputs through it
    /// rather than duplicating the chain.
    pub fn hash(&self) -> Result<[u8; 32], ProgramError> {
        let (tx_pk_lo, tx_pk_hi) = pack33_to_2fe(self.tx_viewing_pk);
        let (auditor_lo, auditor_hi) = pack33_to_2fe(self.auditor_pk);
        let (eph_lo, eph_hi) = pack33_to_2fe(self.eph_pk);
        let ct_hash =
            ciphertext_hash(self.ciphertext).map_err(|_| CustomRingError::HashingFailed)?;
        create_hash_chain_from_slice(&[
            *self.private_tx_hash,
            tx_pk_lo,
            tx_pk_hi,
            auditor_lo,
            auditor_hi,
            eph_lo,
            eph_hi,
            ct_hash,
        ])
        .map_err(|_| CustomRingError::HashingFailed.into())
    }
}

/// The auditor message of a transaction: `eph_pk(33) || ciphertext(32)` split out
/// of the published message data.
struct AuditorMessageParts<'a> {
    eph_pk: &'a [u8; COMPRESSED_PUBKEY_LEN],
    ciphertext: &'a [u8; CIPHERTEXT_LEN],
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
        .split_at_checked(COMPRESSED_PUBKEY_LEN)
        .ok_or(CustomRingError::InvalidAuditorMessage)?;
    let eph_pk: &[u8; COMPRESSED_PUBKEY_LEN] = eph_pk
        .try_into()
        .map_err(|_| CustomRingError::InvalidAuditorMessage)?;
    let ciphertext: &[u8; CIPHERTEXT_LEN] = ciphertext
        .try_into()
        .map_err(|_| CustomRingError::InvalidAuditorMessage)?;
    Ok(AuditorMessageParts { eph_pk, ciphertext })
}

/// Verifies the auditor key-encryption proof against the recomputed public-input
/// hash, then CPIs SPP `RING_TRANSACT` with the `ring_auth` PDA as signer.
///
/// Accounts: `[payer(w,s), config]` followed by SPP's own `RING_TRANSACT` list
/// (`payer, input_tree, output_tree, spp_program, system_program, ring_config,
/// owner signers, settlement accounts`), which is forwarded position for
/// position with only `ring_config` (this ring's `ring_auth` PDA) gaining a
/// signature.
#[inline(never)]
pub fn process_transact_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let mut iter = AccountIterator::new(accounts);
    let payer = iter.next_signer_mut("payer")?;
    let config_account = iter.next_account("config")?;

    let CustomRingTransactIxData { proof, transact } =
        wincode::deserialize_exact(data).map_err(|_| CustomRingError::InvalidInstructionData)?;

    // An approval account, when the caller passes one, sits between the config
    // and the forwarded list. Only this program writes accounts with that
    // discriminator, so ownership plus the first byte identify it; SPP's list
    // starts with a system-owned signer and can never be mistaken for one.
    let rest = iter.remaining_mut()?;
    let (approval, spp_accounts) = match rest.split_first_mut() {
        Some((first, spp_accounts)) if is_approval_account(first) => (Some(first), spp_accounts),
        _ => (None, rest),
    };
    // The forwarded list is taken before the expensive work so a malformed
    // account list costs no pairing.
    validate_spp_program(spp_accounts)?;

    // Only this program can own an account it wrote, and `create_config` writes
    // exactly one -- the canonical config PDA -- so ownership plus the
    // discriminator already identify it; the borrow is released here so the
    // account is not still borrowed across the CPI.
    let auditor_pubkey = {
        let config = load_config(config_account)?;
        // Policy before the pairing: a refused transfer costs no proof work.
        let needs_approval = check_transact(&config, spp_accounts, &transact.interface_transfers)?;
        if needs_approval && approval.is_none() {
            return Err(CustomRingError::ApprovalRequired.into());
        }
        config.auditor_pubkey
    };
    // The approval is bound to this transact through `private_tx_hash`; it is
    // spent after the CPI so it cannot approve a second submission.
    if let Some(approval) = &approval {
        check_approval(approval, &transact.private_tx_hash)?;
    }

    // This ring has one rail: Solana eddsa signers. `RingP256` (and any future
    // selector) would put SPP on a proof shape whose ownership semantics this
    // ring has never reviewed, so it is refused rather than forwarded.
    if !matches!(transact.circuit, CircuitId::RingEddsa(..)) {
        return Err(CustomRingError::UnsupportedCircuit.into());
    }

    // The auditor's view tag is its key's x-coordinate, i.e. the compressed key
    // without the SEC1 prefix.
    let view_tag: &[u8; 32] = auditor_pubkey
        .get(1..COMPRESSED_PUBKEY_LEN)
        .and_then(|tag| tag.try_into().ok())
        .ok_or(CustomRingError::InvalidAuditorPubkey)?;
    let message = select_auditor_message(&transact.messages, view_tag)?;

    verify_groth16(
        CompressedGroth16Proof {
            a: &proof.proof_a,
            b: &proof.proof_b,
            c: &proof.proof_c,
            commitment: Some((&proof.commitment, &proof.commitment_pok)),
        },
        AuditPublicInput {
            private_tx_hash: &transact.private_tx_hash,
            tx_viewing_pk: &transact.tx_viewing_pk,
            auditor_pk: &auditor_pubkey,
            eph_pk: message.eph_pk,
            ciphertext: message.ciphertext,
        }
        .hash()?,
        &crate::verifying_keys::auditor_key_encryption::VERIFYINGKEY,
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
    cpi_spp_signed(spp_accounts, &instruction_data)?;

    // Lamports move only after the CPI: the runtime syncs the caller's changes
    // to the accounts it forwards (the payer) before invoking, and an account
    // outside the CPI list (the approval) only at the end, so moving them
    // earlier reads as an unbalanced instruction.
    if let Some(approval) = approval {
        payer.set_lamports(
            payer
                .lamports()
                .checked_add(approval.lamports())
                .ok_or(ProgramError::ArithmeticOverflow)?,
        );
        approval.set_lamports(0);
        approval.close()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixture of the circuit's Go test
    /// (`prover/circuits/auditor_key_encryption/circuit_test.go`, scalars
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
            (bytes::<32>(TX_PK_LO), bytes::<32>(TX_PK_HI))
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
