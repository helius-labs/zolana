use custom_ring_interface::{
    CompressedPolicyPublicInput, CustomRingBasePublicInput, CustomRingPolicyPublicInput,
    CustomRingTransactIxData, HeadMapTransition, AUDIT_CIPHERTEXT_LEN, COMPRESSED_P256_KEY_LEN,
};
use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use zolana_account_checks::AccountIterator;
use zolana_interface::instruction::{
    instruction_data::transact::{
        confidential_encrypted_output_body, ring_confidential_encrypted_output_body,
    },
    tag, CircuitId, MessageData,
};
use zolana_ring_policy::{ring_id_field, ListNamespace, VelocityMode};

use crate::{
    error::CustomRingError,
    instructions::{
        cosign::{require_approval, require_cosigner, Demand},
        loader::{load_config, load_head_map_root, load_policy_config, validate_spp_program},
        policy_shared::{namespace_address, require_entries_trees, verify_spend_record_output},
        public_legs::{apply_spend_windows, PublicLegs},
        roots::load_roots,
        shared::cpi_spp_signed,
        verifier::{verify_groth16, CompressedGroth16Proof},
    },
    state::advance_head_map_root,
};

/// Verifies the ring proof against the recomputed public input, then CPIs SPP
/// `RING_TRANSACT` with the `ring_auth` PDA as signer.
///
/// The config `has_policy` flag pins the tier and no client input can override
/// it. A policy ring verifies the folded sixteen-element statement over the
/// pinned policy hash, the entries-tree roots and the spend window, its accounts
/// `[payer(w,s), config, cosigner_pda, cosigner, policy_config, entries_tree(r)]`
/// precede one spend window slot per public leg and the SPP list. A base ring
/// verifies just the eight-element audit statement against the base verifying
/// key, its accounts are `[payer(w,s), config, cosigner_pda, cosigner]`. Only
/// the SPP `RING_TRANSACT` list is forwarded, position for position, with
/// `ring_config` gaining a signature and, on a velocity ring, the namespace
/// PDA owning the record slots.
#[inline(never)]
pub fn process_transact_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let mut iter = AccountIterator::new(accounts);
    iter.next_signer_mut("payer")?;
    let config_account = iter.next_account("config")?;
    let cosigner_account = iter.next_account("cosigner_pda")?;
    let cosigner = iter.next_account("cosigner")?;
    verify_and_forward(
        program_id,
        iter,
        Gate {
            config_account,
            cosigner_account,
            cosigner,
        },
        data,
        Rail::Member,
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rail {
    Member,
    /// Owner signatures are replaced by the delegate's, value never leaves.
    Delegate,
}

impl Rail {
    fn accepts(self, circuit: CircuitId) -> bool {
        match self {
            Self::Member => matches!(circuit, CircuitId::RingEddsa(..)),
            Self::Delegate => matches!(circuit, CircuitId::RingAuthority(..)),
        }
    }

    const fn spp_tag(self) -> u8 {
        match self {
            Self::Member => tag::RING_TRANSACT,
            Self::Delegate => tag::RING_AUTHORITY_TRANSACT,
        }
    }
}

pub(crate) struct Gate<'a> {
    pub config_account: &'a AccountView,
    pub cosigner_account: &'a AccountView,
    pub cosigner: &'a AccountView,
}

pub(crate) fn verify_and_forward(
    program_id: &Address,
    mut iter: AccountIterator<'_>,
    gate: Gate<'_>,
    data: &[u8],
    rail: Rail,
) -> ProgramResult {
    let Gate {
        config_account,
        cosigner_account,
        cosigner,
    } = gate;
    let decoded = decode_transact(data)?;
    let proof = &decoded.proof;
    let state_root_index = decoded.state_root_index;
    let nullifier_root_index = decoded.nullifier_root_index;
    let head_transition = decoded.head_transition;
    let transact = &decoded.transact;
    let approval_required = match decoded.approval_required {
        0 => false,
        1 => true,
        _ => return Err(CustomRingError::InvalidInstructionData.into()),
    };
    if rail == Rail::Delegate && !transact.interface_transfers.is_empty() {
        return Err(CustomRingError::DelegatePublicLeg.into());
    }

    // The tier comes from the authenticated config, a policy ring cannot drop its
    // policy accounts to spend through the lighter audit statement.
    let (auditor_pubkey, has_policy) = {
        let config = load_config(program_id, config_account)?;
        (config.auditor_pubkey, config.has_policy)
    };
    let policy = if has_policy != 0 {
        let policy_config_account = iter.next_account("policy_config")?;
        let entries_tree_account = iter.next_account("entries_tree")?;
        let binding = PolicyBinding::load(program_id, policy_config_account)?;
        Some((binding, entries_tree_account))
    } else {
        None
    };
    let rows_on = rail == Rail::Member
        && policy
            .as_ref()
            .is_some_and(|(binding, _)| !matches!(binding.velocity, VelocityMode::Off));
    let windowed = policy
        .as_ref()
        .is_some_and(|(binding, _)| matches!(binding.velocity, VelocityMode::PerWindow { .. }));
    let record_mode = rail == Rail::Member && windowed;
    if approval_required && !rows_on {
        return Err(CustomRingError::InvalidInstructionData.into());
    }
    if head_transition.is_some() != record_mode {
        return Err(CustomRingError::InvalidInstructionData.into());
    }

    let head_map_account = if record_mode {
        let account = iter.next_mut("head_map_root")?;
        let head = load_head_map_root(program_id, account)?;
        if head.root
            != head_transition
                .as_ref()
                .ok_or(CustomRingError::InvalidInstructionData)?
                .old_root
        {
            return Err(CustomRingError::StaleHeadMapRoot.into());
        }
        drop(head);
        Some(account)
    } else {
        None
    };

    // The forwarded list is validated before the pairing so a malformed account
    // list costs no verification.
    let rest = iter.remaining_mut()?;
    let leg_count = transact.interface_transfers.len();
    if rest.len() < leg_count {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let (windows, spp_accounts) = rest.split_at_mut(leg_count);
    validate_spp_program(spp_accounts)?;
    let settlement_len: usize = transact
        .interface_transfers
        .iter()
        .map(|leg| leg.settlement_account_count())
        .sum();
    let settlements = spp_accounts
        .len()
        .checked_sub(settlement_len)
        .and_then(|start| spp_accounts.get(start..))
        .ok_or(CustomRingError::InvalidInstructionData)?;
    let demand = Demand::transact(PublicLegs::from_transact(
        &transact.interface_transfers,
        settlements,
    )?);
    require_cosigner(program_id, cosigner_account, cosigner, &demand)?;
    if rows_on && demand.legs.has_deposits() {
        return Err(CustomRingError::VelocityDepositLeg.into());
    }
    apply_spend_windows(program_id, windows, &demand.legs)?;

    if !rail.accepts(transact.circuit) {
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
    let audit = CustomRingBasePublicInput {
        private_tx_hash: &transact.private_tx_hash,
        tx_viewing_pk: &transact.tx_viewing_pk,
        auditor_pk: &auditor_pubkey,
        eph_pk: message.eph_pk,
        ciphertext: message.ciphertext,
    };
    let compressed = CompressedGroth16Proof {
        a: &proof.proof_a,
        b: &proof.proof_b,
        c: &proof.proof_c,
        commitment: &proof.commitment,
        commitment_pok: &proof.commitment_pok,
    };

    let namespace = match policy {
        Some((binding, entries_tree_account)) => {
            let namespace = if record_mode {
                let record_output = transact
                    .outputs
                    .last()
                    .ok_or(CustomRingError::InvalidSpendRecord)?;
                verify_spend_record_output(
                    record_output,
                    &transact.messages,
                    &ListNamespace {
                        owner_hash: binding.namespace_owner_hash,
                    },
                    &namespace_address(program_id, binding.namespace_bump)?,
                    binding.entries_tree_id,
                )?;
                require_entries_tree(
                    spp_accounts,
                    &binding.entries_tree,
                    transact.tree_contexts.len(),
                )?;
                Some(binding.namespace_bump)
            } else {
                if windowed {
                    let destination = spp_accounts
                        .get(1..2)
                        .ok_or(ProgramError::NotEnoughAccountKeys)?;
                    require_entries_trees(destination, &binding.entries_tree)?;
                }
                None
            };
            if approval_required {
                require_approval(program_id, cosigner_account, cosigner)?;
            }
            let window_index = match (rail, binding.velocity) {
                (Rail::Member, VelocityMode::PerWindow { window_slots }) => {
                    Clock::get()?.slot / window_slots
                }
                _ => 0,
            };
            let ring_id =
                ring_id_field(program_id.as_array()).map_err(|_| CustomRingError::HashingFailed)?;
            // The borrow drops before the CPI below, else SPP faults borrowing the
            // aliased money tree.
            let roots = load_roots(
                entries_tree_account,
                &binding.entries_tree,
                state_root_index,
                nullifier_root_index,
            )?;
            let policy_input = CustomRingPolicyPublicInput {
                audit,
                policy_hash: &binding.policy_hash,
                state_root: &roots.state,
                nullifier_root: &roots.nullifier,
                entries_tree_id: binding.entries_tree_id,
                ring_id: &ring_id,
                namespace_owner_hash: &binding.namespace_owner_hash,
                window_index,
                approval_required,
            };
            verify_policy_proof(
                compressed,
                policy_input,
                rail,
                head_transition,
                head_map_account,
            )?;
            namespace
        }
        None => {
            verify_groth16(
                compressed,
                audit.hash().map_err(|_| CustomRingError::HashingFailed)?,
                &custom_ring_interface::base_verifying_key::VERIFYINGKEY,
            )?;
            None
        }
    };

    // Reserialized from the parsed struct rather than sliced out of `data`: the
    // proof is verified against the parsed content, so the bytes SPP sees must be
    // the ones that were parsed.
    let transact_bytes = transact
        .serialize()
        .map_err(|_| CustomRingError::InvalidInstructionData)?;
    let mut instruction_data = Vec::with_capacity(1 + transact_bytes.len());
    instruction_data.push(rail.spp_tag());
    instruction_data.extend_from_slice(&transact_bytes);
    cpi_spp_signed(program_id, spp_accounts, &instruction_data, namespace)
}

#[inline(never)]
fn decode_transact(data: &[u8]) -> Result<Box<CustomRingTransactIxData>, ProgramError> {
    wincode::deserialize_exact(data)
        .map(Box::new)
        .map_err(|_| CustomRingError::InvalidInstructionData.into())
}

/// Inlining exceeds the SBF stack frame limit.
#[inline(never)]
fn verify_policy_proof(
    compressed: CompressedGroth16Proof<'_>,
    policy_input: CustomRingPolicyPublicInput<'_>,
    rail: Rail,
    head_transition: Option<HeadMapTransition>,
    head_map_account: Option<&mut AccountView>,
) -> ProgramResult {
    match (rail, head_transition) {
        (Rail::Member, Some(transition)) => {
            let public_input = CompressedPolicyPublicInput {
                policy: policy_input,
                head_old_root: &transition.old_root,
                head_new_root: &transition.new_root,
            }
            .hash()
            .map_err(|_| CustomRingError::HashingFailed)?;
            verify_groth16(
                compressed,
                public_input,
                &custom_ring_interface::compressed_policy_verifying_key::VERIFYINGKEY,
            )?;
            advance_head_map_root(
                head_map_account.ok_or(ProgramError::NotEnoughAccountKeys)?,
                &transition.old_root,
                transition.new_root,
                false,
            )
        }
        (Rail::Delegate, None) => verify_groth16(
            compressed,
            policy_input
                .hash()
                .map_err(|_| CustomRingError::HashingFailed)?,
            &custom_ring_interface::delegate_policy_verifying_key::VERIFYINGKEY,
        ),
        (Rail::Member, None) => verify_groth16(
            compressed,
            policy_input
                .hash()
                .map_err(|_| CustomRingError::HashingFailed)?,
            &custom_ring_interface::policy_verifying_key::VERIFYINGKEY,
        ),
        (Rail::Delegate, Some(_)) => Err(CustomRingError::InvalidInstructionData.into()),
    }
}

/// Copied out of the policy config before the entries tree is borrowed.
struct PolicyBinding {
    policy_hash: [u8; 32],
    entries_tree: Address,
    entries_tree_id: u16,
    namespace_owner_hash: [u8; 32],
    namespace_bump: u8,
    velocity: VelocityMode,
}

impl PolicyBinding {
    #[inline(never)]
    fn load(program_id: &Address, account: &AccountView) -> Result<Self, ProgramError> {
        let policy = load_policy_config(program_id, account)?;
        Ok(Self {
            policy_hash: policy.policy_hash,
            entries_tree: policy.entries_tree,
            entries_tree_id: policy.entries_tree_id(),
            namespace_owner_hash: policy.namespace_owner_hash,
            namespace_bump: policy.namespace_bump,
            velocity: policy.rules.velocity_mode(),
        })
    }
}

fn require_entries_tree(
    spp_accounts: &[AccountView],
    entries_tree: &Address,
    input_trees: usize,
) -> ProgramResult {
    let output = spp_accounts
        .get(1..2)
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let inputs = spp_accounts
        .get(5..5 + input_trees)
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    require_entries_trees(output, entries_tree)?;
    require_entries_trees(inputs, entries_tree)
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
/// tagged ciphertext that an indexer or auditor might pick up instead of the proven
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
        let hash = CustomRingBasePublicInput {
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
