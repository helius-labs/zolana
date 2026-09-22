use core::num::NonZeroU64;

use custom_ring_interface::{
    CompressedPolicyPublicInput, CustomRingBasePublicInput, CustomRingPolicyPublicInput,
    CustomRingProof, CustomRingTransactIxData, FixedWindow, HeadMapRoot, HeadMapTransition,
    AUDIT_CIPHERTEXT_LEN, AUDIT_DISCLOSURE_FIELD_COUNT, AUDIT_DISCLOSURE_LEN,
    COMPRESSED_P256_KEY_LEN,
};
use pinocchio::{
    account::RefMut,
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
use zolana_interface::{NULLIFIER_PDA_SEED, SHIELDED_POOL_PROGRAM_ID};
use zolana_ring_policy::{ring_id_field, ListNamespace, VelocityMode, ANSWER_SLOTS};

use crate::{
    error::CustomRingError,
    instructions::{
        cosign::{approval_signer, require_cosigner, CoSignerRequirement},
        loader::{load_append_root_mut, load_config, load_policy_config, validate_spp_program},
        policy_shared::{
            namespace_address, require_entries_trees, RecordNamespace, SpendRecordCarrier,
        },
        public_legs::PublicLegs,
        roots::load_roots,
        shared::{cpi_spp_signed, PdaCheck, SppSigners},
        verifier::verify_groth16,
    },
    state::{Advance, RootTransition},
};

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
    TransactRail::Member.verify_and_forward(
        TransactControls {
            program_id,
            config_account,
            cosigner_account,
            cosigner,
        },
        iter,
        data,
    )
}

/// Selects member ownership authorization or the configured delegate's
/// signature.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum TransactRail {
    Member,
    /// Owner signatures are replaced by the delegate's, value never leaves.
    Delegate,
}

/// Ring-owned control accounts shared by member and delegate settlement.
pub(crate) struct TransactControls<'a> {
    pub program_id: &'a Address,
    pub config_account: &'a AccountView,
    pub cosigner_account: &'a AccountView,
    pub cosigner: &'a AccountView,
}

impl TransactRail {
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

    /// `rest` holds the policy accounts, the window slots and the SPP list.
    pub fn verify_and_forward(
        self,
        controls: TransactControls<'_>,
        mut rest: AccountIterator<'_>,
        data: &[u8],
    ) -> ProgramResult {
        let TransactControls {
            program_id,
            config_account,
            cosigner_account,
            cosigner,
        } = controls;
        // 1. Decode the statement and reject public settlement on the delegate
        // rail.
        let decoded = decode_transact(data)?;
        let CustomRingTransactIxData {
            proof,
            state_root_index,
            nullifier_root_index,
            approval_required,
            head_transition,
            revocation_targets,
            transact,
        } = &*decoded;
        let approval_required = match approval_required {
            0 => false,
            1 => true,
            _ => return Err(CustomRingError::InvalidInstructionData.into()),
        };
        if self == TransactRail::Delegate && !transact.interface_transfers.is_empty() {
            return Err(CustomRingError::DelegatePublicLeg.into());
        }

        // 2. Select the verifier from ring state and pin windowed history to
        // the current head.
        let (auditor_pubkey, has_policy) = {
            let config = load_config(program_id, config_account)?;
            (config.auditor_pubkey, config.has_policy)
        };
        let policy = if has_policy != 0 {
            let policy_config_account = rest.next_account("policy_config")?;
            let entries_tree_account = rest.next_account("entries_tree")?;
            let binding = PolicyBinding::load(program_id, policy_config_account)?;
            Some((binding, entries_tree_account))
        } else {
            None
        };
        let amount_controls_active = self == TransactRail::Member
            && policy
                .as_ref()
                .is_some_and(|(binding, _)| !matches!(binding.velocity, VelocityMode::Off));
        let windowed_policy = policy
            .as_ref()
            .is_some_and(|(binding, _)| matches!(binding.velocity, VelocityMode::PerWindow { .. }));
        if approval_required && !amount_controls_active {
            return Err(CustomRingError::InvalidInstructionData.into());
        }
        let statement = match (self, head_transition) {
            (TransactRail::Delegate, None) => PolicyStatement::Delegate,
            (TransactRail::Member, None) if !windowed_policy => PolicyStatement::Member,
            (TransactRail::Member, Some(transition)) if windowed_policy => {
                let account = rest.next_mut("head_map_root")?;
                let root = load_append_root_mut::<HeadMapRoot>(program_id, account)?;
                let (binding, _) = policy.as_ref().ok_or(CustomRingError::InvalidPolicyRules)?;
                let namespace = namespace_address(program_id, binding.namespace_bump)?;
                let counters_disclosure_hash = CountersDisclosure {
                    namespace: namespace.as_array(),
                    tx_viewing_pk: &transact.tx_viewing_pk,
                    salt: &transact.salt,
                    messages: &transact.messages,
                }
                .hash()?;
                if root.root != transition.old_root {
                    return Err(CustomRingError::StaleHeadMapRoot.into());
                }
                PolicyStatement::Windowed {
                    transition: *transition,
                    root,
                    counters_disclosure_hash,
                }
            }
            _ => return Err(CustomRingError::InvalidInstructionData.into()),
        };
        match policy.as_ref() {
            Some((binding, _)) => {
                validate_revocation_targets(&mut rest, &binding.entries_tree, revocation_targets)?
            }
            None if revocation_targets.iter().any(|target| *target != [0u8; 32]) => {
                return Err(CustomRingError::InvalidInstructionData.into())
            }
            None => {}
        }

        // 3. Enforce approval and public mint caps against the actual
        // settlement legs.
        let rest = rest.remaining_mut()?;
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
        let demand = CoSignerRequirement::transact(PublicLegs::from_transact(
            &transact.interface_transfers,
            settlements,
        )?);
        let demanded = if approval_required {
            Some(approval_signer(program_id, cosigner_account)?)
        } else {
            demand.demanded_signer(program_id, cosigner_account)?
        };
        require_cosigner(demanded, cosigner)?;
        if amount_controls_active && demand.legs.has_deposits() {
            return Err(CustomRingError::VelocityDepositLeg.into());
        }
        demand.legs.apply_windows(program_id, windows)?;

        // 4. Bind auditor disclosure to the selected SPP statement and its
        // unique audit message.
        if !self.accepts(transact.circuit) {
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
        let output_hashes: Vec<[u8; 32]> = transact
            .outputs
            .iter()
            .map(|output| output.utxo_hash)
            .collect();
        let audit = CustomRingBasePublicInput {
            private_tx_hash: &transact.private_tx_hash,
            tx_viewing_pk: &transact.tx_viewing_pk,
            auditor_pk: &auditor_pubkey,
            eph_pk: message.eph_pk,
            ciphertext: message.ciphertext,
            output_hashes: &output_hashes,
            salt: &transact.salt,
            disclosure: message.disclosure,
        };

        // 5. Verify policy and record commitments before granting namespace
        // spend authorization.
        let signers = match policy {
            Some((binding, entries_tree_account)) => {
                let signers = match &statement {
                    PolicyStatement::Windowed { .. } => {
                        let record_output = transact
                            .outputs
                            .last()
                            .ok_or(CustomRingError::InvalidSpendRecord)?;
                        SpendRecordCarrier {
                            output: record_output,
                            messages: &transact.messages,
                        }
                        .verify(&RecordNamespace {
                            owner: ListNamespace {
                                owner_hash: binding.namespace_owner_hash,
                            },
                            address: namespace_address(program_id, binding.namespace_bump)?,
                            tree_id: binding.entries_tree_id,
                        })?;
                        binding
                            .require_transact_trees(spp_accounts, transact.tree_contexts.len())?;
                        SppSigners::RingAuthAndNamespace {
                            bump: binding.namespace_bump,
                        }
                    }
                    PolicyStatement::Member | PolicyStatement::Delegate => {
                        if windowed_policy {
                            let destination = spp_accounts
                                .get(1..2)
                                .ok_or(ProgramError::NotEnoughAccountKeys)?;
                            require_entries_trees(destination, &binding.entries_tree)?;
                        }
                        SppSigners::RingAuth
                    }
                };
                let window_index = match (self, binding.velocity) {
                    (TransactRail::Member, VelocityMode::PerWindow { window_slots }) => {
                        FixedWindow {
                            slots: NonZeroU64::new(window_slots)
                                .ok_or(CustomRingError::InvalidPolicyRules)?,
                        }
                        .index(Clock::get()?.slot)
                    }
                    _ => 0,
                };
                let ring_id = ring_id_field(program_id.as_array())
                    .map_err(|_| CustomRingError::HashingFailed)?;
                // Root reads must release any tree borrow before SPP mutates the same account.
                let roots = load_roots(
                    entries_tree_account,
                    &binding.entries_tree,
                    *state_root_index,
                    *nullifier_root_index,
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
                    revocation_targets,
                };
                statement.verify_and_advance(proof, policy_input)?;
                signers
            }
            None => {
                verify_groth16(
                    proof,
                    audit.hash().map_err(|_| CustomRingError::HashingFailed)?,
                    &custom_ring_interface::base_verifying_key::VERIFYINGKEY,
                )?;
                SppSigners::RingAuth
            }
        };

        // 6. Settle the verified bytes through SPP, any failure rolls back
        // counters and head updates.
        let transact_bytes = transact
            .serialize()
            .map_err(|_| CustomRingError::InvalidInstructionData)?;
        let mut instruction_data = Vec::with_capacity(1 + transact_bytes.len());
        instruction_data.push(self.spp_tag());
        instruction_data.extend_from_slice(&transact_bytes);
        cpi_spp_signed(program_id, spp_accounts, &instruction_data, signers)
    }
}

fn validate_revocation_targets(
    accounts: &mut AccountIterator<'_>,
    entries_tree: &Address,
    targets: &[[u8; 32]; ANSWER_SLOTS],
) -> ProgramResult {
    let spp = Address::from(SHIELDED_POOL_PROGRAM_ID);
    for target in targets
        .iter()
        .filter(|target| target.iter().any(|byte| *byte != 0))
    {
        let account = accounts.next_account("revocation_target")?;
        PdaCheck {
            program_id: &spp,
            address: account.address(),
            seeds: &[NULLIFIER_PDA_SEED, entries_tree.as_array(), target],
            mismatch: CustomRingError::InvalidRevocationTarget,
        }
        .verify()?;
        if !pinocchio_system::check_id(account.owner()) || account.data_len() != 0 {
            return Err(CustomRingError::PolicyFactRevoked.into());
        }
    }
    Ok(())
}

/// Proof variants separating member limits, compressed history and delegate
/// exemptions.
enum PolicyStatement<'a> {
    Member,
    Windowed {
        transition: HeadMapTransition,
        counters_disclosure_hash: [u8; 32],
        root: RefMut<'a, HeadMapRoot>,
    },
    Delegate,
}

impl PolicyStatement<'_> {
    /// Inlining exceeds the SBF stack frame limit.
    #[inline(never)]
    fn verify_and_advance(
        self,
        proof: &CustomRingProof,
        policy_input: CustomRingPolicyPublicInput<'_>,
    ) -> ProgramResult {
        match self {
            Self::Windowed {
                transition,
                mut root,
                counters_disclosure_hash,
            } => {
                let public_input = CompressedPolicyPublicInput {
                    policy: policy_input,
                    counters_disclosure_hash: &counters_disclosure_hash,
                    head_old_root: &transition.old_root,
                    head_new_root: &transition.new_root,
                }
                .hash()
                .map_err(|_| CustomRingError::HashingFailed)?;
                verify_groth16(
                    proof,
                    public_input,
                    &custom_ring_interface::compressed_policy_verifying_key::VERIFYINGKEY,
                )?;
                RootTransition {
                    expected_root: &transition.old_root,
                    new_root: transition.new_root,
                    advance: Advance::Transfer,
                }
                .apply(&mut *root)
            }
            Self::Delegate => verify_groth16(
                proof,
                policy_input
                    .hash()
                    .map_err(|_| CustomRingError::HashingFailed)?,
                &custom_ring_interface::delegate_policy_verifying_key::VERIFYINGKEY,
            ),
            Self::Member => verify_groth16(
                proof,
                policy_input
                    .hash()
                    .map_err(|_| CustomRingError::HashingFailed)?,
                &custom_ring_interface::policy_verifying_key::VERIFYINGKEY,
            ),
        }
    }
}

#[inline(never)]
fn decode_transact(data: &[u8]) -> Result<Box<CustomRingTransactIxData>, ProgramError> {
    wincode::deserialize_exact(data).map_err(|_| CustomRingError::InvalidInstructionData.into())
}

/// Copied out, no account borrow may live across the SPP CPI.
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

    /// The output tree and every input tree of a record transaction.
    fn require_transact_trees(
        &self,
        spp_accounts: &[AccountView],
        input_trees: usize,
    ) -> ProgramResult {
        let output = spp_accounts
            .get(1..2)
            .ok_or(ProgramError::NotEnoughAccountKeys)?;
        let inputs = spp_accounts
            .get(5..5 + input_trees)
            .ok_or(ProgramError::NotEnoughAccountKeys)?;
        require_entries_trees(output, &self.entries_tree)?;
        require_entries_trees(inputs, &self.entries_tree)
    }
}

/// The auditor message of a transaction: `eph_pk(33) || ciphertext(32)` split out
/// of the published message data.
struct AuditorMessageParts<'a> {
    eph_pk: &'a [u8; COMPRESSED_P256_KEY_LEN],
    ciphertext: &'a [u8; AUDIT_CIPHERTEXT_LEN],
    disclosure: &'a [[u8; 32]],
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

    let (eph_pk, body) = last
        .data
        .split_at_checked(COMPRESSED_P256_KEY_LEN)
        .ok_or(CustomRingError::InvalidAuditorMessage)?;
    let eph_pk: &[u8; COMPRESSED_P256_KEY_LEN] = eph_pk
        .try_into()
        .map_err(|_| CustomRingError::InvalidAuditorMessage)?;
    let (ciphertext, disclosure) = body
        .split_at_checked(AUDIT_CIPHERTEXT_LEN)
        .filter(|(_, disclosure)| disclosure.len() == AUDIT_DISCLOSURE_LEN)
        .ok_or(CustomRingError::InvalidAuditorMessage)?;
    let ciphertext: &[u8; AUDIT_CIPHERTEXT_LEN] = ciphertext
        .try_into()
        .map_err(|_| CustomRingError::InvalidAuditorMessage)?;
    let disclosure: &[[u8; 32]] =
        bytemuck::try_cast_slice(disclosure).map_err(|_| CustomRingError::InvalidAuditorMessage)?;
    if disclosure.len() != AUDIT_DISCLOSURE_FIELD_COUNT {
        return Err(CustomRingError::InvalidAuditorMessage.into());
    }
    Ok(AuditorMessageParts {
        eph_pk,
        ciphertext,
        disclosure,
    })
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
    /// (`prover/server/custom_rings/circuits/base/circuit_test.go`, scalars
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
        "25266a07f9480618e9ab495065e3d2a4530ab8e2cefe44d6b5e7324466bb0093";

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
            output_hashes: &[[0u8; 32]],
            salt: &[0u8; 16],
            disclosure: &[[0u8; 32]; AUDIT_DISCLOSURE_FIELD_COUNT],
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
            parts.eph_pk.len() + parts.ciphertext.len() + core::mem::size_of_val(parts.disclosure),
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

struct CountersDisclosure<'a> {
    namespace: &'a [u8; 32],
    tx_viewing_pk: &'a [u8; 33],
    salt: &'a [u8; 16],
    messages: &'a [MessageData],
}

impl CountersDisclosure<'_> {
    fn hash(self) -> Result<[u8; 32], ProgramError> {
        let mut messages = self
            .messages
            .iter()
            .filter(|message| &message.view_tag == self.namespace);
        let message = messages
            .next()
            .ok_or(CustomRingError::InvalidSpendCountersDisclosure)?;
        if messages.next().is_some() || !message.data.starts_with(self.tx_viewing_pk) {
            return Err(CustomRingError::InvalidSpendCountersDisclosure.into());
        }
        let body = message
            .data
            .as_slice()
            .try_into()
            .map_err(|_| CustomRingError::InvalidSpendCountersDisclosure)?;
        zolana_ring_policy::spend_counters_disclosure_hash(self.salt, body)
            .map_err(|_| CustomRingError::HashingFailed.into())
    }
}

#[cfg(test)]
mod counters_tests {
    use super::*;

    #[test]
    fn counters_disclosure_requires_one_full_body_for_the_transaction_key() {
        let namespace = [7; 32];
        let public = [2; 33];
        let salt = [3; 16];
        let mut body = vec![0; zolana_ring_policy::SPEND_COUNTERS_BODY_LEN];
        body[..33].copy_from_slice(&public);
        let message = MessageData {
            view_tag: namespace,
            data: body,
        };
        let hash = |messages: &[MessageData]| {
            CountersDisclosure {
                namespace: &namespace,
                tx_viewing_pk: &public,
                salt: &salt,
                messages,
            }
            .hash()
        };
        assert!(hash(std::slice::from_ref(&message)).is_ok());
        let refused = Err(CustomRingError::InvalidSpendCountersDisclosure.into());
        assert_eq!(hash(&[]), refused);
        assert_eq!(hash(&[message.clone(), message.clone()]), refused);
        let mut changed = message.clone();
        changed.data.pop();
        assert_eq!(hash(&[changed]), refused);
        let mut changed = message.clone();
        changed.data[0] ^= 1;
        assert_eq!(hash(&[changed]), refused);
        let mut changed = message.clone();
        changed.data[384] ^= 1;
        assert_ne!(hash(&[message]).unwrap(), hash(&[changed]).unwrap());
    }
}
