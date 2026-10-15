use core::num::NonZeroU64;

use custom_ring_interface::{
    CompressedPolicyPublicInput, CustomRingBasePublicInput, CustomRingPolicyPublicInput,
    CustomRingProof, CustomRingTransactIxData, DisclosureShape, FixedWindow, RingMode,
    AUDIT_CIPHERTEXT_LEN, VIEWING_PUBKEY_LEN, VIEWING_PUBKEY_TAG,
};
use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use zolana_account_checks::AccountIterator;
use zolana_interface::instruction::{
    instruction_data::transact::{
        confidential_encrypted_output_body, ring_confidential_encrypted_output_body, OwnerTag,
    },
    tag, CircuitId, MessageData, TransactIxData,
};
use zolana_ring_policy::{ring_id_field, spend_record_message_tag, ListNamespace, VelocityMode};

use crate::{
    error::CustomRingError,
    instructions::{
        cosign::{approval_signer, require_cosigner, CoSignerRequirement},
        key_escrow::EscrowRoot,
        loader::{load_audited_config, load_policy_config, load_spp_tree_id, validate_spp_program},
        policy_shared::{namespace_address, RecordNamespace, SpendRecordCarrier},
        policy_trees::{PolicyTrees, RevocationTargets},
        public_legs::PublicLegs,
        shared::{cpi_spp_signed, SppSigners},
        verifier::verify_groth16,
    },
};

#[inline(never)]
pub fn process_transact_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let mut iter = AccountIterator::new(accounts);
    let payer = iter.next_signer_mut("payer")?;
    let config_account = iter.next_account("config")?;
    let cosigner_account = iter.next_account("cosigner_pda")?;
    let cosigner = iter.next_account("cosigner")?;
    TransactRail::Member.verify_and_forward(
        TransactControls {
            program_id,
            payer,
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
    pub payer: &'a AccountView,
    pub config_account: &'a AccountView,
    pub cosigner_account: &'a AccountView,
    pub cosigner: &'a AccountView,
}

impl TransactRail {
    /// An anonymous ring admits only the hidden-owner rail.
    fn accepts(self, circuit: CircuitId, mode: RingMode) -> bool {
        match (self, mode) {
            (Self::Member, RingMode::Anonymous) => {
                matches!(circuit, CircuitId::RingEd25519(..)) && circuit.is_supported()
            }
            (Self::Member, _) => matches!(circuit, CircuitId::RingEddsa(..)),
            (Self::Delegate, RingMode::Anonymous) => false,
            (Self::Delegate, _) => matches!(circuit, CircuitId::RingAuthority(..)),
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
            payer,
            config_account,
            cosigner_account,
            cosigner,
        } = controls;
        // 1. Decode the statement and reject public settlement on the delegate
        // rail.
        let decoded = decode_transact(data)?;
        let CustomRingTransactIxData {
            proof,
            policy_trees,
            key_registry_root_index,
            approval_required,
            revocation_targets,
            revocation_tree_indexes,
            transact,
        } = &*decoded;
        let approval_required = match approval_required {
            0 => false,
            1 => true,
            _ => return Err(CustomRingError::InvalidApprovalFlag.into()),
        };
        if self == TransactRail::Delegate && !transact.interface_transfers.is_empty() {
            return Err(CustomRingError::DelegatePublicLeg.into());
        }
        let revocations = RevocationTargets {
            targets: revocation_targets,
            tree_indexes: revocation_tree_indexes,
        };

        // 2. Select the verifier from ring state, read the policy trees and the
        // escrow registry.
        let config = load_audited_config(program_id, config_account)?;
        let anonymous = config.mode == RingMode::Anonymous;
        let policy = if config.has_policy {
            let policy_config_account = rest.next_account("policy_config")?;
            let binding = PolicyBinding::load(program_id, policy_config_account)?;
            let trees = PolicyTrees::load(&mut rest, policy_trees)?;
            if self == TransactRail::Delegate && config.mode != RingMode::Registry {
                return Err(CustomRingError::InvalidKeyRegistryRoot.into());
            }
            let key_registry_root = EscrowRoot {
                program_id,
                mode: config.mode,
                index: *key_registry_root_index,
            }
            .load(&mut rest)?;
            Some(PolicyReads {
                binding,
                trees,
                key_registry_root,
            })
        } else {
            if self == TransactRail::Delegate {
                return Err(CustomRingError::DelegateRequiresPolicy.into());
            }
            if !policy_trees.is_empty() {
                return Err(CustomRingError::InvalidPolicyTrees.into());
            }
            if *key_registry_root_index != 0 {
                return Err(CustomRingError::InvalidKeyRegistryRootIndex.into());
            }
            None
        };
        let amount_controls_active = self == TransactRail::Member
            && policy
                .as_ref()
                .is_some_and(|reads| !matches!(reads.binding.velocity, VelocityMode::Off));
        let windowed_policy = policy
            .as_ref()
            .is_some_and(|reads| matches!(reads.binding.velocity, VelocityMode::PerWindow { .. }));
        if approval_required && !amount_controls_active {
            return Err(CustomRingError::InvalidApprovalFlag.into());
        }
        // A spend record names its member.
        if anonymous && windowed_policy {
            return Err(CustomRingError::UnsupportedAnonymousPolicy.into());
        }
        let statement = match self {
            TransactRail::Delegate => PolicyStatement::Delegate,
            TransactRail::Member if !windowed_policy => PolicyStatement::Member,
            TransactRail::Member => {
                let reads = policy.as_ref().ok_or(CustomRingError::InvalidPolicyRules)?;
                let namespace = namespace_address(program_id, reads.binding.namespace_bump)?;
                let counters_disclosure_hash = CountersDisclosure {
                    namespace: namespace.as_array(),
                    tx_viewing_pk: &transact.tx_viewing_pk,
                    salt: &transact.salt,
                    messages: &transact.messages,
                }
                .hash()?;
                PolicyStatement::Windowed {
                    counters_disclosure_hash,
                }
            }
        };
        match policy.as_ref() {
            Some(reads) => revocations.verify(&reads.trees, &mut rest)?,
            None => revocations.require_empty()?,
        }
        if let (Some(reads), PolicyStatement::Member | PolicyStatement::Delegate) =
            (policy.as_ref(), &statement)
        {
            refuse_record_messages(program_id, reads.binding.namespace_bump, &transact.messages)?;
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
        if anonymous {
            check_anonymous_settlement(payer, transact, spp_accounts)?;
        }
        let settlement_len: usize = transact
            .interface_transfers
            .iter()
            .map(|leg| leg.settlement_account_count())
            .sum();
        let settlements = spp_accounts
            .len()
            .checked_sub(settlement_len)
            .and_then(|start| spp_accounts.get(start..))
            .ok_or(ProgramError::NotEnoughAccountKeys)?;
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
        if !self.accepts(transact.circuit, config.mode) {
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

        let view_tag: &[u8; 32] = config
            .auditor_pubkey
            .get(1..VIEWING_PUBKEY_LEN)
            .and_then(|tag| tag.try_into().ok())
            .ok_or(CustomRingError::InvalidAuditorPubkey)?;
        let shape = DisclosureShape {
            anonymous,
            inputs: transact.inputs.len(),
            outputs: transact.outputs.len(),
        };
        let message = select_auditor_message(&transact.messages, view_tag, shape)?;
        let output_hashes: Vec<[u8; 32]> = transact
            .outputs
            .iter()
            .map(|output| output.utxo_hash)
            .collect();
        let audit = CustomRingBasePublicInput {
            private_tx_hash: &transact.private_tx_hash,
            tx_viewing_pk: &transact.tx_viewing_pk,
            auditor_pk: &config.auditor_pubkey,
            eph_pk: message.eph_pk,
            ciphertext: message.ciphertext,
            output_hashes: &output_hashes,
            salt: &transact.salt,
            disclosure: message.disclosure,
            anonymous,
        };

        // 5. Verify policy and record commitments before granting namespace
        // spend authorization.
        let signers = match policy {
            Some(PolicyReads {
                binding,
                trees,
                key_registry_root,
            }) => {
                let signers = match &statement {
                    PolicyStatement::Windowed { .. } => {
                        let record_output = transact
                            .outputs
                            .last()
                            .ok_or(CustomRingError::InvalidSpendRecord)?;
                        let output_tree = spp_accounts
                            .get(1)
                            .ok_or(ProgramError::NotEnoughAccountKeys)?;
                        SpendRecordCarrier {
                            output: record_output,
                            messages: &transact.messages,
                            output_tree_id: load_spp_tree_id(
                                output_tree,
                                CustomRingError::InvalidSpendRecord,
                            )?,
                        }
                        .verify(&RecordNamespace {
                            owner: ListNamespace {
                                owner_hash: binding.namespace_owner_hash,
                            },
                            address: namespace_address(program_id, binding.namespace_bump)?,
                            address_tree_id: binding.address_tree_id,
                        })?;
                        SppSigners::RingAuthAndNamespace {
                            bump: binding.namespace_bump,
                        }
                    }
                    PolicyStatement::Member | PolicyStatement::Delegate => SppSigners::RingAuth,
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
                let policy_input = CustomRingPolicyPublicInput {
                    audit,
                    policy_hash: &binding.policy_hash,
                    tree_slots: trees.slots(),
                    address_tree_id: binding.address_tree_id,
                    ring_id: &ring_id,
                    namespace_owner_hash: &binding.namespace_owner_hash,
                    window_index,
                    approval_required,
                    key_registry_root: key_registry_root.as_ref(),
                    revocation_tree_indexes,
                    revocation_targets,
                };
                statement.verify(proof, policy_input)?;
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
        // counters.
        let transact_bytes = transact
            .serialize()
            .map_err(|_| CustomRingError::InvalidInstructionData)?;
        let mut instruction_data = Vec::with_capacity(1 + transact_bytes.len());
        instruction_data.push(self.spp_tag());
        instruction_data.extend_from_slice(&transact_bytes);
        cpi_spp_signed(program_id, spp_accounts, &instruction_data, signers)
    }
}

/// Proof variants separating member limits, compressed history and delegate
/// exemptions.
enum PolicyStatement {
    Member,
    Windowed { counters_disclosure_hash: [u8; 32] },
    Delegate,
}

impl PolicyStatement {
    /// Inlining exceeds the SBF stack frame limit.
    #[inline(never)]
    fn verify(
        self,
        proof: &CustomRingProof,
        policy_input: CustomRingPolicyPublicInput<'_>,
    ) -> ProgramResult {
        match self {
            Self::Windowed {
                counters_disclosure_hash,
            } => verify_groth16(
                proof,
                CompressedPolicyPublicInput {
                    policy: policy_input,
                    counters_disclosure_hash: &counters_disclosure_hash,
                }
                .hash()
                .map_err(|_| CustomRingError::HashingFailed)?,
                &custom_ring_interface::compressed_policy_verifying_key::VERIFYINGKEY,
            ),
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
    address_tree_id: u16,
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
            address_tree_id: policy.address_tree_id(),
            namespace_owner_hash: policy.namespace_owner_hash,
            namespace_bump: policy.namespace_bump,
            velocity: policy.rules.velocity_mode(),
        })
    }
}

struct PolicyReads {
    binding: PolicyBinding,
    trees: PolicyTrees,
    key_registry_root: Option<[u8; 32]>,
}

/// The auditor message of a transaction: `eph_pk(33) || ciphertext(32)` split out
/// of the published message data.
struct AuditorMessageParts<'a> {
    eph_pk: &'a [u8; VIEWING_PUBKEY_LEN],
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
    shape: DisclosureShape,
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

    let field_count = shape
        .field_count()
        .ok_or(CustomRingError::InvalidAuditorMessage)?;
    let (eph_pk, body) = last
        .data
        .split_at_checked(VIEWING_PUBKEY_LEN)
        .ok_or(CustomRingError::InvalidAuditorMessage)?;
    let eph_pk: &[u8; VIEWING_PUBKEY_LEN] = eph_pk
        .try_into()
        .ok()
        .filter(|key: &&[u8; VIEWING_PUBKEY_LEN]| key[0] == VIEWING_PUBKEY_TAG)
        .ok_or(CustomRingError::InvalidAuditorMessage)?;
    let (ciphertext, disclosure) = body
        .split_at_checked(AUDIT_CIPHERTEXT_LEN)
        .filter(|(_, disclosure)| disclosure.len() == 32 * field_count)
        .ok_or(CustomRingError::InvalidAuditorMessage)?;
    let ciphertext: &[u8; AUDIT_CIPHERTEXT_LEN] = ciphertext
        .try_into()
        .map_err(|_| CustomRingError::InvalidAuditorMessage)?;
    let disclosure: &[[u8; 32]] =
        bytemuck::try_cast_slice(disclosure).map_err(|_| CustomRingError::InvalidAuditorMessage)?;
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
    let Some((key, ciphertext)) = body.split_at_checked(VIEWING_PUBKEY_LEN) else {
        return false;
    };
    matches!(key.first(), Some(2 | 3)) && !ciphertext.is_empty()
}

/// The payer is the only signer SPP sees, and no output names its owner.
fn check_anonymous_settlement(
    payer: &AccountView,
    transact: &TransactIxData,
    spp_accounts: &[AccountView],
) -> ProgramResult {
    let (spp_payer, rest) = spp_accounts
        .split_first()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    if spp_payer.address() != payer.address()
        || rest
            .iter()
            .any(|account| account.is_signer() && account.address() != payer.address())
    {
        return Err(CustomRingError::InvalidAnonymousSigner.into());
    }
    if transact
        .outputs
        .iter()
        .any(|output| output.owner_tag != OwnerTag::Inline([0; 32]))
    {
        return Err(CustomRingError::InvalidAnonymousOutput.into());
    }
    Ok(())
}

/// Outside the windowed statement no message may claim the namespace or its
/// record tag, which a recovery would otherwise try to open.
#[inline(never)]
fn refuse_record_messages(
    program_id: &Address,
    namespace_bump: u8,
    messages: &[MessageData],
) -> ProgramResult {
    let namespace = namespace_address(program_id, namespace_bump)?;
    let record_tag = spend_record_message_tag(namespace.as_array())
        .map_err(|_| CustomRingError::HashingFailed)?;
    if messages
        .iter()
        .any(|message| &message.view_tag == namespace.as_array() || message.view_tag == record_tag)
    {
        return Err(CustomRingError::UnexpectedRecordMessage.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use custom_ring_interface::AUDITOR_MESSAGE_PREFIX_LEN;
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
    const EPH_PK: &str = "048ea960e4e1b72cdec9a6e7d86ae28cd04edb4b5c07266d3c32d9133c8ebaa966";
    const AUDITOR_PK: &str = "04708c2645c705baaf44f2ab947574174f9280df58be6fc2f6f2e8881b78a3115a";
    const CIPHERTEXT: &str = "02417a38002f02b2af3e7b938032a1d317e6350831c55a9d3a91e9520feb2314";
    /// `big.NewInt(0xabcdef)` as a 32-byte big-endian field element, the Go
    /// fixture's `PrivateTxHash`.
    const PRIVATE_TX_HASH: &str =
        "0000000000000000000000000000000000000000000000000000000000abcdef";

    const TX_PK_LO: &str = "000268737cf1d852483220d399b5321261d5e9e90d8214dc62b4f7e4d0fee955";
    const TX_PK_HI: &str = "000000000000000000000000000000000000000000000000000000000000c5d5";
    const CT_HASH: &str = "24d5092cd705b878e0c98d8d3dfb79dc71158dfd32358f532e944423716b9671";
    const PUBLIC_INPUT_HASH: &str =
        "2fa6c0b03c0d8efeefc6286b73de7144ddcb30b9ffacf180d7d2ffcbe4fb1779";

    fn bytes<const N: usize>(hex_str: &str) -> [u8; N] {
        let decoded = hex::decode(hex_str).expect("valid hex");
        <[u8; N]>::try_from(decoded.as_slice()).expect("expected byte length")
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

    const SHAPE: DisclosureShape = DisclosureShape {
        anonymous: false,
        inputs: 2,
        outputs: 2,
    };

    fn message_len(shape: DisclosureShape) -> usize {
        AUDITOR_MESSAGE_PREFIX_LEN + 32 * shape.field_count().expect("disclosed shape")
    }

    fn message(view_tag: [u8; 32], len: usize) -> MessageData {
        let mut data = vec![9u8; len];
        if let Some(tag) = data.first_mut() {
            *tag = VIEWING_PUBKEY_TAG;
        }
        MessageData { view_tag, data }
    }

    fn select_err(messages: &[MessageData], shape: DisclosureShape) -> ProgramError {
        select_auditor_message(messages, &[7u8; 32], shape)
            .err()
            .expect("selection must fail")
    }

    #[test]
    fn auditor_message_selection_enforces_unique_last_message() {
        let tag = [7u8; 32];
        let other = [1u8; 32];
        let len = message_len(SHAPE);

        let valid = vec![message(other, 4), message(tag, len)];
        let parts = select_auditor_message(&valid, &tag, SHAPE).expect("valid selection");
        assert_eq!(
            parts.eph_pk.len() + parts.ciphertext.len() + core::mem::size_of_val(parts.disclosure),
            len
        );

        let missing = ProgramError::Custom(CustomRingError::MissingAuditorMessage as u32);
        let invalid = ProgramError::Custom(CustomRingError::InvalidAuditorMessage as u32);
        assert_eq!(select_err(&[], SHAPE), missing);
        assert_eq!(select_err(&[message(other, len)], SHAPE), missing);
        assert_eq!(
            select_err(&[message(tag, len), message(other, 4)], SHAPE),
            invalid
        );
        assert_eq!(
            select_err(&[message(tag, len), message(tag, len)], SHAPE),
            invalid
        );
        assert_eq!(select_err(&[message(tag, len - 1)], SHAPE), invalid);
        assert_eq!(select_err(&[message(tag, len + 32)], SHAPE), invalid);
        let mut sec1 = message(tag, len);
        sec1.data[0] = 2;
        assert_eq!(select_err(&[sec1], SHAPE), invalid);
    }

    #[test]
    fn disclosure_length_follows_the_ring_mode_and_the_published_slots() {
        let tag = [7u8; 32];
        let anonymous = DisclosureShape {
            anonymous: true,
            ..SHAPE
        };
        let invalid = ProgramError::Custom(CustomRingError::InvalidAuditorMessage as u32);
        assert!(
            select_auditor_message(&[message(tag, message_len(anonymous))], &tag, anonymous)
                .is_ok()
        );
        assert_eq!(
            select_err(&[message(tag, message_len(SHAPE))], anonymous),
            invalid
        );
        assert_eq!(
            select_err(&[message(tag, message_len(anonymous))], SHAPE),
            invalid
        );
        let unsupported = DisclosureShape {
            outputs: 5,
            ..SHAPE
        };
        assert_eq!(
            select_err(&[message(tag, message_len(SHAPE))], unsupported),
            invalid
        );
    }

    #[test]
    fn the_rails_follow_the_ring_mode() {
        let slots = zolana_interface::N_PUBLIC_SLOTS as u8;
        let eddsa = CircuitId::RingEddsa(2, 2, slots);
        let authority = CircuitId::RingAuthority(2, 2, slots);
        let hidden = |n_in, n_out| {
            CircuitId::RingEd25519(
                n_in,
                n_out,
                zolana_interface::N_PUBLIC_SLOTS as u8,
                zolana_interface::verifying_keys::Bsb22Commitment {
                    commitment: [0; 32],
                    commitment_pok: [0; 32],
                },
            )
        };
        for mode in [RingMode::Off, RingMode::Registry] {
            assert!(TransactRail::Member.accepts(eddsa, mode));
            assert!(!TransactRail::Member.accepts(hidden(2, 2), mode));
            assert!(TransactRail::Delegate.accepts(authority, mode));
        }
        let anonymous = RingMode::Anonymous;
        assert!(!TransactRail::Member.accepts(eddsa, anonymous));
        assert!(!TransactRail::Delegate.accepts(authority, anonymous));
        for (n_in, n_out) in [(2, 2), (2, 4), (3, 4), (4, 2)] {
            assert!(TransactRail::Member.accepts(hidden(n_in, n_out), anonymous));
        }
        assert!(!TransactRail::Member.accepts(hidden(1, 2), anonymous));
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
