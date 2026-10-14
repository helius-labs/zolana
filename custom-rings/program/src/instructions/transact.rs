use core::num::NonZeroU64;

use custom_ring_interface::{
    base_verifying_key, compressed_policy_verifying_key, delegate_policy_verifying_key,
    policy_verifying_key, AuditorMessage, CompressedPolicyPublicInput, CustomRingBasePublicInput,
    CustomRingError, CustomRingPolicyPublicInput, CustomRingTransactIxData, FixedWindow, KeyEscrow,
    PolicyConfig, RingProgramConfig, COMPRESSED_P256_KEY_LEN,
};
use groth16_solana::groth16::Groth16Verifyingkey;
use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use zolana_account_checks::AccountIterator;
use zolana_interface::instruction::{
    instruction_data::transact::{
        confidential_encrypted_output_body, ring_confidential_encrypted_output_body, OwnerTag,
        TransactOutput,
    },
    tag, CircuitId, MessageData,
};
use zolana_ring_policy::{ring_id_field, ListNamespace, SpendRecord, VelocityMode};

use crate::{
    instructions::{
        cosign::{approval_cosigner, demanded_cosigner},
        loader::{load, load_escrow_root, load_spp_tree_id, validate_spp_program},
        policy_trees::{PolicyTrees, RevocationTargets},
        public_legs::PublicLegs,
        shared::{cpi_spp, namespace_address, parse, SppSigners},
        verifier::verify_groth16,
    },
    state::is_p256_key,
};

#[inline(never)]
pub fn process_transact_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let mut iter = AccountIterator::new(accounts);
    iter.next_signer_mut("payer")?;
    let controls = Controls::next(&mut iter)?;
    Rail::Member.verify_and_forward(program_id, controls, iter, data)
}

/// The ring config and the co-signer slots every forwarded instruction leads with.
pub(crate) struct Controls<'a> {
    pub config: &'a AccountView,
    pub cosigner_pda: &'a AccountView,
    pub cosigner: &'a AccountView,
}

impl<'a> Controls<'a> {
    pub fn next(iter: &mut AccountIterator<'a>) -> Result<Self, ProgramError> {
        Ok(Self {
            config: iter.next_account("config")?,
            cosigner_pda: iter.next_account("cosigner_pda")?,
            cosigner: iter.next_account("cosigner")?,
        })
    }
}

/// Member ownership authorization or the configured delegate's signature.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rail {
    Member,
    /// Owner signatures are replaced by the delegate's, value never leaves.
    Delegate,
}

impl Rail {
    /// `rest` holds the policy accounts, the window slots and the SPP list.
    pub fn verify_and_forward(
        self,
        program_id: &Address,
        controls: Controls<'_>,
        mut rest: AccountIterator<'_>,
        data: &[u8],
    ) -> ProgramResult {
        // 1. Decode the statement and refuse public settlement on the delegate rail.
        let decoded: Box<CustomRingTransactIxData> = parse(data)?;
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
            _ => return Err(CustomRingError::InvalidInstructionData.into()),
        };
        if self == Rail::Delegate && !transact.interface_transfers.is_empty() {
            return Err(CustomRingError::DelegatePublicLeg.into());
        }
        let revocations = RevocationTargets {
            targets: revocation_targets,
            tree_indexes: revocation_tree_indexes,
        };

        // 2. Select the statement from ring state, read the policy trees and the escrow registry.
        let config = *load::<RingProgramConfig>(program_id, controls.config)?;
        let policy = if config.has_policy != 0 {
            let binding = PolicyBinding::load(program_id, rest.next_account("policy_config")?)?;
            let trees = PolicyTrees::load(&mut rest, policy_trees)?;
            let escrow = config.key_escrow();
            if self == Rail::Delegate && escrow != KeyEscrow::Registry {
                return Err(CustomRingError::InvalidKeyRegistryRoot.into());
            }
            let key_registry_root =
                load_escrow_root(program_id, escrow, *key_registry_root_index, &mut rest)?;
            Some((binding, trees, key_registry_root))
        } else {
            if self == Rail::Delegate {
                return Err(CustomRingError::DelegateRequiresPolicy.into());
            }
            if !policy_trees.is_empty() {
                return Err(CustomRingError::InvalidPolicyTrees.into());
            }
            if *key_registry_root_index != 0 {
                return Err(CustomRingError::InvalidInstructionData.into());
            }
            None
        };
        let velocity = policy
            .as_ref()
            .map_or(VelocityMode::Off, |(binding, ..)| binding.velocity);
        let amount_controls = self == Rail::Member && velocity != VelocityMode::Off;
        if approval_required && !amount_controls {
            return Err(CustomRingError::InvalidInstructionData.into());
        }
        let namespace = policy
            .as_ref()
            .map(|(binding, ..)| namespace_address(program_id, binding.namespace_bump));
        let counters = match (self, velocity, namespace) {
            (Rail::Member, VelocityMode::PerWindow { .. }, Some(namespace)) => {
                Some(counters_disclosure_hash(
                    namespace.as_array(),
                    &transact.tx_viewing_pk,
                    &transact.salt,
                    &transact.messages,
                )?)
            }
            _ => None,
        };
        match &policy {
            Some((_, trees, _)) => revocations.verify(trees, &mut rest)?,
            None => revocations.require_empty()?,
        }

        // 3. Enforce approval and public mint caps against the actual settlement legs.
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
        let legs = PublicLegs::from_transact(&transact.interface_transfers, settlements)?;
        let demanded = if approval_required {
            Some(approval_cosigner(program_id, controls.cosigner_pda)?)
        } else {
            demanded_cosigner(program_id, controls.cosigner_pda, legs.classes(), &legs)?
        };
        if let Some(expected) = demanded {
            if !controls.cosigner.is_signer() {
                return Err(CustomRingError::MissingCoSigner.into());
            }
            if controls.cosigner.address() != &expected {
                return Err(CustomRingError::UnauthorizedCoSigner.into());
            }
        }
        if amount_controls && legs.has_deposits() {
            return Err(CustomRingError::VelocityDepositLeg.into());
        }
        legs.apply_windows(program_id, windows)?;

        // 4. Bind auditor disclosure to the SPP statement and its unique audit message.
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
        let message = select_auditor_message(&transact.messages, &config.auditor_pubkey)?;
        let output_hashes: Vec<[u8; 32]> = transact
            .outputs
            .iter()
            .map(|output| output.utxo_hash)
            .collect();
        let audit = CustomRingBasePublicInput {
            private_tx_hash: &transact.private_tx_hash,
            tx_viewing_pk: &transact.tx_viewing_pk,
            auditor_pk: &config.auditor_pubkey,
            eph_pk: &message.eph_pk,
            ciphertext: &message.ciphertext,
            output_hashes: &output_hashes,
            salt: &transact.salt,
            disclosure: &message.disclosure,
        };

        // 5. Verify the statement and the spend record before granting the namespace signature.
        let (public_input, verifying_key, signers) = match (policy, namespace) {
            (Some((binding, trees, key_registry_root)), Some(namespace)) => {
                let signers = match counters {
                    Some(_) => {
                        let record = transact
                            .outputs
                            .last()
                            .ok_or(CustomRingError::InvalidSpendRecord)?;
                        let output_tree = spp_accounts
                            .get(1)
                            .ok_or(ProgramError::NotEnoughAccountKeys)?;
                        verify_spend_record(
                            &namespace,
                            &binding,
                            record,
                            &transact.messages,
                            load_spp_tree_id(output_tree, CustomRingError::InvalidSpendRecord)?,
                        )?;
                        SppSigners::RingAuthAndNamespace {
                            bump: binding.namespace_bump,
                        }
                    }
                    None => SppSigners::RingAuth,
                };
                let window_index = match (self, binding.velocity) {
                    (Rail::Member, VelocityMode::PerWindow { window_slots }) => FixedWindow {
                        slots: NonZeroU64::new(window_slots)
                            .ok_or(CustomRingError::InvalidPolicyRules)?,
                    }
                    .index(Clock::get()?.slot),
                    _ => 0,
                };
                let ring_id =
                    ring_id_field(program_id.as_array()).map_err(CustomRingError::from)?;
                let input = CustomRingPolicyPublicInput {
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
                let (public_input, verifying_key) = self.policy_statement(input, counters)?;
                (public_input, verifying_key, signers)
            }
            _ => (
                audit.hash().map_err(CustomRingError::from)?,
                &base_verifying_key::VERIFYINGKEY,
                SppSigners::RingAuth,
            ),
        };
        verify_groth16(proof, public_input, verifying_key)?;

        // 6. Settle through SPP, a failure rolls the window counters back.
        let mut instruction_data = vec![self.spp_tag()];
        instruction_data.extend_from_slice(
            &transact
                .serialize()
                .map_err(|_| CustomRingError::InvalidInstructionData)?,
        );
        cpi_spp(program_id, spp_accounts, &instruction_data, signers)
    }

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

    /// Kept out of line, the policy chains exceed the caller's SBF stack frame.
    #[inline(never)]
    fn policy_statement(
        self,
        input: CustomRingPolicyPublicInput<'_>,
        counters: Option<[u8; 32]>,
    ) -> Result<([u8; 32], &'static Groth16Verifyingkey<'static>), CustomRingError> {
        Ok(match (self, counters) {
            (Rail::Delegate, _) => (input.hash()?, &delegate_policy_verifying_key::VERIFYINGKEY),
            (Rail::Member, None) => (input.hash()?, &policy_verifying_key::VERIFYINGKEY),
            (Rail::Member, Some(counters_disclosure_hash)) => (
                CompressedPolicyPublicInput {
                    policy: input,
                    counters_disclosure_hash: &counters_disclosure_hash,
                }
                .hash()?,
                &compressed_policy_verifying_key::VERIFYINGKEY,
            ),
        })
    }
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
        let policy = load::<PolicyConfig>(program_id, account)?;
        Ok(Self {
            policy_hash: policy.policy_hash,
            address_tree_id: policy.address_tree_id(),
            namespace_owner_hash: policy.namespace_owner_hash,
            namespace_bump: policy.namespace_bump,
            velocity: policy.rules.velocity_mode(),
        })
    }
}

/// The last output is the namespace-owned successor record its one public
/// message opens, before the namespace signs.
#[inline(never)]
fn verify_spend_record(
    namespace: &Address,
    binding: &PolicyBinding,
    output: &TransactOutput,
    messages: &[MessageData],
    tree_id: u16,
) -> Result<(), CustomRingError> {
    if output.owner_tag != OwnerTag::Inline(namespace.to_bytes())
        || output
            .data
            .as_deref()
            .and_then(confidential_encrypted_output_body)
            .is_none()
    {
        return Err(CustomRingError::InvalidSpendRecord);
    }
    SpendRecord::open_carrier(
        namespace.as_array(),
        &ListNamespace {
            owner_hash: binding.namespace_owner_hash,
        },
        binding.address_tree_id,
        messages
            .iter()
            .map(|message| (&message.view_tag, message.data.as_slice())),
        &output.utxo_hash,
        tree_id,
    )?;
    Ok(())
}

/// Exactly one message carries the auditor's view tag and it is the last, so no
/// second ciphertext can claim the tag beside the one the proof covers.
fn select_auditor_message<'a>(
    messages: &'a [MessageData],
    auditor_pubkey: &[u8; COMPRESSED_P256_KEY_LEN],
) -> Result<&'a AuditorMessage, CustomRingError> {
    let view_tag = &auditor_pubkey[1..];
    let (last, earlier) = messages
        .split_last()
        .ok_or(CustomRingError::MissingAuditorMessage)?;
    let tagged_earlier = earlier.iter().any(|message| message.view_tag == view_tag);
    match (last.view_tag == view_tag, tagged_earlier) {
        (true, false) => {
            bytemuck::try_from_bytes(&last.data).map_err(|_| CustomRingError::InvalidAuditorMessage)
        }
        (false, false) => Err(CustomRingError::MissingAuditorMessage),
        _ => Err(CustomRingError::InvalidAuditorMessage),
    }
}

fn is_valid_confidential_output(data: &[u8]) -> bool {
    confidential_encrypted_output_body(data)
        .or_else(|| ring_confidential_encrypted_output_body(data))
        .and_then(|body| body.split_first_chunk::<COMPRESSED_P256_KEY_LEN>())
        .is_some_and(|(key, ciphertext)| is_p256_key(key) && !ciphertext.is_empty())
}

/// The one namespace-tagged body, opened for the transaction key, that the
/// compressed statement hashes.
fn counters_disclosure_hash(
    namespace: &[u8; 32],
    tx_viewing_pk: &[u8; COMPRESSED_P256_KEY_LEN],
    salt: &[u8; 16],
    messages: &[MessageData],
) -> Result<[u8; 32], CustomRingError> {
    let invalid = CustomRingError::InvalidSpendCountersDisclosure;
    let mut tagged = messages
        .iter()
        .filter(|message| &message.view_tag == namespace);
    let message = tagged.next().ok_or(invalid)?;
    if tagged.next().is_some() || !message.data.starts_with(tx_viewing_pk) {
        return Err(invalid);
    }
    let body = message.data.as_slice().try_into().map_err(|_| invalid)?;
    Ok(zolana_ring_policy::spend_counters_disclosure_hash(
        salt, body,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use custom_ring_interface::{pack33_to_2fe, AUDITOR_MESSAGE_LEN, AUDIT_DISCLOSURE_FIELD_COUNT};
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

    fn select_err(messages: &[MessageData]) -> CustomRingError {
        select_auditor_message(messages, &bytes::<33>(AUDITOR_PK)).expect_err("selection must fail")
    }

    #[test]
    fn auditor_message_selection_enforces_unique_last_message() {
        let tag = auditor_view_tag();
        let other = [1u8; 32];

        let valid = vec![message(other, 4), message(tag, AUDITOR_MESSAGE_LEN)];
        let parts =
            select_auditor_message(&valid, &bytes::<33>(AUDITOR_PK)).expect("valid selection");
        assert_eq!(bytemuck::bytes_of(parts), valid[1].data.as_slice());

        let missing = CustomRingError::MissingAuditorMessage;
        let invalid = CustomRingError::InvalidAuditorMessage;
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
            counters_disclosure_hash(&namespace, &public, &salt, messages)
        };
        assert!(hash(std::slice::from_ref(&message)).is_ok());
        let refused = Err(CustomRingError::InvalidSpendCountersDisclosure);
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
