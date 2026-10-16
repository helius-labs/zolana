use custom_ring_interface::{
    base_verifying_key, delegate_policy_verifying_key, policy_verifying_key, AuditorMessage,
    CustomRingBasePublicInput, CustomRingError, CustomRingPolicyPublicInput,
    CustomRingTransactIxData, KeyEscrow, PolicyConfig, RingProgramConfig, TAGGED_X25519_KEY_LEN,
};
use groth16_solana::groth16::Groth16Verifyingkey;
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_interface::instruction::{
    instruction_data::transact::{
        confidential_encrypted_output_body, ring_confidential_encrypted_output_body,
    },
    tag, CircuitId, MessageData,
};
use zolana_ring_policy::ring_id_field;

use crate::{
    instructions::{
        cosign::{approval_cosigner, demanded_cosigner},
        loader::{load, load_escrow_root, validate_spp_program},
        policy_trees::{PolicyTrees, RevocationTargets},
        public_legs::PublicLegs,
        shared::{cpi_spp, parse, SppSigners},
        verifier::verify_groth16,
    },
    state::is_x25519_viewing_key,
};

#[inline(never)]
pub fn process_transact_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let mut iter = AccountIterator::new(accounts);
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
    /// `rest` holds the policy accounts, then the SPP list.
    pub fn verify_and_forward(
        self,
        program_id: &Address,
        controls: Controls<'_>,
        mut rest: AccountIterator<'_>,
        data: &[u8],
    ) -> ProgramResult {
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
        let approval_required = *approval_required;
        if self == Rail::Delegate && !transact.interface_transfers.is_empty() {
            return Err(CustomRingError::DelegatePublicLeg.into());
        }
        let revocations = RevocationTargets {
            targets: revocation_targets,
            tree_indexes: revocation_tree_indexes,
        };

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
                return Err(CustomRingError::UnexpectedKeyRegistryRoot.into());
            }
            None
        };
        // The delegate rail proves approval off, its statement never demands the co-signer.
        let limited = self == Rail::Member
            && policy
                .as_ref()
                .is_some_and(|(binding, ..)| binding.has_limits);
        if approval_required && !limited {
            return Err(CustomRingError::UnexpectedApproval.into());
        }
        match &policy {
            Some((_, trees, _)) => revocations.verify(trees, &mut rest)?,
            None => revocations.require_empty()?,
        }

        let spp_accounts = rest.remaining_mut()?;
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
            .ok_or(CustomRingError::InvalidSettlementAccounts)?;
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

        let (public_input, verifying_key) = match policy {
            Some((binding, trees, key_registry_root)) => {
                let ring_id =
                    ring_id_field(program_id.as_array()).map_err(CustomRingError::from)?;
                let input = CustomRingPolicyPublicInput {
                    audit,
                    policy_hash: &binding.policy_hash,
                    tree_slots: trees.slots(),
                    address_tree_id: binding.address_tree_id,
                    ring_id: &ring_id,
                    namespace_owner_hash: &binding.namespace_owner_hash,
                    approval_required,
                    key_registry_root: key_registry_root.as_ref(),
                    revocation_tree_indexes,
                    revocation_targets,
                };
                self.policy_statement(input)?
            }
            None => (
                audit.hash().map_err(CustomRingError::from)?,
                &base_verifying_key::VERIFYINGKEY,
            ),
        };
        verify_groth16(proof, public_input, verifying_key)?;

        let mut instruction_data = vec![self.spp_tag()];
        instruction_data.extend_from_slice(
            &transact
                .serialize()
                .map_err(|_| CustomRingError::InvalidInstructionData)?,
        );
        cpi_spp(
            program_id,
            spp_accounts,
            &instruction_data,
            SppSigners::RingAuth,
        )
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

    /// Kept out of line, the policy chain exceeds the caller's SBF stack frame.
    #[inline(never)]
    fn policy_statement(
        self,
        input: CustomRingPolicyPublicInput<'_>,
    ) -> Result<([u8; 32], &'static Groth16Verifyingkey<'static>), CustomRingError> {
        let verifying_key = match self {
            Rail::Delegate => &delegate_policy_verifying_key::VERIFYINGKEY,
            Rail::Member => &policy_verifying_key::VERIFYINGKEY,
        };
        Ok((input.hash()?, verifying_key))
    }
}

/// Copied out, no account borrow may live across the SPP CPI.
struct PolicyBinding {
    policy_hash: [u8; 32],
    address_tree_id: u16,
    namespace_owner_hash: [u8; 32],
    has_limits: bool,
}

impl PolicyBinding {
    #[inline(never)]
    fn load(program_id: &Address, account: &AccountView) -> Result<Self, ProgramError> {
        let policy = load::<PolicyConfig>(program_id, account)?;
        Ok(Self {
            policy_hash: policy.policy_hash,
            address_tree_id: policy.address_tree_id(),
            namespace_owner_hash: policy.namespace_owner_hash,
            has_limits: policy.rules.has_limits(),
        })
    }
}

/// Exactly one message carries the auditor's view tag and it is the last, so no
/// second ciphertext can claim the tag beside the one the proof covers.
fn select_auditor_message<'a>(
    messages: &'a [MessageData],
    auditor_pubkey: &[u8; TAGGED_X25519_KEY_LEN],
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
        .and_then(|body| body.split_first_chunk::<TAGGED_X25519_KEY_LEN>())
        .is_some_and(|(key, ciphertext)| is_x25519_viewing_key(key) && !ciphertext.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use custom_ring_interface::{pack_2fe, AUDITOR_MESSAGE_LEN, AUDIT_DISCLOSURE_FIELD_COUNT};
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
    const TX_PK: &str = "043632fe89228ea5215eea45a56704f569e3929868a8573363d015e39609f0eb63";
    const EPH_PK: &str = "048ea960e4e1b72cdec9a6e7d86ae28cd04edb4b5c07266d3c32d9133c8ebaa966";
    const AUDITOR_PK: &str = "04708c2645c705baaf44f2ab947574174f9280df58be6fc2f6f2e8881b78a3115a";
    const CIPHERTEXT: &str = "03417a38002f02b2af3e7b938032a1d317e6350831c55a9d3a91e9520feb2354";
    /// `big.NewInt(0xabcdef)` as a 32-byte big-endian field element, the Go
    /// fixture's `PrivateTxHash`.
    const PRIVATE_TX_HASH: &str =
        "0000000000000000000000000000000000000000000000000000000000abcdef";

    const TX_PK_LO: &str = "00043632fe89228ea5215eea45a56704f569e3929868a8573363d015e39609f0";
    const TX_PK_HI: &str = "000000000000000000000000000000000000000000000000000000000000eb63";
    const CT_HASH: &str = "1ceeed7a0df2acee11de3ba05f2c9e205cabd3adb067a1eaa9b6bc67149409f8";
    const PUBLIC_INPUT_HASH: &str =
        "1569b2c4bb38c6768a2b8f8ba7ee18c0c30ab441fb6b3edddc08a15c01b130e8";

    fn bytes<const N: usize>(hex_str: &str) -> [u8; N] {
        let decoded = hex::decode(hex_str).expect("valid hex");
        <[u8; N]>::try_from(decoded.as_slice()).expect("expected byte length")
    }

    #[test]
    fn pack_2fe_matches_go_for_33_bytes() {
        assert_eq!(
            pack_2fe(&bytes::<33>(TX_PK)),
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
