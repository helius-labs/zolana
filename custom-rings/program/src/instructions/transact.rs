use custom_ring_interface::{
    base_anonymous_wide_verifying_key, base_confidential_compact_verifying_key,
    base_confidential_verifying_key, base_verifying_key, delegate_policy_2x3_verifying_key,
    delegate_policy_verifying_key, policy_2x3_anonymous_verifying_key, policy_2x3_verifying_key,
    policy_verifying_key, AuditorMessage, CustomRingBasePublicInput, CustomRingError,
    CustomRingPolicyPublicInput, CustomRingProof, CustomRingTransactIxData, DisclosureShape,
    PolicyConfig, PolicyProofKind, RingMode, N_FOREIGN, TAGGED_X25519_KEY_LEN,
};
use groth16_solana::groth16::Groth16Verifyingkey;
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_interface::instruction::{
    instruction_data::transact::{
        confidential_encrypted_output_body, ring_anonymous_encrypted_output_body,
        ring_confidential_encrypted_output_body, OwnerTag,
    },
    tag, CircuitId, MessageData, TransactIxData,
};
use zolana_interface::TRANSACT_ACCOUNT_PREFIX_LEN;
use zolana_ring_policy::ring_id_field;

use crate::{
    instructions::{
        cosign::{approval_cosigner, demanded_cosigner},
        loader::{
            load, load_audited_config, load_curator_root, load_registry_root, validate_spp_program,
            AuditedConfig,
        },
        policy_trees::PolicyTrees,
        public_legs::PublicLegs,
        shared::{cpi_spp, parse},
        verifier::{verify_groth16, verify_groth16_inputs},
    },
    state::is_x25519_viewing_key,
};

#[inline(never)]
pub fn process_transact_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
    kind: PolicyProofKind,
) -> ProgramResult {
    let mut iter = AccountIterator::new(accounts);
    let controls = Controls::next(&mut iter)?;
    Rail::Member.verify_and_forward(program_id, controls, iter, data, kind)
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
    /// Authorize the caller, verify auditor disclosure and policy against the
    /// program's current accounts, then let SPP settle the same transaction.
    /// `rest` holds the policy accounts, then the SPP list.
    pub fn verify_and_forward(
        self,
        program_id: &Address,
        controls: Controls<'_>,
        mut rest: AccountIterator<'_>,
        data: &[u8],
        kind: PolicyProofKind,
    ) -> ProgramResult {
        let decoded: Box<CustomRingTransactIxData> = parse(data)?;
        let transact = &decoded.transact;
        let approval_required = decoded.approval_required;
        if self == Rail::Delegate && !transact.interface_transfers.is_empty() {
            return Err(CustomRingError::DelegatePublicLeg.into());
        }

        let config = load_audited_config(program_id, controls.config)?;
        if kind == PolicyProofKind::TwoByThree
            && (!config.has_policy || transact.inputs.len() != 2 || transact.outputs.len() != 3)
        {
            return Err(CustomRingError::UnsupportedCircuit.into());
        }
        if kind.shaped()
            && (!config.has_policy
                || !transact.circuit.is_supported()
                || transact.outputs.is_empty()
                || transact.inputs.len() > usize::from(transact.circuit.num_inputs())
                || transact.outputs.len() > usize::from(transact.circuit.num_outputs()))
        {
            return Err(CustomRingError::UnsupportedCircuit.into());
        }
        let policy = PolicyContext::load(program_id, self, &config, &mut rest, &decoded, kind)?;
        // The delegate rail proves approval off, its statement never demands the co-signer.
        let limited = self == Rail::Member
            && policy
                .as_ref()
                .is_some_and(|policy| policy.binding.has_limits);
        if approval_required && !limited {
            return Err(CustomRingError::UnexpectedApproval.into());
        }

        let spp_accounts = rest.remaining_mut()?;
        let legs = self.authorize_accounts(config.mode, transact, spp_accounts)?;
        Self::authorize_cosigner(program_id, controls, approval_required, &legs)?;

        RingStatement {
            rail: self,
            program_id,
            config: &config,
            kind,
            proof: &decoded.proof,
            transact,
            policy,
            approval_required,
        }
        .verify()?;

        self.forward_spp(program_id, spp_accounts, transact)
    }

    /// Check the original instruction's signer bits before the ring PDA signs
    /// its SPP CPI. Keep this processor stage out of line for SBF stack space.
    #[inline(never)]
    fn authorize_accounts<'a>(
        self,
        mode: RingMode,
        transact: &TransactIxData,
        spp_accounts: &'a [AccountView],
    ) -> Result<PublicLegs<'a>, ProgramError> {
        let spp = SppTransactAccounts::split(transact, spp_accounts)?;
        if !spp.payer.is_signer() {
            return Err(CustomRingError::MissingFundingSigner.into());
        }
        if mode == RingMode::Anonymous {
            if spp_accounts[1..]
                .iter()
                .any(|account| account.is_signer() && account.address() != spp.payer.address())
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
        }
        if self == Rail::Member && spp.owners.iter().any(|account| !account.is_signer()) {
            return Err(CustomRingError::MissingOwnerSigner.into());
        }
        let mut settlement_offset = 0usize;
        for leg in &transact.interface_transfers {
            let width = leg.settlement_account_count();
            let end = settlement_offset
                .checked_add(width)
                .ok_or(CustomRingError::InvalidSettlementAccounts)?;
            let group = spp
                .settlements
                .get(settlement_offset..end)
                .ok_or(CustomRingError::InvalidSettlementAccounts)?;
            let funder_index = match leg {
                zolana_interface::instruction::instruction_data::transact::InterfaceTransfer::SolDeposit { .. } => Some(1),
                zolana_interface::instruction::instruction_data::transact::InterfaceTransfer::SplDeposit { .. } => Some(2),
                _ => None,
            };
            if let Some(index) = funder_index {
                let funder = group.get(index).ok_or(ProgramError::NotEnoughAccountKeys)?;
                if !funder.is_signer() {
                    return Err(CustomRingError::MissingFundingSigner.into());
                }
            }
            settlement_offset = end;
        }
        PublicLegs::from_transact(&transact.interface_transfers, spp.settlements)
    }

    #[inline(never)]
    fn authorize_cosigner(
        program_id: &Address,
        controls: Controls<'_>,
        approval_required: bool,
        legs: &PublicLegs<'_>,
    ) -> ProgramResult {
        let demanded = if approval_required {
            Some(approval_cosigner(program_id, controls.cosigner_pda)?)
        } else {
            demanded_cosigner(program_id, controls.cosigner_pda, legs.classes(), legs)?
        };
        if let Some(expected) = demanded {
            if !controls.cosigner.is_signer() {
                return Err(CustomRingError::MissingCoSigner.into());
            }
            if controls.cosigner.address() != &expected {
                return Err(CustomRingError::UnauthorizedCoSigner.into());
            }
        }
        Ok(())
    }

    #[inline(never)]
    fn forward_spp(
        self,
        program_id: &Address,
        spp_accounts: &[AccountView],
        transact: &TransactIxData,
    ) -> ProgramResult {
        let mut instruction_data = vec![self.spp_tag()];
        instruction_data.extend_from_slice(
            &transact
                .serialize()
                .map_err(|_| CustomRingError::InvalidInstructionData)?,
        );
        cpi_spp(program_id, spp_accounts, &instruction_data)
    }

    /// An anonymous ring admits only the hidden-owner rail.
    fn accepts(self, circuit: CircuitId, mode: RingMode) -> bool {
        match (self, mode) {
            (Self::Member, RingMode::Anonymous) => {
                matches!(circuit, CircuitId::AnonymousRingEd25519(..)) && circuit.is_supported()
            }
            (Self::Member, _) => matches!(circuit, CircuitId::ConfidentialRingEd25519(..)),
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

/// Proof inputs assembled only from the decoded SPP transaction and loaded
/// ring accounts. Keeping this out of the processor limits the SBF stack frame.
struct RingStatement<'a> {
    rail: Rail,
    program_id: &'a Address,
    config: &'a AuditedConfig,
    kind: PolicyProofKind,
    proof: &'a CustomRingProof,
    transact: &'a TransactIxData,
    policy: Option<PolicyContext>,
    approval_required: bool,
}

impl RingStatement<'_> {
    /// The base proof opens the auditor ciphertext and ties disclosed notes to
    /// `private_tx_hash` and the output commitments in the SPP transaction.
    /// A policy proof extends that statement with the stored rule table and
    /// authenticated member registry roots. Recipient delivery ciphertext is
    /// outside this proof obligation.
    #[inline(never)]
    fn verify(self) -> ProgramResult {
        let anonymous = self.config.mode == RingMode::Anonymous;
        if !self.rail.accepts(self.transact.circuit, self.config.mode) {
            return Err(CustomRingError::UnsupportedCircuit.into());
        }
        if self.transact.outputs.iter().any(|output| {
            !output
                .data
                .as_deref()
                .is_some_and(|data| is_valid_confidential_output(data, anonymous))
        }) {
            return Err(CustomRingError::UnsupportedOutputScheme.into());
        }
        let message = select_auditor_message(
            &self.transact.messages,
            &self.config.auditor_pubkey,
            DisclosureShape {
                anonymous,
                inputs: self.transact.inputs.len(),
                outputs: self.transact.outputs.len(),
            },
        )?;
        let output_hashes: Vec<[u8; 32]> = self
            .transact
            .outputs
            .iter()
            .map(|output| output.utxo_hash)
            .collect();
        let audit = CustomRingBasePublicInput {
            private_tx_hash: &self.transact.private_tx_hash,
            tx_viewing_pk: &self.transact.tx_viewing_pk,
            auditor_pk: &self.config.auditor_pubkey,
            eph_pk: message.eph_pk,
            ciphertext: message.ciphertext,
            output_hashes: &output_hashes,
            salt: &self.transact.salt,
            disclosure: message.disclosure,
            anonymous,
        };
        match self.policy.as_ref() {
            Some(policy) => self.verify_policy(audit, policy),
            None => verify_groth16(
                self.proof,
                audit.hash().map_err(CustomRingError::from)?,
                if anonymous && self.transact.inputs.len() > 4 {
                    &base_anonymous_wide_verifying_key::VERIFYINGKEY
                } else if anonymous || self.transact.outputs.len() != 2 {
                    &base_verifying_key::VERIFYINGKEY
                } else if self.transact.inputs.len() > 16 {
                    &base_confidential_compact_verifying_key::VERIFYINGKEY
                } else {
                    &base_confidential_verifying_key::VERIFYINGKEY
                },
            ),
        }
    }

    /// Choose the key for the declared rail and shape. Rules come from this
    /// program's policy account. Registry roots come from authenticated chain
    /// accounts pinned by that policy, never prover-supplied values.
    #[inline(never)]
    fn verify_policy(
        &self,
        audit: CustomRingBasePublicInput<'_>,
        policy: &PolicyContext,
    ) -> ProgramResult {
        let ring_id = ring_id_field(self.program_id.as_array()).map_err(CustomRingError::from)?;
        let PolicyContext {
            binding,
            trees,
            roots,
        } = policy;
        let input = CustomRingPolicyPublicInput {
            audit,
            policy_hash: &binding.policy_hash,
            tree_slots: trees.slots(),
            address_tree_id: binding.address_tree_id,
            ring_id: &ring_id,
            namespace_owner_hash: &binding.namespace_owner_hash,
            approval_required: self.approval_required,
            key_escrow: self.config.mode == RingMode::Registry,
            member_registry_root: &roots.own,
            foreign_root: &roots.foreign,
        };
        if let Some(table) = binding.table.as_ref() {
            let tree_hash =
                zolana_interface::tree_slot::populated_tree_slots_hash_chain(trees.slots())
                    .map_err(CustomRingError::from)?;
            let inputs = table
                .public_table_inputs(input.hash().map_err(CustomRingError::from)?, tree_hash)?;
            let key = if self.kind.shaped() {
                custom_ring_interface::shaped_verifying_keys::policy_shape_key(
                    usize::from(self.transact.circuit.num_inputs()),
                    usize::from(self.transact.circuit.num_outputs()),
                    self.config.mode == RingMode::Anonymous,
                    self.rail == Rail::Delegate,
                    self.kind == PolicyProofKind::Subtree,
                )
                .ok_or(CustomRingError::UnsupportedCircuit)?
            } else {
                match (self.rail, self.config.mode == RingMode::Anonymous) {
                    (Rail::Delegate, _) => &delegate_policy_2x3_verifying_key::VERIFYINGKEY,
                    (Rail::Member, true) => &policy_2x3_anonymous_verifying_key::VERIFYINGKEY,
                    (Rail::Member, false) => &policy_2x3_verifying_key::VERIFYINGKEY,
                }
            };
            verify_groth16_inputs(self.proof, &inputs, key)
        } else {
            let (public_input, key) = self.rail.policy_statement(input)?;
            verify_groth16(self.proof, public_input, key)
        }
    }
}

/// Structural slices of SPP accounts. The processor checks every signer bit.
struct SppTransactAccounts<'a> {
    payer: &'a AccountView,
    owners: &'a [AccountView],
    settlements: &'a [AccountView],
}

impl<'a> SppTransactAccounts<'a> {
    fn split(transact: &TransactIxData, accounts: &'a [AccountView]) -> Result<Self, ProgramError> {
        validate_spp_program(accounts)?;
        let payer = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
        let settlement_len: usize = transact
            .interface_transfers
            .iter()
            .map(|leg| leg.settlement_account_count())
            .sum();
        let last = accounts
            .len()
            .checked_sub(settlement_len)
            .ok_or(CustomRingError::InvalidSettlementAccounts)?;
        // SPP reads owners after its fixed prefix, tree and nullifier accounts.
        let first = TRANSACT_ACCOUNT_PREFIX_LEN
            .checked_add(transact.tree_contexts.len())
            .and_then(|count| count.checked_add(transact.inputs.len()))
            .ok_or(CustomRingError::InvalidSettlementAccounts)?;
        Ok(Self {
            payer,
            owners: accounts
                .get(first..last)
                .ok_or(CustomRingError::InvalidSettlementAccounts)?,
            settlements: accounts
                .get(last..)
                .ok_or(CustomRingError::InvalidSettlementAccounts)?,
        })
    }
}

/// Copied out, no account borrow may live across the SPP CPI.
struct PolicyContext {
    binding: PolicyBinding,
    trees: PolicyTrees,
    roots: RegistryRoots,
}

impl PolicyContext {
    #[inline(never)]
    fn load(
        program_id: &Address,
        rail: Rail,
        config: &AuditedConfig,
        rest: &mut AccountIterator<'_>,
        decoded: &CustomRingTransactIxData,
        kind: PolicyProofKind,
    ) -> Result<Option<Self>, ProgramError> {
        if !config.has_policy {
            if rail == Rail::Delegate {
                return Err(CustomRingError::DelegateRequiresPolicy.into());
            }
            if !decoded.policy_trees.is_empty() {
                return Err(CustomRingError::InvalidPolicyTrees.into());
            }
            if decoded.registry_root_index != 0 || decoded.foreign_root_indexes != [0; N_FOREIGN] {
                return Err(CustomRingError::UnexpectedMemberRegistryRoot.into());
            }
            return Ok(None);
        }
        let binding = PolicyBinding::load(program_id, rest.next_account("policy_config")?, kind)?;
        let trees = PolicyTrees::load(rest, &decoded.policy_trees)?;
        if rail == Rail::Delegate && config.mode != RingMode::Registry {
            return Err(if config.mode == RingMode::Anonymous {
                CustomRingError::AnonymousRingRefused
            } else {
                CustomRingError::InvalidMemberRegistryRoot
            }
            .into());
        }
        let roots = RegistryRoots::load(
            program_id,
            rest,
            binding.curator.as_ref(),
            decoded.registry_root_index,
            &decoded.foreign_root_indexes,
        )?;
        Ok(Some(Self {
            binding,
            trees,
            roots,
        }))
    }
}

/// Copied out, no account borrow may live across the SPP CPI.
struct PolicyBinding {
    table: Option<Box<PolicyConfig>>,
    policy_hash: [u8; 32],
    address_tree_id: u16,
    namespace_owner_hash: [u8; 32],
    has_limits: bool,
    /// The curator registry root account the sources pin, `None` for own lists only.
    curator: Option<Address>,
}

impl PolicyBinding {
    #[inline(never)]
    fn load(
        program_id: &Address,
        account: &AccountView,
        kind: PolicyProofKind,
    ) -> Result<Self, ProgramError> {
        let policy = load::<PolicyConfig>(program_id, account)?;
        Ok(Self {
            table: kind.public_table().then(|| Box::new(*policy)),
            policy_hash: policy.policy_hash,
            address_tree_id: policy.address_tree_id(),
            namespace_owner_hash: policy.namespace_owner_hash,
            has_limits: policy.rules.has_limits(),
            curator: policy.curator(),
        })
    }
}

/// The registry roots a policy statement binds, `[member_registry_root, foreign_root?]`.
struct RegistryRoots {
    own: [u8; 32],
    /// Zero without a curator.
    foreign: [u8; 32],
}

impl RegistryRoots {
    #[inline(never)]
    fn load(
        program_id: &Address,
        accounts: &mut AccountIterator<'_>,
        curator: Option<&Address>,
        own_index: u8,
        foreign_indexes: &[u8; N_FOREIGN],
    ) -> Result<Self, ProgramError> {
        let own = load_registry_root(
            program_id,
            accounts.next_account("member_registry_root")?,
            own_index,
        )?;
        let foreign = match curator {
            Some(curator) => load_curator_root(
                accounts.next_account("foreign_root")?,
                curator,
                foreign_indexes[0],
            )?,
            None if *foreign_indexes != [0; N_FOREIGN] => {
                return Err(CustomRingError::UnexpectedMemberRegistryRoot.into())
            }
            None => [0; 32],
        };
        Ok(Self { own, foreign })
    }
}

/// Exactly one message carries the auditor's view tag and it is the last, so no
/// second ciphertext can claim the tag beside the one the proof covers.
fn select_auditor_message<'a>(
    messages: &'a [MessageData],
    auditor_pubkey: &[u8; TAGGED_X25519_KEY_LEN],
    shape: DisclosureShape,
) -> Result<AuditorMessage<'a>, CustomRingError> {
    let view_tag = &auditor_pubkey[1..];
    let (last, earlier) = messages
        .split_last()
        .ok_or(CustomRingError::MissingAuditorMessage)?;
    let tagged_earlier = earlier.iter().any(|message| message.view_tag == view_tag);
    match (last.view_tag == view_tag, tagged_earlier) {
        (true, false) => {
            AuditorMessage::parse(&last.data, shape).ok_or(CustomRingError::InvalidAuditorMessage)
        }
        (false, false) => Err(CustomRingError::MissingAuditorMessage),
        _ => Err(CustomRingError::InvalidAuditorMessage),
    }
}

fn is_valid_confidential_output(data: &[u8], anonymous: bool) -> bool {
    if anonymous {
        return ring_anonymous_encrypted_output_body(data).is_some_and(|body| !body.is_empty());
    }
    confidential_encrypted_output_body(data)
        .or_else(|| ring_confidential_encrypted_output_body(data))
        .and_then(|body| body.split_first_chunk::<TAGGED_X25519_KEY_LEN>())
        .is_some_and(|(key, ciphertext)| is_x25519_viewing_key(key) && !ciphertext.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use custom_ring_interface::{
        pack_2fe, AUDITOR_MESSAGE_PREFIX_LEN, AUDIT_DISCLOSURE_FIELD_COUNT, VIEWING_PUBKEY_TAG,
    };
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
    const CIPHERTEXT: &str = "da94f616e95702bdea89178dd9c4547393ebce9d47e67d0cac1533f13b678b90";
    /// `big.NewInt(0xabcdef)` as a 32-byte big-endian field element, the Go
    /// fixture's `PrivateTxHash`.
    const PRIVATE_TX_HASH: &str =
        "0000000000000000000000000000000000000000000000000000000000abcdef";

    const TX_PK_LO: &str = "00043632fe89228ea5215eea45a56704f569e3929868a8573363d015e39609f0";
    const TX_PK_HI: &str = "000000000000000000000000000000000000000000000000000000000000eb63";
    const CT_HASH: &str = "2ec8fca72d305d1cfc2ea01acb5058150dd251c32da26baa29affbca9f7779d9";
    const PUBLIC_INPUT_HASH: &str =
        "291c6025244409748c719079f396ec892db1764098323df8f3a685ae5d7a3a22";

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
            anonymous: false,
        }
        .hash()
        .expect("public input hash");
        assert_eq!(hash, bytes::<32>(PUBLIC_INPUT_HASH));
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

    fn auditor_view_tag() -> [u8; 32] {
        let key = bytes::<33>(AUDITOR_PK);
        let mut tag = [0u8; 32];
        tag.copy_from_slice(&key[1..33]);
        tag
    }

    fn select_err(messages: &[MessageData], shape: DisclosureShape) -> CustomRingError {
        select_auditor_message(messages, &bytes::<33>(AUDITOR_PK), shape)
            .expect_err("selection must fail")
    }

    #[test]
    fn auditor_message_selection_enforces_unique_last_message() {
        let tag = auditor_view_tag();
        let other = [1u8; 32];
        let len = message_len(SHAPE);

        let valid = vec![message(other, 4), message(tag, len)];
        let parts = select_auditor_message(&valid, &bytes::<33>(AUDITOR_PK), SHAPE)
            .expect("valid selection");
        assert_eq!(
            parts.eph_pk.len() + parts.ciphertext.len() + core::mem::size_of_val(parts.disclosure),
            len
        );

        let missing = CustomRingError::MissingAuditorMessage;
        let invalid = CustomRingError::InvalidAuditorMessage;
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
        let tag = auditor_view_tag();
        let anonymous = DisclosureShape {
            anonymous: true,
            ..SHAPE
        };
        let invalid = CustomRingError::InvalidAuditorMessage;
        assert!(select_auditor_message(
            &[message(tag, message_len(anonymous))],
            &bytes::<33>(AUDITOR_PK),
            anonymous
        )
        .is_ok());
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
        let eddsa = CircuitId::ConfidentialRingEd25519(2, 2, slots);
        let authority = CircuitId::RingAuthority(2, 2, slots);
        let hidden = |n_in, n_out| {
            CircuitId::AnonymousRingEd25519(
                n_in,
                n_out,
                slots,
                zolana_interface::verifying_keys::Bsb22Commitment {
                    commitment: [0; 32],
                    commitment_pok: [0; 32],
                },
            )
        };
        for mode in [RingMode::Off, RingMode::Registry] {
            assert!(Rail::Member.accepts(eddsa, mode));
            assert!(!Rail::Member.accepts(hidden(2, 2), mode));
            assert!(Rail::Delegate.accepts(authority, mode));
        }
        let anonymous = RingMode::Anonymous;
        assert!(!Rail::Member.accepts(eddsa, anonymous));
        assert!(!Rail::Delegate.accepts(authority, anonymous));
        for (n_in, n_out) in [(2, 2), (2, 4), (3, 4), (4, 2)] {
            assert!(Rail::Member.accepts(hidden(n_in, n_out), anonymous));
        }
        assert!(!Rail::Member.accepts(hidden(1, 2), anonymous));
    }
}
