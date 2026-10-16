use bytemuck::Zeroable;
use custom_ring_interface::{tag, CustomRingProof, CustomRingTransactIxData};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use zolana_interface::{
    instruction::{
        instruction_data::transact::{InterfaceTransfer, TransactProof, TreeContext},
        CircuitId, TransactIxData,
    },
    pda,
};
use zolana_program::instruction::{TransactInterfaceTransferAccounts, TransactSolTransferAccounts};

use super::support::ring;
use crate::{
    CustomRing, CustomRingDelegateTransact, CustomRingTransact, ForeignBinding, PolicyReads,
    PolicyTreeContext, RegistryBinding, RingError,
};

fn payer() -> Address {
    Address::new_from_array([1; 32])
}

fn cosigner() -> Address {
    Address::new_from_array([2; 32])
}

fn delegate() -> Address {
    Address::new_from_array([3; 32])
}

fn curator() -> CustomRing {
    CustomRing::new(Address::new_from_array([4; 32]))
}

fn transact(interface_transfers: Vec<InterfaceTransfer>) -> TransactIxData {
    TransactIxData {
        expiry_unix_ts: u64::MAX,
        tx_viewing_pk: [0; 33],
        salt: [0; 16],
        interface_transfers,
        data_hash: None,
        ring_data_hash: None,
        outputs: Vec::new(),
        messages: Vec::new(),
        private_tx_hash: [0; 32],
        circuit: CircuitId::RingAuthority(2, 2, 0),
        proof: TransactProof::zeroed(),
        inputs: Vec::new(),
        tree_contexts: Vec::new(),
    }
}

fn context(utxo: u16, nullifier: u16) -> TreeContext {
    TreeContext {
        utxo_tree_root_index: utxo,
        nullifier_tree_root_index: nullifier,
    }
}

/// The address tree, the ring's registry at slot 5 and a curator's at slot 2.
fn reads(foreign: bool) -> PolicyReads {
    PolicyReads {
        trees: vec![PolicyTreeContext {
            tree: pda::tree(0),
            context: context(1, 2),
        }],
        registry: RegistryBinding {
            root_index: 5,
            root: [0x55; 32],
        },
        foreign: foreign.then(|| ForeignBinding {
            registry: curator().member_registry_root_pda(),
            curator: curator(),
            root_index: 2,
            root: [0x22; 32],
            next_index: 3,
        }),
    }
}

fn owner_transact(
    cosigner: Option<Address>,
    approval_required: bool,
    policy: Option<PolicyReads>,
) -> CustomRingTransact {
    CustomRingTransact {
        ring: ring(),
        payer: payer(),
        input_trees: vec![pda::tree(0)],
        output_tree: pda::tree(0),
        policy,
        cosigner,
        owner_signers: Vec::new(),
        interface_transfer_accounts: Vec::new(),
        proof: CustomRingProof::zeroed(),
        transact: transact(Vec::new()),
        approval_required,
    }
}

fn delegate_transact(
    cosigner: Option<Address>,
    approval_required: bool,
    interface_transfers: Vec<InterfaceTransfer>,
) -> CustomRingDelegateTransact {
    CustomRingDelegateTransact {
        ring: ring(),
        payer: payer(),
        input_trees: vec![pda::tree(0)],
        output_tree: pda::tree(0),
        policy: reads(true),
        cosigner,
        delegate: delegate(),
        proof: CustomRingProof::zeroed(),
        transact: transact(interface_transfers),
        approval_required,
    }
}

fn data(instruction: &Instruction) -> CustomRingTransactIxData {
    wincode::deserialize_exact(&instruction.data[1..]).unwrap()
}

#[test]
fn an_approval_without_a_cosigner_is_refused_on_both_rails() {
    assert!(matches!(
        owner_transact(None, true, Some(reads(false))).instruction(),
        Err(RingError::ApprovalWithoutCoSigner)
    ));
    assert!(matches!(
        delegate_transact(None, true, Vec::new()).instruction(),
        Err(RingError::ApprovalWithoutCoSigner)
    ));
}

#[test]
fn an_approved_transfer_carries_the_bit_and_the_cosigner_signs() {
    let instruction = owner_transact(Some(cosigner()), true, Some(reads(false)))
        .instruction()
        .unwrap();
    assert_eq!(instruction.data[0], tag::TRANSACT);
    assert!(data(&instruction).approval_required);
    assert_eq!(
        instruction.accounts[..3],
        [
            AccountMeta::new_readonly(ring().config_pda(), false),
            AccountMeta::new_readonly(ring().cosigner_pda(), false),
            AccountMeta::new_readonly(cosigner(), true),
        ]
    );
}

#[test]
fn an_unset_cosigner_repeats_its_pda_unsigned() {
    let instruction = owner_transact(None, false, None).instruction().unwrap();
    assert_eq!(
        instruction.accounts[1..3],
        [
            AccountMeta::new_readonly(ring().cosigner_pda(), false),
            AccountMeta::new_readonly(ring().cosigner_pda(), false),
        ]
    );
}

#[test]
fn a_delegate_move_settles_no_public_leg() {
    let leg = InterfaceTransfer::SolWithdrawal { amount: 1 };
    assert!(matches!(
        delegate_transact(None, false, vec![leg]).instruction(),
        Err(RingError::DelegatePublicLeg)
    ));
}

/// `[config, cosigner_pda, cosigner, delegate_pda, delegate, policy_config, tree, registry, curator registry]`.
#[test]
fn the_delegate_rail_reads_policy_then_both_registries() {
    let instruction = delegate_transact(None, false, Vec::new())
        .instruction()
        .unwrap();
    assert_eq!(instruction.data[0], tag::DELEGATE_TRANSACT);
    assert_eq!(
        instruction.accounts[3..9],
        [
            AccountMeta::new_readonly(ring().delegate_pda(), false),
            AccountMeta::new_readonly(delegate(), true),
            AccountMeta::new_readonly(ring().policy_config_pda(), false),
            AccountMeta::new_readonly(pda::tree(0), false),
            AccountMeta::new_readonly(ring().member_registry_root_pda(), false),
            AccountMeta::new_readonly(curator().member_registry_root_pda(), false),
        ]
    );
    let decoded = data(&instruction);
    assert_eq!(decoded.registry_root_index, 5);
    assert_eq!(decoded.foreign_root_indexes, [2]);
    assert_eq!(decoded.policy_trees, vec![context(1, 2)]);
}

#[test]
fn a_policy_without_a_curator_binds_a_zero_foreign_slot() {
    let instruction = owner_transact(None, false, Some(reads(false)))
        .instruction()
        .unwrap();
    assert_eq!(
        instruction.accounts[3..6],
        [
            AccountMeta::new_readonly(ring().policy_config_pda(), false),
            AccountMeta::new_readonly(pda::tree(0), false),
            AccountMeta::new_readonly(ring().member_registry_root_pda(), false),
        ]
    );
    let decoded = data(&instruction);
    assert_eq!(decoded.registry_root_index, 5);
    assert_eq!(decoded.foreign_root_indexes, [0]);
}

#[test]
fn an_audit_only_transfer_reads_no_policy_and_zeroes_the_statement_fields() {
    let instruction = owner_transact(None, false, None).instruction().unwrap();
    assert!(!instruction
        .accounts
        .iter()
        .any(|meta| meta.pubkey == ring().policy_config_pda()
            || meta.pubkey == ring().member_registry_root_pda()));
    let decoded = data(&instruction);
    assert!(decoded.policy_trees.is_empty());
    assert_eq!(decoded.registry_root_index, 0);
    assert_eq!(decoded.foreign_root_indexes, [0]);
}

/// The registry roots end the policy reads, the forwarded SPP list follows them.
#[test]
fn a_public_leg_follows_the_policy_reads() {
    let settlement = Address::new_from_array([9; 32]);
    let mut transfer = owner_transact(None, false, Some(reads(true)));
    transfer.transact.interface_transfers = vec![InterfaceTransfer::SolWithdrawal { amount: 1 }];
    transfer.interface_transfer_accounts = vec![TransactInterfaceTransferAccounts::Sol(
        TransactSolTransferAccounts {
            recipient: settlement,
        },
    )];
    let instruction = transfer.instruction().unwrap();
    let curator_registry = curator().member_registry_root_pda();
    let registries = instruction
        .accounts
        .iter()
        .position(|meta| meta.pubkey == curator_registry)
        .unwrap();
    let leg = instruction
        .accounts
        .iter()
        .position(|meta| meta.pubkey == settlement)
        .unwrap();
    assert!(registries < leg);
}
