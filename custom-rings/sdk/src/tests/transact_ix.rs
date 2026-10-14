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
use zolana_ring_policy::ANSWER_SLOTS;
use zolana_transaction::SOL_MINT;

use super::support::ring;
use crate::{
    CustomRingDelegateTransact, CustomRingTransact, EscrowBinding, PolicyReads, PolicyTreeContext,
    RingError,
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

/// Two policy trees, fact 0 revoked in the second, fact 2 in the first.
fn reads(escrow: EscrowBinding) -> PolicyReads {
    let mut revocation_targets = [[0; 32]; ANSWER_SLOTS];
    revocation_targets[0] = [0x21; 32];
    revocation_targets[2] = [0x23; 32];
    let mut revocation_tree_indexes = [0; ANSWER_SLOTS];
    revocation_tree_indexes[0] = 1;
    PolicyReads {
        trees: vec![
            PolicyTreeContext {
                tree: pda::tree(0),
                context: context(1, 2),
            },
            PolicyTreeContext {
                tree: pda::tree(9),
                context: context(3, 4),
            },
        ],
        escrow,
        revocation_targets,
        revocation_tree_indexes,
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
    transfers: Vec<InterfaceTransfer>,
) -> CustomRingDelegateTransact {
    CustomRingDelegateTransact {
        ring: ring(),
        payer: payer(),
        input_trees: vec![pda::tree(0)],
        output_tree: pda::tree(0),
        policy: reads(EscrowBinding::Registry { root_index: 5 }),
        cosigner,
        delegate: delegate(),
        proof: CustomRingProof::zeroed(),
        transact: transact(transfers),
        approval_required,
    }
}

fn data(instruction: &Instruction) -> CustomRingTransactIxData {
    wincode::deserialize(&instruction.data[1..]).unwrap()
}

#[test]
fn an_approval_without_a_cosigner_is_refused_on_both_rails() {
    assert!(matches!(
        owner_transact(None, true, None).instruction(),
        Err(RingError::ApprovalWithoutCoSigner)
    ));
    assert!(matches!(
        delegate_transact(None, true, Vec::new()).instruction(),
        Err(RingError::ApprovalWithoutCoSigner)
    ));
    owner_transact(None, false, None).instruction().unwrap();
    delegate_transact(None, false, Vec::new())
        .instruction()
        .unwrap();
}

#[test]
fn an_approved_transfer_carries_the_bit_and_the_cosigner_signs() {
    let owner = owner_transact(Some(cosigner()), true, None)
        .instruction()
        .unwrap();
    let delegated = delegate_transact(Some(cosigner()), true, Vec::new())
        .instruction()
        .unwrap();
    assert_eq!(owner.data[0], tag::TRANSACT);
    assert_eq!(delegated.data[0], tag::DELEGATE_TRANSACT);
    for instruction in [owner, delegated] {
        assert_eq!(data(&instruction).approval_required, 1);
        assert_eq!(
            instruction.accounts[3],
            AccountMeta::new_readonly(cosigner(), true)
        );
    }
    let unapproved = delegate_transact(Some(cosigner()), false, Vec::new())
        .instruction()
        .unwrap();
    assert_eq!(data(&unapproved).approval_required, 0);
}

#[test]
fn an_unset_cosigner_repeats_its_pda_unsigned() {
    let instruction = owner_transact(None, false, None).instruction().unwrap();
    let pda = ring().cosigner_pda();
    assert_eq!(
        instruction.accounts[..4],
        [
            AccountMeta::new(payer(), true),
            AccountMeta::new_readonly(ring().config_pda(), false),
            AccountMeta::new_readonly(pda, false),
            AccountMeta::new_readonly(pda, false),
        ]
    );
}

#[test]
fn a_delegate_move_settles_no_public_leg() {
    assert!(matches!(
        delegate_transact(
            None,
            false,
            vec![InterfaceTransfer::SolWithdrawal { amount: 1 }]
        )
        .instruction(),
        Err(RingError::DelegatePublicLeg)
    ));
}

#[test]
fn the_delegate_rail_reads_policy_then_escrow_then_revocations_in_their_trees() {
    let instruction = delegate_transact(None, false, Vec::new())
        .instruction()
        .unwrap();
    let keys: Vec<Address> = instruction
        .accounts
        .iter()
        .map(|meta| meta.pubkey)
        .collect();
    assert_eq!(
        keys[4..11],
        [
            ring().delegate_pda(),
            delegate(),
            ring().policy_config_pda(),
            pda::tree(0),
            pda::tree(9),
            ring().key_registry_root_pda(),
            pda::nullifier_pda(&pda::tree(9), &[0x21; 32]).0,
        ]
    );
    assert_eq!(keys[11], pda::nullifier_pda(&pda::tree(0), &[0x23; 32]).0);
    assert!(instruction.accounts[5].is_signer);
    let decoded = data(&instruction);
    assert_eq!(decoded.policy_trees, vec![context(1, 2), context(3, 4)]);
    assert_eq!(decoded.key_registry_root_index, 5);
    assert_eq!(decoded.revocation_tree_indexes[0], 1);
    assert_eq!(decoded.revocation_targets[2], [0x23; 32]);
}

#[test]
fn a_revocation_naming_a_missing_tree_is_refused() {
    let mut policy = reads(EscrowBinding::Off);
    policy.revocation_tree_indexes[2] = 2;
    assert!(matches!(
        owner_transact(None, false, Some(policy)).instruction(),
        Err(RingError::RevocationTree {
            slot: 2,
            index: 2,
            trees: 2
        })
    ));
}

#[test]
fn an_audit_only_transfer_reads_no_policy_and_zeroes_the_statement_fields() {
    let instruction = owner_transact(None, false, None).instruction().unwrap();
    assert!(!instruction
        .accounts
        .iter()
        .any(|meta| meta.pubkey == ring().policy_config_pda()));
    let decoded = data(&instruction);
    assert!(decoded.policy_trees.is_empty());
    assert_eq!(decoded.key_registry_root_index, 0);
    assert_eq!(decoded.revocation_targets, [[0; 32]; ANSWER_SLOTS]);
}

#[test]
fn a_public_leg_writes_its_window_and_the_namespace_never_signs() {
    let recipient = Address::new_from_array([7; 32]);
    let mut transfer = owner_transact(None, false, Some(reads(EscrowBinding::Off)));
    transfer.transact = transact(vec![InterfaceTransfer::SolWithdrawal { amount: 4 }]);
    transfer.interface_transfer_accounts = vec![TransactInterfaceTransferAccounts::Sol(
        TransactSolTransferAccounts { recipient },
    )];
    let instruction = transfer.instruction().unwrap();
    let window = ring().spend_window_pda(&SOL_MINT);
    let position = instruction
        .accounts
        .iter()
        .position(|meta| meta.pubkey == window)
        .unwrap();
    assert!(instruction.accounts[position].is_writable);
    // The window leads the forwarded SPP list, after the policy reads.
    let revocations = instruction.accounts[position - 2..position]
        .iter()
        .map(|meta| meta.pubkey)
        .collect::<Vec<_>>();
    assert_eq!(
        revocations,
        vec![
            pda::nullifier_pda(&pda::tree(9), &[0x21; 32]).0,
            pda::nullifier_pda(&pda::tree(0), &[0x23; 32]).0,
        ]
    );
    let namespace = ring().namespace_pda();
    assert!(instruction
        .accounts
        .iter()
        .filter(|meta| meta.pubkey == namespace)
        .all(|meta| !meta.is_signer));
    assert!(instruction
        .accounts
        .iter()
        .any(|meta| meta.pubkey == recipient));
}
