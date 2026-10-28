use bytemuck::Zeroable;
use dynamic_swap_program::{
    error::DynamicSwapError,
    instructions::{
        cancel::{process_cancel_ix, CancelIxData},
        create_escrow::{process_create_escrow_ix, CreateEscrowIxData},
        process_skip_expired_ix,
        settle::{process_settle_ix, SettleIxData},
        verifier::Groth16ProofBytes,
    },
    state::{discriminator, Escrow, Pair},
};
use pinocchio::{error::ProgramError, AccountView, Address};
use zolana_account_checks::account_info::test_account_info::get_account_view;
use zolana_interface::{
    instruction::instruction_data::transact::{TransactIxData, TransactProof},
    verifying_keys::CircuitId,
};

const AUTHORITY: Address = Address::new_from_array([7; 32]);
const PAIR: Address = Address::new_from_array([8; 32]);
const TAKER: Address = Address::new_from_array([9; 32]);

fn pair() -> Pair {
    Pair {
        discriminator: discriminator::PAIR,
        authority: AUTHORITY,
        price: 2,
        expiry_slots: 10,
        max_order_size: 100,
        price_tolerance: 1,
        min_order_amount: 1,
        available_liquidity: 700,
        open_reservations: 3,
        next_order_id: 6,
        head_order_id: 3,
        ..Pair::zeroed()
    }
}

fn escrow() -> Escrow {
    Escrow {
        discriminator: discriminator::ESCROW,
        pair: PAIR,
        owner: TAKER,
        expires_at: 100,
        execution_price: 2,
        order_id: 3,
        ..Escrow::zeroed()
    }
}

fn accounts(pair: &Pair, escrow: &Escrow) -> Vec<AccountView> {
    vec![
        get_account_view(AUTHORITY.to_bytes(), [0; 32], true, true, false, vec![]),
        get_account_view(
            PAIR.to_bytes(),
            dynamic_swap_program::ID.to_bytes(),
            false,
            true,
            false,
            bytemuck::bytes_of(pair).to_vec(),
        ),
        get_account_view(
            [10; 32],
            dynamic_swap_program::ID.to_bytes(),
            false,
            true,
            false,
            bytemuck::bytes_of(escrow).to_vec(),
        ),
        get_account_view(TAKER.to_bytes(), [0; 32], false, true, false, vec![]),
    ]
}

#[derive(Debug, PartialEq, Eq)]
struct AccountState {
    address: Address,
    owner: Address,
    lamports: u64,
    data: Vec<u8>,
}

fn snapshot(accounts: &[AccountView]) -> Vec<AccountState> {
    accounts
        .iter()
        .map(|account| AccountState {
            address: *account.address(),
            owner: *account.owner(),
            lamports: account.lamports(),
            data: account.try_borrow().expect("read account state").to_vec(),
        })
        .collect()
}

fn dummy_proof() -> Groth16ProofBytes {
    Groth16ProofBytes {
        proof_a: [0; 32],
        proof_b: [0; 64],
        proof_c: [0; 32],
    }
}

fn dummy_transact() -> TransactIxData {
    TransactIxData {
        expiry_unix_ts: u64::MAX,
        private_tx_hash: [0; 32],
        circuit: CircuitId::ConfidentialEddsa(1, 2, 0),
        tx_viewing_pk: [2; 33],
        salt: [0; 16],
        proof: TransactProof::zeroed(),
        inputs: vec![],
        tree_contexts: vec![],
        interface_transfers: vec![],
        data_hash: None,
        ring_data_hash: None,
        outputs: vec![],
        messages: vec![],
    }
}

#[test]
fn settlement_rejects_later_order_before_proof_verification() {
    let mut escrow = escrow();
    escrow.order_id += 1;
    let mut accounts = accounts(&pair(), &escrow);
    let before = snapshot(&accounts);
    let data = wincode::serialize(&SettleIxData {
        proof: dummy_proof(),
        transact: dummy_transact(),
    })
    .expect("serialize settlement");

    assert_eq!(
        process_settle_ix(&mut accounts, &data),
        Err(DynamicSwapError::NotQueueHead.into()),
        "later orders must wait even when the maker signs"
    );
    assert_eq!(
        snapshot(&accounts),
        before,
        "rejected settlement changed state"
    );
}

#[test]
fn settlement_rejects_refunded_head_before_proof_verification() {
    let mut escrow = escrow();
    escrow.cancelled = 1;
    let mut accounts = accounts(&pair(), &escrow);
    let before = snapshot(&accounts);
    let data = wincode::serialize(&SettleIxData {
        proof: dummy_proof(),
        transact: dummy_transact(),
    })
    .expect("serialize settlement");

    assert_eq!(
        process_settle_ix(&mut accounts, &data),
        Err(DynamicSwapError::EscrowCancelled.into()),
        "a cancellation marker cannot settle"
    );
    assert_eq!(
        snapshot(&accounts),
        before,
        "rejected settlement changed state"
    );
}

#[test]
fn cancellation_rejects_duplicate_refund_before_proof_verification() {
    let mut escrow = escrow();
    escrow.cancelled = 1;
    let mut accounts = accounts(&pair(), &escrow);
    let before = snapshot(&accounts);
    let data = wincode::serialize(&CancelIxData {
        proof: dummy_proof(),
        transact: dummy_transact(),
    })
    .expect("serialize cancellation");

    assert_eq!(
        process_cancel_ix(&mut accounts, &data),
        Err(DynamicSwapError::EscrowCancelled.into()),
        "a refunded order must not release another reservation"
    );
    assert_eq!(
        snapshot(&accounts),
        before,
        "duplicate refund changed state"
    );
}

#[test]
fn skipping_rejects_later_cancellation_marker() {
    let mut escrow = escrow();
    escrow.order_id += 1;
    escrow.cancelled = 1;
    let mut accounts = accounts(&pair(), &escrow);
    accounts.remove(0);
    let before = snapshot(&accounts);

    assert_eq!(
        process_skip_expired_ix(&mut accounts, &[]),
        Err(DynamicSwapError::NotQueueHead.into()),
        "refunded later orders cannot move the head"
    );
    assert_eq!(
        snapshot(&accounts),
        before,
        "rejected advancement changed state"
    );
}

#[test]
fn skipping_refunded_head_only_advances_queue_and_returns_rent() {
    let pair = pair();
    let mut escrow = escrow();
    escrow.cancelled = 1;
    let mut accounts = accounts(&pair, &escrow);
    accounts.remove(0);
    let mut expected = snapshot(&accounts);
    let mut expected_pair = pair;
    expected_pair.head_order_id += 1;
    expected.first_mut().expect("pair account").data = bytemuck::bytes_of(&expected_pair).to_vec();
    let marker = expected.get_mut(1).expect("marker account");
    let rent = marker.lamports;
    marker.owner = Address::new_from_array([0; 32]);
    marker.lamports = 0;
    marker.data.clear();
    expected.get_mut(2).expect("rent recipient").lamports += rent;

    assert_eq!(
        process_skip_expired_ix(&mut accounts, &[]),
        Ok(()),
        "cleanup must be permissionless"
    );
    assert_eq!(
        snapshot(&accounts),
        expected,
        "cleanup must advance once, close the marker, return rent, and preserve reservations"
    );
}

#[test]
fn skipping_rejects_marker_from_another_pair() {
    let mut escrow = escrow();
    escrow.pair = Address::new_from_array([11; 32]);
    escrow.cancelled = 1;
    let mut accounts = accounts(&pair(), &escrow);
    accounts.remove(0);
    let before = snapshot(&accounts);

    assert_eq!(
        process_skip_expired_ix(&mut accounts, &[]),
        Err(DynamicSwapError::PairMismatch.into()),
        "a marker from another pair cannot advance this queue"
    );
    assert_eq!(snapshot(&accounts), before, "pair mismatch changed state");
}

#[test]
fn skipping_rejects_rent_redirection() {
    let mut escrow = escrow();
    escrow.owner = Address::new_from_array([11; 32]);
    escrow.cancelled = 1;
    let mut accounts = accounts(&pair(), &escrow);
    accounts.remove(0);
    let before = snapshot(&accounts);

    assert_eq!(
        process_skip_expired_ix(&mut accounts, &[]),
        Err(DynamicSwapError::RentRecipientMismatch.into()),
        "cleanup must return rent to the recorded taker"
    );
    assert_eq!(snapshot(&accounts), before, "rent mismatch changed state");
}

#[test]
fn skipping_rejects_counterfeit_marker_account() {
    let mut escrow = escrow();
    escrow.cancelled = 1;
    let mut accounts = accounts(&pair(), &escrow);
    accounts.remove(0);
    *accounts.get_mut(1).expect("marker account") = get_account_view(
        [10; 32],
        [11; 32],
        false,
        true,
        false,
        bytemuck::bytes_of(&escrow).to_vec(),
    );
    let before = snapshot(&accounts);

    assert_eq!(
        process_skip_expired_ix(&mut accounts, &[]),
        Err(DynamicSwapError::InvalidInstructionData.into()),
        "matching marker data is insufficient without program ownership"
    );
    assert_eq!(
        snapshot(&accounts),
        before,
        "counterfeit marker changed state"
    );
}

#[test]
fn creation_rejects_counter_overflow_before_accepting_funds() {
    let mut pair = pair();
    pair.next_order_id = u64::MAX;
    let mut accounts = accounts(&pair, &escrow());
    accounts.pop();
    accounts.push(get_account_view(
        [0; 32],
        [0; 32],
        false,
        false,
        true,
        vec![],
    ));
    let before = snapshot(&accounts);
    let data = wincode::serialize(&CreateEscrowIxData {
        proof: dummy_proof(),
        public_price_floor: 1,
        transact: dummy_transact(),
    })
    .expect("serialize order opening");

    assert_eq!(
        process_create_escrow_ix(&mut accounts, &data),
        Err(ProgramError::ArithmeticOverflow),
        "exhausted ids must reject before syscalls, proof verification, or account creation"
    );
    assert_eq!(
        snapshot(&accounts),
        before,
        "counter overflow changed state"
    );
}
