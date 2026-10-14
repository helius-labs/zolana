use solana_address::Address;
use zolana_client::Shape;
use zolana_interface::instruction::MessageData;
use zolana_keypair::{PublicKey, ShieldedKeypair};
use zolana_ring_client::seal_counters;
use zolana_ring_policy::{ListNamespace, Member, SpendCounters, SpendRecord, VelocityRow};
use zolana_transaction::{
    instructions::transact::SppProofOutputUtxo, utxo::SppProofInputUtxo, Data, Mint, Utxo,
};

use crate::{
    entry::zero_nullifier_key,
    velocity::{
        charge, record_shape, transaction_key, window_index, Outflows, RowCharges, VelocityContext,
    },
    LiveSpendRecord, RecordOrigin, RingError, RingIdentity, SpendRecordProofInput,
    VelocityProofInput, WINDOW_GUARD_SLOTS,
};

fn identity() -> RingIdentity {
    RingIdentity {
        ring_id: [1; 32],
        namespace_owner_hash: [2; 32],
    }
}

fn mint() -> Mint {
    Mint::new(Address::new_from_array([9; 32]), 9)
}

fn asset_of(mint: Mint) -> [u8; 32] {
    *Member::asset(&mint.asset).unwrap().as_bytes()
}

fn row_asset() -> [u8; 32] {
    asset_of(mint())
}

fn money_input(mint: Mint, amount: u64) -> SppProofInputUtxo {
    let utxo = Utxo {
        owner: PublicKey::from_pda(&Address::new_from_array([7; 32])),
        asset: mint,
        amount,
        blinding: [0; 32],
        ring_program_id: None,
        data: Data::default(),
    };
    let key = zero_nullifier_key();
    let nullifier_pubkey = key.pubkey().unwrap();
    let utxo_hash = utxo.hash(&nullifier_pubkey, &[0; 32], &[0; 32], 0).unwrap();
    SppProofInputUtxo {
        utxo,
        nullifier_pubkey,
        utxo_hash,
        nullifier: key.nullifier(&utxo_hash, &[0; 32]).unwrap(),
        data_hash: None,
        ring_data_hash: None,
        tree_id: 0,
        leaf_index: 0,
        cache_slot: None,
        compact: false,
    }
}

fn counters(rows: &[(&[u8; 32], u64)]) -> SpendCounters {
    let assets: Vec<[u8; 32]> = rows.iter().map(|(asset, _)| **asset).collect();
    let mut counters = SpendCounters::zero(&assets).unwrap();
    for (index, (_, spent)) in rows.iter().enumerate() {
        counters.spent[index] = *spent;
    }
    counters
}

fn charge_rows(
    inputs: &[SppProofInputUtxo],
    rows: &[VelocityRow],
    previous: Option<&SpendCounters>,
) -> Result<RowCharges, RingError> {
    let outputs: [SppProofOutputUtxo; 0] = [];
    let outflows = Outflows {
        sender: Member::owner_tag(&[1; 32]).unwrap(),
        ring: Address::default(),
        inputs,
        outputs: &outputs,
    };
    charge(rows, &outflows, previous)
}

fn charge_one(
    amount: u64,
    cap: u64,
    cosign_above: u64,
    previous: Option<u64>,
) -> Result<RowCharges, RingError> {
    let row = VelocityRow {
        asset: row_asset(),
        cap,
        cosign_above,
    };
    let previous = previous.map(|spent| counters(&[(&row_asset(), spent)]));
    charge_rows(&[money_input(mint(), amount)], &[row], previous.as_ref())
}

#[test]
fn the_record_takes_the_slot_after_the_money() {
    assert_eq!(record_shape(Shape::new(1, 1)).unwrap(), Shape::IN2_OUT2);
    assert_eq!(record_shape(Shape::IN1_OUT2).unwrap(), Shape::IN2_OUT4);
    assert_eq!(record_shape(Shape::IN2_OUT2).unwrap(), Shape::IN3_OUT4);
    assert_eq!(record_shape(Shape::new(1, 3)).unwrap(), Shape::IN2_OUT4);
    assert_eq!(record_shape(Shape::new(2, 3)).unwrap(), Shape::IN3_OUT4);
    assert_eq!(record_shape(Shape::new(3, 3)).unwrap(), Shape::IN4_OUT4);
    assert_eq!(record_shape(Shape::IN4_OUT2).unwrap(), Shape::IN5_OUT4);
    assert!(matches!(
        record_shape(Shape::IN1_OUT4),
        Err(RingError::PolicyShapeUnsupported)
    ));
    assert!(matches!(
        record_shape(Shape::IN4_OUT4),
        Err(RingError::PolicyShapeUnsupported)
    ));
}

#[test]
fn a_transfer_under_the_cap_charges_its_outflow() {
    let charges = charge_one(100, 1000, 0, None).unwrap();
    assert_eq!(charges.spent[0], 100);
    assert_eq!(charges.row_count, 1);
    assert!(!charges.approval_required);
}

#[test]
fn a_transfer_at_the_cap_passes() {
    assert_eq!(charge_one(1000, 1000, 0, None).unwrap().spent[0], 1000);
}

#[test]
fn a_transfer_over_the_cap_is_refused_with_its_outflow() {
    assert!(matches!(
        charge_one(1001, 1000, 0, None),
        Err(RingError::VelocityCapExceeded { asset, cap: 1000, spent: 1001 }) if asset == row_asset()
    ));
}

#[test]
fn the_threshold_reads_the_outflow_alone() {
    assert!(charge_one(600, 0, 500, None).unwrap().approval_required);
    assert!(!charge_one(500, 0, 500, None).unwrap().approval_required);
    assert!(!charge_one(600, 1000, 0, None).unwrap().approval_required);
}

#[test]
fn a_supplied_previous_adds_to_a_capped_charge() {
    assert_eq!(charge_one(100, 1000, 0, Some(50)).unwrap().spent[0], 150);
    assert_eq!(charge_one(100, 1000, 0, None).unwrap().spent[0], 100);
}

#[test]
fn a_previous_over_the_cap_is_refused() {
    assert!(matches!(
        charge_one(600, 1000, 0, Some(500)),
        Err(RingError::VelocityCapExceeded { spent: 1100, .. })
    ));
}

#[test]
fn a_cosign_only_row_keeps_a_zero_counter_whatever_it_carried() {
    let charges = charge_one(u64::MAX, 0, 1, Some(u64::MAX)).unwrap();
    assert_eq!(charges.spent[0], 0);
    assert!(charges.approval_required);
    let below = charge_one(1, 0, 1, Some(u64::MAX)).unwrap();
    assert_eq!(below.spent[0], 0);
    assert!(!below.approval_required);
}

#[test]
fn a_capped_row_beside_a_cosign_only_row_still_accumulates() {
    let sol = asset_of(Mint::SOL);
    let rows = [
        VelocityRow {
            asset: row_asset(),
            cap: 0,
            cosign_above: 10,
        },
        VelocityRow {
            asset: sol,
            cap: 1000,
            cosign_above: 0,
        },
    ];
    let inputs = [money_input(mint(), 50), money_input(Mint::SOL, 300)];
    let previous = counters(&[(&row_asset(), u64::MAX), (&sol, 600)]);
    let charges = charge_rows(&inputs, &rows, Some(&previous)).unwrap();
    assert_eq!(charges.spent[..2], [0, 900]);
    assert_eq!(charges.row_count, 2);
    assert!(charges.approval_required);
    let previous = counters(&[(&row_asset(), 0), (&sol, 701)]);
    assert!(matches!(
        charge_rows(&inputs, &rows, Some(&previous)),
        Err(RingError::VelocityCapExceeded { asset, cap: 1000, spent: 1001 }) if asset == sol
    ));
}

#[test]
fn a_capped_sum_past_u64_is_an_overflow() {
    assert!(matches!(
        charge_one(2, u64::MAX, 0, Some(u64::MAX - 1)),
        Err(RingError::VelocityOverflow)
    ));
}

#[test]
fn change_past_the_inflow_is_a_shape_error() {
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    let ring = Address::new_from_array([3; 32]);
    let inputs = [money_input(mint(), 5)];
    let outputs = [SppProofOutputUtxo {
        ring_program_id: Some(ring),
        ..SppProofOutputUtxo::new(mint(), 6, sender.shielded_address().unwrap()).unwrap()
    }];
    let identity = sender.signing_pubkey().owner_proof_input_hash().unwrap();
    let outflows = Outflows {
        sender: Member::from_bytes(identity).unwrap(),
        ring,
        inputs: &inputs,
        outputs: &outputs,
    };
    let row = VelocityRow {
        asset: row_asset(),
        cap: 1000,
        cosign_above: 0,
    };
    assert!(matches!(
        charge(&[row], &outflows, None),
        Err(RingError::VelocityChangeExceedsInflow { asset }) if asset == row_asset()
    ));
}

#[test]
fn change_back_to_the_sender_in_the_ring_is_not_an_outflow() {
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    let ring = Address::new_from_array([3; 32]);
    let inputs = [money_input(mint(), 10)];
    let change = |ring_program_id| SppProofOutputUtxo {
        ring_program_id,
        ..SppProofOutputUtxo::new(mint(), 4, sender.shielded_address().unwrap()).unwrap()
    };
    let identity = sender.signing_pubkey().owner_proof_input_hash().unwrap();
    let row = VelocityRow {
        asset: row_asset(),
        cap: 1000,
        cosign_above: 0,
    };
    for (outputs, spent) in [([change(Some(ring))], 6), ([change(None)], 10)] {
        let outflows = Outflows {
            sender: Member::from_bytes(identity).unwrap(),
            ring,
            inputs: &inputs,
            outputs: &outputs,
        };
        assert_eq!(charge(&[row], &outflows, None).unwrap().spent[0], spent);
    }
}

#[test]
fn per_transfer_proof_input_carries_the_rows_without_a_record() {
    let charges = charge_one(100, 1000, 0, None).unwrap();
    let proof_input = VelocityProofInput::per_transfer(&charges, identity());
    assert_eq!(proof_input.window_slots, 0);
    assert_eq!(proof_input.window_index, 0);
    assert_eq!(proof_input.row_count, 1);
    assert_eq!(proof_input.rows[0].cap, 1000);
    assert_eq!(proof_input.ring_id, identity().ring_id);
    assert_eq!(proof_input.record, SpendRecordProofInput::default());
}

#[test]
fn the_window_guard_refuses_the_last_slots_of_a_window() {
    assert_eq!(WINDOW_GUARD_SLOTS, 64);
    assert_eq!(window_index(935, 1000).unwrap(), 0);
    for slot in [936, 999] {
        assert!(matches!(
            window_index(slot, 1000),
            Err(RingError::WindowClosing { resumes_at: 1000 })
        ));
    }
    assert_eq!(window_index(1000, 1000).unwrap(), 1);
    assert!(matches!(
        window_index(2936, 1000),
        Err(RingError::WindowClosing { resumes_at: 3000 })
    ));
}

#[test]
fn a_short_window_guards_half_of_itself() {
    assert_eq!(window_index(49, 100).unwrap(), 0);
    assert!(matches!(
        window_index(50, 100),
        Err(RingError::WindowClosing { resumes_at: 100 })
    ));
    assert_eq!(window_index(0, 2).unwrap(), 0);
    assert!(matches!(
        window_index(1, 2),
        Err(RingError::WindowClosing { resumes_at: 2 })
    ));
    for slot in [0, 1, 7] {
        assert_eq!(window_index(slot, 1).unwrap(), slot);
    }
}

fn live(version: u64, window: u64, commitment: [u8; 32], origin: RecordOrigin) -> LiveSpendRecord {
    LiveSpendRecord {
        record: SpendRecord {
            member: Member::owner_tag(&[1; 32]).unwrap(),
            version,
            window,
            blinding: [0; 32],
            counters_commitment: commitment,
        },
        utxo_hash: [0; 32],
        nullifier: [0; 32],
        tree_id: 0,
        leaf_index: 0,
        origin,
    }
}

fn no_origin() -> RecordOrigin {
    RecordOrigin {
        first_nullifier: [0; 32],
        tx_viewing_pk: None,
        salt: None,
        messages: Vec::new(),
    }
}

fn context(namespace: Address, window_slots: u64) -> VelocityContext {
    VelocityContext {
        namespace,
        owner: ListNamespace::new(namespace.as_array()).unwrap(),
        identity: identity(),
        address_tree_id: 0,
        window_slots,
        rows: Vec::new(),
    }
}

#[test]
fn only_an_older_record_can_skip_counter_recovery() {
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    let record = || live(2, 8, [0; 32], no_origin());
    let facts = |slot| context(Address::default(), 1).facts(&sender, record(), slot);
    assert!(matches!(
        facts(7),
        Err(RingError::SpendRecordFromFutureWindow)
    ));
    assert!(matches!(facts(8), Err(RingError::SpendCountersUnknown)));
    let expired = facts(9).unwrap();
    assert_eq!(expired.window_index, 9);
    assert_eq!(expired.counters, None);
}

#[test]
fn a_record_near_the_boundary_is_refused_before_its_counters_open() {
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    let result =
        context(Address::default(), 1000).facts(&sender, live(2, 0, [0; 32], no_origin()), 990);
    assert!(matches!(
        result,
        Err(RingError::WindowClosing { resumes_at: 1000 })
    ));
}

#[test]
fn a_genesis_record_opens_empty_counters_under_their_commitment() {
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    let empty = SpendCounters::EMPTY.commitment().unwrap();
    let facts = context(Address::default(), 1)
        .facts(&sender, live(0, 4, empty, no_origin()), 4)
        .unwrap();
    assert_eq!(facts.counters, Some(SpendCounters::EMPTY));
    assert!(matches!(
        context(Address::default(), 1).facts(&sender, live(0, 4, [1; 32], no_origin()), 4),
        Err(RingError::SpendCountersUnknown)
    ));
}

#[test]
fn a_successor_opens_its_sealed_counters_only_under_their_commitment() {
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    let namespace = Address::new_from_array([8; 32]);
    let first_nullifier = [3; 32];
    let salt = [9; 16];
    let tx_key = transaction_key(&sender, first_nullifier).unwrap();
    let sealed = counters(&[(&row_asset(), 40)]);
    let message = MessageData {
        view_tag: namespace.to_bytes(),
        data: seal_counters(&tx_key, &tx_key.pubkey(), salt, &sealed).unwrap(),
    };
    let origin = |messages: Vec<MessageData>| RecordOrigin {
        first_nullifier,
        tx_viewing_pk: Some(tx_key.pubkey()),
        salt: Some(salt),
        messages,
    };
    let commitment = sealed.commitment().unwrap();
    let facts = context(namespace, 1)
        .facts(
            &sender,
            live(3, 5, commitment, origin(vec![message.clone()])),
            5,
        )
        .unwrap();
    assert_eq!(facts.counters, Some(sealed));

    let refused = [
        live(3, 5, [1; 32], origin(vec![message.clone()])),
        live(
            3,
            5,
            commitment,
            origin(vec![message.clone(), message.clone()]),
        ),
        live(3, 5, commitment, origin(Vec::new())),
        live(
            3,
            5,
            commitment,
            RecordOrigin {
                salt: None,
                ..origin(vec![message.clone()])
            },
        ),
        live(
            3,
            5,
            commitment,
            RecordOrigin {
                first_nullifier: [4; 32],
                ..origin(vec![message])
            },
        ),
    ];
    for record in refused {
        assert!(matches!(
            context(namespace, 1).facts(&sender, record, 5),
            Err(RingError::SpendCountersUnknown)
        ));
    }
}
