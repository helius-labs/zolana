use dynamic_swap_program::{
    circuits::{
        EscrowOpen, EscrowOpenPrivateInputs, EscrowOpenPublicInputs, PoolRebalance,
        PoolRebalancePrivateInputs, PoolRebalancePublicInputs, PoolWithdraw,
        PoolWithdrawPrivateInputs, PoolWithdrawPublicInputs, ProofInputUtxo,
    },
    verifier::{escrow_open, pool_rebalance, pool_withdraw},
};
use dynamic_swap_sdk::state::order_data_hash;
use spr_program::{checked, verifier::verify_groth16, Field};

mod support;
use support::{bytes, check, field, private_tx_hash, prove};

fn value(n: u64) -> Field {
    Field::from(n)
}

fn dummy() -> ProofInputUtxo {
    ProofInputUtxo {
        domain: value(u64::from(spr_interface::DUMMY_DOMAIN)),
        tree_id: Field::zero(),
        owner_hash: Field::zero(),
        asset: Field::zero(),
        amount: Field::zero(),
        blinding: Field::zero(),
        data_hash: Field::zero(),
        ring_data_hash: Field::zero(),
        ring_program_id: Field::zero(),
    }
}

fn note(owner: u64, amount: u64, booked: u64) -> ProofInputUtxo {
    ProofInputUtxo {
        domain: value(u64::from(spr_interface::UTXO_DOMAIN)),
        tree_id: value(3),
        owner_hash: value(owner),
        asset: value(4),
        amount: value(amount),
        blinding: value(5),
        data_hash: value(booked),
        ..dummy()
    }
}

fn hash(note: &ProofInputUtxo) -> Field {
    note.hash().unwrap()
}

fn refresh_open(circuit: &mut EscrowOpen) {
    let private = &mut circuit.private;
    private.private_tx_hash = private_tx_hash(
        &[hash(&private.source_in)],
        &[hash(&private.order_out), hash(&private.taker_change)],
        &private.private_tx_blinding,
    );
}

fn open_public_hash(circuit: &EscrowOpen) -> [u8; 32] {
    escrow_open_public_inputs(circuit)
        .hash(&bytes(&circuit.private.private_tx_hash))
        .unwrap()
}

fn escrow_open_public_inputs(circuit: &EscrowOpen) -> escrow_open::PublicInputs {
    escrow_open::PublicInputs {
        escrow_authority_owner_hash: bytes(&circuit.public.escrow_authority_owner_hash),
        source_asset: bytes(&circuit.public.source_asset),
        public_price_floor: circuit.public.public_price_floor,
        price_tolerance: circuit.public.price_tolerance,
        min_order_amount: circuit.public.min_order_amount,
        max_order_size: circuit.public.max_order_size,
    }
}

fn open() -> EscrowOpen {
    let mut order_out = note(2, 10, 0);
    order_out.data_hash = field(&order_data_hash(&bytes(&value(1)), 5).unwrap());
    let mut circuit = EscrowOpen {
        private: EscrowOpenPrivateInputs {
            private_tx_hash: Field::zero(),
            order_amount: 10,
            min_price: 5,
            source_in: note(1, 15, 0),
            order_out,
            taker_change: note(1, 5, 0),
            private_tx_blinding: value(9),
        },
        public: EscrowOpenPublicInputs {
            escrow_authority_owner_hash: value(2),
            source_asset: value(4),
            public_price_floor: 4,
            price_tolerance: 1,
            min_order_amount: 10,
            max_order_size: 60,
        },
    };
    refresh_open(&mut circuit);
    circuit
}

#[test]
fn escrow_open_checks_private_policy_and_conservation() {
    let good = open();
    let native = checked(|| good.execute()).expect("valid escrow open");
    assert_eq!(bytes(native.public_hash()), open_public_hash(&good));
    check("escrow_open", &good, open_public_hash(&good)).expect("valid escrow open");
    for attack in 0..13 {
        let mut circuit = good;
        match attack {
            0 => circuit.public.min_order_amount = 11,
            1 => circuit.public.max_order_size = 59,
            2 => circuit.private.min_price = 3,
            3 => circuit.private.min_price = 6,
            4 => circuit.private.order_out.owner_hash = value(3),
            5 => circuit.private.order_out.data_hash = value(3),
            6 => circuit.private.order_out.amount = value(11),
            7 => circuit.private.taker_change.amount = value(6),
            8 => circuit.private.taker_change.owner_hash = value(3),
            9 => circuit.private.source_in.asset = value(3),
            10 => circuit.private.source_in.amount = value(9),
            11 => circuit.public.public_price_floor = u64::MAX,
            _ => circuit.private.source_in.ring_program_id = value(1),
        }
        refresh_open(&mut circuit);
        assert!(
            check("escrow_open", &circuit, open_public_hash(&circuit)).is_err(),
            "accepted escrow open attack {attack}"
        );
    }
}

fn refresh_withdraw(circuit: &mut PoolWithdraw) {
    let private = &mut circuit.private;
    private.private_tx_hash = private_tx_hash(
        &[hash(&private.pool_in)],
        &[hash(&private.pool_out)],
        &private.private_tx_blinding,
    );
}

fn pool_withdraw_public_inputs(circuit: &PoolWithdraw) -> pool_withdraw::PublicInputs {
    pool_withdraw::PublicInputs {
        pool_authority_owner_hash: bytes(&circuit.public.pool_authority_owner_hash),
        destination_asset: bytes(&circuit.public.destination_asset),
        amount: circuit.public.amount,
    }
}

fn withdraw_public_hash(circuit: &PoolWithdraw) -> [u8; 32] {
    pool_withdraw_public_inputs(circuit)
        .hash(&bytes(&circuit.private.private_tx_hash))
        .unwrap()
}

fn withdraw() -> PoolWithdraw {
    let mut circuit = PoolWithdraw {
        private: PoolWithdrawPrivateInputs {
            private_tx_hash: Field::zero(),
            pool_in: note(2, 100, 80),
            pool_out: note(2, 70, 50),
            private_tx_blinding: value(9),
        },
        public: PoolWithdrawPublicInputs {
            pool_authority_owner_hash: value(2),
            destination_asset: value(4),
            amount: 30,
        },
    };
    refresh_withdraw(&mut circuit);
    circuit
}

#[test]
fn withdraw_consumes_only_booked_liquidity_and_preserves_surplus() {
    let good = withdraw();
    let native = checked(|| good.execute()).expect("valid withdrawal");
    assert_eq!(bytes(native.public_hash()), withdraw_public_hash(&good));
    check("pool_withdraw", &good, withdraw_public_hash(&good)).expect("valid withdrawal");
    for attack in 0..8 {
        let mut circuit = good;
        match attack {
            0 => circuit.private.pool_in.owner_hash = value(3),
            1 => circuit.private.pool_out.owner_hash = value(3),
            2 => circuit.private.pool_in.asset = value(3),
            3 => circuit.private.pool_out.amount = value(71),
            4 => circuit.private.pool_out.data_hash = value(51),
            5 => circuit.private.pool_in.data_hash = value(20),
            6 => circuit.public.amount = 101,
            _ => circuit.private.pool_out.ring_data_hash = value(1),
        }
        refresh_withdraw(&mut circuit);
        assert!(
            check("pool_withdraw", &circuit, withdraw_public_hash(&circuit)).is_err(),
            "accepted withdrawal attack {attack}"
        );
    }
}

fn refresh_rebalance(circuit: &mut PoolRebalance) {
    let private = &mut circuit.private;
    let slot_hash = |note: &ProofInputUtxo| {
        if note.domain == value(u64::from(spr_interface::DUMMY_DOMAIN)) {
            Field::zero()
        } else {
            hash(note)
        }
    };
    let inputs: Vec<_> = private.inputs.iter().map(slot_hash).collect();
    let outputs: Vec<_> = private.outputs.iter().map(slot_hash).collect();
    private.private_tx_hash = private_tx_hash(&inputs, &outputs, &private.private_tx_blinding);
}

fn pool_rebalance_public_inputs(circuit: &PoolRebalance) -> pool_rebalance::PublicInputs {
    pool_rebalance::PublicInputs {
        pool_authority_owner_hash: bytes(&circuit.public.pool_authority_owner_hash),
        destination_asset: bytes(&circuit.public.destination_asset),
        credit: circuit.public.credit,
    }
}

fn rebalance_public_hash(circuit: &PoolRebalance) -> [u8; 32] {
    pool_rebalance_public_inputs(circuit)
        .hash(&bytes(&circuit.private.private_tx_hash))
        .unwrap()
}

fn rebalance() -> PoolRebalance {
    let mut inputs = [dummy(); 5];
    inputs[0] = note(2, 100, 60);
    inputs[1] = note(2, 50, 20);
    let mut outputs = [dummy(); 4];
    outputs[0] = note(2, 150, 100);
    let mut circuit = PoolRebalance {
        private: PoolRebalancePrivateInputs {
            private_tx_hash: Field::zero(),
            inputs,
            outputs,
            private_tx_blinding: value(9),
        },
        public: PoolRebalancePublicInputs {
            pool_authority_owner_hash: value(2),
            destination_asset: value(4),
            credit: 20,
        },
    };
    refresh_rebalance(&mut circuit);
    circuit
}

#[test]
fn rebalance_conserves_value_and_cannot_overcredit_or_hide_dummy_value() {
    let good = rebalance();
    let native = checked(|| good.execute()).expect("valid padded rebalance");
    assert_eq!(bytes(native.public_hash()), rebalance_public_hash(&good));
    check("pool_rebalance", &good, rebalance_public_hash(&good)).expect("valid padded rebalance");
    for attack in 0..10 {
        let mut circuit = good;
        match attack {
            0 => circuit.private.inputs[0].owner_hash = value(3),
            1 => circuit.private.outputs[0].owner_hash = value(3),
            2 => circuit.private.outputs[0].asset = value(3),
            3 => circuit.private.outputs[0].amount = value(151),
            4 => circuit.private.outputs[0].data_hash = value(151),
            5 => circuit.public.credit = 21,
            6 => circuit.private.inputs[2].amount = value(1),
            7 => circuit.private.outputs[1].data_hash = value(1),
            8 => circuit.private.inputs[0].ring_data_hash = value(1),
            _ => circuit.private.outputs[0].domain = value(99),
        }
        refresh_rebalance(&mut circuit);
        assert!(
            check("pool_rebalance", &circuit, rebalance_public_hash(&circuit)).is_err(),
            "accepted rebalance attack {attack}"
        );
    }
}

#[test]
fn native_circuits_bind_the_private_transaction_hash() {
    let mut open = open();
    let hash = open_public_hash(&open);
    open.private.private_tx_hash = value(1);
    assert!(
        check("escrow_open", &open, hash).is_err(),
        "escrow open accepted another transaction"
    );
    let mut withdraw = withdraw();
    let hash = withdraw_public_hash(&withdraw);
    withdraw.private.private_tx_hash = value(1);
    assert!(
        check("pool_withdraw", &withdraw, hash).is_err(),
        "withdrawal accepted another transaction"
    );
    let mut rebalance = rebalance();
    let hash = rebalance_public_hash(&rebalance);
    rebalance.private.private_tx_hash = value(1);
    assert!(
        check("pool_rebalance", &rebalance, hash).is_err(),
        "rebalance accepted another transaction"
    );
}

#[test]
fn native_open_withdraw_and_rebalance_proofs_verify_with_program_keys() {
    let open = open();
    let hash = open_public_hash(&open);
    verify_groth16(
        &prove("escrow_open", &open, hash),
        hash,
        &escrow_open::VERIFYINGKEY,
    )
    .expect("the program verifies the native escrow open proof");

    let withdraw = withdraw();
    let hash = withdraw_public_hash(&withdraw);
    verify_groth16(
        &prove("pool_withdraw", &withdraw, hash),
        hash,
        &pool_withdraw::VERIFYINGKEY,
    )
    .expect("the program verifies the native withdrawal proof");

    let rebalance = rebalance();
    let hash = rebalance_public_hash(&rebalance);
    verify_groth16(
        &prove("pool_rebalance", &rebalance, hash),
        hash,
        &pool_rebalance::VERIFYINGKEY,
    )
    .expect("the program verifies the native rebalance proof");
}

/// `p - 1` for the BN254 scalar field. It satisfies a subtraction that
/// underflows by one, so only the explicit u64 range check rejects it.
const FIELD_NEGATIVE_ONE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x00,
];

/// The compiled circuit names the failing check and the inputs it reads.
fn assert_range_refusal(error: &str, input: &str) {
    assert!(
        error.contains("require_u64 → to_bits") && error.contains(input),
        "expected the u64 range check on `{input}`: {error}"
    );
}

#[test]
fn escrow_open_rejects_field_wrapped_change_after_source_underflow() {
    let mut circuit = open();
    circuit.private.source_in.amount = value(9);
    circuit.private.taker_change.amount = field(&FIELD_NEGATIVE_ONE);
    refresh_open(&mut circuit);
    let error = check("escrow_open", &circuit, open_public_hash(&circuit)).unwrap_err();
    assert_range_refusal(&error.to_string(), "program.private.taker_change.amount");
}

#[test]
fn withdrawal_rejects_field_wrapped_balance_and_booked_underflow() {
    for booked_underflow in [false, true] {
        let mut circuit = withdraw();
        if booked_underflow {
            circuit.private.pool_in.data_hash = value(29);
            circuit.private.pool_out.data_hash = field(&FIELD_NEGATIVE_ONE);
        } else {
            circuit.private.pool_in.amount = value(29);
            circuit.private.pool_out.amount = field(&FIELD_NEGATIVE_ONE);
        }
        refresh_withdraw(&mut circuit);
        let error = check("pool_withdraw", &circuit, withdraw_public_hash(&circuit)).unwrap_err();
        let input = if booked_underflow {
            "program.private.pool_out.data_hash"
        } else {
            "program.private.pool_out.amount"
        };
        assert_range_refusal(&error.to_string(), input);
    }
}

#[test]
fn rebalance_rejects_conserved_values_wider_than_u64() {
    // 2^64: a valid scalar outside the token amount range.
    let wide = Field::from(1u128 << 64);
    for wide_booked in [false, true] {
        let mut circuit = rebalance();
        circuit.private.inputs[1] = dummy();
        circuit.public.credit = 0;
        if wide_booked {
            circuit.private.inputs[0].data_hash = wide;
            circuit.private.outputs[0].data_hash = wide;
            circuit.private.outputs[0].amount = value(100);
        } else {
            circuit.private.inputs[0].amount = wide;
            circuit.private.outputs[0].amount = wide;
            circuit.private.outputs[0].data_hash = value(60);
        }
        refresh_rebalance(&mut circuit);
        let error = check("pool_rebalance", &circuit, rebalance_public_hash(&circuit)).unwrap_err();
        let input = if wide_booked {
            "program.private.inputs[0].data_hash"
        } else {
            "program.private.inputs[0].amount"
        };
        assert_range_refusal(&error.to_string(), input);
    }
}

#[test]
#[ignore = "run `just ensure-dynamic-swap-keys` first to create checked native proving keys"]
fn native_client_loads_checked_keys() {
    use dynamic_swap_sdk::prover::DynamicSwapProverClient;

    let client = DynamicSwapProverClient::new();
    let open = open();
    let proof = client
        .prove_escrow_open(&open)
        .expect("prove using escrow open key file");
    escrow_open::Verifier {
        proof: &proof.to_compressed(),
        public_inputs: escrow_open_public_inputs(&open),
        private_tx_hash: &bytes(&open.private.private_tx_hash),
        transfers: &[],
    }
    .verify()
    .expect("the program verifies the SDK's escrow open proof");

    let withdraw = withdraw();
    let proof = client
        .prove_pool_withdraw(&withdraw)
        .expect("prove using withdrawal key file");
    pool_withdraw::Verifier {
        proof: &proof.to_compressed(),
        public_inputs: pool_withdraw_public_inputs(&withdraw),
        private_tx_hash: &bytes(&withdraw.private.private_tx_hash),
        transfers: &[],
    }
    .verify()
    .expect("the program verifies the SDK's withdrawal proof");

    let rebalance = rebalance();
    let proof = client
        .prove_pool_rebalance(&rebalance)
        .expect("prove using rebalance key file");
    pool_rebalance::Verifier {
        proof: &proof.to_compressed(),
        public_inputs: pool_rebalance_public_inputs(&rebalance),
        private_tx_hash: &bytes(&rebalance.private.private_tx_hash),
        transfers: &[],
    }
    .verify()
    .expect("the program verifies the SDK's rebalance proof");
}
