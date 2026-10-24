use dynamic_swap_program::{
    circuits::{
        EscrowOpen, EscrowOpenPrivateInputs, EscrowOpenPublicInputs, PoolRebalance,
        PoolRebalancePrivateInputs, PoolRebalancePublicInputs, PoolWithdraw,
        PoolWithdrawPrivateInputs, PoolWithdrawPublicInputs, ProofInputUtxo,
    },
    instructions::shared::u64_right_align,
};
use dynamic_swap_sdk::state::order_data_hash;
use zolana_program::ZkCircuit;
use zolana_transaction::instructions::transact::PrivateTxHash;

fn value(n: u64) -> [u8; 32] {
    u64_right_align(n)
}

fn note(owner: u64, amount: u64, booked: u64) -> ProofInputUtxo {
    ProofInputUtxo {
        domain: value(u64::from(zolana_interface::UTXO_DOMAIN)),
        tree_id: value(3),
        owner_hash: value(owner),
        asset: value(4),
        amount: value(amount),
        blinding: value(5),
        data_hash: value(booked),
        ..Default::default()
    }
}

fn refresh_open(circuit: &mut EscrowOpen) {
    let private = &mut circuit.private;
    private.private_tx_hash = PrivateTxHash::new(
        &[private.source_in.hash().unwrap()],
        &[
            private.order_out.hash().unwrap(),
            private.taker_change.hash().unwrap(),
        ],
        &private.private_tx_blinding,
    )
    .hash()
    .unwrap();
}

fn open() -> EscrowOpen {
    let mut order_out = note(2, 10, 0);
    order_out.data_hash = order_data_hash(&value(1), 5).unwrap();
    let mut circuit = EscrowOpen {
        private: EscrowOpenPrivateInputs {
            private_tx_hash: [0; 32],
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
    good.check_constraints().expect("valid escrow open");
    for attack in 0..13 {
        let mut circuit = good.clone();
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
            circuit.check_constraints().is_err(),
            "accepted escrow open attack {attack}"
        );
    }
}

fn refresh_withdraw(circuit: &mut PoolWithdraw) {
    let private = &mut circuit.private;
    private.private_tx_hash = PrivateTxHash::new(
        &[private.pool_in.hash().unwrap()],
        &[private.pool_out.hash().unwrap()],
        &private.private_tx_blinding,
    )
    .hash()
    .unwrap();
}

fn withdraw() -> PoolWithdraw {
    let mut circuit = PoolWithdraw {
        private: PoolWithdrawPrivateInputs {
            private_tx_hash: [0; 32],
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
    good.check_constraints().expect("valid withdrawal");
    for attack in 0..8 {
        let mut circuit = good.clone();
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
            circuit.check_constraints().is_err(),
            "accepted withdrawal attack {attack}"
        );
    }
}

fn refresh_rebalance(circuit: &mut PoolRebalance) {
    let private = &mut circuit.private;
    let hash = |note: &ProofInputUtxo| {
        if note.domain == value(u64::from(zolana_interface::DUMMY_DOMAIN)) {
            [0; 32]
        } else {
            note.hash().unwrap()
        }
    };
    let inputs: Vec<_> = private.inputs.iter().map(hash).collect();
    let outputs: Vec<_> = private.outputs.iter().map(hash).collect();
    private.private_tx_hash = PrivateTxHash::new(&inputs, &outputs, &private.private_tx_blinding)
        .hash()
        .unwrap();
}

fn rebalance() -> PoolRebalance {
    let mut inputs = std::array::from_fn(|_| ProofInputUtxo {
        domain: value(u64::from(zolana_interface::DUMMY_DOMAIN)),
        ..Default::default()
    });
    inputs[0] = note(2, 100, 60);
    inputs[1] = note(2, 50, 20);
    let mut outputs = std::array::from_fn(|_| ProofInputUtxo {
        domain: value(u64::from(zolana_interface::DUMMY_DOMAIN)),
        ..Default::default()
    });
    outputs[0] = note(2, 150, 100);
    let mut circuit = PoolRebalance {
        private: PoolRebalancePrivateInputs {
            private_tx_hash: [0; 32],
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
    good.check_constraints().expect("valid padded rebalance");
    for attack in 0..10 {
        let mut circuit = good.clone();
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
            circuit.check_constraints().is_err(),
            "accepted rebalance attack {attack}"
        );
    }
}

#[test]
fn native_circuits_bind_the_private_transaction_hash() {
    let mut open = open();
    open.private.private_tx_hash = value(1);
    assert!(
        open.check_constraints().is_err(),
        "escrow open accepted another transaction"
    );
    let mut withdraw = withdraw();
    withdraw.private.private_tx_hash = value(1);
    assert!(
        withdraw.check_constraints().is_err(),
        "withdrawal accepted another transaction"
    );
    let mut rebalance = rebalance();
    rebalance.private.private_tx_hash = value(1);
    assert!(
        rebalance.check_constraints().is_err(),
        "rebalance accepted another transaction"
    );
}

#[test]
fn native_open_withdraw_and_rebalance_proofs_verify_with_program_keys() {
    use dynamic_swap_program::verifier::{escrow_open, pool_rebalance, pool_withdraw};
    use std::sync::OnceLock;
    use zolana_program::{verifier::verify_groth16, CompressedProof, Groth16Prover};

    let open = open();
    static OPEN_PROVER: OnceLock<Groth16Prover<EscrowOpen>> = OnceLock::new();
    let prover = OPEN_PROVER.get_or_init(|| Groth16Prover::new_with_test_setup().unwrap());
    let proof = prover.prove(&open).expect("prove escrow open");
    let hash = escrow_open::PublicInputs {
        escrow_authority_owner_hash: open.public.escrow_authority_owner_hash,
        source_asset: open.public.source_asset,
        public_price_floor: open.public.public_price_floor,
        price_tolerance: open.public.price_tolerance,
        min_order_amount: open.public.min_order_amount,
        max_order_size: open.public.max_order_size,
    }
    .hash(&open.private.private_tx_hash)
    .unwrap();
    verify_groth16(
        &CompressedProof::try_from(&proof.proof).unwrap(),
        hash,
        &escrow_open::VERIFYINGKEY,
    )
    .expect("the program verifies the native escrow open proof");

    let withdraw = withdraw();
    static WITHDRAW_PROVER: OnceLock<Groth16Prover<PoolWithdraw>> = OnceLock::new();
    let prover = WITHDRAW_PROVER.get_or_init(|| Groth16Prover::new_with_test_setup().unwrap());
    let proof = prover.prove(&withdraw).expect("prove withdrawal");
    let hash = pool_withdraw::PublicInputs {
        pool_authority_owner_hash: withdraw.public.pool_authority_owner_hash,
        destination_asset: withdraw.public.destination_asset,
        amount: withdraw.public.amount,
    }
    .hash(&withdraw.private.private_tx_hash)
    .unwrap();
    verify_groth16(
        &CompressedProof::try_from(&proof.proof).unwrap(),
        hash,
        &pool_withdraw::VERIFYINGKEY,
    )
    .expect("the program verifies the native withdrawal proof");

    let rebalance = rebalance();
    static REBALANCE_PROVER: OnceLock<Groth16Prover<PoolRebalance>> = OnceLock::new();
    let prover = REBALANCE_PROVER.get_or_init(|| Groth16Prover::new_with_test_setup().unwrap());
    let proof = prover.prove(&rebalance).expect("prove rebalance");
    let hash = pool_rebalance::PublicInputs {
        pool_authority_owner_hash: rebalance.public.pool_authority_owner_hash,
        destination_asset: rebalance.public.destination_asset,
        credit: rebalance.public.credit,
    }
    .hash(&rebalance.private.private_tx_hash)
    .unwrap();
    verify_groth16(
        &CompressedProof::try_from(&proof.proof).unwrap(),
        hash,
        &pool_rebalance::VERIFYINGKEY,
    )
    .expect("the program verifies the native rebalance proof");
}

// The scalar-field representation of -1 satisfies the subtraction equality;
// the explicit u64 range constraint must reject it.
const FIELD_NEGATIVE_ONE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x00,
];

#[test]
fn escrow_open_rejects_field_wrapped_change_after_source_underflow() {
    let mut circuit = open();
    circuit.private.source_in.amount = value(9);
    circuit.private.taker_change.amount = FIELD_NEGATIVE_ONE;
    refresh_open(&mut circuit);
    let error = circuit.check_constraints().unwrap_err();
    assert!(
        error
            .to_string()
            .contains("the order exceeds the source amount"),
        "unexpected rejection of field-wrapped change: {error}"
    );
}

#[test]
fn withdrawal_rejects_field_wrapped_balance_and_booked_underflow() {
    for booked_underflow in [false, true] {
        let mut circuit = withdraw();
        if booked_underflow {
            circuit.private.pool_in.data_hash = value(29);
            circuit.private.pool_out.data_hash = FIELD_NEGATIVE_ONE;
        } else {
            circuit.private.pool_in.amount = value(29);
            circuit.private.pool_out.amount = FIELD_NEGATIVE_ONE;
        }
        refresh_withdraw(&mut circuit);
        let error = circuit.check_constraints().unwrap_err();
        let expected = if booked_underflow {
            "the withdrawal exceeds the booked liquidity"
        } else {
            "the withdrawal exceeds the pool balance"
        };
        assert!(
            error.to_string().contains(expected),
            "unexpected rejection: {error}"
        );
    }
}

#[test]
fn rebalance_rejects_conserved_values_wider_than_u64() {
    let mut wide = [0; 32];
    wide[23] = 1; // 2^64, a valid scalar outside the token amount range.
    for wide_booked in [false, true] {
        let mut circuit = rebalance();
        circuit.private.inputs[1] = ProofInputUtxo {
            domain: value(u64::from(zolana_interface::DUMMY_DOMAIN)),
            ..Default::default()
        };
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
        let error = circuit.check_constraints().unwrap_err();
        let expected = if wide_booked {
            "a rebalance booked value overflows u64"
        } else {
            "a rebalance amount overflows u64"
        };
        assert!(
            error.to_string().contains(expected),
            "unexpected rejection: {error}"
        );
    }
}

#[test]
#[ignore = "run `just ensure-dynamic-swap-keys` first to create checked native proving keys"]
fn native_client_loads_checked_keys() {
    use dynamic_swap_program::verifier::{escrow_open, pool_rebalance, pool_withdraw};
    use dynamic_swap_sdk::prover::DynamicSwapProverClient;

    let client = DynamicSwapProverClient::new();
    let open = open();
    let proof = client
        .prove_escrow_open(&open)
        .expect("prove using escrow open key file");
    escrow_open::Verifier {
        proof: &proof.to_compressed(),
        public_inputs: escrow_open::PublicInputs {
            escrow_authority_owner_hash: open.public.escrow_authority_owner_hash,
            source_asset: open.public.source_asset,
            public_price_floor: open.public.public_price_floor,
            price_tolerance: open.public.price_tolerance,
            min_order_amount: open.public.min_order_amount,
            max_order_size: open.public.max_order_size,
        },
        private_tx_hash: &open.private.private_tx_hash,
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
        public_inputs: pool_withdraw::PublicInputs {
            pool_authority_owner_hash: withdraw.public.pool_authority_owner_hash,
            destination_asset: withdraw.public.destination_asset,
            amount: withdraw.public.amount,
        },
        private_tx_hash: &withdraw.private.private_tx_hash,
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
        public_inputs: pool_rebalance::PublicInputs {
            pool_authority_owner_hash: rebalance.public.pool_authority_owner_hash,
            destination_asset: rebalance.public.destination_asset,
            credit: rebalance.public.credit,
        },
        private_tx_hash: &rebalance.private.private_tx_hash,
        transfers: &[],
    }
    .verify()
    .expect("the program verifies the SDK's rebalance proof");
}
