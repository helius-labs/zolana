use borsh::BorshDeserialize;
use solana_address::Address;
use std::path::{Path, PathBuf};
use timelock_escrow_program::circuits::{Escrow, EscrowPrivateInputs, EscrowPublicInputs, EscrowTerms, Withdraw, WithdrawPrivateInputs, WithdrawPublicInputs, escrow_authority};
use zolana_keypair::{ShieldedKeypair, random_blinding};
use zolana_program::{InputRecords, ProgramProofInputs, Field, from_bytes, to_bytes};
use zolana_transaction::Mint;

#[allow(dead_code)]
#[path = "shared/mod.rs"]
mod shared;

fn artifacts(name: &str) -> PathBuf {
    std::env::var_os("ZOLANA_ZK_ARTIFACTS_DIR").map(PathBuf::from).unwrap_or_else(||
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../target/zk/timelock-escrow-program"))
        .join(name)
}

fn fixture(mint: Mint, real_inputs: usize) -> (Escrow, InputRecords, ShieldedKeypair, Address) {
    let creator = shared::keypair(5);
    let sender = creator.shielded_address().unwrap();
    let payer = sender.solana_address().unwrap();
    let authority = escrow_authority(&payer);
    let mut records = InputRecords::new();
    let mut wallets = Vec::new();
    for i in 0..real_inputs {
        let mut wallet = shared::token_input(&creator, 1000, i as u64);
        wallet.utxo.asset = mint;
        wallet.utxo_hash = wallet.utxo.hash(&sender.nullifier_pubkey, &[0; 32], &[0; 32], shared::TREE_ID).unwrap();
        wallet.nullifier = creator.nullifier(&wallet.utxo_hash, &wallet.utxo.blinding).unwrap();
        wallets.push(wallet);
    }
    let program = Escrow {
        private: EscrowPrivateInputs {
            tx_context: InputRecords::context(&random_blinding(), None).unwrap(),
            token_utxos_asset_a: records.utxos(&wallets).unwrap(),
            unlock: 1_700_000_000u64, amount: 250u64,
        },
        public: EscrowPublicInputs {
            escrow_owner: records.address(&authority.address(creator.viewing_pubkey()).unwrap()).unwrap(),
            creator_identity: from_bytes(&zolana_hasher::primitives::solana_owner_identity(payer.as_array()).unwrap()).unwrap(),
        },
    };
    (program, records, creator, payer)
}

fn proof(circuit: &xark::prover::Circuit, artifacts: &Path, inputs: zolana_program::ProgramProofInputs, public_hash: [u8; 32]) {
    if let Some(directory) = std::env::var_os("ZOLANA_ZK_FIXTURE_DIR") {
        let directory = PathBuf::from(directory);
        std::fs::create_dir_all(&directory).unwrap();
        let name = artifacts.file_name().unwrap().to_str().unwrap();
        std::fs::write(directory.join(format!("{name}.json")), serde_json::to_vec_pretty(&inputs.to_json()).unwrap()).unwrap();
    }
    circuit.check_constrained(inputs.clone()).unwrap();
    let result = circuit.prove(inputs).unwrap();
    let proof = zolana_program::proof::compressed_proof(&result.proof).unwrap();
    let key = zolana_program::proof::SolanaVerifyingKey::from_xark(&std::fs::read(artifacts.join("vk.bin")).unwrap()).unwrap();
    zolana_program::verifier::verify_groth16(&proof, public_hash, &key.as_key()).unwrap();
    let mut changed = public_hash;
    changed[31] ^= 1;
    assert_eq!(zolana_program::verifier::verify_groth16(&proof, changed, &key.as_key()), Err(zolana_program::verifier::VerifyError::Proof));
}

#[test]
fn sol_and_spl_escrow_then_withdraw_keep_the_spp_commitments() {
    for mint in [Mint::SOL, Mint::new(Address::new_from_array([7; 32]), 2)] {
        let (escrow, records, creator, payer) = fixture(mint, 2);
        let sender = creator.shielded_address().unwrap();
        let transaction = records.create_program_transaction(&escrow, escrow.execute().unwrap(), &sender, payer).unwrap();
        proof(&xark::prover::circuit_at(artifacts("escrow")), &artifacts("escrow"), transaction.proof_inputs, transaction.public_hash);
        let outputs = transaction.finalized.output_utxos();
        assert_eq!(outputs.iter().map(|output| output.amount).collect::<Vec<_>>(), vec![1750, 250]);
        let terms = EscrowTerms::try_from_slice(outputs[1].data.utxo_data().unwrap()).unwrap();
        let authority = escrow_authority(&payer);
        let mut wallet = authority.input(&outputs[1], transaction.finalized.output_tree_id(), 2).unwrap();
        wallet.latest_tree_id = Some(shared::TREE_ID);
        let mut records = InputRecords::new();
        records.address(&sender).unwrap();
        let withdraw = Withdraw {
            private: WithdrawPrivateInputs { tx_context: InputRecords::context(&random_blinding(), None).unwrap(), escrow: records.utxo(&wallet).unwrap(), terms: terms.clone() },
            public: WithdrawPublicInputs { unlock: terms.unlock, creator_identity: escrow.public.creator_identity },
        };
        let tx = records.create_program_transaction(&withdraw, withdraw.execute().unwrap(), &sender, payer).unwrap();
        proof(&xark::prover::circuit_at(artifacts("withdraw")), &artifacts("withdraw"), tx.proof_inputs, tx.public_hash);
        assert_eq!(tx.finalized.output_utxos()[0].amount, 250);
    }
}

fn check(program: &Escrow, public_hash: Field) -> Result<(), xark::prover::ProveError> {
    xark::prover::circuit_at(artifacts("escrow")).check(ProgramProofInputs::new(program, public_hash))
}

#[test]
fn compiled_escrow_refuses_wrong_signer_excess_amount_and_changed_public_hash() {
    let (mut program, _, _, _) = fixture(Mint::SOL, 1);
    let public_hash = program.execute().unwrap().public_hash().to_owned();
    check(&program, public_hash).unwrap();
    assert!(check(&program, public_hash + xark::Field::one()).is_err());
    program.public.creator_identity += Field::from(1u64);
    assert!(check(&program, public_hash).is_err());
    program.public.creator_identity -= Field::from(1u64);
    program.private.amount = 1001u64;
    assert!(check(&program, public_hash).is_err());
}

#[test]
fn one_through_five_real_inputs_match_the_compiled_circuit() {
    for n in 1..=5 {
        let (program, records, creator, payer) = fixture(Mint::SOL, n);
        let tx = records.create_program_transaction(&program, program.execute().unwrap(), &creator.shielded_address().unwrap(), payer).unwrap();
        xark::prover::circuit_at(artifacts("escrow")).check(tx.proof_inputs).unwrap();
        assert_eq!(tx.finalized.padding_independent_private_tx_hash().unwrap(), to_bytes(program.execute().unwrap().private_tx_hash()));
    }
}

#[test]
fn leading_and_interspersed_dummy_slots_keep_real_input_order() {
    let (mut program, records, creator, payer) = fixture(Mint::SOL, 2);
    let real = program.private.token_utxos_asset_a.padded();
    program.private.token_utxos_asset_a = zolana_program::ArrayVec::new([
        zolana_program::circuit::Utxo::dummy(), real[0], zolana_program::circuit::Utxo::dummy(), real[1],
    ]).unwrap();
    let tx = records.create_program_transaction(&program, program.execute().unwrap(), &creator.shielded_address().unwrap(), payer).unwrap();
    xark::prover::circuit_at(artifacts("escrow")).check_constrained(tx.proof_inputs).unwrap();
    assert_eq!(tx.finalized.output_utxos().iter().map(|output| output.amount).collect::<Vec<_>>(), vec![1750, 250]);
}
