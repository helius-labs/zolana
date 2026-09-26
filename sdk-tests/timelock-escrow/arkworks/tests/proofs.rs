use timelock_escrow_arkworks::escrow_authority;
use timelock_escrow_arkworks::{
    Escrow, EscrowPrivateInputs, EscrowPublicInputs, EscrowTerms, Withdraw, WithdrawPrivateInputs,
    WithdrawPublicInputs,
};
use timelock_escrow_program::instructions::{
    escrow::slot,
    verifier::{verify_groth16, CompressedGroth16Proof},
};
use zk_program_sdk::{
    CompressedProof, Groth16Keys, Groth16Prover, Owner, SolanaProof, TxContext, ZkProgram,
};
use zolana_hasher::{
    primitives::{right_align, solana_owner_identity},
    Hasher, Poseidon,
};

mod shared;
use shared::{escrow_utxo, keypair, token_input, token_inputs};

fn verify_groth16_accepts(proof: &SolanaProof, public_hash: [u8; 32], keys: &Groth16Keys) -> bool {
    let compressed = CompressedProof::try_from(proof).expect("compressed proof");
    verify_groth16(
        CompressedGroth16Proof {
            a: &compressed.a,
            b: &compressed.b,
            c: &compressed.c,
            commitment: None,
        },
        public_hash,
        &keys.verifying_key().into(),
    )
    .is_ok()
}

#[test]
fn escrow_proves_from_the_rust_circuit_with_matching_spp_proof_inputs() {
    let creator = keypair(5);
    let address = creator.shielded_address().expect("creator address");
    let first = token_input(&creator, 600, 0);
    let second = token_input(&creator, 400, 1);
    let escrow = Escrow {
        private: EscrowPrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: token_inputs([first, second]),
            unlock: 1_700_000_000,
            amount: 250,
        },
        public: EscrowPublicInputs {
            escrow_owner: escrow_authority()
                .address(address.viewing_pubkey)
                .expect("escrow owner"),
        },
    };

    let spp = escrow
        .create_proof_inputs_and_encrypt(
            &creator,
            address.solana_address().expect("payer"),
            u64::MAX,
        )
        .expect("escrow proof inputs");
    let private_tx_hash = spp
        .padding_independent_private_tx_hash()
        .expect("private tx hash");
    let prover = Groth16Prover::<Escrow>::new_with_test_setup().expect("escrow setup");
    let result = prover.prove(&escrow).expect("escrow proof");
    let public_hash = Poseidon::hashv(&[
        escrow_authority()
            .owner_hash()
            .expect("escrow owner hash")
            .as_slice(),
        private_tx_hash.as_slice(),
    ])
    .expect("public hash");
    let mut tampered = public_hash;
    tampered[31] ^= 1;
    let escrow_output = spp.output_utxos.get(slot::ESCROW).expect("escrow output");

    assert_eq!(
        (
            result.public_hash,
            verify_groth16_accepts(&result.proof, public_hash, prover.keys()),
            verify_groth16_accepts(&result.proof, tampered, prover.keys()),
            spp.output_utxos
                .iter()
                .map(|output| output.amount)
                .collect::<Vec<_>>(),
            escrow_output.owner_hash().expect("escrow output owner"),
            escrow_output.data.utxo_data().map(<[u8]>::to_vec),
        ),
        (
            public_hash,
            true,
            false,
            vec![750, 250],
            escrow_authority().owner_hash().expect("escrow owner hash"),
            Some(
                borsh::to_vec(&EscrowTerms {
                    creator: Owner::try_from(&address).expect("creator owner"),
                    unlock: 1_700_000_000,
                })
                .expect("escrow terms bytes")
            ),
        )
    );
}

#[test]
fn withdraw_proves_from_the_rust_circuit_with_matching_spp_proof_inputs() {
    let creator = keypair(5);
    let address = creator.shielded_address().expect("creator address");
    let escrow = escrow_utxo(&creator, 250, 1_700_000_000);
    let owner_identity =
        solana_owner_identity(address.solana_address().expect("creator").as_array())
            .expect("owner identity");
    let withdraw = Withdraw {
        private: WithdrawPrivateInputs {
            tx_context: TxContext::new(),
            escrow,
            terms: EscrowTerms {
                creator: Owner::try_from(&address).expect("creator owner"),
                unlock: 1_700_000_000,
            },
        },
        public: WithdrawPublicInputs {
            unlock: 1_700_000_000,
            owner_identity,
        },
    };

    let spp = withdraw
        .create_proof_inputs_and_encrypt(
            &creator,
            address.solana_address().expect("payer"),
            u64::MAX,
        )
        .expect("withdraw proof inputs");
    let private_tx_hash = spp
        .padding_independent_private_tx_hash()
        .expect("private tx hash");
    let prover = Groth16Prover::<Withdraw>::new_with_test_setup().expect("withdraw setup");
    let result = prover.prove(&withdraw).expect("withdraw proof");
    let public_hash = Poseidon::hashv(&[
        right_align(&1_700_000_000u64.to_be_bytes()).as_slice(),
        owner_identity.as_slice(),
        private_tx_hash.as_slice(),
    ])
    .expect("public hash");
    let payout = spp.output_utxos.first().expect("payout");

    assert_eq!(
        (
            result.public_hash,
            verify_groth16_accepts(&result.proof, public_hash, prover.keys()),
            (payout.amount, payout.owner_hash().expect("payout owner")),
            spp.input_utxos.first().map(|input| input.utxo.amount),
        ),
        (
            public_hash,
            true,
            (250, address.owner_hash().expect("creator owner hash")),
            Some(250),
        )
    );
}
