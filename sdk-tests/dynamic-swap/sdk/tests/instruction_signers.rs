use dynamic_swap_sdk::{
    escrow_authority_pda, escrow_pda,
    instructions::{create_escrow::CreateEscrow, deposit_liquidity::DepositLiquidity},
    pool_authority_pda, Groth16ProofBytes,
};
use solana_pubkey::Pubkey;
use zolana_interface::{
    instruction::instruction_data::transact::{TransactIxData, TransactProof},
    verifying_keys::CircuitId,
};
use zolana_keypair::{PublicKey, ShieldedAddress, ShieldedKeypair};
use zolana_program::instruction::Transact;
use zolana_transaction::{
    instructions::transact::{ExternalData, SppProofInputs, SppProofOutputUtxo},
    utxo::SppProofInputUtxo,
};

#[test]
fn cpi_accounts_match_proof_owner_signers_including_the_paying_owner() {
    let owner = ShieldedKeypair::new_ed25519().unwrap();
    let payer = Pubkey::new_from_array(owner.signing_pubkey().confidential_view_tag().unwrap());
    let pair = Pubkey::new_unique();
    let tree = Pubkey::new_unique();
    let proof = Groth16ProofBytes {
        proof_a: [0; 32],
        proof_b: [0; 64],
        proof_c: [0; 32],
    };
    let transact = TransactIxData {
        expiry_unix_ts: u64::MAX,
        private_tx_hash: [0; 32],
        circuit: CircuitId::ConfidentialEddsa(1, 2, 0),
        tx_viewing_pk: *owner.viewing_pubkey().as_bytes(),
        salt: [0; 16],
        proof: TransactProof::zeroed(),
        inputs: vec![],
        tree_contexts: vec![],
        interface_transfers: vec![],
        data_hash: None,
        ring_data_hash: None,
        outputs: vec![],
        messages: vec![],
    };

    for deposit in [false, true] {
        let pda = if deposit {
            pool_authority_pda(&pair)
        } else {
            escrow_authority_pda(&pair)
        };
        // Only owner identities matter for signer assembly: a real paying
        // input followed by a data-bearing output owned by the program PDA.
        let mut input = SppProofInputUtxo::dummy(0).unwrap();
        input.utxo.owner = owner.signing_pubkey();
        input.utxo.amount = 1;
        let inputs = SppProofInputs {
            input_utxos: vec![input],
            output_utxos: vec![SppProofOutputUtxo {
                owner_address: Some(ShieldedAddress {
                    signing_pubkey: PublicKey::from_pda(&pda),
                    ..owner.shielded_address().unwrap()
                }),
                data_hash: Some([1; 32]),
                ..Default::default()
            }],
            payer,
            external_data: ExternalData::new([0; 33], [0; 16], vec![], vec![], vec![]),
            blinding_seed: [0; 32],
            output_tree_id: 0,
            cache_accounts: Default::default(),
        };
        let mut expected = Transact {
            payer,
            input_trees: vec![tree],
            output_tree: tree,
            owner_signers: inputs.owner_signer_pubkeys().unwrap(),
            interface_transfer_accounts: vec![],
            data: transact.clone(),
        }
        .instruction();
        for meta in &mut expected.accounts {
            if meta.pubkey == pda {
                meta.is_signer = false;
            }
        }

        let (instruction, prefix_len) = if deposit {
            (
                DepositLiquidity {
                    depositor: payer,
                    pair,
                    tree,
                    amount: 1,
                    proof,
                    transact: transact.clone(),
                }
                .instruction()
                .unwrap(),
                1,
            )
        } else {
            (
                CreateEscrow {
                    taker: payer,
                    pair,
                    escrow: escrow_pda(&pair, 0),
                    tree,
                    proof,
                    public_price_floor: 1,
                    transact: transact.clone(),
                }
                .instruction()
                .unwrap(),
                4,
            )
        };
        assert_eq!(
            instruction.accounts[prefix_len..],
            expected.accounts,
            "CPI accounts must match the proof's owner signer vector (deposit={deposit})"
        );
    }
}
