use ark_relations::r1cs::SynthesisError;
use timelock_escrow_arkworks::{
    Escrow, EscrowPrivateInputs, EscrowPublicInputs, EscrowTerms, Withdraw, WithdrawPrivateInputs,
    WithdrawPublicInputs,
};
use timelock_escrow_sdk::escrow_authority;
use zk_program_sdk::{
    circuit::{value, Circuit, ConstraintSystem},
    conversion::{Allocator, ProofInput},
    ArkworksCircuit, RelationError, TxContext, ZkProgram,
};
use zolana_hasher::primitives::solana_owner_identity;
use zolana_keypair::ShieldedKeypair;

mod shared;
use shared::{escrow_utxo, keypair, token_input, TREE_ID};

fn native<P>(proof_inputs: P) -> Option<String>
where
    P: ProofInput + Clone,
    P::Circuit: Circuit,
{
    ArkworksCircuit::new(proof_inputs)
        .err()
        .map(|e| e.to_string())
}

fn r1cs_refuses<P>(proof_inputs: P) -> bool
where
    P: ProofInput + Clone,
    P::Circuit: Circuit,
{
    let cs = ConstraintSystem::new_ref();
    match proof_inputs
        .instantiate(&Allocator::R1cs(cs))
        .and_then(|circuit| circuit.circuit())
    {
        Err(RelationError::Synthesis(
            SynthesisError::AssignmentMissing | SynthesisError::DivisionByZero,
        )) => true,
        Err(error) => panic!("unexpected R1CS error: {error}"),
        Ok(checked) => ArkworksCircuit::with_public_hash(
            proof_inputs,
            value(checked.public_hash()).expect("own public hash"),
        )
        .check_constraints()
        .is_err(),
    }
}

fn encrypt<P: ZkProgram>(keys: &ShieldedKeypair, proof_inputs: P) -> Option<String> {
    let payer = keys
        .shielded_address()
        .expect("keys")
        .solana_address()
        .expect("payer");
    proof_inputs
        .create_proof_inputs_and_encrypt(keys, payer, u64::MAX)
        .err()
        .map(|e| e.to_string())
}

#[test]
fn escrow_names_every_broken_rule() {
    let creator = keypair(5);
    let address = creator.shielded_address().expect("creator address");
    let first = token_input(&creator, 600, 0);
    let honest = Escrow {
        private: EscrowPrivateInputs {
            tx_context: TxContext::new(first.nullifier, TREE_ID, address),
            token_utxos_asset_a: [first, token_input(&creator, 400, 1)],
            creator: address,
            unlock: 1_700_000_000,
            amount: 250,
        },
        public: EscrowPublicInputs {
            escrow_owner: escrow_authority()
                .address(address.viewing_pubkey)
                .expect("escrow owner"),
        },
    };
    let circuit = ArkworksCircuit::new(honest.clone()).expect("escrow circuit");

    let mut zero_amount = honest.clone();
    zero_amount.private.amount = 0;
    let mut other_owner = honest.clone();
    if let Some(second) = other_owner.private.token_utxos_asset_a.get_mut(1) {
        *second = token_input(&keypair(6), 400, 1);
    }
    let mut other_seed = honest.clone();
    other_seed.private.tx_context = other_seed.private.tx_context.with_blinding_seed([7u8; 32]);
    let mut other_first_nullifier = honest.clone();
    other_first_nullifier.private.tx_context = TxContext::new([7u8; 32], TREE_ID, address);
    let stranger = keypair(6);
    let mut unnamed_change_owner = honest.clone();
    unnamed_change_owner.private.creator = stranger.shielded_address().expect("stranger");
    unnamed_change_owner.private.tx_context.sender = stranger.shielded_address().expect("stranger");
    let mut overspend = honest.clone();
    overspend.private.amount = 1_100;

    assert_eq!(
        (
            native(zero_amount.clone()),
            native(other_owner.clone()),
            encrypt(&creator, other_first_nullifier),
            encrypt(&stranger, unnamed_change_owner),
            encrypt(&creator, overspend),
            encrypt(&stranger, honest.clone()),
            circuit.check_constraints().is_ok(),
            r1cs_refuses(honest),
            r1cs_refuses(zero_amount),
            r1cs_refuses(other_owner),
            ArkworksCircuit::new(other_seed)
                .expect("another seed is a valid transaction")
                .public_hash()
                == circuit.public_hash(),
        ),
        (
            Some("the escrow locks nothing".to_string()),
            Some("the inputs belong to different owners".to_string()),
            Some("the first nullifier is not slot 0's".to_string()),
            Some("output slot 0 has an owner no input names".to_string()),
            Some("output slot 0 has an amount that does not fit in u64".to_string()),
            Some("the keys are not the transaction's sender".to_string()),
            true,
            false,
            true,
            true,
            false,
        )
    );
}

#[test]
fn withdraw_names_every_broken_rule() {
    let creator = keypair(5);
    let address = creator.shielded_address().expect("creator address");
    let escrow = escrow_utxo(&creator, 250, 1_700_000_000);
    let honest = Withdraw {
        private: WithdrawPrivateInputs {
            tx_context: TxContext::new(escrow.nullifier, TREE_ID, address),
            escrow,
            terms: EscrowTerms {
                creator: address.owner_hash().expect("creator owner hash"),
                unlock: 1_700_000_000,
            },
            creator: address,
            creator_nullifier_pk: address.nullifier_pubkey,
        },
        public: WithdrawPublicInputs {
            unlock: 1_700_000_000,
            owner_identity: solana_owner_identity(
                address.solana_address().expect("creator").as_array(),
            )
            .expect("owner identity"),
        },
    };
    let circuit = ArkworksCircuit::new(honest.clone()).expect("withdraw circuit");

    let other_signer = keypair(6)
        .shielded_address()
        .expect("other")
        .solana_address()
        .expect("other solana address");
    let mut other_identity = honest.clone();
    other_identity.public.owner_identity =
        solana_owner_identity(other_signer.as_array()).expect("other identity");
    let mut other_unlock = honest.clone();
    other_unlock.public.unlock = 1_700_000_001;
    let mut other_terms = honest.clone();
    other_terms.private.terms.unlock = 1_700_000_001;

    assert_eq!(
        (
            native(other_identity.clone()),
            native(other_unlock.clone()),
            native(other_terms),
            circuit.check_constraints().is_ok(),
            r1cs_refuses(honest),
            r1cs_refuses(other_identity),
            r1cs_refuses(other_unlock),
        ),
        (
            Some("the signer is not the escrow creator".to_string()),
            Some("the unlock time is not the escrow's".to_string()),
            Some("the input does not commit to its program state".to_string()),
            true,
            false,
            true,
            true,
        )
    );
}
