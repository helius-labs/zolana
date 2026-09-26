use ark_relations::r1cs::SynthesisError;
use timelock_escrow_arkworks::escrow_authority;
use timelock_escrow_arkworks::{
    Escrow, EscrowPrivateInputs, EscrowPublicInputs, EscrowTerms, Withdraw, WithdrawPrivateInputs,
    WithdrawPublicInputs,
};
use zk_program_sdk::{
    circuit::{Circuit, ConstraintSystem},
    conversion::{to_bytes, Allocator, ProofInput},
    Owner, RelationError, TxContext, ZkProgram,
};
use zolana_hasher::primitives::solana_owner_identity;
use zolana_keypair::ShieldedKeypair;

mod shared;
use shared::{escrow_utxo, keypair, token_input, token_inputs};

fn native<P>(proof_inputs: &P) -> Option<String>
where
    P: ProofInput,
    P::Circuit: Circuit,
{
    proof_inputs
        .instantiate(&Allocator::native())
        .and_then(|circuit| circuit.circuit())
        .err()
        .map(|e| e.to_string())
}

fn native_public_hash<P>(proof_inputs: &P) -> [u8; 32]
where
    P: ProofInput,
    P::Circuit: Circuit,
{
    let checked = proof_inputs
        .instantiate(&Allocator::native())
        .and_then(|circuit| circuit.circuit())
        .expect("native circuit");
    to_bytes(checked.public_hash()).expect("public hash")
}

fn r1cs_refuses<P>(proof_inputs: &P) -> bool
where
    P: ProofInput,
    P::Circuit: Circuit,
{
    let cs = ConstraintSystem::new_ref();
    match proof_inputs
        .instantiate(&Allocator::R1cs(cs.clone()))
        .and_then(|circuit| circuit.circuit())
    {
        Err(RelationError::Synthesis(
            SynthesisError::AssignmentMissing | SynthesisError::DivisionByZero,
        )) => true,
        Err(error) => panic!("unexpected R1CS error: {error}"),
        Ok(_) => !cs.is_satisfied().expect("satisfiability"),
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
            tx_context: TxContext::new(),
            token_utxos_asset_a: token_inputs([first, token_input(&creator, 400, 1)]),
            unlock: 1_700_000_000,
            amount: 250,
        },
        public: EscrowPublicInputs {
            escrow_owner: escrow_authority()
                .address(address.viewing_pubkey)
                .expect("escrow owner"),
        },
    };

    let mut zero_amount = honest.clone();
    zero_amount.private.amount = 0;
    let mut other_owner = honest.clone();
    if let Some(second) = other_owner.private.token_utxos_asset_a.get_mut(1) {
        *second = token_input(&keypair(6), 400, 1);
    }
    let mut other_seed = honest.clone();
    other_seed.private.tx_context = other_seed.private.tx_context.with_blinding_seed([7u8; 32]);
    let stranger = keypair(6);
    let mut overspend = honest.clone();
    overspend.private.amount = 1_100;

    assert_eq!(
        (
            native(&zero_amount),
            native(&other_owner),
            encrypt(&stranger, honest.clone()),
            encrypt(&creator, overspend),
            honest.check_constraints().is_ok(),
            r1cs_refuses(&honest),
            r1cs_refuses(&zero_amount),
            r1cs_refuses(&other_owner),
            native_public_hash(&other_seed) == native_public_hash(&honest),
        ),
        (
            Some("the escrow locks nothing".to_string()),
            Some("the inputs belong to different owners".to_string()),
            Some("output slot 0 has an owner no input names".to_string()),
            Some("the transfer exceeds the balance".to_string()),
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
            tx_context: TxContext::new(),
            escrow,
            terms: EscrowTerms {
                creator: Owner::try_from(&address).expect("creator owner"),
                unlock: 1_700_000_000,
            },
        },
        public: WithdrawPublicInputs {
            unlock: 1_700_000_000,
            owner_identity: solana_owner_identity(
                address.solana_address().expect("creator").as_array(),
            )
            .expect("owner identity"),
        },
    };

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
            native(&other_identity),
            native(&other_unlock),
            native(&other_terms),
            honest.check_constraints().is_ok(),
            r1cs_refuses(&honest),
            r1cs_refuses(&other_identity),
            r1cs_refuses(&other_unlock),
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
