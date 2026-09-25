use circuit_lib::{
    constant,
    convert::{utxo, var},
    ArkworksCircuit, Field, ProofInput, U64,
};
use timelock_escrow_arkworks::client::{self, EscrowTerms};
use zolana_client::ProofInputUtxo;
use zolana_hasher::primitives::solana_owner_identity;

mod shared;
use shared::{escrow_utxo, keypair, token_input, TREE_ID};

fn native<P>(proof_inputs: P) -> String
where
    P: ProofInput + Clone,
    P::Circuit: circuit_lib::Circuit,
{
    ArkworksCircuit::new(proof_inputs)
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default()
}

fn r1cs_refuses<P>(proof_inputs: P) -> bool
where
    P: ProofInput + Clone,
    P::Circuit: circuit_lib::Circuit,
{
    ArkworksCircuit::unchecked(proof_inputs)
        .and_then(|circuit| circuit.check_constraints())
        .is_err()
}

#[test]
fn escrow_names_every_broken_rule() {
    let creator = keypair(5);
    let address = creator.shielded_address().expect("creator address");
    let honest = client::Escrow {
        creator: address,
        token_utxos_asset_a: [token_input(&creator, 600, 0), token_input(&creator, 400, 1)],
        amount: 250,
        unlock: 1_700_000_000,
        payer: address.solana_address().expect("payer"),
        output_tree_id: TREE_ID,
    }
    .build(&creator)
    .expect("escrow transaction")
    .proof_inputs;

    let mut zero_amount = honest.clone();
    zero_amount.private.amount = U64::from(0u64);
    let mut too_wide = honest.clone();
    too_wide.private.amount = U64::new(constant(Field::from(u64::MAX) + Field::from(1u64)));
    let mut other_seed = honest.clone();
    other_seed.private.tx_context.blinding_seed = var(&[7u8; 32], "seed").expect("seed");
    let mut other_owner = honest.clone();
    if let Some(second) = other_owner.private.token_utxos_asset_a.get_mut(1) {
        *second = utxo(
            &ProofInputUtxo::try_from(&token_input(&keypair(6), 400, 1)).expect("proof input"),
        )
        .expect("utxo");
    }

    assert_eq!(
        (
            native(honest.clone()),
            native(zero_amount.clone()),
            native(too_wide),
            native(other_seed.clone()),
            native(other_owner.clone()),
            r1cs_refuses(zero_amount),
            r1cs_refuses(other_seed),
            r1cs_refuses(other_owner),
            r1cs_refuses(honest),
        ),
        (
            String::new(),
            "the escrow locks nothing".to_string(),
            "a value does not fit in 64 bits".to_string(),
            "the public hash does not match".to_string(),
            "the inputs belong to different owners".to_string(),
            true,
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
    let honest = client::Withdraw {
        creator: address,
        escrow: escrow_utxo(&creator, 250, 1_700_000_000),
        terms: EscrowTerms {
            creator: address.owner_hash().expect("creator owner hash"),
            unlock: 1_700_000_000,
        },
        payer: address.solana_address().expect("payer"),
        output_tree_id: TREE_ID,
    }
    .build(&creator)
    .expect("withdraw transaction")
    .proof_inputs;

    let other_signer = keypair(6)
        .shielded_address()
        .expect("other")
        .solana_address()
        .expect("other solana address");
    let mut other_identity = honest.clone();
    other_identity.public.owner_identity = var(
        &solana_owner_identity(other_signer.as_array()).expect("identity"),
        "identity",
    )
    .expect("identity");
    let mut other_unlock = honest.clone();
    other_unlock.public.unlock = U64::from(1_700_000_001u64);
    let mut other_terms = honest.clone();
    other_terms.private.terms.unlock = constant(1_700_000_001u64);

    assert_eq!(
        (
            native(honest),
            native(other_identity.clone()),
            native(other_unlock.clone()),
            native(other_terms),
            r1cs_refuses(other_identity),
            r1cs_refuses(other_unlock),
        ),
        (
            String::new(),
            "the signer is not the escrow creator".to_string(),
            "the unlock time is not the escrow's".to_string(),
            "the input does not commit to its program state".to_string(),
            true,
            true,
        )
    );
}

#[test]
fn the_client_refuses_before_any_proof() {
    let creator = keypair(5);
    let address = creator.shielded_address().expect("creator address");
    let escrow = escrow_utxo(&creator, 250, 1_700_000_000);
    let withdraw_by = |signer, unlock| {
        client::Withdraw {
            creator: signer,
            escrow: escrow.clone(),
            terms: EscrowTerms {
                creator: address.owner_hash().expect("creator owner hash"),
                unlock,
            },
            payer: address.solana_address().expect("payer"),
            output_tree_id: TREE_ID,
        }
        .build(&creator)
        .map(|_| ())
        .map_err(|e| e.to_string())
    };

    assert_eq!(
        (
            withdraw_by(keypair(6).shielded_address().expect("other"), 1_700_000_000),
            withdraw_by(address, 1_700_000_001),
            client::Escrow {
                creator: address,
                token_utxos_asset_a: [token_input(&creator, 10, 0), token_input(&creator, 10, 1)],
                amount: 21,
                unlock: 1_700_000_000,
                payer: address.solana_address().expect("payer"),
                output_tree_id: TREE_ID,
            }
            .build(&creator)
            .map(|_| ())
            .map_err(|e| e.to_string()),
        ),
        (
            Err("the signer is not the escrow creator".to_string()),
            Err("the input does not commit to its program state".to_string()),
            Err("the transfers exceed the token balance".to_string()),
        )
    );
}
