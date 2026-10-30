use spr_circuit::protocol::{
    CheckedTransaction, ConfidentialTransaction, DataUtxo, PublicInputs, TokenUtxos, TxContext,
    Utxo, UtxoMeta, UtxoTrait,
};
use spr_circuit::{Field, SigningPubkey, UtxoOwner, nonzero_hash_chain, poseidon, to_bytes};
use spr_instruction::{
    DOMAIN_PRIVATE_TX_BLINDING_V1, DOMAIN_TRANSACT_OUTPUT_BLINDING_SEED_V1,
    DOMAIN_TRANSACT_OUTPUT_BLINDING_V1,
};

struct Public;
impl PublicInputs for Public {
    fn hash(&self, transaction_hash: &Field) -> Result<Field, spr_circuit::CircuitError> {
        poseidon(&[Field::from(31u64), *transaction_hash])
    }
}

fn context() -> TxContext {
    TxContext {
        blinding_seed: Field::from(11u64),
        output_tree_id: 17,
        uses_output_tree_id: true,
    }
}

fn owner(seed: u8) -> UtxoOwner {
    UtxoOwner::new(
        SigningPubkey::new(0x53, [seed; 32]),
        Field::from(seed as u64 + 1),
    )
}

fn input(seed: u8) -> Utxo {
    Utxo {
        owner: owner(seed),
        asset: [seed + 1; 32],
        amount: 100,
        blinding: Field::from(23u64),
        meta: UtxoMeta {
            nullifier: Field::from(29u64),
            ..UtxoMeta::default()
        },
        ..Utxo::default()
    }
}

fn assert_uncached_hashes(checked: &CheckedTransaction) {
    let first = checked.first_nullifier;
    let seed = checked.blinding_seed;
    let output_seed = poseidon(&[
        Field::from(DOMAIN_TRANSACT_OUTPUT_BLINDING_SEED_V1),
        first,
        seed,
    ])
    .unwrap();
    let output_hashes: Vec<_> = checked
        .outputs
        .iter()
        .enumerate()
        .map(|(slot, output)| {
            let blinding = poseidon(&[
                Field::from(DOMAIN_TRANSACT_OUTPUT_BLINDING_V1),
                first,
                output_seed,
                Field::from(slot as u64),
            ])
            .unwrap();
            let uncached = output
                .output
                .hash(output.empty, blinding, checked.output_tree_id)
                .unwrap();
            assert_eq!(to_bytes(&output.hash), to_bytes(&uncached), "output {slot}");
            if output.empty {
                Field::zero()
            } else {
                uncached
            }
        })
        .collect();
    let addresses: Vec<_> = checked
        .addresses
        .iter()
        .map(|address| address.address)
        .collect();
    let private_blinding =
        poseidon(&[Field::from(DOMAIN_PRIVATE_TX_BLINDING_V1), first, seed]).unwrap();
    let private_hash = poseidon(&[
        nonzero_hash_chain(&checked.inputs).unwrap(),
        nonzero_hash_chain(&output_hashes).unwrap(),
        nonzero_hash_chain(&addresses).unwrap(),
        private_blinding,
    ])
    .unwrap();
    let transaction_hash = if checked.public_transfers.is_empty() {
        private_hash
    } else {
        let transfer_chain = checked
            .public_transfers
            .iter()
            .fold(Field::zero(), |chain, transfer| {
                poseidon(&[chain, transfer.hash().unwrap()]).unwrap()
            });
        poseidon(&[private_hash, transfer_chain]).unwrap()
    };
    let expected = [
        private_hash,
        transaction_hash,
        Public.hash(&transaction_hash).unwrap(),
    ]
    .map(|hash| to_bytes(&hash));
    let actual = [
        *checked.private_tx_hash(),
        *checked.transaction_hash(),
        *checked.public_hash(),
    ]
    .map(|hash| to_bytes(&hash));
    assert_eq!(
        actual, expected,
        "transaction hashes must match uncached hashing"
    );
}

#[test]
fn token_change_and_recipient_outputs_match_uncached_hashes() {
    let input = input(7);
    let mut source = TokenUtxos::new_mut(&[input]).unwrap();
    let mut recipient = TokenUtxos::new_init(&owner(9), &input.asset);
    source.transfer(&mut recipient, &37).unwrap();
    let checked = ConfidentialTransaction::new(&context(), &Public)
        .with(source)
        .with(recipient)
        .check()
        .unwrap();
    assert_eq!(
        checked.inputs.iter().map(to_bytes).collect::<Vec<_>>(),
        vec![to_bytes(&input.hash().unwrap())]
    );
    assert_uncached_hashes(&checked);
}

#[test]
fn optional_dummy_inputs_can_replace_the_owner_and_asset() {
    let mut tokens = TokenUtxos::new_mut(&[Utxo::dummy()])
        .unwrap()
        .with_optional(&owner(19), &[21; 32]);
    tokens.deposit(&47, &[22; 32]).unwrap();
    let checked = ConfidentialTransaction::new(&context(), &Public)
        .with(tokens)
        .check()
        .unwrap();
    assert_uncached_hashes(&checked);
}

#[test]
fn data_update_matches_the_original_spent_input_and_uncached_output() {
    let mut input = input(13);
    input.data_hash = Field::from(53u64);
    let mut state = DataUtxo::new_mut_with_hash(&input, &input.data_hash).unwrap();
    *state = Field::from(59u64);
    state.withdraw(&7, &[23; 32]).unwrap();
    let checked = ConfidentialTransaction::new(&context(), &Public)
        .with(state)
        .check()
        .unwrap();
    assert_eq!(
        checked.inputs.iter().map(to_bytes).collect::<Vec<_>>(),
        vec![to_bytes(&input.hash().unwrap())]
    );
    assert_uncached_hashes(&checked);
}

#[test]
fn token_inputs_reject_nondefault_ring_preimages() {
    for dummy in [false, true] {
        for (data_hash, program_id) in
            [(Field::one(), Field::zero()), (Field::zero(), Field::one())]
        {
            let rejected = std::panic::catch_unwind(|| {
                let input = Utxo {
                    ring_data_hash: data_hash,
                    ring_program_id: program_id,
                    ..if dummy { Utxo::dummy() } else { input(7) }
                };
                let _ = TokenUtxos::new_mut(&[input]).unwrap();
            });
            assert!(rejected.is_err());
        }
    }
}

#[test]
fn data_inputs_reject_nondefault_ring_preimages() {
    for (data_hash, program_id) in [(Field::one(), Field::zero()), (Field::zero(), Field::one())] {
        let rejected = std::panic::catch_unwind(|| {
            let input = Utxo {
                ring_data_hash: data_hash,
                ring_program_id: program_id,
                ..input(7)
            };
            let _ = DataUtxo::new_mut_with_hash(&input, &input.data_hash).unwrap();
        });
        assert!(rejected.is_err());
    }
}
