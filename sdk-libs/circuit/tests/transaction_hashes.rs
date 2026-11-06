use solana_address::Address;
use spr_circuit::protocol::{
    CheckedTransaction, ConfidentialTransaction, DataUtxo, PublicInputs, TokenUtxos, TxContext,
    Utxo, UtxoMeta, UtxoTrait,
};
use spr_circuit::{
    CircuitError, CircuitErrorKind, Field, SigningPubkey, UtxoOwner, checked, from_bytes, poseidon,
    to_bytes,
};
use spr_keypair::PublicKey;
use spr_transaction::{Data, Mint};

fn assert_rejected_by_ring_check(result: Result<(), CircuitError>) {
    let error = result.unwrap_err();
    assert!(
        matches!(error.kind(), CircuitErrorKind::RequirementFailed { file, .. } if file.ends_with("input_utxo.rs")),
        "expected the default-ring requirement, got {error}"
    );
}
use spr_instruction::{
    PrivateTxHash, derive_output_blinding_seed, derive_private_tx_blinding,
    derive_transact_output_blinding,
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

/// The wallet's commitment to a UTXO with this preimage and the default ring.
fn wallet_hash(utxo: &Utxo) -> [u8; 32] {
    let (_, key, nullifier_pk) = utxo.owner.preimage();
    spr_transaction::Utxo {
        owner: PublicKey::from_ed25519(&key),
        asset: Mint::new(Address::new_from_array(utxo.asset), 0),
        amount: utxo.amount,
        blinding: to_bytes(&utxo.blinding),
        ring_program_id: None,
        data: Data::default(),
    }
    .hash(
        &nullifier_pk,
        &to_bytes(&utxo.data_hash),
        &[0; 32],
        utxo.tree_id,
    )
    .unwrap()
}

/// Recomputes every output, the private transaction hash and the transaction
/// hash with the instruction crate's derivations and the wallet's commitments.
fn assert_canonical_hashes(checked: &CheckedTransaction) {
    let first = to_bytes(&checked.first_nullifier);
    let seed = to_bytes(&checked.blinding_seed);
    let output_seed = derive_output_blinding_seed(&first, &seed).unwrap();
    let outputs: Vec<_> = checked
        .outputs
        .iter()
        .zip(0u32..)
        .map(|(output, slot)| {
            if output.empty {
                return [0; 32];
            }
            let blinding = derive_transact_output_blinding(&first, &output_seed, slot).unwrap();
            let utxo = Utxo {
                owner: output.output.owner,
                asset: output.output.asset,
                amount: output.output.amount,
                blinding: from_bytes(&blinding).unwrap(),
                data_hash: output.output.data_hash,
                tree_id: checked.output_tree_id,
                ..Utxo::default()
            };
            let hash = wallet_hash(&utxo);
            assert_eq!(to_bytes(&output.hash), hash, "output {slot}");
            hash
        })
        .collect();
    let inputs: Vec<_> = checked.inputs.iter().map(to_bytes).collect();
    let addresses: Vec<_> = checked
        .addresses
        .iter()
        .map(|address| to_bytes(&address.address))
        .collect();
    let blinding = derive_private_tx_blinding(&first, &seed).unwrap();
    let private_tx_hash = PrivateTxHash {
        input_hashes: &inputs,
        output_hashes: &outputs,
        address_nullifiers: Some(&addresses),
        blinding: &blinding,
    }
    .hash()
    .unwrap();
    let transfers: Vec<_> = checked
        .public_transfers
        .iter()
        .map(|transfer| spr_instruction::PublicTransfer {
            mint: Address::new_from_array(transfer.asset),
            is_deposit: transfer.is_deposit,
            amount: transfer.amount,
            account: Address::new_from_array(transfer.account),
        })
        .collect();
    let transaction_hash = spr_instruction::transaction_hash(&private_tx_hash, &transfers).unwrap();
    assert_eq!(
        [
            to_bytes(checked.private_tx_hash()),
            to_bytes(checked.transaction_hash()),
            to_bytes(checked.public_hash()),
        ],
        [
            private_tx_hash,
            transaction_hash,
            to_bytes(
                &Public
                    .hash(&from_bytes(&transaction_hash).unwrap())
                    .unwrap()
            ),
        ],
        "transaction hashes must match the canonical hashing"
    );
}

#[test]
fn token_change_and_recipient_outputs_match_the_canonical_hashes() {
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
        vec![wallet_hash(&input)]
    );
    assert_canonical_hashes(&checked);
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
    assert_canonical_hashes(&checked);
}

#[test]
fn data_update_matches_the_original_spent_input_and_the_canonical_output() {
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
        vec![wallet_hash(&input)]
    );
    assert_canonical_hashes(&checked);
}

#[test]
fn token_inputs_reject_nondefault_ring_preimages() {
    for dummy in [false, true] {
        for (data_hash, program_id) in
            [(Field::one(), Field::zero()), (Field::zero(), Field::one())]
        {
            let input = Utxo {
                ring_data_hash: data_hash,
                ring_program_id: program_id,
                ..if dummy { Utxo::dummy() } else { input(7) }
            };
            assert_rejected_by_ring_check(checked(|| TokenUtxos::new_mut(&[input]).map(drop)));
        }
    }
}

#[test]
fn data_inputs_reject_nondefault_ring_preimages() {
    for (data_hash, program_id) in [(Field::one(), Field::zero()), (Field::zero(), Field::one())] {
        let input = Utxo {
            ring_data_hash: data_hash,
            ring_program_id: program_id,
            ..input(7)
        };
        assert_rejected_by_ring_check(checked(|| {
            DataUtxo::new_mut_with_hash(&input, &input.data_hash).map(drop)
        }));
    }
}
