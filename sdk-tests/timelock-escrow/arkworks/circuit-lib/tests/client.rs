use anyhow::Result;
use circuit_lib::{
    client, constant,
    convert::{to_bytes, utxo, var},
    poseidon, zero, CircuitVar, ConfidentialTransaction, DataHash, DataUtxo, PublicInputs,
    RelationError, TokenUtxo,
};
use zolana_client::ProofInputUtxo;
use zolana_hasher::{Hasher, Poseidon};
use zolana_keypair::{random_blinding, ShieldedKeypair, SigningKey};
use zolana_transaction::{
    utxo::{SppProofInputUtxo, Utxo},
    Data, Mint,
};

const TREE_ID: u16 = 3;

fn keypair(seed: u8) -> ShieldedKeypair {
    ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[seed; 32])).unwrap()
}

fn input(owner: &ShieldedKeypair, amount: u64, data_hash: Option<[u8; 32]>) -> SppProofInputUtxo {
    let address = owner.shielded_address().unwrap();
    let utxo = Utxo {
        owner: owner.signing_pubkey(),
        asset: Mint::SOL,
        amount,
        blinding: random_blinding(),
        ring_program_id: None,
        data: Data::default(),
    };
    let utxo_hash = utxo
        .hash(
            &address.nullifier_pubkey,
            &data_hash.unwrap_or_default(),
            &[0u8; 32],
            TREE_ID,
        )
        .unwrap();
    let nullifier = owner.nullifier(&utxo_hash, &utxo.blinding).unwrap();
    SppProofInputUtxo {
        utxo,
        nullifier_pubkey: address.nullifier_pubkey,
        utxo_hash,
        nullifier,
        data_hash,
        ring_data_hash: None,
        tree_id: TREE_ID,
        leaf_index: 0,
        cache_slot: None,
    }
}

#[derive(Clone, Debug)]
struct Counter {
    value: CircuitVar,
}

impl Default for Counter {
    fn default() -> Self {
        Self { value: zero() }
    }
}

impl DataHash for Counter {
    fn hash(&self) -> Result<CircuitVar, RelationError> {
        poseidon(&[self.value.hash()?])
    }
}

#[derive(Clone, Debug, Default)]
struct ClientCounter {
    value: u64,
}

impl client::State for ClientCounter {
    type Circuit = Counter;

    fn circuit_state(&self) -> Result<Counter> {
        Ok(Counter {
            value: constant(self.value),
        })
    }

    fn utxo_data(&self) -> Vec<u8> {
        self.value.to_le_bytes().to_vec()
    }
}

struct Tag {
    tag: CircuitVar,
}

impl PublicInputs for Tag {
    fn hash(&self, private_tx_hash: &CircuitVar) -> Result<CircuitVar, RelationError> {
        poseidon(&[self.tag.clone(), private_tx_hash.clone()])
    }
}

struct ClientTag {
    tag: [u8; 32],
}

impl client::PublicInputs for ClientTag {
    fn hash(&self, private_tx_hash: &[u8; 32]) -> Result<[u8; 32]> {
        Ok(Poseidon::hashv(&[
            self.tag.as_slice(),
            private_tx_hash.as_slice(),
        ])?)
    }
}

#[test]
fn the_client_and_the_circuit_build_the_same_transaction() {
    let owner = keypair(5);
    let owner_address = owner.shielded_address().unwrap();
    let recipient = keypair(6).shielded_address().unwrap();
    let counter_hash = client::State::data_hash(&ClientCounter { value: 9 }).unwrap();
    let data_input = input(&owner, 7, Some(counter_hash));
    let tag = [9u8; 32];

    let mut token = client::TokenUtxo::new_mut(
        owner_address,
        [input(&owner, 300, None), input(&owner, 200, None)],
    )
    .unwrap();
    let transfer = token.transfer(recipient, 350).unwrap();
    let mut mutated =
        client::DataUtxo::new_mut(owner_address, data_input, ClientCounter { value: 9 }).unwrap();
    mutated.value = 10;
    let token_inputs = token.circuit_inputs().unwrap();
    let data_circuit_input = mutated.circuit_input().unwrap().unwrap();
    let public = ClientTag { tag };
    let built = client::ConfidentialTransaction::<_, 3, 3>::new(
        owner_address.solana_address().unwrap(),
        TREE_ID,
        &public,
    )
    .with_token_utxos(token)
    .with_output_token_utxo(transfer)
    .with_data_utxo(mutated)
    .build(&owner)
    .unwrap();

    let tx_context = built.tx_context.circuit().unwrap();
    let mut circuit_token = TokenUtxo::new_mut(token_inputs).unwrap();
    let circuit_transfer = circuit_token.transfer(
        &var(&recipient.owner_hash().unwrap(), "recipient").unwrap(),
        constant(350u64),
    );
    let mut circuit_mutated = DataUtxo::new_mut(
        &data_circuit_input,
        Counter {
            value: constant(9u64),
        },
    )
    .unwrap();
    circuit_mutated.value = constant(10u64);
    let circuit_public = Tag {
        tag: var(&tag, "tag").unwrap(),
    };
    let circuit_public_hash = ConfidentialTransaction::<_, 3, 3>::new(&tx_context, &circuit_public)
        .with_token_utxos(circuit_token)
        .with_output_token_utxo(circuit_transfer)
        .with_data_utxo(circuit_mutated)
        .check()
        .unwrap();
    let spp = &built.spp_proof_inputs;

    assert_eq!(
        (
            to_bytes(&circuit_public_hash).unwrap(),
            spp.input_utxos
                .iter()
                .map(|input| input.utxo_hash)
                .collect::<Vec<_>>(),
            spp.output_utxos
                .iter()
                .map(|output| output.hash(TREE_ID).unwrap())
                .collect::<Vec<_>>(),
            spp.output_utxos
                .iter()
                .map(|output| output.amount)
                .collect::<Vec<_>>(),
        ),
        (
            built.public_hash,
            built.input_hashes.to_vec(),
            built.output_hashes.to_vec(),
            vec![150, 350, 7],
        )
    );
}

#[test]
fn the_client_names_what_the_circuit_would_refuse() {
    let owner = keypair(5);
    let owner_address = owner.shielded_address().unwrap();
    let other = keypair(6);
    let mut token = client::TokenUtxo::new_mut(owner_address, [input(&owner, 300, None)]).unwrap();

    assert_eq!(
        (
            token
                .transfer(owner_address, 301)
                .map(|_| ())
                .map_err(|e| e.to_string()),
            client::TokenUtxo::new_mut(
                owner_address,
                [input(&owner, 300, None), input(&other, 1, None)]
            )
            .map(|_| ())
            .map_err(|e| e.to_string()),
            client::DataUtxo::new_burn(
                input(&owner, 7, Some([1u8; 32])),
                ClientCounter { value: 9 }
            )
            .map(|_| ())
            .map_err(|e| e.to_string()),
            client::TokenUtxo::new_burn(owner_address, [input(&owner, 300, None)])
                .map(|token| {
                    client::ConfidentialTransaction::<_, 1, 1>::new(
                        owner_address.solana_address().unwrap(),
                        TREE_ID,
                        &ClientTag { tag: [9u8; 32] },
                    )
                    .with_token_utxos(token)
                    .build(&owner)
                    .map(|_| ())
                    .map_err(|e| e.to_string())
                })
                .unwrap(),
        ),
        (
            Err("the transfers exceed the token balance".to_string()),
            Err("the inputs belong to different owners".to_string()),
            Err("the input does not commit to its program state".to_string()),
            Err("a burned token utxo leaves a balance".to_string()),
        )
    );
}

#[test]
fn dummies_and_unused_slots_agree_between_client_and_circuit() {
    let owner = keypair(5);
    let owner_address = owner.shielded_address().unwrap();
    let recipient = keypair(6).shielded_address().unwrap();
    let tag = [9u8; 32];
    let sdk_dummy = SppProofInputUtxo::dummy(TREE_ID).unwrap();
    let converted_dummy = utxo(&ProofInputUtxo::try_from(&sdk_dummy).unwrap()).unwrap();

    let mut token =
        client::TokenUtxo::new_mut(owner_address, [input(&owner, 300, None), sdk_dummy]).unwrap();
    let transfer = token.transfer(recipient, 120).unwrap();
    let [real, _] = token.circuit_inputs().unwrap();
    let public = ClientTag { tag };
    let built = client::ConfidentialTransaction::<_, 3, 3>::new(
        owner_address.solana_address().unwrap(),
        TREE_ID,
        &public,
    )
    .with_token_utxos(token)
    .with_output_token_utxo(transfer)
    .build(&owner)
    .unwrap();

    let tx_context = built.tx_context.circuit().unwrap();
    let circuit_public = Tag {
        tag: var(&tag, "tag").unwrap(),
    };
    let circuit = |dummy: circuit_lib::Utxo| {
        let mut token = TokenUtxo::new_mut([real.clone(), dummy]).unwrap();
        let transfer = token.transfer(
            &var(&recipient.owner_hash().unwrap(), "recipient").unwrap(),
            constant(120u64),
        );
        to_bytes(
            &ConfidentialTransaction::<_, 3, 3>::new(&tx_context, &circuit_public)
                .with_token_utxos(token)
                .with_output_token_utxo(transfer)
                .check()
                .unwrap(),
        )
        .unwrap()
    };

    assert_eq!(
        (
            circuit(circuit_lib::Utxo::dummy()),
            circuit(converted_dummy),
            built.input_hashes.to_vec(),
            built.output_hashes.get(2).copied(),
        ),
        (
            built.public_hash,
            built.public_hash,
            vec![
                built
                    .spp_proof_inputs
                    .input_utxos
                    .first()
                    .unwrap()
                    .utxo_hash,
                [0u8; 32],
                [0u8; 32],
            ],
            Some([0u8; 32]),
        )
    );
}

#[test]
fn the_client_checks_the_full_owner_and_the_burned_value() {
    let owner = keypair(5);
    let owner_address = owner.shielded_address().unwrap();
    let mut other_nullifier_key = owner_address;
    other_nullifier_key.nullifier_pubkey = [3u8; 32];
    let counter_hash = client::State::data_hash(&ClientCounter { value: 9 }).unwrap();
    let burn = |paid: u64| {
        let mut burned = client::DataUtxo::new_burn(
            input(&owner, 7, Some(counter_hash)),
            ClientCounter { value: 9 },
        )
        .unwrap();
        let payout = burned.transfer(owner_address, paid).unwrap();
        client::ConfidentialTransaction::<_, 1, 1>::new(
            owner_address.solana_address().unwrap(),
            TREE_ID,
            &ClientTag { tag: [9u8; 32] },
        )
        .with_data_utxo(burned)
        .with_output_token_utxo(payout)
        .build(&owner)
        .map(|_| ())
        .map_err(|e| e.to_string())
    };

    assert_eq!(
        (
            client::TokenUtxo::new_mut(other_nullifier_key, [input(&owner, 300, None)])
                .map(|_| ())
                .map_err(|e| e.to_string()),
            burn(7),
            burn(5),
        ),
        (
            Err("the inputs belong to different owners".to_string()),
            Ok(()),
            Err("a burned data utxo leaves value unpaid".to_string()),
        )
    );
}
