use anyhow::Result;
use solana_address::Address;
use solana_instruction::AccountMeta;
use timelock_escrow_prover::{ProofInputWriter, ProofInputs};
use timelock_escrow_sdk::zk_program::{
    BuiltTransaction, NewProgramUtxo, OutputEncoding, ProgramOwner, ProgramState,
    ProgramTransaction,
};
use zolana_interface::{
    instruction::instruction_data::transact::{
        CircuitId, InputUtxo, OwnerTag, TransactIxData, TransactProof, TreeContext,
    },
    pda, N_PUBLIC_SLOTS, PROGRAM_ID_PUBKEY,
};
use zolana_keypair::{ShieldedKeypair, SigningKey};
use zolana_transaction::{
    instructions::transact::PrivateTxHash,
    utxo::{derive_output_blinding_seed, derive_transact_output_blinding},
    Mint, SppProofOutputUtxo,
};

const TREE_ID: u16 = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Counter {
    value: u64,
}

struct CounterProofInputs {
    value: [u8; 32],
}

impl ProofInputs for CounterProofInputs {
    fn write(&self, writer: &mut ProofInputWriter<'_>) {
        writer.field("Value", &self.value);
    }
}

impl ProgramState for Counter {
    type ProofInputs = CounterProofInputs;

    fn data_hash(&self) -> Result<[u8; 32]> {
        Ok(zolana_keypair::hash::poseidon(&[&value_field(self.value)])?)
    }

    fn proof_inputs(&self) -> Result<CounterProofInputs> {
        Ok(CounterProofInputs {
            value: value_field(self.value),
        })
    }
}

fn value_field(value: u64) -> [u8; 32] {
    let mut field = [0u8; 32];
    field[24..].copy_from_slice(&value.to_be_bytes());
    field
}

struct Fixture {
    user: ShieldedKeypair,
    owner: ProgramOwner,
}

fn fixture() -> Fixture {
    Fixture {
        user: ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[7u8; 32])).unwrap(),
        owner: ProgramOwner::new(Address::new_from_array([9u8; 32])),
    }
}

fn counter_utxo(fixture: &Fixture, value: u64) -> NewProgramUtxo<Counter> {
    NewProgramUtxo::new(
        fixture.owner,
        Counter { value },
        Mint::SOL,
        300,
        fixture.user.viewing_pubkey(),
    )
}

fn transaction(fixture: &Fixture) -> ProgramTransaction<2, 2> {
    let user = fixture.user.shielded_address().unwrap();
    let source = fixture
        .owner
        .plain_input(Mint::SOL, 1_000, [3u8; 32], TREE_ID, 5)
        .unwrap();
    ProgramTransaction::new(user.solana_address().unwrap(), TREE_ID)
        .with_expiry(77)
        .with_input(0, source)
        .unwrap()
        .with_output(0, SppProofOutputUtxo::new(Mint::SOL, 700, user).unwrap())
        .unwrap()
        .with_program_output(1, &counter_utxo(fixture, 4))
        .unwrap()
}

fn proven_ix(built: &BuiltTransaction<2, 2>) -> TransactIxData {
    let spp = built.spp_proof_inputs();
    TransactIxData {
        expiry_unix_ts: spp.external_data.expiry_unix_ts,
        tx_viewing_pk: spp.external_data.tx_viewing_pk,
        salt: spp.external_data.salt,
        interface_transfers: Vec::new(),
        data_hash: None,
        ring_data_hash: None,
        outputs: spp.external_data.outputs.clone(),
        messages: Vec::new(),
        private_tx_hash: *built.private_tx_hash(),
        circuit: CircuitId::ConfidentialEddsa(2, 2, N_PUBLIC_SLOTS as u8),
        proof: TransactProof::zeroed(),
        inputs: spp
            .input_utxos
            .iter()
            .map(|input| InputUtxo {
                nullifier_hash: input.nullifier,
                tree_index: 0,
            })
            .collect(),
        tree_contexts: vec![TreeContext {
            utxo_tree_root_index: 1,
            nullifier_tree_root_index: 2,
        }],
    }
}

#[test]
fn build_derives_slot_blindings_pads_inputs_and_hashes_once() {
    let fixture = fixture();
    let built = transaction(&fixture).build(&fixture.user).unwrap();
    let spp = built.spp_proof_inputs();
    let first_nullifier = spp.input_utxos.first().unwrap().nullifier;
    let seed = derive_output_blinding_seed(&first_nullifier, &spp.blinding_seed).unwrap();
    let expected_blindings: Vec<[u8; 32]> = (0..2u32)
        .map(|slot| derive_transact_output_blinding(&first_nullifier, &seed, slot).unwrap())
        .collect();
    let output_hashes: Vec<[u8; 32]> = spp
        .output_utxos
        .iter()
        .map(|output| output.hash(TREE_ID).unwrap())
        .collect();
    let expected_private_tx_hash = PrivateTxHash::new(
        &[spp.input_utxos.first().unwrap().utxo_hash, [0u8; 32]],
        &output_hashes,
        built.external_data_hash(),
        built.private_tx_blinding(),
    )
    .hash()
    .unwrap();
    let user_tag = fixture
        .user
        .shielded_address()
        .unwrap()
        .solana_address()
        .unwrap();

    assert_eq!(
        (
            spp.output_utxos
                .iter()
                .map(|output| output.blinding)
                .collect::<Vec<_>>(),
            spp.input_utxos
                .iter()
                .map(|input| (input.is_dummy(), input.tree_id))
                .collect::<Vec<_>>(),
            *built.private_tx_hash(),
            spp.external_data
                .outputs
                .iter()
                .map(|output| (output.owner_tag, output.data.is_some()))
                .collect::<Vec<_>>(),
            spp.external_data.expiry_unix_ts,
        ),
        (
            expected_blindings,
            vec![(false, TREE_ID), (true, TREE_ID)],
            expected_private_tx_hash,
            vec![
                (OwnerTag::Inline(user_tag.to_bytes()), true),
                (OwnerTag::Inline(fixture.owner.owner_tag()), true),
            ],
            77,
        )
    );
}

#[test]
fn created_program_utxo_is_the_one_in_its_slot_and_spends_back() {
    let fixture = fixture();
    let built = transaction(&fixture).build(&fixture.user).unwrap();
    let created = built.created(1, counter_utxo(&fixture, 4)).unwrap();
    let input = created.input(11).unwrap();

    assert_eq!(
        (
            created.hash().unwrap(),
            created.blinding(),
            input.utxo_hash,
            input.leaf_index,
            created.proof_inputs().unwrap().utxo.hash().unwrap(),
        ),
        (
            *built.output_hash(1).unwrap(),
            &built.output(1).unwrap().blinding,
            *built.output_hash(1).unwrap(),
            11,
            *built.output_hash(1).unwrap(),
        )
    );
    assert!(built.created(1, counter_utxo(&fixture, 5)).is_err());
    assert!(built.created(0, counter_utxo(&fixture, 4)).is_err());
}

#[test]
fn hash_only_output_publishes_no_ciphertext() {
    let fixture = fixture();
    let built = transaction(&fixture)
        .with_output_encoding(1, OutputEncoding::HashOnly)
        .unwrap()
        .build(&fixture.user)
        .unwrap();

    assert_eq!(
        built
            .spp_proof_inputs()
            .external_data
            .outputs
            .iter()
            .map(|output| output.data.is_some())
            .collect::<Vec<_>>(),
        vec![true, false]
    );
}

#[test]
fn builder_rejects_misplaced_slots() {
    let fixture = fixture();
    let user = fixture.user.shielded_address().unwrap();
    let source = || {
        fixture
            .owner
            .plain_input(Mint::SOL, 1_000, [3u8; 32], TREE_ID, 5)
            .unwrap()
    };
    let payer = user.solana_address().unwrap();
    let output = || SppProofOutputUtxo::new(Mint::SOL, 1_000, user).unwrap();

    let twice = ProgramTransaction::<2, 1>::new(payer, TREE_ID)
        .with_input(0, source())
        .unwrap()
        .with_input(0, source());
    let outside = ProgramTransaction::<2, 1>::new(payer, TREE_ID).with_output(1, output());
    let unset_output = ProgramTransaction::<2, 2>::new(payer, TREE_ID)
        .with_input(0, source())
        .unwrap()
        .with_output(0, output())
        .unwrap()
        .build(&fixture.user);
    let empty_first_input = ProgramTransaction::<2, 1>::new(payer, TREE_ID)
        .with_input(1, source())
        .unwrap()
        .with_output(0, output())
        .unwrap()
        .build(&fixture.user);

    assert_eq!(
        (
            twice.err().map(|e| e.to_string()),
            outside.err().map(|e| e.to_string()),
            unset_output.err().map(|e| e.to_string()),
            empty_first_input.err().map(|e| e.to_string()),
        ),
        (
            Some("input slot 0 is set twice".to_string()),
            Some("output slot 1 is outside a transaction of 1 outputs".to_string()),
            Some("output slot 1 is unset".to_string()),
            Some("input slot 0 must hold a real input: it is the first nullifier".to_string()),
        )
    );
}

#[test]
fn accept_rejects_a_proof_of_another_transaction() {
    let fixture = fixture();
    let built = transaction(&fixture).build(&fixture.user).unwrap();
    let mut other_hash = proven_ix(&built);
    other_hash.private_tx_hash[0] ^= 1;
    let mut other_output = proven_ix(&built);
    other_output.outputs.get_mut(1).unwrap().utxo_hash[0] ^= 1;
    let mut other_nullifier = proven_ix(&built);
    other_nullifier.inputs.get_mut(0).unwrap().nullifier_hash[0] ^= 1;

    assert_eq!(
        (
            built.clone().accept(proven_ix(&built)).is_ok(),
            built
                .clone()
                .accept(other_hash)
                .err()
                .map(|e| e.to_string()),
            built
                .clone()
                .accept(other_output)
                .err()
                .map(|e| e.to_string()),
            built.accept(other_nullifier).err().map(|e| e.to_string()),
        ),
        (
            true,
            Some(
                "the SPP proof binds another private tx hash than the built transaction"
                    .to_string()
            ),
            Some("output slot 1: the SPP proof appends another utxo".to_string()),
            Some("input slot 0: the SPP proof spends another nullifier".to_string()),
        )
    );
}

#[test]
fn transact_is_what_the_program_rebuilds_and_names_a_foreign_owner_tag() {
    let fixture = fixture();
    let built = transaction(&fixture).build(&fixture.user).unwrap();
    let ix = proven_ix(&built);
    let proven = built.accept(ix.clone()).unwrap();
    let user_tag = fixture
        .user
        .shielded_address()
        .unwrap()
        .solana_address()
        .unwrap()
        .to_bytes();
    let owner_tags = [user_tag, fixture.owner.owner_tag()];

    let transact = proven.transact(owner_tags).unwrap();
    let foreign = proven
        .transact([user_tag, [8u8; 32]])
        .err()
        .map(|e| e.to_string())
        .unwrap();

    assert_eq!(
        (
            transact.into_ix_data(owner_tags),
            foreign.starts_with("output slot 1:")
        ),
        (ix, true)
    );
}

#[test]
fn spp_accounts_follow_the_transact_layout() {
    let fixture = fixture();
    let built = transaction(&fixture).build(&fixture.user).unwrap();
    let ix = proven_ix(&built);
    let payer = *built.payer();
    let proven = built.accept(ix.clone()).unwrap();
    let tree = pda::tree(TREE_ID);
    let signer = *fixture.owner.pda();
    let mut expected = vec![
        AccountMeta::new(payer, true),
        AccountMeta::new(tree, false),
        AccountMeta::new_readonly(PROGRAM_ID_PUBKEY, false),
        AccountMeta::new_readonly(Address::default(), false),
        AccountMeta::new(tree, false),
    ];
    expected.extend(
        ix.inputs.iter().map(|input| {
            AccountMeta::new(pda::nullifier_pda(&tree, &input.nullifier_hash).0, false)
        }),
    );
    expected.push(AccountMeta::new_readonly(signer, false));

    assert_eq!(proven.spp_accounts(&[signer]).unwrap(), expected);
}

#[test]
fn spp_accounts_rejects_signers_the_proof_does_not_commit_to() {
    let fixture = fixture();
    let built = transaction(&fixture).build(&fixture.user).unwrap();
    let ix = proven_ix(&built);
    let proven = built.accept(ix).unwrap();

    assert_eq!(
        (
            proven.spp_accounts(&[]).is_err(),
            proven
                .spp_accounts(&[Address::new_from_array([4u8; 32])])
                .is_err(),
        ),
        (true, true)
    );
}

#[test]
fn accept_rejects_other_published_external_data() {
    let fixture = fixture();
    let built = transaction(&fixture).build(&fixture.user).unwrap();
    let mut other_expiry = proven_ix(&built);
    other_expiry.expiry_unix_ts += 1;
    let mut other_salt = proven_ix(&built);
    other_salt.salt[0] ^= 1;
    let mut other_ciphertext = proven_ix(&built);
    other_ciphertext.outputs.get_mut(0).unwrap().data = None;

    assert_eq!(
        (
            built
                .clone()
                .accept(other_expiry)
                .err()
                .map(|e| e.to_string()),
            built
                .clone()
                .accept(other_salt)
                .err()
                .map(|e| e.to_string()),
            built.accept(other_ciphertext).err().map(|e| e.to_string()),
        ),
        (
            Some("the SPP proof carries another expiry than the built transaction".to_string()),
            Some(
                "the SPP proof carries another encryption key or salt than the built transaction"
                    .to_string()
            ),
            Some("output slot 0: the SPP proof publishes another ciphertext".to_string()),
        )
    );
}

#[test]
fn transact_rejects_what_the_program_would_not_build() {
    let fixture = fixture();
    let built = transaction(&fixture).build(&fixture.user).unwrap();
    let user_tag = fixture
        .user
        .shielded_address()
        .unwrap()
        .solana_address()
        .unwrap()
        .to_bytes();
    let owner_tags = [user_tag, fixture.owner.owner_tag()];
    let mut other_circuit = proven_ix(&built);
    other_circuit.circuit = CircuitId::ConfidentialEddsa(2, 3, N_PUBLIC_SLOTS as u8);
    let mut with_message = proven_ix(&built);
    with_message.messages.push(
        zolana_interface::instruction::instruction_data::transact::MessageData {
            view_tag: [1u8; 32],
            data: vec![2u8],
        },
    );

    let rejected = |ix: TransactIxData| {
        built
            .clone()
            .accept(ix)
            .unwrap()
            .transact(owner_tags)
            .err()
            .map(|e| e.to_string())
    };

    assert_eq!(
        (
            rejected(other_circuit).map(|e| e.starts_with("the SPP proof uses circuit")),
            rejected(with_message),
        ),
        (Some(true), Some("the program sets no messages".to_string()))
    );
}

#[test]
fn a_program_utxo_rebuilt_from_its_opening_is_the_created_one() {
    let fixture = fixture();
    let built = transaction(&fixture).build(&fixture.user).unwrap();
    let created = built.created(1, counter_utxo(&fixture, 4)).unwrap();

    assert_eq!(
        counter_utxo(&fixture, 4).created(*created.blinding(), created.tree_id()),
        created
    );
}
