#![cfg(feature = "compression")]

use borsh::{BorshDeserialize, BorshSerialize};
use pinocchio::Address;
use sha2::Digest;
use spr_account_checks::account_info::test_account_info::get_account_view;
use spr_client::ProofInputUtxo;
use spr_hasher::primitives::{is_canonical_bn254_scalar_be, right_align};
use spr_interface::{
    event::OutputDataEncoding,
    instruction::instruction_data::transact::{TransactProof, TreeContext},
    state::discriminator::TREE_ACCOUNT_DISCRIMINATOR,
    SHIELDED_POOL_PROGRAM_ID,
};
use spr_keypair::NullifierKey;
use spr_program::{
    derive_output_blinding_seed, derive_transact_output_blinding,
    hasher::{unique_data_hash, DataHasher, Hasher, HasherError, Poseidon, Sha256BE},
    program::{
        AddressSeed, PdaOwner, ReadRoots, SppTransactCpi, UniqueDataUtxo, UtxoMeta,
        ACCOUNT_BLINDING_SEED,
    },
};
use spr_transaction::SOL_MINT;
use spr_tree::{NullifierTreeInitParams, TreeAccount, TreeFeeSchedule};

#[derive(Default, BorshSerialize)]
struct ShaState {
    value: u64,
}

impl DataHasher for ShaState {
    fn hash(&self) -> Result<[u8; 32], HasherError> {
        Sha256BE::hashv(&[b"ShaState", &self.value.to_le_bytes()])
    }
}

#[derive(Default, BorshSerialize)]
struct PoseidonState {
    value: u64,
}

impl DataHasher for PoseidonState {
    fn hash(&self) -> Result<[u8; 32], HasherError> {
        Poseidon::hashv(&[
            &right_align(b"PosState"),
            &right_align(&self.value.to_be_bytes()),
        ])
    }
}

const CONTEXT: TreeContext = TreeContext {
    utxo_tree_root_index: 0,
    nullifier_tree_root_index: 0,
};
const TREE_ID: u16 = 5;

fn roots() -> ReadRoots {
    let tree_address = [21u8; 32];
    let mut data = vec![0; TreeAccount::account_size()];
    TreeAccount::init(
        &mut data,
        TREE_ACCOUNT_DISCRIMINATOR,
        32,
        tree_address,
        TREE_ID,
        NullifierTreeInitParams::default(),
        TreeFeeSchedule::at_cost(250, 5_000, 46).unwrap(),
    )
    .unwrap();
    let mut tree = get_account_view(
        tree_address,
        SHIELDED_POOL_PROGRAM_ID,
        false,
        false,
        false,
        data,
    );
    ReadRoots::load(&mut tree, &CONTEXT).unwrap()
}

fn protocol_hash(
    owner: &PdaOwner,
    meta: &UtxoMeta,
    state_hash: [u8; 32],
    tree_id: u16,
) -> [u8; 32] {
    ProofInputUtxo::new(*owner.owner_hash(), &SOL_MINT, 0, &meta.blinding, tree_id)
        .unwrap()
        .with_data_hash(unique_data_hash(&meta.address, &state_hash).unwrap())
        .hash()
        .unwrap()
}

fn payload(address: &[u8; 32], value: u64) -> Vec<u8> {
    let mut data = address.to_vec();
    data.extend(borsh::to_vec(&value).unwrap());
    borsh::to_vec(&OutputDataEncoding::Plaintext(data)).unwrap()
}

#[test]
fn sha_state_uses_a_canonical_sha256_digest() {
    for value in [0, 7, u64::MAX] {
        let actual = ShaState { value }.hash().unwrap();
        let mut digest = sha2::Sha256::new();
        digest.update(b"ShaState");
        digest.update(borsh::to_vec(&value).unwrap());
        let mut expected: [u8; 32] = digest.finalize().into();
        expected[0] = 0;
        assert_eq!(
            (actual, is_canonical_bn254_scalar_be(&actual)),
            (expected, true)
        );
    }
}

#[test]
fn sha_and_poseidon_states_share_create_update_and_read_paths() {
    let owner = PdaOwner::new(&Address::new_from_array([4u8; 32])).unwrap();
    let mut sha = UniqueDataUtxo::<ShaState>::new_init(
        &owner,
        AddressSeed::new(right_align(&[1])).unwrap(),
        CONTEXT,
    )
    .unwrap();
    let mut poseidon = UniqueDataUtxo::<PoseidonState>::new_init(
        &owner,
        AddressSeed::new(right_align(&[2])).unwrap(),
        CONTEXT,
    )
    .unwrap();
    sha.value = 7;
    poseidon.value = 9;
    let addresses = [*sha.address(), *poseidon.address()];
    let first_nullifier = *sha.input_nullifier();
    let seed = derive_output_blinding_seed(&first_nullifier, &ACCOUNT_BLINDING_SEED).unwrap();
    let meta = [0, 1].map(|index| UtxoMeta {
        address: addresses[index],
        blinding: derive_transact_output_blinding(&first_nullifier, &seed, index as u32).unwrap(),
        tree_context: CONTEXT,
    });
    let hashes = [
        protocol_hash(
            &owner,
            &meta[0],
            ShaState { value: 7 }.hash().unwrap(),
            TREE_ID,
        ),
        protocol_hash(
            &owner,
            &meta[1],
            PoseidonState { value: 9 }.hash().unwrap(),
            TREE_ID,
        ),
    ];
    let created = SppTransactCpi::new(TransactProof::zeroed())
        .with_unique_data_utxo(sha)
        .unwrap()
        .with_unique_data_utxo(poseidon)
        .unwrap()
        .into_ix_data(TREE_ID)
        .unwrap();
    assert_eq!(
        created
            .outputs
            .iter()
            .map(|output| (output.utxo_hash, output.data.clone()))
            .collect::<Vec<_>>(),
        vec![
            (hashes[0], Some(payload(&addresses[0], 7))),
            (hashes[1], Some(payload(&addresses[1], 9)))
        ],
    );

    let read = roots();
    let sha_key = read.key(&owner, &meta[0], &ShaState { value: 7 }).unwrap();
    let poseidon_key = read
        .key(&owner, &meta[1], &PoseidonState { value: 9 })
        .unwrap();
    let zero_key = NullifierKey::from_secret([0; 31]);
    let nullifiers = [0, 1].map(|index| {
        zero_key
            .nullifier(&hashes[index], &meta[index].blinding)
            .unwrap()
    });
    assert_eq!(
        [
            (*sha_key.hash(), *sha_key.nullifier()),
            (*poseidon_key.hash(), *poseidon_key.nullifier())
        ],
        [(hashes[0], nullifiers[0]), (hashes[1], nullifiers[1])],
    );

    let mut sha =
        UniqueDataUtxo::new_mut(&owner, &meta[0], ShaState { value: 7 }, TREE_ID).unwrap();
    let mut poseidon =
        UniqueDataUtxo::new_mut(&owner, &meta[1], PoseidonState { value: 9 }, TREE_ID).unwrap();
    sha.value = 8;
    poseidon.value = 10;
    let updated = SppTransactCpi::new(TransactProof::zeroed())
        .with_unique_data_utxo(sha)
        .unwrap()
        .with_unique_data_utxo(poseidon)
        .unwrap()
        .into_ix_data(TREE_ID + 1)
        .unwrap();
    let published: Vec<_> = updated
        .outputs
        .iter()
        .map(|output| OutputDataEncoding::try_from_slice(output.data.as_deref().unwrap()).unwrap())
        .collect();
    assert_eq!(
        (
            updated
                .inputs
                .iter()
                .map(|input| input.nullifier_hash)
                .collect::<Vec<_>>(),
            published
        ),
        (
            nullifiers.to_vec(),
            [(&addresses[0], 8u64), (&addresses[1], 10u64)]
                .map(|(address, value)| {
                    OutputDataEncoding::try_from_slice(&payload(address, value)).unwrap()
                })
                .to_vec()
        ),
    );
}
