//! Pins the exact bytes of every prover request body this crate builds: one
//! request per transfer rail and shape on the complete and the indexed route,
//! and the default and ring merges. A refactor of the builders or the encoders
//! must leave each body byte-for-byte unchanged, so the test compares sha256
//! digests rather than parsed JSON.
//!
//! Regenerate with `cargo test -p spr-client --test request_bodies
//! print_the_request_body_digests -- --ignored --nocapture` only when a wire
//! change is intended, and say so in the change.

#[path = "common/input.rs"]
mod input_fixture;
#[path = "common/blindings.rs"]
mod output_blindings;
#[path = "test_indexer.rs"]
mod test_indexer;

use std::sync::Mutex;

use sha2::{Digest, Sha256};
use solana_address::Address;
use spr_client::{
    prover::{
        attach_input_proofs, confidential_eddsa_signer_pk_hashes,
        indexed::{
            IndexedMergePreparation, IndexedTransferPreparation, IndexedTransferRail, Request,
        },
        transact::{
            anonymous_ring_eddsa::anonymous_signer_pk_hashes, assemble, assemble_confidential_eddsa,
        },
        AnonymousRingEddsaRail, ConfidentialEddsaRail, MergeCacheTarget, ProveRequest,
        RingAuthorityRail, RingSignerRail, Shape, SignerRail, TransferProver,
    },
    ClientError, MergeProver, MerkleContext, MerkleProof, NonInclusionProof, Proof, ProofAuthority,
    Prover, ProverExt, Rpc, SpendProof, NULLIFIER_TREE_HEIGHT, STATE_TREE_HEIGHT,
};
use spr_interface::instruction::{OwnerTag, TransactOutput};
use spr_keypair::{ShieldedKeypair, SigningKey};
use spr_transaction::{
    instructions::{
        merge::{merge_output_key, MergeOutputPlaintext, MergeProofInputs, MergeTransaction},
        transact::SppProofInputs,
    },
    utxo::SppProofInputUtxo,
    Data, ExternalData, Mint, SppProofOutputUtxo, Utxo,
};

use crate::{
    input_fixture::wallet_utxo, output_blindings::assign_output_blindings,
    test_indexer::TestIndexer,
};

const OWNER_SEED: u8 = 0x11;
const RECIPIENT_SEED: u8 = 0x22;
const RING: [u8; 32] = [0x52; 32];
const TREE_ID: u16 = 0;
const OWNER_TAG: [u8; 32] = [0x08; 32];

/// The sha256 of each request body, hex encoded.
const DIGESTS: &[(&str, &str)] = &[
    (
        "signer 1x2",
        "60baabef09a3953f949d58c479832744102394ba917887dcd5a840d26a25cc02",
    ),
    (
        "signer 2x4",
        "562aa7783d96cc1093d107dc84dbae3f70fe5f94e2b66741b377e7f7c2740bea",
    ),
    (
        "signer 2x2 dummy",
        "aaa38cb3e93ba0188eba8d642d45c6b5f6b7341e19a2160974feeff34768442a",
    ),
    (
        "assembled signer 2x2 dummy",
        "aaa38cb3e93ba0188eba8d642d45c6b5f6b7341e19a2160974feeff34768442a",
    ),
    (
        "ring 1x2",
        "fe05bba8269b089424c832e148d8e9c6bf69f3983b1176ace9b9e067b3c7cff2",
    ),
    (
        "ring 2x2",
        "11d3e873ea4cc603dd7b8ee76f60de36a966168b921297c9f8aa9de6fa24c49d",
    ),
    (
        "ring authority 2x2",
        "f1085a02d02d516841ae0922c8f0b6a9da72bd39febd29a6aab44b8dd6346024",
    ),
    (
        "ring authority 2x2 dummy",
        "7cfbeba52622c78e324425e4e434ad1e84613aa105848c12dbc598c8d78c6c53",
    ),
    (
        "confidential eddsa 2x8",
        "2cfe1dc23380d0ed331f81fc9c47777cfe6b6a37b7f34e136d0406df96135ee9",
    ),
    (
        "assembled confidential eddsa 2x8",
        "a12e55b655262659ad77df3748dfd2333e5e692f293218e637ae2440a5e90710",
    ),
    (
        "anonymous ring eddsa 1x2",
        "22eadda432f41d501fcc0f40b8ad18931b7484f028456556b3fbde7749d4d137",
    ),
    (
        "anonymous ring eddsa 2x2",
        "85bff98b13540186c96290ceaa1d83210b360195bd19ca96c7c78c603cd22864",
    ),
    (
        "anonymous default ring eddsa 1x2",
        "ee1adeef1399bb77befe298d25b2baf539346fcbdbbb8b8e1c0858e6db681a9a",
    ),
    (
        "indexed confidential 1x2",
        "3b9e769eac4882e5bba200304d4659cc1c27eef950832c8c719ab4bcb5d27848",
    ),
    (
        "indexed confidential 2x2 dummy",
        "39af8e0ac0efb136121c68fdf568256f95e41a49bd042f15c1e169f2e5411416",
    ),
    (
        "indexed ring 2x2",
        "3c8eafdc5ba337c23fb7ca9a842e4b4ab87ec3362e268ac1ccba08366b4d4a87",
    ),
    (
        "indexed ring authority 2x2",
        "2fa7a6a165249b213793fab783a0c2bd1f3e3ebfcc811099741960f11653e1ac",
    ),
    (
        "indexed confidential eddsa 2x8",
        "5317ade573d149ee7237f8e42096daef92ffe8de8c633c96d5897cba38d725d3",
    ),
    (
        "indexed anonymous ring eddsa 1x2",
        "9e09ae5981b4c8d08e1b97bc549674c202302c8b3a9e7cacbb56502f49ecdd78",
    ),
    (
        "merge",
        "e457372b539112d7ef0314b14b1b5fec8d1e3afb48ce7b01713bb8410896cd3e",
    ),
    (
        "merge ring",
        "0e56022905f9201e25df16c81d1798a87def6148f9253d77d2909dc5baa9651a",
    ),
    (
        "indexed merge",
        "47b308872b5e96075160ff634bb8cb7336bc167f944cb1897c10ba3f3749aee0",
    ),
    (
        "indexed merge for cache",
        "5e56caf7061e02943205da2341574e1b33b7c960c14e73962bd7b6bfbc016bce",
    ),
    (
        "indexed merge ring",
        "316cf1cf0e600ffed795add84209f51a5e5ef5be28f068206bbc78e143488f9b",
    ),
];

fn field_bytes(byte: u8) -> [u8; 32] {
    core::array::from_fn(|index| if index == 0 { 0 } else { byte })
}

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_ed25519_bytes(&[seed; 32])
}

fn keypair(seed: u8) -> ShieldedKeypair {
    ShieldedKeypair::from_keypair(signing_key(seed)).expect("fixed-seed keypair")
}

fn ring() -> Address {
    Address::new_from_array(RING)
}

/// A transfer of `real` owner inputs padded with dummies to `shape`, paying one
/// recipient and returning change to the owner over the remaining outputs.
fn transaction(
    owner: &ShieldedKeypair,
    shape: Shape,
    real: usize,
    input_ring: Option<Address>,
    output_ring: Option<Address>,
) -> SppProofInputs {
    let mut inputs: Vec<SppProofInputUtxo> = (0..real)
        .map(|index| {
            let index = u8::try_from(index).unwrap();
            wallet_utxo(
                Utxo {
                    owner: owner.signing_pubkey(),
                    asset: Mint::SOL,
                    amount: 7,
                    blinding: field_bytes(0x31 + index),
                    ring_program_id: input_ring,
                    data: Data::default(),
                },
                &owner.nullifier_key,
                TREE_ID,
                7 + u64::from(index),
                None,
                None,
            )
            .into()
        })
        .collect();
    for index in real..shape.n_inputs() {
        let index = u8::try_from(index).unwrap();
        inputs.push(
            SppProofInputUtxo::dummy_with_blinding(field_bytes(0x61 + index), TREE_ID).unwrap(),
        );
    }
    let total = 7 * real as u64;
    let change = shape.n_outputs() as u64 - 1;
    let output = |holder: &ShieldedKeypair, amount| {
        let output =
            SppProofOutputUtxo::new(Mint::SOL, amount, holder.shielded_address().unwrap()).unwrap();
        match output_ring {
            Some(ring) => output.with_ring_program_id(ring),
            None => output,
        }
    };
    let mut outputs = vec![output(&keypair(RECIPIENT_SEED), total - change)];
    outputs.extend((0..change).map(|_| output(owner, 1)));
    let blinding_seed = field_bytes(0x41);
    assign_output_blindings(&inputs[0].nullifier, &mut outputs, &blinding_seed);
    let external_data = ExternalData::new(
        *owner.viewing_pubkey().as_bytes(),
        [0x5a; 16],
        outputs
            .iter()
            .map(|output| TransactOutput {
                utxo_hash: output.hash(TREE_ID).unwrap(),
                owner_tag: OwnerTag::Inline(OWNER_TAG),
                data: None,
            })
            .collect(),
        vec![OWNER_TAG; outputs.len()],
        vec![],
    );
    SppProofInputs {
        input_utxos: inputs,
        output_utxos: outputs,
        blinding_seed,
        output_tree_id: TREE_ID,
        external_data,
        payer: Address::new_from_array(owner.signing_pubkey().as_ed25519().unwrap()),
        cache_accounts: Default::default(),
    }
}

fn context() -> MerkleContext {
    MerkleContext {
        tree_type: 1,
        tree: spr_interface::pda::tree(TREE_ID),
    }
}

fn non_inclusion(nullifier: [u8; 32]) -> NonInclusionProof {
    NonInclusionProof {
        leaf: nullifier,
        merkle_context: context(),
        path: vec![field_bytes(0x56); NULLIFIER_TREE_HEIGHT],
        low_element: field_bytes(0x57),
        low_element_index: 3,
        high_element: field_bytes(0x58),
        high_element_index: 4,
        root: field_bytes(0x59),
        root_seq: 13,
        root_index: 9,
    }
}

/// Fixed witnesses under one root pair: a spend proof per real input and a
/// non-inclusion proof per dummy.
fn witnesses(transaction: &SppProofInputs) -> (Vec<SpendProof>, Vec<NonInclusionProof>) {
    let mut spends = Vec::new();
    let mut dummies = Vec::new();
    for input in &transaction.input_utxos {
        if input.is_dummy() {
            dummies.push(non_inclusion(input.nullifier));
            continue;
        }
        spends.push(SpendProof {
            state: MerkleProof {
                leaf: input.hash(),
                merkle_context: context(),
                path: vec![field_bytes(0x53); STATE_TREE_HEIGHT],
                leaf_index: input.leaf_index,
                root: field_bytes(0x54),
                root_seq: 11,
                root_index: 5,
            },
            nullifier: non_inclusion(input.nullifier),
        });
    }
    (spends, dummies)
}

/// A prover that records the body it is handed instead of proving it.
#[derive(Default)]
struct Capture(Mutex<Option<String>>);

impl Prover for Capture {
    fn prove(&self, request: &dyn ProveRequest) -> Result<Proof, ClientError> {
        *self.0.lock().unwrap() = Some(request.body()?.to_string());
        Err(ClientError::Prover("captured".into()))
    }
}

fn captured(prove: impl FnOnce(&Capture) -> Result<Proof, ClientError>) -> String {
    let capture = Capture::default();
    assert!(matches!(prove(&capture), Err(ClientError::Prover(_))));
    capture.0.into_inner().unwrap().expect("a captured body")
}

fn signer_body(shape: Shape, real: usize) -> String {
    let owner = keypair(OWNER_SEED);
    let transaction = transaction(&owner, shape, real, None, None);
    let (spends, dummies) = witnesses(&transaction);
    let mut result = TransferProver {
        signer_pk_hashes: transaction.signer_pk_hashes(shape.signer_width()).unwrap(),
        public_transfers: transaction.public_transfers().unwrap(),
        inputs: attach_input_proofs(transaction.input_utxos, &spends, &dummies).unwrap(),
        outputs: transaction.output_utxos,
        blinding_seed: transaction.blinding_seed,
        output_tree_id: TREE_ID,
        external_data: transaction.external_data,
        allow_dummy_inputs: true,
        shape,
        cache_accounts: Default::default(),
        rail: SignerRail,
    }
    .build()
    .unwrap();
    owner.complete_inputs(&mut result.inputs.inputs).unwrap();
    captured(|prover| prover.prove_transfer(&result.inputs))
}

fn assembled_signer_body(shape: Shape, real: usize) -> String {
    let owner = keypair(OWNER_SEED);
    let transaction = transaction(&owner, shape, real, None, None);
    let (spends, dummies) = witnesses(&transaction);
    let mut assembled = assemble(transaction, &spends, &dummies).unwrap();
    captured(|prover| {
        assembled
            .prove(prover, &owner)
            .map(|_| unreachable!("the capture never proves"))
    })
}

fn ring_body(shape: Shape, real: usize) -> String {
    let owner = keypair(OWNER_SEED);
    let transaction = transaction(&owner, shape, real, Some(ring()), Some(ring()));
    let (spends, dummies) = witnesses(&transaction);
    let mut result = TransferProver {
        signer_pk_hashes: transaction.signer_pk_hashes(shape.signer_width()).unwrap(),
        public_transfers: transaction.public_transfers().unwrap(),
        inputs: attach_input_proofs(transaction.input_utxos, &spends, &dummies).unwrap(),
        outputs: transaction.output_utxos,
        blinding_seed: transaction.blinding_seed,
        output_tree_id: TREE_ID,
        external_data: transaction.external_data,
        allow_dummy_inputs: true,
        shape,
        cache_accounts: Default::default(),
        rail: RingSignerRail {
            ring_program_id: Some(ring()),
        },
    }
    .build()
    .unwrap();
    owner.complete_inputs(&mut result.inputs.inputs).unwrap();
    captured(|prover| prover.prove_transfer_ring(&result.inputs))
}

fn ring_authority_body(shape: Shape, real: usize) -> String {
    let owner = keypair(OWNER_SEED);
    let transaction = transaction(&owner, shape, real, Some(ring()), Some(ring()));
    let (spends, dummies) = witnesses(&transaction);
    let mut result = TransferProver {
        signer_pk_hashes: Vec::new(),
        public_transfers: transaction.public_transfers().unwrap(),
        inputs: attach_input_proofs(transaction.input_utxos, &spends, &dummies).unwrap(),
        outputs: transaction.output_utxos,
        blinding_seed: transaction.blinding_seed,
        output_tree_id: TREE_ID,
        external_data: transaction.external_data,
        allow_dummy_inputs: true,
        shape,
        cache_accounts: Default::default(),
        rail: RingAuthorityRail {
            ring_program_id: Some(ring()),
            payer: transaction.payer,
        },
    }
    .build()
    .unwrap();
    owner.complete_inputs(&mut result.inputs.inputs).unwrap();
    captured(|prover| prover.prove_ring_authority(&result.inputs))
}

fn confidential_eddsa_body(shape: Shape, real: usize) -> String {
    let owner = keypair(OWNER_SEED);
    let key = signing_key(OWNER_SEED);
    let transaction = transaction(&owner, shape, real, None, None);
    let (spends, dummies) = witnesses(&transaction);
    let mut result = TransferProver {
        signer_pk_hashes: confidential_eddsa_signer_pk_hashes(
            &transaction,
            &owner.signing_pubkey(),
        )
        .unwrap(),
        public_transfers: transaction.public_transfers().unwrap(),
        inputs: attach_input_proofs(transaction.input_utxos, &spends, &dummies).unwrap(),
        outputs: transaction.output_utxos,
        blinding_seed: transaction.blinding_seed,
        output_tree_id: TREE_ID,
        external_data: transaction.external_data,
        allow_dummy_inputs: true,
        shape,
        cache_accounts: Default::default(),
        rail: ConfidentialEddsaRail {
            owner: (&key).into(),
        },
    }
    .build()
    .unwrap();
    owner
        .complete_inputs(&mut result.inputs.transfer.inputs)
        .unwrap();
    captured(|prover| prover.prove(&result.inputs))
}

fn assembled_confidential_eddsa_body(shape: Shape, real: usize) -> String {
    let owner = keypair(OWNER_SEED);
    let key = signing_key(OWNER_SEED);
    let transaction = transaction(&owner, shape, real, None, None);
    let (spends, dummies) = witnesses(&transaction);
    let mut assembled = assemble_confidential_eddsa(transaction, &spends, &dummies, &key).unwrap();
    captured(|prover| {
        assembled
            .prove(prover, &owner)
            .map(|_| unreachable!("the capture never proves"))
    })
}

fn anonymous_body(shape: Shape, real: usize, input_ring: Option<Address>) -> String {
    let owner = keypair(OWNER_SEED);
    let key = signing_key(OWNER_SEED);
    let transaction = transaction(&owner, shape, real, input_ring, Some(ring()));
    let (spends, dummies) = witnesses(&transaction);
    let mut result = TransferProver {
        signer_pk_hashes: anonymous_signer_pk_hashes(&transaction, &owner.signing_pubkey())
            .unwrap(),
        public_transfers: transaction.public_transfers().unwrap(),
        inputs: attach_input_proofs(transaction.input_utxos, &spends, &dummies).unwrap(),
        outputs: transaction.output_utxos,
        blinding_seed: transaction.blinding_seed,
        output_tree_id: TREE_ID,
        external_data: transaction.external_data,
        allow_dummy_inputs: true,
        shape,
        cache_accounts: Default::default(),
        rail: AnonymousRingEddsaRail {
            owner: (&key).into(),
            ring_program_id: Some(ring()),
        },
    }
    .build()
    .unwrap();
    owner
        .complete_inputs(&mut result.inputs.transfer.inputs)
        .unwrap();
    captured(|prover| prover.prove(&result.inputs))
}

/// The indexed rails, by name, for one transaction's ring.
fn indexed_body(rail: &str, shape: Shape, real: usize) -> String {
    let owner = keypair(OWNER_SEED);
    let key = signing_key(OWNER_SEED);
    let (rail, input_ring, output_ring) = match rail {
        "confidential" => (IndexedTransferRail::Confidential, None, None),
        "ring" => (
            IndexedTransferRail::Ring(ring()),
            Some(ring()),
            Some(ring()),
        ),
        "ring-authority" => (
            IndexedTransferRail::RingAuthority(ring()),
            Some(ring()),
            Some(ring()),
        ),
        "confidential-eddsa" => (
            IndexedTransferRail::ConfidentialEddsa {
                owner: (&key).into(),
            },
            None,
            None,
        ),
        "anonymous-ring-eddsa" => (
            IndexedTransferRail::AnonymousRingEddsa {
                ring: ring(),
                owner: (&key).into(),
            },
            Some(ring()),
            Some(ring()),
        ),
        rail => panic!("unknown rail {rail}"),
    };
    IndexedTransferPreparation {
        transaction: transaction(&owner, shape, real, input_ring, output_ring),
        rail,
    }
    .prepare(&owner)
    .unwrap()
    .body()
    .unwrap()
    .to_string()
}

/// A two-input merge with a fixed output ciphertext salt, its witnesses from
/// a local tree.
fn merge(ring: Option<Address>) -> (ShieldedKeypair, MergeProofInputs, TestIndexer) {
    let owner = keypair(OWNER_SEED);
    let nullifier_pk = owner.nullifier_key.pubkey().unwrap();
    let mut indexer = TestIndexer::new();
    let inputs = (0..2u8)
        .map(|index| {
            let ring_data_hash = ring.map(|_| field_bytes(index + 1));
            let utxo = Utxo {
                owner: owner.signing_pubkey(),
                asset: Mint::SOL,
                amount: 100,
                blinding: field_bytes(0x71 + index),
                ring_program_id: ring,
                data: Data::default(),
            };
            let utxo_hash = utxo
                .hash(
                    &nullifier_pk,
                    &[0; 32],
                    &ring_data_hash.unwrap_or_default(),
                    TREE_ID,
                )
                .unwrap();
            let leaf_index = indexer.add_utxo(utxo_hash);
            wallet_utxo(
                utxo,
                &owner.nullifier_key,
                TREE_ID,
                leaf_index,
                None,
                ring_data_hash,
            )
        })
        .collect();
    let mut merge = match ring {
        Some(ring) => MergeTransaction::new_with_ring(inputs, ring, Some(field_bytes(0xd2))),
        None => MergeTransaction::new(inputs),
    }
    .unwrap()
    .encrypt(&owner)
    .unwrap();
    let first_nullifier = merge.input_utxos[0].nullifier;
    merge.output_ciphertext_salt = [0x5b; 16];
    merge.output_ciphertext = MergeOutputPlaintext {
        amount: merge.output_utxo.amount,
        mint: merge.output_utxo.asset.asset,
    }
    .encrypt(
        &merge_output_key(&owner.nullifier_key, &first_nullifier).unwrap(),
        &merge.output_ciphertext_salt,
    )
    .unwrap();
    (owner, merge, indexer)
}

fn merge_body(ring: Option<Address>) -> String {
    let (owner, merge, indexer) = merge(ring);
    let commitments = merge.input_utxo_hashes().unwrap();
    let proofs = indexer.get_input_merkle_proofs(&commitments, None).unwrap();
    let dummy_nullifier_proofs = merge
        .dummy_nullifiers()
        .into_iter()
        .map(|nullifier| indexer.dummy_nullifier_proof(nullifier))
        .collect();
    let result = MergeProver {
        transaction: merge,
        nullifier_key: owner.nullifier_key.clone(),
        proofs,
        dummy_nullifier_proofs,
        cache: None,
    }
    .build()
    .unwrap();
    captured(|prover| match ring {
        Some(_) => prover.prove_merge_ring(&result.inputs),
        None => prover.prove_merge(&result.inputs),
    })
}

fn indexed_merge_body(ring: Option<Address>, cache: Option<MergeCacheTarget>) -> String {
    let (owner, merge, _) = merge(ring);
    let preparation = IndexedMergePreparation {
        merge,
        nullifier_key: owner.nullifier_key.clone(),
    };
    match cache {
        Some(cache) => preparation.prepare_for_cache(cache),
        None => preparation.prepare(),
    }
    .unwrap()
    .body()
    .unwrap()
    .to_string()
}

fn bodies() -> Vec<(&'static str, String)> {
    let cache = MergeCacheTarget {
        address: Address::new_from_array([0x63; 32]),
        slot: 1,
    };
    vec![
        ("signer 1x2", signer_body(Shape::IN1_OUT2, 1)),
        ("signer 2x4", signer_body(Shape::IN2_OUT4, 2)),
        ("signer 2x2 dummy", signer_body(Shape::IN2_OUT2, 1)),
        (
            "assembled signer 2x2 dummy",
            assembled_signer_body(Shape::IN2_OUT2, 1),
        ),
        ("ring 1x2", ring_body(Shape::IN1_OUT2, 1)),
        ("ring 2x2", ring_body(Shape::IN2_OUT2, 2)),
        (
            "ring authority 2x2",
            ring_authority_body(Shape::IN2_OUT2, 2),
        ),
        (
            "ring authority 2x2 dummy",
            ring_authority_body(Shape::IN2_OUT2, 1),
        ),
        (
            "confidential eddsa 2x8",
            confidential_eddsa_body(Shape::IN2_OUT8, 2),
        ),
        (
            "assembled confidential eddsa 2x8",
            assembled_confidential_eddsa_body(Shape::IN2_OUT8, 1),
        ),
        (
            "anonymous ring eddsa 1x2",
            anonymous_body(Shape::IN1_OUT2, 1, Some(ring())),
        ),
        (
            "anonymous ring eddsa 2x2",
            anonymous_body(Shape::IN2_OUT2, 2, Some(ring())),
        ),
        (
            "anonymous default ring eddsa 1x2",
            anonymous_body(Shape::IN1_OUT2, 1, None),
        ),
        (
            "indexed confidential 1x2",
            indexed_body("confidential", Shape::IN1_OUT2, 1),
        ),
        (
            "indexed confidential 2x2 dummy",
            indexed_body("confidential", Shape::IN2_OUT2, 1),
        ),
        ("indexed ring 2x2", indexed_body("ring", Shape::IN2_OUT2, 2)),
        (
            "indexed ring authority 2x2",
            indexed_body("ring-authority", Shape::IN2_OUT2, 2),
        ),
        (
            "indexed confidential eddsa 2x8",
            indexed_body("confidential-eddsa", Shape::IN2_OUT8, 2),
        ),
        (
            "indexed anonymous ring eddsa 1x2",
            indexed_body("anonymous-ring-eddsa", Shape::IN1_OUT2, 1),
        ),
        ("merge", merge_body(None)),
        ("merge ring", merge_body(Some(ring()))),
        ("indexed merge", indexed_merge_body(None, None)),
        (
            "indexed merge for cache",
            indexed_merge_body(None, Some(cache)),
        ),
        ("indexed merge ring", indexed_merge_body(Some(ring()), None)),
    ]
}

fn digests() -> Vec<(&'static str, String)> {
    bodies()
        .into_iter()
        .map(|(name, body)| (name, hex::encode(Sha256::digest(body.as_bytes()))))
        .collect()
}

#[test]
fn every_request_body_matches_its_digest() {
    let digests = digests();
    assert_eq!(
        digests
            .iter()
            .map(|(name, digest)| (*name, digest.as_str()))
            .collect::<Vec<_>>(),
        DIGESTS
    );
}

#[test]
#[ignore = "prints the DIGESTS table; run with --nocapture and paste it in"]
fn print_the_request_body_digests() {
    for (name, digest) in digests() {
        println!("    (\"{name}\", \"{digest}\"),");
    }
}
