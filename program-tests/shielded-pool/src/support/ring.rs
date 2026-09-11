use groth16_solana::groth16::Groth16Verifier;
use num_bigint::BigUint;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::{
    prover::field::be, ProofCompressed, ProverClient, TransferOutput, TransferP256Inputs,
    TreeSlotFields,
};
use zolana_hasher::{
    hash_chain::{create_hash_chain_4_from_slice, create_right_hash_chain_from_slice},
    primitives::{hash_bytes, p256_owner_identity, solana_owner_identity},
};
use zolana_interface::{
    instruction::{
        instruction_data::transact::{CircuitId, TransactIxData},
        tag, Transact,
    },
    state::{discriminator::RING_CONFIG, RingConfig},
    tree_slot::{tree_id_field, tree_slots_hash_chain},
    verifying_keys::RingP256ProofData,
    N_PUBLIC_SLOTS, SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::{hash::sha256, pubkey::PublicKey, NullifierKey, ShieldedKeypair, SigningKey};
use zolana_program_test::RING_TEST_PROGRAM_ID;
use zolana_test_utils::transact::{
    build_transfer_prover_inputs, derive_test_transfer_output_blindings, dummy_input,
    dummy_transfer_output, external_data_hash_for_discriminator, fe, inline_outputs, input_utxo,
    new_transact_ix_data, output_owner_pk_hashes, pack_transact_proof, set_output_owner_tags,
    single_tree_slots, sol_public_slots, spend_input, test_private_tx_blinding, SpendInputArgs,
    TransferProverInputsArgs, TEST_BLINDING_SEED,
};
use zolana_transaction::{instructions::transact::PrivateTxHash, SyncWalletAuthority};

use super::fixtures::Pool;
use super::merge::ZeroDeposits;
use super::transact::write_ring_config_account;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RingRail {
    Eddsa,
    P256,
}

impl RingRail {
    pub fn label(self) -> &'static str {
        match self {
            Self::Eddsa => "ring eddsa",
            Self::P256 => "ring p256",
        }
    }
}

pub struct RingTransactProof {
    pub data: TransactIxData,
    pub ring_program: Pubkey,
    pub ring_config: Pubkey,
    pub nullifiers: Vec<[u8; 32]>,
}

impl RingTransactProof {
    pub fn instruction(&self, payer: Pubkey, tree: Pubkey) -> Instruction {
        let mut ix = Transact {
            payer,
            input_trees: vec![tree],
            output_tree: tree,
            owner_signers: Vec::new(),
            interface_transfer_accounts: Vec::new(),
            data: self.data.clone(),
        }
        .instruction();
        *ix.data.first_mut().expect("instruction tag byte") = tag::RING_TRANSACT;
        ix.accounts
            .insert(5, AccountMeta::new_readonly(self.ring_config, true));
        ix
    }
}

pub struct RealRingTransact {
    pub rail: RingRail,
    pub n_inputs: usize,
    pub n_outputs: usize,
    pub ring_config: Pubkey,
}

impl RealRingTransact {
    pub fn build(self, pool: &mut Pool) -> RingTransactProof {
        let RealRingTransact {
            rail,
            n_inputs,
            n_outputs,
            ring_config,
        } = self;
        assert!(
            n_inputs > 0 && n_outputs > 0,
            "a ring proof needs a real slot each"
        );

        let payer = pool.rpc.payer.insecure_clone();
        let payer_bytes = payer.pubkey().to_bytes();
        let tree = pool.tree;
        let tree_id = pool.tree_id;
        let zero = [0u8; 32];
        let payer_hash = solana_owner_identity(&payer_bytes).expect("payer identity");

        let ring_program = Pubkey::new_from_array(RING_TEST_PROGRAM_ID);
        let config = RingConfig {
            discriminator: RING_CONFIG,
            authority: Address::new_from_array(payer_bytes),
            program_id: Address::new_from_array(ring_program.to_bytes()),
            ring_authority_transact_is_enabled: 0,
            paused: 0,
            activated: 1,
            bump: 0,
        };
        write_ring_config_account(
            &mut pool.rpc,
            ring_config,
            Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
            bytemuck::bytes_of(&config).to_vec(),
        );
        let ring_field = hash_bytes(&ring_program.to_bytes()).expect("ring program field");

        let p256_keypair = ShieldedKeypair::from_keypair(
            SigningKey::from_p256_bytes(&[7u8; 32]).expect("fixed P256 signing key"),
        )
        .expect("P256 shielded keypair");
        let (owner_public_key, input_owner_pk_hash) = match rail {
            RingRail::Eddsa => (PublicKey::from_ed25519(&payer_bytes), payer_hash),
            RingRail::P256 => (p256_keypair.signing_pubkey(), zero),
        };

        let nullifier_key = NullifierKey::from_secret([9u8; 31]);
        let deposits = ZeroDeposits {
            rpc: &mut pool.rpc,
            tree,
            depositor: &payer,
            owner: owner_public_key,
            nullifier_key: &nullifier_key,
            tree_id,
            count: 1,
        }
        .deposit();
        let real = deposits.deposits.first().expect("one real input");
        let utxo_root_index = deposits.utxo_root_index;
        let (utxo_root, nullifier_root) = deposits.roots();
        let tree_slots = single_tree_slots(tree_id, utxo_root, nullifier_root);
        let utxo_hash = real.utxo_hash;
        let nullifier = real.nullifier;

        let mut inputs = vec![spend_input(SpendInputArgs {
            utxo: &real.utxo,
            owner_field: &deposits.owner_field,
            state_path: &real.state_path,
            state_path_index: real.leaf_index,
            non_inclusion: &real.non_inclusion,
            tree_id,
            nullifier: &nullifier,
            owner_pk_hash: &input_owner_pk_hash,
            nullifier_key: &nullifier_key,
        })
        .expect("real input")];
        let mut nullifiers = vec![nullifier];
        for index in 0..n_inputs - 1 {
            let seed = u8::try_from(index)
                .ok()
                .and_then(|index| index.checked_add(31))
                .expect("supported ring input count");
            let (input, dummy_nullifier) =
                dummy_input(&[seed; 31], &deposits.nullifier_tree, tree_id).expect("dummy input");
            inputs.push(input);
            nullifiers.push(dummy_nullifier);
        }

        let mut outputs: Vec<TransferOutput> = (0..n_outputs)
            .map(|position| {
                let seed = u8::try_from(position)
                    .ok()
                    .and_then(|position| position.checked_add(1))
                    .expect("supported ring output count");
                let (output, _) =
                    dummy_transfer_output(&[seed; 31], tree_id).expect("dummy output");
                output
            })
            .collect();
        let output_hashes = derive_test_transfer_output_blindings(&nullifier, &mut outputs)
            .expect("derive output blindings");

        let mut transact_ix_data = new_transact_ix_data(
            nullifiers
                .iter()
                .map(|nullifier| input_utxo(*nullifier))
                .collect(),
            utxo_root_index,
            Vec::new(),
            inline_outputs(&output_hashes, &vec![payer_bytes; n_outputs]),
        );
        let owner_pk_hashes =
            output_owner_pk_hashes(&transact_ix_data.outputs).expect("output owner pk hashes");
        set_output_owner_tags(&mut outputs, &owner_pk_hashes, &vec![zero; n_outputs]);

        let external_data_hash =
            external_data_hash_for_discriminator(&transact_ix_data, tag::RING_TRANSACT, &[])
                .expect("ring external data hash");
        let mut private_inputs = vec![zero; n_inputs];
        if let Some(first) = private_inputs.first_mut() {
            *first = utxo_hash;
        }
        let private_tx_blinding =
            test_private_tx_blinding(&nullifier).expect("private tx blinding");
        let private_tx = PrivateTxHash::new(
            &private_inputs,
            &vec![zero; n_outputs],
            &external_data_hash,
            &private_tx_blinding,
        )
        .hash()
        .expect("private tx hash");

        let mut signer_pk_hashes = vec![payer_hash];
        signer_pk_hashes.extend(std::iter::repeat_n(zero, n_inputs));
        let (public_slot_assets, public_slot_amounts) = sol_public_slots(zero);
        let published_output_owner_pk_hashes = vec![zero; n_outputs];

        let mut chain = vec![
            create_hash_chain_4_from_slice(&nullifiers).expect("nullifier chain"),
            create_hash_chain_4_from_slice(&output_hashes).expect("output chain"),
            tree_slots_hash_chain(&tree_slots).expect("tree slot chain"),
            tree_id_field(tree_id),
            private_tx,
        ];
        let message_digest = sha256(&private_tx);
        let p256_authorization = match rail {
            RingRail::Eddsa => None,
            RingRail::P256 => {
                let authorization = SyncWalletAuthority::sign_p256(&p256_keypair, &message_digest)
                    .expect("P256 authorization");
                let default_owner_tag = authorization.pubkey.x();
                let default_p256_owner_pk_hash =
                    p256_owner_identity(&default_owner_tag).expect("default P256 owner identity");
                chain.push(hash_bytes(&message_digest).expect("P256 message proof input hash"));
                chain.push(default_p256_owner_pk_hash);
                Some((authorization, default_owner_tag, default_p256_owner_pk_hash))
            }
        };
        chain.push(external_data_hash);
        for (asset, amount) in public_slot_assets.iter().zip(public_slot_amounts.iter()) {
            chain.push(*asset);
            chain.push(*amount);
        }
        chain.push(ring_field);
        chain.push(create_right_hash_chain_from_slice(&signer_pk_hashes).expect("signer chain"));
        chain.push(fe(1));
        chain.push(
            create_hash_chain_4_from_slice(&published_output_owner_pk_hashes)
                .expect("output owner chain"),
        );
        let public_input_hash =
            create_hash_chain_4_from_slice(&chain).expect("ring public input hash");

        let n_in = u8::try_from(n_inputs).expect("supported ring input count");
        let n_out = u8::try_from(n_outputs).expect("supported ring output count");
        let n_slots = N_PUBLIC_SLOTS as u8;
        let (proof, circuit) = match p256_authorization {
            None => {
                let mut prover_inputs = build_transfer_prover_inputs(TransferProverInputsArgs {
                    inputs,
                    outputs,
                    tree_slots,
                    output_tree_id: tree_id,
                    blinding_seed: TEST_BLINDING_SEED,
                    external_data_hash,
                    private_tx_hash: private_tx,
                    public_slot_assets,
                    public_slot_amounts,
                    signer_pk_hashes: signer_pk_hashes.clone(),
                    public_input_hash,
                });
                prover_inputs.ring_program_id = be(&ring_field);
                prover_inputs.published_output_owner_pk_hashes =
                    published_output_owner_pk_hashes.iter().map(be).collect();
                let proof = ProverClient::local()
                    .prove_transfer_ring(&prover_inputs)
                    .unwrap_or_else(|error| {
                        panic!("prove ring transfer {n_inputs}x{n_outputs}: {error}")
                    });
                let circuit = CircuitId::RingEddsa(n_in, n_out, n_slots);
                let public_inputs = [public_input_hash];
                let verifying_key = circuit
                    .verifying_key()
                    .expect("supported ring verifying key");
                Groth16Verifier::new(&proof.a, &proof.b, &proof.c, &public_inputs, verifying_key)
                    .expect("construct ring verifier")
                    .verify()
                    .expect("ring proof verifies locally");
                (
                    pack_transact_proof(&proof).expect("pack ring proof"),
                    circuit,
                )
            }
            Some((authorization, default_owner_tag, default_p256_owner_pk_hash)) => {
                let point = authorization
                    .pubkey
                    .to_p256()
                    .expect("P256 public key")
                    .to_encoded_point(false);
                let mut pub_y = [0u8; 32];
                pub_y.copy_from_slice(point.y().expect("P256 y coordinate"));
                let (high, low) = message_digest.split_at(16);
                let prover_inputs = TransferP256Inputs {
                    inputs,
                    outputs,
                    tree_slots: TreeSlotFields::encode_all(&tree_slots),
                    output_tree_id: BigUint::from(tree_id),
                    blinding_seed: be(&TEST_BLINDING_SEED),
                    external_data_hash: be(&external_data_hash),
                    private_tx_hash: be(&private_tx),
                    p256_pub_x: be(&default_owner_tag),
                    p256_pub_y: be(&pub_y),
                    p256_sig_r: be(&authorization.sig_r),
                    p256_sig_s: be(&authorization.sig_s),
                    p256_message_hash_low: BigUint::from_bytes_be(low),
                    p256_message_hash_high: BigUint::from_bytes_be(high),
                    default_p256_owner_pk_hash: be(&default_p256_owner_pk_hash),
                    public_assets: public_slot_assets.map(|asset| be(&asset)),
                    public_amounts: public_slot_amounts.map(|amount| be(&amount)),
                    ring_program_id: be(&ring_field),
                    signer_pk_hashes: signer_pk_hashes.iter().map(be).collect(),
                    allow_dummy_inputs: BigUint::from(1u8),
                    published_output_owner_pk_hashes: published_output_owner_pk_hashes
                        .iter()
                        .map(be)
                        .collect(),
                    public_input_hash: be(&public_input_hash),
                };
                let proof = ProverClient::local()
                    .prove_transfer_p256_ring(&prover_inputs)
                    .unwrap_or_else(|error| {
                        panic!("prove P256 ring transfer {n_inputs}x{n_outputs}: {error}")
                    });
                let (compressed_proof, bsb22_commitment) = ProofCompressed::try_from(proof)
                    .expect("compress P256 ring proof")
                    .into_ring_p256_transact_parts()
                    .expect("split P256 ring proof");
                (
                    compressed_proof,
                    CircuitId::RingP256(
                        n_in,
                        n_out,
                        n_slots,
                        RingP256ProofData {
                            bsb22_commitment,
                            default_owner_tag: Some(default_owner_tag),
                        },
                    ),
                )
            }
        };
        transact_ix_data.proof = proof;
        transact_ix_data.private_tx_hash = private_tx;
        transact_ix_data.circuit = circuit;

        RingTransactProof {
            data: transact_ix_data,
            ring_program,
            ring_config,
            nullifiers,
        }
    }
}
