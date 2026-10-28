use groth16_solana::groth16::Groth16Verifier;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use spr_client::{
    prover::{field::be, transact::AnonymousEddsaAuthorization},
    AnonymousEddsaTransferInputs, ProofCompressed, Prover, ProverClient, ProverExt, TransferOutput,
};
use spr_hasher::{
    hash_chain::{
        create_hash_chain_4_from_slice, create_right_hash_chain_4_from_slice,
        create_right_hash_chain_from_slice,
    },
    primitives::{hash_bytes, solana_owner_identity},
};
use spr_interface::{
    instruction::{
        instruction_data::transact::{CircuitId, TransactIxData},
        tag,
    },
    shape::Shape,
    state::{cache::empty_cached_input_fields, discriminator::RING_CONFIG, RingConfig},
    tree_slot::{pack_input_flags, tree_id_field, tree_slots_hash_chain},
    verifying_keys::AnonymousRingEddsaProofData,
    N_PUBLIC_SLOTS, SHIELDED_POOL_PROGRAM_ID,
};
use spr_keypair::{pubkey::PublicKey, NullifierKey, SigningKey};
use spr_program::instruction::Transact;
use spr_program_test::RING_TEST_PROGRAM_ID;
use spr_test_utils::transact::{
    build_transfer_prover_inputs, derive_test_transfer_output_blindings, dummy_input,
    dummy_transfer_output, external_data_hash_for_discriminator, inline_outputs, input_utxo,
    new_transact_ix_data, output_owner_pk_hashes, pack_transact_proof, set_output_owner_tags,
    single_tree_slots, sol_public_slots, test_private_tx_blinding, transfer_input,
    TransferInputArgs, TransferProverInputsArgs, TEST_BLINDING_SEED,
};
use spr_transaction::instructions::transact::{transact_message_hash, PrivateTxHash};

use super::fixtures::Pool;
use super::merge::ZeroDeposits;
use super::transact::write_ring_config_account;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RingRail {
    Eddsa,
    AnonymousEddsa,
}

impl RingRail {
    pub fn label(self) -> &'static str {
        match self {
            Self::Eddsa => "ring eddsa",
            Self::AnonymousEddsa => "ring anonymous eddsa",
        }
    }
}

pub struct RingTransactProof {
    pub data: TransactIxData,
    pub ring_program: Pubkey,
    pub ring_config: Pubkey,
    pub nullifiers: Vec<[u8; 32]>,
    /// The Ed25519 input owners in the proof's signer vector: the payer on the
    /// Eddsa rail, none on the anonymous rail.
    pub owner_signers: Vec<Pubkey>,
}

impl RingTransactProof {
    pub fn instruction(&self, payer: Pubkey, tree: Pubkey) -> Instruction {
        let mut ix = Transact {
            payer,
            input_trees: vec![tree],
            output_tree: tree,
            owner_signers: self.owner_signers.clone(),
            interface_transfer_accounts: Vec::new(),
            data: self.data.clone(),
        }
        .instruction();
        *ix.data.first_mut().expect("instruction tag byte") = tag::RING_TRANSACT;
        ix.accounts
            .insert(4, AccountMeta::new_readonly(self.ring_config, true));
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

        let hidden_owner = SigningKey::from_ed25519_bytes(&[7u8; 32]);
        let (owner_public_key, input_owner_pk_hash) = match rail {
            RingRail::Eddsa => (PublicKey::from_ed25519(&payer_bytes), payer_hash),
            RingRail::AnonymousEddsa => (hidden_owner.pubkey(), zero),
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

        let mut inputs = vec![transfer_input(TransferInputArgs {
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
            &private_tx_blinding,
        )
        .hash()
        .expect("private tx hash");

        // The payer owns the Eddsa rail's real input and signs as its owner. The
        // hidden owner signs in the proof, so that rail's vector is all padding.
        let owner_signers = match rail {
            RingRail::Eddsa => vec![payer.pubkey()],
            RingRail::AnonymousEddsa => Vec::new(),
        };
        let mut signer_pk_hashes = match rail {
            RingRail::Eddsa => vec![payer_hash],
            RingRail::AnonymousEddsa => Vec::new(),
        };
        signer_pk_hashes.resize(Shape::new(n_inputs, n_outputs).signer_width(), zero);
        let (public_slot_assets, public_slot_amounts) = sol_public_slots(zero);
        let published_output_owner_pk_hashes = vec![zero; n_outputs];

        let mut chain = vec![
            create_right_hash_chain_4_from_slice(&nullifiers).expect("nullifier chain"),
            create_right_hash_chain_4_from_slice(&output_hashes).expect("output chain"),
            tree_slots_hash_chain(&tree_slots).expect("tree slot chain"),
            tree_id_field(tree_id),
            private_tx,
        ];
        let message_digest = transact_message_hash(&private_tx, &external_data_hash);
        let authorization = match rail {
            RingRail::Eddsa => None,
            RingRail::AnonymousEddsa => {
                let owner_public_key = owner_public_key.as_ed25519().expect("Ed25519 owner");
                let authorization = AnonymousEddsaAuthorization {
                    owner_public_key,
                    owner_signature: hidden_owner
                        .sign_message(&message_digest)
                        .expect("hidden owner signature"),
                    message_digest,
                    default_owner_pk_hash: solana_owner_identity(&owner_public_key)
                        .expect("default owner identity"),
                };
                chain.push(hash_bytes(&message_digest).expect("message proof input hash"));
                chain.push(authorization.default_owner_pk_hash);
                Some(authorization)
            }
        };
        chain.push(external_data_hash);
        for (asset, amount) in public_slot_assets.iter().zip(public_slot_amounts.iter()) {
            chain.push(*asset);
            chain.push(*amount);
        }
        chain.push(ring_field);
        chain.push(create_right_hash_chain_from_slice(&signer_pk_hashes).expect("signer chain"));
        let input_flags =
            pack_input_flags(true, std::iter::repeat_n(0u8, n_inputs)).expect("input flags");
        chain.push(input_flags);
        chain.push(
            create_right_hash_chain_4_from_slice(&published_output_owner_pk_hashes)
                .expect("output owner chain"),
        );
        // State-tree spends bind an empty cache selection into the statement.
        let cached_inputs = empty_cached_input_fields(n_inputs).expect("cache selection");
        chain.extend_from_slice(&cached_inputs);
        let public_input_hash =
            create_hash_chain_4_from_slice(&chain).expect("ring public input hash");

        let n_in = u8::try_from(n_inputs).expect("supported ring input count");
        let n_out = u8::try_from(n_outputs).expect("supported ring output count");
        let n_slots = N_PUBLIC_SLOTS as u8;
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
        let (proof, circuit) = match authorization {
            None => {
                let proof = ProverClient::local()
                    .prove_transfer_ring(&prover_inputs)
                    .unwrap_or_else(|error| {
                        panic!("prove ring transfer {n_inputs}x{n_outputs}: {error}")
                    });
                let circuit = CircuitId::ConfidentialRingEddsa(n_in, n_out, n_slots);
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
            Some(authorization) => {
                let default_owner_tag = Some(authorization.owner_public_key);
                let proof = ProverClient::local()
                    .prove(&AnonymousEddsaTransferInputs {
                        transfer: prover_inputs,
                        authorization,
                    })
                    .unwrap_or_else(|error| {
                        panic!("prove anonymous ring transfer {n_inputs}x{n_outputs}: {error}")
                    });
                let (compressed_proof, bsb22_commitment) = ProofCompressed::try_from(proof)
                    .expect("compress anonymous ring proof")
                    .into_committed_transact_parts()
                    .expect("split anonymous ring proof");
                (
                    compressed_proof,
                    CircuitId::AnonymousRingEddsa(
                        n_in,
                        n_out,
                        n_slots,
                        AnonymousRingEddsaProofData {
                            bsb22_commitment,
                            default_owner_tag,
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
            owner_signers,
        }
    }
}
