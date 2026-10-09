//! Ring-rail batch settlement: the test batch program acts as the ring
//! program, so its `ring_auth` PDA is the ring config SPP checks, and its
//! `settle_ring` CPIs SPP `ring_transact` with the batch's inputs and outputs.

use anyhow::{anyhow, ensure, Result};
use num_bigint::BigUint;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::{
    prover::field::be, ProofCompressed, ProverClient, ProverExt, TransferOutput,
    TransferP256Inputs, TreeSlotFields,
};
use zolana_hasher::{
    hash_chain::{
        create_hash_chain_4_from_slice, create_right_hash_chain_4_from_slice,
        create_right_hash_chain_from_slice,
    },
    primitives::{hash_bytes, p256_owner_identity, solana_owner_identity},
};
use zolana_interface::{
    instruction::{
        instruction_data::transact::{CircuitId, TransactIxData},
        tag,
    },
    pda,
    shape::Shape,
    state::{cache::empty_cached_input_fields, discriminator::RING_CONFIG, RingConfig},
    tree_slot::{pack_input_flags, tree_id_field, tree_slots_hash_chain},
    verifying_keys::RingP256ProofData,
    N_PUBLIC_SLOTS, SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::{pubkey::PublicKey, NullifierKey, ShieldedKeypair, SigningKey};
use zolana_program::instruction::Transact;
use zolana_program_test::ZolanaProgramTest;
use zolana_test_utils::{
    prover::spawn_workspace_prover,
    transact::{
        build_transfer_prover_inputs, compact_input, derive_test_transfer_output_blindings,
        dummy_input, dummy_transfer_output, external_data_hash_for_discriminator, inline_outputs,
        input_utxo, new_transact_ix_data, output_owner_pk_hashes, pack_transact_proof,
        set_output_owner_tags, single_tree_slots, sol_public_slots, test_private_tx_blinding,
        transfer_input, TransferInputArgs, TransferProverInputsArgs, TEST_BLINDING_SEED,
    },
    wallet::SyncWalletAuthority,
};
use zolana_transaction::{
    instructions::transact::{transact_message_hash, PrivateTxHash},
    SppProofOutputUtxo,
};

use super::{
    batch::{prove_twice, ProvenSpend, BATCH_PROGRAM_ID},
    merge::ZeroDeposits,
    ring::RingRail,
    transact::write_ring_config_account,
};

/// The ring config SPP checks for a ring transact the batch program signs:
/// the batch program's `ring_auth` PDA.
pub fn batch_ring_config() -> Pubkey {
    pda::ring_auth(&BATCH_PROGRAM_ID).0
}

/// The SPP `ring_transact` instruction for a spend from and into `tree`, with
/// the batch program's ring config. `ring_config_signs` is set for a direct
/// call (the runtime harness signs it); the batch settle forwards it unsigned
/// and the batch program signs it in the CPI.
pub fn ring_transact_instruction(
    payer: Pubkey,
    tree: Pubkey,
    data: TransactIxData,
    ring_config_signs: bool,
) -> Instruction {
    let mut ix = Transact {
        payer,
        input_trees: vec![tree],
        output_tree: tree,
        owner_signers: Vec::new(),
        interface_transfer_accounts: Vec::new(),
        data,
    }
    .instruction();
    if let Some(first) = ix.data.first_mut() {
        *first = tag::RING_TRANSACT;
    }
    ix.accounts.insert(
        4,
        AccountMeta::new_readonly(batch_ring_config(), ring_config_signs),
    );
    ix
}

/// A ring transact on `rail` at the `n_inputs x n_outputs` shape: one real
/// zero-amount deposit input, `sent_inputs - 1` dummy inputs and
/// `sent_outputs` dummy outputs, the remaining slots compact padding.
/// `ring_data_hash` is bound into the external data like a ring program's
/// digest would be. Without `prove`, the proof stays zeroed.
pub struct RingScalingSpend {
    pub rail: RingRail,
    pub n_inputs: usize,
    pub n_outputs: usize,
    pub sent_inputs: usize,
    pub sent_outputs: usize,
    pub ring_data_hash: Option<[u8; 32]>,
    /// The dummy-input policy the proof is built for: SPP publishes `false`
    /// once the input tree's dummy-input headroom is below the sent inputs.
    pub allow_dummy_inputs: bool,
    pub prove: bool,
}

impl RingScalingSpend {
    pub fn build(
        &self,
        pt: &mut ZolanaProgramTest,
        tree: Pubkey,
        tree_id: u16,
    ) -> Result<ProvenSpend> {
        let Self {
            rail,
            n_inputs,
            n_outputs,
            sent_inputs,
            sent_outputs,
            ring_data_hash,
            allow_dummy_inputs,
            prove,
        } = *self;
        ensure!(
            (1..=n_inputs).contains(&sent_inputs) && sent_outputs <= n_outputs,
            "sent counts out of range"
        );
        let payer = pt.payer.insecure_clone();
        let payer_bytes = payer.pubkey().to_bytes();
        let zero = [0u8; 32];
        let payer_hash = solana_owner_identity(&payer_bytes)?;

        let ring_config = batch_ring_config();
        let config = RingConfig {
            discriminator: RING_CONFIG,
            authority: Address::new_from_array(payer_bytes),
            program_id: Address::new_from_array(BATCH_PROGRAM_ID.to_bytes()),
            ring_authority_transact_is_enabled: 0,
            paused: 0,
            activated: 1,
            bump: 0,
        };
        write_ring_config_account(
            pt,
            ring_config,
            Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
            bytemuck::bytes_of(&config).to_vec(),
        );
        let ring_field = hash_bytes(&BATCH_PROGRAM_ID.to_bytes())?;

        let p256_keypair = ShieldedKeypair::from_keypair(SigningKey::from_p256_bytes(&[7u8; 32])?)?;
        let (owner_public_key, input_owner_pk_hash) = match rail {
            RingRail::Eddsa => (PublicKey::from_ed25519(&payer_bytes), payer_hash),
            RingRail::P256 => (p256_keypair.signing_pubkey(), zero),
        };

        let nullifier_key = NullifierKey::from_secret([9u8; 31]);
        let deposits = ZeroDeposits {
            rpc: pt,
            tree,
            depositor: &payer,
            owner: owner_public_key,
            nullifier_key: &nullifier_key,
            tree_id,
            count: 1,
        }
        .deposit();
        let real = deposits
            .deposits
            .first()
            .ok_or_else(|| anyhow!("one real input"))?;
        let (utxo_root, nullifier_root) = deposits.roots();
        let tree_slots = single_tree_slots(tree_id, utxo_root, nullifier_root);
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
        })?];
        let mut nullifiers = vec![nullifier];
        for index in 1..sent_inputs {
            let seed = u8::try_from(index + 31)?;
            let (input, dummy_nullifier) =
                dummy_input(&[seed; 31], &deposits.nullifier_tree, tree_id)?;
            inputs.push(input);
            nullifiers.push(dummy_nullifier);
        }
        for _ in sent_inputs..n_inputs {
            inputs.push(compact_input(&deposits.nullifier_tree, tree_id)?);
        }
        let mut padded_nullifiers = nullifiers.clone();
        padded_nullifiers.resize(n_inputs, zero);

        let mut outputs: Vec<TransferOutput> = Vec::with_capacity(n_outputs);
        for position in 0..sent_outputs {
            let seed = u8::try_from(position + 1)?;
            outputs.push(dummy_transfer_output(&[seed; 31], tree_id)?.0);
        }
        let compact = SppProofOutputUtxo {
            compact: true,
            ..Default::default()
        };
        for _ in sent_outputs..n_outputs {
            let (mut output, _) = dummy_transfer_output(&[0u8; 31], tree_id)?;
            output.utxo = zolana_client::ProofInputUtxo::try_from((&compact, tree_id))?;
            outputs.push(output);
        }
        let mut output_hashes = derive_test_transfer_output_blindings(&nullifier, &mut outputs)?;
        for (output, hash) in outputs
            .iter_mut()
            .zip(output_hashes.iter_mut())
            .skip(sent_outputs)
        {
            output.hash = BigUint::ZERO;
            *hash = zero;
        }
        let sent_hashes = output_hashes
            .get(..sent_outputs)
            .ok_or_else(|| anyhow!("sent output hashes"))?;

        let mut data = new_transact_ix_data(
            nullifiers
                .iter()
                .map(|nullifier| input_utxo(*nullifier))
                .collect(),
            deposits.utxo_root_index,
            Vec::new(),
            inline_outputs(sent_hashes, &vec![payer_bytes; sent_outputs]),
        );
        data.ring_data_hash = ring_data_hash;
        let n_in = u8::try_from(n_inputs)?;
        let n_out = u8::try_from(n_outputs)?;
        let n_slots = N_PUBLIC_SLOTS as u8;
        data.circuit = match rail {
            RingRail::Eddsa => CircuitId::RingEddsa(n_in, n_out, n_slots),
            RingRail::P256 => CircuitId::RingP256(
                n_in,
                n_out,
                n_slots,
                RingP256ProofData {
                    bsb22_commitment: zolana_interface::verifying_keys::Bsb22Commitment {
                        commitment: zero,
                        commitment_pok: zero,
                    },
                    default_owner_tag: Some(zero),
                },
            ),
        };
        if !prove {
            return Ok(ProvenSpend { data, timing: None });
        }

        let owner_pk_hashes = output_owner_pk_hashes(&data.outputs)?;
        set_output_owner_tags(&mut outputs, &owner_pk_hashes, &vec![zero; sent_outputs]);
        let external_data_hash =
            external_data_hash_for_discriminator(&data, tag::RING_TRANSACT, &[])?;
        let mut private_inputs = vec![zero; n_inputs];
        if let Some(first) = private_inputs.first_mut() {
            *first = real.utxo_hash;
        }
        let private_tx = PrivateTxHash::new(
            &private_inputs,
            &vec![zero; n_outputs],
            &test_private_tx_blinding(&nullifier)?,
        )
        .hash()?;

        let mut signer_pk_hashes = vec![payer_hash];
        signer_pk_hashes.resize(Shape::new(n_inputs, n_outputs).signer_width(), zero);
        let (public_slot_assets, public_slot_amounts) = sol_public_slots(zero);
        let published_output_owner_pk_hashes = vec![zero; n_outputs];

        let mut chain = vec![
            create_right_hash_chain_4_from_slice(&padded_nullifiers)?,
            create_right_hash_chain_4_from_slice(&output_hashes)?,
            tree_slots_hash_chain(&tree_slots)?,
            tree_id_field(tree_id),
            private_tx,
        ];
        let message_digest = transact_message_hash(&private_tx, &external_data_hash);
        let p256_authorization = match rail {
            RingRail::Eddsa => None,
            RingRail::P256 => {
                let authorization = SyncWalletAuthority::sign_p256(&p256_keypair, &message_digest)?;
                let default_owner_tag = authorization.pubkey.x();
                let default_p256_owner_pk_hash = p256_owner_identity(&default_owner_tag)?;
                chain.push(hash_bytes(&message_digest)?);
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
        chain.push(create_right_hash_chain_from_slice(&signer_pk_hashes)?);
        let input_flags = pack_input_flags(allow_dummy_inputs, std::iter::repeat_n(0u8, n_inputs))?;
        chain.push(input_flags);
        chain.push(create_right_hash_chain_4_from_slice(
            &published_output_owner_pk_hashes,
        )?);
        let cached_inputs = empty_cached_input_fields(n_inputs)?;
        chain.extend_from_slice(&cached_inputs);
        let public_input_hash = create_hash_chain_4_from_slice(&chain)?;

        spawn_workspace_prover(zolana_client::IndexerRequirement::Optional);
        let prover = ProverClient::local();
        let (proof, circuit, timing) = match p256_authorization {
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
                    signer_pk_hashes,
                    public_input_hash,
                });
                prover_inputs.ring_program_id = be(&ring_field);
                prover_inputs.input_flags = be(&input_flags);
                prover_inputs.published_output_owner_pk_hashes =
                    published_output_owner_pk_hashes.iter().map(be).collect();
                let (proof, timing) = prove_twice(&format!("ring {n_inputs}x{n_outputs}"), || {
                    prover.prove_transfer_ring(&prover_inputs)
                })?;
                (
                    pack_transact_proof(&proof)?,
                    CircuitId::RingEddsa(n_in, n_out, n_slots),
                    timing,
                )
            }
            Some((authorization, default_owner_tag, default_p256_owner_pk_hash)) => {
                let point = authorization.pubkey.to_p256()?.to_encoded_point(false);
                let mut pub_y = [0u8; 32];
                pub_y.copy_from_slice(point.y().ok_or_else(|| anyhow!("P256 y"))?);
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
                    input_flags: be(&input_flags),
                    published_output_owner_pk_hashes: published_output_owner_pk_hashes
                        .iter()
                        .map(be)
                        .collect(),
                    cache: zolana_client::CacheReadInputs::uncached(cached_inputs),
                    public_input_hash: be(&public_input_hash),
                };
                let (proof, timing) = prove_twice(&format!("P256 {n_inputs}x{n_outputs}"), || {
                    prover.prove_transfer_p256_ring(&prover_inputs)
                })?;
                let (compressed_proof, bsb22_commitment) =
                    ProofCompressed::try_from(proof)?.into_ring_p256_transact_parts()?;
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
                    timing,
                )
            }
        };
        data.proof = proof;
        data.private_tx_hash = private_tx;
        data.circuit = circuit;
        Ok(ProvenSpend {
            data,
            timing: Some(timing),
        })
    }
}
