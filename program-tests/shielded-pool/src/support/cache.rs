//! A `transact` whose inputs are drawn from a cache instead of the state tree.
//!
//! The cache replaces state inclusion, so the cached UTXOs are never appended
//! to the tree: the fixture seats their hashes directly, the way a merge would,
//! and a group whose inputs are all cached publishes no UTXO root. Everything
//! else is unchanged, so a cached spend still proves ownership and nullifier
//! non-inclusion.

use solana_clock::Clock;
use solana_instruction::Instruction;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::{ProverClient, PublicInputs, PublicTransfers};
use zolana_hasher::primitives::solana_owner_identity;
use zolana_interface::{
    instruction::instruction_data::{
        transact::{CacheAccess, CircuitId, NO_UTXO_ROOT},
        CreateCacheData,
    },
    pda,
    shape::Shape,
    state::{
        cache::{CacheAccount, CACHE_CAPACITY},
        discriminator::CACHE,
    },
    N_PUBLIC_SLOTS,
};
use zolana_keypair::{pubkey::PublicKey, NullifierKey};
use zolana_program::instruction::{CreateCache, Transact};
use zolana_program_test::ZolanaProgramTest;
use zolana_test_utils::{
    prover::spawn_workspace_prover,
    transact::{
        build_transfer_prover_inputs, cache_read_selection, cached_spend_input,
        derive_test_transfer_output_blindings, dummy_input, dummy_transfer_output,
        external_data_hash, fe, inline_outputs, input_utxo, new_transact_ix_data, nullifier_tree,
        output_owner_pk_hashes, pack_transact_proof, real_output, set_output_owner_tags,
        single_tree_slots, sol_public_slots, test_private_tx_blinding, transfer_output,
        TransferProverInputsArgs, TEST_BLINDING_SEED,
    },
};
use zolana_transaction::{instructions::transact::PrivateTxHash, Mint};

use crate::support::transact::tree_roots;

/// The proven instruction plus what a caller needs to assert against it.
pub struct CachedSpend {
    pub instruction: Instruction,
    pub cache: Pubkey,
    /// The UTXO hashes seated in the cache, in slot order.
    pub commitments: Vec<[u8; 32]>,
    pub nullifiers: Vec<[u8; 32]>,
}

/// Builds a `transact` that spends cached UTXOs into one real zero-amount
/// output plus dummies.
pub struct CachedSpendFixture {
    pub n_inputs: usize,
    pub n_outputs: usize,
    /// Distinguishes the cache PDA from any other this test creates.
    pub cache_nonce: u64,
    /// How many leading inputs are drawn from the cache; the rest are padding.
    /// A selection shorter than `n_inputs` leaves the commitment chain with a
    /// zero tail, which is the case the right fold seeds past instead of
    /// hashing, so it is what makes the saving measurable.
    pub cached_slots: usize,
}

impl CachedSpendFixture {
    /// Every input drawn from the cache: the chain has no zero tail and the
    /// fold does its full group count.
    pub fn all_cached(n_inputs: usize, n_outputs: usize, cache_nonce: u64) -> Self {
        Self {
            n_inputs,
            n_outputs,
            cache_nonce,
            cached_slots: n_inputs,
        }
    }
}

impl CachedSpendFixture {
    pub fn build(self, rpc: &mut ZolanaProgramTest, tree: Pubkey, tree_id: u16) -> CachedSpend {
        assert!(
            self.n_inputs <= CACHE_CAPACITY,
            "a cache holds at most one slot per input"
        );
        assert!(self.n_outputs >= 1, "a spend needs one real output");
        assert!(
            (1..=self.n_inputs).contains(&self.cached_slots),
            "a cached spend draws between one input and all of them from the cache"
        );
        spawn_workspace_prover();

        let payer = rpc.payer.insecure_clone();
        let payer_bytes = payer.pubkey().to_bytes();
        let zero = [0u8; 32];
        let owner = PublicKey::from_ed25519(&payer_bytes);
        let payer_identity = solana_owner_identity(&payer_bytes).expect("payer identity");
        let (_, nullifier_root) = tree_roots(rpc, &tree, 0);
        let tree_slots = single_tree_slots(tree_id, zero, nullifier_root);

        let nf_tree = nullifier_tree().expect("indexed nullifier tree");
        assert_eq!(
            nf_tree.root(),
            nullifier_root,
            "the fixture's nullifier tree must match the tree account's root"
        );
        let nullifier_key = NullifierKey::from_secret([21u8; 31]);
        let mut inputs = Vec::with_capacity(self.n_inputs);
        let mut nullifiers = Vec::with_capacity(self.n_inputs);
        // Unselected slots stay zero: that is what the circuit masks them to
        // and what the program reconstructs, so this vector is the chain's
        // preimage as well as what the cache holds.
        let mut commitments = vec![zero; self.n_inputs];
        for (index, commitment) in commitments.iter_mut().enumerate() {
            if index < self.cached_slots {
                let spend = cached_spend_input(
                    owner,
                    &nullifier_key,
                    &[index as u8 + 41; 31],
                    &nf_tree,
                    tree_id,
                )
                .expect("cached spend input");
                *commitment = spend.commitment;
                nullifiers.push(spend.nullifier);
                inputs.push(spend.input);
            } else {
                let (input, nullifier) =
                    dummy_input(&[index as u8 + 41; 31], &nf_tree, tree_id).expect("dummy input");
                nullifiers.push(nullifier);
                inputs.push(input);
            }
        }

        let cache = self.seat_cache(rpc, tree_id, &commitments);
        let reads: Vec<_> = commitments
            .iter()
            .enumerate()
            .map(|(slot, commitment)| (*commitment != zero).then_some((slot as u8, *commitment)))
            .collect();
        let selection = cache_read_selection(tree_id, &reads).expect("cache selection");

        let nullifier_pk = nullifier_key.pubkey().expect("nullifier pubkey");
        let real = real_output(owner, nullifier_pk, Mint::SOL, 0, [23u8; 31]);
        let mut outputs = vec![transfer_output(&real, tree_id).expect("real transfer output")];
        for index in 1..self.n_outputs {
            let (output, _) =
                dummy_transfer_output(&[index as u8; 31], tree_id).expect("dummy output");
            outputs.push(output);
        }
        let first_nullifier = *nullifiers.first().expect("a cached spend has an input");
        let output_hashes = derive_test_transfer_output_blindings(&first_nullifier, &mut outputs)
            .expect("derive output blindings");

        let owner_view_tag = owner.confidential_view_tag().expect("owner view tag");
        let mut view_tags = vec![owner_view_tag];
        view_tags.extend(std::iter::repeat_n(payer_bytes, self.n_outputs - 1));
        let mut ix_data = new_transact_ix_data(
            nullifiers.iter().map(|n| input_utxo(*n)).collect(),
            NO_UTXO_ROOT,
            Vec::new(),
            inline_outputs(&output_hashes, &view_tags),
        );
        ix_data.circuit = CircuitId::ConfidentialEddsaCached(
            self.n_inputs as u8,
            self.n_outputs as u8,
            N_PUBLIC_SLOTS as u8,
            CacheAccess {
                read_bitmap: selection.read_bitmap,
                write_slots: CacheAccess::NO_WRITES,
            },
        );

        let owner_pk_hashes =
            output_owner_pk_hashes(&ix_data.outputs).expect("output owner pk hashes");
        let mut nullifier_pks = vec![nullifier_pk];
        nullifier_pks.extend(std::iter::repeat_n(zero, self.n_outputs - 1));
        set_output_owner_tags(&mut outputs, &owner_pk_hashes, &nullifier_pks);
        let external_data_hash = external_data_hash(&ix_data, &[]).expect("external data hash");
        let mut private_outputs = vec![*output_hashes.first().expect("one real output")];
        private_outputs.extend(std::iter::repeat_n(zero, self.n_outputs - 1));
        // The private transaction hash binds the real inputs' commitments; a
        // padding slot contributes zero, which is already what `commitments`
        // holds for it.
        let private_tx = PrivateTxHash::new(
            &commitments,
            &private_outputs,
            &external_data_hash,
            &test_private_tx_blinding(&first_nullifier).expect("private tx blinding"),
        )
        .hash()
        .expect("private tx hash");

        let mut signer_pk_hashes =
            vec![zero; Shape::new(self.n_inputs, self.n_outputs).signer_width()];
        if let Some(first) = signer_pk_hashes.first_mut() {
            *first = payer_identity;
        }
        let (public_slot_assets, public_slot_amounts) = sol_public_slots(zero);
        let public_input_hash = PublicInputs {
            nullifiers: &nullifiers,
            output_hashes: &output_hashes,
            tree_slots: &tree_slots,
            output_tree_id: tree_id,
            private_tx: &private_tx,
            external_data_hash: &external_data_hash,
            public_transfers: &PublicTransfers {
                assets: public_slot_assets,
                amounts: public_slot_amounts,
            },
            ring_program_id: &zero,
            input_flags: &fe(1),
            signer_pk_hashes: &signer_pk_hashes,
            output_owner_pk_hashes: Some(&owner_pk_hashes),
            cached_inputs: selection.public_fields,
        }
        .hash()
        .expect("public input hash");

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
        prover_inputs.cache = selection.proof_inputs;

        let n_inputs = self.n_inputs;
        let n_outputs = self.n_outputs;
        let proof = ProverClient::local()
            .prove_transfer(&prover_inputs)
            .unwrap_or_else(|error| {
                panic!("prove cached transfer {n_inputs}x{n_outputs}: {error}")
            });
        ix_data.proof = pack_transact_proof(&proof).expect("pack transfer proof");
        ix_data.private_tx_hash = private_tx;

        let instruction = Transact {
            payer: payer.pubkey(),
            input_trees: vec![tree],
            output_tree: tree,
            owner_signers: Vec::new(),
            interface_transfer_accounts: Vec::new(),
            data: ix_data,
        }
        .instruction_with_cache_read(cache);

        CachedSpend {
            instruction,
            cache,
            commitments,
            nullifiers,
        }
    }

    /// Create the cache the way an operator does, then seat the commitments a
    /// merge would have written into it.
    fn seat_cache(
        &self,
        rpc: &mut ZolanaProgramTest,
        tree_id: u16,
        commitments: &[[u8; 32]],
    ) -> Pubkey {
        let sponsor = rpc.payer.pubkey();
        let expires_at = rpc.svm.get_sysvar::<Clock>().unix_timestamp + 3_600;
        rpc.create_and_send_default_payer_transaction(
            &[CreateCache {
                payer: sponsor,
                data: CreateCacheData {
                    write_authority: sponsor,
                    nonce: self.cache_nonce,
                    tree_id,
                    expires_at,
                },
            }
            .instruction()],
            &[],
        )
        .expect("create the cache");

        let (cache, _bump) = pda::cache(&sponsor, self.cache_nonce);
        let mut account = rpc.svm.get_account(&cache).expect("cache account");
        let mut state: CacheAccount = *bytemuck::from_bytes(&account.data);
        assert_eq!(state.discriminator, CACHE, "cache is initialized");
        for (slot, commitment) in state.utxo_hashes.iter_mut().zip(commitments) {
            *slot = *commitment;
        }
        account.data = bytemuck::bytes_of(&state).to_vec();
        rpc.svm
            .set_account(cache, account)
            .expect("seat cache commitments");
        cache
    }
}
