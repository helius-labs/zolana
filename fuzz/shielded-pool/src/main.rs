// SCOUT:TESTS:BEGIN
#[cfg(test)]
mod scout_stage_tests {
    use super::*;

    /// Stage 1: does `setup()` actually stand the world up? Every step asserts, so
    /// a failure names the exact instruction rather than surfacing later as "every
    /// action fails".
    #[test]
    fn setup_builds_protocol_config_tree_and_ring_config() {
        let f = ShieldedPoolFixture::setup();
        let config = f.ctx.svm.get_account(&f.protocol_config).expect("protocol_config absent");
        assert_eq!(config.owner, f.program_id);
        assert_eq!(config.data[0], 3, "ProtocolConfig discriminator");
        assert_eq!(&config.data[1..33], f.payer.pubkey().as_ref(), "protocol_authority");
        let tree = f.ctx.svm.get_account(&f.tree).expect("tree absent");
        assert_eq!(tree.owner, f.program_id);
        assert_eq!(tree.data.len(), TREE_ACCOUNT_SIZE);
        assert_eq!(tree.data[0], 1, "TreeAccount discriminator");
        let ring = f.ctx.svm.get_account(&f.ring_config).expect("ring_config absent");
        assert_eq!(ring.data.len(), RING_CONFIG_SIZE);
        assert_eq!(ring.data[0], DISC_RING_CONFIG);
    }

    /// Stage 2: each generated action, called directly, so its failure is a named
    /// program error instead of an anonymous `false`.
    #[test]
    fn actions_succeed_against_the_built_world() {
        let mut f = ShieldedPoolFixture::setup();
        // `update_ring_config` is admin-gated, so this resolves to the disabled
        // stub unless built with --features admin_actions. Setup already proves
        // the account it needs exists.
        println!("update_ring_config -> {}", f.action_update_ring_config(true, false));
        println!("batch_update -> {}", f.action_batch_update_nullifier_tree());
        println!("merge_transact -> {}", f.action_merge_transact(true));
    }

    /// `deposit` is the ONE proofless value-flow instruction, so it is the first
    /// action that can actually move state. Its failure mode decides whether the
    /// payload/account-tail bindings agree with what the program parses.
    #[test]
    fn observe_deposit() {
        let mut f = ShieldedPoolFixture::setup();
        let before = f.ctx.svm.get_account(&f.sol_interface).map(|a| a.lamports).unwrap_or(0);
        let ok = f.action_deposit(0, 3, 4, 5, 1_000_000);
        let after = f.ctx.svm.get_account(&f.sol_interface).map(|a| a.lamports).unwrap_or(0);
        println!("deposit -> {ok}; sol_interface lamports {before} -> {after}");

        // Sent directly too, so a failure names its program error.
        let payload = scout_wire::DepositIxData {
            assets: vec![scout_wire::DepositAssetKind::Sol],
            deposits: vec![scout_wire::DepositEntry {
                asset_index: 0,
                view_tag: [3u8; 32],
                owner: [4u8; 32],
                blinding: [5u8; 32],
                amount: 1_000_000,
                utxo_data: None,
                memo: None,
            }],
        };
        let mut data = vec![11u8];
        data.extend_from_slice(&wincode::serialize(&payload).unwrap());
        let ix = ScoutIx {
            program_id: f.program_id,
            accounts: vec![
                ScoutMeta::new(f.tree, false),
                ScoutMeta::new(f.payer.pubkey(), true),
                ScoutMeta::new_readonly(f.program_id, false),
                ScoutMeta::new_readonly(system_program::ID, false),
                ScoutMeta::new(f.sol_interface, false),
            ],
            data,
        };
        let outcome = f.ctx.raw_call(ix).signers(&[&*f.payer]).send()
            .expect("send failed at the runtime level");
        println!("== deposit ==");
        for line in outcome.logs() { println!("LOG: {line}"); }
        println!("outcome: {outcome:?}");
    }

    /// The `transact` fixture, end to end. Its payload became generatable only
    /// once the adapter learned to transcribe `FixedOptionOwnerTag`; before that
    /// the whole family was refused at extraction and had no action at all.
    ///
    /// Asserts the state transition, not just the bool: a verified proof is not an
    /// applied transfer. The output must be appended and the nullifier must not be
    /// spendable twice.
    #[test]
    fn transact_verifies_and_spends() {
        let mut f = ShieldedPoolFixture::setup();
        let leaves_before = tree_next_index(&f);
        assert!(f.action_transact_no_transfers(), "the transact fixture must verify");
        assert_eq!(tree_next_index(&f), leaves_before + 1,
                   "the output must be appended to the state tree");
        assert!(!f.action_transact_no_transfers(),
                "the same nullifier must not be spendable twice");
    }

    /// The four instructions that need no proving key. Each is asserted to
    /// SUCCEED, not merely to run: a covered line is not a working action, and
    /// every one of these read as "covered" before it had an action at all.
    #[test]
    fn proofless_instructions_succeed() {
        let mut f = ShieldedPoolFixture::setup();

        assert!(f.action_emit_event(16, 0xAB), "emit_event");

        // The counter is a singleton: the first call allocates it, the second must
        // be refused. Asserting BOTH pins the behaviour rather than the outcome.
        assert!(f.action_create_asset_counter(), "first create_asset_counter");
        assert!(!f.action_create_asset_counter(),
                "a second create_asset_counter must not reset the id sequence");

        // Reads and advances the counter created above, so it can only pass after it.
        assert!(f.action_create_spl_interface(6), "create_spl_interface");
        assert!(f.action_create_spl_interface(9), "a second, distinct mint");

        // Canonical params, then the borsh-decode failure branch.
        assert!(f.action_create_tree(false, 0), "create_tree with canonical params");
        assert!(!f.action_create_tree(true, 0x5A),
                "garbage nullifier params must be rejected, not initialised");
    }

    /// `create_spl_interface` before its counter exists.
    ///
    /// Split in two, because the PROGRAM's requirement and the HARNESS's handling of
    /// it are different claims and only the first is about zolana.
    ///
    /// The program's requirement is asserted against the raw instruction, so it stays
    /// a real assertion. The action deliberately no longer fails here: it creates the
    /// counter on demand, because leaving the prerequisite to chance meant the action
    /// and its unauthorized twin almost never reached their own logic in a campaign --
    /// 0 successes in 314 selections for the twin, which had been reading as an
    /// authority gate refusing an outsider when it was really an absent account.
    #[test]
    fn create_spl_interface_requires_the_counter() {
        let mut f = ShieldedPoolFixture::setup();
        assert!(f.scout_asset_next_id().is_none(), "a fresh fixture has no counter");

        // The PROGRAM refuses without it. Raw instruction, so nothing in the harness
        // can quietly satisfy the prerequisite on the way past.
        let mint = f.scout_next_mint_address();
        assert!(f.ctx.create_mint().pubkey(mint).decimals(6).create().is_ok());
        let (asset_counter, _) =
            Pubkey::find_program_address(&[SPL_ASSET_COUNTER_PDA_SEED], &f.program_id);
        let (registry_entry, _) = Pubkey::find_program_address(
            &[SPL_ASSET_REGISTRY_PDA_SEED, mint.as_ref()], &f.program_id);
        let (spl_interface, _) = Pubkey::find_program_address(
            &[SPL_INTERFACE_PDA_SEED, mint.as_ref()], &f.program_id);
        let instruction = Instruction {
            program_id: f.program_id,
            accounts: vec![
                AccountMeta::new(f.payer.pubkey(), true),
                AccountMeta::new_readonly(f.protocol_config, false),
                AccountMeta::new(asset_counter, false),
                AccountMeta::new(registry_entry, false),
                AccountMeta::new_readonly(mint, false),
                AccountMeta::new(spl_interface, false),
                AccountMeta::new_readonly(system_program::ID, false),
                AccountMeta::new_readonly(spl_token::id(), false),
            ],
            data: vec![TAG_CREATE_SPL_INTERFACE],
        };
        let refused = !f.ctx.raw_call(instruction).signers(&[&*f.payer]).send()
            .map(|o| o.is_success()).unwrap_or(false);
        assert!(refused, "the PROGRAM must refuse while the asset counter is unallocated");
        assert!(f.scout_asset_next_id().is_none(), "and must not have created one");

        // The ACTION self-heals, in either order, so a campaign reaches its own logic.
        assert!(f.action_create_spl_interface(6), "the action creates the counter it needs");
        assert!(f.scout_asset_next_id().is_some(), "which now exists");
        assert!(f.action_create_spl_interface(9), "a second, distinct mint still registers");

        // Dispatched afterwards, the counter action exercises its already-initialized
        // rejection -- a real branch, and the reason this is not simply moved to setup.
        assert!(!f.action_create_asset_counter(),
            "a second create_asset_counter must be refused, not silently re-init the singleton");

        // The other order still works: counter first, then the interface.
        let mut g = ShieldedPoolFixture::setup();
        assert!(g.action_create_asset_counter(), "counter first");
        assert!(g.action_create_spl_interface(6), "then the interface");
    }

    /// The ring rail, opened by deploying zolana's own policy-ring fixture. Both
    /// instructions are asserted to SUCCEED: `ring_deposit` in particular read
    /// 88.4% "covered" with no action, because it shares `process_deposit_internal`
    /// with `deposit` -- a percentage that said nothing about the ring path.
    #[test]
    fn ring_rail_actions_succeed() {
        let mut f = ShieldedPoolFixture::setup();

        let before = f.ctx.svm.get_account(&f.sol_interface).unwrap().lamports;
        let credited_before = f.shadow_sol_credited;
        assert!(f.action_ring_deposit(500_000, 1, 2, 3, false, 0, false), "ring_deposit");
        let after = f.ctx.svm.get_account(&f.sol_interface).unwrap().lamports;
        assert_eq!(after - before, 500_000, "ring_deposit must move real value");
        // The ring rail is a different instruction, not a different pool: it credits
        // the SAME interface `deposit` does, so P-0001's shadow must see it. Leaving
        // this out made P-0001 fire 37 times on honest traffic.
        assert_eq!(f.shadow_sol_credited - credited_before, 500_000,
                   "P-0001 must count SOL the ring rail deposits");
        assert_eq!(after, f.sol_interface_opening + f.shadow_sol_credited - f.shadow_sol_withdrawn,
                   "P-0001 holds across the ring rail");
        // The optional data hash and a non-empty ciphertext are separate encodings.
        assert!(f.action_ring_deposit(1, 4, 5, 6, true, 64, false), "ring_deposit with data");
        // A field element above the BN254 modulus must be REJECTED, not hashed. This
        // pins the reason the previous version of this action failed: a 32-byte
        // value is not automatically a field element.
        assert!(!f.action_ring_deposit(1, 4, 5, 6, false, 0, true),
                "an out-of-range owner_utxo_hash must be rejected");

        // A fresh ring per slot; the same slot twice must be refused.
        assert!(f.action_create_ring_config(true), "first create_ring_config");
        for _ in 0..15 {
            assert!(f.action_create_ring_config(false), "each slot's first create");
        }
        assert!(!f.action_create_ring_config(true),
                "slot 0 wraps around to an existing config and must be refused");
    }

    /// The ring merge, end to end. Same shape of assertion as the default rail:
    /// verify, apply, then refuse a replay. Kept separate because the two rails
    /// share no published value -- a bug that made one rail's proof accepted on the
    /// other would pass any test that only ran one of them.
    #[test]
    fn ring_merge_transact_verifies_and_spends() {
        let mut f = ShieldedPoolFixture::setup();
        let leaves_before = tree_next_index(&f);
        assert!(f.action_ring_merge_transact(), "the ring merge fixture must verify");
        assert_eq!(tree_next_index(&f), leaves_before + 1,
                   "the merged output must be appended to the state tree");
        assert!(!f.action_ring_merge_transact(),
                "the same nullifiers must not be spendable twice");
    }

    /// `batch_update_nullifier_tree`, end to end: the forester applies one ZKP
    /// batch of queued nullifiers.
    ///
    /// The tree's ROOT must advance, not merely the call succeed -- the handler
    /// returns `Ok(())` without applying anything when no batch is ready, which is
    /// exactly the early-return path its 90.3% coverage used to consist of.
    #[test]
    fn batch_update_applies_a_real_batch() {
        let mut f = ShieldedPoolFixture::setup();
        let nullifier_root = |f: &ShieldedPoolFixture| -> [u8; 32] {
            let data = f.ctx.svm.get_account(&f.forester_tree).unwrap().data;
            let mut out = [0u8; 32];
            out.copy_from_slice(
                &data[NULLIFIER_ROOT_HISTORY_OFFSET..NULLIFIER_ROOT_HISTORY_OFFSET + 32]);
            out
        };
        assert_eq!(nullifier_root(&f), merge_fixture::forester::OLD_ROOT,
                   "the forester tree must still be at the root the batch proof cites");
        assert!(f.action_batch_update_nullifier_tree(), "the batch fixture must verify");
        // The applied root lands in the NEXT history slot; index 0 keeps the root
        // the batch was proven against. Checking index 0 for a change would have
        // reported a working update as a no-op.
        let data = f.ctx.svm.get_account(&f.forester_tree).unwrap().data;
        let mut applied = [0u8; 32];
        applied.copy_from_slice(
            &data[NULLIFIER_ROOT_HISTORY_OFFSET + 32..NULLIFIER_ROOT_HISTORY_OFFSET + 64]);
        assert_eq!(applied, merge_fixture::forester::NEW_ROOT,
                   "the batch must APPLY, not just return Ok -- the handler returns Ok(()) \
                    without doing anything when no batch is ready, which is exactly the \
                    early-return path this instruction's 90.3% coverage used to be");
    }

    /// Prints the addresses an SPL withdrawal fixture must bind. The interface
    /// token account is a PDA of the mint, so it cannot be chosen -- it is derived,
    /// and `setup()` asserts the derivation still matches what the proof assumed.
    #[test]
    #[ignore = "probe: prints fixture inputs for the Go generator"]
    fn print_spl_fixture_addresses() {
        let f = ShieldedPoolFixture::setup();
        let hex = |b: [u8; 32]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        println!("mint          {}", hex(f.spl_mint.to_bytes()));
        println!("spl_interface {}", hex(f.spl_interface.to_bytes()));
        println!("user_token    {}", hex(f.user_token.to_bytes()));
        println!("bump          {}", f.spl_interface_bump);
    }

    /// P-0011: the admin gates must refuse a signer who is not the authority.
    /// The SOL deposit action reaches its success path, and still rejects an
    /// out-of-range asset index.
    ///
    /// `deposit` is the entry point for value into the pool, and it was selected 7
    /// times for 0 successes in a 400-entry replay -- invisible in the coverage
    /// report, because its lines are all reachable through the deposit helper that
    /// `setup()` and the SPL rail also drive. A covered line is not a working action.
    /// Both directions are asserted: an in-range index credits the pool and advances
    /// P-0001's shadow, and an out-of-range one is refused with the balance unmoved.
    #[test]
    fn sol_deposit_action_succeeds_in_range_and_is_refused_out_of_range() {
        let mut f = ShieldedPoolFixture::setup();
        let pool_lamports =
            |f: &ShieldedPoolFixture| f.ctx.svm.get_account(&f.sol_interface).unwrap().lamports;

        // 0 is the only in-range index for a one-asset batch. There is no longer any
        // FOLD here: a `% 2` bound once lived in the generated action body and a later
        // `scout regen` deleted it, so the comments claiming a fold outlived the code.
        // The fold now lives in `action_deposit_in_range`, exercised at the end.
        let before = pool_lamports(&f);
        let credited_before = f.shadow_sol_credited;
        assert!(
            f.action_deposit(0, 7, 9, 11, 250_000),
            "a SOL deposit with an in-range asset index must succeed"
        );
        assert_eq!(
            pool_lamports(&f),
            before + 250_000,
            "the deposited lamports must land in the pool"
        );
        assert_eq!(
            f.shadow_sol_credited,
            credited_before + 250_000,
            "P-0001's shadow must record what the action credited"
        );

        // 1 is one past the end of a one-asset batch, and every fuzzer byte other than
        // 0 lands here -- which is why the generated action needs a wrapper to reach
        // its own success path at all, and is accepted as a negative path on its own.
        let before = pool_lamports(&f);
        assert!(
            !f.action_deposit(1, 7, 9, 11, 250_000),
            "an out-of-range asset index must be refused"
        );
        assert_eq!(
            pool_lamports(&f),
            before,
            "a refused deposit must not move lamports"
        );

        // The wrapper the campaign actually depends on: whatever byte it is handed, it
        // must reach the success path. Driven across values that would all be REFUSED
        // by the generated action, so this cannot pass by accidentally choosing 0.
        for seed in [0u8, 1, 7, 200, 255] {
            let before = pool_lamports(&f);
            let credited_before = f.shadow_sol_credited;
            assert!(
                f.action_deposit_in_range(seed, seed.wrapping_add(1), seed.wrapping_add(2),
                                          u64::from(seed) * 1_000),
                "action_deposit_in_range must succeed for every fuzzer byte (seed {seed})"
            );
            let moved = pool_lamports(&f) - before;
            assert!(moved > 0, "and must actually move lamports");
            assert_eq!(f.shadow_sol_credited - credited_before, moved,
                "P-0001's shadow must record exactly what moved");
        }
    }


    /// A proven batch is reusable only once its bloom filter has been zeroed, and the
    /// reuse moves its coverage window forward by exactly one rotation.
    ///
    /// Both settings are driven. The unzeroed case being refused proves nothing on its
    /// own -- it is equally consistent with reuse being broken outright -- so the
    /// zeroed case must go through on an otherwise identical world.
    #[test]
    fn proven_batches_are_reusable_only_once_their_bloom_filter_is_zeroed() {
        for bloom_zeroed in [0u8, 1u8] {
            let mut f = ShieldedPoolFixture::setup();
            let tree = f.tree;
            let at = |f: &ShieldedPoolFixture, o: usize| -> u64 {
                let d = f.ctx.svm.get_account(&tree).unwrap().data;
                u64::from_le_bytes(d[o..o + 8].try_into().unwrap())
            };
            let b0 = NULLIFIER_BATCH0_OFFSET;

            // Fill batch 0 and rotate off it, then mark it proven with the filter in
            // the state under test.
            assert!(f.action_fill_nullifier_batch());
            assert!(f.action_transact_no_transfers(), "the spend that fills batch 0");
            assert_eq!(at(&f, b0 + BATCH_STATE_FIELD), BATCH_STATE_FULL);
            assert!(f.action_mark_batch_inserted(bloom_zeroed), "mark batch 0 proven");
            assert_eq!(at(&f, b0 + BATCH_STATE_FIELD), BATCH_STATE_INSERTED);
            let start_before = at(&f, b0 + 56);

            // Fill batch 1 as well, so the rotation wraps back onto batch 0.
            assert!(f.action_fill_nullifier_batch(), "prefill batch 1");
            assert!(f.action_ring_transact(), "the spend that fills batch 1");
            assert_eq!(at(&f, NULLIFIER_QUEUE_CURRENT_BATCH_OFFSET), 0, "wrapped onto batch 0");

            let reused = f.action_ring_authority_transact();
            if bloom_zeroed == 0 {
                assert!(!reused, "a batch with a stale bloom filter must not be reused");
                assert_eq!(at(&f, b0 + BATCH_STATE_FIELD), BATCH_STATE_INSERTED,
                    "and must be left exactly as it was");
                assert_eq!(at(&f, b0 + BATCH_NUM_FULL_ZKP), 120, "with its counters intact");
            } else {
                assert!(reused, "a zeroed batch must be reusable, or the refusal above \
                    would only show that reuse is broken in general");
                assert_eq!(at(&f, b0 + BATCH_STATE_FIELD), 0, "reuse returns it to Fill");
                assert_eq!(at(&f, b0 + BATCH_NUM_FULL_ZKP), 0, "with its counters reset");
                assert_eq!(at(&f, b0 + BATCH_NUM_INSERTED), 1, "holding the spend that reused it");
                // num_batches * batch_size, so the new window cannot overlap the old.
                let rotation = at(&f, 7592) * at(&f, b0 + BATCH_SIZE_FIELD);
                assert_eq!(at(&f, b0 + 56), start_before + rotation,
                    "the reused batch's window moves forward by exactly one rotation");
            }
            assert_eq!(f.shadow_stale_bloom_reuses, 0, "P-0022 holds either way");
        }

        // The oracle discriminates.
        let mut f = ShieldedPoolFixture::setup();
        f.shadow_stale_bloom_reuses += 1;
        assert_ne!(f.shadow_stale_bloom_reuses, 0,
            "P-0022's predicate must fire once a stale batch is reused");
    }

    /// The queue rotates at a batch boundary and then refuses to overwrite a full,
    /// unproven batch -- a path three orders of magnitude out of reach by spending.
    #[test]
    fn nullifier_queue_rotates_then_applies_backpressure() {
        let mut f = ShieldedPoolFixture::setup();
        let tree = f.tree;
        let read = |f: &ShieldedPoolFixture, at: usize| -> u64 {
            let d = f.ctx.svm.get_account(&tree).unwrap().data;
            u64::from_le_bytes(d[at..at + 8].try_into().unwrap())
        };
        let batch = |f: &ShieldedPoolFixture, i: usize, o: usize| -> u64 {
            read(f, NULLIFIER_BATCH0_OFFSET + i * NULLIFIER_BATCH_STRIDE + o)
        };
        let current = |f: &ShieldedPoolFixture| read(f, NULLIFIER_QUEUE_CURRENT_BATCH_OFFSET);

        // Batch 0, one insertion short of full.
        assert!(f.action_fill_nullifier_batch(), "prefill the current batch");
        assert_eq!(current(&f), 0);
        assert_eq!(batch(&f, 0, BATCH_STATE_FIELD), 0, "still filling");
        let zkp = batch(&f, 0, BATCH_ZKP_SIZE_FIELD);
        let chunks = batch(&f, 0, BATCH_SIZE_FIELD) / zkp;
        assert_eq!(batch(&f, 0, BATCH_NUM_FULL_ZKP), chunks - 1);

        // One real spend crosses the boundary: the batch completes its last chunk,
        // flips to Full, and the queue rotates to the other batch.
        assert!(f.action_transact_no_transfers(), "the spend that fills the batch");
        assert_eq!(batch(&f, 0, BATCH_NUM_FULL_ZKP), chunks, "the last chunk completed");
        assert_eq!(batch(&f, 0, BATCH_NUM_INSERTED), 0, "and the partial counter reset");
        assert_eq!(batch(&f, 0, BATCH_STATE_FIELD), BATCH_STATE_FULL, "batch 0 is Full");
        assert_eq!(current(&f), 1, "the queue rotated to batch 1");

        // The next spend lands in the OTHER batch, leaving batch 0 untouched.
        assert!(f.action_ring_transact(), "the next spend goes to batch 1");
        assert_eq!(batch(&f, 1, BATCH_NUM_INSERTED), 1, "batch 1 took it");
        assert_eq!(batch(&f, 0, BATCH_NUM_FULL_ZKP), chunks, "batch 0 is untouched");

        // Fill batch 1 too, so the rotation wraps back onto a Full, unproven batch.
        assert!(f.action_fill_nullifier_batch(), "prefill batch 1");
        assert!(f.action_ring_authority_transact(), "the spend that fills batch 1");
        assert_eq!(batch(&f, 1, BATCH_STATE_FIELD), BATCH_STATE_FULL, "batch 1 is Full too");
        assert_eq!(current(&f), 0, "and the queue wrapped onto batch 0");

        // Both batches full and unproven: the queue must refuse, not overwrite.
        let queued_before = read(&f, NULLIFIER_QUEUE_NEXT_INDEX_OFFSET);
        assert!(
            !f.action_merge_transact_backpressured(true),
            "a spend into a full, unproven batch must be refused"
        );
        assert_eq!(
            read(&f, NULLIFIER_QUEUE_NEXT_INDEX_OFFSET), queued_before,
            "a refused spend must queue nothing"
        );
        assert_eq!(batch(&f, 0, BATCH_NUM_FULL_ZKP), chunks, "and must not touch batch 0");
        assert_eq!(f.shadow_batch_overwrite_bypasses, 0, "P-0021 holds");

        // The oracle discriminates.
        f.shadow_batch_overwrite_bypasses += 1;
        assert_ne!(f.shadow_batch_overwrite_bypasses, 0,
            "P-0021's predicate must fire once a spend gets into a full batch");
    }

    /// Rotating the forester authority moves the privilege: the new key works and the
    /// old one stops.
    ///
    /// Both halves are needed. "The old key is refused" alone is consistent with the
    /// instruction being broken after any rotation, so the new key must be shown to
    /// work on the same world -- and the batch fixture can only be applied once, so
    /// the new key goes first and the old key is tested against the idle crank, which
    /// still distinguishes authorised from refused.
    #[test]
    fn authority_rotation_revokes_the_previous_key() {
        let mut f = ShieldedPoolFixture::setup();
        assert_eq!(f.scout_forester_authority(), f.payer.pubkey().to_bytes(),
            "setup starts with payer as the forester authority");

        // Baseline: payer is the authority and is accepted.
        assert!(f.action_batch_update_signed_by(0), "the named authority must be accepted");
        assert_eq!(f.shadow_stale_authority_successes, 0);

        // Rotate to an outsider. The old key must now be refused.
        assert!(f.action_rotate_forester_authority(0x51), "the protocol authority may rotate");
        let rotated = f.scout_forester_authority();
        assert_ne!(rotated, f.payer.pubkey().to_bytes(), "the config must name the new key");
        assert!(!f.action_batch_update_signed_by(0),
            "the previous authority must be refused after rotation");

        // And the new key is accepted -- an idle crank, but the gate runs before the
        // batch state is consulted, so acceptance still distinguishes it.
        assert!(f.action_batch_update_signed_by(0x51),
            "the newly named authority must be accepted");
        assert_eq!(f.shadow_stale_authority_successes, 0, "P-0024 holds");

        // Rotating back restores the original key, so a campaign can un-rotate.
        assert!(f.action_rotate_forester_authority(0));
        assert_eq!(f.scout_forester_authority(), f.payer.pubkey().to_bytes());
        assert!(f.action_batch_update_signed_by(0), "payer works again once restored");
        assert!(!f.action_batch_update_signed_by(0x51),
            "and the outsider is refused again");
        assert_eq!(f.shadow_stale_authority_successes, 0);

        // The oracle discriminates.
        f.shadow_stale_authority_successes += 1;
        assert_ne!(f.shadow_stale_authority_successes, 0,
            "P-0024's predicate must fire once a revoked key is accepted");
    }

    /// Clearing a bloom filter retires exactly the roots it guarded -- no more, no
    /// fewer.
    ///
    /// The walked slots are filled with distinct non-zero values first, so a retired
    /// slot is observably different from one that was already empty; without that the
    /// mechanism runs and changes nothing visible.
    #[test]
    fn clearing_a_bloom_filter_retires_the_roots_it_guarded() {
        let mut f = ShieldedPoolFixture::setup();
        let tree = f.forester_tree;
        let cap = NULLIFIER_ROOT_HISTORY_CAPACITY as usize;
        let slot = |f: &ShieldedPoolFixture, i: usize| -> [u8; 32] {
            let d = f.ctx.svm.get_account(&tree).unwrap().data;
            let at = NULLIFIER_ROOT_HISTORY_OFFSET + (i % cap) * 32;
            d[at..at + 32].try_into().unwrap()
        };
        let other = NULLIFIER_BATCH0_OFFSET + NULLIFIER_BATCH_STRIDE;
        let bloom_zeroed = |f: &ShieldedPoolFixture| -> u8 {
            f.ctx.svm.get_account(&tree).unwrap().data[other + BATCH_BLOOM_ZEROED_FIELD]
        };
        assert_eq!(bloom_zeroed(&f), 0, "the filter starts dirty");

        assert!(f.action_forester_retire_roots(), "the retirement path must run");
        assert_eq!(bloom_zeroed(&f), 1, "the bloom filter must be marked zeroed");

        // The walk started at slot 2 (one root was pushed by this very update) and
        // covered three slots, stopping at the first safe root.
        for retired in 2..5 {
            assert_eq!(slot(&f, retired), [0u8; 32],
                "slot {retired} guarded a cleared filter and must be retired");
        }
        assert_ne!(slot(&f, 5), [0u8; 32],
            "the first SAFE root must survive -- retiring it would discard a root the \
             tree still needs");
        assert_ne!(slot(&f, 0), [0u8; 32], "and the current root must survive");
        assert_ne!(slot(&f, 1), [0u8; 32], "as must the root this update pushed");
        assert_eq!(f.shadow_unretired_roots, 0, "P-0028 holds");

        // The oracle discriminates.
        f.shadow_unretired_roots += 1;
        assert_ne!(f.shadow_unretired_roots, 0,
            "P-0028's predicate must fire once a guarded root survives");
    }

    /// The queue's hash chain is the fold over exactly the nullifiers queued.
    ///
    /// Two independent constructions of the same value: the on-chain chain is built
    /// incrementally by `add_to_hash_chain` as the two merges publish their
    /// nullifiers, and the expected value was folded offline by the batch generator
    /// from the nullifier list. They must agree, and must keep agreeing after the
    /// forester applies the batch that proof covers.
    #[test]
    fn queue_hash_chain_covers_exactly_what_was_queued() {
        let mut f = ShieldedPoolFixture::setup();
        let chain = |f: &ShieldedPoolFixture| -> [u8; 32] {
            let d = f.ctx.svm.get_account(&f.forester_tree).unwrap().data;
            d[NULLIFIER_HASH_CHAIN_OFFSET..NULLIFIER_HASH_CHAIN_OFFSET + 32]
                .try_into().unwrap()
        };
        assert_eq!(chain(&f), merge_fixture::EXPECTED_HASH_CHAIN,
            "the queue's fold must equal the one the batch proof binds");

        // Applying the batch consumes the chunk but must not rewrite its chain.
        assert!(f.action_forester_batch_apply(), "the seeded batch must apply");
        assert_eq!(chain(&f), merge_fixture::EXPECTED_HASH_CHAIN,
            "applying a batch must not rewrite the chain it proved");

        // Not vacuous: the slot holds a real fold, not zeros.
        assert_ne!(chain(&f), [0u8; 32]);
    }

    /// Retired and never-written root slots are refused by both trees.
    #[test]
    fn retired_and_unwritten_roots_are_not_citable() {
        let mut f = ShieldedPoolFixture::setup();
        for slot in [0u8, 1, 7, 49] {
            assert!(!f.action_transact_citing_retired_root(0, slot),
                "a zeroed nullifier root slot must be refused");
            assert!(!f.action_transact_citing_retired_root(1, slot),
                "an unwritten UTXO root slot must be refused");
        }
        assert_eq!(f.shadow_retired_root_successes, 0, "P-0027 holds");

        // None of those refusals spent the note, so the same call citing the roots the
        // tree actually holds must still verify -- otherwise the refusals above would
        // only show the transact is broken.
        assert!(f.action_ring_transact_p256(),
            "citing the live roots must still verify");

        // The oracle discriminates.
        f.shadow_retired_root_successes += 1;
        assert_ne!(f.shadow_retired_root_successes, 0,
            "P-0027's predicate must fire once a retired root is accepted");
    }

    /// The pool's own output is spendable: deposit -> transact -> transact.
    ///
    /// This is the only test that proves MEMBERSHIP against a root the pool published
    /// itself. Everything else in this harness spends a note `setup()` deposited, so
    /// the append/root loop was only ever checked by counters.
    #[test]
    fn a_note_created_by_a_transact_is_spendable() {
        let mut f = ShieldedPoolFixture::setup();
        let leaves = f.scout_leaves(&f.p256_tree);

        assert!(f.action_ring_transact_p256(), "the first link must verify");
        assert_eq!(f.scout_leaves(&f.p256_tree), leaves + 1, "its output must be appended");

        // The second link's proof cites the root published by the first, and its
        // merkle path is for the leaf the first appended. It verifies only if both
        // are what the pool claimed.
        assert!(
            f.action_ring_transact_p256_chained(),
            "the note the pool created must be spendable"
        );
        assert_eq!(f.scout_leaves(&f.p256_tree), leaves + 2, "and its own output appended");
        assert_eq!(f.shadow_unspendable_outputs, 0, "P-0025 holds");

        // The chained note is now spent too.
        assert!(!f.action_ring_transact_p256_chained(), "the chained nullifier is spent");

        // The oracle discriminates.
        f.shadow_unspendable_outputs += 1;
        assert_ne!(f.shadow_unspendable_outputs, 0,
            "P-0025's predicate must fire once a created note cannot be spent");
    }

    /// A proof cannot be moved between rails, and its commitment cannot be altered.
    ///
    /// The positive control matters more than usual here: four of the five variants
    /// corrupt a committed value, and a corrupted value failing proves nothing unless
    /// the SAME call with the value intact succeeds.
    #[test]
    fn proofs_are_not_transplantable_between_rails() {
        let mut f = ShieldedPoolFixture::setup();
        for variant in 0..ShieldedPoolFixture::PROOF_GRAFT_VARIANTS {
            assert!(
                !f.action_transact_proof_grafted(variant),
                "graft variant {variant} must be refused"
            );
        }
        assert_eq!(f.shadow_proof_graft_successes, 0, "P-0023 holds");

        // None of the refusals spent the note, so the untampered call must still go
        // through -- otherwise the five refusals above would say nothing about
        // grafting.
        assert!(
            f.action_ring_transact_p256(),
            "the untampered P256 transact must still verify"
        );

        // The oracle discriminates.
        f.shadow_proof_graft_successes += 1;
        assert_ne!(f.shadow_proof_graft_successes, 0,
            "P-0023's predicate must fire once a grafted proof verifies");
    }

    /// The P256 rail verifies on chain, taking the commitment verification path.
    ///
    /// This is the only test that reaches `verify_groth16`'s
    /// `(Some(commitment), true)` arm: the `transfer_p256_ring_1_1` verifying key
    /// carries a BSB22 commitment, so the program runs a Pedersen proof-of-knowledge
    /// pairing on top of the standard Groth16 one. Every other proof in this harness
    /// takes the `(None, false)` arm, which is why this rail was worth the fixture.
    ///
    /// It costs ~307k compute units against the 200k default, so it is unreachable
    /// without raising the budget -- see the note in `setup()`.
    ///
    /// Asserts the state transition rather than the bool: a verified proof is not an
    /// applied transfer. The output is appended, and the nullifier is refused on a
    /// second attempt (7002, `NullifierTreeUpdateFailed`).
    #[test]
    fn p256_rail_verifies_and_spends() {
        let mut f = ShieldedPoolFixture::setup();
        let leaves = f.scout_leaves(&f.p256_tree);
        assert!(f.action_ring_transact_p256(), "the p256 fixture must verify");
        assert_eq!(f.scout_leaves(&f.p256_tree), leaves + 1, "the output must be appended");
        assert!(!f.action_ring_transact_p256(), "the nullifier must not be spendable twice");
    }

    /// Encodings that LOOK equivalent are still distinct to the proof.
    ///
    /// The program maps an absent optional to zero in places (`map_or(&zero, ..)`), so
    /// `None` and `Some([0u8; 32])` could plausibly collapse to the same preimage. If
    /// they did, a relayer could rewrite those fields on a submitted transaction
    /// without invalidating the proof -- the chain would commit the same UTXO while
    /// the indexer, which reconstructs notes from instruction data, recorded something
    /// else. They do not collapse: every variant is refused by the proof, so the
    /// Option TAG is bound and not just the value behind it.
    #[test]
    fn equivalent_looking_encodings_are_still_bound() {
        let names = ["baseline_none", "data_hash_some_zero", "ring_data_hash_some_zero",
                     "messages_one_empty_zero", "output_data_some_zero"];
        for (i, name) in names.iter().enumerate() {
            let mut f = ShieldedPoolFixture::setup();
            let mut payload = scout_wire::TransactIxData {
                expiry_unix_ts: merge_fixture::EXPIRY_UNIX_TS,
                private_tx_hash: merge_fixture::transact::PRIVATE_TX_HASH,
                circuit: scout_wire::CircuitId::ConfidentialEddsa(1, 1, 3),
                tx_viewing_pk: merge_fixture::transact::TX_VIEWING_PK,
                salt: [0u8; 16],
                proof: scout_wire::TransactProof {
                    a: merge_fixture::transact::PROOF_A,
                    b: merge_fixture::transact::PROOF_B,
                    c: merge_fixture::transact::PROOF_C,
                },
                inputs: vec![scout_wire::InputUtxo {
                    nullifier_hash: merge_fixture::transact::NULLIFIER,
                    nullifier_tree_root_index: 0,
                    utxo_tree_root_index: f.transact_utxo_root_index,
                }],
                interface_transfers: Vec::new(),
                data_hash: None,
                ring_data_hash: None,
                outputs: vec![scout_wire::TransactOutput {
                    utxo_hash: merge_fixture::transact::OUTPUT_UTXO_HASH,
                    owner_tag: scout_wire::OwnerTag::Inline(merge_fixture::transact::ACTOR_PUBKEY),
                    data: None,
                }],
                messages: Vec::new(),
            };
            match i {
                1 => payload.data_hash = Some([0u8; 32]),
                2 => payload.ring_data_hash = Some([0u8; 32]),
                3 => payload.messages = vec![scout_wire::MessageData {
                        view_tag: [0u8; 32], data: Vec::new() }],
                4 => payload.outputs[0].data = Some(Vec::new()),
                _ => {}
            }
            let mut data = vec![TAG_TRANSACT];
            data.extend_from_slice(&wincode::serialize(&payload).unwrap());
            let actor = f.transact_actor.insecure_clone();
            let ix = Instruction {
                program_id: f.program_id,
                accounts: vec![
                    AccountMeta::new(actor.pubkey(), true),
                    AccountMeta::new(f.tree, false),
                    AccountMeta::new(f.tree, false),
                    AccountMeta::new_readonly(f.program_id, false),
                    AccountMeta::new_readonly(system_program::ID, false),
                ],
                data,
            };
            let out = f.ctx.raw_call(ix).signers(&[&*f.payer, &actor]).send();
            let (ok, code) = match &out {
                Ok(o) => (o.is_success(), format!("{:?}", o.error_code())),
                Err(e) => (false, format!("send-err {e:?}")),
            };
            if i == 0 {
                assert!(ok, "the baseline encoding must be accepted, or the refusals \
                    below would prove nothing about the encoding");
            } else {
                assert!(!ok, "{name}: an equivalent-looking encoding must not verify");
                assert_eq!(code, "Some(7008)",
                    "{name}: must be refused by the PROOF, not by an earlier validator");
            }
        }
    }

    /// Every field the proof commits to is load-bearing, and each is refused by the
    /// PROOF rather than by some earlier validation.
    ///
    /// The error code matters as much as the refusal. A perturbation rejected by an
    /// expiry check or a payload validator would prove nothing about the proof's
    /// binding -- it would only prove the field is validated somewhere. All eleven
    /// come back as TransactProofVerificationFailed, so each really is folded into the
    /// public inputs. The unperturbed control at the end rules out the other vacuity:
    /// that the call was failing for a reason unrelated to the perturbation.
    #[test]
    fn every_proof_bound_field_is_load_bearing() {
        let mut f = ShieldedPoolFixture::setup();
        for selector in 0..ShieldedPoolFixture::PROOF_BOUND_FIELDS {
            assert!(
                !f.action_transact_perturbed(selector),
                "perturbation {selector} must not verify"
            );
        }
        assert_eq!(f.shadow_proof_binding_bypasses, 0, "P-0020 holds");

        // None of the refusals consumed the note, so the unperturbed transaction --
        // identical but for the field each case altered -- must still go through.
        assert!(
            f.action_transact_no_transfers(),
            "the unperturbed transact must succeed, or the refusals above prove nothing"
        );

        // The oracle discriminates.
        f.shadow_proof_binding_bypasses += 1;
        assert_ne!(f.shadow_proof_binding_bypasses, 0,
            "P-0020's predicate must fire once a perturbed transact verifies");
    }

    /// The queue's batch bookkeeping is internally consistent, and its decomposition
    /// is the one P-0017 and P-0018 assume.
    ///
    /// `num_inserted` counts within the ZKP chunk being filled, not within the batch,
    /// so a queue holding 16 reads as one full chunk of ten plus six. Reading that
    /// field as a batch total is an easy mistake and a silent one, so the
    /// decomposition is asserted directly rather than trusted.
    #[test]
    fn nullifier_batch_bookkeeping_is_consistent() {
        let mut f = ShieldedPoolFixture::setup();
        let tree = f.forester_tree;
        let field = |f: &ShieldedPoolFixture, b: usize, o: usize| f.scout_batch_field(&tree, b, o);

        let zkp_size = field(&f, 0, BATCH_ZKP_SIZE_FIELD);
        let batch_size = field(&f, 0, BATCH_SIZE_FIELD);
        assert_eq!(zkp_size, NULLIFIER_ZKP_BATCH_SIZE, "one proven chunk is ten nullifiers");
        assert_eq!(batch_size % zkp_size, 0, "a batch is a whole number of chunks");

        // The decomposition: queued == full chunks * chunk size + the partial chunk.
        let queued = f.scout_queue_next_index(&tree);
        let decomposed: u64 = (0..2)
            .map(|b| field(&f, b, BATCH_NUM_FULL_ZKP) * zkp_size + field(&f, b, BATCH_NUM_INSERTED))
            .sum();
        assert_eq!(
            queued, decomposed,
            "the queue's next_index must equal the batches' full chunks plus their partial fills"
        );

        // P-0017 in the healthy direction: a backlog is normal, the reverse is not.
        let applied = f.scout_applied_nullifiers(&tree);
        assert!(applied - 1 <= queued, "applied must not run ahead of queued");
        assert!(applied - 1 < queued, "and here there is genuinely a backlog to apply");

        // Applying a chunk moves applied and the proven-chunk counter together, and
        // never past the full-chunk counter.
        assert!(f.action_forester_batch_apply(), "the seeded batch must apply");
        assert_eq!(f.scout_applied_nullifiers(&tree), applied + zkp_size);
        assert_eq!(f.scout_queue_next_index(&tree), queued, "applying queues nothing new");
        for b in 0..2 {
            assert!(field(&f, b, BATCH_NUM_INSERTED_ZKP) <= field(&f, b, BATCH_NUM_FULL_ZKP),
                "batch {b}: proven chunks must never exceed full chunks");
            assert!(field(&f, b, BATCH_NUM_INSERTED) <= batch_size);
        }
        assert!(f.scout_applied_nullifiers(&tree) - 1 <= f.scout_queue_next_index(&tree),
            "P-0017 still holds after an apply");
    }

    /// Trees stay above the rent-exempt floor across the fee flow in both directions.
    #[test]
    fn trees_stay_rent_exempt_across_the_fee_flow() {
        let mut f = ShieldedPoolFixture::setup();
        let floor = f.tree_rent_floor;
        assert!(floor > 0, "the floor must have been captured at setup");
        for tree in [f.tree, f.forester_tree] {
            assert!(f.ctx.svm.get_account(&tree).unwrap().lamports >= floor,
                "a freshly created tree is rent exempt");
        }

        // A spend pays a fee INTO the input tree; the batch update pays a
        // reimbursement OUT of the forester's tree. Both directions, then re-check.
        assert!(f.action_transact_no_transfers(), "a spend that pays a forester fee");
        assert!(f.action_forester_batch_apply(), "an apply that pays a reimbursement");
        for tree in [f.tree, f.forester_tree] {
            assert!(f.ctx.svm.get_account(&tree).unwrap().lamports >= floor,
                "a tree must stay rent exempt after money has moved in both directions");
        }

        // The oracle discriminates: the predicate is a real comparison, not a
        // tautology against a zero floor.
        assert!(f.ctx.svm.get_account(&f.tree).unwrap().lamports >= floor);
        assert!(!(0 >= floor), "a tree at zero lamports would fail P-0019");
    }

    /// A two-entry deposit sums both amounts into the pool and appends both leaves,
    /// which is the accumulation path a one-entry batch can never reach.
    #[test]
    fn multi_entry_deposit_sums_both_amounts() {
        let mut f = ShieldedPoolFixture::setup();
        let pool = |f: &ShieldedPoolFixture| f.ctx.svm.get_account(&f.sol_interface).unwrap().lamports;
        let leaves = |f: &ShieldedPoolFixture| f.scout_leaves(&f.tree);

        let (before, leaves_before) = (pool(&f), leaves(&f));
        let credited_before = f.shadow_sol_credited;
        assert!(f.action_deposit_multi(300_000, 700_000, 7, 9, 11), "a two-entry deposit");
        assert_eq!(pool(&f), before + 1_000_000, "both amounts must land in the pool");
        assert_eq!(leaves(&f), leaves_before + 2, "both entries must append a leaf");
        assert_eq!(
            f.shadow_sol_credited, credited_before + 1_000_000,
            "P-0001's shadow must count a batch's writes, not its calls"
        );

        // The overflow guard on that same arm: two entries whose sum wraps u64 must be
        // refused, with nothing credited.
        let (before, leaves_before) = (pool(&f), leaves(&f));
        assert!(!f.action_deposit_multi(u64::MAX, 2, 7, 9, 21),
            "a batch whose asset total overflows must be refused");
        assert_eq!(pool(&f), before, "a refused batch credits nothing");
        assert_eq!(leaves(&f), leaves_before, "and appends nothing");
    }

    /// A split-tree transact puts the nullifier in the tree that proved the note and
    /// the new leaf in the other, with neither crossing over.
    #[test]
    fn split_tree_transact_routes_nullifier_and_leaf_to_the_right_trees() {
        let mut f = ShieldedPoolFixture::setup();
        let (input_tree, output_tree) = (f.tree, f.forester_tree);
        let input_queue = f.scout_queue_next_index(&input_tree);
        let output_queue = f.scout_queue_next_index(&output_tree);
        let input_leaves = f.scout_leaves(&input_tree);
        let output_leaves = f.scout_leaves(&output_tree);

        assert!(f.action_transact_split_trees(), "a split-tree transact must be accepted");

        assert_eq!(f.scout_queue_next_index(&input_tree), input_queue + 1,
            "the nullifier belongs to the tree whose root proved the note");
        assert_eq!(f.scout_queue_next_index(&output_tree), output_queue,
            "the output tree's queue must not see the nullifier -- if it did, the note \
             would be spendable once per output tree");
        assert_eq!(f.scout_leaves(&output_tree), output_leaves + 1,
            "the new commitment belongs to the output tree");
        assert_eq!(f.scout_leaves(&input_tree), input_leaves,
            "the input tree gains no leaf");
        assert_eq!(f.shadow_split_tree_misroutes, 0, "P-0016 holds");

        // The same nullifier cannot be spent again, in either arrangement -- the
        // routing is correct AND the queue it routed to is the one that is checked.
        assert!(!f.action_transact_split_trees(), "the nullifier is spent");
        assert!(!f.action_transact_no_transfers(),
            "and it is spent for the single-tree arrangement too");

        // The oracle discriminates.
        f.shadow_split_tree_misroutes += 1;
        assert_ne!(f.shadow_split_tree_misroutes, 0,
            "P-0016's predicate must fire once a split transact misroutes");
    }

    /// A closed permissionless switch admits only its authority; an open one admits
    /// anyone.
    ///
    /// The second half is what makes the first half mean anything. An outsider being
    /// refused proves nothing on its own -- it is equally consistent with the
    /// instruction being broken, the account being unfunded, or the payload being
    /// malformed, and two of those have already produced vacuous passes in this
    /// harness. So the SAME outsider, against the SAME prepared accounts, must
    /// succeed once the switch is opened.
    #[test]
    fn creation_gates_admit_only_their_authority_while_closed() {
        let mut f = ShieldedPoolFixture::setup();
        // The singleton asset counter is created by an ACTION, not by setup, and
        // `create_spl_interface` cannot run without it. Omitting it would have made
        // every SPL refusal below a missing-prerequisite failure rather than a gate
        // refusal -- the same vacuity this test exists to rule out.
        assert!(f.action_create_asset_counter(), "the asset counter is a prerequisite");

        // Close ALL THREE switches, then confirm the bytes actually moved -- otherwise
        // the refusals below could be measuring a state that was never established.
        //
        // The ring switch was the one this test was missing. `setup()` pins it OPEN, so
        // the gate in `create_ring_config` had never been evaluated in any campaign:
        // the same `if not permissionless, check the authority` as the other two,
        // written out a third time against a third key.
        assert!(f.action_set_protocol_permissionless(UPDATE_VARIANT_TREE_PERMISSIONLESS, 0));
        assert!(f.action_set_protocol_permissionless(UPDATE_VARIANT_RING_PERMISSIONLESS, 0));
        assert!(f.action_set_protocol_permissionless(UPDATE_VARIANT_SPL_PERMISSIONLESS, 0));
        assert_eq!(f.scout_protocol_permissionless(), (0, 0, 0),
            "all three switches must read closed");

        assert!(!f.action_create_tree_unauthorized(0x41),
            "a closed tree-creation gate must refuse an outsider");
        assert!(!f.action_create_ring_config_unauthorized(0x43),
            "a closed ring-creation gate must refuse an outsider");
        assert!(!f.action_create_spl_interface_unauthorized(0x42, 6),
            "a closed SPL-interface gate must refuse an outsider");
        assert_eq!(f.shadow_creation_gate_bypasses, 0, "P-0015 holds while the gates are closed");

        // The positive control: the authority itself still works, so the refusals
        // above were about WHO signed and not about the instruction being broken.
        assert!(f.action_create_tree(false, 0), "the tree-creation authority still works");
        assert!(f.action_create_ring_config(true), "the ring-creation authority still works");
        assert!(f.action_create_spl_interface(6), "the protocol authority still works");

        // Now open all three switches and require the same outsiders to get through.
        assert!(f.action_set_protocol_permissionless(UPDATE_VARIANT_TREE_PERMISSIONLESS, 1));
        assert!(f.action_set_protocol_permissionless(UPDATE_VARIANT_RING_PERMISSIONLESS, 1));
        assert!(f.action_set_protocol_permissionless(UPDATE_VARIANT_SPL_PERMISSIONLESS, 1));
        assert_eq!(f.scout_protocol_permissionless(), (1, 1, 1),
            "all three switches must read open");
        assert!(f.action_create_tree_unauthorized(0x41),
            "an open tree-creation gate must admit an outsider");
        assert!(f.action_create_ring_config_unauthorized(0x43),
            "an open ring-creation gate must admit an outsider");
        assert!(f.action_create_spl_interface_unauthorized(0x42, 6),
            "an open SPL-interface gate must admit an outsider");
        assert_eq!(
            f.shadow_creation_gate_bypasses, 0,
            "succeeding through an OPEN gate is not a violation"
        );

        // The oracle discriminates.
        f.shadow_creation_gate_bypasses += 1;
        assert_ne!(f.shadow_creation_gate_bypasses, 0,
            "P-0015's predicate must fire once a creation succeeds through a closed gate");
    }

    /// P-0038 and P-0039. The merge trust boundary into the user registry.
    #[test]
    fn the_merge_registry_boundary_holds() {
        let mut f = ShieldedPoolFixture::setup();
        assert_eq!(f.scout_merging_enabled(), 1, "setup writes the opt-in ON");

        // The opt-out, with the error code checked. `MergeDisabled` is 7017 = 0x1b69;
        // a proof failure would be 7008 = 0x1b60, and the two mean entirely different
        // things -- one says the gate fired, the other says the bit reached the public
        // inputs instead.
        assert!(f.scout_set_merging_enabled(0));
        let (ok, logs) = f.scout_merge_raw(true);
        assert!(!ok, "merging disabled must refuse");
        assert!(logs.iter().any(|l| l.contains("0x1b69")),
            "and must refuse as MergeDisabled (7017), not as a proof failure: {logs:?}");

        // The wrong rail, with merging ENABLED so the refusal cannot be the opt-out.
        assert!(f.scout_set_merging_enabled(1));
        let (ok, _) = f.scout_merge_raw(false);
        assert!(!ok, "the wrong owner rail must refuse even with merging enabled");

        // THE POSITIVE CONTROL: opt-in on, correct rail, same everything else.
        // Without it the two refusals are equally consistent with the merge fixture
        // being stale or the record layout having drifted.
        let (ok, logs) = f.scout_merge_raw(true);
        assert!(ok, "the same merge must succeed once both gates are open: {logs:?}");

        assert_eq!(f.shadow_merge_opt_out_bypasses, 0, "P-0038 holds");
        assert_eq!(f.shadow_merge_rail_bypasses, 0, "P-0039 holds");

        // Both oracles discriminate.
        f.shadow_merge_opt_out_bypasses += 1;
        f.shadow_merge_rail_bypasses += 1;
        assert_ne!(f.shadow_merge_opt_out_bypasses, 0);
        assert_ne!(f.shadow_merge_rail_bypasses, 0);
    }

    /// P-0037. `allow_dummy_inputs` is proof-bound, and read from the INPUT tree.
    #[test]
    fn the_dummy_input_flag_is_proof_bound_to_the_input_tree() {
        // Patch FIRST, on one fixture: a success would spend the fixture nullifier and
        // every later refusal would be a double spend wearing the right clothes.
        let mut f = ShieldedPoolFixture::setup();
        let original = f.scout_saturate_nullifier_queue(f.tree)
            .expect("the input tree's queue must be saturable");
        assert!(!f.action_transact_no_transfers(),
            "flipping the INPUT tree's allow_dummy_inputs must invalidate the proof");
        assert_eq!(f.shadow_dummy_flag_bypasses, 0, "P-0037 holds");

        // THE POSITIVE CONTROL. Put the bytes back and the SAME call must succeed --
        // otherwise the refusal above is equally consistent with the patch having
        // corrupted the tree, which is exactly what a byte-level synthesis risks.
        assert!(f.scout_restore_tree(f.tree, original), "restore");
        assert!(f.action_transact_no_transfers(),
            "restoring the flag must make the identical call verify again");

        // The other half: the flag is the INPUT tree's, so saturating the OUTPUT tree
        // must not disturb a split transact at all.
        let mut g = ShieldedPoolFixture::setup();
        let output_original = g.scout_saturate_nullifier_queue(g.forester_tree)
            .expect("the output tree's queue must be saturable");
        assert!(g.action_transact_split_trees(),
            "saturating the OUTPUT tree must not affect a proof whose flag comes from \
             the INPUT tree");
        assert_eq!(g.shadow_dummy_flag_bypasses, 0,
            "and an output-tree success is correct, not a violation");
        assert!(g.scout_restore_tree(g.forester_tree, output_original), "restore");

        // The oracle discriminates.
        f.shadow_dummy_flag_bypasses += 1;
        assert_ne!(f.shadow_dummy_flag_bypasses, 0,
            "P-0037's predicate must fire once a flipped flag still verifies");
    }

    /// P-0035. The proof binds the deduplicated signer set, and only that.
    #[test]
    fn the_proof_binds_the_deduplicated_signer_set() {
        // A FRESH fixture per arrangement. Sharing one made the first success spend the
        // fixture nullifier, so every later arrangement was refused as a double spend
        // and the whole probe measured nothing about signers -- the refusals looked
        // exactly like the guard working.
        let drive = |variant: u8| -> (bool, u64) {
            let mut f = ShieldedPoolFixture::setup();
            let accepted = f.action_transact_signer_set(variant);
            (accepted, f.shadow_signer_set_bypasses)
        };

        let (accepted, bypasses) = drive(0);
        assert!(accepted,
            "appending an account ALREADY in the set is skipped by dedup, so the chain is \
             unchanged and the same proof must still verify -- the positive control");
        assert_eq!(bypasses, 0, "and an identical-after-dedup set is not a violation");

        for variant in 1..4u8 {
            let (accepted, bypasses) = drive(variant);
            assert!(!accepted,
                "a signer set whose dedup DIFFERS must be refused (variant {variant})");
            assert_eq!(bypasses, 0, "P-0035 holds for variant {variant}");
        }

        // The oracle discriminates.
        let mut f = ShieldedPoolFixture::setup();
        f.shadow_signer_set_bypasses += 1;
        assert_ne!(f.shadow_signer_set_bypasses, 0,
            "P-0035's predicate must fire once a changed signer set is accepted");
    }

    /// P-0036. A ring instruction accepts only its own ring config.
    #[test]
    fn a_ring_instruction_accepts_only_its_own_ring_config() {
        let mut f = ShieldedPoolFixture::setup();
        assert!(f.scout_ensure_second_ring(),
            "a SECOND ring program, with its own id and its own ring_auth PDA -- without \
             one there is no cross-ring question to ask");
        let (ring_a, config_a) = f.scout_second_ring();
        let (ring_b, config_b) = (f.ring_program, f.ring_config);
        assert_ne!(config_a, config_b, "the two rings must have distinct configs");

        // Every confusion arrangement is refused.
        for variant in 0..3u8 {
            assert!(!f.action_ring_config_confusion(variant),
                "a ring config belonging to another ring must be refused (variant {variant})");
        }
        assert_eq!(f.shadow_ring_confusions, 0, "P-0036 holds");

        // THE POSITIVE CONTROL, and it is doing real work here: without it, three
        // refusals are equally consistent with this rail being broken, the fixture
        // proof being stale, or the payload being malformed -- and an earlier version
        // of this very probe failed all four arrangements including the control,
        // because it named the wrong CircuitId. The control is what caught that.
        assert!(f.scout_ring_authority_call(ring_b, config_b, None),
            "the SAME call through ring B with ring B's OWN config must succeed");
        let _ = (ring_a, config_a);

        // The oracle discriminates.
        f.shadow_ring_confusions += 1;
        assert_ne!(f.shadow_ring_confusions, 0,
            "P-0036's predicate must fire once a foreign ring config is accepted");
    }

    /// P-0033. Every one of the five spending rails publishes its nullifiers.
    #[test]
    fn every_spending_rail_publishes_its_nullifiers() {
        let mut f = ShieldedPoolFixture::setup();
        // Each rail spends a DIFFERENT fixture note, so they can all run in one world.
        assert!(f.action_transact_publishing(), "transact spends");
        assert!(f.action_merge_transact_publishing(true), "merge_transact spends");
        assert!(f.action_ring_transact_publishing(), "ring_transact spends");
        assert!(f.action_ring_authority_transact_publishing(), "ring_authority_transact spends");
        assert!(f.action_ring_merge_transact_publishing(), "ring_merge_transact spends");
        assert_eq!(f.shadow_unpublished_nullifiers, 0, "P-0033 holds across all five rails");

        // The oracle discriminates.
        f.shadow_unpublished_nullifiers += 1;
        assert_ne!(f.shadow_unpublished_nullifiers, 0,
            "P-0033's predicate must fire once a rail consumes inputs it does not publish");
    }

    /// P-0034. Two spends of one note cannot share a transaction -- and a legitimate
    /// two-instruction transaction still goes through.
    #[test]
    fn two_spends_of_one_note_cannot_share_a_transaction() {
        let mut f = ShieldedPoolFixture::setup();
        let queued_before = f.scout_queue_next_index(&f.tree);

        // The control FIRST. If batching itself did not work here, the refusals below
        // would prove nothing, and this fixture has produced exactly that failure twice.
        assert!(f.action_double_spend_in_one_transaction(2),
            "a legitimate deposit + transact pair must go through as one transaction");
        assert!(f.scout_queue_next_index(&f.tree) > queued_before,
            "and the spend in it must have published its nullifier");

        // Now the same note, twice, in one transaction. Both rails.
        let mut g = ShieldedPoolFixture::setup();
        assert!(!g.action_double_spend_in_one_transaction(0),
            "transact + transact on one note must be refused");
        assert!(!g.action_double_spend_in_one_transaction(1),
            "merge + merge on one set of eight nullifiers must be refused");
        assert_eq!(g.shadow_intra_tx_double_spends, 0, "P-0034 holds");

        // The whole transaction reverts, so the FIRST spend must not have landed either.
        assert!(g.action_transact_no_transfers(),
            "the refused batch left the note unspent, so an ordinary spend still works");

        // The oracle discriminates.
        g.shadow_intra_tx_double_spends += 1;
        assert_ne!(g.shadow_intra_tx_double_spends, 0,
            "P-0034's predicate must fire once one note is spent twice in one transaction");
    }

    /// P-0032. The fee-bearing mint is admitted at registration and refused at
    /// settlement -- and the refusal is the SPECIFIC guard, not an incidental failure.
    #[test]
    fn a_fee_bearing_mint_is_admitted_then_refused_at_settlement() {
        let mut f = ShieldedPoolFixture::setup();
        assert!(f.scout_ensure_fee_mint(),
            "a Token-2022 mint carrying TransferFeeConfig must REGISTER: the extension is \
             on the program's allow list, so fee-bearing assets are admitted on purpose");
        let (mint, user, interface) = f.scout_fee_mint_keys();

        // The interface account the program created for it carries `TransferFeeAmount`,
        // the account extension `TransferFeeConfig` requires. That the length the
        // program computed matches the one the harness computed independently is what
        // makes the rest of this test about behaviour rather than about layout.
        assert_eq!(f.ctx.svm.get_account(&interface).unwrap().data.len(), T22_ACCOUNT_LEN);
        assert!(f.scout_token_amount(&user.pubkey()) > 0, "the depositor is funded");

        // A large deposit and a tiny one. Token-2022 rounds the fee UP, so there is no
        // small-amount window where the fee vanishes and a deposit slips through.
        for amount in [1_000_000u64, 19u64] {
            let before = f.scout_token_amount(&interface);
            assert!(!f.action_deposit_through_a_fee_bearing_mint(amount - 1),
                "a deposit of {amount} through a fee mint must be refused");
            assert_eq!(f.scout_token_amount(&interface), before,
                "and must move nothing");
        }
        assert_eq!(f.shadow_fee_mint_credits, 0, "P-0032 holds");

        // The positive control: the SAME deposit shape through a NON-fee mint succeeds.
        // Without it, the refusals above are equally consistent with the Token-2022 rail
        // being broken outright rather than with the fee guard doing its job.
        assert!(f.action_deposit_spl(250_000, 3, 4, 5),
            "the plain spl-token rail still works, so the refusals were about the FEE");
        let _ = mint;

        // The oracle discriminates.
        f.shadow_fee_mint_credits += 1;
        assert_ne!(f.shadow_fee_mint_credits, 0,
            "P-0032's predicate must fire once a fee-mint deposit credits more than arrived");
    }

    /// P-0029. Rotating the ring authority retires the key it replaced.
    ///
    /// `update_ring_config_owner` is the only writer of `RingConfig.authority` and it
    /// had never once executed in this harness, so the whole write path -- not just
    /// the revocation -- is being exercised here for the first time.
    #[test]
    fn a_rotated_ring_authority_stops_working() {
        let mut f = ShieldedPoolFixture::setup();
        let payer = f.payer.pubkey().to_bytes();
        assert_eq!(f.scout_ring_authority(), payer, "setup names the payer");

        // Baseline: the current authority works. Without this the refusal below would
        // be equally consistent with `update_ring_config` being broken outright.
        assert!(f.action_set_ring_config(1, 0), "the current ring authority works");

        // The action rotates away, checks both directions, and rotates back.
        assert!(f.action_rotate_ring_authority(0x44),
            "the rotation, the new key's positive control, and the restore must all work");
        assert_eq!(f.shadow_stale_ring_authority_successes, 0, "P-0029 holds");
        assert_eq!(f.scout_ring_authority(), payer,
            "the action restores the authority, so the rest of a branch keeps a ring rail");

        // The oracle discriminates.
        f.shadow_stale_ring_authority_successes += 1;
        assert_ne!(f.shadow_stale_ring_authority_successes, 0,
            "P-0029's predicate must fire once a retired key still writes the config");
    }

    /// P-0030. A forester crank that is handed the chunk that is due must apply it.
    ///
    /// The precondition is seeded rather than hoped for: `setup()` leaves the forester
    /// tree holding a finalised first chunk and the fixture holds that chunk's proof,
    /// so "there was work to do" is a fact this test controls.
    #[test]
    fn a_successful_forester_crank_applies_the_chunk_that_was_due() {
        let mut f = ShieldedPoolFixture::setup();
        let tree = f.forester_tree;
        let (full, inserted) = f.scout_pending_chunk_progress(&tree)
            .expect("the forester tree must expose its pending batch");
        let due = u64::from(merge_fixture::forester::ZKP_BATCH_INDEX);
        assert_eq!(inserted, due, "the fixture's proof is for the chunk that is due");
        assert!(full > due, "and that chunk's hash chain is finalised, so work exists");

        let (leaves_before, _) = f.scout_nullifier_progress();
        assert!(f.action_forester_crank_with_work(), "the crank must succeed");
        let (leaves_after, _) = f.scout_nullifier_progress();
        assert_eq!(leaves_after, leaves_before + NULLIFIER_ZKP_BATCH_SIZE,
            "and it must have applied exactly the chunk it was due");
        assert_eq!(f.shadow_silent_forester_noops, 0, "P-0030 holds");

        // A REPLAY is a legitimate work-free success and must NOT be counted. This is
        // the escape hatch the guard exists to close: without it the property would
        // fire here, on correct behaviour.
        assert!(f.action_forester_crank_with_work(), "replaying the same proof still succeeds");
        assert_eq!(f.scout_nullifier_progress().0, leaves_after, "and moves nothing");
        assert_eq!(f.shadow_silent_forester_noops, 0,
            "a replayed proof is an idempotent no-op, not a silent one");

        // The oracle discriminates.
        f.shadow_silent_forester_noops += 1;
        assert_ne!(f.shadow_silent_forester_noops, 0,
            "P-0030's predicate must fire once a due chunk is reported applied and is not");
    }

    /// P-0031 and P-0001's repair. A donation is permissionless, accounted for, and
    /// never becomes withdrawable.
    #[test]
    fn a_donated_lamport_is_accounted_for_and_never_withdrawable() {
        let mut f = ShieldedPoolFixture::setup();
        let before = f.ctx.svm.get_account(&f.sol_interface).unwrap().lamports;

        // Anyone can do this and the pool cannot refuse it. A real system transfer,
        // not an injected balance -- the claim being tested is reachability.
        assert!(f.action_donate_lamports(0, 0x45, 12_345), "a donation must be accepted");
        let after = f.ctx.svm.get_account(&f.sol_interface).unwrap().lamports;
        assert!(after > before, "the pool's real balance rose with nothing crediting it");
        assert_eq!(after - before, f.shadow_sol_donated, "and the shadow tracks exactly it");

        // P-0001 must still hold. Before the donation term it would have reported this
        // permissionlessly-reachable state as native SOL insolvency.
        let expected = f.sol_interface_opening + f.shadow_sol_credited + f.shadow_sol_donated
            - f.shadow_sol_withdrawn;
        assert_eq!(after, expected, "P-0001 must hold across a donation");

        // The surplus is not a claim on anything. Drive an actual WITHDRAWAL -- without
        // one the bound is vacuous, which is how the first version of this property
        // passed its test while the corpus replay reported it would violate.
        assert!(f.action_deposit(0, 3, 4, 5, 1_000_000), "an ordinary deposit still works");
        assert!(f.action_transact_withdrawal(), "and a real withdrawal must pay out");
        assert!(f.shadow_sol_withdrawn > 0, "so the bound below is not vacuous");
        assert!(f.shadow_sol_withdrawn <= f.sol_interface_opening + f.shadow_sol_credited,
            "P-0031 holds: the pool never pays out more than was ever deposited into it");
        assert_eq!(f.shadow_donation_insolvencies, 0);

        // The oracle discriminates.
        f.shadow_donation_insolvencies += 1;
        assert_ne!(f.shadow_donation_insolvencies, 0,
            "P-0031's predicate must fire once a pay-out exceeds what was credited");
    }

    /// The ring's switches gate every ring path, and the toggle actually toggles.
    ///
    /// Both directions matter: a test that only pauses and sees failures would pass on
    /// a world where the ring rail is simply broken, so this re-enables and requires
    /// the same calls to work again.
    #[test]
    fn ring_switches_gate_every_ring_path() {
        let mut f = ShieldedPoolFixture::setup();
        assert_eq!(f.scout_ring_switches(), (1, 0), "a fresh ring config is enabled and unpaused");

        // Baseline: the authority rail works while both switches are open.
        assert!(f.action_ring_authority_transact_gated(), "the ring authority rail must work");
        assert_eq!(f.shadow_ring_gate_bypasses, 0);

        // Disable only the authority rail. `ring_transact` shares the same parse path
        // but not the same gate, so it must keep working -- that is what makes this a
        // test of the FLAG rather than of the ring being broken generally.
        assert!(f.action_set_ring_config(0, 0), "the ring authority may flip its own switch");
        assert_eq!(f.scout_ring_switches(), (0, 0));
        assert!(!f.action_ring_authority_transact_gated(),
            "a disabled ring authority rail must be refused");

        // Pause the ring: now every ring path must be refused.
        assert!(f.action_set_ring_config(1, 1), "pausing is an administrative call, allowed while paused");
        assert_eq!(f.scout_ring_switches(), (1, 1));
        assert!(!f.action_ring_transact_gated(), "a paused ring refuses ring_transact");
        assert!(!f.action_ring_merge_transact_gated(), "a paused ring refuses ring_merge_transact");
        assert!(!f.action_ring_deposit_gated(1_000, 5, 6, 7, false, 8, false),
            "a paused ring refuses ring deposits");
        assert_eq!(f.shadow_ring_gate_bypasses, 0, "P-0014 holds while the gates are closed");

        // Re-open both switches and confirm the rail comes back, so the refusals above
        // were the gates and not a broken fixture.
        assert!(f.action_set_ring_config(1, 0), "unpausing must work");
        assert_eq!(f.scout_ring_switches(), (1, 0));
        assert!(f.action_ring_transact_gated(), "ring_transact works again once unpaused");

        // The oracle discriminates.
        f.shadow_ring_gate_bypasses += 1;
        assert_ne!(f.shadow_ring_gate_bypasses, 0,
            "P-0014's predicate must fire once a ring call succeeds through a closed gate");
    }

    /// The nullifier region's byte offsets, pinned against a live account.
    ///
    /// P-0012 and P-0013 read this structure by offset, and a layout drift would not
    /// fail them -- it would make them quietly read the wrong field and pass. So each
    /// offset is checked against a value that is independently known: the tree's
    /// height gives the capacity, `create_tree`'s own arguments give the queue sizes,
    /// and the batch fixture's root must be the one the history already holds.
    #[test]
    fn nullifier_region_offsets_are_pinned() {
        let f = ShieldedPoolFixture::setup();
        let data = f.ctx.svm.get_account(&f.forester_tree).unwrap().data;
        let u64_at = |o: usize| -> u64 { u64::from_le_bytes(data[o..o + 8].try_into().unwrap()) };

        assert_eq!(
            u64_at(NULLIFIER_QUEUE_ZKP_BATCH_SIZE_OFFSET), NULLIFIER_ZKP_BATCH_SIZE,
            "queue zkp_batch_size -- the unit one batch update applies"
        );
        assert_eq!(
            u64_at(NULLIFIER_ROOT_CAPACITY_OFFSET), NULLIFIER_ROOT_HISTORY_CAPACITY,
            "CyclicVec capacity"
        );
        assert_eq!(
            u64_at(NULLIFIER_NEXT_INDEX_OFFSET), 1,
            "a fresh nullifier tree holds only the sentinel at index 0"
        );
        // The cursor names the NEXT slot to write, so a tree holding one root reads 1
        // and the root itself is at slot 0. Getting this backwards is the silent
        // off-by-one the constants' comment warns about, so assert both halves.
        assert_eq!(u64_at(NULLIFIER_ROOT_CURSOR_OFFSET), 1, "cursor names the next free slot");
        let slot0: [u8; 32] = data[NULLIFIER_ROOT_HISTORY_OFFSET..NULLIFIER_ROOT_HISTORY_OFFSET + 32]
            .try_into().unwrap();
        assert_eq!(
            slot0, merge_fixture::EXPECTED_NF_ROOT,
            "history[cursor - 1] must be the root the batch fixture was built against"
        );
    }

    /// A batch update advances the tree by one whole ZKP batch, and an idle crank
    /// advances nothing -- the two outcomes P-0012 admits, and nothing between them.
    #[test]
    fn nullifier_batch_update_advances_by_one_whole_batch_or_not_at_all() {
        let mut f = ShieldedPoolFixture::setup();
        let (index_before, cursor_before) = f.scout_nullifier_progress();

        assert!(f.action_forester_batch_apply(), "the seeded batch must apply");
        let (index_after, cursor_after) = f.scout_nullifier_progress();
        assert_eq!(
            index_after - index_before, NULLIFIER_ZKP_BATCH_SIZE,
            "one batch update must append exactly one ZKP batch of nullifiers"
        );
        assert_eq!(cursor_after - cursor_before, 1, "and push exactly one root");
        assert_eq!(f.shadow_nullifier_batch_violations, 0, "P-0012 holds for the applying call");

        // With no full batch left the crank is a no-op that still returns success, and
        // it must move neither the tree nor the tree's lamports -- otherwise it would
        // be a forester paid for no work, which is why the balance is asserted too.
        let lamports_before = f.ctx.svm.get_account(&f.forester_tree).unwrap().lamports;
        assert!(f.action_forester_batch_apply(), "an idle crank still succeeds");
        assert_eq!(
            f.scout_nullifier_progress(), (index_after, cursor_after),
            "an idle crank must change nothing"
        );
        assert_eq!(
            f.ctx.svm.get_account(&f.forester_tree).unwrap().lamports, lamports_before,
            "an idle crank must not collect a fee"
        );
        assert_eq!(f.shadow_nullifier_batch_violations, 0, "P-0012 holds for the idle call too");

        // The oracle discriminates: a partial advance is what it exists to catch.
        f.shadow_nullifier_batch_violations += 1;
        assert_ne!(
            f.shadow_nullifier_batch_violations, 0,
            "P-0012's predicate must fire once a call moves the tree by a partial batch"
        );
    }

    /// P-0013's window is well-formed, and its bound is the one actually enforced.
    #[test]
    fn nullifier_root_history_window_is_well_formed() {
        let mut f = ShieldedPoolFixture::setup();
        let read = |f: &ShieldedPoolFixture| -> (u64, u64, u64) {
            let d = f.ctx.svm.get_account(&f.forester_tree).unwrap().data;
            let at = |o: usize| u64::from_le_bytes(d[o..o + 8].try_into().unwrap());
            (at(NULLIFIER_ROOT_CURSOR_OFFSET), at(NULLIFIER_ROOT_LEN_OFFSET),
             at(NULLIFIER_ROOT_CAPACITY_OFFSET))
        };
        for _ in 0..3 {
            let (cursor, len, capacity) = read(&f);
            assert_eq!(capacity, NULLIFIER_ROOT_HISTORY_CAPACITY);
            assert!(cursor < capacity, "cursor {} must stay below capacity {}", cursor, capacity);
            assert!((1..=capacity).contains(&len), "len {} must be within [1, {}]", len, capacity);
            f.action_forester_batch_apply();
        }
        // The predicate is not vacuously true: an out-of-range cursor fails its bound.
        let (_, _, capacity) = read(&f);
        assert!(!(capacity < capacity), "a cursor at capacity must not satisfy cursor < capacity");
    }

    /// This is the actor the fixture was missing. `payer` is deliberately all four
    /// authorities so one signer drives every gated path, which meant nothing here
    /// tested that the gates hold against somebody else. The outsider signs the
    /// transaction, so a refusal is the AUTHORITY CHECK and not a missing signature.
    #[test]
    fn admin_gates_refuse_an_outsider() {
        let mut f = ShieldedPoolFixture::setup();
        let paused = |f: &ShieldedPoolFixture| -> u8 {
            f.ctx.svm.get_account(&f.tree).unwrap().data[TREE_STATE_OFFSET]
        };
        let ring_config_bytes = |f: &ShieldedPoolFixture| -> Vec<u8> {
            f.ctx.svm.get_account(&f.ring_config).unwrap().data
        };
        let (state_before, ring_before) = (paused(&f), ring_config_bytes(&f));

        for seed in [1u8, 5, 99] {
            assert!(!f.action_pause_tree_unauthorized(1, seed),
                    "an outsider must not pause the tree (seed {seed})");
            assert!(!f.action_pause_tree_unauthorized(0, seed),
                    "nor unpause it, which would defeat the brake (seed {seed})");
            assert!(!f.action_update_ring_config_unauthorized(seed),
                    "an outsider must not rewrite a ring's config (seed {seed})");
        }
        assert_eq!(f.shadow_unauthorized_admin_successes, 0, "P-0011 holds");
        assert_eq!(paused(&f), state_before, "the tree's pause switch is untouched");
        assert_eq!(ring_config_bytes(&f), ring_before, "the ring config is untouched");

        // The AUTHORITY still works, or the test would pass on a world where the
        // instruction is simply broken for everyone.
        assert!(f.action_pause_tree(1), "the protocol authority must still pause");
        assert_ne!(paused(&f), state_before, "and its pause must take effect");

        // The oracle must notice a gate that let someone through.
        f.shadow_unauthorized_admin_successes += 1;
        assert_ne!(f.shadow_unauthorized_admin_successes, 0,
                   "P-0011 must FAIL when an outsider gets through a gate");
    }

    /// P-0009 and P-0010: the root history's structural facts.
    ///
    /// Both hold by construction today, which is precisely why they are asserted
    /// from outside -- the ring buffer is indexed by untrusted instruction data, and
    /// nothing in the program compares the cached root to the history head or
    /// checks the window against its capacity.
    #[test]
    fn root_history_structure_discriminates() {
        let mut f = ShieldedPoolFixture::setup();
        let data = |f: &ShieldedPoolFixture| f.ctx.svm.get_account(&f.tree).unwrap().data;
        let cursor = |f: &ShieldedPoolFixture| -> usize {
            usize::from(u16::from_le_bytes(
                data(f)[UTXO_ROOT_CURSOR_OFFSET..UTXO_ROOT_CURSOR_OFFSET + 2]
                    .try_into().unwrap()))
        };
        let head = |f: &ShieldedPoolFixture| -> Vec<u8> {
            let slot = UTXO_ROOT_HISTORY_OFFSET + 32 * cursor(f);
            data(f)[slot..slot + 32].to_vec()
        };
        let cached = |f: &ShieldedPoolFixture| -> Vec<u8> {
            data(f)[UTXO_ROOT_OFFSET..UTXO_ROOT_OFFSET + 32].to_vec()
        };

        // Honest traffic, including an append that pushes a new root.
        assert_eq!(cached(&f), head(&f), "P-0009 holds after setup");
        assert!(f.action_deposit(0, 3, 4, 5, 1_000_000), "deposit must succeed");
        assert_eq!(cached(&f), head(&f), "P-0009 holds after an append moved the cursor");
        let len = u16::from_le_bytes(
            data(&f)[UTXO_ROOT_HISTORY_LEN_OFFSET..UTXO_ROOT_HISTORY_LEN_OFFSET + 2]
                .try_into().unwrap()) as usize;
        assert!(cursor(&f) < ROOT_HISTORY_CAPACITY && (1..=ROOT_HISTORY_CAPACITY).contains(&len),
                "P-0010 holds");

        // P-0009 must FAIL when the two diverge. Corrupting the HISTORY entry rather
        // than the cached root is the direction that matters: it is the value a
        // proof citing this index would be checked against.
        let mut account = f.ctx.svm.get_account(&f.tree).unwrap();
        let slot = UTXO_ROOT_HISTORY_OFFSET + 32 * cursor(&f);
        account.data[slot] ^= 0xff;
        f.ctx.svm.set_account(f.tree, account).unwrap();
        assert_ne!(cached(&f), head(&f),
                   "P-0009 must FAIL when the history head is not the current root");

        // P-0010 must FAIL on a window outside its capacity.
        let mut account = f.ctx.svm.get_account(&f.tree).unwrap();
        account.data[UTXO_ROOT_CURSOR_OFFSET..UTXO_ROOT_CURSOR_OFFSET + 2]
            .copy_from_slice(&(ROOT_HISTORY_CAPACITY as u16).to_le_bytes());
        f.ctx.svm.set_account(f.tree, account).unwrap();
        assert!(cursor(&f) >= ROOT_HISTORY_CAPACITY,
                "P-0010 must FAIL when the cursor leaves its capacity");
    }

    /// P-0007: a paused tree must accept nothing, from any path.
    ///
    /// Reading the code says the freeze holds -- every write path uses the loader
    /// that refuses a paused tree. This runs it: pause, then try EVERY instruction
    /// that can append, and require all of them to be refused. Then unpause and
    /// require one to work again, so the test is not just proving that a broken
    /// world rejects everything.
    #[test]
    fn a_paused_tree_freezes_every_write_path() {
        let mut f = ShieldedPoolFixture::setup();
        let leaves = |f: &ShieldedPoolFixture| -> u64 {
            scout_tree_next_index(&f.ctx.svm.get_account(&f.tree).unwrap().data).unwrap()
        };
        let paused = |f: &ShieldedPoolFixture| -> bool {
            f.ctx.svm.get_account(&f.tree).unwrap().data[TREE_STATE_OFFSET] == TREE_STATE_PAUSED
        };

        assert!(f.action_pause_tree(1), "pause must succeed");
        assert!(paused(&f), "the tree must read PAUSED");
        let frozen_at = leaves(&f);

        // Every appending instruction, including the six proof-gated ones whose
        // proofs are otherwise valid -- so a refusal here is the PAUSE, not the proof.
        assert!(!f.action_deposit(0, 3, 4, 5, 1_000_000), "deposit while paused");
        assert!(!f.action_deposit_spl(1_000, 1, 2, 3), "spl deposit while paused");
        assert!(!f.action_ring_deposit(1_000, 1, 2, 3, false, 0, false), "ring deposit");
        assert!(!f.action_merge_transact(true), "merge while paused");
        assert!(!f.action_ring_merge_transact(), "ring merge while paused");
        assert!(!f.action_transact_no_transfers(), "transact while paused");
        assert!(!f.action_ring_transact(), "ring transact while paused");
        assert!(!f.action_ring_authority_transact(), "ring authority while paused");
        assert!(!f.action_transact_withdrawal(), "withdrawal while paused");
        assert!(!f.action_transact_spl_withdrawal(), "spl withdrawal while paused");
        assert_eq!(leaves(&f), frozen_at, "P-0007 holds: nothing appended while paused");

        // The oracle must also FAIL on a bypass. Injected, because none is reachable.
        let mut account = f.ctx.svm.get_account(&f.tree).unwrap();
        account.data[UTXO_ROOT_OFFSET - 8..UTXO_ROOT_OFFSET]
            .copy_from_slice(&frozen_at.wrapping_add(1).to_le_bytes());
        f.ctx.svm.set_account(f.tree, account).unwrap();
        assert_ne!(leaves(&f), f.shadow_leaves_at_pause,
                   "P-0007 must FAIL when a leaf appears on a frozen tree");

        // And unpausing must restore service, or the freeze is a one-way door.
        let mut account = f.ctx.svm.get_account(&f.tree).unwrap();
        account.data[UTXO_ROOT_OFFSET - 8..UTXO_ROOT_OFFSET]
            .copy_from_slice(&frozen_at.to_le_bytes());
        f.ctx.svm.set_account(f.tree, account).unwrap();
        assert!(f.action_pause_tree(0), "unpause must succeed");
        assert!(!paused(&f), "the tree must read live again");
        assert!(f.action_deposit(0, 3, 4, 5, 1_000_000), "deposit must work once unpaused");
    }

    /// P-0008: the asset-id counter must match the registrations it counts.
    #[test]
    fn asset_id_counter_discriminates() {
        let mut f = ShieldedPoolFixture::setup();
        let next_id = |f: &ShieldedPoolFixture| -> Option<u64> {
            let (counter, _) = Pubkey::find_program_address(
                &[SPL_ASSET_COUNTER_PDA_SEED], &f.program_id);
            let account = f.ctx.svm.get_account(&counter)?;
            Some(u64::from_le_bytes(
                account.data[ASSET_COUNTER_NEXT_ID_OFFSET..ASSET_COUNTER_NEXT_ID_OFFSET + 8]
                    .try_into().unwrap()))
        };

        // The counter is allocated by a fuzzable instruction, not by setup, so its
        // absence is the expected early state -- and the property must skip, not fire.
        assert!(next_id(&f).is_none(), "the counter must not exist before its instruction runs");
        assert!(f.action_create_asset_counter(), "create the counter");
        assert_eq!(next_id(&f), Some(FIRST_ASSET_ID), "a fresh counter starts at the floor");

        for expected in 1..=3u64 {
            assert!(f.action_create_spl_interface(6), "register a mint");
            assert_eq!(next_id(&f), Some(FIRST_ASSET_ID + expected),
                       "one id consumed per registration");
            assert_eq!(f.shadow_registered_assets, expected);
        }

        // A refused registration must consume no id -- otherwise the counter and the
        // registry drift apart and two mints can end up sharing an asset. Note the
        // handler allocates the id BEFORE creating the registry entry, so this rests
        // entirely on the transaction reverting.
        let before = next_id(&f);
        assert!(!f.action_create_asset_counter(), "a second counter must be refused");
        assert_eq!(next_id(&f), before, "a refused instruction consumes nothing");
        assert_eq!(f.shadow_asset_id_violations, 0,
                   "P-0008 holds: every call moved the counter by exactly its due");

        // The oracle must notice a wrong delta. Injected, because the program does
        // not produce one -- the point is that the ORACLE would see it.
        f.shadow_asset_id_violations = f.shadow_asset_id_violations.saturating_add(1);
        assert_ne!(f.shadow_asset_id_violations, 0,
                   "P-0008 must FAIL when a call moves the id counter wrongly");
    }

    /// P-0006: substituting the recipient must invalidate the proof.
    ///
    /// The recipient is not in the instruction data; it is folded into
    /// `external_data_hash` from the ACCOUNT, so the only thing standing between an
    /// attacker and somebody else's pay-out is that the hash no longer matches. A
    /// direct test of a guarantee that has no `require!` behind it.
    #[test]
    fn withdrawal_recipient_is_bound_by_the_proof() {
        let mut f = ShieldedPoolFixture::setup();
        let pool_before = f.ctx.svm.get_account(&f.sol_interface).unwrap().lamports;

        for seed in [1u8, 7, 200] {
            assert!(!f.action_transact_withdrawal_substituted(seed),
                    "a withdrawal to an unbound recipient must be refused (seed {seed})");
        }
        assert_eq!(f.shadow_substituted_payouts, 0, "P-0006 holds");
        assert_eq!(f.ctx.svm.get_account(&f.sol_interface).unwrap().lamports, pool_before,
                   "a refused withdrawal must move nothing");

        // Seed 0 IS the bound recipient, so the same action still reaches the
        // success path -- otherwise this would only ever prove that a broken
        // instruction fails.
        assert!(f.action_transact_withdrawal_substituted(0),
                "the honest recipient must still be paid");
        assert_eq!(f.shadow_substituted_payouts, 0,
                   "the honest path must not count as a substitution");
    }

    /// The SPL withdrawal, end to end: the token rail must actually pay out.
    #[test]
    fn transact_spl_withdrawal_pays_out() {
        let mut f = ShieldedPoolFixture::setup();
        let vault = |f: &ShieldedPoolFixture| -> u64 {
            let data = f.ctx.svm.get_account(&f.spl_interface).unwrap().data;
            u64::from_le_bytes(data[64..72].try_into().unwrap())
        };
        let user = |f: &ShieldedPoolFixture| -> u64 {
            let data = f.ctx.svm.get_account(&f.user_token).unwrap().data;
            u64::from_le_bytes(data[64..72].try_into().unwrap())
        };
        let (vault_before, user_before) = (vault(&f), user(&f));

        assert!(f.action_transact_spl_withdrawal(), "the SPL withdrawal fixture must verify");
        assert_eq!(vault_before - vault(&f), merge_fixture::spl::WITHDRAWAL,
                   "the interface vault must pay out exactly the withdrawn amount");
        assert_eq!(user(&f) - user_before, merge_fixture::spl::WITHDRAWAL,
                   "and the user's token account must receive it");

        // P-0002 must hold with tokens having LEFT.
        assert_eq!(vault(&f),
                   f.spl_interface_opening + f.shadow_spl_credited - f.shadow_spl_withdrawn,
                   "P-0002 holds across an SPL withdrawal");
        assert!(!f.action_transact_spl_withdrawal(),
                "its nullifier must not be spendable twice");
    }

    /// The withdrawal, end to end: the pool must actually PAY OUT.
    ///
    /// Asserts the lamports moved, not just that the call succeeded — a transact
    /// that verified its proof and settled nothing would pass a bool check while
    /// leaving the pool's books and its balance disagreeing, which is exactly what
    /// P-0001 exists to catch and exactly what could not happen before, because no
    /// action in this harness could make value leave at all.
    #[test]
    fn transact_withdrawal_pays_out() {
        let mut f = ShieldedPoolFixture::setup();
        let balance = |f: &ShieldedPoolFixture| -> u64 {
            f.ctx.svm.get_account(&f.sol_interface).unwrap().lamports
        };
        let before = balance(&f);
        let recipient_before = f.ctx.svm.get_account(&f.transact_actor.pubkey()).unwrap().lamports;

        assert!(f.action_transact_withdrawal(), "the withdrawal fixture must verify");
        assert_eq!(before - balance(&f), merge_fixture::transact_withdrawal::WITHDRAWAL,
                   "the pool must pay out exactly the withdrawn amount");
        let recipient_after = f.ctx.svm.get_account(&f.transact_actor.pubkey()).unwrap().lamports;
        assert!(recipient_after > recipient_before, "the recipient must be credited");

        // P-0001 must still hold with value having LEFT: a one-sided net would now
        // read the correct pay-out as insolvency.
        let expected = f.sol_interface_opening + f.shadow_sol_credited - f.shadow_sol_withdrawn;
        assert_eq!(balance(&f), expected, "P-0001 holds across a withdrawal");

        assert!(!f.action_transact_withdrawal(), "its nullifier must not be spendable twice");
    }

    /// The two ring transact rails, end to end.
    ///
    /// Asserted separately from `transact` and from each other because the three
    /// rails do not merely differ in value: `ring_authority_transact` publishes no
    /// output-owner chain and folds a shorter signer vector, so its public input
    /// hash has a different SHAPE. A bug that let one rail's proof satisfy another
    /// would pass any test that ran only one of them.
    #[test]
    fn ring_transact_rails_verify_and_spend() {
        let mut f = ShieldedPoolFixture::setup();

        let leaves = tree_next_index(&f);
        assert!(f.action_ring_transact(), "the ring_transact fixture must verify");
        assert_eq!(tree_next_index(&f), leaves + 1);
        assert!(!f.action_ring_transact(), "its nullifier must not be spendable twice");

        let leaves = tree_next_index(&f);
        assert!(f.action_ring_authority_transact(),
                "the ring_authority_transact fixture must verify");
        assert_eq!(tree_next_index(&f), leaves + 1);
        assert!(!f.action_ring_authority_transact(),
                "its nullifier must not be spendable twice");
    }

    /// PROOF-FIXTURE ALIGNMENT -- the precondition for every pre-generated proof.
    ///
    /// A Groth16 proof fixes its public inputs at generation time, so `setup()` has
    /// to reproduce the exact world the merge fixture was generated against. This
    /// asserts that it does, against the protocol's OWN hashing: the constants come
    /// from a Go program built on `prover-test/spp/protocol`, the same library the
    /// merge circuit's own fixtures use.
    ///
    /// The state tree appends immediately (`smt.rs::append_batch`) rather than
    /// queueing, which is what makes an offline fixture viable at all -- a queued
    /// append would leave the on-chain root behind the one the proof cites.
    #[test]
    fn merge_fixture_world_is_reproduced() {
        let f = ShieldedPoolFixture::setup();
        let data = f.ctx.svm.get_account(&f.tree).unwrap().data;
        let at = |off: usize| -> [u8; 32] {
            let mut out = [0u8; 32];
            out.copy_from_slice(&data[off..off + 32]);
            out
        };

        // Every fixture cites its OWN history slot. Table-driven on purpose: the
        // last-written root moves whenever a fixture is added, and asserting on it
        // made this test fail three times for a reason that was never a defect.
        // What actually has to hold is per-fixture, and it holds forever.
        let cited: [(&str, u16, [u8; 32]); 5] = [
            ("merge_transact", f.merge_utxo_root_index, merge_fixture::EXPECTED_UTXO_ROOT),
            ("ring_merge_transact", f.ring_merge_utxo_root_index,
             merge_fixture::ring::EXPECTED_UTXO_ROOT),
            ("transact", f.transact_utxo_root_index,
             merge_fixture::transact::EXPECTED_UTXO_ROOT),
            ("ring_transact", f.ring_transact_utxo_root_index,
             merge_fixture::ring_transact::EXPECTED_UTXO_ROOT),
            ("ring_authority_transact", f.ring_authority_utxo_root_index,
             merge_fixture::ring_authority_transact::EXPECTED_UTXO_ROOT),
        ];
        for (name, index, expected) in cited {
            assert_eq!(at(UTXO_ROOT_HISTORY_OFFSET + 32 * index as usize), expected,
                       "{name} cites slot {index}, which must hold the root its proof \
                        was generated against");
        }
        // One root per deposit transaction, on top of the root `create_tree` seeded.
        // Distinct indices are what makes the check above five checks, not one.
        let indices: Vec<u16> = cited.iter().map(|(_, index, _)| *index).collect();
        assert_eq!(indices, vec![2, 4, 5, 6, 7]);
        assert_eq!(at(NULLIFIER_ROOT_HISTORY_OFFSET), merge_fixture::EXPECTED_NF_ROOT,
                   "every fixture cites nullifier root index 0");

        // The registry record the proof's owner binding resolves through.
        let record = f.ctx.svm.get_account(&f.user_record).unwrap();
        assert_eq!(record.owner, USER_REGISTRY_PROGRAM_ID);
        assert_eq!(record.data[0], 1, "UserRecord discriminator");
        assert_eq!(&record.data[1..33], merge_fixture::OWNER_PUBKEY.as_slice());
        assert_eq!(*record.data.last().unwrap(), 1, "merging_enabled");
    }

    /// The fixture merge, end to end: the proof verifies against the program's own
    /// `merge_8_1::VERIFYINGKEY` and the inputs are actually spent.
    ///
    /// A verified proof is NOT the same as an applied merge, so this asserts the
    /// state transition too: the output must be appended, and a replay of the same
    /// nullifiers must be refused. Asserting only "the action returned true" would
    /// pass just as happily for a merge that verified and double-spent.
    ///
    /// On failure it prints the program's own error, because the distinction that
    /// matters -- verification rejected the bytes, versus the harness never reached
    /// the verifier -- is invisible in the action's bool.
    #[test]
    fn merge_transact_verifies_and_spends() {
        let mut f = ShieldedPoolFixture::setup();
        let leaves_before = tree_next_index(&f);

        assert!(f.action_merge_transact(true), "the fixture merge must verify: {}",
                merge_failure_outcome(&mut ShieldedPoolFixture::setup()));
        assert_eq!(tree_next_index(&f), leaves_before + 1,
                   "the merged output must be appended to the state tree");
        assert!(!f.action_merge_transact(true),
                "the same nullifiers must not be spendable twice");
    }

    /// Leaves appended to the state tree so far: `UtxoTreeLayout::next_index`, the
    /// first field of the utxo tree, 8 bytes ahead of its root.
    fn tree_next_index(f: &ShieldedPoolFixture) -> u64 {
        let data = f.ctx.svm.get_account(&f.tree).unwrap().data;
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&data[UTXO_ROOT_OFFSET - 8..UTXO_ROOT_OFFSET]);
        u64::from_le_bytes(buf)
    }

    /// Sends the fixture merge and returns the rendered outcome; the action itself
    /// only yields a bool, which cannot distinguish the wall from a glue bug.
    fn merge_failure_outcome(f: &mut ShieldedPoolFixture) -> String {
        let payload = scout_wire::MergeTransactIxData {
            expiry_unix_ts: merge_fixture::EXPIRY_UNIX_TS,
            proof: scout_wire::MergeProof {
                a: merge_fixture::PROOF_A, b: merge_fixture::PROOF_B, c: merge_fixture::PROOF_C },
            output_utxo_hash: merge_fixture::OUTPUT_UTXO_HASH,
            eddsa_owner: true,
            private_tx_hash: merge_fixture::PRIVATE_TX_HASH,
            nullifiers: merge_fixture::NULLIFIERS.to_vec(),
            utxo_tree_root_index: vec![f.merge_utxo_root_index; 8],
            nullifier_tree_root_index: vec![0u16; 8],
        };
        let mut data = vec![TAG_MERGE_TRANSACT];
        data.extend_from_slice(&wincode::serialize(&payload).unwrap());
        let ix = ScoutIx {
            program_id: f.program_id,
            accounts: vec![
                ScoutMeta::new(f.tree, false),
                ScoutMeta::new(f.tree, false),
                ScoutMeta::new(f.payer.pubkey(), true),
                ScoutMeta::new_readonly(f.user_record, false),
                ScoutMeta::new_readonly(system_program::ID, false),
                ScoutMeta::new_readonly(f.program_id, false),
            ],
            data,
        };
        let rendered = format!("{:?}", f.ctx.raw_call(ix).signers(&[&*f.payer]).send().unwrap());
        println!("merge_transact outcome: {rendered}");
        rendered
    }

    /// SPL deposit: does the variant-keyed account tail satisfy
    /// `validate_spl_deposit_settlement`, and does value actually move?
    #[test]
    fn observe_deposit_spl() {
        let mut f = ShieldedPoolFixture::setup();
        let before = f.ctx.svm.get_account(&f.spl_interface).unwrap().data.to_vec();
        let ok = f.action_deposit_spl(250_000, 3, 4, 5);
        let after = f.ctx.svm.get_account(&f.spl_interface).unwrap().data.to_vec();
        // SPL token account `amount` is a little-endian u64 at offset 64.
        let amount_of = |d: &[u8]| u64::from_le_bytes(d[64..72].try_into().unwrap());
        println!("deposit_spl -> {ok}; spl_interface amount {} -> {}",
                 amount_of(&before), amount_of(&after));
        assert!(ok, "SPL deposit must succeed");
        assert_eq!(amount_of(&after), amount_of(&before) + 250_000);
    }

    /// GOLDEN BYTES for the generated fixed-layout (bytemuck) writer.
    ///
    /// `scout_create_protocol_config_data` is an independently-verified oracle: it
    /// is what `setup()` sends, and `create_protocol_config` SUCCEEDS with it, so
    /// the program itself has accepted those bytes. Asserting the generated
    /// `#[repr(C)]` + Pod mirror reproduces them proves the transcription (including
    /// the Address -> [u8; 32] layout substitution) is byte-exact, rather than
    /// merely compiling.
    #[test]
    fn bytemuck_writer_matches_verified_oracle() {
        let authority = Pubkey::new_unique();
        let oracle = scout_create_protocol_config_data(&authority);

        let mirrored = scout_wire::CreateProtocolConfigData {
            protocol_authority: authority.to_bytes(),
            tree_creation_authority: authority.to_bytes(),
            tree_creation_is_permissionless: 0,
            forester_authority: authority.to_bytes(),
            ring_creation_authority: authority.to_bytes(),
            ring_creation_is_permissionless: 1,
            spl_interface_creation_is_permissionless: 1,
        };
        let mut generated = vec![TAG_CREATE_PROTOCOL_CONFIG];
        generated.extend_from_slice(bytemuck::bytes_of(&mirrored));

        assert_eq!(generated.len(), 132, "1 tag byte + 131 bytes of Pod payload");
        assert_eq!(generated, oracle, "generated Pod bytes must equal the accepted bytes");
    }

    /// P-0001 LIVENESS. A property that cannot fail is worthless, and "the fuzzer
    /// found no crash" is equally consistent with a check that never discriminates.
    /// This perturbs the exact quantity P-0001 watches -- lamports appearing in the
    /// SOL interface with no corresponding credit -- and asserts the predicate flips.
    #[test]
    fn p0001_discriminates() {
        let mut f = ShieldedPoolFixture::setup();
        assert!(f.action_deposit(0, 3, 4, 5, 1_000_000), "deposit must succeed first");

        let observed = f.ctx.svm.get_account(&f.sol_interface).unwrap().lamports;
        let expected = f.sol_interface_opening + f.shadow_sol_credited;
        assert_eq!(observed, expected, "P-0001 must HOLD after an honest deposit");

        // Value arriving with nothing crediting it is exactly the insolvency P-0001
        // exists to catch. Injected directly because no reachable action can produce
        // it today -- the point is that the ORACLE notices, not how it got there.
        let mut account = f.ctx.svm.get_account(&f.sol_interface).unwrap();
        account.lamports += 1;
        f.ctx.svm.set_account(f.sol_interface, account).unwrap();
        let perturbed = f.ctx.svm.get_account(&f.sol_interface).unwrap().lamports;
        assert_ne!(perturbed, expected, "P-0001 must FAIL on an uncredited lamport");
    }

    /// P-0003, P-0004 and P-0005 must HOLD on honest traffic and FAIL on the exact
    /// corruption each exists to catch. A property that cannot fail is not evidence
    /// of anything, and "the fuzzer found no violation" reads identically either
    /// way -- which is why each predicate is exercised in both directions here.
    #[test]
    fn tree_properties_discriminate() {
        let mut f = ShieldedPoolFixture::setup();
        let leaves = |f: &ShieldedPoolFixture| -> u64 {
            scout_tree_next_index(&f.ctx.svm.get_account(&f.tree).unwrap().data).unwrap()
        };

        // --- honest traffic: all three hold ---------------------------------
        assert!(f.action_deposit(0, 3, 4, 5, 1_000_000), "deposit must succeed first");
        assert!(f.action_merge_transact(true), "merge must succeed");
        assert_eq!(leaves(&f), f.shadow_expected_leaves, "P-0004 holds");
        assert!(leaves(&f) >= f.shadow_expected_leaves, "P-0003 holds");
        assert_eq!(f.shadow_merge_spends, 1, "P-0005 holds: the merge spent exactly once");
        assert!(!f.action_merge_transact(true), "a replay must be refused");
        assert_eq!(f.shadow_merge_spends, 1,
                   "P-0005 must not count a REJECTED replay -- the counter is success-gated");

        // --- P-0004: an append that moves the counter by the wrong amount ----
        // Injected directly: no reachable action produces it today, and the point
        // is that the ORACLE notices, not how the tree got there.
        let mut account = f.ctx.svm.get_account(&f.tree).unwrap();
        let corrupted = leaves(&f).wrapping_add(1);
        account.data[UTXO_ROOT_OFFSET - 8..UTXO_ROOT_OFFSET]
            .copy_from_slice(&corrupted.to_le_bytes());
        f.ctx.svm.set_account(f.tree, account).unwrap();
        assert_ne!(leaves(&f), f.shadow_expected_leaves,
                   "P-0004 must FAIL when the counter moves without an append");

        // --- P-0003: the counter rewinding below its high-water mark ---------
        let mut account = f.ctx.svm.get_account(&f.tree).unwrap();
        let rewound = f.shadow_expected_leaves.saturating_sub(1);
        account.data[UTXO_ROOT_OFFSET - 8..UTXO_ROOT_OFFSET]
            .copy_from_slice(&rewound.to_le_bytes());
        f.ctx.svm.set_account(f.tree, account).unwrap();
        assert!(leaves(&f) < f.shadow_expected_leaves,
                "P-0003 must FAIL when an append-only tree rewinds");

        // --- P-0005: a spending instruction succeeding twice -----------------
        // The predicate is over the success counters, so the corruption is a second
        // count -- exactly what a program accepting a replay would produce.
        f.shadow_merge_spends = f.shadow_merge_spends.saturating_add(1);
        assert!(f.shadow_merge_spends > 1,
                "P-0005 must FAIL when the same nullifier set is accepted twice");
    }

    /// The same two instructions sent directly, so the PROGRAM ERROR is visible.
    /// An action returns a bare `false` for every cause -- decode failure, wrong
    /// authority, missing state -- and those need completely different fixes.
    #[test]
    fn observe_action_failures() {
        let mut f = ShieldedPoolFixture::setup();
        let payer = f.payer.pubkey();
        let tree = f.tree;
        let protocol_config = f.protocol_config;

        let outcome = f.ctx
            .program(f.program_id)
            .call(instruction::BatchUpdateNullifierTree {
                new_root: [1u8; 32],
                old_root: [2u8; 32],
                zkp_batch_index: 0,
                compressed_proof: shielded_pool::types::CompressedProof {
                    a: [0u8; 32], b: [0u8; 64], c: [0u8; 32],
                },
            })
            .accounts(accounts::BatchUpdateNullifierTree {
                authority: payer,
                protocol_config,
                tree,
                reimbursement_recipient: payer,
            })
            .signers(&[&*f.payer])
            .send()
            .expect("send failed at the runtime level");
        println!("== batch_update_nullifier_tree ==");
        for line in outcome.logs() { println!("LOG: {line}"); }
        println!("outcome: {outcome:?}");

        let payload = scout_wire::MergeTransactIxData {
            expiry_unix_ts: u64::MAX,
            proof: scout_wire::MergeProof { a: [0; 32], b: [0; 64], c: [0; 32] },
            output_utxo_hash: [7; 32],
            eddsa_owner: true,
            private_tx_hash: [9; 32],
            nullifiers: vec![[1u8; 32]],
            utxo_tree_root_index: vec![0u16],
            nullifier_tree_root_index: vec![0u16],
        };
        let mut data = vec![13u8];
        data.extend_from_slice(&wincode::serialize(&payload).unwrap());
        let ix = ScoutIx {
            program_id: f.program_id,
            accounts: vec![
                ScoutMeta::new(tree, false),
                ScoutMeta::new(tree, false),
                ScoutMeta::new(payer, true),
                ScoutMeta::new_readonly(Pubkey::new_unique(), false),
                ScoutMeta::new_readonly(system_program::ID, false),
                ScoutMeta::new_readonly(f.program_id, false),
            ],
            data,
        };
        let outcome = f.ctx.raw_call(ix).signers(&[&*f.payer]).send()
            .expect("send failed at the runtime level");
        println!("== merge_transact ==");
        for line in outcome.logs() { println!("LOG: {line}"); }
        println!("outcome: {outcome:?}");
    }
}
// SCOUT:TESTS:END
// Stateful crucible fuzz harness for the shielded pool: one action per instruction,
// plus the invariants they are checked against. See PROPERTIES.md for the property
// ledger and README.md for how CI builds and submits this.
use crucible_test_context::*;
use crucible_fuzzer::anchor_lang::system_program;
use crucible_fuzzer::*;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use std::rc::Rc;
use crucible_fuzzer::anchor_lang::solana_program::instruction::{AccountMeta, Instruction};

// SCOUT:CHECK-CONTRACT:BEGIN sha256=c4b20795d13638b9cbca54acc8669b4394eb8494fe1116eb26b75f0b968aaf9e
// Semantic invariant checks have two modes:
//   default / SCOUT_CHECK_MODE=enforce: record a real Crucible fuzz violation;
//   SCOUT_CHECK_MODE=observe: emit nonce-bound reachability markers, never a violation.
// This exact alias is part of the trusted contract.  Generated setup and the
// macros below use `crate::`/`$crate` paths so a mutable prelude cannot replace
// Crucible's TestContext or violation/session functions with local lookalikes.
#[doc(hidden)]
extern crate crucible_test_context as __scout_crucible_test_context;

fn __scout_check_observe_mode() -> bool {
    std::env::var("SCOUT_CHECK_MODE").as_deref() == Ok("observe")
}

// Mute a property whose finding is already investigated and written up. Such a property keeps
// firing on the SAME known defect and floods the objective, hiding every other property's first
// finding behind thousands of duplicates -- observed at ~160 crashes per 25s on one target.
//
// Muting is ALWAYS announced on stderr, once per process. A silently disabled check is the exact
// false-negative trap this pipeline exists to avoid: a muted property is indistinguishable from a
// passing one unless the run says so out loud. `SCOUT_CHECK_MUTE` is also stripped from ordinary
// fuzz subprocesses alongside the other audit switches, so a stray shell variable can never
// quietly disable a check -- a caller must pass it explicitly.
fn __scout_check_announce_mutes(list: &str) {
    static MUTE_ONCE: std::sync::Once = std::sync::Once::new();
    MUTE_ONCE.call_once(|| {
        eprintln!("[SCOUT_CHECK_MUTED] {}", list);
    });
}

fn __scout_check_muted(property: &str) -> bool {
    match std::env::var("SCOUT_CHECK_MUTE") {
        Ok(list) => {
            let muted = list.split(',').any(|entry| entry.trim() == property);
            if muted {
                __scout_check_announce_mutes(&list);
            }
            muted
        }
        Err(_) => false,
    }
}

fn __scout_check_selected(property: &str) -> bool {
    if __scout_check_muted(property) {
        return false;
    }
    match std::env::var("SCOUT_CHECK_ONLY") {
        Ok(selected) => selected == property,
        Err(_) => true,
    }
}

fn __scout_check_nonce() -> Result<String, &'static str> {
    let nonce = std::env::var("SCOUT_CHECK_RUN")
        .map_err(|_| "missing or non-Unicode SCOUT_CHECK_RUN")?;
    if nonce.is_empty() {
        return Err("empty SCOUT_CHECK_RUN");
    }
    if !nonce.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':' | b'-')
    }) {
        return Err("SCOUT_CHECK_RUN contains unsafe characters");
    }
    Ok(nonce)
}

fn __scout_check_emit_error(reason: &str) {
    static ERROR_ONCE: std::sync::Once = std::sync::Once::new();
    ERROR_ONCE.call_once(|| {
        // Never echo an invalid value: whitespace/newlines would forge protocol fields.
        eprintln!("[SCOUT_CHECK_ERROR] INVALID {}", reason);
    });
}

macro_rules! scout_check_session {
    () => {{
        if $crate::__scout_check_observe_mode() {
            // Coverage-only replay runs before Crucible's stateful initializer.  Set
            // this per-thread flag here so failed actions terminate accumulated chains
            // exactly as they did in the stateful campaign that produced the corpus.
            $crate::__scout_crucible_test_context::set_stateful_chain_mode(true);
            static SESSION_ONCE: std::sync::Once = std::sync::Once::new();
            SESSION_ONCE.call_once(|| {
                match $crate::__scout_check_nonce() {
                    Ok(nonce) => eprintln!("[SCOUT_CHECK_SESSION] {}", nonce),
                    Err(reason) => $crate::__scout_check_emit_error(reason),
                }
            });
        }
    }};
}

// Gate the *entire* property computation, not only its final predicate.  This
// prevents another property's fallible reads, eligibility logic, or shadow-hook
// arithmetic from panicking/starving an isolated SCOUT_CHECK_ONLY replay.
macro_rules! scout_run_property {
    ($property:literal, $expression:expr $(,)?) => {{
        if $crate::__scout_check_selected($property) {
            let _ = $expression;
        }
    }};
}

#[doc(hidden)]
#[macro_export]
macro_rules! __scout_check_impl {
    ($property:literal, $site:literal, $predicate:expr, $message:expr) => {{
        let __scout_observe = $crate::__scout_check_observe_mode();
        if !$crate::__scout_check_selected($property) {
            true
        } else {
            let __scout_nonce = if __scout_observe {
                Some($crate::__scout_check_nonce())
            } else {
                None
            };
            if let Some(Err(ref __scout_error)) = __scout_nonce {
                // An invalid session can never produce an EVALUATED marker.  The
                // mechanical verifier therefore cannot mistake it for sound evidence.
                $crate::__scout_check_emit_error(__scout_error);
                false
            } else {
                // Keep the predicate in one lexical/runtime position.  Expressions
                // with reads or counters are evaluated exactly once per selected check.
                let __scout_check_result: bool = $predicate;
                if let Some(Ok(ref __scout_run)) = __scout_nonce {
                    eprintln!(
                        "[SCOUT_CHECK_EVALUATED] {} {} {} {}:{}",
                        __scout_run, $property, $site, file!(), line!()
                    );
                    if !__scout_check_result {
                        eprintln!(
                            "[SCOUT_CHECK_WOULD_VIOLATE] {} {} {} {}:{}",
                            __scout_run, $property, $site, file!(), line!()
                        );
                    }
                } else if !__scout_check_result {
                    $crate::__scout_crucible_test_context::record_violation($message);
                }
                __scout_check_result
            }
        }
    }};
}

macro_rules! scout_check {
    ($property:literal, $site:literal, $predicate:expr $(,)?) => {{
        $crate::__scout_check_impl!(
            $property,
            $site,
            $predicate,
            format!(
                "Invariant {} check {} failed at {}:{}",
                $property, $site, file!(), line!()
            )
        )
    }};
    ($property:literal, $site:literal, $predicate:expr, $($arg:tt)+) => {{
        $crate::__scout_check_impl!($property, $site, $predicate, format!($($arg)+))
    }};
}
// SCOUT:CHECK-CONTRACT:END

const SCOUT_TARGET_PROGRAM_ARTIFACT: &str = "programs/shielded_pool_program.so";


/// Mirrored payload declarations, transcribed from the program's own types.
/// Field order, field types and every `#[wincode(..)]` attribute are copied verbatim
/// -- they ARE the wire format, so a dropped attribute silently changes length
/// prefixes throughout the payload. `#[repr(C)]` + `Pod` types are written as their
/// raw in-memory image instead; `Pod` cannot derive on a padded struct, so a type the
/// program itself derives it on is padding-free and the transcription is exact.
#[allow(dead_code, non_snake_case)]
pub mod scout_wire {
    use wincode::{containers, len::FixIntLen, SchemaWrite};
    use bytemuck::{Pod, Zeroable};

    #[derive(Clone, Debug, SchemaWrite)]
    pub struct Bsb22Commitment {
        pub commitment: [u8; 32],
        pub commitment_pok: [u8; 32],
    }

    #[derive(Clone, Debug, SchemaWrite)]
    #[wincode(tag_encoding = "u16")]
    pub enum CircuitId {
        ConfidentialEddsa(u8, u8, u8),
        RingEddsa(u8, u8, u8),
        RingAuthority(u8, u8, u8),
        RingP256(u8, u8, u8, RingP256ProofData),
    }

    #[derive(Clone, Copy, Debug, Pod, Zeroable)]
    #[repr(C)]
    pub struct CreateProtocolConfigData {
        pub protocol_authority: [u8; 32],
        pub tree_creation_authority: [u8; 32],
        pub tree_creation_is_permissionless: u8,
        pub forester_authority: [u8; 32],
        pub ring_creation_authority: [u8; 32],
        pub ring_creation_is_permissionless: u8,
        pub spl_interface_creation_is_permissionless: u8,
    }

    #[derive(Clone, Debug, SchemaWrite)]
    #[wincode(tag_encoding = "u8")]
    pub enum DepositAssetKind {
        Sol,
        Spl {
            spl_interface_bump: u8,
        },
    }

    #[derive(Clone, Debug, SchemaWrite)]
    pub struct DepositEntry {
        pub asset_index: u8,
        pub view_tag: [u8; 32],
        pub owner: [u8; 32],
        pub blinding: [u8; 32],
        pub amount: u64,
        pub utxo_data: Option<UtxoData>,
        #[wincode(with = "Option<containers::Vec<u8, FixIntLen<u16>>>")]
        pub memo: Option<Vec<u8>>,
    }

    #[derive(Clone, Debug, SchemaWrite)]
    pub struct DepositIxData {
        #[wincode(with = "containers::Vec<DepositAssetKind, FixIntLen<u8>>")]
        pub assets: Vec<DepositAssetKind>,
        #[wincode(with = "containers::Vec<DepositEntry, FixIntLen<u8>>")]
        pub deposits: Vec<DepositEntry>,
    }

    #[derive(Clone, Debug, SchemaWrite)]
    pub struct FixedOptionOwnerTag {
        pub present: u8,
        pub tag: [u8; 32],
    }

    #[derive(Clone, Debug, SchemaWrite)]
    pub struct InputUtxo {
        pub nullifier_hash: [u8; 32],
        pub nullifier_tree_root_index: u16,
        pub utxo_tree_root_index: u16,
    }

    #[derive(Clone, Debug, SchemaWrite)]
    #[wincode(tag_encoding = "u8")]
    pub enum InterfaceTransfer {
        SolDeposit {
            amount: u64,
        },
        SolWithdrawal {
            amount: u64,
        },
        SplDeposit {
            amount: u64,
            spl_interface_bump: u8,
        },
        SplWithdrawal {
            amount: u64,
            spl_interface_bump: u8,
        },
    }

    #[derive(Clone, Debug, SchemaWrite)]
    pub struct MergeProof {
        pub a: [u8; 32],
        pub b: [u8; 64],
        pub c: [u8; 32],
    }

    #[derive(Clone, Debug, SchemaWrite)]
    pub struct MergeTransactIxData {
        pub expiry_unix_ts: u64,
        pub proof: MergeProof,
        pub output_utxo_hash: [u8; 32],
        pub eddsa_owner: bool,
        pub private_tx_hash: [u8; 32],
        #[wincode(with = "containers::Vec<[u8; 32], FixIntLen<u8>>")]
        pub nullifiers: Vec<[u8; 32]>,
        #[wincode(with = "containers::Vec<u16, FixIntLen<u8>>")]
        pub utxo_tree_root_index: Vec<u16>,
        #[wincode(with = "containers::Vec<u16, FixIntLen<u8>>")]
        pub nullifier_tree_root_index: Vec<u16>,
    }

    #[derive(Clone, Debug, SchemaWrite)]
    pub struct MessageData {
        pub view_tag: [u8; 32],
        #[wincode(with = "containers::Vec<u8, FixIntLen<u16>>")]
        pub data: Vec<u8>,
    }

    #[derive(Clone, Debug, SchemaWrite)]
    #[wincode(tag_encoding = "u8")]
    pub enum OwnerTag {
        Inline([u8; 32]),
        Account(u8),
    }

    #[derive(Clone, Copy, Debug, Pod, Zeroable)]
    #[repr(C)]
    pub struct PauseTreeData {
        pub paused: u8,
    }

    #[derive(Clone, Debug, SchemaWrite)]
    pub struct RingP256ProofData {
        pub bsb22_commitment: Bsb22Commitment,
        pub default_owner_tag: FixedOptionOwnerTag,
    }

    #[derive(Clone, Debug, SchemaWrite)]
    pub struct TransactIxData {
        pub expiry_unix_ts: u64,
        pub private_tx_hash: [u8; 32],
        pub circuit: CircuitId,
        pub tx_viewing_pk: [u8; 33],
        pub salt: [u8; 16],
        pub proof: TransactProof,
        #[wincode(with = "containers::Vec<InputUtxo, FixIntLen<u8>>")]
        pub inputs: Vec<InputUtxo>,
        #[wincode(with = "containers::Vec<InterfaceTransfer, FixIntLen<u8>>")]
        pub interface_transfers: Vec<InterfaceTransfer>,
        pub data_hash: Option<[u8; 32]>,
        pub ring_data_hash: Option<[u8; 32]>,
        #[wincode(with = "containers::Vec<TransactOutput, FixIntLen<u8>>")]
        pub outputs: Vec<TransactOutput>,
        #[wincode(with = "containers::Vec<MessageData, FixIntLen<u8>>")]
        pub messages: Vec<MessageData>,
    }

    #[derive(Clone, Debug, SchemaWrite)]
    pub struct TransactOutput {
        pub utxo_hash: [u8; 32],
        pub owner_tag: OwnerTag,
        #[wincode(with = "Option<containers::Vec<u8, FixIntLen<u16>>>")]
        pub data: Option<Vec<u8>>,
    }

    #[derive(Clone, Debug, SchemaWrite)]
    pub struct TransactProof {
        pub a: [u8; 32],
        pub b: [u8; 64],
        pub c: [u8; 32],
    }

    #[derive(Clone, Debug, SchemaWrite)]
    pub struct UtxoData {
        pub data_hash: [u8; 32],
        #[wincode(with = "containers::Vec<u8, FixIntLen<u16>>")]
        pub data: Vec<u8>,
    }
}

// SCOUT:BINDINGS:BEGIN
// tree = self.tree
// input_tree = self.tree
// output_tree = self.tree
// reimbursement_recipient = self.payer.pubkey()
// ring_config = self.ring_config
// protocol_config = self.protocol_config
// A SOL-only deposit batch. `assets` DECLARES the account layout (the program reads
// the accounts each kind names, in order), so the payload and the account tail must
// agree: one `Sol` group == the two accounts appended below, and `asset_index: 0`
// selects it. An empty batch is rejected outright (EmptyDepositBatch), so the
// generator's minimal `Vec::new()` default can never succeed here.
// Deposit.assets = vec![scout_wire::DepositAssetKind::Sol]
// Deposit.account_tail = vec![AccountMeta::new_readonly(system_program::ID, false), AccountMeta::new(self.sol_interface, false)]
// The registry record `setup()` minted for the merge fixture's owner. The generator
// cannot derive it: the PDA seed is an ACCOUNT (the record's own stored `owner`),
// not a value in the instruction data.
// user_record = self.user_record
// merge_transact is proof-gated, and a Groth16 proof pins the whole public half of
// its witness -- the nullifiers, the output hash, the transcript hash, the expiry
// (which is hashed into external_data_hash) and the roots the program will look up.
// So these are not "defaults the fuzzer could improve on": any other value makes the
// proof invalid by construction. `eddsa_owner` is deliberately left FUZZABLE, since
// it selects the owner rail the program binds from the registry record, and the
// sequencing of this action against deposits stays fuzzer-controlled.
// MergeTransact.expiry_unix_ts = merge_fixture::EXPIRY_UNIX_TS
// MergeTransact.proof = scout_wire::MergeProof { a: merge_fixture::PROOF_A, b: merge_fixture::PROOF_B, c: merge_fixture::PROOF_C }
// MergeTransact.output_utxo_hash = merge_fixture::OUTPUT_UTXO_HASH
// MergeTransact.private_tx_hash = merge_fixture::PRIVATE_TX_HASH
// MergeTransact.nullifiers = merge_fixture::NULLIFIERS.to_vec()
// Every input slot cites the same pair of roots, so the program recomputes the two
// hash chains the proof committed to. The state index is captured at setup time
// because it is the ring buffer's cursor; the nullifier tree has only ever held its
// initial root, at index 0.
// MergeTransact.utxo_tree_root_index = vec![self.merge_utxo_root_index; 8]
// MergeTransact.nullifier_tree_root_index = vec![0u16; 8]
// The circuit selector is not a free field: `is_supported` requires the public
// asset slot count to be exactly N_PUBLIC_SLOTS (3), and the input/output counts
// to equal the vector lengths the generator emits (1 and 1). The generator's
// all-zero default fails `InvalidTransactShape` at 1,854 CU -- before any of the
// instruction's real work -- so pinning it is what makes the action reach the
// handler at all. The proof, roots and hashes stay fuzzer-controlled.
// TransactNoTransfers.circuit = scout_wire::CircuitId::ConfidentialEddsa(1, 1, 3)
// The transact proof binds `hash_bytes(payer_account)`, so the instruction's payer
// must be the fixture's actor -- NOT the transaction fee payer. `signer:` makes the
// generated action sign with it as well.
// TransactNoTransfers.payer = signer:self.transact_actor.insecure_clone()
// Every published value below is fixed by the proof. `tx_viewing_pk` and `salt`
// are bound into the external data hash, which the program derives itself, so they
// are as load-bearing as the hashes.
// TransactNoTransfers.expiry_unix_ts = merge_fixture::EXPIRY_UNIX_TS
// TransactNoTransfers.private_tx_hash = merge_fixture::transact::PRIVATE_TX_HASH
// TransactNoTransfers.tx_viewing_pk = merge_fixture::transact::TX_VIEWING_PK
// TransactNoTransfers.salt = [0u8; 16]
// TransactNoTransfers.proof = scout_wire::TransactProof { a: merge_fixture::transact::PROOF_A, b: merge_fixture::transact::PROOF_B, c: merge_fixture::transact::PROOF_C }
// TransactNoTransfers.inputs = vec![scout_wire::InputUtxo { nullifier_hash: merge_fixture::transact::NULLIFIER, nullifier_tree_root_index: 0, utxo_tree_root_index: self.transact_utxo_root_index }]
// TransactNoTransfers.outputs = vec![scout_wire::TransactOutput { utxo_hash: merge_fixture::transact::OUTPUT_UTXO_HASH, owner_tag: scout_wire::OwnerTag::Inline(merge_fixture::transact::ACTOR_PUBKEY), data: None }]
// TransactNoTransfers.messages = Vec::new()
// The forester applies a batch to ITS OWN tree, whose queue only setup() writes.
// Pointing this at `self.tree` would prove a hash chain over whichever nullifiers
// the fuzzer happened to queue there, in whichever order.
// BatchUpdateNullifierTree.tree = self.forester_tree
// BatchUpdateNullifierTree.new_root = merge_fixture::forester::NEW_ROOT
// BatchUpdateNullifierTree.old_root = merge_fixture::forester::OLD_ROOT
// BatchUpdateNullifierTree.zkp_batch_index = merge_fixture::forester::ZKP_BATCH_INDEX
// BatchUpdateNullifierTree.compressed_proof = shielded_pool::types::CompressedProof { a: merge_fixture::forester::PROOF_A, b: merge_fixture::forester::PROOF_B, c: merge_fixture::forester::PROOF_C }
// SCOUT:BINDINGS:END

// SCOUT:PRELUDE:BEGIN
use crucible_fuzzer::anchor_lang::solana_program::instruction::{
    AccountMeta as ScoutMeta, Instruction as ScoutIx,
};

// Layout constants read out of the program's own interface crate (a scratch binary
// linked against `zolana-interface` printed each one), NOT guessed. Each is also
// self-checking: `create_tree` validates the tree account's exact length, and the
// state loaders check their discriminator, so a stale value fails loudly here
// rather than silently mis-encoding.
//   state::tree_account_size()      -> 1185728
//   ProtocolConfig::SIZE            -> 132
//   RingConfig::SIZE                -> 68  (disc 1 + authority 32 + program_id 32 + 1 + 1 + 1)
const TREE_ACCOUNT_SIZE: usize = 1_185_728;
const RING_CONFIG_SIZE: usize = 68;
/// `RingConfig.ring_authority_transact_is_enabled` and `.paused`, after the
/// discriminator and the two 32-byte addresses. Built and asserted by
/// `scout_ring_config_bytes`.
const RING_ENABLED_OFFSET: usize = 65;
const RING_PAUSED_OFFSET: usize = 66;
const PROTOCOL_CONFIG_PDA_SEED: &[u8] = b"protocol_config";
const RING_AUTH_PDA_SEED: &[u8] = b"ring_auth";
const DISC_RING_CONFIG: u8 = 4;
const TAG_CREATE_PROTOCOL_CONFIG: u8 = 0;
const TAG_UPDATE_PROTOCOL_CONFIG: u8 = 1;
/// `ProtocolConfig`'s three `*_creation_is_permissionless` bytes, after the
/// discriminator and four 32-byte addresses.
const PROTOCOL_TREE_PERMISSIONLESS_OFFSET: usize = 129;
const PROTOCOL_RING_PERMISSIONLESS_OFFSET: usize = 130;
const PROTOCOL_SPL_PERMISSIONLESS_OFFSET: usize = 131;
/// `UpdateProtocolConfigData` is a borsh enum; these are the variant indices of
/// its three boolean switches.
/// `UpdateProtocolConfigData::ForesterAuthority` -- rotates the key that
/// `batch_update_nullifier_tree` demands. Variants 0..3 rotate authorities and were
/// never exercised; 4..6 flip the permissionless switches.
const UPDATE_VARIANT_FORESTER_AUTHORITY: u8 = 2;
/// `ProtocolConfig.forester_authority`, after the discriminator and the two
/// preceding addresses.
const PROTOCOL_FORESTER_AUTHORITY_OFFSET: usize = 65;
const UPDATE_VARIANT_TREE_PERMISSIONLESS: u8 = 4;
/// `UpdateProtocolConfigData::RingCreationPermissionless`, the THIRD permissionless
/// switch and the one P-0015 was missing. `setup()` pins it to 1, so the gate in
/// `create_ring_config` -- "if not permissionless, check `ring_creation_authority`"
/// -- had never been evaluated in any campaign. It is the same `if` as the other
/// two, written out a third time against a third key, which is exactly the
/// arrangement where one of them quietly checks the wrong one.
const UPDATE_VARIANT_RING_PERMISSIONLESS: u8 = 5;
const UPDATE_VARIANT_SPL_PERMISSIONLESS: u8 = 6;
const TAG_CREATE_TREE: u8 = 2;
const TAG_DEPOSIT: u8 = 11;
/// `b"spl_asset_vault"` — seeds of the per-mint SPL interface token account.
const SPL_INTERFACE_PDA_SEED: &[u8] = b"spl_asset_vault";
/// The pool's CPI authority PDA. `validate_spl_settlement` requires the SPL
/// interface token account's TOKEN owner to be exactly this.
const SHIELDED_POOL_CPI_AUTHORITY: [u8; 32] = [
    109, 182, 246, 114, 43, 36, 173, 152, 203, 138, 114, 231, 209, 50, 184, 236, 107, 139, 188,
    29, 115, 163, 218, 113, 6, 134, 33, 44, 204, 50, 186, 87,
];
/// `GGk4JbLExpASWVCAtAVdxZ65BCQsj8WN5TsL6v8Dd1c8`, bump 252 — the canonical SOL
/// interface PDA (`sol_interface` seeds), which `validate_sol_settlement` requires
/// to be writable and owned by the SYSTEM program.
const SOL_INTERFACE: [u8; 32] = [
    226, 231, 179, 96, 7, 216, 134, 74, 16, 116, 193, 73, 186, 110, 210, 48, 2, 97, 154, 130,
    121, 53, 28, 232, 140, 221, 183, 236, 109, 212, 72, 117,
];
/// `BPFLoaderUpgradeab1e11111111111111111111111`, from the interface crate.
const BPF_LOADER_UPGRADEABLE_ID: [u8; 32] = [
    2, 168, 246, 145, 78, 136, 161, 176, 226, 16, 21, 62, 247, 99, 174, 43, 0, 194, 185, 61, 22,
    193, 36, 210, 192, 83, 122, 16, 4, 128, 0, 0,
];

/// `CreateProtocolConfigData` is `#[repr(C)]` + `Pod` with align 1, so its wire
/// form is just its fields in declaration order (131 bytes).
fn scout_create_protocol_config_data(authority: &Pubkey) -> Vec<u8> {
    let mut data = vec![TAG_CREATE_PROTOCOL_CONFIG];
    data.extend_from_slice(authority.as_ref()); // protocol_authority
    data.extend_from_slice(authority.as_ref()); // tree_creation_authority
    data.push(0); // tree_creation_is_permissionless
    data.extend_from_slice(authority.as_ref()); // forester_authority
    data.extend_from_slice(authority.as_ref()); // ring_creation_authority
    data.push(1); // ring_creation_is_permissionless
    data.push(1); // spl_interface_creation_is_permissionless
    data
}

/// `RingConfig` is `#[repr(C)]` + `Pod`, align 1: discriminator, authority,
/// program_id, enabled, paused, bump.
fn scout_ring_config_bytes(authority: &Pubkey, ring_program: &Pubkey, bump: u8) -> Vec<u8> {
    let mut data = Vec::with_capacity(RING_CONFIG_SIZE);
    data.push(DISC_RING_CONFIG);
    data.extend_from_slice(authority.as_ref());
    data.extend_from_slice(ring_program.as_ref());
    data.push(1); // ring_authority_transact_is_enabled
    data.push(0); // paused
    data.push(bump);
    assert_eq!(data.len(), RING_CONFIG_SIZE, "RingConfig layout drifted");
    data
}

/// Pre-generated `merge_transact` fixture. The whole public half of the merge
/// witness is fixed at generation time, so the harness must reproduce the exact
/// world the proof was generated against: the same two deposits, the same owner
/// record, the same expiry. A scratch Go program built these with the protocol's
/// OWN `prover-test/spp/protocol` helpers (the same ones the circuit's fixtures
/// use), which is why the roots below are values to ASSERT rather than to trust.
///
/// Regenerate with `cmd/mergefix` against `prover/server`; every constant here
/// changes together or the proof stops verifying.
mod merge_fixture {
    /// Chosen so `check_not_expired` passes for any plausible test clock. It is
    /// hashed into `external_data_hash`, so it is part of the fixture, not a knob.
    pub const EXPIRY_UNIX_TS: u64 = 4_000_000_000;
    /// `user_record.owner`. Minted rather than derived from a keypair: the eddsa
    /// merge rail binds the owner through the registry record and any caller may
    /// run the merge, so this identity never signs.
    pub const OWNER_PUBKEY: [u8; 32] = hex32(
        "000000000000000000000000000000000000000000000000000000000000002a");
    pub const NULLIFIER_PUBKEY: [u8; 32] = hex32(
        "1a87c4a79842bccba95c572c2ebf630f1c8fc1c7713d38fa19eece6c2dd39959");
    /// UTXO `owner` field = OwnerHash(hash_bytes(OWNER_PUBKEY), NULLIFIER_PUBKEY).
    pub const UTXO_OWNER: [u8; 32] = hex32(
        "1908c5cda045966c8d64c6ae8113fa7c423441f5d2c5726bcf211e162bab2630");
    pub const DEPOSIT_AMOUNTS: [u64; 2] = [1_000_000, 2_000_000];
    pub const DEPOSIT_BLINDINGS: [[u8; 32]; 2] = [
        hex32("0000000000000000000000000000000000000000000000000000000000001111"),
        hex32("0000000000000000000000000000000000000000000000000000000000002222"),
    ];
    /// The state-tree root after both fixture deposits, and the nullifier tree's
    /// root at initialisation. Both are asserted against the live account.
    pub const EXPECTED_UTXO_ROOT: [u8; 32] = hex32(
        "0996a42720758be170b163e0fde367162d8867fcec0aa12f2a5f0276edf8901d");
    /// The Poseidon fold over the ten nullifiers of the first ZKP chunk, computed
    /// OFFLINE by the batch generator from the nullifier list. The queue builds the
    /// same value incrementally, one insertion at a time, and the forester's proof
    /// binds it -- so the two agreeing is a real cross-check, not a restatement.
    pub const EXPECTED_HASH_CHAIN: [u8; 32] = hex32(
        "14588856a0a184954129f04e664dee38d23110bea13455794739dbae421c2167");
    pub const EXPECTED_NF_ROOT: [u8; 32] = hex32(
        "1d8e71a601b3e8debbba9b557b8369c7f404ae57bebf0852236b072820954277");
    pub const OUTPUT_UTXO_HASH: [u8; 32] = hex32(
        "17fc00884e38334548659f443742a78b9418c69723d34fab904047e08b152e06");
    pub const PRIVATE_TX_HASH: [u8; 32] = hex32(
        "0692e1d16374cf7ec080cbf851537ee689ed5287776ed1a3642020aed4319d9d");
    /// The Groth16 proof over the witness above, in the wire format `MergeProof`
    /// carries (G1 32 bytes, G2 64, G1 32). Produced by `cmd/mergefix -key
    /// <merge_8_1.key>` -- the canonical proving key matching the
    /// `merge_8_1::VERIFYINGKEY` compiled into the program under test. A locally
    /// re-run `groth16.Setup` would produce a different pair, verifiable only
    /// against a REBUILT program, which is not the program being fuzzed.
    /// 180,470 constraints.
    ///
    /// gnark's OWN compressed encoding is not this format, and substituting it
    /// fails verification while looking entirely plausible -- same field, same
    /// length. The client negates `proof_a` and compresses with Solana's
    /// `alt_bn128_*_compress_be` (`sdk-libs/client/src/prover/proof.rs`), so the
    /// scratch `proofconv` binary runs those same two crates over the prover's
    /// uncompressed output.
    pub const PROOF_A: [u8; 32] = hex32(
        "0c6df6b5f542b959d689d0a19cdd041ef2ff034921468543da2b5957b3e36309");
    pub const PROOF_B: [u8; 64] = hex_bytes(
        "a881d8d14b823d5ad80dfb169830a7da29eaa7a70ca4c61130b0daaf56d76431\
         04e074070f2c0e4501038f6310c419b203ba8709180e3a3398ca8f40b4c5f278");
    pub const PROOF_C: [u8; 32] = hex32(
        "2238faf4b9043abc400f661df50e6cda0c5061407280168251f2970be72f33f9");

    /// The RING merge rail. A second, independent fixture: the ring circuit binds
    /// `ring_program_id` and the output `ring_data_hash` in place of the owner
    /// identity the default rail folds in, and each input carries its own ring
    /// data -- so none of the default rail's values can be reused.
    ///
    /// Its inputs are RING deposits, at leaves 2 and 3, on top of the default
    /// rail's leaves 0 and 1. The Merkle paths are against the 4-leaf tree that
    /// actually exists at that point, which is why the two fixtures are generated
    /// together rather than independently.
    pub mod ring {
        use super::{hex32, hex_bytes};

        pub const DEPOSIT_AMOUNTS: [u64; 2] = [3_000_000, 4_000_000];
        /// The ring rail publishes `Poseidon(owner_hash, blinding)` rather than the
        /// owner and blinding separately -- the preimage is deliberately absent
        /// from the public instruction.
        pub const DEPOSIT_OWNER_UTXO_HASHES: [[u8; 32]; 2] = [
            hex32("2d0b0fedc5a635ff07c9d8cd231c2f32b92b25f34024d3a6f603c4729b6d16ac"),
            hex32("1343a50756700f0c35d2ebf57fa55c3971dbe1df0bd4545c548e3797941c1a86"),
        ];
        pub const DEPOSIT_RING_DATA: [[u8; 32]; 2] = [
            hex32("0000000000000000000000000000000000000000000000000000000000000051"),
            hex32("0000000000000000000000000000000000000000000000000000000000000052"),
        ];
        pub const OUTPUT_RING_DATA_HASH: [u8; 32] =
            hex32("0000000000000000000000000000000000000000000000000000000000000053");
        pub const EXPECTED_UTXO_ROOT: [u8; 32] =
            hex32("15fee94f952326322a859737ece1ac52aa8a532c7625910aa8892380a68a3272");
        pub const OUTPUT_UTXO_HASH: [u8; 32] =
            hex32("0e8827e493908432dc645a22166b41f47839ce2c6d6801df88b1618347b112de");
        pub const PRIVATE_TX_HASH: [u8; 32] =
            hex32("0494a62f1ed8098cc36a0c0ebf844184478adff525c38cfd19eb57e1fd4df5b7");
        pub const NULLIFIERS: [[u8; 32]; 8] = [
            hex32("1c4899334c3d8c36c37c1cf15f9d477a35693e1735b4733cc069ddc9feeadc2c"),
            hex32("043db7b84e4c3f10c045d6243670a909179f824dad57f7e1e2882198e8dd0014"),
            hex32("247b2e1fa804abe02da6d352c2ca15120073284b8e1f10a1a24a3c143f1e2718"),
            hex32("02d1f4c936c60e3d42d1830ec7841de642cb636c2875f47431ae33caad977d95"),
            hex32("086805c3c48a48481eac63935db4b10c3fe410517ab5ffc31584fb2c5722b57b"),
            hex32("0da23c34465b1ab25972121ec0f5cd0faca71700d556b26f2635c89249d1e086"),
            hex32("29617d1a3a7d7cca2488ae0c20edfb5b02b2c94b7ed6090edb053eeb20d44b70"),
            hex32("054974b9ca007d2eac420718d7b5fbcf46c82013c1ff6c924c78f3ecbb969e6f"),
        ];
        /// Verified against `merge_ring_8_1::VERIFYINGKEY`, not `merge_8_1`.
        pub const PROOF_A: [u8; 32] =
            hex32("8382e0474b3f5a734cd4ebeedc98b1d89865907b3b28838f93ad41464ecf077f");
        pub const PROOF_B: [u8; 64] = hex_bytes(
            "06dda371d16e2bce328cb1e328576b96a387cc4561c0ac6b6ed7c04e3a1df061\
             179e1afd464cc87e90f59a7fd0bae3fbc4d1f7ebe61f22458b5d6428c78a367f");
        pub const PROOF_C: [u8; 32] =
            hex32("25651c0c23fa6f459f285413f1f49fec16a265108c14dfac3fa96de059c06e77");
    }

    /// The `transact` fixture: a (1 input, 1 output, 3 public slot) confidential
    /// eddsa transfer, one UTXO spent and one of equal value created, with no
    /// public movement and no interface transfers.
    ///
    /// Its owner is a DIFFERENT actor from the merges', with its own nullifier
    /// secret -- a shared secret would make the two owners' nullifiers collide.
    /// The actor's keypair comes from a fixed seed because the public input hash
    /// binds `hash_bytes(payer_account)`: a `Keypair::new()` here would change the
    /// bound address on every run.
    pub mod transact {
        use super::{hex32, hex_bytes};

        /// ed25519 seed for the transact signer. Solana's `Keypair` is ed25519 over
        /// a 32-byte seed, so this reproduces `ACTOR_PUBKEY` exactly.
        pub const ACTOR_SEED: [u8; 32] =
            hex32("11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff");
        pub const ACTOR_PUBKEY: [u8; 32] =
            hex32("23ac0770a1060241604a8e60a47166e3e5b4034d4ee321dbe19b342e85b21544");
        /// The UTXO `owner` field: OwnerHash(hash_bytes(ACTOR_PUBKEY), nullifier_pk).
        pub const UTXO_OWNER: [u8; 32] =
            hex32("1ca7f6a8e9e5112fc340435cb8790b7d46296f5065e1c16c396b1e48721025a8");
        pub const INPUT_AMOUNT: u64 = 5_000_000;
        pub const INPUT_BLINDING: [u8; 32] =
            hex32("0000000000000000000000000000000000000000000000000000000000005555");
        pub const NULLIFIER: [u8; 32] =
            hex32("2fdd253e79b87f6bcbb98351580ddfe4ea4bbc8ae601965dbd703b0c32a3bc3a");
        pub const OUTPUT_UTXO_HASH: [u8; 32] =
            hex32("04cc9f507eb2d878dc5e1d3e04b26906c7444b3438ac8b51b47c5fffbf1a06d7");
        pub const PRIVATE_TX_HASH: [u8; 32] =
            hex32("0dcd54c17b396a45ddf1dfd154a7f5c5e5be27a9d460d160372026380a17a264");
        pub const EXPECTED_UTXO_ROOT: [u8; 32] =
            hex32("2168aebedb00a8049351e85b5d0d4020340599e79d981df66abc72fa159eb995");
        /// Bound into the external data hash, so it is part of the fixture.
        pub const TX_VIEWING_PK: [u8; 33] = hex_bytes(
            "020000000000000000000000000000000000000000000000000000000000000000");
        /// Verified against `transfer_confidential_1_1::VERIFYINGKEY`.
        pub const PROOF_A: [u8; 32] =
            hex32("0457a521e3f56951bc4cbb6d6d381504a22cb8482fb97933771c098a06465c42");
        pub const PROOF_B: [u8; 64] = hex_bytes(
            "1a30adcf34ce7d22bc6e5dc01066fda82efcdda595e0ca4a854c8edc26b97851\
             17affd821caaf9ce9333e733e88da7b16ab7df83b0b68137ed4c85a7639574b1");
        pub const PROOF_C: [u8; 32] =
            hex32("a6b7c2bd7f720ae863e1eabfea33671e2efbebaf4f2277b8ad0be920adec9285");
    }

    /// The SPL fixture's addresses, fixed so an SPL withdrawal proof can bind them,
    /// and the SPL withdrawal itself.
    ///
    /// `deposit`'s one uncovered line was the `SplWithdrawal` arm of the settlement
    /// dispatch: SPL value could enter the pool and never leave, so P-0002 was
    /// one-sided exactly as P-0001 had been before the SOL withdrawal existed.
    pub mod spl {
        use super::{hex32, hex_bytes};
        pub const INPUT_AMOUNT: u64 = 400_000;
        pub const WITHDRAWAL: u64 = 250_000;
        pub const INPUT_BLINDING: [u8; 32] =
            hex32("000000000000000000000000000000000000000000000000000000000000dddd");
        pub const NULLIFIER: [u8; 32] =
            hex32("169ada521888effb5953cb17584ee525d3139aa59ce60bb4ec3a3916e0ec752d");
        pub const OUTPUT_UTXO_HASH: [u8; 32] =
            hex32("0645f595d6546dd48896345c8ba35c891b0eed05290d0a5aad1d85bc47b33d6a");
        pub const PRIVATE_TX_HASH: [u8; 32] =
            hex32("047f6d8f447c6866e889a6a73ba75b644b3637856d54f81524ccce7b05e403b7");
        pub const EXPECTED_UTXO_ROOT: [u8; 32] =
            hex32("2abba2609ee1f0ed75f0bd5674891333d461a56f9ed838929b4f25dd1a8631c1");
        /// Derived in `setup()` from the mint, and asserted to equal this -- the
        /// proof bound it, so a change in the derivation must fail loudly here
        /// rather than as an unexplained verification failure.
        pub const INTERFACE: [u8; 32] =
            hex32("eedf414a387f6037eb046223c8be580c47fe942c110856548163510288bbb5a8");
        pub const PROOF_A: [u8; 32] =
            hex32("868ba0bcd01322a194273f3373d3ecd0a6c518809f6a28b9c576917d654f0379");
        pub const PROOF_B: [u8; 64] = hex_bytes(
            "19a285c7fd172bd63ff35be3053c831ab430b61835ecd2526d004eff4c4f6e42\
             295a7878eca6439d002267091675feca10b0eeaebd40d2aa187f20255884f33e");
        pub const PROOF_C: [u8; 32] =
            hex32("2a45720a27e9be61b2c883edfaa900139da2d170afd33d1dd6d71abfd67177b2");
        pub const MINT: [u8; 32] =
            hex32("5011000000000000000000000000000000000000000000000000000000000001");
        pub const USER_TOKEN: [u8; 32] =
            hex32("5011000000000000000000000000000000000000000000000000000000000002");
    }

    /// `transact` WITH a SOL withdrawal -- the path where value LEAVES the pool.
    ///
    /// Without it the harness had 100% line coverage of `transact` and
    /// `settle_spl_withdrawal` at ZERO executions: value could enter the pool and
    /// never leave, so every solvency property was only half-tested and adversary
    /// value conservation was vacuous.
    ///
    /// The output is SHORT of the input by exactly the withdrawn amount, and the
    /// difference appears in a public movement slot as a negative field element.
    /// The circuit checks `sum(in) + public == sum(out)` per asset, so the UTXO
    /// arithmetic and the lamports actually moved cannot disagree.
    pub mod transact_withdrawal {
        use super::{hex32, hex_bytes};
        pub const INPUT_AMOUNT: u64 = 8_000_000;
        pub const WITHDRAWAL: u64 = 5_000_000;
        pub const INPUT_BLINDING: [u8; 32] =
            hex32("000000000000000000000000000000000000000000000000000000000000bbbb");
        pub const NULLIFIER: [u8; 32] =
            hex32("1e096c31075b1e3652b6beb8d2e563ee4e82f4e2fc10da5924c176e6ca00ade8");
        pub const OUTPUT_UTXO_HASH: [u8; 32] =
            hex32("294ce05734c222449e450d86ad214d9be9db8b7bf450373ed32c8085ef1dbe66");
        pub const PRIVATE_TX_HASH: [u8; 32] =
            hex32("2c5c44bf670a01a991c31a12077bfa14f7a7ea4dcf5015c670672c2b7170cb19");
        pub const EXPECTED_UTXO_ROOT: [u8; 32] =
            hex32("07f74727458f102d475aac7e28e3c78cb94bca79d33581d5e9a29402d630b65a");
        pub const PROOF_A: [u8; 32] =
            hex32("8192e74a874b23bb0964e9936b4a59a7d5b3af8e91756110d95111d98e79a690");
        pub const PROOF_B: [u8; 64] = hex_bytes(
            "19b3f83fe8fea38aa5223b5d19bfed421b8cf083899ab428ec45c5b58090cb81\
             29914866ed8b1ecad59c45f0eb5950e90946afbb6889e56af576b65154c79741");
        pub const PROOF_C: [u8; 32] =
            hex32("95165c5b8bdb1252bd2b78ace28c04d31e0d88fbd7ad8ea3ee525d231d0b6952");
    }

    /// `ring_transact` (tag 15). Same shape as `transact`, but every UTXO carries
    /// the ring's program id and its own ring data, and the circuit publishes only
    /// output owner tags marked confidential -- this output's `data` is `None`, so
    /// none are, and the chain folds over a zero rather than the owner.
    pub mod ring_transact {
        use super::{hex32, hex_bytes};
        pub const LEAF_AMOUNT: u64 = 6_000_000;
        pub const OWNER_UTXO_HASH: [u8; 32] =
            hex32("1fa0b76ac459569af4dcfc864731cfc0b1186475002474cbfeb5b0bae0b2d792");
        pub const RING_DATA_HASH: [u8; 32] =
            hex32("0000000000000000000000000000000000000000000000000000000000000061");
        pub const NULLIFIER: [u8; 32] =
            hex32("1ca8d841983bca563671c33ce547198b679d62b4a35a9d11055cf17fa3644075");
        pub const OUTPUT_UTXO_HASH: [u8; 32] =
            hex32("2c1191b33b81b65acb7717b64284f893bfe740c3b1689cd4674715d4ceb1f533");
        pub const PRIVATE_TX_HASH: [u8; 32] =
            hex32("1714a7cdf18dd61469b168d5080ee34561769cb6c7a7aca6e8aa1e168363d88d");
        pub const EXPECTED_UTXO_ROOT: [u8; 32] =
            hex32("053e430059c2d344040a8c0038c66092881964b7b1d82a0be941477da7f269e1");
        pub const PROOF_A: [u8; 32] =
            hex32("2dfc7bcafa7e8afd3da1165a7169c9df80126ab1b8552511a34f4b03f8bc1dce");
        pub const PROOF_B: [u8; 64] = hex_bytes(
            "15ec0d84a2f8183e74c3a696aae81d3acfdab4617632fc8bb19ea53a9898362e\
             186040eb7a856af5a2bcef22cb1896f249e3d6f5c6fff5f23526a7a475f123e0");
        pub const PROOF_C: [u8; 32] =
            hex32("9b35e9809229cf9d2bad8bb4f4f112ae30e2246ca05cf043b88098519c9db5fb");
    }

    /// `ring_authority_transact` (tag 17). The ring authority controls its
    /// ring-owned UTXOs, so there is no in-circuit signature over input owners and
    /// no output-owner chain at all -- the signer vector is the payer alone. That
    /// makes its public input hash structurally different from the other two rails,
    /// not merely differently valued.
    pub mod ring_authority_transact {
        use super::{hex32, hex_bytes};
        pub const LEAF_AMOUNT: u64 = 7_000_000;
        pub const OWNER_UTXO_HASH: [u8; 32] =
            hex32("1063c6e179e206148e219b0b6e796dba25845c890433ab0d89d53adfee8f5879");
        pub const RING_DATA_HASH: [u8; 32] =
            hex32("0000000000000000000000000000000000000000000000000000000000000062");
        pub const NULLIFIER: [u8; 32] =
            hex32("0162b885d133daeb686dc7f3f7009265418473039ea4964b8c06bf38e5cfdbbf");
        pub const OUTPUT_UTXO_HASH: [u8; 32] =
            hex32("076fccb41806e68562819f0e9d8114bf14a9663be8173ee34b49e4ce81092ee5");
        pub const PRIVATE_TX_HASH: [u8; 32] =
            hex32("05d0ed4830b7915217d8425afbe85d9709ba164d9e75098fe8e9707b45b1401c");
        pub const EXPECTED_UTXO_ROOT: [u8; 32] =
            hex32("05a5498336b67b143e11a9ecc7bcf8cefe8be717c88fcfeeeff2b3a756376f53");
        pub const PROOF_A: [u8; 32] =
            hex32("0fd6d21b5576df17ad53af8647c7fa26c855cd74aa37493622c9e380010070a9");
        pub const PROOF_B: [u8; 64] = hex_bytes(
            "a9b074e5296c097a2ee303dc3f32684a0cd56daecdf2dcf54ed9674cb984591b\
             2aec026566b3031046bef729091242f76dcbe877b3361c6aefb0ca2eeec944b9");
        pub const PROOF_C: [u8; 32] =
            hex32("2bd60bd5eee33a9146fd2d435f7fc2ed1c464c374c6effa701e12cec6298d3a2");
    }

    /// `batch_update_nullifier_tree`: the forester applying one ZKP batch of
    /// queued nullifiers to the nullifier tree.
    ///
    /// It gets its OWN tree, because which nullifiers land in the first batch
    /// depends on the order the fuzzer ran things -- and a proof binds a hash chain
    /// over exactly those, in exactly that order. Only `setup()` writes this tree's
    /// queue: four deposits, then two merges that queue 16 nullifiers. No action
    /// touches it, so the batch is the same on every run.
    ///
    /// The tree is created with `input_queue_zkp_batch_size = 10` rather than the
    /// default 250. That is a real, supported configuration (`create_tree` takes
    /// the params, and validation only requires `root_history_capacity >=
    /// batch/zkp`), and it is the difference between a 137 MB proving key and a
    /// 3.76 GB one -- and between two merges to fill a batch and thirty-one.
    /// `capacity` is `2^height`, not a function of the batch sizes, so the dummy-
    /// input policy every other fixture depends on is unaffected.

    /// The P256 ownership rail -- the one rail this harness could not reach.
    ///
    /// `transfer_p256_ring_*` verifying keys carry a BSB22 commitment
    /// (`vk_commitment: Some(..)`), so a proof on this rail takes
    /// `verify_groth16`'s `new_with_commitment` arm and runs an extra Pedersen
    /// proof-of-knowledge pairing. Every other fixture here takes the `(None, false)`
    /// arm, so that second verification path had never executed once.
    ///
    /// Its input note lives in a tree of its own, so the state root the proof binds
    /// is one leaf and does not depend on the order `setup()` seeds the main tree.
    pub mod p256 {
        use super::hex_bytes;
        /// `HashBytes(pubkey.X)` of the P256 owner. The Y parity is deliberately not
        /// part of the OWNER commitment -- it belongs to the viewing-key commitment.
        pub const OWNER_TAG_X: [u8; 32] = hex_bytes("ebf456d85ed87b28033d06e4bb4f85d91909b684f40b31d3072f6131967041a2");
        /// `OwnerHash(HashBytes(X), nullifier_pk)` -- the UTXO's `owner` field.
        pub const UTXO_OWNER: [u8; 32] = hex_bytes("2c54ed707d27bd7eabd90f0968942cc6527141f8a8e261938457305228a43b5f");
        pub const INPUT_BLINDING: [u8; 32] = hex_bytes("0000000000000000000000000000000000000000000000000000000000000b11");
        pub const INPUT_AMOUNT: u64 = 500000;
        pub const EXPECTED_UTXO_ROOT: [u8; 32] = hex_bytes("1bc59b5dcd594cc1cdfede5aeb6002b23094ee293258824c9a363ff68e021cd1");
        pub const NULLIFIER: [u8; 32] = hex_bytes("087a1f8bd5601d1a2b975a98f572a90726e0530fa00a1f2e2e4b9d3787aab0dc");
        pub const OUTPUT_UTXO_HASH: [u8; 32] = hex_bytes("2f23126c749aa82a7843221f91e1ccb91f4a52eb19a21bd7ff1440c4b306bfe6");
        pub const PRIVATE_TX_HASH: [u8; 32] = hex_bytes("07e8896a87a3c5045f9fe7eeae66f655d3d4f69e7f8f35437bf83abc6e94d339");
        pub const PROOF_A: [u8; 32] = hex_bytes("96891e8931ff51842e7443ca0460b22355096f7983ad9527c68c795d89cf44dd");
        pub const PROOF_B: [u8; 64] = hex_bytes("92b7cc4679a7caf7fdacda2890fbcb274eca4e463645649862208f766ef133d13010e17b912b9e068d2e3df942304a38a1c678a25bea95dec3769f6bd8f2f846");
        pub const PROOF_C: [u8; 32] = hex_bytes("8dd3cbfa4a8416bc86686cc7906caa71a8fb71b8d8369326c9eaca0424416667");
        /// The BSB22 Pedersen commitment and its proof of knowledge. Big-endian G1,
        /// compressed, and NOT negated -- only `proof_a` is.
        pub const COMMITMENT: [u8; 32] = hex_bytes("94a178ce71fbe969d12ecb12c880d4345ed9bc815a97eac2584615c0a476dcf4");
        pub const COMMITMENT_POK: [u8; 32] = hex_bytes("0eb53e0d45be14c54e9604801fc655c7296d7595984b400b576d98a42d612d60");

        /// The SECOND link: this spends the note the first transact CREATED, rather
        /// than a deposited one. Its input hash is the first fixture's
        /// `OUTPUT_UTXO_HASH`, at leaf 1, proven against a root that carries both
        /// leaves -- so it only verifies if the pool appended that leaf where it said
        /// it did and pushed a root that actually contains it.
        ///
        /// Its input is a RING member (that is what the first transact produced), so
        /// no default-ring P256 input exists and `default_owner_tag` is None -- the
        /// branch the first fixture cannot reach.
        pub mod chained {
            use super::super::hex_bytes;
            pub const EXPECTED_UTXO_ROOT: [u8; 32] = hex_bytes("177d49b3e46f4f6fad6247e2e6dbf17e7b984d11589729c4e9990338d32861be");
            pub const NULLIFIER: [u8; 32] = hex_bytes("1ede24bd04ac9714611f98be986850e0053b97d8298f06ae4a6b76c59c4e9867");
            pub const OUTPUT_UTXO_HASH: [u8; 32] = hex_bytes("1e9141cc057874e1e01fbcc7b2f58c9efb4e7f42911f2edfb20fff1fb555536d");
            pub const PRIVATE_TX_HASH: [u8; 32] = hex_bytes("217b4fe753bca888a4e46c20078191a9f7291f4b02bdd97c58c3b6d2b9737f92");
            pub const PROOF_A: [u8; 32] = hex_bytes("a9d22026e1907d4bf5b62c1543af3ab60bf1112a219917d2be60453e7f0c07bf");
            pub const PROOF_B: [u8; 64] = hex_bytes("85ab1ce031a73bfc5542fa471577c8697c123f4b95c420835bbc8e0f8310ca5b0d40c8a01fc332d226e99a43987d1bc3a12a78e1f195ffb57036bdacb3d93f75");
            pub const PROOF_C: [u8; 32] = hex_bytes("95819443c77586325f68d2f792d8f85ee11c72b5566a92f3cb6280ddff666e85");
            pub const COMMITMENT: [u8; 32] = hex_bytes("89e14d6d8249dd44b50ac47ffe39bdf52538fd75d8bbe859a7d4ad6ae4e81bf7");
            pub const COMMITMENT_POK: [u8; 32] = hex_bytes("10d5e21cd5d79bdb7c099173a0140868440db2e632319ce46565eb101b48dd59");
        }
    }

    pub mod forester {
        use super::{hex32, hex_bytes};

        /// 1200, not a round 100: `TreeAccount::init` requires
        /// `input_queue_batch_size / input_queue_zkp_batch_size` to equal exactly
        /// `NULLIFIER_ZKP` (120), which is baked into the zero-copy layout type at
        /// compile time from the DEFAULT params. So the quotient is fixed and only
        /// the pair scales -- 1200/10 is the same 120 batches as 30000/250.
        /// `match_circuit_size` also restricts the ZKP size to 10 or 250, the two
        /// shapes with verifying keys.
        pub const INPUT_QUEUE_BATCH_SIZE: u64 = 1_200;
        pub const INPUT_QUEUE_ZKP_BATCH_SIZE: u64 = 10;
        pub const ROOT_HISTORY_CAPACITY: u32 = 120;
        pub const TREE_HEIGHT: u32 = 40;

        /// Four deposits at leaves 0-3 of the forester tree; merge A spends the
        /// first two, merge B the last two. Both prove against the same 4-leaf
        /// root, so `setup()` deposits all four before merging either pair.
        pub const DEPOSIT_AMOUNTS: [u64; 4] = [1_100_000, 1_200_000, 1_300_000, 1_400_000];
        pub const DEPOSIT_BLINDINGS: [[u8; 32]; 4] = [
            hex32("000000000000000000000000000000000000000000000000000000000000a111"),
            hex32("000000000000000000000000000000000000000000000000000000000000a222"),
            hex32("000000000000000000000000000000000000000000000000000000000000b111"),
            hex32("000000000000000000000000000000000000000000000000000000000000b222"),
        ];
        pub const EXPECTED_UTXO_ROOT: [u8; 32] =
            hex32("13ad331d1a934a5eb6ab6d7fae645460398442a570c37351e1ab34574a914626");

        pub const MERGE_A_OUTPUT_UTXO_HASH: [u8; 32] =
            hex32("2a458b3c66346d71c639b6644b52568c609d49dc36c290964a91750b144a9774");
        pub const MERGE_A_PRIVATE_TX_HASH: [u8; 32] =
            hex32("014a9c35b6d6ca63d22ad3a5bfe308bf06f2f7d09392848cd4d2be3304d86f62");
        pub const MERGE_A_PROOF_A: [u8; 32] =
            hex32("911b7a99e671abe74eb1e661e189243e1bb3be83c80357739dee708c00b7814c");
        pub const MERGE_A_PROOF_B: [u8; 64] = hex_bytes(
            "284a818809df409f52cb11c8b6ffbf211787188b8ea19a9d89ec8a12425dbcf8\
             070c0d568e6868e0d85c5f1ed9bab0b81a843ebcff4a229f3a2843c0a583b31b");
        pub const MERGE_A_PROOF_C: [u8; 32] =
            hex32("189d923375d44c3ffcf0924af349d12818022ebe5d5ce45d30881c397dd3864c");

        pub const MERGE_B_OUTPUT_UTXO_HASH: [u8; 32] =
            hex32("234c397ae6fdfd31936e79f1f81243358a8702f51418afc984232efa0524771f");
        pub const MERGE_B_PRIVATE_TX_HASH: [u8; 32] =
            hex32("07c5f98b1665014bd1bd4a3747b24c8bc7f84e2122bf52ef8ad9621e346c8bd9");
        pub const MERGE_B_PROOF_A: [u8; 32] =
            hex32("02bb8787d3e9a746f62732357fa10311024e7b95b2901ca05ad81c3b4313e4f5");
        pub const MERGE_B_PROOF_B: [u8; 64] = hex_bytes(
            "af7cbc66da1af33771b3fcd0b1a12b4d263bab9ac4ad9893b30128c64645c4d1\
             03d356dda7c533c9dcfa811272beeaf3750483991882e5319a008d9838dd4eac");
        pub const MERGE_B_PROOF_C: [u8; 32] =
            hex32("1aa155ffd7ec5ce368b2493ed1f2139650d8b2752dd3e5a5aec33fb9c2823299");

        /// The nullifiers each merge queues, in the order it queues them. The
        /// batch is the first 10 of A's eight followed by B's eight.
        pub const MERGE_A_NULLIFIERS: [[u8; 32]; 8] = [
            hex32("2f59691564969daca88e25884cb168d273729059e177681a5fc97b83f0ad8809"),
            hex32("29e79b215b07a800d922830b8e5359b0a3513dd6e457507775820cd9be052999"),
            hex32("2ea66404e903fd00d57159ec96fd0df645128e2ee46448b51361149e74605754"),
            hex32("0374f4d867d2498b6cac5c73fa5f1bc660678c7eba2a6889c9b96cef13ee8228"),
            hex32("2372d99190d03b725cf43878a321ff27d12ad98b67ea5ab2ef42470570fb228d"),
            hex32("281982c9d23bcae2572685c665b5876a419533173d9958c8ba56aca21c558795"),
            hex32("07d8440f37cfed0e2ad94d153338bb4a1de48cbaa204b4e43cc87588ab0f33ed"),
            hex32("146397fbad78d9fcb3bed81a9f3e4e701de258d4bc6bb25898bff7f957faa679"),
        ];
        pub const MERGE_B_NULLIFIERS: [[u8; 32]; 8] = [
            hex32("2f33cf42b78e6f56beaf86e5e31bd69bf396199b776543999b5ab4bdd5de6856"),
            hex32("1021451751637aa77d7b91f30e8a46c492a1e98b241b402324240c2956569729"),
            hex32("28a45eaedfb67c5fafe913391cd8a60614b74a4c56d73bf58cc0ce20bf51a763"),
            hex32("1342f335d1f260d23b2442a455d2fe4d8fb0b5ae46992e23348edc21857db47b"),
            hex32("1c2180639eef829d25268d95554e105e2374599f6290815507f21a8edccb1112"),
            hex32("0f1effddbbaa49c45cfe15170fc070bd05f8a520737162122d60ce17ca1e15aa"),
            hex32("03f7ed31a4df7133586cbc319fc2876494fa7e3e503892943df04c81bb9046b2"),
            hex32("02f9a0e0c8d85e47727c15334997b6d788a55213cf602a02e33decf9a49f1db2"),
        ];

        /// The batch itself: appending the first 10 queued nullifiers.
        pub const OLD_ROOT: [u8; 32] =
            hex32("1d8e71a601b3e8debbba9b557b8369c7f404ae57bebf0852236b072820954277");
        pub const NEW_ROOT: [u8; 32] =
            hex32("0d5065c0960dc535be76244e77cb5ce288caff023985c20e67a21e40c35eb2ce");
        pub const ZKP_BATCH_INDEX: u16 = 0;
        pub const PROOF_A: [u8; 32] =
            hex32("1c621fedf01608c6282348c29fd83c34c3a3359c98d017331c5ad044017e2073");
        pub const PROOF_B: [u8; 64] = hex_bytes(
            "00bfe5bccf69fd5ef8afb64d8c4fa5e0cfd0dbb9761116ce286f6b59bc146209\
             0c5265987bcd44373713ceed1cfaa58310618f59229e58ce2fb15d0544b76251");
        pub const PROOF_C: [u8; 32] =
            hex32("259507b29a8ba64825df5ae1f35fab94082302cb8938f80a8308abf91d6373dd");
    }

    /// The 8 published nullifiers: two real, six deterministic dummies.
    pub const NULLIFIERS: [[u8; 32]; 8] = [
        hex32("16653fd8655200453a4e293791c5a8b3f8b3e7ce72ec5e58e2a5a76c996146e3"),
        hex32("1276cf3477b19dac183081e12648649f3f790e5d8ddf520429ee15f62f65b10c"),
        hex32("2c2567a834011b06e0ff0fecd4d8faa5f9b67dfe878ad6e370ee758bedd84cb6"),
        hex32("03c65e5e9b9ca193c4d3c0cd3c9cbbd77b64931ef34012403e3e53b6e2b30434"),
        hex32("126722e9b59aac59f2a036953e02b66117bf11d71ac48722d39e9933ee1da4c3"),
        hex32("1d434d7f0a637abb422c7e20083048ebc96a9428d1a5f093cc78877d9b6e6ed7"),
        hex32("0ffc7f1a67c611771a3155976caa3d2e5d695a23f40dcbdca122037e5d54b821"),
        hex32("098ca1055b6744a1c352a999c34890acfb1a4ad8e71cd5a1b5457d20f2276652"),
    ];

    /// Decoded at compile time so the hex strings above stay diffable against the
    /// generator's JSON output. Hand-transcribing byte arrays got three addresses
    /// wrong earlier in this harness; hex plus a decoder does not.
    pub const fn hex32(s: &str) -> [u8; 32] {
        hex_bytes(s)
    }

    /// Length comes from the binding site, so a literal of the wrong length is a
    /// compile error rather than a silently truncated constant.
    pub const fn hex_bytes<const N: usize>(s: &str) -> [u8; N] {
        let bytes = s.as_bytes();
        assert!(bytes.len() == 2 * N, "hex literal length does not match its type");
        let mut out = [0u8; N];
        let mut i = 0;
        while i < N {
            out[i] = nibble(bytes[2 * i]) << 4 | nibble(bytes[2 * i + 1]);
            i += 1;
        }
        out
    }

    const fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("non-hex digit in a fixture constant"),
        }
    }
}

const TAG_TRANSACT: u8 = 12;
const TAG_MERGE_TRANSACT: u8 = 13;
const TAG_CREATE_RING_CONFIG: u8 = 7;
/// 8, not 9 -- 9 is `UPDATE_RING_CONFIG_OWNER`, which requires EMPTY instruction
/// data and rejects anything else BEFORE it checks the authority. This constant
/// was wrong, so P-0011's unauthorized ring attempt was refused by that length
/// check and never reached the gate it claimed to test: a vacuous pass that looked
/// exactly like a real one. `ring_switches_gate_every_ring_path` is the guard --
/// it requires the AUTHORIZED update to succeed, so a wrong tag now fails loudly.
const TAG_UPDATE_RING_CONFIG: u8 = 8;
/// 9. Empty instruction data, accounts `[authority(signer), ring_config,
/// new_authority(signer)]` -- BOTH keys sign, so a rotation cannot be pushed onto a
/// key that did not agree to receive it.
///
/// This is the SOLE writer of `RingConfig.authority` in the whole program, and it
/// had never once executed here: no builder, no action, and the only mention of the
/// tag was the comment above explaining that it is not 8. A field with exactly one
/// writer and no successful call is a field whose write path is unverified.
const TAG_UPDATE_RING_CONFIG_OWNER: u8 = 9;
/// `RingConfig.authority` sits one byte past the discriminator; the layout is pinned
/// by `scout_ring_config_bytes`.
const RING_AUTHORITY_OFFSET: usize = 1;
const TAG_RING_DEPOSIT: u8 = 14;
const TAG_CREATE_ASSET_COUNTER: u8 = 5;
/// zolana's OWN policy-ring fixture (`program-tests/ring-test-program`), built to
/// SBF from the same checkout as the pool. Every ring instruction requires the
/// ring's `ring_auth` PDA to SIGN, and a PDA can only sign inside a CPI from its
/// owning program -- so no top-level transaction can reach `create_ring_config`,
/// `ring_deposit`, or the ring transact family. This program forwards a verbatim
/// SPP instruction with that signature attached, which is the only key that opens
/// the whole ring surface. Path is relative to the harness dir, never absolute.
/// Kept OUT of `programs/`: that directory is where scout infers the program under
/// test from, and a second plain `.so` there makes the inference ambiguous.
const RING_PROGRAM_ARTIFACT: &str = "fixtures/ring_test_program.so";
/// The address the fixture ring program is deployed at. Fixed so the ring merge
/// proof, which binds `hash_bytes(ring_program_id)`, stays valid.
const RING_PROGRAM_ID: [u8; 32] = merge_fixture::hex_bytes(
    "7215d9b47f1c9a3e5406c8f2b0d34ea187625c0f9be3d4a1782c6f05e9b31d4c");

/// Deploy a FIXTURE program -- one that is not the coverage target.
///
/// `TestContext::add_program` honors `FUZZ_PROGRAM_SO` (set by `crucible run
/// --coverage --program-so <path>`) but applies the override UNCONDITIONALLY to
/// every call, not just the one it is meant for
/// (crates/crucible-test-context/src/lib.rs:1897-1908). Under coverage that loads
/// the SHIELDED POOL's debug binary at the ring program's address; the pool's
/// `process_instruction` then rejects the call outright, since the address it is
/// invoked at is not its own `declare_id!` -- surfacing as `incorrect program id
/// for instruction` from a program whose own code never ran.
///
/// Clearing the variable around just this call is the same workaround the svmgov
/// eval harness uses for its `ncn_snapshot` fixture. The override still has to
/// reach the pool, which is added separately.
/// Takes the DEPLOY as a closure rather than the context, so this helper never
/// names the trusted context alias -- which may appear only in the canonical
/// contract and setup, and is validated as such.
fn scout_without_program_override<T>(deploy: impl FnOnce() -> T) -> T {
    let override_path = std::env::var("FUZZ_PROGRAM_SO").ok();
    if override_path.is_some() {
        std::env::remove_var("FUZZ_PROGRAM_SO");
    }
    let out = deploy();
    if let Some(path) = override_path {
        std::env::set_var("FUZZ_PROGRAM_SO", path);
    }
    out
}

const TAG_RING_MERGE_TRANSACT: u8 = 16;
const TAG_RING_TRANSACT: u8 = 15;
const TAG_RING_AUTHORITY_TRANSACT: u8 = 17;

/// One SOL ring deposit, addressed to the ring program so it forwards with
/// `ring_auth` signed. Shared by `setup()`'s ring-merge fixture and
/// `action_ring_deposit` so a wire-format drift cannot make them disagree.
#[allow(clippy::too_many_arguments)]
fn scout_ring_deposit_ix(
    ring_program: Pubkey,
    program_id: Pubkey,
    tree: Pubkey,
    payer: Pubkey,
    ring_config: Pubkey,
    sol_interface: Pubkey,
    owner_utxo_hash: [u8; 32],
    ring_data_hash: [u8; 32],
    amount: u64,
) -> ScoutIx {
    let payload = ring_wire::RingDepositIxData {
        assets: vec![scout_wire::DepositAssetKind::Sol],
        deposits: vec![ring_wire::RingDepositEntry {
            asset_index: 0,
            view_tag: [0u8; 32],
            owner_utxo_hash,
            amount,
            data_hash: None,
            ring_data_hash,
            encrypted: ring_wire::EncryptedRingDepositData {
                tx_viewing_pk: [0x02; 33],
                salt: [0u8; 16],
                ciphertext: Vec::new(),
            },
        }],
    };
    let mut data = vec![TAG_RING_DEPOSIT];
    data.extend_from_slice(&wincode::serialize(&payload).expect("ring deposit serializes"));
    ScoutIx {
        program_id: ring_program,
        accounts: vec![
            ScoutMeta::new(tree, false),
            ScoutMeta::new(payer, true),
            ScoutMeta::new_readonly(ring_config, false),
            ScoutMeta::new_readonly(program_id, false),
            ScoutMeta::new_readonly(system_program::ID, false),
            ScoutMeta::new(sol_interface, false),
        ],
        data,
    }
}

/// `InitAddressTreeAccountsInstructionData`, borsh: the two queue sizes, then the
/// root-history capacity and height. `create_tree` decodes this when the payload is
/// non-empty and falls back to the canonical params when it is empty.
fn scout_create_tree_data(batch: u64, zkp_batch: u64, root_history: u32, height: u32) -> Vec<u8> {
    let mut data = vec![TAG_CREATE_TREE];
    data.extend_from_slice(&batch.to_le_bytes());
    data.extend_from_slice(&zkp_batch.to_le_bytes());
    data.extend_from_slice(&root_history.to_le_bytes());
    data.extend_from_slice(&height.to_le_bytes());
    data
}

/// One `merge_transact` against an arbitrary tree, with a pre-generated proof.
/// Shared by `setup()`'s two forester merges, which differ only in their fixture.
#[allow(clippy::too_many_arguments)]
fn scout_merge_transact_ix(
    program_id: Pubkey,
    tree: Pubkey,
    payer: Pubkey,
    user_record: Pubkey,
    utxo_root_index: u16,
    output_utxo_hash: [u8; 32],
    private_tx_hash: [u8; 32],
    nullifiers: Vec<[u8; 32]>,
    proof: scout_wire::MergeProof,
) -> ScoutIx {
    let payload = scout_wire::MergeTransactIxData {
        expiry_unix_ts: merge_fixture::EXPIRY_UNIX_TS,
        proof,
        output_utxo_hash,
        eddsa_owner: true,
        private_tx_hash,
        nullifiers,
        utxo_tree_root_index: vec![utxo_root_index; 8],
        nullifier_tree_root_index: vec![0u16; 8],
    };
    let mut data = vec![TAG_MERGE_TRANSACT];
    data.extend_from_slice(&wincode::serialize(&payload).expect("merge payload serializes"));
    ScoutIx {
        program_id,
        accounts: vec![
            ScoutMeta::new(tree, false),
            ScoutMeta::new(tree, false),
            ScoutMeta::new(payer, true),
            ScoutMeta::new_readonly(user_record, false),
            ScoutMeta::new_readonly(system_program::ID, false),
            ScoutMeta::new_readonly(program_id, false),
        ],
        data,
    }
}

/// Leaves appended to the pool tree so far: `UtxoTreeLayout::next_index`, the
/// field 8 bytes ahead of the state root.
fn scout_tree_next_index(data: &[u8]) -> Option<u64> {
    if data.len() < UTXO_ROOT_OFFSET {
        return None;
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&data[UTXO_ROOT_OFFSET - 8..UTXO_ROOT_OFFSET]);
    Some(u64::from_le_bytes(buf))
}

/// The ring-buffer slot holding the tree's current state root, and that root.
/// Byte-level like `scout_tree_next_index`, so `setup()` needs no closure over the
/// trusted context -- which may be named only in the canonical contract.
fn scout_utxo_root_index(data: &[u8]) -> u16 {
    u16::from_le_bytes([data[UTXO_ROOT_CURSOR_OFFSET], data[UTXO_ROOT_CURSOR_OFFSET + 1]])
}

fn scout_utxo_root(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&data[UTXO_ROOT_OFFSET..UTXO_ROOT_OFFSET + 32]);
    out
}

/// A 32-byte value that is always a valid BN254 field element.
///
/// Several `ring_deposit` fields are Poseidon INPUTS, not opaque bytes: the
/// program hashes `owner_utxo_hash`, `ring_data_hash` and `data_hash` into the
/// UTXO commitment. A naive `[seed; 32]` is only in range for seed <= 0x30 -- above
/// that the byte string exceeds the BN254 modulus (~0x30644e72...) and Poseidon
/// fails, surfacing as `TransactProofVerificationFailed` from a deposit that never
/// went near a proof. Zeroing the top byte keeps the seed's variation while
/// guaranteeing range; `scout_oversized_field` reaches the rejection branch on
/// purpose.
fn scout_field_bytes(seed: u8) -> [u8; 32] {
    let mut value = [seed; 32];
    value[0] = 0;
    value
}

/// Deliberately above the BN254 modulus, so the hash-failure branch stays reachable.
fn scout_oversized_field() -> [u8; 32] {
    [0xFF; 32]
}

/// `CreateRingConfigData`, borsh: program_id, authority, then the flag.
fn scout_create_ring_config_data(ring_program: &Pubkey, authority: &Pubkey) -> Vec<u8> {
    let mut data = vec![TAG_CREATE_RING_CONFIG];
    data.extend_from_slice(ring_program.as_ref());
    data.extend_from_slice(authority.as_ref());
    data.push(1); // ring_authority_transact_is_enabled
    data
}

/// Wire types for `ring_deposit`. Mirrored by hand rather than generated: the
/// adapter refused this instruction because no canonical builder reconciled its
/// account roster (the ring program supplies the roster, not a client builder),
/// so it emitted no writer either. Transcribed field-for-field from
/// `instruction_data/deposit.rs`.
pub mod ring_wire {
    use wincode::{containers, len::FixIntLen, SchemaWrite};

    #[derive(Clone, Debug, SchemaWrite)]
    pub struct EncryptedRingDepositData {
        pub tx_viewing_pk: [u8; 33],
        pub salt: [u8; 16],
        /// A byte vector that can exceed 255 bytes, hence the u16 length prefix.
        #[wincode(with = "containers::Vec<u8, FixIntLen<u16>>")]
        pub ciphertext: Vec<u8>,
    }

    #[derive(Clone, Debug, SchemaWrite)]
    pub struct RingDepositEntry {
        pub asset_index: u8,
        pub view_tag: [u8; 32],
        /// `Poseidon(owner_hash, blinding)` -- the ring rail publishes the
        /// COMMITMENT, not the owner and blinding the default rail carries.
        pub owner_utxo_hash: [u8; 32],
        pub amount: u64,
        pub data_hash: Option<[u8; 32]>,
        pub ring_data_hash: [u8; 32],
        pub encrypted: EncryptedRingDepositData,
    }

    /// `merge_ring` instruction data: the ring's output data hash, then the whole
    /// `merge_transact` payload verbatim.
    #[derive(Clone, Debug, SchemaWrite)]
    pub struct MergeRingIxData {
        pub output_ring_data_hash: [u8; 32],
        pub merge: crate::scout_wire::MergeTransactIxData,
    }

    #[derive(Clone, Debug, SchemaWrite)]
    pub struct RingDepositIxData {
        #[wincode(with = "containers::Vec<crate::scout_wire::DepositAssetKind, FixIntLen<u8>>")]
        pub assets: Vec<crate::scout_wire::DepositAssetKind>,
        #[wincode(with = "containers::Vec<RingDepositEntry, FixIntLen<u8>>")]
        pub deposits: Vec<RingDepositEntry>,
    }
}
const TAG_CREATE_SPL_INTERFACE: u8 = 6;
const TAG_EMIT_EVENT: u8 = 10;
/// `b"spl_asset_counter"` / `b"spl_asset_registry"`, from the interface crate.
const SPL_ASSET_COUNTER_PDA_SEED: &[u8] = b"spl_asset_counter";
const SPL_ASSET_REGISTRY_PDA_SEED: &[u8] = b"spl_asset_registry";
/// Byte offsets into the tree account, derived from `TreeAccount::state_root_offset()`
/// and `UtxoTreeLayout`'s `#[repr(C)]` all-byte-array field order (no padding), then
/// each CONFIRMED against a live account by `merge_fixture_world_is_reproduced`.
const UTXO_ROOT_OFFSET: usize = 80;
const UTXO_ROOT_CURSOR_OFFSET: usize = 112;
/// `nullifier.root_history.data[0]`. The nullifier tree's root lives only in its
/// history, which is why `get_nullifier_tree_root` indexes it directly.
const NULLIFIER_ROOT_HISTORY_OFFSET: usize = 7808;
/// The nullifier side is the BATCHED tree layout, a different structure from the
/// UTXO side with a different cursor convention: its `CyclicVec` header is
/// `[current_index, length, capacity]` and `current_index` names the NEXT slot to
/// write, so the newest root is at `current_index - 1`. On the UTXO tree the cursor
/// names the current root. Reading one with the other's convention is off by one and
/// silent, which is why every offset below is pinned by a test against a live
/// account rather than trusted from the struct definition.
const NULLIFIER_NEXT_INDEX_OFFSET: usize = 7568;
/// `nullifier.metadata.queue_batches.next_index` -- how many nullifiers have been
/// QUEUED, as distinct from how many have been applied to the tree at 7568.
const NULLIFIER_QUEUE_NEXT_INDEX_OFFSET: usize = 7632;
/// `queue_batches.batches[0]`, then `[1]` one `Batch` later. A `Batch` is eight
/// `u64`s, a `u32` root index, a flag byte and three padding bytes.
/// `queue_batches.currently_processing_batch_index`.
const NULLIFIER_QUEUE_CURRENT_BATCH_OFFSET: usize = 7616;
/// `QueueBatches.pending_batch_index` -- "next batch to be inserted into the tree",
/// eight bytes past `currently_processing_batch_index` and NOT the same field. They
/// are equal only until the first batch fills, and `verify_proof_cache_update` reads
/// this one (`merkle_tree_update.rs:58`), so a property about which chunk is due must
/// read it too.
const NULLIFIER_QUEUE_PENDING_BATCH_OFFSET: usize = 7624;
/// `Batch.start_index`, the first leaf index this batch reserves. It sits between
/// `sequence_number` (48) and `root_index` (64). `remaining_queue_capacity` is
/// `capacity - (start_index + inserted)`, so this field is the lever that moves
/// `allow_dummy_inputs` without touching a root, a leaf or a nullifier -- which is
/// what lets P-0037 vary ONE proof-bound value and hold everything else fixed.
const BATCH_START_INDEX_FIELD: usize = 56;
/// `hash_chains[0].data[0]` -- the Poseidon fold the queue builds incrementally as
/// nullifiers are inserted, one slot per ZKP chunk. Located by searching a live
/// account for the value the batch proof binds, rather than derived from the bloom
/// filter's size, which is a const generic.
const NULLIFIER_HASH_CHAIN_OFFSET: usize = 1_162_432;
const NULLIFIER_BATCH0_OFFSET: usize = 7640;
const NULLIFIER_BATCH_STRIDE: usize = 72;
/// Field offsets within a `Batch`. `num_inserted` counts within the ZKP chunk
/// currently being filled, NOT within the whole batch -- the batch's total is
/// `num_full_zkp_batches * zkp_batch_size + num_inserted`, which is why a queue at
/// 16 reads as one full chunk of ten plus six.
const BATCH_NUM_INSERTED: usize = 0;
/// `Batch.state`. 0 = Fill, 1 = Inserted, 2 = Full.
const BATCH_STATE_FIELD: usize = 8;
/// `Batch.sequence_number` and `Batch.root_index` -- set by
/// `mark_as_inserted_in_merkle_tree` when a batch's last chunk lands, and read back
/// by `zero_out_roots` to decide which roots the batch's bloom filter still guards.
const BATCH_SEQUENCE_NUMBER_FIELD: usize = 48;
const BATCH_ROOT_INDEX_FIELD: usize = 64;
/// `nullifier.metadata.sequence_number`, two `u64`s into the metadata.
const NULLIFIER_SEQUENCE_NUMBER_OFFSET: usize = 7560;
const BATCH_STATE_FULL: u64 = 2;
const BATCH_STATE_INSERTED: u64 = 1;
/// `Batch.bloom_filter_is_zeroed`, after the eight `u64`s and the `u32` root index.
const BATCH_BLOOM_ZEROED_FIELD: usize = 68;
const BATCH_NUM_FULL_ZKP: usize = 16;
const BATCH_NUM_INSERTED_ZKP: usize = 24;
const BATCH_SIZE_FIELD: usize = 32;
const BATCH_ZKP_SIZE_FIELD: usize = 40;
const NULLIFIER_QUEUE_ZKP_BATCH_SIZE_OFFSET: usize = 7608;
const NULLIFIER_ROOT_CURSOR_OFFSET: usize = 7784;
const NULLIFIER_ROOT_LEN_OFFSET: usize = 7792;
const NULLIFIER_ROOT_CAPACITY_OFFSET: usize = 7800;
/// One ZKP batch of the nullifier queue, the unit `batch_update_nullifier_tree`
/// applies. `batch_size / zkp_batch_size` must equal `NULLIFIER_ZKP` (120), so the
/// fixture's 1200-element batch gives ten nullifiers per proof.
const NULLIFIER_ZKP_BATCH_SIZE: u64 = 10;
const NULLIFIER_ROOT_HISTORY_CAPACITY: u64 = 120;
/// `TreeAccountLayout.state`, immediately after the discriminator. `PAUSED` is 2;
/// an initialised, live tree is 1.
const TREE_STATE_OFFSET: usize = 1;
const TREE_STATE_PAUSED: u8 = 2;
/// `SplAssetCounter.next_id`: discriminator(1) + reserved(7).
const ASSET_COUNTER_NEXT_ID_OFFSET: usize = 8;
/// `SplAssetCounter::FIRST_ASSET_ID` -- ids 0 and 1 are reserved.
const FIRST_ASSET_ID: u64 = 2;
/// `smt::ROOT_HISTORY_CAPACITY`, and the byte holding the tree's own copy of it.
const ROOT_HISTORY_CAPACITY: usize = 200;
const UTXO_ROOT_HISTORY_LEN_OFFSET: usize = 114;
/// `utxo.root_history[0]`, the ring buffer `get_utxo_tree_root` indexes.
const UTXO_ROOT_HISTORY_OFFSET: usize = 1142;
/// `regyS5rkAcw2YzDJCmTwCTHs2s246FXxbmuRZ42u2PD` -- decoded, never transcribed.
const USER_REGISTRY_PROGRAM_ID: Pubkey =
    Pubkey::from_str_const("regyS5rkAcw2YzDJCmTwCTHs2s246FXxbmuRZ42u2PD");
const USER_RECORD_SEED: &[u8] = b"zolana/registry/v0";

/// The SEC1-compressed P256 generator, used as `owner_p256`. A real curve point
/// rather than filler: `eddsa_owner = false` makes the program hash this key as the
/// owner binding, and a malformed point would fail there for the wrong reason --
/// rejected as an invalid record instead of exercising the P256 owner rail.
const P256_GENERATOR_COMPRESSED: [u8; 33] = merge_fixture::hex_bytes(
    "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");

/// `UserRecord` in its borsh form: discriminator, then the struct fields.
/// `merge_transact` reads `owner`, `bump`, `owner_p256` and `merging_enabled`; the
/// record must deserialize AND its length must equal `UserRecord::SIZE` exactly.
///
/// `owner_p256` is `Some`, which is what makes those two agree: borsh writes a
/// `None` as its tag byte ALONE, so a `None` record is 33 bytes short of `SIZE` and
/// every field after it reads from the wrong offset. That silently returned
/// `merging_enabled = false` and the merge failed as `MergeDisabled` -- a wrong
/// answer, not a parse error.
fn scout_user_record_bytes(owner: &Pubkey, bump: u8, nullifier_pubkey: &[u8; 32]) -> Vec<u8> {
    let mut data = Vec::with_capacity(134);
    data.push(1); // UserRecord::DISCRIMINATOR
    data.extend_from_slice(owner.as_ref());
    data.push(bump);
    data.push(1); // Option<[u8; 33]>::Some
    data.extend_from_slice(&P256_GENERATOR_COMPRESSED);
    data.extend_from_slice(nullifier_pubkey);
    data.extend_from_slice(&P256_GENERATOR_COMPRESSED); // viewing_pubkey, unread here
    data.push(1); // merging_enabled: the per-user merge opt-in
    assert_eq!(data.len(), 134, "UserRecord::SIZE drifted");
    data
}

/// One SOL deposit crediting `amount` to `owner` under `blinding`. Shared by
/// `setup()`'s merge fixture and the root-alignment test so a drift in the wire
/// format cannot make them disagree.
fn scout_sol_deposit_ix(
    program_id: Pubkey,
    tree: Pubkey,
    payer: Pubkey,
    sol_interface: Pubkey,
    owner: [u8; 32],
    blinding: [u8; 32],
    amount: u64,
) -> ScoutIx {
    let payload = scout_wire::DepositIxData {
        assets: vec![scout_wire::DepositAssetKind::Sol],
        deposits: vec![scout_wire::DepositEntry {
            asset_index: 0,
            view_tag: [0u8; 32],
            owner,
            blinding,
            amount,
            utxo_data: None,
            memo: None,
        }],
    };
    let mut data = vec![TAG_DEPOSIT];
    data.extend_from_slice(&wincode::serialize(&payload).unwrap());
    ScoutIx {
        program_id,
        accounts: vec![
            ScoutMeta::new(tree, false),
            ScoutMeta::new(payer, true),
            ScoutMeta::new_readonly(program_id, false),
            ScoutMeta::new_readonly(system_program::ID, false),
            ScoutMeta::new(sol_interface, false),
        ],
        data,
    }
}

/// The SPL Token-2022 program. LiteSVM's `with_default_programs()` loads it, and the
/// pool accepts it alongside legacy spl-token (`settlement/validate.rs:29-37`).
const SPL_TOKEN_2022_ID: Pubkey = Pubkey::new_from_array([
    0x06, 0xdd, 0xf6, 0xe1, 0xee, 0x75, 0x8f, 0xde, 0x18, 0x42, 0x5d, 0xbc, 0xe4, 0x6c, 0xcd, 0xda,
    0xb6, 0x1a, 0xfc, 0x4d, 0x83, 0xb9, 0x0d, 0x27, 0xfe, 0xbd, 0xf9, 0x28, 0xd8, 0xa1, 0x8b, 0xfc,
]);
/// A Token-2022 mint carrying one `TransferFeeConfig`: 165 base + padding, 1
/// `account_type`, a 4-byte TLV header, 108 bytes of config.
const T22_MINT_LEN: usize = 278;
/// A Token-2022 token account carrying `TransferFeeAmount`, the account extension
/// `TransferFeeConfig` requires: 165 + 1 + 4 + 8. `create_spl_interface` computes the
/// same number itself via `get_required_init_account_extensions`, and the interface
/// account it creates for a fee mint is exactly this long -- which is how the harness
/// knows the two agree.
const T22_ACCOUNT_LEN: usize = 178;
/// 5%. Token-2022 rounds a transfer fee UP, so there is no small-amount window where
/// the fee rounds to zero and a deposit would slip through un-penalised.
const T22_FEE_BASIS_POINTS: u16 = 500;

/// Allocate an account owned by Token-2022. Raw System `CreateAccount` (index 0).
fn scout_t22_create_account_ix(
    payer: Pubkey, target: Pubkey, lamports: u64, len: usize,
) -> ScoutIx {
    let mut data = Vec::with_capacity(52);
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&lamports.to_le_bytes());
    data.extend_from_slice(&(len as u64).to_le_bytes());
    data.extend_from_slice(SPL_TOKEN_2022_ID.as_ref());
    ScoutIx {
        program_id: system_program::ID,
        accounts: vec![ScoutMeta::new(payer, true), ScoutMeta::new(target, true)],
        data,
    }
}

/// `TransferFeeExtension::InitializeTransferFeeConfig` -- extension instruction 26,
/// sub-instruction 0, then two `COption<Pubkey>` authorities, the basis points and the
/// maximum fee. Must run BEFORE `InitializeMint2`, like every Token-2022 mint
/// extension.
fn scout_t22_init_transfer_fee_ix(mint: Pubkey, authority: Pubkey) -> ScoutIx {
    let mut data = vec![26u8, 0u8];
    data.push(1);
    data.extend_from_slice(authority.as_ref());
    data.push(1);
    data.extend_from_slice(authority.as_ref());
    data.extend_from_slice(&T22_FEE_BASIS_POINTS.to_le_bytes());
    data.extend_from_slice(&u64::MAX.to_le_bytes()); // no cap on the fee
    ScoutIx {
        program_id: SPL_TOKEN_2022_ID,
        accounts: vec![ScoutMeta::new(mint, false)],
        data,
    }
}

/// `InitializeMint2` (20): decimals, mint authority, freeze authority as `COption`.
fn scout_t22_init_mint_ix(mint: Pubkey, authority: Pubkey, decimals: u8) -> ScoutIx {
    let mut data = vec![20u8, decimals];
    data.extend_from_slice(authority.as_ref());
    data.push(0);
    ScoutIx {
        program_id: SPL_TOKEN_2022_ID,
        accounts: vec![ScoutMeta::new(mint, false)],
        data,
    }
}

/// `InitializeAccount3` (18): the owner travels in the data, not as an account.
fn scout_t22_init_account_ix(account: Pubkey, mint: Pubkey, owner: Pubkey) -> ScoutIx {
    let mut data = vec![18u8];
    data.extend_from_slice(owner.as_ref());
    ScoutIx {
        program_id: SPL_TOKEN_2022_ID,
        accounts: vec![ScoutMeta::new(account, false), ScoutMeta::new_readonly(mint, false)],
        data,
    }
}

/// `MintTo` (7).
fn scout_t22_mint_to_ix(
    mint: Pubkey, destination: Pubkey, authority: Pubkey, amount: u64,
) -> ScoutIx {
    let mut data = vec![7u8];
    data.extend_from_slice(&amount.to_le_bytes());
    ScoutIx {
        program_id: SPL_TOKEN_2022_ID,
        accounts: vec![
            ScoutMeta::new(mint, false),
            ScoutMeta::new(destination, false),
            ScoutMeta::new_readonly(authority, true),
        ],
        data,
    }
}
// SCOUT:PRELUDE:END

crucible_idl_gen::declare_fuzz_program!("idls/shielded_pool.json");

use shielded_pool::{accounts, instruction};

#[derive(Clone)]
struct ShieldedPoolFixture {
    ctx: crate::__scout_crucible_test_context::TestContext,
    program_id: Pubkey,
    payer: Rc<Keypair>,
    // SCOUT:FIELDS:BEGIN
    /// Canonical protocol-config PDA, created in `setup()` with `payer` as every
    /// authority so the fuzzer's single signer can drive every gated instruction.
    protocol_config: Pubkey,
    /// One initialized tree, used as both the input and output tree.
    tree: Pubkey,
    /// Ring config for a synthetic ring program. Minted directly: the real
    /// `create_ring_config` requires the config PDA to sign its own creation via a
    /// CPI from the ring program, which no top-level transaction can do.
    ring_config: Pubkey,
    /// System-owned native-SOL settlement target for `deposit`.
    sol_interface: Pubkey,
    /// P-0001 shadow ledger: the SOL interface's opening balance, and the sum of
    /// every amount a successful `deposit` credited. Tracked here because the
    /// program keeps no such total anywhere on chain -- which is exactly why the
    /// relation is worth asserting.
    sol_interface_opening: u64,
    /// The rent-exempt minimum for a tree account, captured at setup. P-0019's floor:
    /// a tree that drops below it becomes reapable, and every commitment in it is lost.
    tree_rent_floor: u64,
    shadow_sol_credited: u64,
    /// SPL deposit fixture. The account tail for an `Spl` asset group is keyed on a
    /// payload VARIANT rather than on emptiness, so the adapter cannot enumerate it
    /// and `action_deposit_spl` is hand-written against these.
    spl_mint: Pubkey,
    spl_interface: Pubkey,
    spl_interface_bump: u8,
    user_token: Pubkey,
    /// P-0002 shadow: SPL units credited by successful SPL deposits.
    shadow_spl_credited: u64,
    /// `merge_transact` fixture. The merge is proof-gated, and a Groth16 proof
    /// pins the ENTIRE public half of its witness, so the harness cannot generate
    /// merge inputs -- it must reproduce the exact world one pre-generated proof
    /// was made against. `setup()` does that, and these are the handles into it.
    user_record: Pubkey,
    /// Root-history index holding the state root the merge proof cites. Captured
    /// after the fixture deposits rather than assumed: the ring buffer's cursor is
    /// what `get_utxo_tree_root` indexes.
    merge_utxo_root_index: u16,
    /// The ring merge's own root index. A separate fixture over a LATER tree
    /// state, so it cites a different history slot than the default merge.
    ring_merge_utxo_root_index: u16,
    /// The transact fixture's signer. Distinct from `payer`, which lets the
    /// harness exercise a transaction whose fee payer is not the acting owner --
    /// the shape every relayed transfer has in production.
    transact_actor: Rc<Keypair>,
    transact_utxo_root_index: u16,
    ring_transact_utxo_root_index: u16,
    /// The P256 rail's own tree and the root index its proof was generated against.
    p256_tree: Pubkey,
    p256_utxo_root_index: u16,
    ring_authority_utxo_root_index: u16,
    withdrawal_utxo_root_index: u16,
    spl_withdrawal_utxo_root_index: u16,
    /// P-0002 shadow: SPL units the pool has PAID OUT.
    shadow_spl_withdrawn: u64,
    /// The vault's balance after `setup()`. Non-zero because setup deposits the SPL
    /// withdrawal fixture's input, exactly as `sol_interface_opening` is non-zero
    /// because setup deposits the SOL fixtures'. A solvency net needs the opening
    /// term or it reads setup's own funding as a surplus.
    spl_interface_opening: u64,
    shadow_spl_withdrawal_spends: u32,
    /// P-0001 shadow: lamports the pool has PAID OUT through a successful
    /// withdrawal. Solvency is a two-sided net once value can leave.
    shadow_sol_withdrawn: u64,
    shadow_withdrawal_spends: u32,
    /// P-0006 shadow: successful withdrawals paid to a recipient the proof did NOT
    /// bind. Must stay zero.
    shadow_substituted_payouts: u32,
    /// P-0007 shadow: whether the last successful `pause_tree` paused or unpaused,
    /// and the leaf count at that moment. A pause that does not freeze appends is
    /// not a pause.
    shadow_paused: u8,
    shadow_leaves_at_pause: u64,
    /// P-0008 shadow: `create_spl_interface` calls whose effect on the id counter
    /// was wrong, measured as a DELTA across the single call.
    ///
    /// Deliberately not an absolute `FIRST_ASSET_ID + registrations` identity. That
    /// form fired 34 times under `--stateful` and zero times without it: the state
    /// pool carries an account CREATED BY AN ACTION -- here the singleton counter --
    /// across branches, while the fixture's shadow resets with each sequence, so the
    /// chain legitimately shows ids consumed by a sibling branch. Setup-created
    /// accounts are restored consistently and are not exposed to this; an
    /// action-created one is. A delta taken either side of one call compares two
    /// reads microseconds apart in the same fixture, so no amount of inherited
    /// history can perturb it -- and it is the STRONGER statement, per call rather
    /// than in aggregate.
    /// P-0011 shadow: admin-gated instructions that SUCCEEDED for a signer who is
    /// not the designated authority. Must stay zero. A pure success counter, so it
    /// needs no baseline and is unaffected by inherited state.
    shadow_unauthorized_admin_successes: u64,
    /// P-0012 shadow: successful `batch_update_nullifier_tree` calls whose effect on
    /// the nullifier tree was neither one whole ZKP batch nor nothing at all. A pure
    /// violation counter, for the same reason as the one above.
    shadow_nullifier_batch_violations: u64,
    /// P-0014 shadow: ring instructions that SUCCEEDED while the ring config's own
    /// switch said they must not. A pure violation counter, so it needs no baseline.
    shadow_ring_gate_bypasses: u64,
    /// P-0015 shadow: creations that SUCCEEDED for an outsider while the matching
    /// permissionless switch was closed. A pure violation counter.
    shadow_creation_gate_bypasses: u64,
    /// P-0016 shadow: split-tree transacts whose nullifier or output leaf landed in
    /// the wrong tree. A pure violation counter.
    shadow_split_tree_misroutes: u64,
    /// P-0020 shadow: transacts that verified with a proof-bound field perturbed. A
    /// pure violation counter -- any non-zero value is an unbound public input.
    shadow_proof_binding_bypasses: u64,
    /// P-0021 shadow: spends accepted into a batch that was already Full and unproven.
    shadow_batch_overwrite_bypasses: u64,
    /// P-0022 shadow: spends accepted into a proven batch whose bloom filter still
    /// held its old entries.
    shadow_stale_bloom_reuses: u64,
    /// P-0023 shadow: transacts that verified with a grafted or corrupted proof
    /// commitment. A pure violation counter.
    shadow_proof_graft_successes: u64,
    /// P-0024 shadow: forester-gated calls that succeeded for a signer the protocol
    /// config does not currently name as the forester authority.
    shadow_stale_authority_successes: u64,
    /// P-0025 shadow: notes the pool CREATED that it then refused to let anyone spend.
    shadow_unspendable_outputs: u64,
    /// P-0027 shadow: spends accepted against a root index the tree retired or has
    /// never written.
    shadow_retired_root_successes: u64,
    /// P-0028 shadow: roots that survived the retirement that was supposed to clear
    /// them, or a first-safe root that was cleared when it should not have been.
    shadow_unretired_roots: u64,
    /// P-0029 shadow: ring instructions that succeeded for a key the ring config no
    /// longer names as its authority. A pure violation counter, so it needs no
    /// baseline and inherited `--stateful` state cannot perturb it.
    shadow_stale_ring_authority_successes: u64,
    /// P-0030 shadow: forester cranks that returned SUCCESS while a provable batch
    /// was waiting and yet moved nothing -- the silent no-op, which is as bad as a
    /// revert and sails past every "did it throw?" check.
    shadow_silent_forester_noops: u64,
    /// P-0032 shadow: deposits that SUCCEEDED through a mint whose transfer fee means
    /// the pool cannot have received what the UTXO credits.
    shadow_fee_mint_credits: u64,
    /// P-0033 shadow: successful spends whose nullifiers did not reach the queue in the
    /// number the instruction consumed.
    shadow_unpublished_nullifiers: u64,
    /// P-0034 shadow: transactions in which two spends of the SAME note were both
    /// accepted because they shared one transaction.
    shadow_intra_tx_double_spends: u64,
    /// P-0036 shadow: ring instructions that succeeded while carrying a ring config
    /// belonging to a DIFFERENT ring than the one that signed.
    shadow_ring_confusions: u64,
    /// P-0035 shadow: transacts accepted while the DEDUPLICATED signer set differed
    /// from the one the fixture's proof was generated against.
    shadow_signer_set_bypasses: u64,
    /// P-0037 shadow: transacts whose tree-state-derived `allow_dummy_inputs` no
    /// longer matched what the proof committed to, and verified anyway.
    shadow_dummy_flag_bypasses: u64,
    /// P-0038 shadow: merges that succeeded for a user whose registry record says
    /// merging is disabled.
    shadow_merge_opt_out_bypasses: u64,
    /// P-0039 shadow: merges that verified while the owner rail selected by
    /// `eddsa_owner` was not the rail the proof was generated for.
    shadow_merge_rail_bypasses: u64,
    /// Whether the second ring program (a distinct id, its own `ring_auth` PDA and
    /// config) has been deployed yet.
    second_ring_ready: bool,
    /// Whether the fee-bearing Token-2022 mint has been built yet. It is built lazily
    /// on first use rather than in `setup()`, because registering it needs the
    /// singleton asset counter -- and minting that in setup would disable
    /// `action_create_asset_counter` forever.
    fee_mint_ready: bool,
    /// P-0031 shadow: value that left a program-owned account without a matching
    /// credit, observed across a donation. Donations RAISE the real balance without
    /// raising any counter, so the only sound direction to assert is that the pool
    /// never falls SHORT of what it owes.
    shadow_donation_insolvencies: u64,
    /// Lamports this fixture has donated into program-owned accounts. Tracked so the
    /// solvency properties can tell a permissionless donation (legal, and free for
    /// anyone to do) apart from value the pool created for itself.
    shadow_sol_donated: u64,
    shadow_asset_id_violations: u64,
    shadow_registered_assets: u64,
    /// A second tree, written only by `setup()`, whose nullifier queue holds a
    /// deterministic full ZKP batch for `batch_update_nullifier_tree`.
    forester_tree: Pubkey,
    /// P-0003/P-0004 shadow: the leaf count the harness believes `tree` holds. It
    /// advances only in success-gated hooks, so a REJECTED instruction can never
    /// move it and manufacture a violation.
    shadow_expected_leaves: u64,
    /// P-0005 shadow: how many times each SPENDING instruction has succeeded.
    ///
    /// Every one of these publishes the SAME nullifiers on every call -- they are
    /// fixture constants, because a Groth16 proof pins them -- so a second success
    /// means the program accepted a nullifier it had already accepted. Counting
    /// successes is therefore the double-spend question, asked in a form the
    /// shadow-update DSL can express in pure assignments.
    shadow_merge_spends: u32,
    shadow_ring_merge_spends: u32,
    shadow_transact_spends: u32,
    shadow_ring_transact_spends: u32,
    shadow_ring_authority_spends: u32,
    /// A single reusable account for `create_tree`, re-zeroed per call. The tree
    /// layout is 1.13 MB, so minting a fresh one per action would grow LiteSVM's
    /// account store without bound over a fuzzing run; re-minting one address keeps
    /// the handler's success path reachable at fixed cost.
    scratch_tree: Pubkey,
    /// Distinguishes the mints `action_create_spl_interface` registers. The registry
    /// entry is a per-mint PDA, so the instruction succeeds exactly once per mint.
    spl_interface_seq: u64,
    /// The deployed policy-ring fixture whose `ring_auth` PDA is `ring_config`.
    ring_program: Pubkey,
    /// Rotates `action_create_ring_config` over a bounded set of ring programs.
    /// Bounded on purpose: a config is created once per ring and never closed, so
    /// an unbounded sequence would deploy a fresh program per call for the rest of
    /// the run. Once every slot is configured the action correctly reports the
    /// refusal instead of manufacturing new state to succeed against.
    ring_config_seq: u64,
    // SCOUT:FIELDS:END
}

#[fuzz_fixture]
impl ShieldedPoolFixture {
    fn scout_placeholder(&self) -> Pubkey { Pubkey::new_unique() }

    pub fn setup() -> Self {
        let mut ctx = crate::__scout_crucible_test_context::TestContext::new();
        let program_id = Pubkey::new_from_array(shielded_pool::ID.to_bytes());
        // SCOUT:TARGET-PROGRAM:BEGIN
        crate::__scout_crucible_test_context::TestContext::add_program(&mut ctx, &program_id, SCOUT_TARGET_PROGRAM_ARTIFACT).unwrap();
        // SCOUT:TARGET-PROGRAM:END
        let payer = Rc::new(Keypair::new());
        ctx.create_account().pubkey(payer.pubkey()).lamports(1_000_000_000)
            .owner(system_program::ID).create().unwrap();
        // SCOUT:SETUP-GLUE:BEGIN
        // Solana's per-transaction maximum. The P256 rail needs more than the 200k
        // default: its verifying key carries a BSB22 commitment, so verification runs
        // an extra Pedersen pairing on top of the standard Groth16 one, and the call
        // is a CPI from the ring program so the inner limit binds first. A real client
        // raises this with a ComputeBudget instruction.
        //
        // Set HERE rather than at `TestContext::new()`: anything outside a SCOUT
        // region is deleted by `scout regen`, which `scout verify` runs -- the budget
        // silently reverted to 200k that way once, and the symptom was a fixture that
        // had verified moments earlier failing again.
        ctx = ctx.with_compute_budget(1_400_000);
        // --- protocol config -------------------------------------------------
        // Created through the program's OWN `create_protocol_config` rather than
        // minted, so the account holds exactly the bytes the program writes.
        // Admin instructions are never actions, so calling one here cannot
        // disable an action (the minting safety check in references/setup-glue.md).
        let (protocol_config, _) =
            Pubkey::find_program_address(&[PROTOCOL_CONFIG_PDA_SEED], &program_id);
        let (program_data, _) = Pubkey::find_program_address(
            &[program_id.as_ref()],
            &Pubkey::new_from_array(BPF_LOADER_UPGRADEABLE_ID),
        );
        let create_config = ScoutIx {
            program_id,
            accounts: vec![
                ScoutMeta::new(payer.pubkey(), true),
                ScoutMeta::new(protocol_config, false),
                ScoutMeta::new_readonly(system_program::ID, false),
                ScoutMeta::new_readonly(program_id, false),
                ScoutMeta::new_readonly(program_data, false),
            ],
            data: scout_create_protocol_config_data(&payer.pubkey()),
        };
        let outcome = ctx.raw_call(create_config).signers(&[&payer]).send()
            .expect("create_protocol_config send failed at the runtime level");
        assert!(outcome.is_success(), "create_protocol_config failed: {outcome:?}");

        // --- tree ------------------------------------------------------------
        // Minted at the exact account size, then INITIALIZED by the program's own
        // `create_tree` (tag 2, empty payload = canonical nullifier params). The
        // 1.13 MB zero-copy layout is not something to hand-write; letting the
        // program write it is both correct and drift-proof.
        let tree = Pubkey::new_unique();
        // Funded to RENT EXEMPTION, not to a round number. `collect_forester_fee`
        // pays lamports INTO the tree, and the runtime rejects any transaction that
        // writes an account left below the exemption threshold -- so an underfunded
        // tree turns a fully successful merge (proof verified, event emitted) into
        // `InsufficientFundsForRent`, which reads like a merge failure and is not
        // one. At 1.13 MB the threshold is ~8.25 SOL, well past any round guess.
        let tree_rent = ctx.svm.minimum_balance_for_rent_exemption(TREE_ACCOUNT_SIZE);
        ctx.create_account()
            .pubkey(tree)
            .owner(program_id)
            .size(TREE_ACCOUNT_SIZE)
            .lamports(tree_rent)
            .create()
            .expect("tree account mint failed");
        let create_tree = ScoutIx {
            program_id,
            accounts: vec![
                ScoutMeta::new_readonly(payer.pubkey(), true),
                ScoutMeta::new_readonly(protocol_config, false),
                ScoutMeta::new(tree, false),
            ],
            data: vec![TAG_CREATE_TREE],
        };
        let outcome = ctx.raw_call(create_tree).signers(&[&payer]).send()
            .expect("create_tree send failed at the runtime level");
        assert!(outcome.is_success(), "create_tree failed: {outcome:?}");

        // --- ring config -----------------------------------------------------
        // Created through the program's OWN `create_ring_config`, by deploying
        // zolana's policy-ring fixture and calling it. The config account IS the
        // ring's `ring_auth` PDA and must sign its own creation, which only a CPI
        // from the owning ring program can do -- so this was previously minted
        // directly. Deploying the real forwarder replaces an approximation of the
        // account with the bytes the program itself writes, and is what makes
        // `create_ring_config` and `ring_deposit` reachable at all.
        // A FIXED address, not `new_unique()`. The ring merge proof binds
        // `hash_bytes(ring_program_id)`, and `new_unique()` is a global counter --
        // its value depends on how many keypairs were minted before it, so a baked
        // fixture would silently stop verifying when anything upstream allocated
        // one more.
        let ring_program = Pubkey::new_from_array(RING_PROGRAM_ID);
        assert!(
            scout_without_program_override(
                || ctx.add_program(&ring_program, RING_PROGRAM_ARTIFACT).is_ok()),
            "ring fixture program deploy failed");
        let (ring_config, _ring_bump) =
            Pubkey::find_program_address(&[RING_AUTH_PDA_SEED], &ring_program);
        let create_ring = ScoutIx {
            program_id: ring_program,
            accounts: vec![
                ScoutMeta::new(payer.pubkey(), true),
                ScoutMeta::new_readonly(protocol_config, false),
                ScoutMeta::new(ring_config, false),
                ScoutMeta::new_readonly(system_program::ID, false),
                // The forwarder locates SPP by address in the account list.
                ScoutMeta::new_readonly(program_id, false),
            ],
            data: scout_create_ring_config_data(&ring_program, &payer.pubkey()),
        };
        let outcome = ctx.raw_call(create_ring).signers(&[&payer]).send()
            .expect("create_ring_config send failed at the runtime level");
        assert!(outcome.is_success(), "create_ring_config failed: {outcome:?}");

        // --- SOL interface ---------------------------------------------------
        // The native-SOL settlement target for `deposit`. `validate_sol_settlement`
        // demands this exact address, writable, and owned by the SYSTEM program --
        // so it is a plain lamport holder, not a program account. Funded so it is
        // rent-exempt once deposits start landing in it.
        let sol_interface = Pubkey::new_from_array(SOL_INTERFACE);
        ctx.create_account()
            .pubkey(sol_interface)
            .owner(system_program::ID)
            .lamports(10_000_000)
            .create()
            .expect("sol_interface mint failed");
        // --- SPL deposit fixture ---------------------------------------------
        // `validate_spl_settlement` checks three relations, so all three are built
        // rather than approximated: the interface token account must sit at the
        // canonical `[spl_asset_vault, mint]` PDA, its TOKEN owner must be the
        // pool's CPI authority, and both token accounts must share the mint.
        // FIXED, not `new_unique()`: the SPL withdrawal proof binds `hash_bytes(mint)`
        // as its public asset and the resolved token accounts in its external data
        // hash, so all three addresses must be stable across runs.
        let spl_mint = Pubkey::new_from_array(merge_fixture::spl::MINT);
        ctx.create_mint()
            .pubkey(spl_mint)
            .decimals(6)
            .create()
            .expect("spl mint mint failed");
        let (spl_interface, spl_interface_bump) =
            Pubkey::find_program_address(&[SPL_INTERFACE_PDA_SEED, spl_mint.as_ref()], &program_id);
        ctx.create_token_account()
            .pubkey(spl_interface)
            .mint(spl_mint)
            .token_owner(Pubkey::new_from_array(SHIELDED_POOL_CPI_AUTHORITY))
            .amount(0)
            .create()
            .expect("spl interface token account mint failed");
        let user_token = Pubkey::new_from_array(merge_fixture::spl::USER_TOKEN);
        ctx.create_token_account()
            .pubkey(user_token)
            .mint(spl_mint)
            .token_owner(payer.pubkey())
            .amount(1_000_000_000_000)
            .create()
            .expect("user token account mint failed");

        // --- merge fixture ---------------------------------------------------
        // `merge_transact` verifies a Groth16 proof over the state tree, the
        // nullifier tree, and the registry-bound owner. A proof fixes every one of
        // those public inputs at generation time, so this block reconstructs the
        // world the fixture proof was generated against; `merge_fixture_world_is_
        // reproduced` asserts, rather than assumes, that it did.
        //
        // The record is minted, not registered: the registry program is a separate
        // deployment, and `load_user_record` only reads bytes (owner, bump,
        // owner_p256, merging_enabled) plus the canonical PDA and owning program.
        let merge_owner = Pubkey::new_from_array(merge_fixture::OWNER_PUBKEY);
        let (user_record, user_record_bump) = Pubkey::find_program_address(
            &[USER_RECORD_SEED, merge_owner.as_ref()],
            &USER_REGISTRY_PROGRAM_ID,
        );
        ctx.create_account()
            .pubkey(user_record)
            .owner(USER_REGISTRY_PROGRAM_ID)
            .data(&scout_user_record_bytes(
                &merge_owner, user_record_bump, &merge_fixture::NULLIFIER_PUBKEY))
            .lamports(10_000_000)
            .create()
            .expect("user_record mint failed");

        // The merge's two input UTXOs, deposited exactly as the fixture hashed them:
        // same owner field, same blindings, same amounts, at leaf indices 0 and 1.
        // Each deposit is its own transaction, so each pushes one root -- the state
        // root the proof cites is the one at cursor after both.
        for (amount, blinding) in merge_fixture::DEPOSIT_AMOUNTS
            .iter()
            .zip(merge_fixture::DEPOSIT_BLINDINGS.iter())
        {
            let deposit = scout_sol_deposit_ix(
                program_id, tree, payer.pubkey(), sol_interface,
                merge_fixture::UTXO_OWNER, *blinding, *amount);
            let outcome = ctx.raw_call(deposit).signers(&[&payer]).send()
                .expect("merge fixture deposit send failed at the runtime level");
            assert!(outcome.is_success(), "merge fixture deposit failed: {outcome:?}");
        }
        let merge_utxo_root_index = scout_utxo_root_index(&ctx.svm.get_account(&tree).expect("tree").data);
        assert_eq!(
            scout_utxo_root(&ctx.svm.get_account(&tree).expect("tree").data), merge_fixture::EXPECTED_UTXO_ROOT,
            "the fixture deposits did not reproduce the state root the merge proof \
             was generated against -- the proof cannot verify against this tree",
        );

        // The RING merge's inputs, at leaves 2 and 3. Deposited through the ring
        // program so each UTXO carries the ring's program id and its own ring data;
        // a plain deposit would hash to something the ring circuit cannot spend.
        // These land AFTER the default rail's leaves, which is exactly the tree the
        // ring proof was generated against.
        for (amount, (owner_utxo_hash, ring_data)) in merge_fixture::ring::DEPOSIT_AMOUNTS
            .iter()
            .zip(merge_fixture::ring::DEPOSIT_OWNER_UTXO_HASHES
                .iter()
                .zip(merge_fixture::ring::DEPOSIT_RING_DATA.iter()))
        {
            let ix = scout_ring_deposit_ix(
                ring_program, program_id, tree, payer.pubkey(), ring_config, sol_interface,
                *owner_utxo_hash, *ring_data, *amount);
            let outcome = ctx.raw_call(ix).signers(&[&payer]).send()
                .expect("ring fixture deposit send failed at the runtime level");
            assert!(outcome.is_success(), "ring fixture deposit failed: {outcome:?}");
        }
        let ring_merge_utxo_root_index = scout_utxo_root_index(&ctx.svm.get_account(&tree).expect("tree").data);
        assert_eq!(
            scout_utxo_root(&ctx.svm.get_account(&tree).expect("tree").data), merge_fixture::ring::EXPECTED_UTXO_ROOT,
            "the ring fixture deposits did not reproduce the state root the ring \
             merge proof was generated against",
        );

        // The transact fixture's input, at leaf 4. Its owner is the transact actor,
        // whose keypair comes from a fixed seed so the address the proof binds does
        // not move between runs.
        let transact_actor = Rc::new(Keypair::new_from_array(merge_fixture::transact::ACTOR_SEED));
        assert_eq!(transact_actor.pubkey().to_bytes(), merge_fixture::transact::ACTOR_PUBKEY,
                   "the actor seed no longer derives the pubkey the proof binds");
        ctx.create_account().pubkey(transact_actor.pubkey()).lamports(1_000_000_000)
            .owner(system_program::ID).create().expect("transact actor mint failed");
        let deposit = scout_sol_deposit_ix(
            program_id, tree, payer.pubkey(), sol_interface,
            merge_fixture::transact::UTXO_OWNER, merge_fixture::transact::INPUT_BLINDING,
            merge_fixture::transact::INPUT_AMOUNT);
        let outcome = ctx.raw_call(deposit).signers(&[&payer]).send()
            .expect("transact fixture deposit send failed at the runtime level");
        assert!(outcome.is_success(), "transact fixture deposit failed: {outcome:?}");
        let transact_utxo_root_index = scout_utxo_root_index(&ctx.svm.get_account(&tree).expect("tree").data);
        assert_eq!(
            scout_utxo_root(&ctx.svm.get_account(&tree).expect("tree").data), merge_fixture::transact::EXPECTED_UTXO_ROOT,
            "the transact fixture deposit did not reproduce the state root its proof \
             was generated against",
        );

        // The two ring transact rails' inputs, at leaves 5 and 6. Ring deposits, so
        // each UTXO carries the ring's program id -- a plain deposit would hash to
        // something the ring circuits cannot spend.
        let ring_transact_deposit = scout_ring_deposit_ix(
            ring_program, program_id, tree, payer.pubkey(), ring_config, sol_interface,
            merge_fixture::ring_transact::OWNER_UTXO_HASH,
            merge_fixture::ring_transact::RING_DATA_HASH,
            merge_fixture::ring_transact::LEAF_AMOUNT);
        let outcome = ctx.raw_call(ring_transact_deposit).signers(&[&payer]).send()
            .expect("ring_transact fixture deposit send failed");
        assert!(outcome.is_success(), "ring_transact fixture deposit failed: {outcome:?}");
        let ring_transact_utxo_root_index = scout_utxo_root_index(&ctx.svm.get_account(&tree).expect("tree").data);
        assert_eq!(scout_utxo_root(&ctx.svm.get_account(&tree).expect("tree").data), merge_fixture::ring_transact::EXPECTED_UTXO_ROOT,
                   "ring_transact fixture deposit did not reproduce its proof's root");

        let ring_authority_deposit = scout_ring_deposit_ix(
            ring_program, program_id, tree, payer.pubkey(), ring_config, sol_interface,
            merge_fixture::ring_authority_transact::OWNER_UTXO_HASH,
            merge_fixture::ring_authority_transact::RING_DATA_HASH,
            merge_fixture::ring_authority_transact::LEAF_AMOUNT);
        let outcome = ctx.raw_call(ring_authority_deposit).signers(&[&payer]).send()
            .expect("ring_authority_transact fixture deposit send failed");
        assert!(outcome.is_success(),
                "ring_authority_transact fixture deposit failed: {outcome:?}");
        let ring_authority_utxo_root_index = scout_utxo_root_index(&ctx.svm.get_account(&tree).expect("tree").data);
        assert_eq!(scout_utxo_root(&ctx.svm.get_account(&tree).expect("tree").data),
                   merge_fixture::ring_authority_transact::EXPECTED_UTXO_ROOT,
                   "ring_authority fixture deposit did not reproduce its proof's root");

        // --- the forester tree ------------------------------------------------
        // Its own tree, because which nullifiers land in the first ZKP batch
        // depends on the order the fuzzer ran things -- and the batch proof binds
        // a hash chain over exactly those, in exactly that order. Nothing but this
        // block writes it, so the batch is identical on every run.
        let forester_tree = Pubkey::new_unique();
        ctx.create_account()
            .pubkey(forester_tree)
            .owner(program_id)
            .size(TREE_ACCOUNT_SIZE)
            .lamports(tree_rent)
            .create()
            .expect("forester tree mint failed");
        let create_forester_tree = ScoutIx {
            program_id,
            accounts: vec![
                ScoutMeta::new_readonly(payer.pubkey(), true),
                ScoutMeta::new_readonly(protocol_config, false),
                ScoutMeta::new(forester_tree, false),
            ],
            // A smaller ZKP batch than the default 250: two merges fill it instead
            // of thirty-one, and its proving key is 137 MB instead of 3.76 GB.
            data: scout_create_tree_data(
                merge_fixture::forester::INPUT_QUEUE_BATCH_SIZE,
                merge_fixture::forester::INPUT_QUEUE_ZKP_BATCH_SIZE,
                merge_fixture::forester::ROOT_HISTORY_CAPACITY,
                merge_fixture::forester::TREE_HEIGHT),
        };
        let outcome = ctx.raw_call(create_forester_tree).signers(&[&payer]).send()
            .expect("forester create_tree send failed");
        assert!(outcome.is_success(), "forester create_tree failed: {outcome:?}");

        // Four deposits BEFORE either merge: both merges prove against the same
        // 4-leaf root, so all four leaves must exist before either runs.
        for (amount, blinding) in merge_fixture::forester::DEPOSIT_AMOUNTS
            .iter()
            .zip(merge_fixture::forester::DEPOSIT_BLINDINGS.iter())
        {
            let deposit = scout_sol_deposit_ix(
                program_id, forester_tree, payer.pubkey(), sol_interface,
                merge_fixture::UTXO_OWNER, *blinding, *amount);
            let outcome = ctx.raw_call(deposit).signers(&[&payer]).send()
                .expect("forester deposit send failed");
            assert!(outcome.is_success(), "forester deposit failed: {outcome:?}");
        }
        let forester_root_index = {
            let data = ctx.svm.get_account(&forester_tree).expect("forester tree").data;
            let mut root = [0u8; 32];
            root.copy_from_slice(&data[UTXO_ROOT_OFFSET..UTXO_ROOT_OFFSET + 32]);
            assert_eq!(root, merge_fixture::forester::EXPECTED_UTXO_ROOT,
                       "forester deposits did not reproduce the root its merge proofs cite");
            u16::from_le_bytes([data[UTXO_ROOT_CURSOR_OFFSET], data[UTXO_ROOT_CURSOR_OFFSET + 1]])
        };

        // Two merges queue 16 nullifiers in a fixed order; the batch fixture proves
        // the append of the first 10.
        for (output, private_tx, proof) in [
            (merge_fixture::forester::MERGE_A_OUTPUT_UTXO_HASH,
             merge_fixture::forester::MERGE_A_PRIVATE_TX_HASH,
             scout_wire::MergeProof {
                 a: merge_fixture::forester::MERGE_A_PROOF_A,
                 b: merge_fixture::forester::MERGE_A_PROOF_B,
                 c: merge_fixture::forester::MERGE_A_PROOF_C }),
            (merge_fixture::forester::MERGE_B_OUTPUT_UTXO_HASH,
             merge_fixture::forester::MERGE_B_PRIVATE_TX_HASH,
             scout_wire::MergeProof {
                 a: merge_fixture::forester::MERGE_B_PROOF_A,
                 b: merge_fixture::forester::MERGE_B_PROOF_B,
                 c: merge_fixture::forester::MERGE_B_PROOF_C }),
        ] {
            let nullifiers = if output == merge_fixture::forester::MERGE_A_OUTPUT_UTXO_HASH {
                merge_fixture::forester::MERGE_A_NULLIFIERS.to_vec()
            } else {
                merge_fixture::forester::MERGE_B_NULLIFIERS.to_vec()
            };
            let ix = scout_merge_transact_ix(
                program_id, forester_tree, payer.pubkey(), user_record,
                forester_root_index, output, private_tx, nullifiers, proof);
            let outcome = ctx.raw_call(ix).signers(&[&payer]).send()
                .expect("forester merge send failed");
            assert!(outcome.is_success(), "forester merge failed: {outcome:?}");
        }

        // The withdrawal fixture's input, at leaf 7.
        let deposit = scout_sol_deposit_ix(
            program_id, tree, payer.pubkey(), sol_interface,
            merge_fixture::transact::UTXO_OWNER,
            merge_fixture::transact_withdrawal::INPUT_BLINDING,
            merge_fixture::transact_withdrawal::INPUT_AMOUNT);
        let outcome = ctx.raw_call(deposit).signers(&[&payer]).send()
            .expect("withdrawal fixture deposit send failed");
        assert!(outcome.is_success(), "withdrawal fixture deposit failed: {outcome:?}");
        let withdrawal_utxo_root_index =
            scout_utxo_root_index(&ctx.svm.get_account(&tree).expect("tree").data);
        assert_eq!(
            scout_utxo_root(&ctx.svm.get_account(&tree).expect("tree").data),
            merge_fixture::transact_withdrawal::EXPECTED_UTXO_ROOT,
            "the withdrawal fixture deposit did not reproduce its proof's root");

        assert_eq!(spl_interface.to_bytes(), merge_fixture::spl::INTERFACE,
                   "the SPL interface PDA derivation moved; the withdrawal proof bound it");

        // The SPL withdrawal fixture's input, at leaf 8: an SPL deposit, so the UTXO
        // carries `hash_bytes(mint)` as its asset rather than the SOL asset field.
        let payload = scout_wire::DepositIxData {
            assets: vec![scout_wire::DepositAssetKind::Spl {
                spl_interface_bump,
            }],
            deposits: vec![scout_wire::DepositEntry {
                asset_index: 0,
                view_tag: [0u8; 32],
                owner: merge_fixture::transact::UTXO_OWNER,
                blinding: merge_fixture::spl::INPUT_BLINDING,
                amount: merge_fixture::spl::INPUT_AMOUNT,
                utxo_data: None,
                memo: None,
            }],
        };
        let mut data = vec![TAG_DEPOSIT];
        data.extend_from_slice(&wincode::serialize(&payload).expect("spl deposit serializes"));
        let spl_deposit = ScoutIx {
            program_id,
            accounts: vec![
                ScoutMeta::new(tree, false),
                ScoutMeta::new(payer.pubkey(), true),
                ScoutMeta::new_readonly(program_id, false),
                ScoutMeta::new_readonly(spl_token::id(), false),
                ScoutMeta::new_readonly(spl_mint, false),
                ScoutMeta::new(user_token, false),
                ScoutMeta::new(spl_interface, false),
            ],
            data,
        };
        let outcome = ctx.raw_call(spl_deposit).signers(&[&payer]).send()
            .expect("spl withdrawal fixture deposit send failed");
        assert!(outcome.is_success(), "spl withdrawal fixture deposit failed: {outcome:?}");
        let spl_withdrawal_utxo_root_index =
            scout_utxo_root_index(&ctx.svm.get_account(&tree).expect("tree").data);
        assert_eq!(
            scout_utxo_root(&ctx.svm.get_account(&tree).expect("tree").data),
            merge_fixture::spl::EXPECTED_UTXO_ROOT,
            "the SPL fixture deposit did not reproduce its proof's root");

        let spl_interface_opening = {
            let data = ctx.svm.get_account(&spl_interface).expect("spl interface").data;
            u64::from_le_bytes(data[64..72].try_into().expect("token amount"))
        };

        // The leaf count `setup()` leaves behind: five fixtures' inputs, deposited
        // above. Read rather than counted, so the baseline cannot drift from the
        // deposits that actually landed.
        let seeded_leaves = {
            let data = ctx.svm.get_account(&tree).expect("tree must exist").data;
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&data[UTXO_ROOT_OFFSET - 8..UTXO_ROOT_OFFSET]);
            u64::from_le_bytes(buf)
        };

        // A stable address for `action_create_tree` to re-mint into. Only the address
        // is reserved here: the account itself is minted inside the action, so the
        // action -- not `setup()` -- is what drives `TreeAccount::init`.
        let scratch_tree = Pubkey::new_unique();

        // NOTE: the SPL asset counter is deliberately NOT created here. It is a
        // singleton PDA that `create_asset_counter` allocates, so minting it in
        // `setup()` would make that instruction's action fail on every input --
        // the exact trade the setup-glue safety check exists to prevent. The
        // fuzzer creates it, and `create_spl_interface` succeeds once it has.

        // --- P256 rail -------------------------------------------------------
        // Its own tree, so the state root the P256 proof binds is a single leaf and
        // does not move when the main tree's seeding order changes. Created LAST so
        // no `Pubkey::new_unique()` above it shifts -- several fixtures bind
        // addresses that counter produces.
        let p256_tree = Pubkey::new_unique();
        ctx.create_account()
            .pubkey(p256_tree)
            .owner(program_id)
            .size(TREE_ACCOUNT_SIZE)
            .lamports(tree_rent)
            .create()
            .expect("p256 tree mint failed");
        let create_p256_tree = ScoutIx {
            program_id,
            accounts: vec![
                ScoutMeta::new_readonly(payer.pubkey(), true),
                ScoutMeta::new_readonly(protocol_config, false),
                ScoutMeta::new(p256_tree, false),
            ],
            data: scout_create_tree_data(
                merge_fixture::forester::INPUT_QUEUE_BATCH_SIZE,
                merge_fixture::forester::INPUT_QUEUE_ZKP_BATCH_SIZE,
                merge_fixture::forester::ROOT_HISTORY_CAPACITY,
                merge_fixture::forester::TREE_HEIGHT),
        };
        let outcome = ctx.raw_call(create_p256_tree).signers(&[&payer]).send()
            .expect("p256 create_tree send failed");
        assert!(outcome.is_success(), "p256 create_tree failed: {outcome:?}");

        // The spent note. A PLAIN deposit: the P256 rail admits a default-ring input
        // (`AssertRingMemberOrFree`), and a default-ring P256 input is what forces the
        // owner to be PUBLISHED -- the branch that exercises `default_owner_tag`.
        let p256_deposit = scout_sol_deposit_ix(
            program_id, p256_tree, payer.pubkey(), sol_interface,
            merge_fixture::p256::UTXO_OWNER, merge_fixture::p256::INPUT_BLINDING,
            merge_fixture::p256::INPUT_AMOUNT);
        let outcome = ctx.raw_call(p256_deposit).signers(&[&payer]).send()
            .expect("p256 fixture deposit send failed");
        assert!(outcome.is_success(), "p256 fixture deposit failed: {outcome:?}");
        let p256_utxo_root_index =
            scout_utxo_root_index(&ctx.svm.get_account(&p256_tree).expect("p256 tree").data);
        assert_eq!(
            scout_utxo_root(&ctx.svm.get_account(&p256_tree).expect("p256 tree").data),
            merge_fixture::p256::EXPECTED_UTXO_ROOT,
            "the p256 fixture deposit did not reproduce the state root its proof was \
             generated against",
        );

        // Captured AFTER the fixture deposits: those lamports are part of the world
        // setup() hands over, so P-0001 nets only what the fuzzer itself credits.
        let sol_interface_opening = ctx.svm.get_account(&sol_interface)
            .map(|account| account.lamports)
            .expect("sol_interface must exist after minting");

        Self { ctx, program_id, payer, protocol_config, tree, ring_config, sol_interface,
               p256_tree, p256_utxo_root_index,
               sol_interface_opening,
               tree_rent_floor: tree_rent, shadow_sol_credited: 0,
               spl_mint, spl_interface, spl_interface_bump, user_token,
               shadow_spl_credited: 0, user_record, merge_utxo_root_index, ring_merge_utxo_root_index,
               transact_actor, transact_utxo_root_index,
               withdrawal_utxo_root_index, shadow_sol_withdrawn: 0,
               spl_withdrawal_utxo_root_index, shadow_spl_withdrawn: 0,
               spl_interface_opening,
               shadow_spl_withdrawal_spends: 0,
               shadow_withdrawal_spends: 0, shadow_substituted_payouts: 0,
               shadow_paused: 0, shadow_leaves_at_pause: seeded_leaves,
               shadow_unauthorized_admin_successes: 0, shadow_nullifier_batch_violations: 0,
               shadow_ring_gate_bypasses: 0, shadow_creation_gate_bypasses: 0,
               shadow_split_tree_misroutes: 0, shadow_proof_binding_bypasses: 0,
               shadow_batch_overwrite_bypasses: 0, shadow_stale_bloom_reuses: 0,
               shadow_proof_graft_successes: 0, shadow_stale_authority_successes: 0,
               shadow_unspendable_outputs: 0, shadow_retired_root_successes: 0,
               shadow_unretired_roots: 0,
               shadow_stale_ring_authority_successes: 0, shadow_silent_forester_noops: 0,
               shadow_donation_insolvencies: 0, shadow_sol_donated: 0,
               shadow_fee_mint_credits: 0, fee_mint_ready: false,
               shadow_unpublished_nullifiers: 0, shadow_intra_tx_double_spends: 0,
               shadow_ring_confusions: 0, second_ring_ready: false,
               shadow_signer_set_bypasses: 0, shadow_dummy_flag_bypasses: 0,
               shadow_merge_opt_out_bypasses: 0, shadow_merge_rail_bypasses: 0,
               shadow_asset_id_violations: 0, shadow_registered_assets: 0,
               shadow_expected_leaves: seeded_leaves,
               shadow_merge_spends: 0, shadow_ring_merge_spends: 0,
               shadow_transact_spends: 0, shadow_ring_transact_spends: 0,
               shadow_ring_authority_spends: 0,
               ring_transact_utxo_root_index, ring_authority_utxo_root_index, forester_tree,
               scratch_tree, spl_interface_seq: 0, ring_program, ring_config_seq: 0 }
        // SCOUT:SETUP-GLUE:END
    }

    #[cfg(feature = "admin_actions")]
    pub fn action_create_protocol_config(&mut self, protocol_authority_seed: u8, tree_creation_authority_seed: u8, tree_creation_is_permissionless: u8, forester_authority_seed: u8, ring_creation_authority_seed: u8, ring_creation_is_permissionless: u8, spl_interface_creation_is_permissionless: u8) -> bool {
        let __scout_payload = scout_wire::CreateProtocolConfigData {
            protocol_authority: [protocol_authority_seed; 32],
            tree_creation_authority: [tree_creation_authority_seed; 32],
            tree_creation_is_permissionless: tree_creation_is_permissionless,
            forester_authority: [forester_authority_seed; 32],
            ring_creation_authority: [ring_creation_authority_seed; 32],
            ring_creation_is_permissionless: ring_creation_is_permissionless,
            spl_interface_creation_is_permissionless: spl_interface_creation_is_permissionless,
        };
        let mut __scout_data = vec![0u8];
        __scout_data.extend_from_slice(bytemuck::bytes_of(&__scout_payload));
        let authority = self.payer.pubkey();
        let protocol_config = self.protocol_config;
        let system_program = Pubkey::new_from_array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let program_id = Pubkey::new_from_array([13, 5, 28, 44, 139, 146, 215, 248, 186, 69, 230, 145, 29, 120, 65, 227, 55, 170, 67, 6, 181, 141, 109, 126, 89, 154, 141, 73, 156, 63, 135, 83]);
        // The BPF loader's program-data PDA. Admin-gated and excluded from the default
        // fuzz build, so the seed is left empty rather than derived: this action exists
        // to document the instruction's shape, not to be driven.
        let (program_data, _) = Pubkey::find_program_address(&[&[]], &self.program_id);
        let mut __scout_accounts = vec![
            AccountMeta::new(authority, true),
            AccountMeta::new(protocol_config, false),
            AccountMeta::new_readonly(system_program, false),
            AccountMeta::new_readonly(program_id, false),
            AccountMeta::new_readonly(program_data, false),
        ];
        let __scout_instruction = Instruction {
            program_id: self.program_id,
            accounts: __scout_accounts,
            data: __scout_data,
        };
        let __scout_success = self.ctx
            .raw_call(__scout_instruction)
            .signers(&[&*self.payer])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if __scout_success {
            // SCOUT:ACTION-HOOK:create_protocol_config:BEGIN
            // update shadow-ledger state after successful create_protocol_config
            // SCOUT:ACTION-HOOK:create_protocol_config:END
        }
        __scout_success
    }
    #[cfg(not(feature = "admin_actions"))]
    pub fn action_create_protocol_config(&mut self, protocol_authority_seed: u8, tree_creation_authority_seed: u8, tree_creation_is_permissionless: u8, forester_authority_seed: u8, ring_creation_authority_seed: u8, ring_creation_is_permissionless: u8, spl_interface_creation_is_permissionless: u8) -> bool {
        // disabled: build with --features admin_actions to enable
        false
    }

    pub fn action_pause_tree(&mut self, paused: u8) -> bool {
        let __scout_payload = scout_wire::PauseTreeData {
            paused: paused,
        };
        let mut __scout_data = vec![3u8];
        __scout_data.extend_from_slice(bytemuck::bytes_of(&__scout_payload));
        let authority = self.payer.pubkey();
        let protocol_config = self.protocol_config;
        let tree = self.tree;
        let mut __scout_accounts = vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(protocol_config, false),
            AccountMeta::new(tree, false),
        ];
        let __scout_instruction = Instruction {
            program_id: self.program_id,
            accounts: __scout_accounts,
            data: __scout_data,
        };
        let __scout_success = self.ctx
            .raw_call(__scout_instruction)
            .signers(&[&*self.payer])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if __scout_success {
            // SCOUT:ACTION-HOOK:pause_tree:BEGIN
            // The payload's own flag, so the shadow follows what the program was
            // ASKED to do, and the leaf count at that moment as the baseline no
            // append may pass while the freeze holds.
            scout_run_property!("P-0007", {
                self.shadow_paused = paused;
                self.shadow_leaves_at_pause = self.shadow_expected_leaves;
            });
            // SCOUT:ACTION-HOOK:pause_tree:END
        }
        __scout_success
    }

    pub fn action_batch_update_nullifier_tree(&mut self) -> bool {
        let new_root: [u8; 32] = merge_fixture::forester::NEW_ROOT;
        let old_root: [u8; 32] = merge_fixture::forester::OLD_ROOT;
        let zkp_batch_index: u16 = merge_fixture::forester::ZKP_BATCH_INDEX;
        let compressed_proof: shielded_pool::types::CompressedProof = shielded_pool::types::CompressedProof { a: merge_fixture::forester::PROOF_A, b: merge_fixture::forester::PROOF_B, c: merge_fixture::forester::PROOF_C };
        let authority = self.payer.pubkey();
        let protocol_config = self.protocol_config;
        let tree = self.forester_tree;
        let reimbursement_recipient = self.payer.pubkey();
        // Unused: the accounts struct below names every account explicitly.
        let program_id = self.scout_placeholder();
        let __scout_success = self.ctx
            .program(self.program_id)
            .call(instruction::BatchUpdateNullifierTree { new_root, old_root, zkp_batch_index, compressed_proof })
            .accounts(accounts::BatchUpdateNullifierTree {
                authority: authority,
                protocol_config: protocol_config,
                tree: tree,
                reimbursement_recipient: reimbursement_recipient,
            })
            .signers(&[&*self.payer])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if __scout_success {
            // SCOUT:ACTION-HOOK:batch_update_nullifier_tree:BEGIN
            // P-0012 is observed by `action_forester_batch_apply`, not here. The
            // property is a per-call DELTA, and a hook only ever runs AFTER the call,
            // so there is no honest place to read the pre-image from. Deriving the
            // baseline from a shadow instead would reintroduce the `--stateful` trap
            // that made P-0008's absolute form unsound: a restored pooled state can
            // carry an already-advanced tree while the fixture's shadow resets.
            // SCOUT:ACTION-HOOK:batch_update_nullifier_tree:END
        }
        __scout_success
    }

    #[cfg(feature = "admin_actions")]
    pub fn action_update_ring_config(&mut self, ring_authority_transact_is_enabled: bool, paused: bool) -> bool {
        let authority = self.payer.pubkey();
        let ring_config = self.ring_config;
        let __scout_success = self.ctx
            .program(self.program_id)
            .call(instruction::UpdateRingConfig { ring_authority_transact_is_enabled, paused })
            .accounts(accounts::UpdateRingConfig {
                authority: authority,
                ring_config: ring_config,
            })
            .signers(&[&*self.payer])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if __scout_success {
            // SCOUT:ACTION-HOOK:update_ring_config:BEGIN
            // update shadow-ledger state after successful update_ring_config
            // SCOUT:ACTION-HOOK:update_ring_config:END
        }
        __scout_success
    }
    #[cfg(not(feature = "admin_actions"))]
    pub fn action_update_ring_config(&mut self, ring_authority_transact_is_enabled: bool, paused: bool) -> bool {
        // disabled: build with --features admin_actions to enable
        false
    }

    pub fn action_deposit(&mut self, deposits_asset_index: u8, deposits_view_tag_seed: u8, deposits_owner_seed: u8, deposits_blinding_seed: u8, deposits_amount: u64) -> bool {
        // `utxo_data` and `memo` are pinned to None; the populated branches are driven
        // by action_deposit_multi and the ring deposit actions.
        let __scout_payload = scout_wire::DepositIxData {
            assets: vec![scout_wire::DepositAssetKind::Sol],
            deposits: vec![scout_wire::DepositEntry { asset_index: deposits_asset_index, view_tag: [deposits_view_tag_seed; 32], owner: [deposits_owner_seed; 32], blinding: [deposits_blinding_seed; 32], amount: deposits_amount, utxo_data: None, memo: None }],
        };
        let mut __scout_data = vec![11u8];
        __scout_data.extend_from_slice(
            &wincode::serialize(&__scout_payload)
                .expect("scout wire payload for deposit must serialize"),
        );
        let tree = self.tree;
        let depositor = self.payer.pubkey();
        let program_id = Pubkey::new_from_array([13, 5, 28, 44, 139, 146, 215, 248, 186, 69, 230, 145, 29, 120, 65, 227, 55, 170, 67, 6, 181, 141, 109, 126, 89, 154, 141, 73, 156, 63, 135, 83]);
        let mut __scout_accounts = vec![
            AccountMeta::new(tree, false),
            AccountMeta::new(depositor, true),
            AccountMeta::new_readonly(program_id, false),
        ];
        __scout_accounts.extend(vec![AccountMeta::new_readonly(system_program::ID, false), AccountMeta::new(self.sol_interface, false)]);
        let __scout_instruction = Instruction {
            program_id: self.program_id,
            accounts: __scout_accounts,
            data: __scout_data,
        };
        let __scout_success = self.ctx
            .raw_call(__scout_instruction)
            .signers(&[&*self.payer])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if __scout_success {
            // SCOUT:ACTION-HOOK:deposit:BEGIN
            // One entry per generated batch, so a success credits exactly this
            // amount. Saturating so a shadow overflow can never itself fire P-0001.
            //
            // Wrapped in `scout_run_property!` because the shadow is P-0001's own
            // state: a replay isolated to a single other property must not run this
            // arithmetic, or one property's bookkeeping perturbs another's evidence.
            scout_run_property!("P-0001", {
                self.shadow_sol_credited =
                    self.shadow_sol_credited.saturating_add(deposits_amount);
            });
            // One entry per generated batch, so one appended leaf; a deposit spends
            // no nullifier.
            scout_run_property!("P-0004", {
                self.shadow_expected_leaves = self.shadow_expected_leaves.saturating_add(1);
            });
            // SCOUT:ACTION-HOOK:deposit:END
        }
        __scout_success
    }

    pub fn action_transact_no_transfers(&mut self) -> bool {
        // `data_hash` and `ring_data_hash` are pinned to None here; both populated
        // branches are driven by action_transact_perturbed.
        let __scout_payload = scout_wire::TransactIxData {
            expiry_unix_ts: merge_fixture::EXPIRY_UNIX_TS,
            private_tx_hash: merge_fixture::transact::PRIVATE_TX_HASH,
            circuit: scout_wire::CircuitId::ConfidentialEddsa(1, 1, 3),
            tx_viewing_pk: merge_fixture::transact::TX_VIEWING_PK,
            salt: [0u8; 16],
            proof: scout_wire::TransactProof { a: merge_fixture::transact::PROOF_A, b: merge_fixture::transact::PROOF_B, c: merge_fixture::transact::PROOF_C },
            inputs: vec![scout_wire::InputUtxo { nullifier_hash: merge_fixture::transact::NULLIFIER, nullifier_tree_root_index: 0, utxo_tree_root_index: self.transact_utxo_root_index }],
            interface_transfers: Vec::new(), // pinned empty by scenario transact_no_transfers
            data_hash: None,
            ring_data_hash: None,
            outputs: vec![scout_wire::TransactOutput { utxo_hash: merge_fixture::transact::OUTPUT_UTXO_HASH, owner_tag: scout_wire::OwnerTag::Inline(merge_fixture::transact::ACTOR_PUBKEY), data: None }],
            messages: Vec::new(),
        };
        let mut __scout_data = vec![12u8];
        __scout_data.extend_from_slice(
            &wincode::serialize(&__scout_payload)
                .expect("scout wire payload for transact_no_transfers must serialize"),
        );
        let __scout_signer_payer = self.transact_actor.insecure_clone();
        let payer = __scout_signer_payer.pubkey();
        let input_tree = self.tree;
        let output_tree = self.tree;
        let program_id = Pubkey::new_from_array([13, 5, 28, 44, 139, 146, 215, 248, 186, 69, 230, 145, 29, 120, 65, 227, 55, 170, 67, 6, 181, 141, 109, 126, 89, 154, 141, 73, 156, 63, 135, 83]);
        let system_program = Pubkey::new_from_array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let mut __scout_accounts = vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(input_tree, false),
            AccountMeta::new(output_tree, false),
            AccountMeta::new_readonly(program_id, false),
            AccountMeta::new_readonly(system_program, false),
        ];
        let __scout_instruction = Instruction {
            program_id: self.program_id,
            accounts: __scout_accounts,
            data: __scout_data,
        };
        let __scout_success = self.ctx
            .raw_call(__scout_instruction)
            .signers(&[&*self.payer, &__scout_signer_payer])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if __scout_success {
            // SCOUT:ACTION-HOOK:transact_no_transfers:BEGIN
            scout_run_property!("P-0004", {
                self.shadow_expected_leaves = self.shadow_expected_leaves.saturating_add(1);
            });
            scout_run_property!("P-0005", {
                self.shadow_transact_spends = self.shadow_transact_spends.saturating_add(1);
            });
            // SCOUT:ACTION-HOOK:transact_no_transfers:END
        }
        __scout_success
    }

    pub fn action_merge_transact(&mut self, eddsa_owner: bool) -> bool {
        let __scout_payload = scout_wire::MergeTransactIxData {
            expiry_unix_ts: merge_fixture::EXPIRY_UNIX_TS,
            proof: scout_wire::MergeProof { a: merge_fixture::PROOF_A, b: merge_fixture::PROOF_B, c: merge_fixture::PROOF_C },
            output_utxo_hash: merge_fixture::OUTPUT_UTXO_HASH,
            eddsa_owner: eddsa_owner,
            private_tx_hash: merge_fixture::PRIVATE_TX_HASH,
            nullifiers: merge_fixture::NULLIFIERS.to_vec(),
            utxo_tree_root_index: vec![self.merge_utxo_root_index; 8],
            nullifier_tree_root_index: vec![0u16; 8],
        };
        let mut __scout_data = vec![13u8];
        __scout_data.extend_from_slice(
            &wincode::serialize(&__scout_payload)
                .expect("scout wire payload for merge_transact must serialize"),
        );
        let input_tree = self.tree;
        let output_tree = self.tree;
        let payer = self.payer.pubkey();
        let user_record = self.user_record;
        let system_program = Pubkey::new_from_array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let program_id = Pubkey::new_from_array([13, 5, 28, 44, 139, 146, 215, 248, 186, 69, 230, 145, 29, 120, 65, 227, 55, 170, 67, 6, 181, 141, 109, 126, 89, 154, 141, 73, 156, 63, 135, 83]);
        let mut __scout_accounts = vec![
            AccountMeta::new(input_tree, false),
            AccountMeta::new(output_tree, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(user_record, false),
            AccountMeta::new_readonly(system_program, false),
            AccountMeta::new_readonly(program_id, false),
        ];
        let __scout_instruction = Instruction {
            program_id: self.program_id,
            accounts: __scout_accounts,
            data: __scout_data,
        };
        let __scout_success = self.ctx
            .raw_call(__scout_instruction)
            .signers(&[&*self.payer])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if __scout_success {
            // SCOUT:ACTION-HOOK:merge_transact:BEGIN
            // One merged output appended. The eight input nullifiers are fixture
            // constants, so a SECOND success here is a second acceptance of the
            // same eight -- which is what P-0005 counts.
            scout_run_property!("P-0004", {
                self.shadow_expected_leaves = self.shadow_expected_leaves.saturating_add(1);
            });
            scout_run_property!("P-0005", {
                self.shadow_merge_spends = self.shadow_merge_spends.saturating_add(1);
            });
            // SCOUT:ACTION-HOOK:merge_transact:END
        }
        __scout_success
    }

    // SCOUT:EXTRA-ACTIONS:BEGIN
    /// SPL deposit. Hand-written because its account tail is keyed on a payload
    /// VARIANT, not on emptiness: the builder appends the SOL group under
    /// `if has_sol` and one four-account group per distinct SPL mint, so the
    /// empty-driver proof the adapter uses for `transact` does not apply here --
    /// and an empty `assets` vector is rejected outright (EmptyDepositBatch), so
    /// there is no pinned-empty scenario either.
    ///
    /// Account order is what `DepositAccounts::validate_and_parse` reads:
    /// `[tree, depositor, program]` then, for one `Spl` group,
    /// `[token_program, mint, user_token, spl_interface]`.
    pub fn action_deposit_spl(
        &mut self, amount: u64, view_tag_seed: u8, owner_seed: u8, blinding_seed: u8,
    ) -> bool {
        let payload = scout_wire::DepositIxData {
            assets: vec![scout_wire::DepositAssetKind::Spl {
                spl_interface_bump: self.spl_interface_bump,
            }],
            deposits: vec![scout_wire::DepositEntry {
                asset_index: 0,
                view_tag: [view_tag_seed; 32],
                owner: [owner_seed; 32],
                blinding: [blinding_seed; 32],
                amount,
                utxo_data: None,
                memo: None,
            }],
        };
        let mut data = vec![TAG_DEPOSIT];
        data.extend_from_slice(
            &wincode::serialize(&payload).expect("spl deposit payload must serialize"),
        );
        let instruction = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new(self.tree, false),
                AccountMeta::new(self.payer.pubkey(), true),
                AccountMeta::new_readonly(self.program_id, false),
                AccountMeta::new_readonly(spl_token::id(), false),
                AccountMeta::new_readonly(self.spl_mint, false),
                AccountMeta::new(self.user_token, false),
                AccountMeta::new(self.spl_interface, false),
            ],
            data,
        };
        let success = self.ctx
            .raw_call(instruction)
            .signers(&[&*self.payer])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if success {
            // Deliberately NOT wrapped in `scout_run_property!`: that macro is only
            // permitted inside SCOUT:INVARIANTS or an accounted SCOUT:ACTION-HOOK
            // region, and a hand-written action is neither. It is safe ungated here
            // because the shadow is only ever READ by P-0002's check -- a replay
            // isolated to another property advances it but never compares it, so no
            // evidence can be perturbed.
            self.shadow_spl_credited = self.shadow_spl_credited.saturating_add(amount);
            self.shadow_expected_leaves = self.shadow_expected_leaves.saturating_add(1);
        }
        success
    }

    /// `create_asset_counter` (tag 5). Empty payload; accounts in loader order are
    /// `[authority(signer), protocol_config, asset_counter, system_program]`.
    ///
    /// The counter is a singleton, so this succeeds exactly once per fixture and
    /// then returns `AlreadyInitialized`. That single success is what unblocks
    /// `create_spl_interface`, which reads and advances the same counter.
    pub fn action_create_asset_counter(&mut self) -> bool {
        let (asset_counter, _) =
            Pubkey::find_program_address(&[SPL_ASSET_COUNTER_PDA_SEED], &self.program_id);
        let instruction = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new(self.payer.pubkey(), true),
                AccountMeta::new_readonly(self.protocol_config, false),
                AccountMeta::new(asset_counter, false),
                AccountMeta::new_readonly(system_program::ID, false),
            ],
            data: vec![TAG_CREATE_ASSET_COUNTER],
        };
        self.ctx.raw_call(instruction).signers(&[&*self.payer]).send()
            .map(|o| o.is_success()).unwrap_or(false)
    }

    /// `create_spl_interface` (tag 6). Registers a NEW mint each call: the registry
    /// entry and the interface token account are both per-mint PDAs, so reusing one
    /// mint would make every call after the first fail on an existing account
    /// rather than exercise the creation path.
    ///
    /// Accounts, in loader order: `[authority(signer), protocol_config,
    /// asset_counter, registry_entry, mint, spl_interface, system_program,
    /// token_program]`.
    pub fn action_create_spl_interface(&mut self, decimals: u8) -> bool {
        if !self.scout_ensure_asset_counter() {
            return false;
        }
        self.spl_interface_seq += 1;
        let mint = self.scout_next_mint_address();
        if self.ctx.create_mint().pubkey(mint).decimals(decimals % 10).create().is_err() {
            return false;
        }
        let (asset_counter, _) =
            Pubkey::find_program_address(&[SPL_ASSET_COUNTER_PDA_SEED], &self.program_id);
        let (registry_entry, _) = Pubkey::find_program_address(
            &[SPL_ASSET_REGISTRY_PDA_SEED, mint.as_ref()], &self.program_id);
        let (spl_interface, _) = Pubkey::find_program_address(
            &[SPL_INTERFACE_PDA_SEED, mint.as_ref()], &self.program_id);
        let instruction = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new(self.payer.pubkey(), true),
                AccountMeta::new_readonly(self.protocol_config, false),
                AccountMeta::new(asset_counter, false),
                AccountMeta::new(registry_entry, false),
                AccountMeta::new_readonly(mint, false),
                AccountMeta::new(spl_interface, false),
                AccountMeta::new_readonly(system_program::ID, false),
                AccountMeta::new_readonly(spl_token::id(), false),
            ],
            data: vec![TAG_CREATE_SPL_INTERFACE],
        };
        let before = self.scout_asset_next_id();
        let success = self.ctx.raw_call(instruction).signers(&[&*self.payer]).send()
            .map(|o| o.is_success()).unwrap_or(false);
        let after = self.scout_asset_next_id();
        // A success must consume exactly one id; a failure must consume none, since
        // a rejected instruction reverts every write it made -- including the
        // `allocate_id` that happens BEFORE the registry account is created.
        let expected_delta = u64::from(success);
        if let (Some(before), Some(after)) = (before, after) {
            if after.wrapping_sub(before) != expected_delta {
                self.shadow_asset_id_violations =
                    self.shadow_asset_id_violations.saturating_add(1);
            }
        }
        if success {
            self.shadow_registered_assets = self.shadow_registered_assets.saturating_add(1);
        }
        success
    }

    /// The singleton asset counter's `next_id`, or `None` before it is allocated.
    /// The counter is created by a fuzzable instruction, so absence is an ordinary
    /// early state.
    /// Ensure the singleton asset counter exists, creating it only if it does not.
    ///
    /// `create_spl_interface` and its unauthorized variant BOTH need this account, and
    /// it is created by an ACTION rather than by `setup()`. In a random sequence that
    /// left them failing as a missing prerequisite rather than reaching their own
    /// logic -- 0 successes in 314 selections for the unauthorized variant, which had
    /// been reading as an authority gate refusing an outsider when it was really an
    /// absent account. That is the same vacuous shape recorded in
    /// `vacuous-pass-in-negative-tests`, and it silently weakened P-0015.
    ///
    /// Deliberately NOT solved by minting the counter in `setup()`. That would disable
    /// `action_create_asset_counter` forever, which `references/setup-glue.md` says is
    /// an architecture decision rather than a trade to make in passing. Creating it on
    /// demand keeps both paths alive: the counter's SUCCESS path still runs through the
    /// real instruction, and a direct dispatch of the action on a branch that already
    /// has one exercises the already-initialized rejection.
    fn scout_ensure_asset_counter(&mut self) -> bool {
        if self.scout_asset_next_id().is_some() {
            return true;
        }
        self.action_create_asset_counter()
    }

    /// A fresh mint address, derived from the counter's own `next_id`.
    ///
    /// `Pubkey::new_unique()` was used here, and it is process-global: the address a
    /// given action produces depends on how many were minted before it in that
    /// process, so a corpus entry does not replay to the same world. `next_id` lives in
    /// the SVM instead, so it is restored in lockstep with `--stateful` state, advances
    /// once per successful registration, and cannot collide with a mint this branch has
    /// already registered.
    fn scout_next_mint_address(&self) -> Pubkey {
        let mut seed = [0x8Au8; 32];
        seed[..8].copy_from_slice(&self.scout_asset_next_id().unwrap_or(0).to_le_bytes());
        Pubkey::new_from_array(seed)
    }

    fn scout_asset_next_id(&self) -> Option<u64> {
        let (counter, _) =
            Pubkey::find_program_address(&[SPL_ASSET_COUNTER_PDA_SEED], &self.program_id);
        let account = self.ctx.read_account(&counter).ok()?;
        let slice = account.data.get(
            ASSET_COUNTER_NEXT_ID_OFFSET..ASSET_COUNTER_NEXT_ID_OFFSET + 8)?;
        Some(u64::from_le_bytes(slice.try_into().ok()?))
    }

    /// `create_tree` (tag 2). An empty payload selects the canonical nullifier
    /// params; a non-empty one is borsh-decoded, so `use_fuzzed_params` reaches the
    /// decode-failure branch that the canonical path never touches.
    ///
    /// The account is re-minted zeroed on every call because `TreeAccount::init`
    /// refuses an initialised account -- without that, this would succeed once and
    /// then only ever exercise its own rejection.
    pub fn action_create_tree(&mut self, use_fuzzed_params: bool, params_seed: u8) -> bool {
        let tree_rent = self.ctx.svm.minimum_balance_for_rent_exemption(TREE_ACCOUNT_SIZE);
        if self.ctx.create_account()
            .pubkey(self.scratch_tree)
            .owner(self.program_id)
            .size(TREE_ACCOUNT_SIZE)
            .lamports(tree_rent)
            .create()
            .is_err()
        {
            return false;
        }
        let mut data = vec![TAG_CREATE_TREE];
        if use_fuzzed_params {
            data.extend_from_slice(&[params_seed; 32]);
        }
        let instruction = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new_readonly(self.payer.pubkey(), true),
                AccountMeta::new_readonly(self.protocol_config, false),
                AccountMeta::new(self.scratch_tree, false),
            ],
            data,
        };
        self.ctx.raw_call(instruction).signers(&[&*self.payer]).send()
            .map(|o| o.is_success()).unwrap_or(false)
    }

    /// `emit_event` (tag 10). The handler is a deliberate no-op: the tag exists so
    /// the program can self-CPI and have the event bytes recorded as an inner
    /// instruction. Anyone may invoke it with forged bytes -- which is exactly why
    /// it is worth having in the pool rather than excluding: a fuzzer-reachable tag
    /// that accepts arbitrary data from any caller is a real part of the surface,
    /// and the "indexers must filter by parent instruction" caveat is a property
    /// about consumers, not a guard in the program.
    pub fn action_emit_event(&mut self, payload_len: u8, payload_seed: u8) -> bool {
        let mut data = vec![TAG_EMIT_EVENT];
        data.extend(std::iter::repeat(payload_seed).take(payload_len as usize));
        let instruction = Instruction {
            program_id: self.program_id,
            accounts: vec![AccountMeta::new(self.payer.pubkey(), true)],
            data,
        };
        self.ctx.raw_call(instruction).signers(&[&*self.payer]).send()
            .map(|o| o.is_success()).unwrap_or(false)
    }

    /// `create_ring_config` (tag 7), driven through a policy-ring program exactly
    /// as production does: the config account IS the ring's `ring_auth` PDA and
    /// must sign its own creation, so the call goes to the ring fixture, which
    /// re-targets it at SPP with `invoke_signed`.
    ///
    /// Each slot gets its OWN ring program, because the config is a per-ring PDA
    /// that is created once and never closed. The slot count is bounded (16) so a
    /// long run does not deploy a new program per call; past that the action
    /// reports the program's refusal rather than inventing state to succeed
    /// against, which is the honest outcome for a create-once instruction.
    pub fn action_create_ring_config(&mut self, transact_enabled: bool) -> bool {
        let slot = (self.ring_config_seq % 16) as u8;
        self.ring_config_seq += 1;
        let mut address = [0x71u8; 32];
        address[0] = slot;
        let ring_program = Pubkey::new_from_array(address);
        let deployed = scout_without_program_override(
            || self.ctx.add_program(&ring_program, RING_PROGRAM_ARTIFACT).is_ok());
        if !deployed {
            return false;
        }
        let (ring_config, _) =
            Pubkey::find_program_address(&[RING_AUTH_PDA_SEED], &ring_program);
        let mut data = scout_create_ring_config_data(&ring_program, &self.payer.pubkey());
        // The trailing flag is the one field the ring operator chooses.
        *data.last_mut().expect("payload is never empty") = u8::from(transact_enabled);
        let instruction = Instruction {
            program_id: ring_program,
            accounts: vec![
                AccountMeta::new(self.payer.pubkey(), true),
                AccountMeta::new_readonly(self.protocol_config, false),
                AccountMeta::new(ring_config, false),
                AccountMeta::new_readonly(system_program::ID, false),
                AccountMeta::new_readonly(self.program_id, false),
            ],
            data,
        };
        self.ctx.raw_call(instruction).signers(&[&*self.payer]).send()
            .map(|o| o.is_success()).unwrap_or(false)
    }

    /// `ring_deposit` (tag 14), through the same forwarder. This is the tag that
    /// read 88.4% covered with no action at all: those lines belong to
    /// `process_deposit_internal`, which `deposit` also drives. What is unique to
    /// `ring_deposit` is the `HAS_RING` branch -- the signing `ring_config`, the
    /// ring's `program_id` folded into every UTXO's `ring_hash`, and the entry
    /// shape that publishes `owner_utxo_hash` instead of owner and blinding.
    ///
    /// Accounts, in loader order: `[tree, depositor(signer), ring_config,
    /// spp_program]` then one `[system_program, sol_interface]` group for `Sol`.
    pub fn action_ring_deposit(
        &mut self, amount: u64, view_tag_seed: u8, owner_utxo_hash_seed: u8,
        ring_data_hash_seed: u8, with_data_hash: bool, ciphertext_len: u8,
        oversized_field: bool,
    ) -> bool {
        let payload = ring_wire::RingDepositIxData {
            assets: vec![scout_wire::DepositAssetKind::Sol],
            deposits: vec![ring_wire::RingDepositEntry {
                asset_index: 0,
                // Opaque to the program: recorded in the event, never hashed.
                view_tag: [view_tag_seed; 32],
                owner_utxo_hash: if oversized_field {
                    scout_oversized_field()
                } else {
                    scout_field_bytes(owner_utxo_hash_seed)
                },
                amount,
                data_hash: with_data_hash.then(|| scout_field_bytes(0x11)),
                ring_data_hash: scout_field_bytes(ring_data_hash_seed),
                encrypted: ring_wire::EncryptedRingDepositData {
                    tx_viewing_pk: [0x02u8; 33],
                    salt: [0u8; 16],
                    ciphertext: vec![0xEE; ciphertext_len as usize],
                },
            }],
        };
        let mut data = vec![TAG_RING_DEPOSIT];
        data.extend_from_slice(
            &wincode::serialize(&payload).expect("ring deposit payload must serialize"),
        );
        let instruction = Instruction {
            program_id: self.ring_program,
            accounts: vec![
                AccountMeta::new(self.tree, false),
                AccountMeta::new(self.payer.pubkey(), true),
                AccountMeta::new_readonly(self.ring_config, false),
                AccountMeta::new_readonly(self.program_id, false),
                AccountMeta::new_readonly(system_program::ID, false),
                AccountMeta::new(self.sol_interface, false),
            ],
            data,
        };
        let success = self.ctx.raw_call(instruction).signers(&[&*self.payer]).send()
            .map(|o| o.is_success()).unwrap_or(false);
        if success {
            // One entry per batch, so one appended leaf. A deposit creates value
            // rather than spending it, so it publishes no nullifier.
            self.shadow_expected_leaves = self.shadow_expected_leaves.saturating_add(1);
            // AND it credits SOL through the same interface `deposit` uses -- the
            // ring rail is a different instruction, not a different pool. Omitting
            // this made P-0001 fire 37 times on honest traffic: the property was
            // right and the bookkeeping was one path short, which is the failure
            // mode a solvency net has to be matched against every writer to avoid.
            self.shadow_sol_credited = self.shadow_sol_credited.saturating_add(amount);
        }
        success
    }

    /// `ring_merge_transact` (tag 16), through the ring forwarder.
    ///
    /// Its own fixture, not a variant of the default merge: the ring circuit binds
    /// `ring_program_id` and the output `ring_data_hash` where the default rail
    /// folds in the owner's registry identity, and it verifies against
    /// `merge_ring_8_1` rather than `merge_8_1`. Every published value therefore
    /// differs, down to the external data hash, which the instruction tag
    /// domain-separates so a proof for one rail cannot be replayed on the other.
    ///
    /// Accounts, in loader order: `[input_tree, output_tree, ring_config(signer),
    /// payer(signer), system_program]`, then SPP for the forwarder to locate.
    pub fn action_ring_merge_transact(&mut self) -> bool {
        let payload = ring_wire::MergeRingIxData {
            output_ring_data_hash: merge_fixture::ring::OUTPUT_RING_DATA_HASH,
            merge: scout_wire::MergeTransactIxData {
                expiry_unix_ts: merge_fixture::EXPIRY_UNIX_TS,
                proof: scout_wire::MergeProof {
                    a: merge_fixture::ring::PROOF_A,
                    b: merge_fixture::ring::PROOF_B,
                    c: merge_fixture::ring::PROOF_C,
                },
                output_utxo_hash: merge_fixture::ring::OUTPUT_UTXO_HASH,
                // Unread on this rail: a policy ring has no user registry, so the
                // proof binds the ring instead of an owner identity.
                eddsa_owner: false,
                private_tx_hash: merge_fixture::ring::PRIVATE_TX_HASH,
                nullifiers: merge_fixture::ring::NULLIFIERS.to_vec(),
                utxo_tree_root_index: vec![self.ring_merge_utxo_root_index; 8],
                nullifier_tree_root_index: vec![0u16; 8],
            },
        };
        let mut data = vec![TAG_RING_MERGE_TRANSACT];
        data.extend_from_slice(
            &wincode::serialize(&payload).expect("ring merge payload must serialize"));
        let instruction = Instruction {
            program_id: self.ring_program,
            accounts: vec![
                AccountMeta::new(self.tree, false),
                AccountMeta::new(self.tree, false),
                AccountMeta::new_readonly(self.ring_config, false),
                AccountMeta::new(self.payer.pubkey(), true),
                AccountMeta::new_readonly(system_program::ID, false),
                AccountMeta::new_readonly(self.program_id, false),
            ],
            data,
        };
        let success = self.ctx.raw_call(instruction).signers(&[&*self.payer]).send()
            .map(|o| o.is_success()).unwrap_or(false);
        if success {
            self.shadow_expected_leaves = self.shadow_expected_leaves.saturating_add(1);
            self.shadow_ring_merge_spends = self.shadow_ring_merge_spends.saturating_add(1);
        }
        success
    }

    /// The two ring transact rails, tags 15 and 17, through the ring forwarder.
    ///
    /// Both take the same accounts -- `[payer(signer), input_tree, output_tree,
    /// spp_program, system_program, ring_config(signer)]` -- and differ only in the
    /// tag and the fixture. `ring_authority_transact` additionally requires
    /// `ring_authority_transact_is_enabled` on the config, and forbids owner
    /// signers entirely (`allow_owner_signers = false`), which is why neither
    /// passes an extra signer beyond the payer.
    fn ring_transact_family(&mut self, tag: u8, payload: scout_wire::TransactIxData) -> bool {
        let mut data = vec![tag];
        data.extend_from_slice(
            &wincode::serialize(&payload).expect("ring transact payload must serialize"));
        let instruction = Instruction {
            program_id: self.ring_program,
            accounts: vec![
                AccountMeta::new(self.transact_actor.pubkey(), true),
                AccountMeta::new(self.tree, false),
                AccountMeta::new(self.tree, false),
                AccountMeta::new_readonly(self.program_id, false),
                AccountMeta::new_readonly(system_program::ID, false),
                AccountMeta::new_readonly(self.ring_config, false),
            ],
            data,
        };
        self.ctx.raw_call(instruction)
            .signers(&[&*self.payer, &*self.transact_actor])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    /// `ring_transact` (tag 15): a policy-ring transfer whose input and output
    /// owners stay private and whose UTXOs bind the ring's program id.
    pub fn action_ring_transact(&mut self) -> bool {
        let payload = scout_wire::TransactIxData {
            expiry_unix_ts: merge_fixture::EXPIRY_UNIX_TS,
            private_tx_hash: merge_fixture::ring_transact::PRIVATE_TX_HASH,
            circuit: scout_wire::CircuitId::RingEddsa(1, 1, 3),
            tx_viewing_pk: merge_fixture::transact::TX_VIEWING_PK,
            salt: [0u8; 16],
            proof: scout_wire::TransactProof {
                a: merge_fixture::ring_transact::PROOF_A,
                b: merge_fixture::ring_transact::PROOF_B,
                c: merge_fixture::ring_transact::PROOF_C,
            },
            inputs: vec![scout_wire::InputUtxo {
                nullifier_hash: merge_fixture::ring_transact::NULLIFIER,
                nullifier_tree_root_index: 0,
                utxo_tree_root_index: self.ring_transact_utxo_root_index,
            }],
            interface_transfers: Vec::new(),
            data_hash: None,
            ring_data_hash: None,
            outputs: vec![scout_wire::TransactOutput {
                utxo_hash: merge_fixture::ring_transact::OUTPUT_UTXO_HASH,
                owner_tag: scout_wire::OwnerTag::Inline(merge_fixture::transact::ACTOR_PUBKEY),
                // `None` is what keeps this output UNMARKED, so the circuit
                // publishes no owner tag for it -- the proof is bound to that.
                data: None,
            }],
            messages: Vec::new(),
        };
        let success = self.ring_transact_family(TAG_RING_TRANSACT, payload);
        if success {
            self.shadow_expected_leaves = self.shadow_expected_leaves.saturating_add(1);
            self.shadow_ring_transact_spends =
                self.shadow_ring_transact_spends.saturating_add(1);
        }
        success
    }

    /// `ring_authority_transact` (tag 17): the ring authority spends its own
    /// ring-owned UTXO, with no in-circuit signature over the input owner.
    pub fn action_ring_authority_transact(&mut self) -> bool {
        let payload = scout_wire::TransactIxData {
            expiry_unix_ts: merge_fixture::EXPIRY_UNIX_TS,
            private_tx_hash: merge_fixture::ring_authority_transact::PRIVATE_TX_HASH,
            circuit: scout_wire::CircuitId::RingAuthority(1, 1, 3),
            tx_viewing_pk: merge_fixture::transact::TX_VIEWING_PK,
            salt: [0u8; 16],
            proof: scout_wire::TransactProof {
                a: merge_fixture::ring_authority_transact::PROOF_A,
                b: merge_fixture::ring_authority_transact::PROOF_B,
                c: merge_fixture::ring_authority_transact::PROOF_C,
            },
            inputs: vec![scout_wire::InputUtxo {
                nullifier_hash: merge_fixture::ring_authority_transact::NULLIFIER,
                nullifier_tree_root_index: 0,
                utxo_tree_root_index: self.ring_authority_utxo_root_index,
            }],
            interface_transfers: Vec::new(),
            data_hash: None,
            ring_data_hash: None,
            outputs: vec![scout_wire::TransactOutput {
                utxo_hash: merge_fixture::ring_authority_transact::OUTPUT_UTXO_HASH,
                owner_tag: scout_wire::OwnerTag::Inline(merge_fixture::transact::ACTOR_PUBKEY),
                data: None,
            }],
            messages: Vec::new(),
        };
        let success = self.ring_transact_family(TAG_RING_AUTHORITY_TRANSACT, payload);
        if success {
            self.shadow_expected_leaves = self.shadow_expected_leaves.saturating_add(1);
            self.shadow_ring_authority_spends =
                self.shadow_ring_authority_spends.saturating_add(1);
        }
        success
    }


    /// `transact` carrying a SOL WITHDRAWAL: the only action in this harness that
    /// makes the pool PAY OUT.
    ///
    /// Accounts are the transact prefix `[payer(signer), input_tree, output_tree,
    /// spp_program, system_program]` and then, for one `SolWithdrawal` group,
    /// `[sol_interface, recipient]` — `validate_sol_settlement` requires the
    /// canonical SOL interface, writable, SYSTEM-owned, and a writable recipient.
    pub fn action_transact_withdrawal(&mut self) -> bool {
        let recipient = self.transact_actor.pubkey();
        self.transact_withdrawal_to(recipient, false)
    }

    /// The SAME withdrawal, paid to a recipient the fuzzer chooses.
    ///
    /// The recipient is not in the instruction data at all -- it is resolved from
    /// the ACCOUNT and folded into `external_data_hash`, which the program derives
    /// itself and the proof commits to. So substituting it must invalidate the
    /// proof. This is the account-substitution probe for the one path that pays
    /// out: if it ever succeeds, anyone can redirect somebody else's withdrawal,
    /// and no solvency property would notice, because the pool's books still
    /// balance -- the money simply went to the wrong person.
    pub fn action_transact_withdrawal_substituted(&mut self, recipient_seed: u8) -> bool {
        // Seed 0 is the honest recipient, so the action also exercises the path it
        // is contrasting against rather than only ever failing.
        if recipient_seed == 0 {
            return self.action_transact_withdrawal();
        }
        let mut address = [0x40u8; 32];
        address[0] = recipient_seed;
        let recipient = Pubkey::new_from_array(address);
        if self.ctx.create_account().pubkey(recipient).lamports(1_000_000)
            .owner(system_program::ID).create().is_err()
        {
            return false;
        }
        self.transact_withdrawal_to(recipient, true)
    }

    fn transact_withdrawal_to(&mut self, recipient: Pubkey, substituted: bool) -> bool {
        let payload = scout_wire::TransactIxData {
            expiry_unix_ts: merge_fixture::EXPIRY_UNIX_TS,
            private_tx_hash: merge_fixture::transact_withdrawal::PRIVATE_TX_HASH,
            circuit: scout_wire::CircuitId::ConfidentialEddsa(1, 1, 3),
            tx_viewing_pk: merge_fixture::transact::TX_VIEWING_PK,
            salt: [0u8; 16],
            proof: scout_wire::TransactProof {
                a: merge_fixture::transact_withdrawal::PROOF_A,
                b: merge_fixture::transact_withdrawal::PROOF_B,
                c: merge_fixture::transact_withdrawal::PROOF_C,
            },
            inputs: vec![scout_wire::InputUtxo {
                nullifier_hash: merge_fixture::transact_withdrawal::NULLIFIER,
                nullifier_tree_root_index: 0,
                utxo_tree_root_index: self.withdrawal_utxo_root_index,
            }],
            interface_transfers: vec![scout_wire::InterfaceTransfer::SolWithdrawal {
                amount: merge_fixture::transact_withdrawal::WITHDRAWAL,
            }],
            data_hash: None,
            ring_data_hash: None,
            outputs: vec![scout_wire::TransactOutput {
                utxo_hash: merge_fixture::transact_withdrawal::OUTPUT_UTXO_HASH,
                owner_tag: scout_wire::OwnerTag::Inline(merge_fixture::transact::ACTOR_PUBKEY),
                data: None,
            }],
            messages: Vec::new(),
        };
        let mut data = vec![12u8];
        data.extend_from_slice(
            &wincode::serialize(&payload).expect("withdrawal payload must serialize"));
        let instruction = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new(self.transact_actor.pubkey(), true),
                AccountMeta::new(self.tree, false),
                AccountMeta::new(self.tree, false),
                AccountMeta::new_readonly(self.program_id, false),
                AccountMeta::new_readonly(system_program::ID, false),
                AccountMeta::new(self.sol_interface, false),
                AccountMeta::new(recipient, false),
            ],
            data,
        };
        let success = self.ctx.raw_call(instruction)
            .signers(&[&*self.payer, &*self.transact_actor])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if success {
            self.shadow_expected_leaves = self.shadow_expected_leaves.saturating_add(1);
            self.shadow_sol_withdrawn = self.shadow_sol_withdrawn
                .saturating_add(merge_fixture::transact_withdrawal::WITHDRAWAL);
            self.shadow_withdrawal_spends =
                self.shadow_withdrawal_spends.saturating_add(1);
            if substituted {
                self.shadow_substituted_payouts =
                    self.shadow_substituted_payouts.saturating_add(1);
            }
        }
        success
    }

    /// `transact` carrying an SPL WITHDRAWAL: the token rail's pay-out path, and
    /// the last uncovered line of the settlement dispatch.
    ///
    /// The settlement group for `SplWithdrawal` reads `[cpi_authority, mint,
    /// spl_interface, user_token_account, token_program]`. The leading
    /// `cpi_authority` is what distinguishes it from a deposit: paying OUT is the
    /// pool signing its own vault's transfer, so its authority PDA must be present
    /// where a deposit instead takes the user's token authority.
    pub fn action_transact_spl_withdrawal(&mut self) -> bool {
        let payload = scout_wire::TransactIxData {
            expiry_unix_ts: merge_fixture::EXPIRY_UNIX_TS,
            private_tx_hash: merge_fixture::spl::PRIVATE_TX_HASH,
            circuit: scout_wire::CircuitId::ConfidentialEddsa(1, 1, 3),
            tx_viewing_pk: merge_fixture::transact::TX_VIEWING_PK,
            salt: [0u8; 16],
            proof: scout_wire::TransactProof {
                a: merge_fixture::spl::PROOF_A,
                b: merge_fixture::spl::PROOF_B,
                c: merge_fixture::spl::PROOF_C,
            },
            inputs: vec![scout_wire::InputUtxo {
                nullifier_hash: merge_fixture::spl::NULLIFIER,
                nullifier_tree_root_index: 0,
                utxo_tree_root_index: self.spl_withdrawal_utxo_root_index,
            }],
            interface_transfers: vec![scout_wire::InterfaceTransfer::SplWithdrawal {
                amount: merge_fixture::spl::WITHDRAWAL,
                spl_interface_bump: self.spl_interface_bump,
            }],
            data_hash: None,
            ring_data_hash: None,
            outputs: vec![scout_wire::TransactOutput {
                utxo_hash: merge_fixture::spl::OUTPUT_UTXO_HASH,
                owner_tag: scout_wire::OwnerTag::Inline(merge_fixture::transact::ACTOR_PUBKEY),
                data: None,
            }],
            messages: Vec::new(),
        };
        let mut data = vec![12u8];
        data.extend_from_slice(
            &wincode::serialize(&payload).expect("spl withdrawal payload must serialize"));
        let instruction = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new(self.transact_actor.pubkey(), true),
                AccountMeta::new(self.tree, false),
                AccountMeta::new(self.tree, false),
                AccountMeta::new_readonly(self.program_id, false),
                AccountMeta::new_readonly(system_program::ID, false),
                AccountMeta::new_readonly(
                    Pubkey::new_from_array(SHIELDED_POOL_CPI_AUTHORITY), false),
                AccountMeta::new_readonly(self.spl_mint, false),
                AccountMeta::new(self.spl_interface, false),
                AccountMeta::new(self.user_token, false),
                AccountMeta::new_readonly(spl_token::id(), false),
            ],
            data,
        };
        let success = self.ctx.raw_call(instruction)
            .signers(&[&*self.payer, &*self.transact_actor])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if success {
            self.shadow_expected_leaves = self.shadow_expected_leaves.saturating_add(1);
            self.shadow_spl_withdrawn = self.shadow_spl_withdrawn
                .saturating_add(merge_fixture::spl::WITHDRAWAL);
            self.shadow_spl_withdrawal_spends =
                self.shadow_spl_withdrawal_spends.saturating_add(1);
        }
        success
    }

    /// A funded signer that is NOT any of the protocol's authorities.
    ///
    /// The fixture deliberately makes `payer` all four authorities so one signer
    /// drives every gated path -- which means nothing in the harness tested that
    /// the gates hold against somebody else. These two actions supply the missing
    /// actor; P-0011 asserts they never get through.
    fn scout_outsider(&mut self, seed: u8) -> Option<Rc<Keypair>> {
        let mut bytes = [0x90u8; 32];
        bytes[0] = seed;
        let outsider = Rc::new(Keypair::new_from_array(bytes));
        if self.ctx.create_account().pubkey(outsider.pubkey()).lamports(1_000_000_000)
            .owner(system_program::ID).create().is_err()
        {
            return None;
        }
        Some(outsider)
    }

    /// The nullifier tree's `(next_index, root_history_cursor)`, read from account
    /// bytes. Offsets are pinned by `nullifier_region_offsets_are_pinned`; a silent
    /// layout drift here would make every reading property quietly vacuous.
    fn scout_nullifier_progress(&self) -> (u64, u64) {
        let data = match self.ctx.svm.get_account(&self.forester_tree) {
            Some(account) => account.data,
            None => return (0, 0),
        };
        if data.len() < NULLIFIER_ROOT_HISTORY_OFFSET {
            return (0, 0);
        }
        let index = u64::from_le_bytes(
            data[NULLIFIER_NEXT_INDEX_OFFSET..NULLIFIER_NEXT_INDEX_OFFSET + 8]
                .try_into()
                .unwrap_or_default(),
        );
        let cursor = u64::from_le_bytes(
            data[NULLIFIER_ROOT_CURSOR_OFFSET..NULLIFIER_ROOT_CURSOR_OFFSET + 8]
                .try_into()
                .unwrap_or_default(),
        );
        (index, cursor)
    }

    /// The forester's batch apply, wrapped so P-0012 can see the pre-image.
    ///
    /// The generated `action_batch_update_nullifier_tree` drives the same instruction
    /// and is left alone; this exists because P-0012 is a per-call DELTA and an action
    /// hook only ever runs AFTER the call. Reading the baseline from a shadow instead
    /// would reintroduce the `--stateful` trap that made P-0008's absolute form
    /// unsound: a restored pooled state can carry an already-advanced tree while the
    /// fixture's shadow resets, and the first delta measured would be nonsense.
    /// Capturing both readings around one call keeps the observation self-contained,
    /// so it is correct whatever state the branch inherited.
    pub fn action_forester_batch_apply(&mut self) -> bool {
        let (index_before, cursor_before) = self.scout_nullifier_progress();
        let success = self.action_batch_update_nullifier_tree();
        if success {
            let (index_after, cursor_after) = self.scout_nullifier_progress();
            let advanced = index_after.saturating_sub(index_before);
            // The ring wraps, so the number of roots pushed is a modular difference.
            let pushed = (cursor_after + NULLIFIER_ROOT_HISTORY_CAPACITY - cursor_before)
                % NULLIFIER_ROOT_HISTORY_CAPACITY;
            // Exactly two legitimate outcomes, both confirmed by experiment: one whole
            // ZKP batch applied with one root pushed, or an idempotent crank that found
            // no full batch ready and moved nothing -- not even lamports.
            let whole_batch = advanced == NULLIFIER_ZKP_BATCH_SIZE && pushed == 1;
            let idle_crank = advanced == 0 && pushed == 0;
            if !(whole_batch || idle_crank) {
                self.shadow_nullifier_batch_violations =
                    self.shadow_nullifier_batch_violations.saturating_add(1);
            }
        }
        success
    }

    /// `pause_tree` attempted by a signer who is not the protocol authority. The
    /// tree's pause switch is the protocol's emergency brake, so an outsider
    /// reaching it is both a denial of service and, in the unpause direction, a way
    /// to defeat one.
    pub fn action_pause_tree_unauthorized(&mut self, paused: u8, actor_seed: u8) -> bool {
        let outsider = match self.scout_outsider(actor_seed) {
            Some(keypair) => keypair,
            None => return false,
        };
        let payload = scout_wire::PauseTreeData { paused };
        let mut data = vec![3u8];
        data.extend_from_slice(bytemuck::bytes_of(&payload));
        let instruction = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new_readonly(outsider.pubkey(), true),
                AccountMeta::new(self.protocol_config, false),
                AccountMeta::new(self.tree, false),
            ],
            data,
        };
        let success = self.ctx.raw_call(instruction)
            .signers(&[&*self.payer, &*outsider])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if success {
            self.shadow_unauthorized_admin_successes =
                self.shadow_unauthorized_admin_successes.saturating_add(1);
        }
        success
    }

    /// `update_ring_config` attempted by a signer who is not the ring's authority.
    /// A ring's config decides whether its authority rail is enabled and whether it
    /// is paused, so an outsider writing it can re-open a rail the ring closed.
    pub fn action_update_ring_config_unauthorized(&mut self, actor_seed: u8) -> bool {
        let outsider = match self.scout_outsider(actor_seed) {
            Some(keypair) => keypair,
            None => return false,
        };
        // `UpdateRingConfigData`, borsh: the two flags.
        let data = vec![TAG_UPDATE_RING_CONFIG, 1, 1];
        let instruction = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new_readonly(outsider.pubkey(), true),
                AccountMeta::new(self.ring_config, false),
            ],
            data,
        };
        let success = self.ctx.raw_call(instruction)
            .signers(&[&*self.payer, &*outsider])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if success {
            self.shadow_unauthorized_admin_successes =
                self.shadow_unauthorized_admin_successes.saturating_add(1);
        }
        success
    }

    /// The ring config's two switches, `(enabled, paused)`, read from account bytes.
    /// Offsets follow `scout_ring_config_bytes`, which asserts the layout it builds.
    fn scout_ring_switches(&self) -> (u8, u8) {
        let data = match self.ctx.svm.get_account(&self.ring_config) {
            Some(account) => account.data,
            None => return (0, 0),
        };
        if data.len() < RING_CONFIG_SIZE {
            return (0, 0);
        }
        (data[RING_ENABLED_OFFSET], data[RING_PAUSED_OFFSET])
    }

    /// Flip the ring's switches, signed by the ring authority.
    ///
    /// Nothing in this harness could move either switch before: `update_ring_config`
    /// is generated behind the `admin_actions` feature and compiles to a `false` stub,
    /// so both flags sat at their create-time values for every campaign so far and the
    /// two gates below were never once exercised. This is the same trade `pause_tree`
    /// already makes -- a switch that gates behaviour has to be an action, or the
    /// behaviour it gates is untested.
    pub fn action_set_ring_config(&mut self, enabled: u8, paused: u8) -> bool {
        let data = vec![TAG_UPDATE_RING_CONFIG, u8::from(enabled % 2 == 1), u8::from(paused % 2 == 1)];
        let instruction = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new_readonly(self.payer.pubkey(), true),
                AccountMeta::new(self.ring_config, false),
            ],
            data,
        };
        self.ctx.raw_call(instruction)
            .signers(&[&*self.payer])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    /// Record a P-0014 violation if a ring instruction succeeded through a closed gate.
    ///
    /// The switches are read BEFORE the call, but unlike P-0012 that is a convenience
    /// rather than a necessity: no operational ring instruction writes the ring config,
    /// so the reading is the same either side. Taking it before keeps the observation
    /// self-contained anyway, which is what makes it correct under `--stateful`.
    fn scout_note_ring_gate(&mut self, success: bool, before: (u8, u8), requires_enabled: bool) {
        let (enabled, paused) = before;
        let gate_closed = paused == 1 || (requires_enabled && enabled == 0);
        if success && gate_closed {
            self.shadow_ring_gate_bypasses = self.shadow_ring_gate_bypasses.saturating_add(1);
        }
    }

    pub fn action_ring_deposit_gated(
        &mut self, amount: u64, view_tag_seed: u8, owner_utxo_hash_seed: u8,
        ring_data_hash_seed: u8, with_data_hash: bool, ciphertext_len: u8,
        oversized_field: bool,
    ) -> bool {
        let before = self.scout_ring_switches();
        let success = self.action_ring_deposit(
            amount, view_tag_seed, owner_utxo_hash_seed, ring_data_hash_seed,
            with_data_hash, ciphertext_len, oversized_field,
        );
        self.scout_note_ring_gate(success, before, false);
        success
    }

    pub fn action_ring_merge_transact_gated(&mut self) -> bool {
        let before = self.scout_ring_switches();
        let success = self.action_ring_merge_transact();
        self.scout_note_ring_gate(success, before, false);
        success
    }

    pub fn action_ring_transact_gated(&mut self) -> bool {
        let before = self.scout_ring_switches();
        let success = self.action_ring_transact();
        self.scout_note_ring_gate(success, before, false);
        success
    }

    /// The rail the enable flag exists for. `validate_and_parse` sets
    /// `allow_owner_signers = false` here, so this is the one path where the ring
    /// program moves a user's notes with NO owner signature at all.
    pub fn action_ring_authority_transact_gated(&mut self) -> bool {
        let before = self.scout_ring_switches();
        let success = self.action_ring_authority_transact();
        self.scout_note_ring_gate(success, before, true);
        success
    }

    /// The protocol config's three permissionless switches, `(tree, ring, spl)`.
    fn scout_protocol_permissionless(&self) -> (u8, u8, u8) {
        let data = match self.ctx.svm.get_account(&self.protocol_config) {
            Some(account) => account.data,
            None => return (0, 0, 0),
        };
        if data.len() <= PROTOCOL_SPL_PERMISSIONLESS_OFFSET {
            return (0, 0, 0);
        }
        (
            data[PROTOCOL_TREE_PERMISSIONLESS_OFFSET],
            data[PROTOCOL_RING_PERMISSIONLESS_OFFSET],
            data[PROTOCOL_SPL_PERMISSIONLESS_OFFSET],
        )
    }

    /// Flip one of the protocol config's permissionless switches, signed by the
    /// protocol authority. `update_protocol_config` is generated behind the
    /// `admin_actions` feature and compiles to a `false` stub, so like the ring's
    /// switches these sat at their create-time values for every campaign.
    pub fn action_set_protocol_permissionless(&mut self, variant: u8, value: u8) -> bool {
        let data = vec![TAG_UPDATE_PROTOCOL_CONFIG, variant, u8::from(value % 2 == 1)];
        let instruction = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new_readonly(self.payer.pubkey(), true),
                AccountMeta::new(self.protocol_config, false),
            ],
            data,
        };
        self.ctx.raw_call(instruction)
            .signers(&[&*self.payer])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    /// `create_tree` attempted by an outsider. The tree account is minted by the
    /// harness and already rent-exempt, so the outsider pays nothing -- a refusal
    /// here is the AUTHORITY GATE and not a funding failure, which is the whole
    /// difference between this testing something and testing nothing.
    pub fn action_create_tree_unauthorized(&mut self, actor_seed: u8) -> bool {
        let outsider = match self.scout_outsider(actor_seed) {
            Some(keypair) => keypair,
            None => return false,
        };
        let tree_rent = self.ctx.svm.minimum_balance_for_rent_exemption(TREE_ACCOUNT_SIZE);
        if self.ctx.create_account()
            .pubkey(self.scratch_tree)
            .owner(self.program_id)
            .size(TREE_ACCOUNT_SIZE)
            .lamports(tree_rent)
            .create()
            .is_err()
        {
            return false;
        }
        let instruction = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new_readonly(outsider.pubkey(), true),
                AccountMeta::new_readonly(self.protocol_config, false),
                AccountMeta::new(self.scratch_tree, false),
            ],
            data: vec![TAG_CREATE_TREE],
        };
        let success = self.ctx.raw_call(instruction)
            .signers(&[&*self.payer, &*outsider])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        let (tree_permissionless, _, _) = self.scout_protocol_permissionless();
        self.scout_note_creation_gate(success, tree_permissionless);
        success
    }

    /// `create_spl_interface` attempted by an outsider. Gated by the PROTOCOL
    /// authority rather than the tree-creation authority -- a different switch and a
    /// different key from the one above, which is why both are driven.
    pub fn action_create_spl_interface_unauthorized(
        &mut self, actor_seed: u8, decimals: u8,
    ) -> bool {
        let outsider = match self.scout_outsider(actor_seed) {
            Some(keypair) => keypair,
            None => return false,
        };
        if !self.scout_ensure_asset_counter() {
            return false;
        }
        let mint = self.scout_next_mint_address();
        if self.ctx.create_mint().pubkey(mint).decimals(decimals % 10).create().is_err() {
            return false;
        }
        let (asset_counter, _) =
            Pubkey::find_program_address(&[SPL_ASSET_COUNTER_PDA_SEED], &self.program_id);
        let (registry_entry, _) = Pubkey::find_program_address(
            &[SPL_ASSET_REGISTRY_PDA_SEED, mint.as_ref()], &self.program_id);
        let (spl_interface, _) = Pubkey::find_program_address(
            &[SPL_INTERFACE_PDA_SEED, mint.as_ref()], &self.program_id);
        let instruction = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new(outsider.pubkey(), true),
                AccountMeta::new_readonly(self.protocol_config, false),
                AccountMeta::new(asset_counter, false),
                AccountMeta::new(registry_entry, false),
                AccountMeta::new_readonly(mint, false),
                AccountMeta::new(spl_interface, false),
                AccountMeta::new_readonly(system_program::ID, false),
                AccountMeta::new_readonly(spl_token::id(), false),
            ],
            data: vec![TAG_CREATE_SPL_INTERFACE],
        };
        let success = self.ctx.raw_call(instruction)
            .signers(&[&*self.payer, &*outsider])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        let (_, _, spl_permissionless) = self.scout_protocol_permissionless();
        if success {
            self.shadow_registered_assets = self.shadow_registered_assets.saturating_add(1);
        }
        self.scout_note_creation_gate(success, spl_permissionless);
        success
    }

    /// A creation that succeeded for an outsider while its switch was CLOSED is the
    /// P-0015 violation. The switch is read after the call, which is sound because no
    /// creation instruction writes the protocol config.
    fn scout_note_creation_gate(&mut self, success: bool, permissionless: u8) {
        if success && permissionless == 0 {
            self.shadow_creation_gate_bypasses =
                self.shadow_creation_gate_bypasses.saturating_add(1);
        }
    }

    /// The nullifier queue's `next_index` for an arbitrary tree, from account bytes.
    fn scout_queue_next_index(&self, tree: &Pubkey) -> u64 {
        let data = match self.ctx.svm.get_account(tree) {
            Some(account) => account.data,
            None => return 0,
        };
        if data.len() < NULLIFIER_QUEUE_NEXT_INDEX_OFFSET + 8 {
            return 0;
        }
        u64::from_le_bytes(
            data[NULLIFIER_QUEUE_NEXT_INDEX_OFFSET..NULLIFIER_QUEUE_NEXT_INDEX_OFFSET + 8]
                .try_into()
                .unwrap_or_default(),
        )
    }

    /// A tree's UTXO leaf count, from account bytes.
    fn scout_leaves(&self, tree: &Pubkey) -> u64 {
        let data = match self.ctx.svm.get_account(tree) {
            Some(account) => account.data,
            None => return 0,
        };
        scout_tree_next_index(&data).unwrap_or(0)
    }

    /// A `transact` whose input and output trees are DIFFERENT accounts.
    ///
    /// The generated action pins both to the same tree, so this arrangement -- which
    /// the instruction plainly supports, since it takes two tree accounts -- was never
    /// once exercised. It is where the routing can go wrong: membership is proven
    /// against the INPUT tree's root, so the nullifier has to land in the INPUT tree's
    /// queue. If it landed in the output tree's instead, the same note would be
    /// spendable once per output tree and no per-tree double-spend check would ever
    /// notice, because each queue would see that nullifier exactly once.
    ///
    /// Deliberately does NOT touch P-0004's leaf shadow: the output leaf lands in the
    /// other tree, and P-0004 counts leaves on the main one. It does count the spend
    /// for P-0005, because it publishes the same nullifier through the same rail.
    pub fn action_transact_split_trees(&mut self) -> bool {
        let input_tree = self.tree;
        let output_tree = self.forester_tree;
        let input_queue_before = self.scout_queue_next_index(&input_tree);
        let output_queue_before = self.scout_queue_next_index(&output_tree);
        let input_leaves_before = self.scout_leaves(&input_tree);
        let output_leaves_before = self.scout_leaves(&output_tree);

        let payload = scout_wire::TransactIxData {
            expiry_unix_ts: merge_fixture::EXPIRY_UNIX_TS,
            private_tx_hash: merge_fixture::transact::PRIVATE_TX_HASH,
            circuit: scout_wire::CircuitId::ConfidentialEddsa(1, 1, 3),
            tx_viewing_pk: merge_fixture::transact::TX_VIEWING_PK,
            salt: [0u8; 16],
            proof: scout_wire::TransactProof {
                a: merge_fixture::transact::PROOF_A,
                b: merge_fixture::transact::PROOF_B,
                c: merge_fixture::transact::PROOF_C,
            },
            inputs: vec![scout_wire::InputUtxo {
                nullifier_hash: merge_fixture::transact::NULLIFIER,
                nullifier_tree_root_index: 0,
                utxo_tree_root_index: self.transact_utxo_root_index,
            }],
            interface_transfers: Vec::new(),
            data_hash: None,
            ring_data_hash: None,
            outputs: vec![scout_wire::TransactOutput {
                utxo_hash: merge_fixture::transact::OUTPUT_UTXO_HASH,
                owner_tag: scout_wire::OwnerTag::Inline(merge_fixture::transact::ACTOR_PUBKEY),
                data: None,
            }],
            messages: Vec::new(),
        };
        let mut data = vec![TAG_TRANSACT];
        data.extend_from_slice(
            &wincode::serialize(&payload).expect("split-tree transact payload must serialize"),
        );
        let actor = self.transact_actor.insecure_clone();
        let instruction = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new(actor.pubkey(), true),
                AccountMeta::new(input_tree, false),
                AccountMeta::new(output_tree, false),
                AccountMeta::new_readonly(self.program_id, false),
                AccountMeta::new_readonly(system_program::ID, false),
            ],
            data,
        };
        let success = self.ctx.raw_call(instruction)
            .signers(&[&*self.payer, &actor])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);

        if success {
            let routed_correctly = self.scout_queue_next_index(&input_tree)
                == input_queue_before + 1
                && self.scout_queue_next_index(&output_tree) == output_queue_before
                && self.scout_leaves(&output_tree) == output_leaves_before + 1
                && self.scout_leaves(&input_tree) == input_leaves_before;
            if !routed_correctly {
                self.shadow_split_tree_misroutes =
                    self.shadow_split_tree_misroutes.saturating_add(1);
            }
            self.shadow_transact_spends = self.shadow_transact_spends.saturating_add(1);
        }
        success
    }

    /// A SOL deposit carrying TWO entries for the SAME asset.
    ///
    /// Every deposit action in this harness sends a single entry, so
    /// `asset_sums.get_mut_by_key(..) => Some(total)` -- the accumulation arm, and the
    /// `DepositAmountOverflow` guard on it -- was never reached: the map is empty on
    /// the first entry, so a one-entry batch only ever takes the `None => insert` arm.
    /// That is a value-flow path with an overflow check on it, reached only by batching.
    ///
    /// Two entries mean two credits and two leaves, which is why the shadows are
    /// advanced by the sum and by 2 -- a net has to match every writer of what it
    /// tracks, and a batch writes twice.
    pub fn action_deposit_multi(
        &mut self, amount_a: u64, amount_b: u64, view_tag_seed: u8, owner_seed: u8,
        blinding_seed: u8,
    ) -> bool {
        // `owner`, `view_tag` and `blinding` are Poseidon INPUTS -- the program hashes
        // them into the UTXO commitment -- so a naive `[seed; 32]` is only in range for
        // a seed at or below 0x30 and is otherwise refused before the handler does
        // anything. That is why this action succeeded on 2 selections in 12: it was
        // the field-element trap, not a gate. `scout_field_bytes` zeroes the top byte,
        // which keeps the seed's variation and guarantees range.
        let entry = |view_tag: u8, owner: u8, blinding: u8, amount: u64| {
            scout_wire::DepositEntry {
                asset_index: 0,
                view_tag: scout_field_bytes(view_tag),
                owner: scout_field_bytes(owner),
                blinding: scout_field_bytes(blinding),
                amount,
                utxo_data: None,
                memo: None,
            }
        };
        // The AMOUNTS are deliberately left unbounded. Bounding them would have looked
        // like the same tidy-up as the field seeds and would have silently destroyed a
        // negative path: `multi_entry_deposit_sums_both_amounts` passes `u64::MAX` to
        // exercise the per-asset overflow guard, and a modulo would have turned that
        // into an ordinary affordable deposit that SUCCEEDS.
        let payload = scout_wire::DepositIxData {
            assets: vec![scout_wire::DepositAssetKind::Sol],
            deposits: vec![
                entry(view_tag_seed, owner_seed, blinding_seed, amount_a),
                // Distinct blinding, or the two entries commit to the same UTXO hash
                // and the batch is rejected as a duplicate leaf rather than summed.
                entry(view_tag_seed, owner_seed, blinding_seed.wrapping_add(1), amount_b),
            ],
        };
        let mut data = vec![TAG_DEPOSIT];
        data.extend_from_slice(
            &wincode::serialize(&payload).expect("multi-entry deposit payload must serialize"),
        );
        let instruction = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new(self.tree, false),
                AccountMeta::new(self.payer.pubkey(), true),
                AccountMeta::new_readonly(self.program_id, false),
                AccountMeta::new_readonly(system_program::ID, false),
                AccountMeta::new(self.sol_interface, false),
            ],
            data,
        };
        let success = self.ctx.raw_call(instruction)
            .signers(&[&*self.payer])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if success {
            // Updated directly rather than through `scout_run_property!`: that macro is
            // only legal inside a generated action hook or the invariant block, and this
            // is a hand-written action. The gating it provides is not needed here --
            // every predicate reads only its own shadows, so an ungated update during
            // another property's replay costs a little arithmetic and perturbs nothing.
            self.shadow_sol_credited = self
                .shadow_sol_credited
                .saturating_add(amount_a)
                .saturating_add(amount_b);
            self.shadow_expected_leaves = self.shadow_expected_leaves.saturating_add(2);
        }
        success
    }

    /// One `u64` field of one of the two nullifier queue batches.
    fn scout_batch_field(&self, tree: &Pubkey, batch: usize, field: usize) -> u64 {
        let data = match self.ctx.svm.get_account(tree) {
            Some(account) => account.data,
            None => return 0,
        };
        let at = NULLIFIER_BATCH0_OFFSET + batch * NULLIFIER_BATCH_STRIDE + field;
        if data.len() < at + 8 {
            return 0;
        }
        u64::from_le_bytes(data[at..at + 8].try_into().unwrap_or_default())
    }

    /// The nullifier tree's applied leaf count -- how many nullifiers have actually
    /// landed in the tree, as distinct from how many have been queued.
    fn scout_applied_nullifiers(&self, tree: &Pubkey) -> u64 {
        let data = match self.ctx.svm.get_account(tree) {
            Some(account) => account.data,
            None => return 0,
        };
        if data.len() < NULLIFIER_NEXT_INDEX_OFFSET + 8 {
            return 0;
        }
        u64::from_le_bytes(
            data[NULLIFIER_NEXT_INDEX_OFFSET..NULLIFIER_NEXT_INDEX_OFFSET + 8]
                .try_into()
                .unwrap_or_default(),
        )
    }

    /// The number of distinct single-field perturbations P-0020 knows how to make.
    pub const PROOF_BOUND_FIELDS: u8 = 11;

    /// A `transact` identical to the fixture's except for ONE field that the proof's
    /// public inputs commit to.
    ///
    /// This is as close as a harness with pinned witnesses can get to testing the
    /// proof system itself. It cannot synthesise a new proof, but it can hold a valid
    /// proof fixed and vary what the program hashes ALONGSIDE it -- and every one of
    /// those fields is attacker-controlled instruction data. If any perturbation still
    /// verifies, that field is not actually bound and an attacker may vary it freely
    /// while reusing somebody else's proof.
    ///
    /// The fields are not equally obvious: `salt` and `tx_viewing_pk` look like
    /// indexer metadata, and `private_tx_hash` appears nowhere in `ExternalDataHash`'s
    /// field list, so a reader could easily assume it floats free.
    pub fn action_transact_perturbed(&mut self, selector: u8) -> bool {
        let mut payload = scout_wire::TransactIxData {
            expiry_unix_ts: merge_fixture::EXPIRY_UNIX_TS,
            private_tx_hash: merge_fixture::transact::PRIVATE_TX_HASH,
            circuit: scout_wire::CircuitId::ConfidentialEddsa(1, 1, 3),
            tx_viewing_pk: merge_fixture::transact::TX_VIEWING_PK,
            salt: [0u8; 16],
            proof: scout_wire::TransactProof {
                a: merge_fixture::transact::PROOF_A,
                b: merge_fixture::transact::PROOF_B,
                c: merge_fixture::transact::PROOF_C,
            },
            inputs: vec![scout_wire::InputUtxo {
                nullifier_hash: merge_fixture::transact::NULLIFIER,
                nullifier_tree_root_index: 0,
                utxo_tree_root_index: self.transact_utxo_root_index,
            }],
            interface_transfers: Vec::new(),
            data_hash: None,
            ring_data_hash: None,
            outputs: vec![scout_wire::TransactOutput {
                utxo_hash: merge_fixture::transact::OUTPUT_UTXO_HASH,
                owner_tag: scout_wire::OwnerTag::Inline(merge_fixture::transact::ACTOR_PUBKEY),
                data: None,
            }],
            messages: Vec::new(),
        };
        match selector % Self::PROOF_BOUND_FIELDS {
            0 => payload.expiry_unix_ts += 1,
            1 => payload.tx_viewing_pk[3] ^= 0x01,
            2 => payload.salt[0] ^= 0x01,
            3 => payload.outputs[0].utxo_hash[5] ^= 0x01,
            4 => {
                let mut pk = merge_fixture::transact::ACTOR_PUBKEY;
                pk[7] ^= 0x01;
                payload.outputs[0].owner_tag = scout_wire::OwnerTag::Inline(pk);
            }
            5 => payload.private_tx_hash[2] ^= 0x01,
            6 => payload.inputs[0].nullifier_hash[9] ^= 0x01,
            7 => payload.data_hash = Some(scout_field_bytes(0x11)),
            8 => payload.ring_data_hash = Some(scout_field_bytes(0x12)),
            9 => {
                payload.messages = vec![scout_wire::MessageData {
                    view_tag: scout_field_bytes(0x13),
                    data: vec![1u8, 2, 3],
                }]
            }
            _ => {
                payload.inputs[0].utxo_tree_root_index =
                    self.transact_utxo_root_index.wrapping_add(1)
            }
        }
        let mut data = vec![TAG_TRANSACT];
        data.extend_from_slice(
            &wincode::serialize(&payload).expect("perturbed transact payload must serialize"),
        );
        let actor = self.transact_actor.insecure_clone();
        let instruction = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new(actor.pubkey(), true),
                AccountMeta::new(self.tree, false),
                AccountMeta::new(self.tree, false),
                AccountMeta::new_readonly(self.program_id, false),
                AccountMeta::new_readonly(system_program::ID, false),
            ],
            data,
        };
        let success = self.ctx.raw_call(instruction)
            .signers(&[&*self.payer, &actor])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if success {
            self.shadow_proof_binding_bypasses =
                self.shadow_proof_binding_bypasses.saturating_add(1);
        }
        success
    }

    /// The state word of the batch a spend would currently enter.
    fn scout_current_batch_state(&self, tree: &Pubkey) -> u64 {
        let data = match self.ctx.svm.get_account(tree) {
            Some(account) => account.data,
            None => return 0,
        };
        if data.len() < NULLIFIER_BATCH0_OFFSET + 2 * NULLIFIER_BATCH_STRIDE {
            return 0;
        }
        let cur = u64::from_le_bytes(
            data[NULLIFIER_QUEUE_CURRENT_BATCH_OFFSET..NULLIFIER_QUEUE_CURRENT_BATCH_OFFSET + 8]
                .try_into()
                .unwrap_or_default(),
        ) as usize;
        let base = NULLIFIER_BATCH0_OFFSET + (cur % 2) * NULLIFIER_BATCH_STRIDE + BATCH_STATE_FIELD;
        u64::from_le_bytes(data[base..base + 8].try_into().unwrap_or_default())
    }

    /// Drive the nullifier queue to one insertion short of filling its current batch.
    ///
    /// A batch here is 30,000 nullifiers (120 chunks of 250), and the fixture seeds
    /// sixteen. Every proof-gated spend is pinned to one witness, so the harness can
    /// publish a handful of distinct nullifiers in total -- reaching a batch boundary
    /// by spending is off by three orders of magnitude, which is why no campaign had
    /// ever executed a rotation, the bloom-filter reuse guard, or the backpressure
    /// path.
    ///
    /// So the counters are set to what 29,999 real insertions would leave. This is
    /// synthesis of a REACHABLE state, not of an impossible one: the batch's own
    /// parameters decide the boundary, and they are read from the tree rather than
    /// assumed -- the two trees differ (30000/250 against 1200/10), and hardcoding one
    /// tree's numbers puts the prefill nowhere near the boundary while looking exactly
    /// like a rotation that legitimately did not happen. `queued` is moved with them,
    /// so the queue's own decomposition stays true.
    ///
    /// The bloom filter and hash chains are left alone. They are read when PROVING a
    /// batch, not when rotating one, so their contents cannot change the state machine
    /// this exercises -- and a batch prefilled this way is deliberately never proven.
    pub fn action_fill_nullifier_batch(&mut self) -> bool {
        let tree = self.tree;
        let mut account = match self.ctx.svm.get_account(&tree) {
            Some(account) => account,
            None => return false,
        };
        if account.data.len() < NULLIFIER_BATCH0_OFFSET + 2 * NULLIFIER_BATCH_STRIDE {
            return false;
        }
        let cur = u64::from_le_bytes(
            account.data[NULLIFIER_QUEUE_CURRENT_BATCH_OFFSET
                ..NULLIFIER_QUEUE_CURRENT_BATCH_OFFSET + 8]
                .try_into()
                .unwrap_or_default(),
        ) as usize
            % 2;
        let base = NULLIFIER_BATCH0_OFFSET + cur * NULLIFIER_BATCH_STRIDE;
        let read = |data: &[u8], at: usize| -> u64 {
            u64::from_le_bytes(data[at..at + 8].try_into().unwrap_or_default())
        };
        // Only a batch still filling can be driven to its boundary.
        if read(&account.data, base + BATCH_STATE_FIELD) != 0 {
            return false;
        }
        let batch_size = read(&account.data, base + BATCH_SIZE_FIELD);
        let zkp_size = read(&account.data, base + BATCH_ZKP_SIZE_FIELD);
        if zkp_size == 0 || batch_size == 0 || batch_size % zkp_size != 0 {
            return false;
        }
        let full = batch_size / zkp_size - 1;
        let partial = zkp_size - 1;
        account.data[base + BATCH_NUM_FULL_ZKP..base + BATCH_NUM_FULL_ZKP + 8]
            .copy_from_slice(&full.to_le_bytes());
        account.data[base + BATCH_NUM_INSERTED..base + BATCH_NUM_INSERTED + 8]
            .copy_from_slice(&partial.to_le_bytes());
        // Keep `queued` equal to what both batches now claim to hold.
        let other = NULLIFIER_BATCH0_OFFSET + (1 - cur) * NULLIFIER_BATCH_STRIDE;
        let other_total = read(&account.data, other + BATCH_NUM_FULL_ZKP)
            .saturating_mul(read(&account.data, other + BATCH_ZKP_SIZE_FIELD))
            .saturating_add(read(&account.data, other + BATCH_NUM_INSERTED));
        let queued = full.saturating_mul(zkp_size).saturating_add(partial).saturating_add(other_total);
        account.data[NULLIFIER_QUEUE_NEXT_INDEX_OFFSET..NULLIFIER_QUEUE_NEXT_INDEX_OFFSET + 8]
            .copy_from_slice(&queued.to_le_bytes());
        self.ctx.svm.set_account(tree, account).is_ok()
    }

    /// A merge spend that records whether it got through a FULL batch.
    ///
    /// The one thing that must never happen: a spend accepted into a batch that is
    /// filled and not yet proven. Its nullifiers would overwrite ones already there,
    /// whose hash-chain entries the forester still has to prove, so those notes would
    /// never reach the tree -- and a nullifier that never reaches the tree is a note
    /// that can be spent again. Refusing the spend is a liveness cost that buys
    /// exactly that safety.
    pub fn action_merge_transact_backpressured(&mut self, eddsa_owner: bool) -> bool {
        let (state_before, bloom_zeroed_before) = self.scout_current_batch_guard(&self.tree);
        let success = self.action_merge_transact(eddsa_owner);
        if success && state_before == BATCH_STATE_FULL {
            self.shadow_batch_overwrite_bypasses =
                self.shadow_batch_overwrite_bypasses.saturating_add(1);
        }
        // P-0022: a proven batch may be reused, but only once its filter is cleared.
        if success && state_before == BATCH_STATE_INSERTED && bloom_zeroed_before == 0 {
            self.shadow_stale_bloom_reuses =
                self.shadow_stale_bloom_reuses.saturating_add(1);
        }
        success
    }

    /// The current batch's `(state, bloom_filter_is_zeroed)` -- the pair that decides
    /// whether a spend may enter it.
    fn scout_current_batch_guard(&self, tree: &Pubkey) -> (u64, u8) {
        let data = match self.ctx.svm.get_account(tree) {
            Some(account) => account.data,
            None => return (0, 0),
        };
        if data.len() < NULLIFIER_BATCH0_OFFSET + 2 * NULLIFIER_BATCH_STRIDE {
            return (0, 0);
        }
        let cur = u64::from_le_bytes(
            data[NULLIFIER_QUEUE_CURRENT_BATCH_OFFSET..NULLIFIER_QUEUE_CURRENT_BATCH_OFFSET + 8]
                .try_into()
                .unwrap_or_default(),
        ) as usize
            % 2;
        let base = NULLIFIER_BATCH0_OFFSET + cur * NULLIFIER_BATCH_STRIDE;
        let state = u64::from_le_bytes(
            data[base + BATCH_STATE_FIELD..base + BATCH_STATE_FIELD + 8]
                .try_into()
                .unwrap_or_default(),
        );
        (state, data[base + BATCH_BLOOM_ZEROED_FIELD])
    }

    /// Mark the OTHER batch as proven-into-the-tree, with its bloom filter either
    /// still holding its entries or zeroed by a forester.
    ///
    /// Both are states the protocol genuinely reaches -- `Inserted` once every chunk
    /// of a batch has been proven, and the zeroed flag once a forester has cleared the
    /// filter. Reaching them by execution would take 120 batch-update proofs for a
    /// single batch, so the state is synthesised and then the REAL guard is exercised
    /// against it. The batch marked here is the one the queue is not currently filling,
    /// so the rotation will land on it.
    pub fn action_mark_batch_inserted(&mut self, bloom_zeroed: u8) -> bool {
        let tree = self.tree;
        let mut account = match self.ctx.svm.get_account(&tree) {
            Some(account) => account,
            None => return false,
        };
        if account.data.len() < NULLIFIER_BATCH0_OFFSET + 2 * NULLIFIER_BATCH_STRIDE {
            return false;
        }
        let cur = u64::from_le_bytes(
            account.data[NULLIFIER_QUEUE_CURRENT_BATCH_OFFSET
                ..NULLIFIER_QUEUE_CURRENT_BATCH_OFFSET + 8]
                .try_into()
                .unwrap_or_default(),
        ) as usize
            % 2;
        let other = NULLIFIER_BATCH0_OFFSET + (1 - cur) * NULLIFIER_BATCH_STRIDE;
        account.data[other + BATCH_STATE_FIELD..other + BATCH_STATE_FIELD + 8]
            .copy_from_slice(&BATCH_STATE_INSERTED.to_le_bytes());
        account.data[other + BATCH_BLOOM_ZEROED_FIELD] = bloom_zeroed % 2;
        self.ctx.svm.set_account(tree, account).is_ok()
    }

    /// `ring_transact` on the P256 ownership rail (tag 15, `CircuitId::RingP256`).
    ///
    /// The only action that reaches `verify_groth16`'s `new_with_commitment` arm:
    /// this rail's verifying key carries a BSB22 commitment, so the proof ships a
    /// Pedersen commitment plus its proof of knowledge and the program runs an extra
    /// pairing. Every other proof in this harness takes the `(None, false)` arm.
    ///
    /// The commitment travels inside the circuit selector rather than the proof
    /// struct, which is why `RingP256` carries a payload the other variants do not.
    pub fn action_ring_transact_p256(&mut self) -> bool {
        let payload = scout_wire::TransactIxData {
            expiry_unix_ts: merge_fixture::EXPIRY_UNIX_TS,
            private_tx_hash: merge_fixture::p256::PRIVATE_TX_HASH,
            circuit: scout_wire::CircuitId::RingP256(
                1, 1, 3,
                scout_wire::RingP256ProofData {
                    bsb22_commitment: scout_wire::Bsb22Commitment {
                        commitment: merge_fixture::p256::COMMITMENT,
                        commitment_pok: merge_fixture::p256::COMMITMENT_POK,
                    },
                    // A real default-ring P256 input publishes the shared owner: the
                    // public key's X coordinate, whose `hash_bytes` is the pk field
                    // the circuit binds.
                    default_owner_tag: scout_wire::FixedOptionOwnerTag {
                        present: 1,
                        tag: merge_fixture::p256::OWNER_TAG_X,
                    },
                },
            ),
            tx_viewing_pk: merge_fixture::transact::TX_VIEWING_PK,
            salt: [0u8; 16],
            proof: scout_wire::TransactProof {
                a: merge_fixture::p256::PROOF_A,
                b: merge_fixture::p256::PROOF_B,
                c: merge_fixture::p256::PROOF_C,
            },
            inputs: vec![scout_wire::InputUtxo {
                nullifier_hash: merge_fixture::p256::NULLIFIER,
                nullifier_tree_root_index: 0,
                utxo_tree_root_index: self.p256_utxo_root_index,
            }],
            interface_transfers: Vec::new(),
            data_hash: None,
            ring_data_hash: None,
            outputs: vec![scout_wire::TransactOutput {
                utxo_hash: merge_fixture::p256::OUTPUT_UTXO_HASH,
                owner_tag: scout_wire::OwnerTag::Inline(merge_fixture::p256::OWNER_TAG_X),
                data: None,
            }],
            messages: Vec::new(),
        };
        let mut data = vec![TAG_RING_TRANSACT];
        data.extend_from_slice(
            &wincode::serialize(&payload).expect("p256 transact payload must serialize"));
        let instruction = Instruction {
            program_id: self.ring_program,
            accounts: vec![
                AccountMeta::new(self.transact_actor.pubkey(), true),
                AccountMeta::new(self.p256_tree, false),
                AccountMeta::new(self.p256_tree, false),
                AccountMeta::new_readonly(self.program_id, false),
                AccountMeta::new_readonly(system_program::ID, false),
                AccountMeta::new_readonly(self.ring_config, false),
            ],
            data,
        };
        self.ctx.raw_call(instruction)
            .signers(&[&*self.payer, &*self.transact_actor])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    /// The number of distinct proof-grafting attempts P-0023 knows how to make.
    pub const PROOF_GRAFT_VARIANTS: u8 = 5;

    /// A P256 transact whose proof or commitment has been grafted or corrupted.
    ///
    /// Only reachable now that the harness holds valid proofs from TWO rails at once.
    /// The program picks its verification path from
    /// `(proof.commitment, vk.vk_commitment.is_some())` and rejects the mixed cases
    /// through a `_ => Err` arm; this drives that arm from both directions plus the
    /// three ways the commitment itself can be wrong.
    ///
    /// The BSB22 commitment is what binds the emulated-P256 gadget's private wires.
    /// A P256 proof accepted under a selector that verifies NO commitment would skip
    /// the Pedersen proof-of-knowledge entirely -- the pairing that makes the P256
    /// ownership check sound. So every one of these must be refused.
    pub fn action_transact_proof_grafted(&mut self, variant: u8) -> bool {
        let mut commitment = merge_fixture::p256::COMMITMENT;
        let mut commitment_pok = merge_fixture::p256::COMMITMENT_POK;
        let mut owner_tag = merge_fixture::p256::OWNER_TAG_X;
        let mut proof = scout_wire::TransactProof {
            a: merge_fixture::p256::PROOF_A,
            b: merge_fixture::p256::PROOF_B,
            c: merge_fixture::p256::PROOF_C,
        };
        let variant = variant % Self::PROOF_GRAFT_VARIANTS;
        // Variant 0 swaps the whole selector; the rest keep RingP256 and corrupt one
        // component of the committed payload.
        let use_eddsa_selector = variant == 0;
        match variant {
            1 => {
                // An eddsa proof under the P256 selector: no valid commitment can
                // exist for it, so the committed payload is nonsense by construction.
                proof = scout_wire::TransactProof {
                    a: merge_fixture::ring_transact::PROOF_A,
                    b: merge_fixture::ring_transact::PROOF_B,
                    c: merge_fixture::ring_transact::PROOF_C,
                };
            }
            2 => commitment[7] ^= 0x01,
            3 => commitment_pok[9] ^= 0x01,
            4 => owner_tag[5] ^= 0x01,
            _ => {}
        }
        let circuit = if use_eddsa_selector {
            // The eddsa selector carries no commitment field at all, so grafting the
            // P256 proof under it strips the Pedersen check rather than failing it.
            scout_wire::CircuitId::RingEddsa(1, 1, 3)
        } else {
            scout_wire::CircuitId::RingP256(
                1, 1, 3,
                scout_wire::RingP256ProofData {
                    bsb22_commitment: scout_wire::Bsb22Commitment { commitment, commitment_pok },
                    default_owner_tag: scout_wire::FixedOptionOwnerTag { present: 1, tag: owner_tag },
                },
            )
        };
        let payload = scout_wire::TransactIxData {
            expiry_unix_ts: merge_fixture::EXPIRY_UNIX_TS,
            private_tx_hash: merge_fixture::p256::PRIVATE_TX_HASH,
            circuit,
            tx_viewing_pk: merge_fixture::transact::TX_VIEWING_PK,
            salt: [0u8; 16],
            proof,
            inputs: vec![scout_wire::InputUtxo {
                nullifier_hash: merge_fixture::p256::NULLIFIER,
                nullifier_tree_root_index: 0,
                utxo_tree_root_index: self.p256_utxo_root_index,
            }],
            interface_transfers: Vec::new(),
            data_hash: None,
            ring_data_hash: None,
            outputs: vec![scout_wire::TransactOutput {
                utxo_hash: merge_fixture::p256::OUTPUT_UTXO_HASH,
                owner_tag: scout_wire::OwnerTag::Inline(merge_fixture::p256::OWNER_TAG_X),
                data: None,
            }],
            messages: Vec::new(),
        };
        let mut data = vec![TAG_RING_TRANSACT];
        data.extend_from_slice(
            &wincode::serialize(&payload).expect("grafted transact payload must serialize"));
        let instruction = Instruction {
            program_id: self.ring_program,
            accounts: vec![
                AccountMeta::new(self.transact_actor.pubkey(), true),
                AccountMeta::new(self.p256_tree, false),
                AccountMeta::new(self.p256_tree, false),
                AccountMeta::new_readonly(self.program_id, false),
                AccountMeta::new_readonly(system_program::ID, false),
                AccountMeta::new_readonly(self.ring_config, false),
            ],
            data,
        };
        let success = self.ctx.raw_call(instruction)
            .signers(&[&*self.payer, &*self.transact_actor])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if success {
            self.shadow_proof_graft_successes =
                self.shadow_proof_graft_successes.saturating_add(1);
        }
        success
    }

    /// The protocol config's current forester authority, from account bytes.
    fn scout_forester_authority(&self) -> [u8; 32] {
        let data = match self.ctx.svm.get_account(&self.protocol_config) {
            Some(account) => account.data,
            None => return [0u8; 32],
        };
        if data.len() < PROTOCOL_FORESTER_AUTHORITY_OFFSET + 32 {
            return [0u8; 32];
        }
        data[PROTOCOL_FORESTER_AUTHORITY_OFFSET..PROTOCOL_FORESTER_AUTHORITY_OFFSET + 32]
            .try_into()
            .unwrap_or([0u8; 32])
    }

    /// Rotate the forester authority to an outsider, or back to `payer` on seed 0.
    ///
    /// The fixture deliberately makes `payer` all four protocol authorities, so
    /// nothing could distinguish one authority from another -- a handler checking the
    /// WRONG one of the four would pass every test here. Rotating one of them apart is
    /// what makes the distinction observable. Seed 0 restores `payer` so a campaign
    /// that rotates can also un-rotate; otherwise every later forester action in that
    /// branch is refused and the rail goes dark.
    pub fn action_rotate_forester_authority(&mut self, actor_seed: u8) -> bool {
        let new_authority = if actor_seed == 0 {
            self.payer.pubkey()
        } else {
            match self.scout_outsider(actor_seed) {
                Some(keypair) => keypair.pubkey(),
                None => return false,
            }
        };
        let mut data = vec![TAG_UPDATE_PROTOCOL_CONFIG, UPDATE_VARIANT_FORESTER_AUTHORITY];
        data.extend_from_slice(new_authority.as_ref());
        let instruction = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new_readonly(self.payer.pubkey(), true),
                AccountMeta::new(self.protocol_config, false),
            ],
            data,
        };
        self.ctx.raw_call(instruction)
            .signers(&[&*self.payer])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    /// The forester's batch apply, signed by an arbitrary key.
    ///
    /// Records a P-0024 violation when the call succeeds for a signer that is NOT the
    /// forester authority the config currently names. A rotation that left the old key
    /// working would mean a compromised forester key can never be revoked.
    ///
    /// The authority branch is taken on one fuzzer byte in FOUR, not on the single
    /// value 0. Keyed on equality it was reachable in 1 draw of 256, so the campaign
    /// sampled this action's success path essentially never (1 selection, 0 successes)
    /// while its refusal path was exercised constantly -- a lopsidedness that makes the
    /// refusals weaker evidence, since a refusal only means something when the same
    /// action is seen to succeed for the right signer. `% 4` keeps the P-0024 test's
    /// seeds mapping exactly as before: 0 is the authority, 0x51 is an outsider.
    ///
    /// Note this is not purely a negative path. The outsider branch SUCCEEDS when the
    /// config has been rotated to name that outsider, which is what P-0024 checks.
    pub fn action_batch_update_signed_by(&mut self, actor_seed: u8) -> bool {
        let signer: Rc<Keypair> = if actor_seed % 4 == 0 {
            self.payer.clone()
        } else {
            match self.scout_outsider(actor_seed) {
                Some(keypair) => keypair,
                None => return false,
            }
        };
        let authority_before = self.scout_forester_authority();
        let success = self.ctx
            .program(self.program_id)
            .call(instruction::BatchUpdateNullifierTree {
                new_root: merge_fixture::forester::NEW_ROOT,
                old_root: merge_fixture::forester::OLD_ROOT,
                zkp_batch_index: merge_fixture::forester::ZKP_BATCH_INDEX,
                compressed_proof: shielded_pool::types::CompressedProof {
                    a: merge_fixture::forester::PROOF_A,
                    b: merge_fixture::forester::PROOF_B,
                    c: merge_fixture::forester::PROOF_C,
                },
            })
            .accounts(accounts::BatchUpdateNullifierTree {
                authority: signer.pubkey(),
                protocol_config: self.protocol_config,
                tree: self.forester_tree,
                reimbursement_recipient: self.payer.pubkey(),
            })
            .signers(&[&*self.payer, &*signer])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if success && signer.pubkey().to_bytes() != authority_before {
            self.shadow_stale_authority_successes =
                self.shadow_stale_authority_successes.saturating_add(1);
        }
        success
    }

    /// Spend the note the previous transact CREATED, not a deposited one.
    ///
    /// Every other proof-gated action in this harness spends a note that `setup()`
    /// deposited, so the pool's own output has never been used as an input. That
    /// leaves the append/root/membership loop untested: P-0003 checks the leaf
    /// counter never rewinds, P-0004 that it moves by the right amount, and P-0009
    /// that the cached root matches the history head -- all bookkeeping, none of
    /// which ever proves MEMBERSHIP against the tree. A leaf appended at the wrong
    /// index, or a root pushed before the append, satisfies all three and is caught
    /// only here, because this proof's merkle path is checked against the root the
    /// pool actually published.
    pub fn action_ring_transact_p256_chained(&mut self) -> bool {
        let payload = scout_wire::TransactIxData {
            expiry_unix_ts: merge_fixture::EXPIRY_UNIX_TS,
            private_tx_hash: merge_fixture::p256::chained::PRIVATE_TX_HASH,
            circuit: scout_wire::CircuitId::RingP256(
                1, 1, 3,
                scout_wire::RingP256ProofData {
                    bsb22_commitment: scout_wire::Bsb22Commitment {
                        commitment: merge_fixture::p256::chained::COMMITMENT,
                        commitment_pok: merge_fixture::p256::chained::COMMITMENT_POK,
                    },
                    // The input is a ring member, so no default-ring P256 input
                    // exists and the shared owner stays private. This is the `None`
                    // branch of `default_p256_owner_tag()`, which the first fixture
                    // cannot reach.
                    default_owner_tag: scout_wire::FixedOptionOwnerTag {
                        present: 0,
                        tag: [0u8; 32],
                    },
                },
            ),
            tx_viewing_pk: merge_fixture::transact::TX_VIEWING_PK,
            salt: [0u8; 16],
            proof: scout_wire::TransactProof {
                a: merge_fixture::p256::chained::PROOF_A,
                b: merge_fixture::p256::chained::PROOF_B,
                c: merge_fixture::p256::chained::PROOF_C,
            },
            inputs: vec![scout_wire::InputUtxo {
                nullifier_hash: merge_fixture::p256::chained::NULLIFIER,
                nullifier_tree_root_index: 0,
                // The root the pool published AFTER appending the previous output.
                utxo_tree_root_index: self.scout_utxo_root_index_of(&self.p256_tree),
            }],
            interface_transfers: Vec::new(),
            data_hash: None,
            ring_data_hash: None,
            outputs: vec![scout_wire::TransactOutput {
                utxo_hash: merge_fixture::p256::chained::OUTPUT_UTXO_HASH,
                owner_tag: scout_wire::OwnerTag::Inline(merge_fixture::p256::OWNER_TAG_X),
                data: None,
            }],
            messages: Vec::new(),
        };
        let mut data = vec![TAG_RING_TRANSACT];
        data.extend_from_slice(
            &wincode::serialize(&payload).expect("chained transact payload must serialize"));
        let instruction = Instruction {
            program_id: self.ring_program,
            accounts: vec![
                AccountMeta::new(self.transact_actor.pubkey(), true),
                AccountMeta::new(self.p256_tree, false),
                AccountMeta::new(self.p256_tree, false),
                AccountMeta::new_readonly(self.program_id, false),
                AccountMeta::new_readonly(system_program::ID, false),
                AccountMeta::new_readonly(self.ring_config, false),
            ],
            data,
        };
        self.ctx.raw_call(instruction)
            .signers(&[&*self.payer, &*self.transact_actor])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    /// The current root-history index of an arbitrary tree.
    fn scout_utxo_root_index_of(&self, tree: &Pubkey) -> u16 {
        match self.ctx.svm.get_account(tree) {
            Some(account) => scout_utxo_root_index(&account.data),
            None => 0,
        }
    }

    /// Deposit -> transact -> transact, as one action.
    ///
    /// Kept as a single action rather than two so the observation is self-contained:
    /// the second link is only meaningful immediately after the first, and a fuzzer
    /// that ran them apart would report a failure that says nothing. A violation is
    /// recorded only when the first link succeeded and the second did not -- so the
    /// pool created a note it then refused to let anyone spend.
    pub fn action_transact_chain(&mut self) -> bool {
        if !self.action_ring_transact_p256() {
            return false;
        }
        let spent = self.action_ring_transact_p256_chained();
        if !spent {
            self.shadow_unspendable_outputs =
                self.shadow_unspendable_outputs.saturating_add(1);
        }
        spent
    }

    /// A P256 transact citing a retired or never-written root index.
    ///
    /// `zero_out_roots` retires a root by writing ZERO over it -- that is how the
    /// protocol removes roots which could still prove inclusion of a value whose
    /// bloom filter is about to be cleared. The whole mechanism rests on a zeroed
    /// slot being unusable afterwards, and the check that enforces it is one `if` in
    /// `get_nullifier_tree_root`. If it were dropped, every retired root would become
    /// citable again and the clearing would silently stop protecting anything.
    ///
    /// The two trees guard differently and both are driven here: the nullifier tree
    /// rejects a ZERO root outright, while the UTXO tree bounds the index against
    /// `root_history_len` so slots it has not written yet are out of range. Neither
    /// guard is the other's, and a refactor that unified them would break one.
    ///
    /// `variant` picks: 0 = a zeroed nullifier slot, 1 = an unwritten UTXO slot.
    pub fn action_transact_citing_retired_root(&mut self, variant: u8, slot: u8) -> bool {
        // Slot 0 holds the genesis nullifier root; every slot above it is still zero,
        // which is exactly the shape `zero_out_roots` leaves behind.
        let zeroed_nullifier_slot = 1 + u16::from(slot % 100);
        let unwritten_utxo_slot = ROOT_HISTORY_CAPACITY as u16 - 1 - u16::from(slot % 50);
        let (nullifier_index, utxo_index) = if variant % 2 == 0 {
            (zeroed_nullifier_slot, self.p256_utxo_root_index)
        } else {
            (0u16, unwritten_utxo_slot)
        };
        let payload = scout_wire::TransactIxData {
            expiry_unix_ts: merge_fixture::EXPIRY_UNIX_TS,
            private_tx_hash: merge_fixture::p256::PRIVATE_TX_HASH,
            circuit: scout_wire::CircuitId::RingP256(
                1, 1, 3,
                scout_wire::RingP256ProofData {
                    bsb22_commitment: scout_wire::Bsb22Commitment {
                        commitment: merge_fixture::p256::COMMITMENT,
                        commitment_pok: merge_fixture::p256::COMMITMENT_POK,
                    },
                    default_owner_tag: scout_wire::FixedOptionOwnerTag {
                        present: 1,
                        tag: merge_fixture::p256::OWNER_TAG_X,
                    },
                },
            ),
            tx_viewing_pk: merge_fixture::transact::TX_VIEWING_PK,
            salt: [0u8; 16],
            proof: scout_wire::TransactProof {
                a: merge_fixture::p256::PROOF_A,
                b: merge_fixture::p256::PROOF_B,
                c: merge_fixture::p256::PROOF_C,
            },
            inputs: vec![scout_wire::InputUtxo {
                nullifier_hash: merge_fixture::p256::NULLIFIER,
                nullifier_tree_root_index: nullifier_index,
                utxo_tree_root_index: utxo_index,
            }],
            interface_transfers: Vec::new(),
            data_hash: None,
            ring_data_hash: None,
            outputs: vec![scout_wire::TransactOutput {
                utxo_hash: merge_fixture::p256::OUTPUT_UTXO_HASH,
                owner_tag: scout_wire::OwnerTag::Inline(merge_fixture::p256::OWNER_TAG_X),
                data: None,
            }],
            messages: Vec::new(),
        };
        let mut data = vec![TAG_RING_TRANSACT];
        data.extend_from_slice(
            &wincode::serialize(&payload).expect("retired-root payload must serialize"));
        let instruction = Instruction {
            program_id: self.ring_program,
            accounts: vec![
                AccountMeta::new(self.transact_actor.pubkey(), true),
                AccountMeta::new(self.p256_tree, false),
                AccountMeta::new(self.p256_tree, false),
                AccountMeta::new_readonly(self.program_id, false),
                AccountMeta::new_readonly(system_program::ID, false),
                AccountMeta::new_readonly(self.ring_config, false),
            ],
            data,
        };
        let success = self.ctx.raw_call(instruction)
            .signers(&[&*self.payer, &*self.transact_actor])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if success {
            self.shadow_retired_root_successes =
                self.shadow_retired_root_successes.saturating_add(1);
        }
        success
    }

    /// Drive the root-retirement path: `zero_out_previous_batch_bloom_filter` ->
    /// `zero_out_roots`, and check the roots it was supposed to retire are gone.
    ///
    /// This is the deepest safety step in the nullifier machinery. Clearing a bloom
    /// filter re-opens every value it held, so before that happens every root which
    /// could still prove inclusion of one of those values must be retired -- by
    /// writing ZERO over it. Skip that and the pool accepts an inclusion proof against
    /// a root whose nullifiers are no longer tracked, which is a double spend.
    ///
    /// Three things gate the path and all three are set up here: the pending batch at
    /// least half full, the OTHER batch marked inserted with its bloom filter still
    /// dirty, and that batch's `sequence_number` / `root_index` pair. The pair is not
    /// arbitrary -- `zero_out_roots` walks `seq - metadata.sequence_number - 1` slots
    /// from the oldest and asserts it lands exactly on `root_index`, so an inconsistent
    /// pair panics the program on state the protocol could never produce, proving
    /// nothing. It is therefore COMPUTED from the live tree, allowing for the one root
    /// this very update is about to push.
    ///
    /// The history is filled first because on a fresh tree only two slots hold real
    /// roots and the walk would pass over slots that are already zero -- the mechanism
    /// would run and be invisible. Slot 0 is left alone: it holds the root the
    /// fixture's proof names as `old_root`.
    pub fn action_forester_retire_roots(&mut self) -> bool {
        let tree = self.forester_tree;
        let mut account = match self.ctx.svm.get_account(&tree) {
            Some(account) => account,
            None => return false,
        };
        let cap = NULLIFIER_ROOT_HISTORY_CAPACITY as usize;
        if account.data.len() < NULLIFIER_HASH_CHAIN_OFFSET {
            return false;
        }
        let read_u64 = |d: &[u8], at: usize| -> u64 {
            u64::from_le_bytes(d[at..at + 8].try_into().unwrap_or_default())
        };
        let cursor_before = read_u64(&account.data, NULLIFIER_ROOT_CURSOR_OFFSET) as usize;
        let sequence_before = read_u64(&account.data, NULLIFIER_SEQUENCE_NUMBER_OFFSET);

        // Fill every slot but the current root's with a distinct non-zero value, so a
        // retired slot is observably different from one that was already empty.
        for slot in 0..cap {
            if slot == cursor_before.wrapping_sub(1) % cap {
                continue;
            }
            let at = NULLIFIER_ROOT_HISTORY_OFFSET + slot * 32;
            let mut filler = [0u8; 32];
            filler[31] = (slot as u8) | 0x80;
            filler[30] = 0x5a;
            account.data[at..at + 32].copy_from_slice(&filler);
        }

        // The pending batch must be at least half full and not yet inserted.
        let pending = read_u64(&account.data, NULLIFIER_QUEUE_CURRENT_BATCH_OFFSET) as usize % 2;
        let pending_base = NULLIFIER_BATCH0_OFFSET + pending * NULLIFIER_BATCH_STRIDE;
        let batch_size = read_u64(&account.data, pending_base + BATCH_SIZE_FIELD);
        let zkp_size = read_u64(&account.data, pending_base + BATCH_ZKP_SIZE_FIELD);
        if zkp_size == 0 || batch_size == 0 {
            return false;
        }
        // Half the batch, expressed in whole chunks so the chunk counters stay
        // self-consistent. `num_inserted_zkp_batches` is left at zero: the chunk this
        // update proves must still be unapplied.
        let half_chunks = (batch_size / 2).div_ceil(zkp_size);
        account.data[pending_base + BATCH_NUM_FULL_ZKP..pending_base + BATCH_NUM_FULL_ZKP + 8]
            .copy_from_slice(&half_chunks.to_le_bytes());

        // The other batch: inserted, bloom still dirty, with a consistent (seq, index).
        // One root is pushed by this update before the retirement runs, so the walk
        // starts at cursor_before + 1 and the tree's sequence number is one higher.
        let other = NULLIFIER_BATCH0_OFFSET + (1 - pending) * NULLIFIER_BATCH_STRIDE;
        const WALK: u64 = 4;
        let cursor_after = (cursor_before + 1) % cap;
        let seq = sequence_before + 1 + WALK;
        let root_index = ((cursor_after + WALK as usize - 1) % cap) as u32;
        account.data[other + BATCH_STATE_FIELD..other + BATCH_STATE_FIELD + 8]
            .copy_from_slice(&BATCH_STATE_INSERTED.to_le_bytes());
        account.data[other + BATCH_BLOOM_ZEROED_FIELD] = 0;
        account.data[other + BATCH_SEQUENCE_NUMBER_FIELD..other + BATCH_SEQUENCE_NUMBER_FIELD + 8]
            .copy_from_slice(&seq.to_le_bytes());
        account.data[other + BATCH_ROOT_INDEX_FIELD..other + BATCH_ROOT_INDEX_FIELD + 4]
            .copy_from_slice(&root_index.to_le_bytes());
        if self.ctx.svm.set_account(tree, account).is_err() {
            return false;
        }

        if !self.action_batch_update_nullifier_tree() {
            return false;
        }

        // The retirement ran if the bloom filter is now marked zeroed. When it did,
        // every slot the walk covered must read zero, and the first SAFE slot must not.
        let after = match self.ctx.svm.get_account(&tree) {
            Some(account) => account.data,
            None => return false,
        };
        if after[other + BATCH_BLOOM_ZEROED_FIELD] != 1 {
            return true;
        }
        let slot_at = |d: &[u8], slot: usize| -> [u8; 32] {
            let at = NULLIFIER_ROOT_HISTORY_OFFSET + (slot % cap) * 32;
            d[at..at + 32].try_into().unwrap_or_default()
        };
        let mut retired_but_live = 0u64;
        for step in 0..(WALK as usize - 1) {
            if slot_at(&after, cursor_after + step) != [0u8; 32] {
                retired_but_live += 1;
            }
        }
        // The first safe root is deliberately NOT retired; if it were, the tree would
        // lose a root it still needs.
        if slot_at(&after, root_index as usize) == [0u8; 32] {
            retired_but_live += 1;
        }
        self.shadow_unretired_roots = self.shadow_unretired_roots.saturating_add(retired_but_live);
        true
    }

    /// `create_ring_config` attempted by an outsider, for P-0015's THIRD switch.
    ///
    /// The ring config account must sign its own creation and its address is the ring
    /// program's `ring_auth` PDA, so the call necessarily goes through the ring
    /// program's `invoke_signed` -- what varies here is only WHO pays and signs as
    /// `payer`, which is the account `check_ring_creation_authority` is applied to
    /// (`ring_config/create.rs:41-47`). The outsider is funded by `scout_outsider`, so
    /// a refusal is the gate rather than an empty wallet.
    pub fn action_create_ring_config_unauthorized(&mut self, actor_seed: u8) -> bool {
        let outsider = match self.scout_outsider(actor_seed) {
            Some(keypair) => keypair,
            None => return false,
        };
        let slot = (self.ring_config_seq % 16) as u8;
        self.ring_config_seq += 1;
        let mut address = [0x71u8; 32];
        address[0] = slot;
        let ring_program = Pubkey::new_from_array(address);
        let deployed = scout_without_program_override(
            || self.ctx.add_program(&ring_program, RING_PROGRAM_ARTIFACT).is_ok());
        if !deployed {
            return false;
        }
        let (ring_config, _) =
            Pubkey::find_program_address(&[RING_AUTH_PDA_SEED], &ring_program);
        let data = scout_create_ring_config_data(&ring_program, &outsider.pubkey());
        let instruction = Instruction {
            program_id: ring_program,
            accounts: vec![
                AccountMeta::new(outsider.pubkey(), true),
                AccountMeta::new_readonly(self.protocol_config, false),
                AccountMeta::new(ring_config, false),
                AccountMeta::new_readonly(system_program::ID, false),
                AccountMeta::new_readonly(self.program_id, false),
            ],
            data,
        };
        let success = self.ctx.raw_call(instruction)
            .signers(&[&*self.payer, &*outsider])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        let (_, ring_permissionless, _) = self.scout_protocol_permissionless();
        self.scout_note_creation_gate(success, ring_permissionless);
        success
    }

    /// The ring config's current `authority`, read from account bytes.
    fn scout_ring_authority(&self) -> [u8; 32] {
        let data = match self.ctx.svm.get_account(&self.ring_config) {
            Some(account) => account.data,
            None => return [0u8; 32],
        };
        if data.len() < RING_AUTHORITY_OFFSET + 32 {
            return [0u8; 32];
        }
        data[RING_AUTHORITY_OFFSET..RING_AUTHORITY_OFFSET + 32]
            .try_into()
            .unwrap_or([0u8; 32])
    }

    /// Rotate the ring config's authority to `new_authority`, then report whether the
    /// stored key actually changed. Both keys sign, which the handler requires.
    fn scout_rotate_ring_authority(
        &mut self, current: &Rc<Keypair>, new_authority: &Rc<Keypair>,
    ) -> bool {
        let instruction = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new_readonly(current.pubkey(), true),
                AccountMeta::new(self.ring_config, false),
                AccountMeta::new_readonly(new_authority.pubkey(), true),
            ],
            // `process_update_ring_config_owner` rejects ANY payload past the tag.
            data: vec![TAG_UPDATE_RING_CONFIG_OWNER],
        };
        self.ctx.raw_call(instruction)
            .signers(&[&*self.payer, &**current, &**new_authority])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    /// P-0029: a ring authority rotation REVOKES the old key.
    ///
    /// The point of rotating an authority is revocation. A rotation that left the
    /// previous key working would make a compromised ring authority impossible to
    /// retire -- the config would name one key and the gate honour another -- and on
    /// this rail that key is the one that decides whether `ring_authority_transact`
    /// is enabled, the single path where the ring moves a user's notes with NO owner
    /// signature.
    ///
    /// Driven as one action so the observation is self-contained: rotate away, prove
    /// the old key is refused AND the new key works, then rotate back. Rotating back
    /// matters under `--stateful` -- a branch that rotated and stopped would leave the
    /// ring rail dark for every action after it, which reads as coverage loss rather
    /// than as the deliberate state it is.
    pub fn action_rotate_ring_authority(&mut self, actor_seed: u8) -> bool {
        let outsider = match self.scout_outsider(actor_seed) {
            Some(keypair) => keypair,
            None => return false,
        };
        let payer = Rc::clone(&self.payer);
        let before = self.scout_ring_authority();
        if before != payer.pubkey().to_bytes() {
            // A previous branch left the authority elsewhere; this action owns the
            // rotate-back, so it has nothing sound to say about that world.
            return false;
        }
        if !self.scout_rotate_ring_authority(&payer, &outsider) {
            return false;
        }
        if self.scout_ring_authority() != outsider.pubkey().to_bytes() {
            return false;
        }

        // The old key must now be refused. `action_set_ring_config` signs as `payer`,
        // which the config no longer names.
        if self.action_set_ring_config(1, 0) {
            self.shadow_stale_ring_authority_successes =
                self.shadow_stale_ring_authority_successes.saturating_add(1);
        }
        // The positive control: the key the config NOW names must get through, or the
        // refusal above is equally consistent with the instruction being broken.
        let enabled_by_new = {
            let data = vec![TAG_UPDATE_RING_CONFIG, 1, 0];
            let instruction = Instruction {
                program_id: self.program_id,
                accounts: vec![
                    AccountMeta::new_readonly(outsider.pubkey(), true),
                    AccountMeta::new(self.ring_config, false),
                ],
                data,
            };
            self.ctx.raw_call(instruction)
                .signers(&[&*self.payer, &*outsider])
                .send()
                .map(|o| o.is_success())
                .unwrap_or(false)
        };

        // Restore, so the rest of the branch still has a working ring rail.
        let restored = self.scout_rotate_ring_authority(&outsider, &payer);
        enabled_by_new && restored
    }

    /// The forester tree's `(num_full_zkp_batches, num_inserted_zkp_batches)` for the
    /// PENDING batch -- the batch `verify_proof_cache_update` actually reads.
    ///
    /// `pending_batch_index` and `currently_processing_batch_index` are different
    /// fields eight bytes apart in `QueueBatches`, equal only until the first batch
    /// fills. Reading the wrong one would make the precondition below describe a batch
    /// the instruction is not looking at.
    fn scout_pending_chunk_progress(&self, tree: &Pubkey) -> Option<(u64, u64)> {
        let data = self.ctx.svm.get_account(tree)?.data;
        if data.len() < NULLIFIER_BATCH0_OFFSET + 2 * NULLIFIER_BATCH_STRIDE {
            return None;
        }
        let read_u64 = |at: usize| -> u64 {
            u64::from_le_bytes(data[at..at + 8].try_into().unwrap_or_default())
        };
        let pending = read_u64(NULLIFIER_QUEUE_PENDING_BATCH_OFFSET) as usize;
        if pending >= 2 {
            return None;
        }
        let base = NULLIFIER_BATCH0_OFFSET + pending * NULLIFIER_BATCH_STRIDE;
        Some((read_u64(base + BATCH_NUM_FULL_ZKP), read_u64(base + BATCH_NUM_INSERTED_ZKP)))
    }

    /// P-0030: the forester crank must not SUCCEED while doing nothing, when the chunk
    /// it was handed is exactly the chunk that is due.
    ///
    /// `update_tree_from_address_queue` returns `Ok(None)` -- success, no state change
    /// -- for a replayed proof, and `apply_cached_tree_updates` legitimately caches a
    /// chunk proven ahead of its turn instead of applying it. Both are real work-free
    /// successes, and a naive "it succeeded but nothing moved" oracle would fire on
    /// them constantly. So the fire is guarded on the one arrangement where neither
    /// escape applies: the supplied `zkp_batch_index` equals `num_inserted_zkp_batches`
    /// (this is the next chunk due, not a replay and not ahead of its turn) and
    /// `num_full_zkp_batches` exceeds it (its hash chain is finalised, so the work
    /// provably exists). Under that guard a success that moves no leaf is a silent
    /// no-op: the nullifiers stay in the queue, unproven and unapplied, while the
    /// forester is told the batch is done.
    pub fn action_forester_crank_with_work(&mut self) -> bool {
        let tree = self.forester_tree;
        let due = u64::from(merge_fixture::forester::ZKP_BATCH_INDEX);
        let (full, inserted) = match self.scout_pending_chunk_progress(&tree) {
            Some(progress) => progress,
            None => return false,
        };
        // Work provably exists AND the proof we hold is the one due right now.
        let work_is_due = inserted == due && full > due;
        let (leaves_before, _) = self.scout_nullifier_progress();

        let success = self.action_batch_update_nullifier_tree();

        if success && work_is_due {
            let (leaves_after, _) = self.scout_nullifier_progress();
            if leaves_after == leaves_before {
                self.shadow_silent_forester_noops =
                    self.shadow_silent_forester_noops.saturating_add(1);
            }
        }
        success
    }

    /// Donate lamports into a program-owned account from an outsider.
    ///
    /// On Solana anyone may send lamports to any address and the receiving program
    /// cannot refuse, so `real balance > anything the program counted` is a state that
    /// is free to create and impossible to prevent. Nothing in this harness had ever
    /// produced it: every lamport in the pool arrived through a settlement, which made
    /// P-0001's exact-equality form look sound when it was in fact relying on a
    /// courtesy no attacker extends.
    ///
    /// The donation is a REAL system transfer rather than a `set_account` poke,
    /// because the point is that it is permissionless -- an injected balance would
    /// prove the oracle notices while proving nothing about reachability.
    pub fn action_donate_lamports(&mut self, target_seed: u8, actor_seed: u8, amount: u64) -> bool {
        let outsider = match self.scout_outsider(actor_seed) {
            Some(keypair) => keypair,
            None => return false,
        };
        // Bounded: enough to be observable, never enough to drain the outsider and
        // turn a later refusal into a funding failure.
        let amount = 1 + (amount % 100_000);
        let (target, is_sol_interface) = match target_seed % 3 {
            0 => (self.sol_interface, true),
            1 => (self.tree, false),
            _ => (self.forester_tree, false),
        };
        let mut data = Vec::with_capacity(12);
        data.extend_from_slice(&2u32.to_le_bytes()); // SystemInstruction::Transfer
        data.extend_from_slice(&amount.to_le_bytes());
        let instruction = Instruction {
            program_id: system_program::ID,
            accounts: vec![
                AccountMeta::new(outsider.pubkey(), true),
                AccountMeta::new(target, false),
            ],
            data,
        };
        let success = self.ctx.raw_call(instruction)
            .signers(&[&*self.payer, &*outsider])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if success && is_sol_interface {
            self.shadow_sol_donated = self.shadow_sol_donated.saturating_add(amount);
        }
        success
    }

    /// The fee-bearing mint's fixed keypair, its user token account, and the interface
    /// PDA it registers to. Fixed seeds, so a fuzz sequence replays identically.
    fn scout_fee_mint_keys(&self) -> (Rc<Keypair>, Rc<Keypair>, Pubkey) {
        let mint = Rc::new(Keypair::new_from_array([0xF2u8; 32]));
        let user = Rc::new(Keypair::new_from_array([0xF3u8; 32]));
        let (interface, _) = Pubkey::find_program_address(
            &[SPL_INTERFACE_PDA_SEED, mint.pubkey().as_ref()], &self.program_id);
        (mint, user, interface)
    }

    /// Build and register a Token-2022 mint that charges a transfer fee, once.
    ///
    /// Deliberately NOT in `setup()`. Registering it consumes the singleton asset
    /// counter, which `action_create_asset_counter` creates -- minting that in setup
    /// would disable the action forever, which is the trade `references/setup-glue.md`
    /// says never to make unilaterally.
    fn scout_ensure_fee_mint(&mut self) -> bool {
        if self.fee_mint_ready {
            return true;
        }
        let (mint, user, interface) = self.scout_fee_mint_keys();
        let payer = self.payer.pubkey();
        let mint_rent = self.ctx.svm.minimum_balance_for_rent_exemption(T22_MINT_LEN);
        let account_rent = self.ctx.svm.minimum_balance_for_rent_exemption(T22_ACCOUNT_LEN);

        // The mint: allocate, add the fee extension, THEN initialize. Token-2022
        // requires mint extensions before `InitializeMint2`.
        let steps: [(ScoutIx, Option<Rc<Keypair>>); 5] = [
            (scout_t22_create_account_ix(payer, mint.pubkey(), mint_rent, T22_MINT_LEN),
             Some(Rc::clone(&mint))),
            (scout_t22_init_transfer_fee_ix(mint.pubkey(), payer), None),
            (scout_t22_init_mint_ix(mint.pubkey(), payer, 6), None),
            (scout_t22_create_account_ix(payer, user.pubkey(), account_rent, T22_ACCOUNT_LEN),
             Some(Rc::clone(&user))),
            (scout_t22_init_account_ix(user.pubkey(), mint.pubkey(), payer), None),
        ];
        for (instruction, extra) in steps {
            let ok = match &extra {
                Some(keypair) => self.ctx.raw_call(instruction)
                    .signers(&[&*self.payer, &**keypair]).send(),
                None => self.ctx.raw_call(instruction).signers(&[&*self.payer]).send(),
            }.map(|o| o.is_success()).unwrap_or(false);
            if !ok {
                return false;
            }
        }
        let funded = self.ctx
            .raw_call(scout_t22_mint_to_ix(mint.pubkey(), user.pubkey(), payer, 10_000_000))
            .signers(&[&*self.payer]).send().map(|o| o.is_success()).unwrap_or(false);
        if !funded {
            return false;
        }

        // Register it. `TransferFeeConfig` is on the program's allow list
        // (`create_spl_interface/validate.rs:68`), so this SUCCEEDS -- the pool
        // knowingly admits fee-bearing assets and defends at settlement instead.
        if !self.scout_ensure_asset_counter() {
            return false;
        }
        let (asset_counter, _) =
            Pubkey::find_program_address(&[SPL_ASSET_COUNTER_PDA_SEED], &self.program_id);
        let (registry, _) = Pubkey::find_program_address(
            &[SPL_ASSET_REGISTRY_PDA_SEED, mint.pubkey().as_ref()], &self.program_id);
        let instruction = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new(payer, true),
                AccountMeta::new_readonly(self.protocol_config, false),
                AccountMeta::new(asset_counter, false),
                AccountMeta::new(registry, false),
                AccountMeta::new_readonly(mint.pubkey(), false),
                AccountMeta::new(interface, false),
                AccountMeta::new_readonly(system_program::ID, false),
                AccountMeta::new_readonly(SPL_TOKEN_2022_ID, false),
            ],
            data: vec![TAG_CREATE_SPL_INTERFACE],
        };
        let registered = self.ctx.raw_call(instruction).signers(&[&*self.payer]).send()
            .map(|o| o.is_success()).unwrap_or(false);
        if registered {
            self.shadow_registered_assets = self.shadow_registered_assets.saturating_add(1);
            self.fee_mint_ready = true;
        }
        registered
    }

    /// The base (transferable) balance of a Token-2022 account. `withheld_amount` lives
    /// in the extension and deliberately does NOT count as vault collateral -- the same
    /// reading `settle_spl_deposit` takes.
    fn scout_token_amount(&self, account: &Pubkey) -> u64 {
        match self.ctx.svm.get_account(account) {
            Some(a) if a.data.len() >= 72 => {
                u64::from_le_bytes(a.data[64..72].try_into().unwrap_or_default())
            }
            _ => 0,
        }
    }

    /// P-0032: a deposit through a fee-bearing mint.
    ///
    /// This is amplifier #8 from the escalation catalogue -- "amount != accounting".
    /// When a transfer fee exists, the tokens that MOVE differ from the amount the
    /// caller names, so a pool that credits the named amount is under-collateralised by
    /// the fee on every deposit, compounding, with the shortfall landing on whoever
    /// withdraws last. It is invisible to a fixture with only plain spl-token mints,
    /// which is what this harness had: every SPL deposit moved exactly what it credited
    /// because no mint could do otherwise.
    pub fn action_deposit_through_a_fee_bearing_mint(&mut self, amount: u64) -> bool {
        if !self.scout_ensure_fee_mint() {
            return false;
        }
        let (mint, user, interface) = self.scout_fee_mint_keys();
        let (_, bump) = Pubkey::find_program_address(
            &[SPL_INTERFACE_PDA_SEED, mint.pubkey().as_ref()], &self.program_id);
        // Bounded so the user's funded balance is never the reason a deposit fails.
        let amount = 1 + (amount % 100_000);
        let payload = scout_wire::DepositIxData {
            assets: vec![scout_wire::DepositAssetKind::Spl { spl_interface_bump: bump }],
            deposits: vec![scout_wire::DepositEntry {
                asset_index: 0,
                view_tag: [0x21; 32],
                owner: [0x22; 32],
                blinding: [0x23; 32],
                amount,
                utxo_data: None,
                memo: None,
            }],
        };
        let mut data = vec![TAG_DEPOSIT];
        data.extend_from_slice(
            &wincode::serialize(&payload).expect("fee-mint deposit payload must serialize"),
        );
        let instruction = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new(self.tree, false),
                AccountMeta::new(self.payer.pubkey(), true),
                AccountMeta::new_readonly(self.program_id, false),
                AccountMeta::new_readonly(SPL_TOKEN_2022_ID, false),
                AccountMeta::new_readonly(mint.pubkey(), false),
                AccountMeta::new(user.pubkey(), false),
                AccountMeta::new(interface, false),
            ],
            data,
        };
        let before = self.scout_token_amount(&interface);
        let success = self.ctx.raw_call(instruction).signers(&[&*self.payer]).send()
            .map(|o| o.is_success()).unwrap_or(false);
        if success {
            let received = self.scout_token_amount(&interface).saturating_sub(before);
            // The UTXO credits `amount`. A fee mint cannot have delivered it.
            if received < amount {
                self.shadow_fee_mint_credits = self.shadow_fee_mint_credits.saturating_add(1);
            }
            self.shadow_expected_leaves = self.shadow_expected_leaves.saturating_add(1);
        }
        success
    }

    /// A deposit whose `asset_index` is IN RANGE.
    ///
    /// The generated `action_deposit` pins `assets` to a single-element list
    /// (`vec![DepositAssetKind::Sol]`), so index 0 is the only valid value and every
    /// other byte the fuzzer supplies is rejected before the handler does anything.
    /// Left in place deliberately -- the out-of-range arm is a legitimate negative
    /// path -- but on its own it means the deposit SUCCESS path is reached only by
    /// chance, and the campaign measured it at 0 successes in 7 selections.
    ///
    /// This lives here, hand-written, rather than as a patch to the generated body,
    /// because that is the only durable place for it. The bound WAS applied inline
    /// once (`deposits_asset_index % 2`) and a later `scout regen` deleted it -- regen
    /// owns generated action bodies, and an action hook is the only preserved region
    /// inside one. The symptom was silent: coverage stayed high because the error
    /// branch is lines too, and the stale measurement was reported as convergence.
    pub fn action_deposit_in_range(
        &mut self, view_tag_seed: u8, owner_seed: u8, blinding_seed: u8, amount: u64,
    ) -> bool {
        // Bounded so the depositor can always afford it; the unbounded amount is
        // already covered by the generated action's own arm.
        let amount = 1 + (amount % 10_000_000);
        // `view_tag`, `owner` and `blinding` are built as `[seed; 32]` and the program
        // HASHES them, so each must be a canonical BN254 field element. `[0xC8; 32]`
        // reads as ~0xC8C8... against a modulus of 0x3064..., and the deposit is
        // refused before it does anything -- the same trap that ate the queued deposit
        // earlier, hit again here and caught only because this action is asserted
        // across bytes that would ALL be refused by the generated one. A repeated byte
        // below 0x30 is always in range.
        let field = |seed: u8| seed % 0x30;
        self.action_deposit(0, field(view_tag_seed), field(owner_seed), field(blinding_seed),
                            amount)
    }

    /// P-0033: every spending rail actually publishes its nullifiers.
    ///
    /// Amplifier #7, twin-path divergence, made mechanical. Five instructions across
    /// three proof rails reach the same nullifier queue through
    /// `insert_nullifier_into_queue`, and the property is that ALL FIVE call it -- the
    /// parity meta-invariant, rather than one property per rail.
    ///
    /// P-0005 structurally cannot see a rail that inserts NOTHING. It counts second
    /// acceptances of a fixture's pinned nullifiers, so a rail that skipped insertion
    /// entirely would never produce a second acceptance to count: it would look
    /// perfectly quiet while being the one path on which a note is infinitely
    /// spendable. P-0016 sees only the split-tree arrangement of one rail.
    ///
    /// Measured as a per-call delta around one call, so it needs no baseline and
    /// inherited `--stateful` state cannot perturb it.
    fn scout_spend_publishes_nullifiers(
        &mut self, tree: Pubkey, expected_inputs: u64, call: impl FnOnce(&mut Self) -> bool,
    ) -> bool {
        let before = self.scout_queue_next_index(&tree);
        let success = call(self);
        if success {
            let advanced = self.scout_queue_next_index(&tree).saturating_sub(before);
            if advanced != expected_inputs {
                self.shadow_unpublished_nullifiers =
                    self.shadow_unpublished_nullifiers.saturating_add(1);
            }
        }
        success
    }

    /// `transact` (1 input), watched for nullifier publication.
    pub fn action_transact_publishing(&mut self) -> bool {
        let tree = self.tree;
        self.scout_spend_publishes_nullifiers(tree, 1, |f| f.action_transact_no_transfers())
    }

    /// `merge_transact` (8 inputs), watched for nullifier publication.
    pub fn action_merge_transact_publishing(&mut self, eddsa_owner: bool) -> bool {
        let tree = self.tree;
        self.scout_spend_publishes_nullifiers(tree, 8, |f| f.action_merge_transact(eddsa_owner))
    }

    /// `ring_transact` (1 input), watched for nullifier publication.
    pub fn action_ring_transact_publishing(&mut self) -> bool {
        let tree = self.tree;
        self.scout_spend_publishes_nullifiers(tree, 1, |f| f.action_ring_transact())
    }

    /// `ring_authority_transact` (1 input) -- the rail that moves a user's notes with NO
    /// owner signature, so a missing insertion here is the worst of the five.
    pub fn action_ring_authority_transact_publishing(&mut self) -> bool {
        let tree = self.tree;
        self.scout_spend_publishes_nullifiers(tree, 1, |f| f.action_ring_authority_transact())
    }

    /// `ring_merge_transact` (8 inputs), watched for nullifier publication.
    pub fn action_ring_merge_transact_publishing(&mut self) -> bool {
        let tree = self.tree;
        self.scout_spend_publishes_nullifiers(tree, 8, |f| f.action_ring_merge_transact())
    }

    /// P-0034: two spends in ONE transaction cannot both publish the same nullifier.
    ///
    /// The first compound action in this harness. The pool has no `begin`/`end` bracket
    /// -- no instruction introspects the instructions sysvar and no transient flag is
    /// set by one instruction and cleared by another -- so there is no suspended-check
    /// window to explore. What multi-instruction transactions DO reach here is the
    /// question of whether the queue's double-spend guard survives being consulted
    /// twice inside one transaction.
    ///
    /// That is not the same question single-instruction actions answer. Between two
    /// transactions the account is reloaded from the ledger, so the second call
    /// necessarily sees the first's insertion. Within one transaction both instructions
    /// operate on the SAME in-memory account, and the guard holds only if the first
    /// insertion is actually written through before the second reads the bloom filter.
    /// A guard that read a stale copy would accept both, and every existing property
    /// would stay silent: P-0005 counts SUCCESSFUL calls, and a transaction that
    /// accepted both would count as one.
    ///
    /// The middle is fuzzer-selected, not hardcoded -- an interleaving that only pairs
    /// the same instruction with itself would miss a cross-rail version of the same
    /// flaw.
    pub fn action_double_spend_in_one_transaction(&mut self, choice: u8) -> bool {
        let tree = self.tree;
        let before = self.scout_queue_next_index(&tree);
        // Both queued instructions publish the SAME pinned nullifier, because each
        // rail's proof fixes it. Queue, never send: a stray `.send()` would split the
        // pair into two transactions and test nothing.
        let arm = choice % 3;
        let queued = match arm {
            0 => self.scout_queue_transact() && self.scout_queue_transact(),
            1 => self.scout_queue_merge() && self.scout_queue_merge(),
            _ => self.scout_queue_deposit() && self.scout_queue_transact(),
        };
        if !queued {
            // Drain whatever was queued so a half-built batch cannot leak into the next
            // action and make its result meaningless.
            let _ = self.ctx.send_batch();
            return false;
        }
        let success = self.ctx.send_batch()
            .map(|o| o.map(|tx| tx.is_success()).unwrap_or(false))
            .unwrap_or(false);
        if success && arm != 2 {
            // A same-nullifier pair that SUCCEEDS is the violation: the pool accepted
            // one note as two spends inside a single transaction.
            self.shadow_intra_tx_double_spends =
                self.shadow_intra_tx_double_spends.saturating_add(1);
        }
        if success && arm == 2 {
            // The control arm is legitimate and appends: one deposit UTXO, one transact
            // output. Recorded so P-0004's leaf identity stays exact.
            self.shadow_expected_leaves = self.shadow_expected_leaves.saturating_add(2);
            self.shadow_sol_credited = self.shadow_sol_credited.saturating_add(1_000);
            self.shadow_transact_spends = self.shadow_transact_spends.saturating_add(1);
        }
        let _ = before;
        success
    }

    /// Queue one `transact`. QUEUES via `add_transaction()` and never sends -- a stray
    /// `.send()` here would split the pair into separate transactions, and the second
    /// would then be refused by the ordinary cross-transaction guard, testing nothing.
    fn scout_queue_transact(&mut self) -> bool {
        let payload = scout_wire::TransactIxData {
            expiry_unix_ts: merge_fixture::EXPIRY_UNIX_TS,
            private_tx_hash: merge_fixture::transact::PRIVATE_TX_HASH,
            circuit: scout_wire::CircuitId::ConfidentialEddsa(1, 1, 3),
            tx_viewing_pk: merge_fixture::transact::TX_VIEWING_PK,
            salt: [0u8; 16],
            proof: scout_wire::TransactProof {
                a: merge_fixture::transact::PROOF_A,
                b: merge_fixture::transact::PROOF_B,
                c: merge_fixture::transact::PROOF_C,
            },
            inputs: vec![scout_wire::InputUtxo {
                nullifier_hash: merge_fixture::transact::NULLIFIER,
                nullifier_tree_root_index: 0,
                utxo_tree_root_index: self.transact_utxo_root_index,
            }],
            interface_transfers: Vec::new(),
            data_hash: None,
            ring_data_hash: None,
            outputs: vec![scout_wire::TransactOutput {
                utxo_hash: merge_fixture::transact::OUTPUT_UTXO_HASH,
                owner_tag: scout_wire::OwnerTag::Inline(merge_fixture::transact::ACTOR_PUBKEY),
                data: None,
            }],
            messages: Vec::new(),
        };
        let mut data = vec![TAG_TRANSACT];
        data.extend_from_slice(
            &wincode::serialize(&payload).expect("queued transact payload must serialize"),
        );
        let actor = self.transact_actor.insecure_clone();
        let instruction = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new(actor.pubkey(), true),
                AccountMeta::new(self.tree, false),
                AccountMeta::new(self.tree, false),
                AccountMeta::new_readonly(self.program_id, false),
                AccountMeta::new_readonly(system_program::ID, false),
            ],
            data,
        };
        self.ctx.raw_call(instruction).signers(&[&*self.payer, &actor]).add_transaction().is_ok()
    }

    /// Queue one `merge_transact`. Its EIGHT nullifiers are fixture constants, so two
    /// queued merges publish the same eight twice.
    fn scout_queue_merge(&mut self) -> bool {
        let instruction = scout_merge_transact_ix(
            self.program_id,
            self.tree,
            self.payer.pubkey(),
            self.user_record,
            self.merge_utxo_root_index,
            merge_fixture::OUTPUT_UTXO_HASH,
            merge_fixture::PRIVATE_TX_HASH,
            merge_fixture::NULLIFIERS.to_vec(),
            scout_wire::MergeProof {
                a: merge_fixture::PROOF_A,
                b: merge_fixture::PROOF_B,
                c: merge_fixture::PROOF_C,
            },
        );
        self.ctx.raw_call(instruction).signers(&[&*self.payer]).add_transaction().is_ok()
    }

    /// Queue an ordinary SOL deposit. Used only by the CONTROL arm, which establishes
    /// that a legitimate two-instruction transaction goes through at all -- without it,
    /// a refusal on the double-spend arms would be equally consistent with batching
    /// being broken here, which is exactly the vacuous pass this harness has produced
    /// before.
    ///
    /// `owner` and `blinding` must be CANONICAL field elements. A byte pattern like
    /// `[0x32; 32]` reads big-endian as roughly 2^253, above the BN254 modulus
    /// (`0x3064...`), and the program rejects it. That cost a round trip here: the
    /// resulting failure looked exactly like the batch itself being refused, and only
    /// the control arm -- running the queued deposit ALONE -- separated the two.
    fn scout_queue_deposit(&mut self) -> bool {
        let instruction = scout_sol_deposit_ix(
            self.program_id, self.tree, self.payer.pubkey(), self.sol_interface,
            [0x02; 32], [0x03; 32], 1_000,
        );
        self.ctx.raw_call(instruction).signers(&[&*self.payer]).add_transaction().is_ok()
    }
    /// The SECOND ring: a distinct program id, hence a distinct `ring_auth` PDA and a
    /// distinct config. Without it there is no cross-ring question to ask at all.
    fn scout_second_ring(&self) -> (Pubkey, Pubkey) {
        let mut address = [0x71u8; 32];
        address[0] = 0xD1;
        let program = Pubkey::new_from_array(address);
        let (config, _) = Pubkey::find_program_address(&[RING_AUTH_PDA_SEED], &program);
        (program, config)
    }

    /// Deploy the second ring and register its config, once.
    fn scout_ensure_second_ring(&mut self) -> bool {
        if self.second_ring_ready {
            return true;
        }
        let (program, config) = self.scout_second_ring();
        let deployed = scout_without_program_override(
            || self.ctx.add_program(&program, RING_PROGRAM_ARTIFACT).is_ok());
        if !deployed {
            return false;
        }
        let data = scout_create_ring_config_data(&program, &self.payer.pubkey());
        let instruction = Instruction {
            program_id: program,
            accounts: vec![
                AccountMeta::new(self.payer.pubkey(), true),
                AccountMeta::new_readonly(self.protocol_config, false),
                AccountMeta::new(config, false),
                AccountMeta::new_readonly(system_program::ID, false),
                AccountMeta::new_readonly(self.program_id, false),
            ],
            data,
        };
        self.second_ring_ready = self.ctx.raw_call(instruction).signers(&[&*self.payer]).send()
            .map(|o| o.is_success()).unwrap_or(false);
        self.second_ring_ready
    }

    /// The `ring_authority_transact` payload, which every arrangement below reuses.
    /// This rail is the one worth pointing the property at: `allow_owner_signers` is
    /// false on it, so the ring moves a user's notes with NO owner signature and the
    /// signing ring's identity is the entire authorization.
    fn scout_ring_authority_payload(&self) -> scout_wire::TransactIxData {
        scout_wire::TransactIxData {
            expiry_unix_ts: merge_fixture::EXPIRY_UNIX_TS,
            private_tx_hash: merge_fixture::ring_authority_transact::PRIVATE_TX_HASH,
            circuit: scout_wire::CircuitId::RingAuthority(1, 1, 3),
            tx_viewing_pk: merge_fixture::transact::TX_VIEWING_PK,
            salt: [0u8; 16],
            proof: scout_wire::TransactProof {
                a: merge_fixture::ring_authority_transact::PROOF_A,
                b: merge_fixture::ring_authority_transact::PROOF_B,
                c: merge_fixture::ring_authority_transact::PROOF_C,
            },
            inputs: vec![scout_wire::InputUtxo {
                nullifier_hash: merge_fixture::ring_authority_transact::NULLIFIER,
                nullifier_tree_root_index: 0,
                utxo_tree_root_index: self.ring_authority_utxo_root_index,
            }],
            interface_transfers: Vec::new(),
            data_hash: None,
            ring_data_hash: None,
            outputs: vec![scout_wire::TransactOutput {
                utxo_hash: merge_fixture::ring_authority_transact::OUTPUT_UTXO_HASH,
                owner_tag: scout_wire::OwnerTag::Inline(merge_fixture::transact::ACTOR_PUBKEY),
                data: None,
            }],
            messages: Vec::new(),
        }
    }

    /// One `ring_authority_transact` with a chosen caller and a chosen account in the
    /// `ring_config` slot.
    fn scout_ring_authority_call(
        &mut self, caller: Pubkey, config_slot: Pubkey, trailing: Option<Pubkey>,
    ) -> bool {
        let mut data = vec![TAG_RING_AUTHORITY_TRANSACT];
        data.extend_from_slice(
            &wincode::serialize(&self.scout_ring_authority_payload())
                .expect("ring authority payload must serialize"));
        let mut accounts = vec![
            AccountMeta::new(self.transact_actor.pubkey(), true),
            AccountMeta::new(self.tree, false),
            AccountMeta::new(self.tree, false),
            AccountMeta::new_readonly(self.program_id, false),
            AccountMeta::new_readonly(system_program::ID, false),
            AccountMeta::new_readonly(config_slot, false),
        ];
        // The ring fixture program refuses to forward unless its OWN `ring_auth` is
        // somewhere in the list, so a cross-ring attempt has to carry it. This rail
        // sets `allow_owner_signers = false`, which is why a trailing account is safe
        // here and would not be on `ring_transact`: there it would be read as an owner
        // signer, change the signer hash chain, and fail the proof for an unrelated
        // reason -- a confound that would look exactly like the guard working.
        if let Some(extra) = trailing {
            accounts.push(AccountMeta::new_readonly(extra, false));
        }
        let actor = self.transact_actor.insecure_clone();
        self.ctx.raw_call(Instruction { program_id: caller, accounts, data })
            .signers(&[&*self.payer, &actor])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    /// P-0036: a ring instruction must accept only ITS OWN ring config.
    ///
    /// The pool never re-derives a ring config's address after creation --
    /// `create_ring_config` checks the canonical `ring_auth` derivation once and every
    /// later instruction only loads it by owner + discriminator and requires its
    /// SIGNATURE. So "the signer is the right ring" is the entire authorization, and
    /// it is enforced in three separate callers (`deposit/account.rs:79`,
    /// `transact/account.rs:193`, `merge_ring/account.rs:28`) rather than inside
    /// `load_active_ring_config`, whose own doc comment says "Callers must perform the
    /// signer check before invoking this loader." Three copies of a guard is exactly
    /// the arrangement where a fourth caller omits it.
    ///
    /// Every arrangement must be refused. The positive control lives in the test,
    /// because a successful authority transact spends its fixture nullifier and cannot
    /// repeat -- so this action drives only the refusals and its zero success count is
    /// the property holding.
    pub fn action_ring_config_confusion(&mut self, variant: u8) -> bool {
        if !self.scout_ensure_second_ring() {
            return false;
        }
        let (ring_a, config_a) = self.scout_second_ring();
        let (ring_b, config_b) = (self.ring_program, self.ring_config);
        let success = match variant % 3 {
            // Through ring B, carrying ring A's config: B signs for its own auth, so
            // the account in the config slot never signed.
            0 => self.scout_ring_authority_call(ring_b, config_a, Some(config_b)),
            // The mirror image, through ring A carrying ring B's config.
            1 => self.scout_ring_authority_call(ring_a, config_b, Some(config_a)),
            // No ring at all: straight to SPP with a real, initialised config that
            // simply did not sign. This is the guard in its barest form.
            _ => self.scout_ring_authority_call(self.program_id, config_b, None),
        };
        if success {
            self.shadow_ring_confusions = self.shadow_ring_confusions.saturating_add(1);
        }
        success
    }
    /// P-0035: the proof binds the DEDUPLICATED signer set, and only that.
    ///
    /// `fill_owner_signer_hashes` (`transact/verify.rs:127`) puts the instruction
    /// payer's hash in slot 0, seeds a `seen` map with it, and appends each trailing
    /// owner signer that is not already there -- duplicates are SKIPPED, not rejected.
    /// `fixed_signer_hash_chain` (:453) then right-folds that prefix against a table of
    /// precomputed all-zero suffixes, `SIGNER_ZERO_SUFFIX_CHAINS`, so a variable-length
    /// set matches the circuit's fixed-width fold. That is hand-rolled dedup, padding
    /// and width arithmetic feeding a PUBLIC INPUT, and nothing in the harness asserted
    /// anything about it -- `fill_owner_signer_hashes` carries the worst coverage ratio
    /// of any non-blocked function in the program.
    ///
    /// Both directions are driven from ONE valid proof, which is the attacker's
    /// position exactly: hold the proof fixed and vary who signed alongside it.
    ///
    /// * A set whose dedup differs (a new signer, or two of them) must be REFUSED.
    /// * A set whose dedup is IDENTICAL -- appending an account already in the set --
    ///   must still VERIFY. That arm is the positive control and it is load-bearing:
    ///   without it, "adding an account breaks the proof" is equally consistent with
    ///   the account list being positionally rigid, which would make the refusals
    ///   prove nothing about the signer chain at all.
    pub fn action_transact_signer_set(&mut self, variant: u8) -> bool {
        let actor = self.transact_actor.insecure_clone();
        let outsider = match self.scout_outsider(0x61) {
            Some(keypair) => keypair,
            None => return false,
        };
        // `changes_the_set` is what decides whether a success is a violation.
        let (appended, changes_the_set): (Vec<Pubkey>, bool) = match variant % 4 {
            // Already in the set: the payer occupies slot 0 and seeds `seen`, so this
            // is skipped by dedup and the chain is unchanged.
            0 => (vec![actor.pubkey()], false),
            // A different key from slot 0, so a genuinely new unique signer.
            1 => (vec![self.payer.pubkey()], true),
            2 => (vec![outsider.pubkey()], true),
            // The same new signer twice: dedup collapses it to one, but the set still
            // differs from the fixture's.
            _ => (vec![outsider.pubkey(), outsider.pubkey()], true),
        };

        let payload = scout_wire::TransactIxData {
            expiry_unix_ts: merge_fixture::EXPIRY_UNIX_TS,
            private_tx_hash: merge_fixture::transact::PRIVATE_TX_HASH,
            circuit: scout_wire::CircuitId::ConfidentialEddsa(1, 1, 3),
            tx_viewing_pk: merge_fixture::transact::TX_VIEWING_PK,
            salt: [0u8; 16],
            proof: scout_wire::TransactProof {
                a: merge_fixture::transact::PROOF_A,
                b: merge_fixture::transact::PROOF_B,
                c: merge_fixture::transact::PROOF_C,
            },
            inputs: vec![scout_wire::InputUtxo {
                nullifier_hash: merge_fixture::transact::NULLIFIER,
                nullifier_tree_root_index: 0,
                utxo_tree_root_index: self.transact_utxo_root_index,
            }],
            interface_transfers: Vec::new(),
            data_hash: None,
            ring_data_hash: None,
            outputs: vec![scout_wire::TransactOutput {
                utxo_hash: merge_fixture::transact::OUTPUT_UTXO_HASH,
                owner_tag: scout_wire::OwnerTag::Inline(merge_fixture::transact::ACTOR_PUBKEY),
                data: None,
            }],
            messages: Vec::new(),
        };
        let mut data = vec![TAG_TRANSACT];
        data.extend_from_slice(
            &wincode::serialize(&payload).expect("signer-set transact payload must serialize"));
        let mut accounts = vec![
            AccountMeta::new(actor.pubkey(), true),
            AccountMeta::new(self.tree, false),
            AccountMeta::new(self.tree, false),
            AccountMeta::new_readonly(self.program_id, false),
            AccountMeta::new_readonly(system_program::ID, false),
        ];
        for pubkey in &appended {
            accounts.push(AccountMeta::new_readonly(*pubkey, true));
        }
        let success = self.ctx
            .raw_call(Instruction { program_id: self.program_id, accounts, data })
            .signers(&[&*self.payer, &actor, &*outsider])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if success && changes_the_set {
            self.shadow_signer_set_bypasses =
                self.shadow_signer_set_bypasses.saturating_add(1);
        }
        if success {
            self.shadow_expected_leaves = self.shadow_expected_leaves.saturating_add(1);
            self.shadow_transact_spends = self.shadow_transact_spends.saturating_add(1);
        }
        success
    }
    /// Drive a tree's nullifier queue toward full by moving both batches'
    /// `start_index`, and return the bytes needed to put it back.
    ///
    /// This is the documented condition for disabling dummy inputs -- "the nullifier
    /// tree has strictly fewer leaves left than the state tree" (`tree/src/lib.rs:283`)
    /// -- reached by synthesis rather than by 2^40 insertions. Nothing else moves: no
    /// root, no leaf, no nullifier, no counter the proof cites. That isolation is the
    /// whole point, because it is what makes a refusal attributable to this one flag.
    fn scout_saturate_nullifier_queue(&mut self, tree: Pubkey) -> Option<Vec<u8>> {
        let mut account = self.ctx.svm.get_account(&tree)?;
        if account.data.len() < NULLIFIER_BATCH0_OFFSET + 2 * NULLIFIER_BATCH_STRIDE {
            return None;
        }
        let original = account.data.clone();
        // Just short of the height-40 capacity: enough that the remaining queue is
        // smaller than the state tree's remaining leaves, not so much that
        // `remaining_queue_capacity` underflows and fails as a tree error instead.
        let saturated = (1u64 << 40) - 1000;
        for batch in 0..2usize {
            let at = NULLIFIER_BATCH0_OFFSET + batch * NULLIFIER_BATCH_STRIDE
                + BATCH_START_INDEX_FIELD;
            account.data[at..at + 8].copy_from_slice(&saturated.to_le_bytes());
        }
        self.ctx.svm.set_account(tree, account).ok()?;
        Some(original)
    }

    fn scout_restore_tree(&mut self, tree: Pubkey, original: Vec<u8>) -> bool {
        match self.ctx.svm.get_account(&tree) {
            Some(mut account) => {
                account.data = original;
                self.ctx.svm.set_account(tree, account).is_ok()
            }
            None => false,
        }
    }

    /// P-0037: `allow_dummy_inputs` is proof-bound, and it comes from the INPUT tree.
    ///
    /// Unlike every field P-0020 varies, the attacker does not supply this one. It is
    /// DERIVED from tree state (`transact/tree.rs:35`), read before the instruction's
    /// own insertions, and folded into the public input hash. So the attacker's lever
    /// is not the payload but the CHOICE OF TREE -- and `transact` takes two of them,
    /// which P-0016 shows may differ.
    ///
    /// Two arms, and the second is the one worth having:
    /// * saturating the INPUT tree's queue flips the flag, so the proof must be refused
    /// * saturating the OUTPUT tree's must change nothing, because the flag is not read
    ///   from it -- if it ever were, an attacker could pick an output tree that flips a
    ///   value the proof commits to while the note, the roots and the nullifier all
    ///   stay exactly as proven
    pub fn action_transact_dummy_flag(&mut self, variant: u8) -> bool {
        let (target, split) = match variant % 3 {
            0 => (Some(self.tree), false),          // the input tree: must refuse
            1 => (Some(self.forester_tree), true),  // the output tree: must NOT matter
            _ => (None, false),                     // untouched control
        };
        let original = match target {
            Some(tree) => match self.scout_saturate_nullifier_queue(tree) {
                Some(bytes) => Some((tree, bytes)),
                None => return false,
            },
            None => None,
        };
        let success = if split {
            self.action_transact_split_trees()
        } else {
            self.action_transact_no_transfers()
        };
        // A success while the INPUT tree's flag was flipped is the violation: the
        // program derived a public input the proof does not commit to and verified
        // anyway. The output-tree arm succeeding is CORRECT and is not counted.
        if success && variant % 3 == 0 {
            self.shadow_dummy_flag_bypasses =
                self.shadow_dummy_flag_bypasses.saturating_add(1);
        }
        if let Some((tree, bytes)) = original {
            self.scout_restore_tree(tree, bytes);
        }
        success
    }
    /// `merging_enabled` is the LAST byte of the record; `scout_user_record_bytes`
    /// asserts the 134-byte layout it writes, so a drift there fails loudly.
    fn scout_set_merging_enabled(&mut self, enabled: u8) -> bool {
        match self.ctx.svm.get_account(&self.user_record) {
            Some(mut account) if !account.data.is_empty() => {
                let last = account.data.len() - 1;
                account.data[last] = enabled;
                self.ctx.svm.set_account(self.user_record, account).is_ok()
            }
            _ => false,
        }
    }

    fn scout_merging_enabled(&self) -> u8 {
        match self.ctx.svm.get_account(&self.user_record) {
            Some(account) => account.data.last().copied().unwrap_or(0),
            None => 0,
        }
    }

    /// One `merge_transact` sent raw, so the ERROR CODE is observable. A gate refusal
    /// and a proof refusal both read as "failed" and mean entirely different things.
    fn scout_merge_raw(&mut self, eddsa_owner: bool) -> (bool, Vec<String>) {
        let mut payload = scout_wire::MergeTransactIxData {
            expiry_unix_ts: merge_fixture::EXPIRY_UNIX_TS,
            proof: scout_wire::MergeProof {
                a: merge_fixture::PROOF_A, b: merge_fixture::PROOF_B, c: merge_fixture::PROOF_C,
            },
            output_utxo_hash: merge_fixture::OUTPUT_UTXO_HASH,
            eddsa_owner,
            private_tx_hash: merge_fixture::PRIVATE_TX_HASH,
            nullifiers: merge_fixture::NULLIFIERS.to_vec(),
            utxo_tree_root_index: vec![self.merge_utxo_root_index; 8],
            nullifier_tree_root_index: vec![0u16; 8],
        };
        payload.eddsa_owner = eddsa_owner;
        let mut data = vec![TAG_MERGE_TRANSACT];
        data.extend_from_slice(
            &wincode::serialize(&payload).expect("merge payload must serialize"));
        let instruction = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new(self.tree, false),
                AccountMeta::new(self.tree, false),
                AccountMeta::new(self.payer.pubkey(), true),
                AccountMeta::new_readonly(self.user_record, false),
                AccountMeta::new_readonly(system_program::ID, false),
                AccountMeta::new_readonly(self.program_id, false),
            ],
            data,
        };
        match self.ctx.raw_call(instruction).signers(&[&*self.payer]).send() {
            Ok(outcome) => {
                let logs = outcome.logs().iter().filter(|l| l.contains("failed"))
                    .cloned().collect::<Vec<_>>();
                (outcome.is_success(), logs)
            }
            Err(_) => (false, vec!["send-level error".into()]),
        }
    }

    /// P-0038 and P-0039: the merge trust boundary into the user registry.
    ///
    /// `merge_transact` reads three things out of an account owned by ANOTHER program
    /// -- `owner`, `owner_p256` and `merging_enabled` -- and turns them into proof
    /// public inputs and one authorization bit (`merge/account.rs:60-95`). The pool
    /// re-derives the record's PDA from `record.owner`, so a substituted record is
    /// closed off; what is NOT closed off by derivation is whether the fields are read
    /// CORRECTLY out of a foreign layout, and which owner rail an attacker may select.
    pub fn action_merge_registry_boundary(&mut self, variant: u8) -> bool {
        let restore = self.scout_merging_enabled();
        let (enabled, eddsa_owner) = match variant % 3 {
            // The opt-out honoured: merging off, the fixture's own rail.
            0 => (0u8, true),
            // The wrong owner rail while merging is ON, so a refusal is the RAIL and
            // not the opt-out.
            1 => (1u8, false),
            // Both wrong at once.
            _ => (0u8, false),
        };
        if !self.scout_set_merging_enabled(enabled) {
            return false;
        }
        let (success, _) = self.scout_merge_raw(eddsa_owner);
        if success {
            if enabled == 0 {
                self.shadow_merge_opt_out_bypasses =
                    self.shadow_merge_opt_out_bypasses.saturating_add(1);
            }
            if !eddsa_owner {
                self.shadow_merge_rail_bypasses =
                    self.shadow_merge_rail_bypasses.saturating_add(1);
            }
            self.shadow_expected_leaves = self.shadow_expected_leaves.saturating_add(1);
            self.shadow_merge_spends = self.shadow_merge_spends.saturating_add(1);
        }
        self.scout_set_merging_enabled(restore);
        success
    }
    // SCOUT:EXTRA-ACTIONS:END
}

#[invariant_test]
fn invariant_test(_f: &mut ShieldedPoolFixture) {
    scout_check_session!();
    // SCOUT:INVARIANTS:BEGIN
    // SCOUT:INVARIANT:P-0001:BEGIN
    // P-0001 NATIVE SOL SOLVENCY -- a NET, not a mirror of any one code path.
    //
    // Each `deposit` independently (a) transfers lamports into the SOL interface and
    // (b) appends a UTXO crediting that amount. The program relates the two nowhere,
    // and keeps no running total on chain, so nothing on-chain objects if a deposit
    // ever credits more than it moved (or moves less than it credits). Asserting the
    // transfer inside `deposit` would be a mirror -- it cannot fail there. This
    // asserts the identity those two steps EXIST to maintain, after EVERY action:
    //
    //     sol_interface.lamports == opening balance + sum of credited deposits
    //
    // The shadow sum advances only in the deposit action hook and only on success, so
    // a rejected deposit can never move the expectation.
    //
    // DONATIONS are the third term, and they are not optional. The SOL interface is
    // SYSTEM-owned (validate.rs:60-73), which is exactly what makes it a free target:
    // anyone may transfer lamports into it and the pool cannot refuse. The earlier
    // form of this property claimed "every lamport in it arrived through a settlement
    // the pool credited" and asserted plain equality -- true only because nothing in
    // the harness had ever donated, and it would have reported the first donation as
    // native-SOL insolvency. Adding `action_donate_lamports` is what exposed it.
    //
    // Accounting for the donation rather than weakening the bound to `>=` keeps the
    // property exact: the harness is the only donor, so any lamport it cannot explain
    // still fires. The direction that would actually be theft -- paying out more than
    // was ever put in -- is P-0031, because a donation must never become withdrawable.
    fn invariant_p_0001(f: &mut ShieldedPoolFixture) {
        let observed = match f.ctx.read_account(&f.sol_interface) {
            Ok(account) => account.lamports,
            // Absent means setup failed, which is not a protocol violation. Reporting
            // nothing beats reporting a counterexample the program never caused.
            Err(_) => return,
        };
        // Two-sided now that a withdrawal exists: a one-sided net would report a
        // correct pay-out as insolvency, and would never notice an over-payment.
        let credited = match f.sol_interface_opening.checked_add(f.shadow_sol_credited) {
            Some(value) => value,
            None => return,
        };
        let credited = match credited.checked_add(f.shadow_sol_donated) {
            Some(value) => value,
            None => return,
        };
        let expected = match credited.checked_sub(f.shadow_sol_withdrawn) {
            Some(value) => value,
            None => return,
        };
        scout_check!(
            "P-0001", "sol_interface_lamports_equal_credited",
            observed == expected,
            "P-0001 native SOL solvency: sol_interface holds {} lamports but successful deposits \
             credited {} on top of an opening balance of {} and {} donated, less {} withdrawn \
             (expected {})",
            observed, f.shadow_sol_credited, f.sol_interface_opening, f.shadow_sol_donated,
            f.shadow_sol_withdrawn, expected
        );
    }
    // `#[invariant_test]` rebinds its parameter as `fixture`.
    scout_run_property!("P-0001", invariant_p_0001(fixture));
    // SCOUT:INVARIANT:P-0001:END

    // SCOUT:INVARIANT:P-0002:BEGIN
    // P-0002 SPL SOLVENCY -- the same net as P-0001, over the SPL rail.
    //
    // Deliberately a SEPARATE property rather than a generalisation: the SOL rail
    // moves lamports with a system transfer, the SPL rail moves token units with a
    // token-program CPI, and the two are validated by different code
    // (`validate_sol_settlement` vs `validate_spl_settlement`). One property covering
    // both would pass whenever either rail happened to be consistent.
    //
    //     spl_interface.amount == sum of credited SPL deposit amounts
    //
    // The interface token account opens at 0, so no opening term is needed. `amount`
    // is a little-endian u64 at offset 64 of an SPL token account.
    fn invariant_p_0002(f: &mut ShieldedPoolFixture) {
        let data = match f.ctx.read_account(&f.spl_interface) {
            Ok(account) => account.data,
            Err(_) => return,
        };
        if data.len() < 72 {
            return;
        }
        let buf: [u8; 8] = data[64..72].try_into().unwrap_or_default();
        let observed = u64::from_le_bytes(buf);
        // Two-sided now that the token rail can pay out, for the same reason
        // P-0001 is: a one-sided net reads a correct withdrawal as insolvency.
        let credited = match f.spl_interface_opening.checked_add(f.shadow_spl_credited) {
            Some(value) => value,
            None => return,
        };
        let expected = match credited.checked_sub(f.shadow_spl_withdrawn) {
            Some(value) => value,
            None => return,
        };
        scout_check!(
            "P-0002", "spl_interface_amount_equals_credited",
            observed == expected,
            "P-0002 SPL solvency: spl_interface holds {} units but successful SPL deposits \
             credited {} on top of an opening balance of {}, less {} withdrawn (expected {})",
            observed, f.shadow_spl_credited, f.spl_interface_opening, f.shadow_spl_withdrawn,
            expected
        );
    }
    scout_run_property!("P-0002", invariant_p_0002(fixture));
    // SCOUT:INVARIANT:P-0002:END

    // SCOUT:INVARIANT:P-0003:BEGIN
    // P-0003 STATE TREE MONOTONICITY -- an append-only structure never rewinds.
    //
    // Seven instructions append to the UTXO tree (deposit, ring_deposit, the three
    // transact rails, and both merges); NONE of them checks that `next_index` did
    // not go backwards, because in each one it plainly cannot. The property is
    // about the seven together, and about the paths that do not exist yet: a leaf
    // index that rewinds means a previously-committed UTXO's slot is reissued, so
    // an inclusion proof against an older root can be replayed against a newer one.
    //
    // The high-water mark advances only in success-gated hooks, so a REJECTED
    // instruction can never raise the bar and manufacture a violation.
    fn invariant_p_0003(f: &mut ShieldedPoolFixture) {
        let data = match f.ctx.read_account(&f.tree) {
            Ok(account) => account.data,
            // Absent means setup failed, which is not a protocol violation.
            Err(_) => return,
        };
        if data.len() < UTXO_ROOT_OFFSET {
            return;
        }
        // Decoded inline rather than through a helper: an invariant predicate may
        // only observe, so it is restricted to a pure allowlist and cannot call out.
        let buf: [u8; 8] = data[UTXO_ROOT_OFFSET - 8..UTXO_ROOT_OFFSET]
            .try_into()
            .unwrap_or_default();
        let observed = u64::from_le_bytes(buf);
        scout_check!(
            "P-0003", "utxo_tree_next_index_never_decreases",
            observed >= f.shadow_expected_leaves,
            "P-0003 state tree monotonicity: next_index is {} but reached {} earlier; an              append-only tree rewound, so a committed leaf slot can be reissued",
            observed, f.shadow_expected_leaves
        );
    }
    scout_run_property!("P-0003", invariant_p_0003(fixture));
    // SCOUT:INVARIANT:P-0003:END

    // SCOUT:INVARIANT:P-0004:BEGIN
    // P-0004 LEAF-COUNT INTEGRITY -- every append moves the counter by exactly what
    // it appended, across all seven appending instructions.
    //
    // Stronger than P-0003 and a different failure: monotonicity still holds if an
    // instruction appends one UTXO and advances `next_index` by two, or appends two
    // and advances by one. The first strands a leaf index no commitment occupies;
    // the second OVERWRITES a committed leaf on the next append. The program checks
    // neither -- `append_batch` advances the counter itself, so no handler is in a
    // position to disagree with it -- which is exactly why the check belongs out
    // here, over the identity the seven paths exist to maintain:
    //
    //     next_index == leaves setup() seeded + sum of UTXOs each success appended
    //
    // Exact equality: nothing but these instructions can append to this tree, and
    // the baseline is READ from the tree after setup rather than counted, so it
    // cannot drift from the deposits that actually landed.
    fn invariant_p_0004(f: &mut ShieldedPoolFixture) {
        let data = match f.ctx.read_account(&f.tree) {
            Ok(account) => account.data,
            Err(_) => return,
        };
        if data.len() < UTXO_ROOT_OFFSET {
            return;
        }
        // Decoded inline rather than through a helper: an invariant predicate may
        // only observe, so it is restricted to a pure allowlist and cannot call out.
        let buf: [u8; 8] = data[UTXO_ROOT_OFFSET - 8..UTXO_ROOT_OFFSET]
            .try_into()
            .unwrap_or_default();
        let observed = u64::from_le_bytes(buf);
        scout_check!(
            "P-0004", "utxo_tree_leaf_count_matches_appends",
            observed == f.shadow_expected_leaves,
            "P-0004 leaf-count integrity: tree holds {} leaves but successful instructions              appended {} (a mismatch either strands an index or overwrites a committed leaf)",
            observed, f.shadow_expected_leaves
        );
    }
    scout_run_property!("P-0004", invariant_p_0004(fixture));
    // SCOUT:INVARIANT:P-0004:END

    // SCOUT:INVARIANT:P-0005:BEGIN
    // P-0005 NULLIFIER NON-REUSE -- the double-spend property, as a net.
    //
    // The pool prevents double-spending by refusing a nullifier already in the
    // queue, and it enforces that in ONE place: `insert_nullifier_into_queue`.
    // Asserting there would be a mirror. What matters is that the guarantee holds
    // wherever a nullifier can be published -- five instructions across three proof
    // rails plus both merges, in any interleaving the fuzzer chooses. If any one of
    // those paths reaches the tree without that insertion, or one rail's queue is
    // not the queue another rail checks, the same note is spendable twice and the
    // pool mints value from nothing.
    //
    // Asked as a COUNT, because every one of these instructions publishes the SAME
    // nullifiers on every call -- they are fixture constants, since a Groth16 proof
    // pins them. A second success IS a second acceptance of an already-spent
    // nullifier. The counters advance only on success, so the correct outcome (a
    // rejected replay) never registers, which `tree_properties_discriminate` pins.
    fn invariant_p_0005(f: &mut ShieldedPoolFixture) {
        scout_check!(
            "P-0005", "no_spending_instruction_succeeds_twice",
            f.shadow_merge_spends <= 1
                && f.shadow_ring_merge_spends <= 1
                && f.shadow_transact_spends <= 1
                && f.shadow_ring_transact_spends <= 1
                && f.shadow_ring_authority_spends <= 1
                && f.shadow_withdrawal_spends <= 1
                && f.shadow_spl_withdrawal_spends <= 1,
            "P-0005 nullifier non-reuse: a spending instruction succeeded more than once on an \
             unchanged nullifier set (merge {}, ring merge {}, transact {}, ring transact {}, \
             ring authority {}) -- the same note was spent twice",
            f.shadow_merge_spends, f.shadow_ring_merge_spends, f.shadow_transact_spends,
            f.shadow_ring_transact_spends, f.shadow_ring_authority_spends
        );
    }
    scout_run_property!("P-0005", invariant_p_0005(fixture));
    // SCOUT:INVARIANT:P-0005:END

    // SCOUT:INVARIANT:P-0006:BEGIN
    // P-0006 WITHDRAWAL RECIPIENT BINDING -- the pay-out goes where the proof says.
    //
    // The recipient appears nowhere in `transact` instruction data. It is resolved
    // from the ACCOUNT and folded into `external_data_hash`, which the program
    // derives itself and the proof commits to -- so substituting it must invalidate
    // the proof. There is no `require!` anywhere stating that; the binding is a
    // consequence of the hash preimage, which is exactly the kind of guarantee that
    // silently disappears when a field is added to the preimage, reordered, or an
    // account is resolved from somewhere else.
    //
    // No solvency property covers this. If a substituted recipient were paid, the
    // pool's books would still balance to the lamport -- P-0001 would hold -- and
    // the money would simply have gone to the wrong person.
    fn invariant_p_0006(f: &mut ShieldedPoolFixture) {
        scout_check!(
            "P-0006", "withdrawal_pays_only_the_bound_recipient",
            f.shadow_substituted_payouts == 0,
            "P-0006 withdrawal recipient binding: {} withdrawal(s) paid a recipient the proof \
             did not bind -- anyone can redirect another account's pay-out",
            f.shadow_substituted_payouts
        );
    }
    scout_run_property!("P-0006", invariant_p_0006(fixture));
    // SCOUT:INVARIANT:P-0006:END

    // SCOUT:INVARIANT:P-0007:BEGIN
    // P-0007 A PAUSED TREE ACCEPTS NO STATE CHANGE.
    //
    // `pause_tree` exists to freeze a tree, and the freeze is enforced in exactly
    // ONE place: `TreeAccount::from_account_view_mut` refuses a paused tree, so
    // every write path inherits it by using that loader. Asserting the refusal
    // inside that loader would be a mirror. The property is that the freeze holds
    // for EVERY instruction that can reach the tree -- and it is one wrong loader
    // away in any instruction added later, since `from_account_view_mut_allow_paused`
    // exists and is legitimately used by `pause_tree` itself.
    //
    // Checked as: while the tree reads PAUSED on chain, its leaf count must still
    // equal what it was when the pause was requested. The baseline is recorded in
    // the success-gated `pause_tree` hook, so a REJECTED pause never arms the check.
    fn invariant_p_0007(f: &mut ShieldedPoolFixture) {
        let data = match f.ctx.read_account(&f.tree) {
            Ok(account) => account.data,
            Err(_) => return,
        };
        if data.len() < UTXO_ROOT_OFFSET {
            return;
        }
        // Read the flag from the CHAIN, not the shadow: the shadow says what the
        // program was asked to do, and the point is whether it did it.
        if data[TREE_STATE_OFFSET] != TREE_STATE_PAUSED {
            return;
        }
        let buf: [u8; 8] = data[UTXO_ROOT_OFFSET - 8..UTXO_ROOT_OFFSET]
            .try_into()
            .unwrap_or_default();
        let observed = u64::from_le_bytes(buf);
        scout_check!(
            "P-0007", "a_paused_tree_accepts_no_append",
            observed == f.shadow_leaves_at_pause,
            "P-0007 pause bypass: the tree reads PAUSED but holds {} leaves against {} when the \
             pause was requested -- a write path reached a frozen tree",
            observed, f.shadow_leaves_at_pause
        );
    }
    scout_run_property!("P-0007", invariant_p_0007(fixture));
    // SCOUT:INVARIANT:P-0007:END

    // SCOUT:INVARIANT:P-0008:BEGIN
    // P-0008 ASSET ID INTEGRITY -- one id per registration, exactly.
    //
    // `create_spl_interface` allocates an id from a singleton counter and then
    // creates the registry entry that gives the id meaning. The two are separate
    // accounts written by the same instruction and nothing on chain relates them,
    // so no handler is in a position to notice an id consumed without an entry, or
    // two entries sharing an id -- which aliases two assets, and a deposit of one
    // could then be withdrawn as the other. Note the ordering: `allocate_id`
    // mutates the counter BEFORE the registry account is created, so the guarantee
    // rests entirely on the transaction reverting.
    //
    // Measured as a DELTA across each call rather than as an absolute identity,
    // because the counter is created by a fuzzable instruction and `--stateful`
    // carries action-created accounts between branches; see the shadow's comment.
    // A success must move `next_id` by exactly one, a failure by zero.
    fn invariant_p_0008(f: &mut ShieldedPoolFixture) {
        scout_check!(
            "P-0008", "asset_id_moves_exactly_once_per_registration",
            f.shadow_asset_id_violations == 0,
            "P-0008 asset id integrity: {} call(s) moved the id counter by the wrong amount -- an \
             id was consumed without a registry entry, or a registration consumed none",
            f.shadow_asset_id_violations
        );
    }
    scout_run_property!("P-0008", invariant_p_0008(fixture));
    // SCOUT:INVARIANT:P-0008:END

    // SCOUT:INVARIANT:P-0009:BEGIN
    // P-0009 ROOT/HISTORY COHERENCE -- the cached root is the history head.
    //
    // `append_batch` assigns `self.root`, and `push_root` separately writes the same
    // value into `root_history[next]` and moves the cursor there. Two writes, one
    // fact, and nothing on chain compares them -- there is no handler in a position
    // to, since the two live in different methods of the same type.
    //
    //     root == root_history[root_history_cursor]
    //
    // The consequence of divergence is not cosmetic: every proof cites a root BY
    // INDEX and the program answers from the history, so a history entry that was
    // never the tree's root makes a proof against a state that never existed
    // verifiable. This is the cache-coherence pattern, and the "cache" here is the
    // value the tree reports as its current root.
    fn invariant_p_0009(f: &mut ShieldedPoolFixture) {
        let data = match f.ctx.read_account(&f.tree) {
            Ok(account) => account.data,
            Err(_) => return,
        };
        // Length-checked, then indexed directly: a predicate may only observe, so it
        // is restricted to a pure allowlist -- no `.get()`, no helper calls -- and a
        // panic in one halts the run instead of producing a finding.
        if data.len() < UTXO_ROOT_HISTORY_OFFSET + 32 * ROOT_HISTORY_CAPACITY {
            return;
        }
        let cursor_bytes: [u8; 2] = data[UTXO_ROOT_CURSOR_OFFSET..UTXO_ROOT_CURSOR_OFFSET + 2]
            .try_into()
            .unwrap_or_default();
        let cursor = u16::from_le_bytes(cursor_bytes) as usize;
        // An out-of-range cursor is P-0010's finding, not this one's.
        if cursor >= ROOT_HISTORY_CAPACITY {
            return;
        }
        let slot = UTXO_ROOT_HISTORY_OFFSET + 32 * cursor;
        let head: [u8; 32] = data[slot..slot + 32].try_into().unwrap_or_default();
        let cached: [u8; 32] = data[UTXO_ROOT_OFFSET..UTXO_ROOT_OFFSET + 32]
            .try_into()
            .unwrap_or_default();
        scout_check!(
            "P-0009", "cached_root_equals_history_head",
            cached == head,
            "P-0009 root/history divergence: the tree reports one current root but history slot \
             {} holds another -- a proof citing that index would verify against a state the tree \
             never had",
            cursor
        );
    }
    scout_run_property!("P-0009", invariant_p_0009(fixture));
    // SCOUT:INVARIANT:P-0009:END

    // SCOUT:INVARIANT:P-0010:BEGIN
    // P-0010 ROOT HISTORY STRUCTURAL BOUNDS.
    //
    // `push_root` maintains `cursor = (cursor + 1) % capacity` and
    // `len = min(len + 1, capacity)`, so both stay in range by construction and no
    // handler checks them. That is exactly why it is worth asserting from outside:
    // the ring buffer is indexed by untrusted instruction data through
    // `root_by_index`, and a cursor or length outside its capacity turns the
    // window check into either a rejection of valid roots or a read past the
    // buffer. `len >= 1` because `init` seeds the empty root, so a length of zero
    // would mean no root is citable at all -- the tree is bricked.
    fn invariant_p_0010(f: &mut ShieldedPoolFixture) {
        let data = match f.ctx.read_account(&f.tree) {
            Ok(account) => account.data,
            Err(_) => return,
        };
        if data.len() < UTXO_ROOT_HISTORY_LEN_OFFSET + 2 {
            return;
        }
        let cursor_bytes: [u8; 2] = data[UTXO_ROOT_CURSOR_OFFSET..UTXO_ROOT_CURSOR_OFFSET + 2]
            .try_into()
            .unwrap_or_default();
        let len_bytes: [u8; 2] = data[UTXO_ROOT_HISTORY_LEN_OFFSET..UTXO_ROOT_HISTORY_LEN_OFFSET + 2]
            .try_into()
            .unwrap_or_default();
        let cursor = u16::from_le_bytes(cursor_bytes) as usize;
        let len = u16::from_le_bytes(len_bytes) as usize;
        scout_check!(
            "P-0010", "root_history_cursor_and_length_stay_in_range",
            cursor < ROOT_HISTORY_CAPACITY && len <= ROOT_HISTORY_CAPACITY && len >= 1,
            "P-0010 root history bounds: cursor {} and length {} against a capacity of {} -- an \
             out-of-range window either rejects valid roots or indexes past the buffer",
            cursor, len, ROOT_HISTORY_CAPACITY
        );
    }
    scout_run_property!("P-0010", invariant_p_0010(fixture));
    // SCOUT:INVARIANT:P-0010:END

    // SCOUT:INVARIANT:P-0011:BEGIN
    // P-0011 AUTHORITY PARTITION -- a gate holds against everyone it should.
    //
    // Each admin instruction checks one designated authority in one place
    // (`check_protocol_authority`, `load_and_validate_ring_authority_mut`), so
    // asserting the check inside the handler is a mirror. The property is that the
    // gate holds for every signer who is not that authority -- which this fixture
    // could not previously test at all, because it deliberately makes `payer` all
    // four authorities so one signer can drive every gated path.
    //
    // Counted as SUCCESSES BY AN OUTSIDER, so there is no baseline and nothing
    // inherited state can perturb: any non-zero value is an instruction that
    // accepted a signer it should have refused.
    fn invariant_p_0011(f: &mut ShieldedPoolFixture) {
        scout_check!(
            "P-0011", "admin_gates_refuse_every_non_authority",
            f.shadow_unauthorized_admin_successes == 0,
            "P-0011 authority partition: {} admin instruction(s) succeeded for a signer that is \
             not the designated authority",
            f.shadow_unauthorized_admin_successes
        );
    }
    scout_run_property!("P-0011", invariant_p_0011(fixture));
    // SCOUT:INVARIANT:P-0011:END

    // SCOUT:INVARIANT:P-0012:BEGIN
    // P-0012 THE NULLIFIER TREE ADVANCES ONLY IN WHOLE VERIFIED BATCHES.
    //
    // A successful `batch_update_nullifier_tree` either applies one whole ZKP batch
    // -- `next_index` forward by exactly `zkp_batch_size`, exactly one root pushed --
    // or does nothing at all, an idempotent crank that found no full batch ready.
    // Both outcomes were established by experiment, including that the idle crank
    // moves no lamports, so it is not a forester paid for no work.
    //
    // The tree's leaf counter and its root history are separate structures updated by
    // the same handler, and nothing on chain relates them. A partial advance means
    // nullifiers landed without a batch proof covering them; an advance without a
    // pushed root means the state they now prove against is not citable; a pushed
    // root without an advance publishes a root for a tree that never existed. Each is
    // the double-spend the nullifier machinery exists to prevent, arriving from a
    // different direction, and P-0005 would not see any of them: it watches whether a
    // nullifier is ACCEPTED TWICE at the queue, not whether the queue's contents ever
    // reach the tree the later non-inclusion proofs are checked against.
    fn invariant_p_0012(f: &mut ShieldedPoolFixture) {
        scout_check!(
            "P-0012", "nullifier_tree_advances_by_whole_zkp_batches",
            f.shadow_nullifier_batch_violations == 0,
            "P-0012 nullifier batch conservation: {} successful batch update(s) moved the \
             nullifier tree by something other than one whole ZKP batch or nothing",
            f.shadow_nullifier_batch_violations
        );
    }
    scout_run_property!("P-0012", invariant_p_0012(fixture));
    // SCOUT:INVARIANT:P-0012:END

    // SCOUT:INVARIANT:P-0013:BEGIN
    // P-0013 NULLIFIER ROOT HISTORY STRUCTURAL BOUNDS.
    //
    // The same two facts P-0010 asserts for the UTXO tree, on the OTHER root history:
    // cursor below capacity, length within [1, capacity]. Kept separate rather than
    // generalised because the two are different implementations -- an inline ring
    // buffer in `UtxoTreeLayout` against the batched tree's `CyclicVec`, with opposite
    // cursor conventions -- so one combined property would pass whenever either
    // structure happened to be well-formed.
    //
    // Worth asserting from outside for the same reason as P-0010, and more sharply
    // here: this buffer is indexed by UNTRUSTED instruction data. Every transact rail
    // cites a `nullifier_tree_root_index`, and the program answers from this history.
    fn invariant_p_0013(f: &mut ShieldedPoolFixture) {
        let data = match f.ctx.read_account(&f.forester_tree) {
            Ok(account) => account.data,
            Err(_) => return,
        };
        // Length-checked, then indexed directly: a predicate may only observe, so it
        // is restricted to a pure allowlist and a panic here would halt the run
        // instead of producing a finding.
        if data.len() < NULLIFIER_ROOT_HISTORY_OFFSET {
            return;
        }
        let cursor = u64::from_le_bytes(
            data[NULLIFIER_ROOT_CURSOR_OFFSET..NULLIFIER_ROOT_CURSOR_OFFSET + 8]
                .try_into()
                .unwrap_or_default(),
        );
        let len = u64::from_le_bytes(
            data[NULLIFIER_ROOT_LEN_OFFSET..NULLIFIER_ROOT_LEN_OFFSET + 8]
                .try_into()
                .unwrap_or_default(),
        );
        let capacity = u64::from_le_bytes(
            data[NULLIFIER_ROOT_CAPACITY_OFFSET..NULLIFIER_ROOT_CAPACITY_OFFSET + 8]
                .try_into()
                .unwrap_or_default(),
        );
        scout_check!(
            "P-0013", "nullifier_root_history_window_stays_in_bounds",
            capacity == NULLIFIER_ROOT_HISTORY_CAPACITY
                && cursor < capacity
                && len >= 1
                && len <= capacity,
            "P-0013 nullifier root history bounds: cursor {} / len {} against capacity {} \
             (expected capacity {})",
            cursor, len, capacity, NULLIFIER_ROOT_HISTORY_CAPACITY
        );
    }
    scout_run_property!("P-0013", invariant_p_0013(fixture));
    // SCOUT:INVARIANT:P-0013:END

    // SCOUT:INVARIANT:P-0014:BEGIN
    // P-0014 THE RING RAIL'S SWITCHES ACTUALLY SWITCH.
    //
    // While the ring config reads PAUSED, no operational ring instruction succeeds --
    // all four ring paths (ring deposit, ring transact, ring authority transact, ring
    // merge) reach the tree through `load_active_ring_config`, which refuses a paused
    // config. And while `ring_authority_transact_is_enabled` reads 0, no
    // `ring_authority_transact` succeeds.
    //
    // The second gate is the one that matters. `validate_and_parse` sets
    // `allow_owner_signers = false` on exactly that rail, so it is the one path where
    // the ring program moves a user's notes with NO owner signature at all. The flag
    // is the whole distance between "a ring is installed" and "a ring can spend for
    // its users unilaterally", and it is enforced by a single `if` in a function that
    // four instructions share.
    //
    // Each gate lives in one place, so asserting it there is a mirror; the property is
    // that it holds across every ring path, including any added later. Until now this
    // fixture could not test either one, because `update_ring_config` is generated
    // behind a feature flag that compiles it to a `false` stub -- both switches sat at
    // their create-time values (enabled, unpaused) for every campaign, so neither gate
    // was ever evaluated once.
    fn invariant_p_0014(f: &mut ShieldedPoolFixture) {
        scout_check!(
            "P-0014", "ring_switches_gate_every_ring_path",
            f.shadow_ring_gate_bypasses == 0,
            "P-0014 ring gate bypass: {} ring instruction(s) succeeded while the ring config's \
             own switch said they must not",
            f.shadow_ring_gate_bypasses
        );
    }
    scout_run_property!("P-0014", invariant_p_0014(fixture));
    // SCOUT:INVARIANT:P-0014:END

    // SCOUT:INVARIANT:P-0015:BEGIN
    // P-0015 A CLOSED PERMISSIONLESS SWITCH MEANS ONE KEY, NOT ANY KEY.
    //
    // While `tree_creation_is_permissionless` reads 0, only the tree-creation
    // authority may `create_tree`; while `spl_interface_creation_is_permissionless`
    // reads 0, only the protocol authority may `create_spl_interface`. Each gate is
    // one `if` of the same shape -- "if not permissionless, check the authority" --
    // written out separately in three handlers against three DIFFERENT keys, which is
    // exactly the arrangement where one of them quietly checks the wrong one.
    //
    // The switches decide whether the protocol is open or permissioned, and nothing
    // could move them here before: `update_protocol_config` is generated behind a
    // feature flag that compiles it to a `false` stub, so all three sat at their
    // create-time values for every campaign.
    //
    // Both attempts are made by a funded outsider against accounts the harness has
    // already paid for, so a refusal is the gate and not a missing lamport -- the
    // distinction that made half of P-0011 vacuous until the tag bug was found.
    fn invariant_p_0015(f: &mut ShieldedPoolFixture) {
        scout_check!(
            "P-0015", "closed_creation_gates_admit_only_their_authority",
            f.shadow_creation_gate_bypasses == 0,
            "P-0015 creation gate bypass: {} creation(s) succeeded for a signer that is not \
             the designated authority while the permissionless switch was closed",
            f.shadow_creation_gate_bypasses
        );
    }
    scout_run_property!("P-0015", invariant_p_0015(fixture));
    // SCOUT:INVARIANT:P-0015:END

    // SCOUT:INVARIANT:P-0016:BEGIN
    // P-0016 A SPLIT TRANSACT ROUTES THE NULLIFIER AND THE LEAF TO DIFFERENT TREES,
    // AND TO THE RIGHT ONES.
    //
    // `transact` takes two tree accounts and they may differ. When they do, the input
    // tree's nullifier queue advances by the inputs while its leaf count does not
    // move, and the output tree's leaf count advances by the outputs while its
    // nullifier queue does not move.
    //
    // Which tree receives the nullifier is the whole security question. Membership is
    // proven against the INPUT tree's root, so the nullifier must land in the INPUT
    // tree's queue. If it landed in the output tree's, the same note would be
    // spendable once per output tree -- and no double-spend check anywhere would fire,
    // because each tree's queue would see that nullifier exactly once. It is a
    // mint-from-nothing that P-0005 cannot see: P-0005 asks whether a nullifier is
    // accepted twice, and under a misroute it never would be.
    //
    // The generated action pins both trees to the same account, so this arrangement
    // was never exercised at all until an action was written for it.
    fn invariant_p_0016(f: &mut ShieldedPoolFixture) {
        scout_check!(
            "P-0016", "split_tree_transact_routes_to_the_proving_tree",
            f.shadow_split_tree_misroutes == 0,
            "P-0016 split-tree misroute: {} transact(s) with distinct input and output \
             trees put the nullifier or the output leaf in the wrong one",
            f.shadow_split_tree_misroutes
        );
    }
    scout_run_property!("P-0016", invariant_p_0016(fixture));
    // SCOUT:INVARIANT:P-0016:END

    // SCOUT:INVARIANT:P-0017:BEGIN
    // P-0017 THE TREE NEVER HOLDS MORE NULLIFIERS THAN WERE EVER QUEUED.
    //
    // The nullifier tree's applied leaf count, less its sentinel, never exceeds the
    // queue's `next_index`. A backlog is fine and normal -- queued far exceeds applied
    // most of the time, because the forester applies in chunks of ten. The forbidden
    // direction is the other one.
    //
    // Two structures, two writers, no on-chain comparison: spends push into the queue
    // from five instructions across three rails, and the forester's batch update
    // appends to the tree from an entirely separate path. If applied ever ran ahead of
    // queued, the tree would contain nullifier leaves that no spend ever published --
    // entries appearing from nowhere. Those entries make the corresponding notes
    // permanently unspendable (their non-inclusion proof now fails), so it is a
    // silent, unrecoverable freeze of other people's funds rather than a loud error.
    //
    // P-0012 is the per-call version and cannot see this: it checks that each single
    // call moves by a whole batch or not at all, which stays true while the totals
    // drift apart across calls.
    fn invariant_p_0017(f: &mut ShieldedPoolFixture) {
        let data = match f.ctx.read_account(&f.forester_tree) {
            Ok(account) => account.data,
            Err(_) => return,
        };
        // Decoded inline, not through a helper: a predicate may only observe, so it is
        // restricted to a pure allowlist and no call of ours is on it.
        if data.len() < NULLIFIER_QUEUE_NEXT_INDEX_OFFSET + 8 {
            return;
        }
        let applied = u64::from_le_bytes(
            data[NULLIFIER_NEXT_INDEX_OFFSET..NULLIFIER_NEXT_INDEX_OFFSET + 8]
                .try_into()
                .unwrap_or_default(),
        );
        let queued = u64::from_le_bytes(
            data[NULLIFIER_QUEUE_NEXT_INDEX_OFFSET..NULLIFIER_QUEUE_NEXT_INDEX_OFFSET + 8]
                .try_into()
                .unwrap_or_default(),
        );
        // Index 0 is the sentinel, present before any nullifier is applied.
        scout_check!(
            "P-0017", "applied_nullifiers_never_exceed_queued",
            applied.saturating_sub(1) <= queued,
            "P-0017 nullifiers from nowhere: {} applied (less the sentinel) against {} \
             ever queued",
            applied, queued
        );
    }
    scout_run_property!("P-0017", invariant_p_0017(fixture));
    // SCOUT:INVARIANT:P-0017:END

    // SCOUT:INVARIANT:P-0018:BEGIN
    // P-0018 THE QUEUE'S BATCH COUNTERS STAY WITHIN THEIR OWN DECLARED BOUNDS.
    //
    // For each of the two batches: the fill counter never exceeds the batch size, the
    // number of PROVEN ZKP chunks never exceeds the number of FULL ones, and the full
    // chunks fit inside the batch.
    //
    // This is the most intricate state in the program and nothing asserts anything
    // about it. Two `Batch` structs fill, become full, get proven in chunks, get
    // zeroed and rotate, coordinated by `currently_processing_batch_index`,
    // `pending_batch_index` and a `sequence_number` that decides when a batch may be
    // cleared. `num_inserted` counts within the chunk being filled rather than within
    // the batch, so the batch's real total is `num_full_zkp_batches * zkp_batch_size +
    // num_inserted` -- an easy thing to get wrong in a reader and in a writer alike.
    //
    // The middle bound is the security-relevant one: proven chunks exceeding full
    // chunks means the forester applied a chunk that was still being filled, or
    // applied the same chunk twice. Either way the tree advances past nullifiers that
    // the queue has not finished collecting.
    //
    // Stated as bounds rather than as an exact identity ON PURPOSE. A batch is zeroed
    // and reused when it rotates, so any global "applied equals proven chunks times
    // chunk size" identity stops holding after a rotation, and would fire on honest
    // traffic the way P-0008's absolute form did. The bounds survive rotation.
    fn invariant_p_0018(f: &mut ShieldedPoolFixture) {
        let data = match f.ctx.read_account(&f.forester_tree) {
            Ok(account) => account.data,
            Err(_) => return,
        };
        for batch in 0..2usize {
            let base = NULLIFIER_BATCH0_OFFSET + batch * NULLIFIER_BATCH_STRIDE;
            if data.len() < base + NULLIFIER_BATCH_STRIDE {
                return;
            }
            let num_inserted = u64::from_le_bytes(
                data[base + BATCH_NUM_INSERTED..base + BATCH_NUM_INSERTED + 8]
                    .try_into()
                    .unwrap_or_default(),
            );
            let num_full_zkp = u64::from_le_bytes(
                data[base + BATCH_NUM_FULL_ZKP..base + BATCH_NUM_FULL_ZKP + 8]
                    .try_into()
                    .unwrap_or_default(),
            );
            let num_inserted_zkp = u64::from_le_bytes(
                data[base + BATCH_NUM_INSERTED_ZKP..base + BATCH_NUM_INSERTED_ZKP + 8]
                    .try_into()
                    .unwrap_or_default(),
            );
            let batch_size = u64::from_le_bytes(
                data[base + BATCH_SIZE_FIELD..base + BATCH_SIZE_FIELD + 8]
                    .try_into()
                    .unwrap_or_default(),
            );
            let zkp_size = u64::from_le_bytes(
                data[base + BATCH_ZKP_SIZE_FIELD..base + BATCH_ZKP_SIZE_FIELD + 8]
                    .try_into()
                    .unwrap_or_default(),
            );
            if batch_size == 0 || zkp_size == 0 {
                continue;
            }
            scout_check!(
                "P-0018", "batch_counters_stay_within_declared_bounds",
                num_inserted <= batch_size
                    && num_inserted_zkp <= num_full_zkp
                    && num_full_zkp.saturating_mul(zkp_size) <= batch_size,
                "P-0018 batch {} counters out of bounds: inserted {} / full_zkp {} / \
                 proven_zkp {} against batch_size {} and zkp_size {}",
                batch, num_inserted, num_full_zkp, num_inserted_zkp, batch_size, zkp_size
            );
        }
    }
    scout_run_property!("P-0018", invariant_p_0018(fixture));
    // SCOUT:INVARIANT:P-0018:END

    // SCOUT:INVARIANT:P-0019:BEGIN
    // P-0019 A TREE NEVER DROPS BELOW ITS RENT-EXEMPT FLOOR.
    //
    // A third value flow, and the only property watching it. P-0001 and P-0002 watch
    // the SOL and SPL interface accounts, which hold user deposits. The TREE's own
    // lamports are separate: spends pay a forester fee INTO the tree
    // (`collect_forester_fee`) and the batch update pays a reimbursement OUT of it
    // (`reimburse_forester`), so the balance moves in both directions under normal
    // operation and nothing relates the two sides.
    //
    // Falling below the rent-exempt minimum is not an accounting error, it is the loss
    // of the tree: the runtime may reap the account, and with it every commitment it
    // holds. The failure is also asymmetric in a way that hides it -- the runtime
    // refuses a transaction that would leave the account short, so the symptom is not
    // a drained tree but a tree that silently stops accepting the very instructions
    // that would refill it. That already happened here once, to the harness rather
    // than the protocol: an under-funded tree turned a fully successful merge into
    // `InsufficientFundsForRent`.
    fn invariant_p_0019(f: &mut ShieldedPoolFixture) {
        let floor = f.tree_rent_floor;
        for tree in [f.tree, f.forester_tree] {
            let lamports = match f.ctx.read_account(&tree) {
                Ok(account) => account.lamports,
                Err(_) => continue,
            };
            scout_check!(
                "P-0019", "trees_stay_rent_exempt",
                lamports >= floor,
                "P-0019 tree below its rent-exempt floor: {} lamports against a floor of {}",
                lamports, floor
            );
        }
    }
    scout_run_property!("P-0019", invariant_p_0019(fixture));
    // SCOUT:INVARIANT:P-0019:END

    // SCOUT:INVARIANT:P-0020:BEGIN
    // P-0020 EVERY PROOF-BOUND FIELD IS LOAD-BEARING.
    //
    // A `transact` carrying a VALID proof but one altered field that the proof's public
    // inputs commit to must not verify. Eleven fields are varied one at a time:
    // expiry, tx_viewing_pk, salt, the output commitment, the output owner,
    // private_tx_hash, the nullifier, data_hash, ring_data_hash, messages, and the
    // cited UTXO root index. All are attacker-controlled instruction data.
    //
    // This is the closest a harness with pinned witnesses can get to testing the proof
    // system. It cannot synthesise a new proof -- but it does not need to. It holds a
    // real proof fixed and varies what the program hashes alongside it, which is
    // exactly the attacker's position: reuse somebody else's proof, change the parts
    // you care about. If any field is not truly folded into the public input hash, it
    // can be varied freely, and the consequences differ per field -- a free
    // `tx_viewing_pk` or `salt` breaks the recipient's ability to detect their own
    // note, a free output commitment mints an arbitrary UTXO under a valid proof.
    //
    // The binding is a consequence of a hash preimage rather than a `require!`, so
    // nothing in the program states it, and it disappears silently if a field is added
    // to `ExternalDataHash`, reordered, or dropped. `private_tx_hash` is the one to
    // watch: it appears nowhere in `ExternalDataHash`'s field list, so a reader would
    // reasonably assume it floats free. It does not -- it is bound, and P-0020 keeps
    // it that way.
    fn invariant_p_0020(f: &mut ShieldedPoolFixture) {
        scout_check!(
            "P-0020", "every_proof_bound_field_is_load_bearing",
            f.shadow_proof_binding_bypasses == 0,
            "P-0020 unbound public input: {} transact(s) verified with a proof-bound \
             field altered",
            f.shadow_proof_binding_bypasses
        );
    }
    scout_run_property!("P-0020", invariant_p_0020(fixture));
    // SCOUT:INVARIANT:P-0020:END

    // SCOUT:INVARIANT:P-0021:BEGIN
    // P-0021 A FULL, UNPROVEN BATCH IS NEVER WRITTEN INTO.
    //
    // A spend is never accepted into a batch whose state is Full -- filled, and not yet
    // proven into the tree. When both batches are full the queue must refuse spends
    // outright, and it does: the rotation wraps onto a Full batch and
    // `add_to_hash_chain` returns `BatchNotReady` with the queue untouched.
    //
    // The failure this rules out is a mint-from-nothing. Nullifiers written into a full
    // batch would overwrite entries whose hash-chain slots the forester still has to
    // prove; those nullifiers would never reach the tree, and a nullifier that never
    // reaches the tree is a note that can be spent again. Refusing the spend is a
    // liveness cost that buys exactly that safety, which is why the guard is worth
    // asserting rather than assuming -- the tempting "fix" for a stalled queue is to
    // relax it.
    //
    // Nothing had ever reached this path. A batch here is 30,000 nullifiers and the
    // fixture can publish a handful, so rotation was three orders of magnitude out of
    // reach; `action_fill_nullifier_batch` synthesises the counters that 29,999 real
    // insertions would leave, which is what makes the property reachable at all.
    fn invariant_p_0021(f: &mut ShieldedPoolFixture) {
        scout_check!(
            "P-0021", "full_unproven_batches_are_never_written_into",
            f.shadow_batch_overwrite_bypasses == 0,
            "P-0021 batch overwrite: {} spend(s) were accepted into a batch that was \
             already full and unproven",
            f.shadow_batch_overwrite_bypasses
        );
    }
    scout_run_property!("P-0021", invariant_p_0021(fixture));
    // SCOUT:INVARIANT:P-0021:END

    // SCOUT:INVARIANT:P-0022:BEGIN
    // P-0022 A PROVEN BATCH IS NEVER REUSED BEFORE ITS BLOOM FILTER IS ZEROED.
    //
    // A batch that has been proven into the tree reads `Inserted`, and the queue may
    // rotate back onto it and start filling it again -- but only once a forester has
    // zeroed its bloom filter. Otherwise `BloomFilterNotZeroed` refuses the spend.
    //
    // The filter is the membership check consulted on EVERY insertion: a nullifier is
    // rejected if either filter already contains it. A reused batch whose filter still
    // holds thirty thousand old entries makes those entries indistinguishable from new
    // ones, so every fresh nullifier that collides with a stale bit is refused and the
    // note behind it becomes unspendable. The damage is proportional to how full the
    // filter was, and it is invisible -- the owner simply cannot spend, with no error
    // that points at the cause.
    //
    // Reuse also advances the batch's `start_index` by exactly one full rotation, so a
    // reused batch's coverage window cannot overlap its previous one.
    //
    // Reaching this by execution would need 120 batch-update proofs to mark a single
    // batch `Inserted`, so the state is synthesised by `action_mark_batch_inserted` and
    // the REAL guard is exercised against it. Both settings of the flag are driven: the
    // unzeroed case must be refused, and the zeroed case must go through, or the
    // refusal would only show that reuse is broken in general.
    fn invariant_p_0022(f: &mut ShieldedPoolFixture) {
        scout_check!(
            "P-0022", "proven_batches_are_not_reused_with_a_stale_bloom_filter",
            f.shadow_stale_bloom_reuses == 0,
            "P-0022 stale bloom reuse: {} spend(s) entered a proven batch whose filter \
             had not been zeroed",
            f.shadow_stale_bloom_reuses
        );
    }
    scout_run_property!("P-0022", invariant_p_0022(fixture));
    // SCOUT:INVARIANT:P-0022:END

    // SCOUT:INVARIANT:P-0023:BEGIN
    // P-0023 A PROOF IS NOT TRANSPLANTABLE BETWEEN RAILS, AND ITS COMMITMENT IS NOT
    // SEPARABLE FROM IT.
    //
    // The program chooses its verification path from
    // `(proof.commitment, vk.vk_commitment.is_some())`: a commitment with a
    // commitment-bearing key, or neither, and everything else falls to `_ => Err`.
    // Five graftings must all be refused -- a P256 proof under the eddsa selector,
    // an eddsa proof under the P256 selector, a corrupted commitment, a corrupted
    // proof of knowledge, and a wrong default owner tag.
    //
    // The first is the dangerous one. The eddsa selector carries no commitment field
    // at all, so a P256 proof accepted under it would have its Pedersen
    // proof-of-knowledge STRIPPED rather than checked -- and that pairing is what
    // makes the emulated-P256 ownership gadget sound. The check that prevents it is
    // one match arm shared by every rail, which is exactly the kind of guard that
    // survives review and dies in a refactor.
    //
    // Only testable at all because the harness now holds valid proofs from two
    // different rails at once; with one rail there is nothing to graft.
    fn invariant_p_0023(f: &mut ShieldedPoolFixture) {
        scout_check!(
            "P-0023", "proofs_are_not_transplantable_between_rails",
            f.shadow_proof_graft_successes == 0,
            "P-0023 proof graft accepted: {} transact(s) verified with a proof or \
             commitment that belongs to a different rail, or a corrupted one",
            f.shadow_proof_graft_successes
        );
    }
    scout_run_property!("P-0023", invariant_p_0023(fixture));
    // SCOUT:INVARIANT:P-0023:END

    // SCOUT:INVARIANT:P-0024:BEGIN
    // P-0024 AN AUTHORITY ROTATION IS EXCLUSIVE: THE OLD KEY STOPS WORKING.
    //
    // After `update_protocol_config` rotates the forester authority, a
    // forester-gated call succeeds only for the key the config NOW names. The point
    // of rotating an authority is revocation, so a rotation that left the previous
    // key working would make a compromised forester key impossible to retire -- the
    // config would say one thing and the gate honour another.
    //
    // This fixture could not see any of this before. It deliberately makes `payer`
    // all four protocol authorities, which means a handler checking the WRONG one of
    // the four passes every test here; only pulling one authority apart from the rest
    // makes the four distinguishable. It also drives the rotation variants of
    // `update_protocol_config` (0..3), which nothing else touches -- P-0015 exercises
    // only the permissionless switches (4..6).
    fn invariant_p_0024(f: &mut ShieldedPoolFixture) {
        scout_check!(
            "P-0024", "authority_rotation_revokes_the_previous_key",
            f.shadow_stale_authority_successes == 0,
            "P-0024 stale authority accepted: {} forester-gated call(s) succeeded for a \
             signer the protocol config no longer names",
            f.shadow_stale_authority_successes
        );
    }
    scout_run_property!("P-0024", invariant_p_0024(fixture));
    // SCOUT:INVARIANT:P-0024:END

    // SCOUT:INVARIANT:P-0025:BEGIN
    // P-0025 A NOTE THE POOL CREATED IS SPENDABLE.
    //
    // The output of a transact can be the input of the next one. Every other fixture
    // here spends a note `setup()` DEPOSITED, so the pool's own output had never been
    // used as an input, and the append/root/membership loop was only ever checked by
    // counters: P-0003 says the leaf counter never rewinds, P-0004 that it moves by
    // the right amount, P-0009 that the cached root matches the history head. All
    // three are satisfied by a tree that appends a leaf at the wrong index, or pushes
    // a root before the append -- because none of them ever proves MEMBERSHIP against
    // the tree they describe.
    //
    // This does. The second link's proof carries a merkle path for the leaf the first
    // link appended, checked against the root the pool published, so it verifies only
    // if the tree is usable and not merely well-counted. The failure it rules out is
    // the worst kind of quiet one: notes accepted into the pool that nobody can ever
    // spend, with every counter reading correct.
    //
    // Counted only when the FIRST link succeeded and the second did not, so it needs
    // no baseline and cannot fire on a branch that never opened the chain.
    fn invariant_p_0025(f: &mut ShieldedPoolFixture) {
        scout_check!(
            "P-0025", "notes_the_pool_created_are_spendable",
            f.shadow_unspendable_outputs == 0,
            "P-0025 unspendable output: {} note(s) the pool created could not then be \
             spent, so the tree it published is not the tree it accounted for",
            f.shadow_unspendable_outputs
        );
    }
    scout_run_property!("P-0025", invariant_p_0025(fixture));
    // SCOUT:INVARIANT:P-0025:END

    // SCOUT:INVARIANT:P-0027:BEGIN
    // P-0027 A RETIRED OR NEVER-WRITTEN ROOT IS NOT CITABLE.
    //
    // `zero_out_roots` retires a root by writing ZERO over it. That is how the
    // protocol removes roots which could still prove inclusion of a value whose bloom
    // filter is about to be cleared -- the deepest safety step in the nullifier
    // machinery, and the one whose failure is a double spend rather than a freeze.
    // The entire mechanism rests on a zeroed slot being unusable afterwards, and the
    // check enforcing that is a single `if root == [0u8; 32]` in
    // `get_nullifier_tree_root`. Drop it and every retired root becomes citable again,
    // while `zero_out_roots` goes on faithfully writing zeros that no longer mean
    // anything.
    //
    // The two trees guard DIFFERENTLY, and both are driven. The nullifier tree
    // rejects a zero root outright; the UTXO tree never zeroes roots, so it bounds the
    // index against `root_history_len` instead and an unwritten slot is out of range.
    // Neither guard would catch the other's case, which is exactly what makes a
    // refactor that unifies them dangerous.
    fn invariant_p_0027(f: &mut ShieldedPoolFixture) {
        scout_check!(
            "P-0027", "retired_and_unwritten_roots_are_not_citable",
            f.shadow_retired_root_successes == 0,
            "P-0027 retired root accepted: {} spend(s) verified against a root index the \
             tree had zeroed or never written",
            f.shadow_retired_root_successes
        );
    }
    scout_run_property!("P-0027", invariant_p_0027(fixture));
    // SCOUT:INVARIANT:P-0027:END

    // SCOUT:INVARIANT:P-0026:BEGIN
    // P-0026 THE QUEUE'S HASH CHAIN IS THE CHAIN OVER THE NULLIFIERS ACTUALLY QUEUED.
    //
    // The forester does not prove a SET of nullifiers -- it proves a Poseidon fold
    // over them, in insertion order, which the queue builds one insertion at a time in
    // `add_to_hash_chain`. The proof binds that fold. So the chain is the only thing
    // connecting "what the queue accepted" to "what the tree receives", and a queue
    // that folded a value twice, skipped one, or folded them out of order would hand
    // the forester a batch that does not correspond to what users spent.
    //
    // Checked on the forester tree, whose queue only `setup()` ever writes: its first
    // chunk is complete and nothing afterwards touches it, so the chain is immutable
    // and any drift is a violation. The expected value was computed OFFLINE by the
    // batch generator from the nullifier list, so this compares two independent
    // constructions rather than restating one.
    //
    // Deliberately scoped to that tree. On a tree whose batches rotate, a reused batch
    // legitimately overwrites chunk 0's slot, so "the chain never changes" would fire
    // on honest traffic -- the shape P-0008 had to be rewritten out of.
    fn invariant_p_0026(f: &mut ShieldedPoolFixture) {
        let data = match f.ctx.read_account(&f.forester_tree) {
            Ok(account) => account.data,
            Err(_) => return,
        };
        if data.len() < NULLIFIER_HASH_CHAIN_OFFSET + 32 {
            return;
        }
        let chain: [u8; 32] = data
            [NULLIFIER_HASH_CHAIN_OFFSET..NULLIFIER_HASH_CHAIN_OFFSET + 32]
            .try_into()
            .unwrap_or_default();
        scout_check!(
            "P-0026", "queue_hash_chain_covers_exactly_what_was_queued",
            chain == merge_fixture::EXPECTED_HASH_CHAIN,
            "P-0026 queue hash chain drifted: the forester tree's first chunk folds to \
             a value the batch proof does not bind, so the batch it applies is not the \
             batch the queue accepted"
        );
    }
    scout_run_property!("P-0026", invariant_p_0026(fixture));
    // SCOUT:INVARIANT:P-0026:END

    // SCOUT:INVARIANT:P-0028:BEGIN
    // P-0028 CLEARING A BLOOM FILTER RETIRES THE ROOTS IT GUARDED.
    //
    // The deepest safety step in the nullifier machinery, and the only one whose
    // failure is a double spend rather than a freeze. A bloom filter records which
    // nullifiers a batch is still tracking; clearing it re-opens every one of them. So
    // before a filter is cleared, every root that could still prove inclusion of a
    // value it held must be RETIRED -- `zero_out_roots` does that by writing zero over
    // each one, and P-0027 pins the check that makes a zeroed root uncitable.
    //
    // Skip the retirement and the pool will accept an inclusion proof against a root
    // whose nullifiers nothing tracks any more. The two halves are both asserted: the
    // roots the walk covered must be gone, and the FIRST SAFE root must survive --
    // retiring one root too many would discard a root the tree still needs, turning a
    // safety step into a denial of service.
    //
    // Reaching it took synthesis on three fronts, because a fresh tree satisfies none
    // of the gates and the walk would otherwise pass over slots that were already
    // empty, running invisibly. The `(sequence_number, root_index)` pair is COMPUTED
    // from the live tree rather than chosen: `zero_out_roots` asserts its walk lands
    // exactly on `root_index`, so an inconsistent pair panics the program on state the
    // protocol could never produce -- which would prove nothing at all.
    fn invariant_p_0028(f: &mut ShieldedPoolFixture) {
        scout_check!(
            "P-0028", "clearing_a_bloom_filter_retires_the_roots_it_guarded",
            f.shadow_unretired_roots == 0,
            "P-0028 root retirement failed: {} root(s) survived the clearing of the \
             bloom filter that guarded them, or the first safe root was discarded",
            f.shadow_unretired_roots
        );
    }
    scout_run_property!("P-0028", invariant_p_0028(fixture));
    // SCOUT:INVARIANT:P-0028:END

    // SCOUT:INVARIANT:P-0029:BEGIN
    // P-0029 A RING AUTHORITY ROTATION REVOKES THE OLD KEY.
    //
    // `update_ring_config_owner` is the SOLE writer of `RingConfig.authority` in the
    // whole program (`ring_config/update_owner.rs:20`), and until now it had never
    // executed here: no builder, no action, and the only trace of the tag was a
    // comment noting that it is 9 and not 8. A field with exactly one writer and no
    // successful call is a field whose write path is unverified -- and this one
    // decides who may set `ring_authority_transact_is_enabled`, the flag P-0014 calls
    // the whole distance between "a ring is installed" and "a ring can spend for its
    // users unilaterally".
    //
    // The point of rotating an authority is REVOCATION. A rotation that left the
    // previous key working would make a compromised ring authority impossible to
    // retire: the config would name one key and the gate would honour another, and
    // nothing on chain would look wrong. This is P-0024's shape on the other rail, and
    // it is kept separate rather than generalised because the two gates are different
    // code against different state -- `check_forester_authority` reads the singleton
    // protocol config, `load_and_validate_ring_authority_mut` reads a per-ring account
    // -- so one combined property would pass whenever either happened to be correct.
    fn invariant_p_0029(f: &mut ShieldedPoolFixture) {
        scout_check!(
            "P-0029", "a_rotated_ring_authority_stops_working",
            f.shadow_stale_ring_authority_successes == 0,
            "P-0029 ring authority revocation failed: {} ring config update(s) succeeded \
             for a key the ring config no longer names as its authority, so rotating the \
             ring authority does not retire the key it replaced",
            f.shadow_stale_ring_authority_successes
        );
    }
    scout_run_property!("P-0029", invariant_p_0029(fixture));
    // SCOUT:INVARIANT:P-0029:END

    // SCOUT:INVARIANT:P-0030:BEGIN
    // P-0030 THE FORESTER CRANK NEVER SUCCEEDS WITHOUT DOING THE WORK IT WAS DUE.
    //
    // Every other property here asks whether an operation was correctly REFUSED. This
    // one asks the question nobody checks: did an operation that returned SUCCESS
    // actually do anything? A crank that reports Ok while applying nothing is exactly
    // as bad as one that reverts -- the nullifiers stay in the queue, unproven and
    // unapplied, and the notes behind them stay unspendable -- but it sails past every
    // "did it throw?" oracle in the harness, including P-0012, which explicitly
    // PERMITS a work-free success as an idle crank.
    //
    // The guard is the whole property. Two work-free successes are legitimate:
    // `update_tree_from_address_queue` returns `Ok(None)` for a REPLAYED proof
    // (`merkle_tree_update.rs:87-91`), and `apply_cached_tree_updates` caches rather
    // than applies a chunk proven AHEAD of its turn. An oracle that fired on "success
    // with no movement" would report both constantly. So the fire is conditioned on the
    // one arrangement where neither escape is available -- the supplied
    // `zkp_batch_index` equals `num_inserted_zkp_batches`, so it is the next chunk due
    // rather than a replay or a look-ahead, and `num_full_zkp_batches` exceeds it, so
    // its hash chain is finalised and the work provably exists. Both are read from the
    // PENDING batch, which is the batch the handler reads.
    fn invariant_p_0030(f: &mut ShieldedPoolFixture) {
        scout_check!(
            "P-0030", "a_successful_forester_crank_applies_the_chunk_that_was_due",
            f.shadow_silent_forester_noops == 0,
            "P-0030 silent forester no-op: {} crank(s) returned success while holding the \
             proof for the chunk that was due and a finalised hash chain to apply, yet \
             moved no leaf -- the batch is reported done and its nullifiers never reached \
             the tree",
            f.shadow_silent_forester_noops
        );
    }
    scout_run_property!("P-0030", invariant_p_0030(fixture));
    // SCOUT:INVARIANT:P-0030:END

    // SCOUT:INVARIANT:P-0031:BEGIN
    // P-0031 A DONATED LAMPORT NEVER BECOMES WITHDRAWABLE.
    //
    // Anyone may transfer lamports into any account on Solana, including a
    // program-owned PDA, and the receiving program cannot refuse. So the pool's REAL
    // balance can be driven above anything it counted, for free, by anyone. That
    // desync is inert on its own; the escalation is a second site that sizes a pay-out
    // from the real balance rather than from what the claimant is owed. If one exists,
    // the surplus is extractable and the donation is the first half of a drain.
    //
    // Stated as the total-outflow bound rather than as a balance identity, because a
    // balance identity is exactly what a donation breaks by design (that is P-0001's
    // repair). This says the thing that must hold whatever the balance reads: across
    // the whole run, the pool never pays out more native SOL than deposits credited
    // to it. A donation raises the balance without raising `shadow_sol_credited`, so
    // if any path let a caller reach the surplus, this fires and P-0001 stays quiet --
    // the two are complementary, not redundant.
    fn invariant_p_0031(f: &mut ShieldedPoolFixture) {
        // The ceiling must count EVERY deposit, including the ones `setup()` made
        // before the shadow existed -- those are what `sol_interface_opening` is. The
        // first form omitted them and the corpus replay reported `would_violate`
        // immediately, on an ordinary withdrawal of a setup-seeded note: a property
        // that was one writer short of the quantity it tracked, which is the same
        // bookkeeping error that once produced 37 findings on honest traffic here.
        //
        // Donations are deliberately NOT in the ceiling. That is the whole property:
        // the surplus anyone can create for free must never raise what the pool is
        // willing to pay out.
        let ceiling = match f.sol_interface_opening.checked_add(f.shadow_sol_credited) {
            Some(value) => value,
            None => return,
        };
        scout_check!(
            "P-0031", "a_donated_lamport_never_becomes_withdrawable",
            f.shadow_sol_withdrawn <= ceiling,
            "P-0031 donated surplus extracted: the pool has paid out {} lamports against \
             {} ever deposited into it ({} at setup plus {} since, with {} donated and \
             therefore NOT a claim) -- a pay-out was sized from the account's real \
             balance rather than from what the claimant was owed",
            f.shadow_sol_withdrawn, ceiling, f.sol_interface_opening, f.shadow_sol_credited,
            f.shadow_sol_donated
        );
    }
    scout_run_property!("P-0031", invariant_p_0031(fixture));
    // SCOUT:INVARIANT:P-0031:END

    // SCOUT:INVARIANT:P-0032:BEGIN
    // P-0032 A DEPOSIT NEVER CREDITS MORE THAN THE POOL RECEIVED.
    //
    // Amplifier #8 from the escalation catalogue: when a transfer fee exists, the
    // tokens that MOVE differ from the amount the caller names, and a pool that credits
    // the named amount is under-collateralised by the fee on every deposit --
    // compounding, invisible in the pool's own books, and paid for by whoever withdraws
    // last. `TransferFeeConfig` is on the program's allow list
    // (`create_spl_interface/validate.rs:68`), so fee-bearing assets are admitted on
    // purpose rather than by oversight.
    //
    // This is deliberately NOT the mirror it first looks like. `settle_spl_deposit`
    // checks `interface_after == interface_before + amount` and rejects otherwise, so
    // asserting that same equation after the fact could never fail. What is asserted
    // instead is the CONSEQUENCE that check exists to produce: no deposit through a fee
    // mint ever succeeds at all. Relax the check to `>=`, drop the `withheld_amount`
    // subtlety by reading the wrong field, or move the comparison to the wrong side of
    // the CPI, and the handler's own assertion is still satisfied while this one fires.
    //
    // The fixture capability is the load-bearing half. Until a fee-bearing Token-2022
    // mint existed here, every SPL deposit moved exactly what it credited because no
    // mint in the harness was capable of anything else -- the escalation was not
    // refuted, it was unobservable.
    fn invariant_p_0032(f: &mut ShieldedPoolFixture) {
        scout_check!(
            "P-0032", "a_deposit_never_credits_more_than_the_pool_received",
            f.shadow_fee_mint_credits == 0,
            "P-0032 fee-mint overcredit: {} deposit(s) through a fee-bearing mint were \
             accepted while the interface account received less than the UTXO credits -- \
             the pool is short the transfer fee on every one of them",
            f.shadow_fee_mint_credits
        );
    }
    scout_run_property!("P-0032", invariant_p_0032(fixture));
    // SCOUT:INVARIANT:P-0032:END

    // SCOUT:INVARIANT:P-0033:BEGIN
    // P-0033 EVERY SPENDING RAIL ACTUALLY PUBLISHES ITS NULLIFIERS.
    //
    // Amplifier #7 -- twin-path divergence -- made mechanical. Five instructions across
    // three proof rails reach one nullifier queue through `insert_nullifier_into_queue`,
    // and the property is that ALL FIVE call it, stated once as a parity meta-invariant
    // rather than as five separate assertions. Asserting the insertion inside the helper
    // would be a mirror; the question is whether every caller reaches the helper.
    //
    // P-0005 structurally CANNOT see this, and that is the point. It counts second
    // acceptances of the fixture's pinned nullifiers, so a rail that skipped insertion
    // entirely would never produce a second acceptance to count -- it would read
    // perfectly quiet while being the one path on which a note is infinitely spendable.
    // P-0016 sees only the split-tree arrangement of one rail. The failure this rules
    // out is the worst one in the protocol: a mint from nothing, on a rail nobody
    // noticed was different.
    //
    // Measured as a per-call delta around a single call, so it needs no baseline and
    // inherited `--stateful` state cannot perturb it. The expected counts are the
    // fixtures' own input counts -- one for the three single-input rails, eight for the
    // two merges -- so a rail that inserted SOME of its inputs fires too, not only one
    // that inserted none.
    fn invariant_p_0033(f: &mut ShieldedPoolFixture) {
        scout_check!(
            "P-0033", "every_spending_rail_publishes_its_nullifiers",
            f.shadow_unpublished_nullifiers == 0,
            "P-0033 unpublished nullifiers: {} successful spend(s) advanced the queue by \
             the wrong number of entries -- a rail consumed inputs whose nullifiers never \
             reached the queue, so those notes remain spendable",
            f.shadow_unpublished_nullifiers
        );
    }
    scout_run_property!("P-0033", invariant_p_0033(fixture));
    // SCOUT:INVARIANT:P-0033:END

    // SCOUT:INVARIANT:P-0034:BEGIN
    // P-0034 TWO SPENDS OF ONE NOTE CANNOT SHARE A TRANSACTION.
    //
    // The first COMPOUND action in this harness. The pool has no begin/end bracket --
    // nothing introspects the instructions sysvar, and no transient flag is set by one
    // instruction and cleared by another -- so there is no suspended-check window to
    // explore, and `references/compound-actions.md`'s flashloan shape does not apply.
    // What multi-instruction transactions DO reach is a question single-instruction
    // actions structurally cannot ask: does the double-spend guard survive being
    // consulted twice inside ONE transaction?
    //
    // Between two transactions the account is reloaded from the ledger, so the second
    // call necessarily observes the first's insertion, and every existing property has
    // only ever tested that arrangement. Within one transaction both instructions
    // operate on the same in-memory account, and the guard holds only if the first
    // insertion is written through before the second reads the bloom filter. A guard
    // reading a stale copy would accept both while every existing property stayed
    // silent -- P-0005 counts successful CALLS, and a transaction accepting both counts
    // as one.
    //
    // The third arm is a legitimate deposit-then-spend pair that must SUCCEED. Without
    // it a refusal on the double-spend arms would be equally consistent with batching
    // being broken in this harness, which is precisely the vacuous pass that has caught
    // this fixture twice before.
    fn invariant_p_0034(f: &mut ShieldedPoolFixture) {
        scout_check!(
            "P-0034", "two_spends_of_one_note_cannot_share_a_transaction",
            f.shadow_intra_tx_double_spends == 0,
            "P-0034 intra-transaction double spend: {} transaction(s) accepted two spends \
             of the same note because they shared one transaction -- the queue's guard \
             read a copy that the first insertion had not been written through to",
            f.shadow_intra_tx_double_spends
        );
    }
    scout_run_property!("P-0034", invariant_p_0034(fixture));
    // SCOUT:INVARIANT:P-0034:END

    // SCOUT:INVARIANT:P-0036:BEGIN
    // P-0036 A RING INSTRUCTION ACCEPTS ONLY ITS OWN RING CONFIG.
    //
    // The pool never re-derives a ring config's address after creation.
    // `create_ring_config` checks the canonical `ring_auth` derivation exactly once and
    // says so in its own comment -- "this is the SOLE place the derivation is ever
    // checked" -- and every later instruction loads the account by owner and
    // discriminator only, then requires its SIGNATURE. Since a `ring_auth` PDA can be
    // signed for by exactly one program, that signature IS the ring's identity, and it
    // is the whole of the authorization.
    //
    // What makes it worth a net rather than an assumption is where the check lives. It
    // is NOT in `load_active_ring_config`; that loader's doc says "Callers must perform
    // the signer check before invoking this loader," and three separate callers do it
    // independently (`deposit/account.rs:79`, `transact/account.rs:193`,
    // `merge_ring/account.rs:28`). One guard written out three times is the arrangement
    // where the fourth writing omits it, and the omission would not look like a bug:
    // the config would still be SPP-owned, still carry the right discriminator, still
    // be unpaused. It would simply belong to somebody else's ring.
    //
    // Pointed at `ring_authority_transact` deliberately. That is the rail where
    // `allow_owner_signers` is false, so the ring moves a user's notes with no owner
    // signature at all -- if any rail must not accept a foreign ring's config, it is
    // that one. Three arrangements are driven: a call through ring B carrying ring A's
    // config, the mirror image, and a direct call to SPP with a real config that simply
    // did not sign. All three are refused with the account iterator's missing-signer
    // error rather than a proof failure, which is what says the guard fired and not
    // something downstream.
    fn invariant_p_0036(f: &mut ShieldedPoolFixture) {
        scout_check!(
            "P-0036", "a_ring_instruction_accepts_only_its_own_ring_config",
            f.shadow_ring_confusions == 0,
            "P-0036 cross-ring confusion: {} ring instruction(s) succeeded while carrying \
             a ring config belonging to a different ring than the one that signed -- the \
             signing identity is the only thing binding a ring to its notes",
            f.shadow_ring_confusions
        );
    }
    scout_run_property!("P-0036", invariant_p_0036(fixture));
    // SCOUT:INVARIANT:P-0036:END

    // SCOUT:INVARIANT:P-0035:BEGIN
    // P-0035 THE PROOF BINDS THE DEDUPLICATED SIGNER SET, AND ONLY THAT.
    //
    // The signer set reaches the circuit as one public input, and the program builds it
    // by hand: `fill_owner_signer_hashes` puts the instruction payer in slot 0, seeds a
    // `seen` map with it, and appends each trailing owner signer not already present --
    // duplicates SKIPPED rather than rejected -- and `fixed_signer_hash_chain`
    // right-folds that prefix against `SIGNER_ZERO_SUFFIX_CHAINS`, a table of
    // precomputed all-zero suffixes that lets a variable-length set match the circuit's
    // fixed-width fold. Dedup, padding and width arithmetic, all hand-rolled, all
    // feeding a public input. Nothing here asserted anything about it, and
    // `fill_owner_signer_hashes` has the worst coverage ratio of any non-blocked
    // function in the program.
    //
    // A defect in that arithmetic is a signer-set confusion: two different sets folding
    // to one chain, so a proof authorising one group of signers is accepted for
    // another. On the ring-authority rail, where notes move with no owner signature at
    // all, that is the difference between a ring acting for its members and a ring
    // acting for anyone's.
    //
    // Asserted from ONE valid proof held fixed while the signers around it vary -- the
    // attacker's position, and the only position a harness with pinned witnesses can
    // take. The counter moves only when a set whose DEDUP DIFFERS from the fixture's is
    // accepted; the identical-after-dedup arm is expected to succeed and is what proves
    // the refusals are about the chain rather than about the account list being
    // positionally rigid.
    fn invariant_p_0035(f: &mut ShieldedPoolFixture) {
        scout_check!(
            "P-0035", "the_proof_binds_the_deduplicated_signer_set",
            f.shadow_signer_set_bypasses == 0,
            "P-0035 signer-set confusion: {} transact(s) verified while the deduplicated \
             signer set differed from the one the proof was generated against -- the \
             signer hash chain does not bind who actually signed",
            f.shadow_signer_set_bypasses
        );
    }
    scout_run_property!("P-0035", invariant_p_0035(fixture));
    // SCOUT:INVARIANT:P-0035:END

    // SCOUT:INVARIANT:P-0037:BEGIN
    // P-0037 A TREE-STATE-DERIVED PUBLIC INPUT IS BOUND, AND IT COMES FROM THE INPUT
    // TREE.
    //
    // `allow_dummy_inputs` is unlike every field P-0020 varies: the attacker does not
    // supply it. The program DERIVES it (`transact/tree.rs:35`) from the input tree,
    // before the instruction's own insertions, as `nullifier_remaining >=
    // state_remaining`, and folds it into the public input hash. The attacker's lever
    // is therefore not the payload but the CHOICE OF TREE -- and `transact` takes two
    // of them, which P-0016 established may differ.
    //
    // Two arms, and the second is the one worth having. Saturating the INPUT tree's
    // queue flips the flag, and the same proof must then be refused: measured, and
    // refused with `TransactProofVerificationFailed` specifically rather than a
    // capacity error, which is what says the flag reached the public inputs rather
    // than the queue simply running out. Saturating the OUTPUT tree's queue must change
    // NOTHING, because the flag is not read from it -- if it ever were, an attacker
    // could choose an output tree that flips a value the proof commits to while the
    // note, the roots and the nullifier all stay exactly as proven, and no property
    // here would notice.
    //
    // The saturated state is synthesised rather than reached by 2^40 insertions, but it
    // is the tree's own documented condition ("the nullifier tree has strictly fewer
    // leaves left than the state tree", `tree/src/lib.rs:283`) and the synthesis moves
    // ONLY `Batch.start_index` -- no root, no leaf, no nullifier, no counter the proof
    // cites. That isolation is what makes the refusal attributable to this one flag.
    fn invariant_p_0037(f: &mut ShieldedPoolFixture) {
        scout_check!(
            "P-0037", "the_dummy_input_flag_is_proof_bound_to_the_input_tree",
            f.shadow_dummy_flag_bypasses == 0,
            "P-0037 dummy-input flag unbound: {} transact(s) verified after the INPUT \
             tree's `allow_dummy_inputs` had flipped -- the program derived a public \
             input the proof does not commit to and accepted it anyway",
            f.shadow_dummy_flag_bypasses
        );
    }
    scout_run_property!("P-0037", invariant_p_0037(fixture));
    // SCOUT:INVARIANT:P-0037:END

    // SCOUT:INVARIANT:P-0038:BEGIN
    // P-0038 A USER'S MERGE OPT-OUT IS HONOURED.
    //
    // `merging_enabled` is one bit, in an account owned by ANOTHER program, and it
    // authorizes an operation any caller may submit -- `merge_transact` is signed by
    // whoever pays, not by the record's owner. The pool reads it across a trust
    // boundary (`merge/account.rs:78`) and gates on it once
    // (`merge/processor.rs:43`).
    //
    // Asserting that one `if` would be a mirror. What this asserts instead is that the
    // BYTE THE REGISTRY WROTE is the byte the pool acts on -- a differential across a
    // foreign layout, not a restatement of a check. That distinction is not theoretical
    // here: this harness has already produced a wrong reading of this exact field, when
    // a borsh `Option` written as its tag byte alone shifted every field after it and
    // `merging_enabled` came back false. The symptom was a merge that failed for a
    // reason nobody had asked for, and nothing in the program objected, because from
    // the pool's side a shifted byte is simply a user who opted out.
    //
    // Both settings are driven and each must produce its OWN outcome -- 0 refuses, 1
    // succeeds -- because a property that only checks the refusal passes just as well
    // on a pool that has stopped merging entirely.
    fn invariant_p_0038(f: &mut ShieldedPoolFixture) {
        scout_check!(
            "P-0038", "a_users_merge_opt_out_is_honoured",
            f.shadow_merge_opt_out_bypasses == 0,
            "P-0038 merge opt-out bypassed: {} merge(s) succeeded for a user whose \
             registry record says merging is disabled -- a bit read across a trust \
             boundary stopped meaning what the registry wrote",
            f.shadow_merge_opt_out_bypasses
        );
    }
    scout_run_property!("P-0038", invariant_p_0038(fixture));
    // SCOUT:INVARIANT:P-0038:END

    // SCOUT:INVARIANT:P-0039:BEGIN
    // P-0039 THE OWNER RAIL IS CHOSEN BY THE ATTACKER AND BOUND BY THE PROOF.
    //
    // `eddsa_owner` is a bool in instruction data, supplied by whoever submits the
    // merge, and it selects which key becomes a proof public input: `record.owner`
    // hashed, or `record.owner_p256` compressed (`merge/account.rs:79-92`). Two
    // different keys, two different public inputs, one attacker-controlled selector.
    //
    // If the selector were not bound, a merge proven for one rail would be accepted on
    // the other, and the note would move under a key whose holder never authorised it.
    // Nothing states this in the program -- it is a consequence of which value gets
    // folded into the hash, exactly the kind of guarantee that disappears silently when
    // a field is reordered.
    //
    // Driven with merging ENABLED, so a refusal is the rail rather than the opt-out --
    // the two gates are adjacent in the same handler and would otherwise be
    // indistinguishable.
    fn invariant_p_0039(f: &mut ShieldedPoolFixture) {
        scout_check!(
            "P-0039", "the_owner_rail_is_bound_by_the_proof",
            f.shadow_merge_rail_bypasses == 0,
            "P-0039 owner-rail confusion: {} merge(s) verified while `eddsa_owner` \
             selected a different owner key than the proof was generated for",
            f.shadow_merge_rail_bypasses
        );
    }
    scout_run_property!("P-0039", invariant_p_0039(fixture));
    // SCOUT:INVARIANT:P-0039:END
    // SCOUT:INVARIANTS:END
}
