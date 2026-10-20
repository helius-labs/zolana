//! Every shipped policy key executes both proofs and the SPP state transition.

use super::*;
use custom_ring_interface::{policy_shape_supported, tag};
use custom_ring_test_validator::policy::{owner_member, RegistryWrite, RingNotes};
use custom_ring_test_validator::shared::setup_with_extra_rings;
use zolana_interface::shape::{Shape, SPP_SUPPORTED_SHAPES};
use zolana_ring_client::TransactionAudit;
use zolana_ring_policy::{ListId, OutflowLimit, Rule, RuleTable, Subject};
use zolana_test_utils::test_validator_asserts::{assert_ring_transact, RingTransactAssertArgs};
use zolana_transaction::instructions::transact::AnonymousOutputKeys;

const NOTE_AMOUNT: u64 = 1_000_000;

#[derive(Clone, Copy, Debug)]
enum Mode {
    Member,
    Anonymous,
    Delegate,
}

impl Mode {
    fn anonymous(self) -> bool {
        matches!(self, Self::Anonymous)
    }

    fn delegate(self) -> bool {
        matches!(self, Self::Delegate)
    }

    fn ring_mode(self) -> RingMode {
        if self.anonymous() {
            RingMode::Anonymous
        } else {
            RingMode::Registry
        }
    }

    fn tag(self, subtree: bool) -> u8 {
        match (self.delegate(), subtree) {
            (false, false) => tag::TRANSACT_SHAPED,
            (false, true) => tag::TRANSACT_SHAPED_SUBTREE,
            (true, false) => tag::DELEGATE_TRANSACT_SHAPED,
            (true, true) => tag::DELEGATE_TRANSACT_SHAPED_SUBTREE,
        }
    }
}

struct GovernedRing<'a> {
    env: &'a TestEnv,
    ring: CustomRing,
    mode: Mode,
    auditor: X25519Keypair,
    delegate: Keypair,
}

impl GovernedRing<'_> {
    fn configure(&self) -> Result<()> {
        let env = self.env;
        let authority = env.payer.pubkey();
        let create = if self.mode.anonymous() {
            self.ring
                .create_anonymous_config(authority, authority, self.auditor.pubkey(), true)?
        } else {
            self.ring
                .create_config(authority, authority, self.auditor.pubkey(), true)?
        };
        send(env.client.rpc(), &env.payer, &[create])?;
        let rules = RuleTable::builder()
            .rule(Rule::require(Subject::Sender, ListId::Allow))
            .rule(Rule::require(Subject::OutputOwner, ListId::Allow))
            .rule(Rule::require(Subject::Asset, ListId::Allow))
            .rule(Rule::forbid(Subject::Sender, ListId::Frozen))
            .limits(&[OutflowLimit {
                asset: zolana_interface::SOL_ASSET_FIELD,
                cap: 16 * NOTE_AMOUNT,
                cosign_above: 0,
            }])
            .build();
        send(
            env.client.rpc(),
            &env.payer,
            &[
                self.ring.create_member_registry_root(authority, authority),
                self.ring
                    .create_policy(authority, authority, env.tree, &rules, &[])?,
            ],
        )?;
        send(
            env.client.rpc(),
            &env.payer,
            &[self.ring.init_spp_ring_config(authority, authority, true)],
        )?;
        if !self.mode.anonymous() {
            EscrowedDelegate {
                ring: self.ring,
                delegate: self.delegate.pubkey(),
                members: &[&env.sender.keypair, &env.recipient.keypair],
            }
            .set(env)?;
        }
        if self.mode.delegate() {
            env.enable_authority_rail(self.ring)?;
        }
        for member in [
            owner_member(&env.sender.keypair)?,
            owner_member(&env.recipient.keypair)?,
            Member::asset(&SOL_MINT)?,
        ] {
            RegistryWrite {
                ring: self.ring,
                list_id: ListId::Allow,
                member,
                present: true,
                env,
            }
            .send()?;
        }
        Ok(())
    }

    fn owner_transfer(
        &self,
        shape: Shape,
        output_count: usize,
        inputs: Vec<WalletUtxo>,
        payer: Address,
    ) -> Result<CustomRingTransfer<'_>> {
        let env = self.env;
        let total = NOTE_AMOUNT * shape.n_inputs() as u64;
        let mut tx = if output_count < shape.n_outputs() {
            ConfidentialTransaction::new_compact_with_ring(inputs, payer, self.ring.program_id())?
        } else {
            ConfidentialTransaction::new_with_ring(inputs, payer, self.ring.program_id())?
        }
        .with_output_tree_id(env.tree_id(env.tree)?)?;
        for _ in 1..output_count {
            tx.transfer_sol(
                &env.recipient.keypair.shielded_address()?,
                total / (2 * output_count as u64),
            )?;
        }
        tx.pad_utxos(shape, &env.sender.keypair.shielded_address()?)?;
        Ok(CustomRingTransfer::new(CustomRingTransferInput {
            ring: self.ring,
            sender: &env.sender.keypair,
            nullifier_key: Some(&env.sender.keypair.nullifier_key),
            transaction: tx,
        }))
    }

    fn reject_oversized_cosigned_transfer(&self, inputs: &[WalletUtxo]) -> Result<()> {
        let env = self.env;
        let authority = env.payer.pubkey();
        let cosigner = env.funded_keypair()?;
        send(
            env.client.rpc(),
            &env.payer,
            &[self.ring.set_cosigner(
                authority,
                authority,
                cosigner.pubkey(),
                CoSignScope::TRANSFERS,
                &[],
            )?],
        )?;
        let unreachable = env.client_with(
            ProverClient::new("http://127.0.0.1:1".into())
                .with_proof_data_source(ProofDataSource::Client),
        );
        let tree_before = fetch_account(env.client.rpc(), &env.tree)?;
        let mut sizes = Vec::new();
        for _ in 0..2 {
            let transfer = self
                .owner_transfer(Shape::IN16_OUT4, 4, inputs.to_vec(), env.payer.pubkey())?
                .with_cosigner(cosigner.pubkey());
            match env.run(transfer.prove(unreachable.as_async())) {
                Err(RingError::TransactionTooLarge { bytes, limit }) => {
                    assert_eq!(limit, MAX_TRANSACTION_SIZE);
                    assert!(bytes > limit);
                    sizes.push(bytes);
                }
                Err(error) => {
                    return Err(anyhow!("expected pre-proof size rejection, got {error}"))
                }
                Ok(_) => return Err(anyhow!("oversized co-signed transfer was proved")),
            }
        }
        assert_eq!(
            sizes[0], sizes[1],
            "size rejection is independent of encryption randomness"
        );
        assert_account_unchanged(env.client.rpc(), &env.tree, &tree_before)?;
        send(
            env.client.rpc(),
            &env.payer,
            &[self.ring.clear_cosigner(authority, authority)],
        )?;
        println!(
            "POLICY_SIZE_REJECTION Member 16x4 cosigner=true separate_payer=true bytes={}",
            sizes[0]
        );
        Ok(())
    }

    fn transfer(&self, shape: Shape, subtree: bool) -> Result<()> {
        self.transfer_with_outputs(shape, shape.n_outputs(), subtree)
    }

    fn transfer_with_outputs(
        &self,
        shape: Shape,
        output_count: usize,
        subtree: bool,
    ) -> Result<()> {
        let env = self.env;
        let label = format!(
            "{:?} {}x{} subtree={subtree}",
            self.mode,
            shape.n_inputs(),
            output_count
        );
        let client = env.client_with(ProverClient::new(prover_url()).with_proof_data_source(
            if subtree {
                ProofDataSource::Client
            } else {
                ProofDataSource::Prover
            },
        ));
        let inputs = RingNotes {
            ring: self.ring,
            owner: &env.sender.keypair,
            amount: NOTE_AMOUNT,
            count: shape.n_inputs(),
            env,
        }
        .deposit_from(&env.payer)?
        .into_iter()
        .map(|note| indexed_note(note, &env.sender.keypair, env, env.tree))
        .collect::<Result<Vec<_>>>()?;
        if matches!(self.mode, Mode::Member) && shape == Shape::IN16_OUT4 && !subtree {
            self.reject_oversized_cosigned_transfer(&inputs)?;
        }
        let input_nullifiers: Vec<_> = inputs.iter().map(|input| input.nullifier).collect();
        let total = NOTE_AMOUNT * shape.n_inputs() as u64;
        let payer: &(dyn Signer + Sync) = if matches!(self.mode, Mode::Member) {
            &env.sender.keypair
        } else {
            &env.payer
        };
        let proven = if self.mode.delegate() {
            let mut transfer = DelegateTransfer::new(DelegateTransferInput {
                ring: self.ring,
                delegate: self.delegate.pubkey(),
                payer: payer.pubkey(),
                source_nullifier_key: &env.sender.keypair.nullifier_key,
                inputs: inputs.into_iter().map(SppProofInputUtxo::from).collect(),
                outputs: (0..output_count)
                    .map(|index| {
                        Ok(DelegateOutput {
                            recipient: env.recipient.keypair.shielded_address()?,
                            asset: SOL_MINT,
                            amount: total / output_count as u64
                                + if index + 1 == output_count {
                                    total % output_count as u64
                                } else {
                                    0
                                },
                        })
                    })
                    .collect::<Result<Vec<_>>>()?,
            })
            .with_assets(&env.assets);
            if output_count < shape.n_outputs() {
                transfer = transfer.with_compact_padding();
            }
            env.run(transfer.prove(client.as_async()))
        } else {
            let transfer = self.owner_transfer(shape, output_count, inputs, payer.pubkey())?;
            if self.mode.anonymous() {
                env.run(
                    transfer
                        .with_anonymous_signer(
                            &env.sender.keypair.signing_key,
                            AnonymousViewTags::new(AnonymousOutputKeys {
                                tag: env.sender.keypair.get_sender_view_tag(0)?,
                                pair_pk: X25519Keypair::new().pubkey(),
                            })
                            .with_recipient(
                                env.recipient.keypair.shielded_address()?.viewing_pubkey,
                                AnonymousOutputKeys {
                                    tag: env.recipient.keypair.recipient_bootstrap_view_tag(),
                                    pair_pk: X25519Keypair::new().pubkey(),
                                },
                            ),
                        )
                        .prove(client.as_async()),
                )
            } else {
                env.run(transfer.prove(client.as_async()))
            }
        }
        .with_context(|| format!("prove {label}"))?;
        let instruction = proven.instruction()?;
        let expected_tag = if shape.n_inputs() == 2 && output_count == 3 {
            assert!(subtree, "the exact 2x3 keys require a shared subtree");
            if self.mode.delegate() {
                tag::DELEGATE_TRANSACT_TWO_BY_THREE
            } else {
                tag::TRANSACT_TWO_BY_THREE
            }
        } else {
            self.mode.tag(subtree)
        };
        assert_eq!(instruction.data[0], expected_tag, "{label}");
        assert_eq!(proven.data.inputs.len(), shape.n_inputs(), "{label}");
        assert_eq!(proven.data.outputs.len(), output_count, "{label}");
        assert_eq!(
            proven
                .data
                .inputs
                .iter()
                .map(|input| input.nullifier_hash)
                .collect::<Vec<_>>(),
            input_nullifiers,
            "{label}: every real input must be consumed",
        );
        let size = zolana_client::transaction_size(
            &payer.pubkey(),
            std::slice::from_ref(&instruction),
            ComputeBudgetConfig::new(compute_unit_limit(InstructionTag::Transact)),
        )?;
        assert!(
            size.bytes <= MAX_TRANSACTION_SIZE,
            "{label}: {} bytes",
            size.bytes
        );
        let tree_before = fetch_account(env.client.rpc(), &env.tree)?;
        let signers: Vec<&(dyn Signer + Sync)> = if self.mode.delegate() {
            vec![&self.delegate]
        } else {
            Vec::new()
        };
        let signature = land(env, instruction, payer, &signers)?;
        let units = assert_transaction_compute_units(
            env.client.rpc(),
            &signature,
            &label,
            u64::from(compute_unit_limit(InstructionTag::Transact)),
        )?;
        let auditor_tag = auditor_view_tag(&self.auditor.pubkey());
        assert_ring_transact(
            env.client.rpc(),
            env.client.indexer(),
            RingTransactAssertArgs {
                tree: &env.tree,
                data: &proven.data,
                signature,
                fetch_view_tag: auditor_tag,
                tree_before: &tree_before,
            },
        )?;
        let indexed = wait_for_indexed_transaction(env.client.indexer(), auditor_tag, signature);
        let audited = TransactionAudit {
            auditor: &self.auditor,
            transaction: &indexed,
            assets: &env.assets,
        }
        .run_with_mode(self.mode.ring_mode())?;
        assert_eq!(audited.output_openings.len(), output_count, "{label}");
        for (opening, output) in audited.output_openings.iter().zip(&proven.data.outputs) {
            assert_eq!(
                opening.hash()?,
                output.utxo_hash,
                "{label}: auditor sees settled commitments"
            );
        }
        assert_eq!(
            audited
                .outputs
                .iter()
                .map(|output| output.amount)
                .sum::<u64>(),
            total,
            "{label}"
        );
        assert!(audited.undecryptable_slots.is_empty(), "{label}");
        assert_eq!(
            audited.anonymous.is_some(),
            self.mode.anonymous(),
            "{label}"
        );
        println!(
            "POLICY_SETTLEMENT {label} bytes={} addresses={} cu={units}",
            size.bytes, size.addresses
        );
        Ok(())
    }
}

#[test]
fn every_shipped_policy_shape_settles_with_general_and_subtree_proofs() -> Result<()> {
    let anonymous_program = Keypair::new().pubkey();
    let delegate_program = Keypair::new().pubkey();
    let env = setup_with_extra_rings(&[anonymous_program, delegate_program])?;
    println!("POLICY_FIXTURE tree={} mint={}", env.tree, env.usdc_mint);
    let mut covered = 0;
    for (mode, program) in [
        (Mode::Anonymous, anonymous_program),
        (Mode::Delegate, delegate_program),
        (Mode::Member, custom_ring_program_id()?),
    ] {
        let ring = GovernedRing {
            env: &env,
            ring: CustomRing::new(program),
            mode,
            auditor: X25519Keypair::new(),
            delegate: Keypair::new(),
        };
        ring.configure()?;
        // Exercise each rail's largest payload before the smaller shapes.
        for shape in SPP_SUPPORTED_SHAPES.into_iter().rev() {
            if !policy_shape_supported(
                shape.n_inputs(),
                shape.n_outputs(),
                mode.anonymous(),
                mode.delegate(),
            ) {
                continue;
            }
            for subtree in [false, true] {
                ring.transfer(shape, subtree)?;
                covered += 1;
            }
        }
    }
    assert_eq!(
        covered,
        custom_ring_interface::shaped_verifying_keys::SHAPED_PROVING_KEY_SHA256S.len()
    );
    Ok(())
}

#[test]
fn exact_two_by_three_policy_keys_settle_for_every_mode() -> Result<()> {
    let anonymous_program = Keypair::new().pubkey();
    let delegate_program = Keypair::new().pubkey();
    let env = setup_with_extra_rings(&[anonymous_program, delegate_program])?;
    for (mode, program) in [
        (Mode::Member, custom_ring_program_id()?),
        (Mode::Anonymous, anonymous_program),
        (Mode::Delegate, delegate_program),
    ] {
        let ring = GovernedRing {
            env: &env,
            ring: CustomRing::new(program),
            mode,
            auditor: X25519Keypair::new(),
            delegate: Keypair::new(),
        };
        ring.configure()?;
        ring.transfer_with_outputs(Shape::IN2_OUT4, 3, true)?;
    }
    Ok(())
}

/// The anonymous settlement keys still match the post-427 program. Keep these
/// cases runnable while ordinary owner-signed keys await publication.
#[test]
fn anonymous_shapes_settle_with_current_keys() -> Result<()> {
    settle_matching_key_mode(Mode::Anonymous, 28)
}

/// The ring-authority settlement keys also match the post-427 program.
#[test]
fn delegate_shapes_settle_with_current_keys() -> Result<()> {
    settle_matching_key_mode(Mode::Delegate, 4)
}

#[test]
#[ignore = "requires post-427 ordinary SPP transfer proving keys"]
fn ordinary_two_by_two_settles_after_key_rotation() -> Result<()> {
    let env = setup_with_extra_rings(&[])?;
    let ring = GovernedRing {
        env: &env,
        ring: CustomRing::new(custom_ring_program_id()?),
        mode: Mode::Member,
        auditor: X25519Keypair::new(),
        delegate: Keypair::new(),
    };
    ring.configure()?;
    for subtree in [false, true] {
        ring.transfer(Shape::IN2_OUT2, subtree)?;
    }
    Ok(())
}

fn settle_matching_key_mode(mode: Mode, expected_capacities: usize) -> Result<()> {
    let program = Keypair::new().pubkey();
    let env = setup_with_extra_rings(&[program])?;
    let ring = GovernedRing {
        env: &env,
        ring: CustomRing::new(program),
        mode,
        auditor: X25519Keypair::new(),
        delegate: Keypair::new(),
    };
    ring.configure()?;
    let mut covered = 0;
    for shape in SPP_SUPPORTED_SHAPES {
        if !policy_shape_supported(
            shape.n_inputs(),
            shape.n_outputs(),
            mode.anonymous(),
            mode.delegate(),
        ) {
            continue;
        }
        for subtree in [false, true] {
            ring.transfer(shape, subtree)?;
            covered += 1;
        }
    }
    assert_eq!(covered, expected_capacities);
    ring.transfer_with_outputs(Shape::IN2_OUT4, 3, true)?;
    Ok(())
}
