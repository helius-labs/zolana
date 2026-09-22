use std::{num::NonZeroU64, time::Instant};

use anyhow::{Context, Result};
use custom_ring_cli::transact::{self, Probe};
use custom_ring_program::CustomRingError;
use custom_ring_sdk::{
    CustomRing, CustomRingTransfer, CustomRingTransferInput, DepositAsset, DepositProofEnvironment,
    RegisterSpend, RingDeposit, TransferProofEnvironment,
};
use custom_ring_test_validator::shared::{
    custom_ring_program_id, send, send_expecting_rejection, setup, RegisterRing, TestEnv, Tier,
};
use solana_signer::Signer;
use zolana_client::{rpc::RingMemberProofRequest, ProverClient, Rpc};
use zolana_interface::SOL_ASSET_FIELD;
use zolana_keypair::{ShieldedKeypair, ViewingKey};
use zolana_program_test::Rejection;
use zolana_ring_policy::{Member, RuleTable, VelocityRow};
use zolana_transaction::instructions::transact::{canonical_shape, ConfidentialTransaction};

const RULES: RuleTable = RuleTable::builder()
    .windowed(NonZeroU64::new(1_000_000).unwrap())
    .velocity(&[VelocityRow {
        asset: SOL_ASSET_FIELD,
        cap: 1_000_000_000,
        cosign_above: 1_000_000_000,
    }])
    .build();

#[derive(Clone, Copy)]
enum Churn {
    Stable,
    Register,
}

struct Benchmark<'a> {
    env: &'a TestEnv,
    ring: CustomRing,
    prover: ProverClient,
    vacant: Member,
}

impl Benchmark<'_> {
    fn catch_up(&self) -> Result<()> {
        let root = self
            .ring
            .read_head_map_root(self.env.client.rpc())?
            .context("head map missing")?;
        let request = RingMemberProofRequest {
            ring_program_id: self.ring.program_id().into(),
            member: (*self.vacant.as_bytes()).into(),
            expected_root: root.root.into(),
            expected_next_index: root.next_index,
        };
        transact::wait_for("head projection".to_owned(), || {
            Ok(
                match self
                    .env
                    .client
                    .indexer()
                    .get_ring_head_register_proof(request.clone())
                {
                    Ok(_) => Probe::Ready(()),
                    Err(error) => Probe::Retry(error),
                },
            )
        })?;
        Ok(())
    }

    fn actor(&self) -> Result<ShieldedKeypair> {
        let member = ShieldedKeypair::new_ed25519()?;
        zolana_client::SolanaRpc::new(self.env.rpc_url.clone())
            .airdrop(&member.pubkey(), 1_000_000_000)?;
        self.catch_up()?;
        let registration = RegisterSpend {
            ring: self.ring,
            payer: member.pubkey(),
        }
        .prove(self.proving())?;
        send(
            self.env.client.rpc(),
            &member,
            &[registration.instruction()?],
        )?;
        self.catch_up()?;
        Ok(member)
    }

    fn proving(
        &self,
    ) -> TransferProofEnvironment<'_, zolana_client::ZolanaIndexer, zolana_client::SolanaRpc> {
        TransferProofEnvironment {
            indexer: self.env.client.indexer(),
            rpc: self.env.client.rpc(),
            prover: &self.prover,
        }
    }

    fn run(&self, case: ContentionCase) -> Result<()> {
        let actors = (0..case.members)
            .map(|_| self.actor())
            .collect::<Result<Vec<_>>>()?;
        let mut transfers = Vec::new();
        for member in &actors {
            let deposit = RingDeposit {
                ring: self.ring,
                payer: member,
                recipient: member,
                tree: self.env.tree,
                asset: DepositAsset::Sol,
                amount: 2_000_000,
                cosigner: None,
            }
            .send(DepositProofEnvironment {
                rpc: self.env.client.rpc(),
                prover: &self.prover,
            })?;
            transact::wait_for_indexed_transaction(self.env.client.indexer(), deposit.signature)?;
            let tree_id = custom_ring_sdk::tree_id(self.env.client.rpc(), self.env.tree)?;
            let input = zolana_test_utils::utxo::indexed(
                deposit.utxo,
                &member.nullifier_key,
                self.env.client.indexer(),
                tree_id,
            )?;
            let mut transfer = ConfidentialTransaction::new_with_ring(
                vec![input],
                member.pubkey(),
                self.ring.program_id(),
            )?
            .with_output_tree_id(tree_id)?;
            transfer.transfer_sol(&self.env.recipient.keypair.shielded_address()?, 1_000_000)?;
            transfer.pad_utxos(
                canonical_shape(transfer.inputs().len(), 2)?,
                &member.shielded_address()?,
            )?;
            transfers.push(
                CustomRingTransfer::new(CustomRingTransferInput {
                    ring: self.ring,
                    sender: member,
                    nullifier_key: Some(&member.nullifier_key),
                    transaction: transfer,
                })
                .with_tree(self.env.tree),
            );
        }
        self.catch_up()?;
        let start = Instant::now();
        let proofs = transfers
            .iter()
            .map(|transfer| transfer.clone().prove(self.proving()))
            .collect::<Result<Vec<_>, _>>()?;
        let initial_proof_ms = start.elapsed().as_millis();
        if matches!(case.churn, Churn::Register) {
            self.actor()?;
        }
        let mut stale = 0;
        let mut reproof_ms = 0;
        let start = Instant::now();
        for (index, ((member, transfer), proof)) in
            actors.iter().zip(transfers).zip(proofs).enumerate()
        {
            let proof = if index > 0 || matches!(case.churn, Churn::Register) {
                let error =
                    send_expecting_rejection(self.env.client.rpc(), member, proof.instruction()?)?;
                Rejection::custom(CustomRingError::StaleHeadMapRoot as u32)
                    .at(0)
                    .assert_client(&error);
                stale += 1;
                self.catch_up()?;
                let retry_start = Instant::now();
                let proof = transfer.prove(self.proving())?;
                reproof_ms += retry_start.elapsed().as_millis();
                proof
            } else {
                proof
            };
            send(self.env.client.rpc(), member, &[proof.instruction()?])?;
        }
        let settle_ms = start.elapsed().as_millis();
        println!(
            "head_contention,{},{},{},{},{},{},{}",
            case.members,
            u8::from(matches!(case.churn, Churn::Register)),
            stale,
            case.members + stale,
            initial_proof_ms,
            reproof_ms,
            settle_ms
        );
        Ok(())
    }
}

struct ContentionCase {
    members: usize,
    churn: Churn,
}

#[test]
#[ignore = "requires isolated local validator and prover"]
fn same_root_batches_measure_reproof_cost_with_registration_churn() -> Result<()> {
    let env = setup()?;
    let ring = CustomRing::new(custom_ring_program_id()?);
    RegisterRing {
        ring,
        payer: &env.payer,
        auditor_pubkey: ViewingKey::new().pubkey(),
        tier: Tier::policy(&RULES, env.tree),
    }
    .send(env.client.rpc())?;
    let seed = RingDeposit {
        ring,
        payer: &env.sender.keypair,
        recipient: &env.sender.keypair,
        tree: env.tree,
        asset: DepositAsset::Sol,
        amount: 2_000_000,
        cosigner: None,
    }
    .send(DepositProofEnvironment {
        rpc: env.client.rpc(),
        prover: &ProverClient::local(),
    })?;
    transact::wait_for_indexed_transaction(env.client.indexer(), seed.signature)?;
    let benchmark = Benchmark {
        env: &env,
        ring,
        prover: ProverClient::local(),
        vacant: Member::owner_tag(ShieldedKeypair::new_ed25519()?.pubkey().as_array())?,
    };
    println!("head_contention,members,registration_churn,stale_rejections,proof_attempts,initial_proof_ms,reproof_ms,settle_ms");
    for churn in [Churn::Stable, Churn::Register] {
        for members in [1, 2, 4, 8] {
            benchmark.run(ContentionCase { members, churn })?;
        }
    }
    Ok(())
}
