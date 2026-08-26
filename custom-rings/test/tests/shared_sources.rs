//! Two rings share one policy source on localnet + photon + prover. The
//! subscriber's Block kind reads the curator ring's records, so one curator
//! write refuses the subscriber's transfer, clearing the record or re-pointing
//! the source re-admits it, and the subscriber cannot mutate the curator-served
//! kind on its own ring.

#[allow(dead_code)]
mod shared;

use anyhow::{anyhow, bail, Result};
use custom_ring_interface::POLICY;
use custom_ring_program::CustomRingError;
use custom_ring_sdk::{
    read_record, CreateConfig, CreatePolicy, CreateRecord, CustomRing, CustomRingTransfer,
    CustomRingTransferInput, InitSppRingConfig, PolicySource, ProvenTransfer,
    RecordProofEnvironment, RingDeposit, RingDepositReceipt, SetPolicySource, TransferError,
    TransferProofEnvironment, UpdateRecord, V0WithLookupTable,
};
use shared::{
    custom_ring_program_id, send, send_v0_expecting_rejection, setup_with_extra_rings, TestEnv,
};
use solana_keypair::Keypair;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{ProverClient, SolanaRpc};
use zolana_keypair::ViewingKey;
use zolana_program_test::Rejection;
use zolana_ring_policy::{Member, Record, RecordKind, RecordState, RuleSource};
use zolana_test_utils::test_validator_asserts::{wait_for_indexed_utxo, wait_for_merkle_proof};
use zolana_transaction::{
    instructions::{transact::ConfidentialTransfer, types::SppProofInputUtxo},
    Utxo, SOL_MINT,
};

const DEPOSIT: u64 = 1_000_000_000;
const TRANSFER_AMOUNT: u64 = 250_000_000;

#[test]
fn a_curator_sourced_blocklist_governs_the_subscriber_ring() -> Result<()> {
    // The host table must be the one row the blocklist image compiles, a wider
    // or empty table cannot reproduce the on-chain policy hash.
    let rules = POLICY.rules();
    assert!(
        matches!(rules, [rule] if matches!(rule.source, RuleSource::Records(RecordKind::Block))),
        "the compiled table is the blocklist row alone"
    );

    let curator_program = Keypair::new().pubkey();
    let env = setup_with_extra_rings(&[curator_program])?;
    let rpc = env.client.rpc();
    let indexer = env.client.indexer();
    let subscriber = CustomRing::new(custom_ring_program_id()?);
    let curator = CustomRing::new(curator_program);
    let prover = ProverClient::local();
    let authority = env.payer.pubkey();

    // 1. Both rings get a config and an SPP registration under one authority.
    for ring in [subscriber, curator] {
        RegisterRing {
            ring,
            payer: &env.payer,
        }
        .send(rpc)?;
    }

    // 2. The curator serves its own records and must exist first, the
    //    subscriber's Block slot copies the curator's resolved records owner.
    send(
        rpc,
        &env.payer,
        &[CreatePolicy {
            ring: curator,
            payer: authority,
            authority,
            records_tree: env.tree,
            shared_sources: vec![],
        }
        .instruction()?],
    )?;
    send(
        rpc,
        &env.payer,
        &[CreatePolicy {
            ring: subscriber,
            payer: authority,
            authority,
            records_tree: env.tree,
            shared_sources: vec![(RecordKind::Block, curator)],
        }
        .instruction()?],
    )?;
    let stored = subscriber
        .read_policy_config(rpc)?
        .ok_or_else(|| anyhow!("subscriber policy config"))?;
    assert_eq!(
        stored.source_for(RecordKind::Block as u8),
        Some(curator.records_pda()),
        "the Block slot names the curator records"
    );

    // 3. Three subscriber-ring notes, one transfer per policy phase.
    let mut notes = Vec::with_capacity(3);
    for _ in 0..3 {
        let RingDepositReceipt { utxo, .. } = RingDeposit {
            ring: subscriber,
            payer: &env.sender.keypair,
            recipient: &env.sender.keypair,
            tree: env.tree,
            amount: DEPOSIT,
        }
        .send(rpc)?;
        let leaf = SppProofInputUtxo::new(utxo.clone(), &env.sender.keypair).hash()?;
        wait_for_merkle_proof(indexer, env.tree, leaf);
        notes.push(utxo);
    }

    // 4. No Block record exists yet, the transfer passes on the absence proof
    //    against the curator's empty records.
    SubscriberTransfer {
        ring: subscriber,
        note: notes[0].clone(),
        env: &env,
    }
    .land(&prover)?;

    // 5. One curator write refuses the next transfer at witness build.
    let member = Member::owner_tag(
        &env.recipient
            .keypair
            .signing_pubkey()
            .confidential_view_tag()?,
    )?;
    let active = CuratorBlockWrite {
        curator,
        member,
        state: RecordState::Active,
        spent: None,
        env: &env,
    }
    .send(&prover)?;
    let blocked = SubscriberTransfer {
        ring: subscriber,
        note: notes[1].clone(),
        env: &env,
    }
    .prove(&prover);
    match blocked {
        Err(TransferError::PolicyRuleUnsatisfied) => {}
        Err(other) => bail!("expected PolicyRuleUnsatisfied, got {other}"),
        Ok(_) => bail!("expected PolicyRuleUnsatisfied, the transfer was proven"),
    }

    // 6. The curator-served kind is immutable on the subscriber ring, the
    //    program refuses the mutation after a valid record proof.
    let foreign = CreateRecord {
        ring: subscriber,
        payer: authority,
        records_tree: env.tree,
        kind: RecordKind::Block,
        member,
        state: RecordState::Active,
        payload_hash: [0u8; 32],
    }
    .prove(RecordProofEnvironment {
        indexer,
        rpc,
        prover: &prover,
    })?;
    let rejection = send_v0_expecting_rejection(rpc, &env.payer, foreign.instruction()?)?;
    Rejection::custom(CustomRingError::ForeignRecordSource as u32)
        .at(1)
        .assert_client(&rejection);

    // 7. Clearing the record re-admits the transfer through the cleared-record
    //    absence branch, the refused note is still unspent.
    let cleared = CuratorBlockWrite {
        curator,
        member,
        state: RecordState::Cleared,
        spent: Some(active),
        env: &env,
    }
    .send(&prover)?;
    SubscriberTransfer {
        ring: subscriber,
        note: notes[1].clone(),
        env: &env,
    }
    .land(&prover)?;

    // 8. With the record active again, re-pointing Block to the subscriber's
    //    own records turns curator enforcement off.
    CuratorBlockWrite {
        curator,
        member,
        state: RecordState::Active,
        spent: Some(cleared),
        env: &env,
    }
    .send(&prover)?;
    send(
        rpc,
        &env.payer,
        &[SetPolicySource {
            ring: subscriber,
            authority,
            kind: RecordKind::Block,
            source: PolicySource::Own,
        }
        .instruction()?],
    )?;
    let repointed = subscriber
        .read_policy_config(rpc)?
        .ok_or_else(|| anyhow!("subscriber policy config"))?;
    assert_eq!(
        repointed.source_for(RecordKind::Block as u8),
        Some(subscriber.records_pda()),
        "the Block slot is back on the subscriber records"
    );
    SubscriberTransfer {
        ring: subscriber,
        note: notes[2].clone(),
        env: &env,
    }
    .land(&prover)?;

    Ok(())
}

struct RegisterRing<'a> {
    ring: CustomRing,
    payer: &'a Keypair,
}

impl RegisterRing<'_> {
    fn send(self, rpc: &SolanaRpc) -> Result<()> {
        let authority = self.payer.pubkey();
        send(
            rpc,
            self.payer,
            &[CreateConfig {
                ring: self.ring,
                payer: authority,
                authority,
                auditor_pubkey: ViewingKey::new().pubkey(),
            }
            .instruction()?],
        )?;
        send(
            rpc,
            self.payer,
            &[InitSppRingConfig {
                ring: self.ring,
                payer: authority,
                authority,
            }
            .instruction()],
        )?;
        Ok(())
    }
}

/// One 1-in 2-out ring transfer of [`TRANSFER_AMOUNT`] to the recipient.
struct SubscriberTransfer<'a> {
    ring: CustomRing,
    note: Utxo,
    env: &'a TestEnv,
}

impl SubscriberTransfer<'_> {
    fn prove(self, prover: &ProverClient) -> Result<ProvenTransfer, TransferError> {
        let sender = &self.env.sender.keypair;
        let mut transfer = ConfidentialTransfer::new(
            sender.shielded_address()?,
            vec![SppProofInputUtxo::new(self.note, sender)],
            sender.pubkey(),
        )
        .with_compact_change()
        .with_ring_program_id(self.ring.program_id());
        transfer.send(
            &self.env.recipient.keypair.shielded_address()?,
            SOL_MINT,
            TRANSFER_AMOUNT,
        )?;
        CustomRingTransfer::new(CustomRingTransferInput {
            ring: self.ring,
            sender,
            prepared: transfer.prepare()?,
        })
        .with_tree(self.env.tree)
        .with_assets(&self.env.assets)
        .prove(TransferProofEnvironment {
            indexer: self.env.client.indexer(),
            rpc: self.env.client.rpc(),
            prover,
        })
    }

    /// Submits the proven transfer and waits until photon serves its first
    /// output leaf, the next proof then builds on a synced index.
    fn land(self, prover: &ProverClient) -> Result<Signature> {
        let env = self.env;
        let proven = self
            .prove(prover)
            .map_err(|error| anyhow!("transfer proof failed {error}"))?;
        let landed = proven
            .data
            .outputs
            .first()
            .ok_or_else(|| anyhow!("transfer output"))?
            .utxo_hash;
        let signature = V0WithLookupTable {
            payer: &env.sender.keypair,
            signers: &[],
            instruction: proven.instruction()?,
        }
        .send(env.client.rpc())?;
        wait_for_merkle_proof(env.client.indexer(), env.tree, landed);
        Ok(signature)
    }
}

/// One curator-signed Block mutation for `member`, landed and readable through
/// the indexer before it returns.
struct CuratorBlockWrite<'a> {
    curator: CustomRing,
    member: Member,
    state: RecordState,
    spent: Option<Record>,
    env: &'a TestEnv,
}

impl CuratorBlockWrite<'_> {
    fn send(self, prover: &ProverClient) -> Result<Record> {
        let env = self.env;
        let rpc = env.client.rpc();
        let indexer = env.client.indexer();
        let environment = RecordProofEnvironment {
            indexer,
            rpc,
            prover,
        };
        let proven = match self.spent {
            None => CreateRecord {
                ring: self.curator,
                payer: env.payer.pubkey(),
                records_tree: env.tree,
                kind: RecordKind::Block,
                member: self.member,
                state: self.state,
                payload_hash: [0u8; 32],
            }
            .prove(environment)?,
            Some(spent) => UpdateRecord {
                ring: self.curator,
                payer: env.payer.pubkey(),
                records_tree: env.tree,
                spent,
                state: self.state,
                payload_hash: [0u8; 32],
            }
            .prove(environment)?,
        };
        let record = proven.record();
        let signature = send(rpc, &env.payer, &[proven.instruction()?])?;
        wait_for_indexed_utxo(indexer, self.curator.records_pda().to_bytes(), signature);
        let live = read_record(
            indexer,
            self.curator.records_pda(),
            RecordKind::Block,
            &self.member,
        )?
        .ok_or_else(|| anyhow!("curator Block record after the write"))?;
        assert_eq!(live.record, record, "indexed record equals the mutation");
        wait_for_merkle_proof(indexer, env.tree, live.utxo_hash);
        Ok(record)
    }
}
