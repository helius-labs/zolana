//! The rules image on localnet + photon + prover. The Allow rows admit only
//! enrolled parties, a Frozen sender and a Block output owner are refused,
//! and the operator cli's pipeline enrols its demo parties before its transfer.

use std::{
    net::{Ipv4Addr, TcpListener},
    sync::Arc,
    time::Duration,
};

use anyhow::{anyhow, Result};
use custom_ring_interface::RULES;
use custom_ring_sdk::{CustomRing, ReadEntry};
use custom_ring_test_validator::{
    cli::{RingProject, RingToml},
    policy::{
        owner_member, EntryTarget, EntryWrite, PolicyTransfer, RingNotes, DEPOSIT, TRANSFER_AMOUNT,
    },
    shared::{
        custom_ring_program_id, ring_program_so, setup, RegisterRing, TestEnv, Tier, ACTOR_AIRDROP,
    },
};
use solana_address::Address;
use solana_signer::Signer;
use zolana_client::ProverClient;
use zolana_keypair::{ShieldedKeypair, ViewingKey};
use zolana_ring_client::{RingAudit, RingEnvironment};
use zolana_ring_policy::{EntryState, ListId, Member, Rule};
use zolana_ring_rpc::{
    run_server, BindPolicy, ChainSource, Hub, ServerOptions, TransactionSource, Upstreams,
};
use zolana_transaction::Utxo;

#[test]
fn allow_frozen_and_block_rows_govern_every_transfer() -> Result<()> {
    // The host table must be the four rows the rules image compiles, a
    // narrower table cannot reproduce the on-chain policy hash.
    let referenced: Vec<ListId> = RULES
        .rules()
        .iter()
        .flat_map(Rule::referenced_lists)
        .collect();
    assert_eq!(
        referenced,
        [ListId::Allow, ListId::Allow, ListId::Block, ListId::Frozen],
        "the compiled table is the rules image"
    );

    let env = setup()?;
    let rpc = env.client.rpc();
    let ring = CustomRing::new(custom_ring_program_id()?);
    let prover = ProverClient::local();
    RegisterRing {
        ring,
        payer: &env.payer,
        auditor_pubkey: ViewingKey::new().pubkey(),
        tier: Tier::policy(env.tree),
    }
    .send(rpc)?;
    let sender = &env.sender.keypair;
    let recipient = &env.recipient.keypair;
    let sender_member = owner_member(sender)?;
    let blocked = ShieldedKeypair::new_ed25519()?;
    env.fund(blocked.pubkey(), ACTOR_AIRDROP)?;
    let blocked_member = owner_member(&blocked)?;
    let egress = Egress {
        ring,
        recipient,
        env: &env,
    };
    let enrol = |list_id, member| EntryWrite {
        ring,
        target: EntryTarget::Claim { list_id, member },
        state: EntryState::Active,
        fee_payer: &env.payer,
        env: &env,
    };
    let clear = |entry| EntryWrite {
        ring,
        target: EntryTarget::Successor(entry),
        state: EntryState::Cleared,
        fee_payer: &env.payer,
        env: &env,
    };

    // 1. Allow admits a transfer only with both parties enrolled.
    let notes = RingNotes {
        ring,
        owner: sender,
        amount: DEPOSIT,
        count: 2,
        env: &env,
    }
    .deposit()?;
    enrol(ListId::Allow, sender_member).send(&prover)?;
    egress.spend(sender, &notes[0]).expect_refusal()?;
    enrol(ListId::Allow, owner_member(recipient)?).send(&prover)?;
    egress.spend(sender, &notes[0]).land(&prover)?;

    // 2. A Frozen sender is refused until its entry clears.
    let frozen = enrol(ListId::Frozen, sender_member).send(&prover)?;
    egress.spend(sender, &notes[1]).expect_refusal()?;
    clear(frozen).send(&prover)?;
    egress.spend(sender, &notes[1]).land(&prover)?;

    // 3. Deposits are ungoverned ingress, the rows bound egress, and Block
    //    refuses the party's own change output even once Allow admits it.
    let block = enrol(ListId::Block, blocked_member).send(&prover)?;
    let note = RingNotes {
        ring,
        owner: &blocked,
        amount: DEPOSIT,
        count: 1,
        env: &env,
    }
    .deposit()?
    .into_iter()
    .next()
    .ok_or_else(|| anyhow!("the Block party's note"))?;
    egress.spend(&blocked, &note).expect_refusal()?;
    enrol(ListId::Allow, blocked_member).send(&prover)?;
    egress.spend(&blocked, &note).expect_refusal()?;
    clear(block).send(&prover)?;
    egress.spend(&blocked, &note).land(&prover)?;

    Ok(())
}

/// `pipeline` over a `[policy]` ring against the rules image, the ring rpc it
/// reads back from runs in process.
#[test]
fn the_pipeline_enrols_the_demo_parties_and_transacts() -> Result<()> {
    let env = setup()?;
    let rpc = env.client.rpc();
    let indexer = env.client.indexer();
    let ring_program = custom_ring_program_id()?;
    let ring = CustomRing::new(ring_program);
    // The pipeline pins the cli's default tree and deposits into it.
    let default_tree = env.register_default_tree()?;
    let auditor = ViewingKey::new();
    let ring_rpc = RingRpcSpec {
        env: &env,
        ring: ring_program,
        auditor: auditor.clone(),
    }
    .serve()?;
    let project = RingProject::create(&env, &auditor.pubkey())?;
    project.write_config(RingToml {
        env: &env,
        ring_rpc: &ring_rpc.url,
        policy: true,
    })?;

    let output = project.run(&["pipeline", "--program-so", &ring_program_so()])?;
    for line in [
        "policy      created",
        "spp ring    registered",
        "allow       sender claimed",
        "allow       recipient claimed",
    ] {
        assert!(output.contains(line), "{line} in\n{output}");
    }
    let config = ring
        .read_config(rpc)?
        .ok_or_else(|| anyhow!("config after the pipeline"))?;
    assert_eq!(
        config.authority,
        project.config_authority.pubkey(),
        "the config authority holds the config"
    );
    assert!(config.has_policy, "policy tier");
    let policy = ring
        .read_policy_config(rpc)?
        .ok_or_else(|| anyhow!("policy after the pipeline"))?;
    assert_eq!(
        policy.entries_tree, default_tree,
        "the policy pins the cli's default tree"
    );

    // The auditor opens the demo transfer, both output owners sit on Allow.
    let audited = RingAudit::new(ring_program, &auditor)
        .run(
            RingEnvironment {
                indexer,
                origin: rpc,
            },
            &env.assets,
        )?
        .transactions;
    let [transfer] = audited.as_slice() else {
        return Err(anyhow!(
            "expected one audited transfer, got {}",
            audited.len()
        ));
    };
    assert_eq!(transfer.outputs.len(), 2, "change and recipient");
    for output in &transfer.outputs {
        assert_eq!(output.ring_program_id, Some(ring_program));
        let live = ReadEntry {
            entries_tree: default_tree,
            namespace: ring.namespace_pda(),
            list_id: ListId::Allow,
            member: Member::owner_tag(&output.owner_tag)?,
        }
        .read(indexer)?
        .ok_or_else(|| anyhow!("Allow entry of slot {}", output.slot_index))?;
        assert_eq!(
            live.entry.state,
            EntryState::Active,
            "slot {} is enrolled",
            output.slot_index
        );
    }
    project.remove()?;
    Ok(())
}

struct Egress<'a> {
    ring: CustomRing,
    recipient: &'a ShieldedKeypair,
    env: &'a TestEnv,
}

impl<'a> Egress<'a> {
    fn spend(&self, sender: &'a ShieldedKeypair, note: &Utxo) -> PolicyTransfer<'a> {
        PolicyTransfer {
            ring: self.ring,
            sender,
            recipient: self.recipient,
            note: note.clone(),
            amount: TRANSFER_AMOUNT,
            env: self.env,
        }
    }
}

struct RingRpcSpec<'a> {
    env: &'a TestEnv,
    ring: Address,
    auditor: ViewingKey,
}

struct LocalRingRpc {
    url: String,
    _runtime: tokio::runtime::Runtime,
}

impl RingRpcSpec<'_> {
    fn serve(self) -> Result<LocalRingRpc> {
        let runtime = tokio::runtime::Runtime::new()?;
        let source = ChainSource::connect(Upstreams {
            indexer_url: &self.env.indexer_url,
            rpc_url: &self.env.rpc_url,
            timeout: Duration::from_secs(30),
        })
        .map_err(|e| anyhow!("ring rpc upstreams {e:?}"))?;
        let genesis_hash = runtime
            .block_on(source.genesis_hash())
            .map_err(|e| anyhow!("genesis hash {e:?}"))?;
        let hub = Hub::builder(source, genesis_hash)
            .local(self.ring, self.auditor)
            .map_err(|e| anyhow!("hub {e:?}"))?;
        let port = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?
            .local_addr()?
            .port();
        let server = runtime
            .block_on(run_server(
                Arc::new(hub),
                ServerOptions {
                    bind: Ipv4Addr::LOCALHOST.into(),
                    bind_policy: BindPolicy::LoopbackOnly,
                    port,
                    max_connections: 16,
                    request_timeout: Duration::from_secs(30),
                },
            ))
            .map_err(|e| anyhow!("ring rpc server {e:?}"))?;
        // The server stops with its last handle, the task holds one until the
        // runtime goes.
        runtime.spawn(async move {
            let _server = server;
            std::future::pending::<()>().await;
        });
        Ok(LocalRingRpc {
            url: format!("http://127.0.0.1:{port}"),
            _runtime: runtime,
        })
    }
}
