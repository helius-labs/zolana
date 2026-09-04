//! The four released rows on localnet + photon + prover. The Allow rows admit
//! only enrolled parties, a Frozen sender and a Block output owner are refused,
//! and the operator cli pins the same rows from `ring.toml`, enrols its demo
//! parties and transacts under them.

use std::{
    net::{Ipv4Addr, TcpListener},
    sync::Arc,
    time::Duration,
};

use anyhow::{anyhow, Result};
use custom_ring_sdk::{policy_config_table, CustomRing, ReadEntry};
use custom_ring_test_validator::{
    cli::{merged, ListMember, ListWrite, RingProject, RingToml},
    policy::{
        owner_member, policy_config, EntryTarget, EntryWrite, PolicyTransfer, RingNotes, DEPOSIT,
        RELEASED, TOKEN_BLOCK, TRANSFER_AMOUNT,
    },
    shared::{custom_ring_program_id, setup, RegisterRing, TestEnv, Tier, ACTOR_AIRDROP},
};
use solana_address::Address;
use solana_signer::Signer;
use zolana_client::ProverClient;
use zolana_keypair::{ShieldedKeypair, ViewingKey};
use zolana_ring_client::{AuditedTransaction, RingAudit, RingEnvironment};
use zolana_ring_policy::{EntryState, ListId, Member};
use zolana_ring_rpc::{
    run_server, BindPolicy, ChainSource, Hub, ServerOptions, TransactionSource, Upstreams,
};
use zolana_transaction::{Utxo, SOL_MINT};

/// `RELEASED` as `ring.toml` spells it.
const RELEASED_TOML: &str = r#"[policy]

[[policy.rules]]
subject = "output-owner"
require = "allow"

[[policy.rules]]
subject = "sender"
require = "allow"

[[policy.rules]]
subject = "output-owner"
forbid = "block"

[[policy.rules]]
subject = "sender"
forbid = "frozen"
"#;

const TOKEN_BLOCK_TOML: &str = r#"[policy]

[[policy.rules]]
subject = "asset"
forbid = "block"
"#;

#[test]
fn allow_frozen_and_block_rows_govern_every_transfer() -> Result<()> {
    let env = setup()?;
    let rpc = env.client.rpc();
    let ring = CustomRing::new(custom_ring_program_id()?);
    let prover = ProverClient::local();
    RegisterRing {
        ring,
        payer: &env.payer,
        auditor_pubkey: ViewingKey::new().pubkey(),
        tier: Tier::policy(&RELEASED, env.tree),
    }
    .send(rpc)?;
    let pinned = policy_config(ring, rpc)?;
    assert_eq!(
        policy_config_table(&pinned)?,
        RELEASED,
        "the stored rows reproduce the pinned hash"
    );
    assert_eq!(pinned.generation(), 1);
    assert!(pinned.generation_slot() > 0);
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

/// The ring rpc `transact` reads back from runs in process.
#[test]
fn the_cli_pins_the_released_rows_and_governs_its_demo_transfers() -> Result<()> {
    let env = setup()?;
    let rpc = env.client.rpc();
    let indexer = env.client.indexer();
    let demo = DemoRing::init(&env, RELEASED_TOML)?;
    let ring = demo.ring;

    // 1. `init` pins the rows verbatim at generation 1 and registers the ring.
    let config = ring
        .read_config(rpc)?
        .ok_or_else(|| anyhow!("config after init"))?;
    assert_eq!(
        config.authority,
        demo.project.config_authority.pubkey(),
        "the config authority holds the config"
    );
    assert!(config.has_policy, "policy tier");
    let policy = policy_config(ring, rpc)?;
    assert_eq!(
        policy.entries_tree, demo.tree,
        "the policy pins the cli's default tree"
    );
    assert_eq!(policy_config_table(&policy)?, RELEASED);
    assert_eq!(policy.generation(), 1);
    assert!(policy.generation_slot() > 0);

    // 2. The demo, a granted reader, enrols both parties in Allow, the
    //    auditor opens its transfer.
    demo.grant_reader()?;
    let output = demo.project.run(&["transact"])?;
    for line in [
        "allow       sender claimed",
        "allow       recipient claimed",
    ] {
        assert!(output.contains(line), "{line} in\n{output}");
    }
    let transactions = demo.audited()?;
    let [transfer] = transactions.as_slice() else {
        return Err(anyhow!(
            "expected one audited transfer, got {}",
            transactions.len()
        ));
    };
    assert_eq!(transfer.outputs.len(), 2, "change and recipient");
    for output in &transfer.outputs {
        assert_eq!(output.ring_program_id, Some(ring.program_id()));
        let live = ReadEntry {
            entries_tree: demo.tree,
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

    // 3. A Frozen demo sender is refused until `list clear` releases it.
    let sender = demo.project.demo_sender()?;
    let frozen = |state| ListWrite {
        env: &env,
        entries_tree: demo.tree,
        list_id: ListId::Frozen,
        member: ListMember::Owner(&sender),
        state,
    };
    demo.project.write_list(frozen(EntryState::Active))?;
    demo.refused_transact()?;
    demo.project.write_list(frozen(EntryState::Cleared))?;
    demo.project.run(&["transact"])?;
    assert_eq!(
        demo.audited()?.len(),
        2,
        "the released sender transacts again"
    );
    demo.project.remove()?;
    Ok(())
}

/// Every demo output carries SOL.
#[test]
fn a_blocked_token_refuses_every_transfer() -> Result<()> {
    let env = setup()?;
    let rpc = env.client.rpc();
    let demo = DemoRing::init(&env, TOKEN_BLOCK_TOML)?;

    // 1. `init` pins the asset row at generation 1.
    let policy = policy_config(demo.ring, rpc)?;
    assert_eq!(
        policy.entries_tree, demo.tree,
        "the policy pins the cli's default tree"
    );
    assert_eq!(policy_config_table(&policy)?, TOKEN_BLOCK);
    assert_eq!(policy.generation(), 1);
    assert!(policy.generation_slot() > 0);

    // 2. An empty Block list admits the demo transfer.
    demo.grant_reader()?;
    demo.project.run(&["transact"])?;
    assert_eq!(
        demo.audited()?.len(),
        1,
        "an empty Block list admits the demo"
    );

    // 3. SOL on Block refuses the demo until `list clear` releases it.
    let block = |state| ListWrite {
        env: &env,
        entries_tree: demo.tree,
        list_id: ListId::Block,
        member: ListMember::Asset(SOL_MINT),
        state,
    };
    demo.project.write_list(block(EntryState::Active))?;
    demo.refused_transact()?;
    demo.project.write_list(block(EntryState::Cleared))?;
    demo.project.run(&["transact"])?;
    assert_eq!(
        demo.audited()?.len(),
        2,
        "the released token transacts again"
    );
    demo.project.remove()?;
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

struct DemoRing<'a> {
    env: &'a TestEnv,
    ring: CustomRing,
    tree: Address,
    auditor: ViewingKey,
    project: RingProject,
    _ring_rpc: LocalRingRpc,
}

impl<'a> DemoRing<'a> {
    fn init(env: &'a TestEnv, policy: &str) -> Result<Self> {
        let ring = CustomRing::new(custom_ring_program_id()?);
        // Without `entries_tree` the block pins the cli's default tree, the demo
        // deposits there too.
        let tree = env.register_default_tree()?;
        let auditor = ViewingKey::new();
        let ring_rpc = RingRpcSpec {
            env,
            ring: ring.program_id(),
            auditor: auditor.clone(),
        }
        .serve()?;
        let project = RingProject::create(env, &auditor.pubkey())?;
        project.write_config(RingToml {
            env,
            ring_rpc: &ring_rpc.url,
            policy: Some(policy),
        })?;
        let init = project.run(&["init"])?;
        for line in ["policy      created", "spp ring    registered"] {
            assert!(init.contains(line), "{line} in\n{init}");
        }
        Ok(Self {
            env,
            ring,
            tree,
            auditor,
            project,
            _ring_rpc: ring_rpc,
        })
    }

    fn grant_reader(&self) -> Result<()> {
        self.project.run(&[
            "reader",
            "grant",
            &self.project.config_authority.pubkey().to_string(),
        ])?;
        Ok(())
    }

    fn audited(&self) -> Result<Vec<AuditedTransaction>> {
        Ok(RingAudit::new(self.ring.program_id(), &self.auditor)
            .run(
                RingEnvironment {
                    indexer: self.env.client.indexer(),
                    origin: self.env.client.rpc(),
                },
                &self.env.assets,
            )?
            .transactions)
    }

    fn refused_transact(&self) -> Result<()> {
        let refused = self.project.output(&["transact"])?;
        assert!(
            !refused.status.success(),
            "transact landed under a refusing rule"
        );
        let text = merged(&refused);
        assert!(
            text.contains("a policy rule refuses the transfer"),
            "{text}"
        );
        Ok(())
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
