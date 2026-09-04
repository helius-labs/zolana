//! The upgrade authority re-pins the table of a live ring on localnet +
//! photon + prover, and a curated Block list yields to the subscriber's own
//! Approval entries.

use anyhow::{anyhow, Result};
use custom_ring_program::CustomRingError;
use custom_ring_sdk::{policy_config_table, CustomRing, SetPolicyRules};
use custom_ring_test_validator::{
    cli::{ListMember, ListWrite, RingProject, RingToml},
    policy::{
        owner_member, policy_config, CuratedRings, EntryTarget, EntryWrite, PolicyTransfer,
        RingNotes, APPROVAL_OR_UNBLOCKED, BLOCK_ONLY, DEPOSIT, TRANSFER_AMOUNT,
    },
    shared::{send_v0_expecting_rejection, ExpectRejection, TestEnv},
};
use solana_signer::Signer;
use zolana_client::ProverClient;
use zolana_keypair::{ShieldedKeypair, ViewingKey};
use zolana_program_test::Rejection;
use zolana_ring_policy::{EntryState, ListId};
use zolana_transaction::Utxo;

/// A local ring rpc, `init` reads the auditor key file and contacts nothing.
const RING_RPC: &str = "http://127.0.0.1:1";

const FORBID_BLOCK_TOML: &str = r#"[policy]
entries_tree = "$TREE"

[[policy.rules]]
subject = "output-owner"
forbid = "block"
"#;

const APPROVAL_OR_UNBLOCKED_TOML: &str = r#"[policy]
entries_tree = "$TREE"

[[policy.rules]]
subject = "output-owner"
any = [{ require = "approval" }, { forbid = "block" }]
"#;

const CURATED_BLOCK_TOML: &str = r#"[policy]
entries_tree = "$TREE"

[policy.sources.localnet]
block = "$CURATOR"

[[policy.rules]]
subject = "output-owner"
any = [{ require = "approval" }, { forbid = "block" }]
"#;

#[test]
fn the_upgrade_authority_re_pins_the_table_of_a_live_ring() -> Result<()> {
    let rings = CuratedRings::setup()?;
    let env = &rings.env;
    let rpc = env.client.rpc();
    let ring = rings.subscriber;
    let prover = ProverClient::local();
    let sender = &env.sender.keypair;
    let blocked = &env.recipient.keypair;
    let clean = ShieldedKeypair::new_ed25519()?;
    let egress = Egress { ring, sender, env };

    // 1. `init` pins the Block row from `ring.toml` at generation 1.
    let project = init_subscriber(&rings, &block(FORBID_BLOCK_TOML, &rings))?;
    let pinned = policy_config(ring, rpc)?;
    assert_eq!(policy_config_table(&pinned)?, BLOCK_ONLY);
    assert_eq!(pinned.generation(), 1);
    assert!(pinned.generation_slot() > 0);
    assert_eq!(pinned.source_for(ListId::Block), Some(ring.namespace_pda()));
    let notes = RingNotes {
        ring,
        owner: sender,
        amount: DEPOSIT,
        count: 2,
        env,
    }
    .deposit()?;

    // 2. Block refuses at witness build, an unblocked recipient proves under
    //    the pinned hash.
    project.write_list(ListWrite {
        env,
        entries_tree: env.tree,
        list_id: ListId::Block,
        member: ListMember::Owner(blocked),
        state: EntryState::Active,
    })?;
    egress.to(blocked, &notes[0]).expect_refusal()?;
    let stale = egress
        .to(&clean, &notes[1])
        .prove(&prover)
        .map_err(|error| anyhow!("proof under the pinned table failed {error}"))?;

    // 3. `policy check` reports the edited `ring.toml` until `policy set` lands
    //    generation 2, both lists on the ring's own entries.
    let mixed = block(APPROVAL_OR_UNBLOCKED_TOML, &rings);
    project.write_config(RingToml {
        env,
        ring_rpc: RING_RPC,
        policy: Some(&mixed),
    })?;
    assert!(
        !project.policy_check()?.status.success(),
        "policy check missed the drift"
    );
    project.policy_set(&mixed)?;
    assert!(
        project.policy_check()?.status.success(),
        "policy check disagrees after the re-pin"
    );
    let repinned = policy_config(ring, rpc)?;
    assert_eq!(policy_config_table(&repinned)?, APPROVAL_OR_UNBLOCKED);
    assert_eq!(repinned.generation(), 2);
    assert!(repinned.generation_slot() > pinned.generation_slot());
    assert_ne!(repinned.policy_hash, pinned.policy_hash);
    assert_eq!(
        repinned.source_for(ListId::Approval),
        Some(ring.namespace_pda())
    );
    assert_eq!(
        repinned.source_for(ListId::Block),
        Some(ring.namespace_pda())
    );

    // 4. The proof over the old hash fails verification, its note stays unspent.
    let rejection = send_v0_expecting_rejection(rpc, sender, stale.instruction()?)?;
    Rejection::custom(CustomRingError::ProofVerificationFailed as u32)
        .at(1)
        .assert_client(&rejection);

    // 5. Block still refuses until the ring's own Approval entry admits.
    egress.to(blocked, &notes[0]).expect_refusal()?;
    project.write_list(ListWrite {
        env,
        entries_tree: env.tree,
        list_id: ListId::Approval,
        member: ListMember::Owner(blocked),
        state: EntryState::Active,
    })?;
    egress.to(blocked, &notes[0]).land(&prover)?;

    // 6. Only the upgrade authority re-pins.
    let stranger = env.funded_keypair()?;
    let rejection = ExpectRejection {
        payer: &stranger,
        instructions: &[SetPolicyRules {
            ring,
            authority: stranger.pubkey(),
            rules: &BLOCK_ONLY,
            shared_sources: Vec::new(),
        }
        .instruction()?],
    }
    .send(rpc)?;
    Rejection::custom(CustomRingError::UnauthorizedInitializer as u32)
        .at(1)
        .assert_client(&rejection);
    let unchanged = policy_config(ring, rpc)?;
    assert_eq!(
        unchanged.generation(),
        2,
        "a refused re-pin counts no generation"
    );
    assert_eq!(unchanged.generation_slot(), repinned.generation_slot());
    assert_eq!(policy_config_table(&unchanged)?, APPROVAL_OR_UNBLOCKED);

    // 7. A source re-point on the re-pinned table counts generation 3, the
    //    unspent note lands against the curator's empty Block list.
    project.run(&[
        "list",
        "set-source",
        "block",
        "--curator",
        &rings.curator.program_id().to_string(),
    ])?;
    let repointed = policy_config(ring, rpc)?;
    assert_eq!(repointed.generation(), 3);
    assert!(repointed.generation_slot() > repinned.generation_slot());
    assert_eq!(
        repointed.source_for(ListId::Block),
        Some(rings.curator.namespace_pda())
    );
    assert_eq!(policy_config_table(&repointed)?, APPROVAL_OR_UNBLOCKED);
    egress.to(&clean, &notes[1]).land(&prover)?;
    project.remove()?;
    Ok(())
}

#[test]
fn a_curated_block_list_yields_to_the_subscribers_own_approval_entries() -> Result<()> {
    let rings = CuratedRings::setup()?;
    let env = &rings.env;
    let rpc = env.client.rpc();
    let ring = rings.subscriber;
    let prover = ProverClient::local();
    let sender = &env.sender.keypair;
    let recipient = &env.recipient.keypair;
    let egress = Egress { ring, sender, env };
    let curator_block = |target, state| EntryWrite {
        ring: rings.curator,
        target,
        state,
        fee_payer: &env.payer,
        env,
    };

    // 1. The subscriber pins the mixed group with Block read from the curator.
    let project = init_subscriber(&rings, &block(CURATED_BLOCK_TOML, &rings))?;
    let pinned = policy_config(ring, rpc)?;
    assert_eq!(policy_config_table(&pinned)?, APPROVAL_OR_UNBLOCKED);
    assert_eq!(pinned.generation(), 1);
    assert!(pinned.generation_slot() > 0);
    assert_eq!(
        pinned.source_for(ListId::Block),
        Some(rings.curator.namespace_pda())
    );
    assert_eq!(
        pinned.source_for(ListId::Approval),
        Some(ring.namespace_pda())
    );
    let notes = RingNotes {
        ring,
        owner: sender,
        amount: DEPOSIT,
        count: 2,
        env,
    }
    .deposit()?;

    // 2. One curator write refuses the recipient, the subscriber's own
    //    Approval entry admits it.
    let blocked = curator_block(
        EntryTarget::Claim {
            list_id: ListId::Block,
            member: owner_member(recipient)?,
        },
        EntryState::Active,
    )
    .send(&prover)?;
    egress.to(recipient, &notes[0]).expect_refusal()?;
    project.write_list(ListWrite {
        env,
        entries_tree: env.tree,
        list_id: ListId::Approval,
        member: ListMember::Owner(recipient),
        state: EntryState::Active,
    })?;
    egress.to(recipient, &notes[0]).land(&prover)?;

    // 3. A cleared Approval entry admits nothing, the curator's Block entry
    //    refuses again.
    project.write_list(ListWrite {
        env,
        entries_tree: env.tree,
        list_id: ListId::Approval,
        member: ListMember::Owner(recipient),
        state: EntryState::Cleared,
    })?;
    egress.to(recipient, &notes[1]).expect_refusal()?;

    // 4. The curator clearing its entry admits through the cleared-entry
    //    absence branch.
    curator_block(EntryTarget::Successor(blocked), EntryState::Cleared).send(&prover)?;
    egress.to(recipient, &notes[1]).land(&prover)?;
    project.remove()?;
    Ok(())
}

/// The literal with the env tree and the curator program filled in.
fn block(literal: &str, rings: &CuratedRings) -> String {
    literal
        .replace("$TREE", &rings.env.tree.to_string())
        .replace("$CURATOR", &rings.curator.program_id().to_string())
}

/// After `init` the project's config authority holds the config.
fn init_subscriber(rings: &CuratedRings, policy: &str) -> Result<RingProject> {
    let project = RingProject::create(&rings.env, &ViewingKey::new().pubkey())?;
    project.write_config(RingToml {
        env: &rings.env,
        ring_rpc: RING_RPC,
        policy: Some(policy),
    })?;
    let init = project.run(&["init"])?;
    for line in ["policy      created", "spp ring    registered"] {
        assert!(init.contains(line), "{line} in\n{init}");
    }
    Ok(project)
}

struct Egress<'a> {
    ring: CustomRing,
    sender: &'a ShieldedKeypair,
    env: &'a TestEnv,
}

impl<'a> Egress<'a> {
    fn to(&self, recipient: &'a ShieldedKeypair, note: &Utxo) -> PolicyTransfer<'a> {
        PolicyTransfer {
            ring: self.ring,
            sender: self.sender,
            recipient,
            note: note.clone(),
            amount: TRANSFER_AMOUNT,
            env: self.env,
        }
    }
}
