//! The upgrade authority re-pins the table of a live ring on localnet +
//! photon + prover, and a curated Block list yields to the subscriber's own
//! Approval list.

use anyhow::{anyhow, Result};
use custom_ring_interface::CustomRingError;
use custom_ring_sdk::{policy_config_table, CustomRing, ListRegistry};
use custom_ring_test_validator::{
    cli::{ListWrite, RingProject, RingToml},
    policy::{
        owner_member, policy_config, CuratedRings, PolicyTransfer, RegistryWrite, RingNotes,
        APPROVAL_OR_UNBLOCKED, BLOCK_ONLY, DEPOSIT, TRANSFER_AMOUNT,
    },
    shared::{send_expecting_rejection, ExpectRejection, TestEnv},
};
use solana_signer::Signer;
use zolana_keypair::ShieldedKeypair;
use zolana_program_test::Rejection;
use zolana_ring_policy::ListId;
use zolana_transaction::Utxo;

/// A local ring rpc, `init` reads the auditor key file and contacts nothing.
const RING_RPC: &str = "http://127.0.0.1:1";

const FORBID_BLOCK_TOML: &str = r#"[policy]
address_tree = "$TREE"

[[policy.rules]]
subject = "output-owner"
forbid = "block"
"#;

const APPROVAL_OR_UNBLOCKED_TOML: &str = r#"[policy]
address_tree = "$TREE"

[[policy.rules]]
subject = "output-owner"
any = [{ require = "approval" }, { forbid = "block" }]
"#;

const CURATED_BLOCK_TOML: &str = r#"[policy]
address_tree = "$TREE"

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
    let sender = &env.sender.keypair;
    let blocked = &env.recipient.keypair;
    let clean = ShieldedKeypair::new_ed25519()?;
    let egress = Egress { ring, sender, env };

    // 1. `init` pins the Block row from `ring.toml` at generation 1.
    let project = init_subscriber(&rings, &block(FORBID_BLOCK_TOML, &rings))?;
    let pinned = policy_config(ring, env)?;
    assert_eq!(policy_config_table(&pinned)?, BLOCK_ONLY);
    assert_eq!(pinned.generation(), 1);
    assert!(pinned.generation_slot() > 0);
    assert_eq!(pinned.registry_for(ListId::Block), Some(ListRegistry::Own));
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
        list_id: ListId::Block,
        member: blocked,
        present: true,
    })?;
    egress.to(blocked, &notes[0]).expect_refusal()?;
    let stale = egress
        .to(&clean, &notes[1])
        .prove(&env.client)
        .map_err(|error| anyhow!("proof under the pinned table failed {error}"))?;

    // 3. `policy check` reports the edited `ring.toml` until `policy set` lands
    //    generation 2, both lists on the ring's own registry.
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
    let repinned = policy_config(ring, env)?;
    assert_eq!(policy_config_table(&repinned)?, APPROVAL_OR_UNBLOCKED);
    assert_eq!(repinned.generation(), 2);
    assert!(repinned.generation_slot() > pinned.generation_slot());
    assert_ne!(repinned.policy_hash, pinned.policy_hash);
    assert_eq!(
        repinned.registry_for(ListId::Approval),
        Some(ListRegistry::Own)
    );
    assert_eq!(
        repinned.registry_for(ListId::Block),
        Some(ListRegistry::Own)
    );

    // 4. The proof over the old hash fails verification, its note stays unspent.
    let rejection = send_expecting_rejection(rpc, sender, stale.instruction()?)?;
    Rejection::custom(CustomRingError::ProofVerificationFailed as u32)
        .at(0)
        .assert_client(&rejection);

    // 5. Block still refuses until the ring's own Approval bit admits.
    egress.to(blocked, &notes[0]).expect_refusal()?;
    project.write_list(ListWrite {
        env,
        list_id: ListId::Approval,
        member: blocked,
        present: true,
    })?;
    egress.to(blocked, &notes[0]).land()?;

    // 6. Only the upgrade authority re-pins.
    let stranger = env.funded_keypair()?;
    let rejection = ExpectRejection {
        payer: &stranger,
        instructions: &[ring.set_policy_rules(stranger.pubkey(), &BLOCK_ONLY, &[])?],
    }
    .send(rpc)?;
    Rejection::custom(CustomRingError::UnauthorizedInitializer as u32)
        .at(0)
        .assert_client(&rejection);
    let unchanged = policy_config(ring, env)?;
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
    let repointed = policy_config(ring, env)?;
    assert_eq!(repointed.generation(), 3);
    assert!(repointed.generation_slot() > repinned.generation_slot());
    assert_eq!(
        repointed.registry_for(ListId::Block),
        Some(ListRegistry::Curator(
            rings.curator.member_registry_root_pda()
        ))
    );
    assert_eq!(policy_config_table(&repointed)?, APPROVAL_OR_UNBLOCKED);
    egress.to(&clean, &notes[1]).land()?;
    project.remove()?;
    Ok(())
}

#[test]
fn a_curated_block_list_yields_to_the_subscribers_own_approval_list() -> Result<()> {
    let rings = CuratedRings::setup()?;
    let env = &rings.env;
    let ring = rings.subscriber;
    let sender = &env.sender.keypair;
    let recipient = &env.recipient.keypair;
    let egress = Egress { ring, sender, env };
    let member = owner_member(recipient)?;
    let curator_block = |present| RegistryWrite {
        ring: rings.curator,
        list_id: ListId::Block,
        member,
        present,
        env,
    };

    // 1. The subscriber pins the mixed group with Block read from the curator.
    let project = init_subscriber(&rings, &block(CURATED_BLOCK_TOML, &rings))?;
    let pinned = policy_config(ring, env)?;
    assert_eq!(policy_config_table(&pinned)?, APPROVAL_OR_UNBLOCKED);
    assert_eq!(pinned.generation(), 1);
    assert!(pinned.generation_slot() > 0);
    assert_eq!(
        pinned.registry_for(ListId::Block),
        Some(ListRegistry::Curator(
            rings.curator.member_registry_root_pda()
        ))
    );
    assert_eq!(
        pinned.registry_for(ListId::Approval),
        Some(ListRegistry::Own)
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
    //    Approval bit admits it.
    curator_block(true).send()?;
    egress.to(recipient, &notes[0]).expect_refusal()?;
    project.write_list(ListWrite {
        env,
        list_id: ListId::Approval,
        member: recipient,
        present: true,
    })?;
    egress.to(recipient, &notes[0]).land()?;

    // 3. A cleared Approval bit admits nothing, the curator's Block bit
    //    refuses again.
    project.write_list(ListWrite {
        env,
        list_id: ListId::Approval,
        member: recipient,
        present: false,
    })?;
    egress.to(recipient, &notes[1]).expect_refusal()?;

    // 4. The curator clearing its bit admits the recipient again.
    curator_block(false).send()?;
    egress.to(recipient, &notes[1]).land()?;
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
    let project = RingProject::create(&rings.env, &zolana_keypair::X25519Secret::new().pubkey())?;
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
