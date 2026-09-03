//! Two rings share one policy source on localnet + photon + prover. The
//! subscriber's Block list reads the curator ring's entries, so one curator
//! write refuses the subscriber's transfer, clearing the entry or re-pointing
//! the source re-admits it, and the subscriber cannot mutate the curator-served
//! list on its own ring.

use anyhow::Result;
use custom_ring_program::CustomRingError;
use custom_ring_sdk::{CreateEntry, EntryProofEnvironment, SetSourceOwner, SourceOwner};
use custom_ring_test_validator::{
    policy::{
        owner_member, policy_config, CuratedRings, EntryTarget, EntryWrite, PolicyTransfer,
        RingNotes, BLOCK_ONLY, DEPOSIT, TRANSFER_AMOUNT,
    },
    shared::{send, send_v0_expecting_rejection, RegisterRing, Tier},
};
use solana_signer::Signer;
use zolana_client::ProverClient;
use zolana_keypair::ViewingKey;
use zolana_program_test::Rejection;
use zolana_ring_policy::{EntryState, ListId};
use zolana_transaction::Utxo;

#[test]
fn a_curator_sourced_blocklist_governs_the_subscriber_ring() -> Result<()> {
    let CuratedRings {
        env,
        curator,
        subscriber,
    } = CuratedRings::setup()?;
    let rpc = env.client.rpc();
    let indexer = env.client.indexer();
    let prover = ProverClient::local();
    let authority = env.payer.pubkey();
    let transfer = |note: &Utxo| PolicyTransfer {
        ring: subscriber,
        sender: &env.sender.keypair,
        recipient: &env.recipient.keypair,
        note: note.clone(),
        amount: TRANSFER_AMOUNT,
        env: &env,
    };

    // 1. The subscriber pins behind the curator's pin, its Block slot copies
    //    the curator's resolved namespace owner, and it registers with SPP
    //    only behind its own pin.
    RegisterRing {
        ring: subscriber,
        payer: &env.payer,
        auditor_pubkey: ViewingKey::new().pubkey(),
        tier: Tier::Policy {
            entries_tree: env.tree,
            rules: &BLOCK_ONLY,
            shared_sources: vec![(ListId::Block, curator)],
        },
    }
    .send(rpc)?;
    let stored = policy_config(subscriber, rpc)?;
    assert_eq!(
        stored.source_for(ListId::Block),
        Some(curator.namespace_pda()),
        "the Block slot names the curator entries"
    );
    assert_eq!(stored.generation(), 1);

    // 2. Three subscriber-ring notes, one transfer per policy phase.
    let notes = RingNotes {
        ring: subscriber,
        owner: &env.sender.keypair,
        amount: DEPOSIT,
        count: 3,
        env: &env,
    }
    .deposit()?;

    // 3. No Block entry exists yet, the transfer passes on the absence proof
    //    against the curator's empty entries.
    transfer(&notes[0]).land(&prover)?;

    // 4. One curator write refuses the next transfer at witness build.
    let member = owner_member(&env.recipient.keypair)?;
    let active = EntryWrite {
        ring: curator,
        target: EntryTarget::Claim {
            list_id: ListId::Block,
            member,
        },
        state: EntryState::Active,
        fee_payer: &env.payer,
        env: &env,
    }
    .send(&prover)?;
    transfer(&notes[1]).expect_refusal()?;

    // 5. The curator-served list is immutable on the subscriber ring, the
    //    program refuses the mutation after a valid entry proof.
    let foreign = CreateEntry {
        ring: subscriber,
        payer: authority,
        entries_tree: env.tree,
        list_id: ListId::Block,
        member,
        state: EntryState::Active,
        content_hash: [0u8; 32],
    }
    .prove(EntryProofEnvironment {
        indexer,
        rpc,
        prover: &prover,
    })?;
    let rejection = send_v0_expecting_rejection(rpc, &env.payer, foreign.instruction()?)?;
    Rejection::custom(CustomRingError::ForeignSource as u32)
        .at(1)
        .assert_client(&rejection);

    // 6. Clearing the entry re-admits the transfer through the cleared-entry
    //    absence branch, the refused note is still unspent. An unrelated
    //    deposit rotates the state root between the entry read and the proof.
    let cleared = EntryWrite {
        ring: curator,
        target: EntryTarget::Successor(active),
        state: EntryState::Cleared,
        fee_payer: &env.payer,
        env: &env,
    }
    .send(&prover)?;
    RingNotes {
        ring: subscriber,
        owner: &env.sender.keypair,
        amount: DEPOSIT,
        count: 1,
        env: &env,
    }
    .deposit()?;
    transfer(&notes[1]).land(&prover)?;

    // 7. A relayer pays the reactivation, the curator authority only co-signs.
    //    With the entry active again, re-pointing Block to the subscriber's
    //    own entries turns curator enforcement off.
    let relayer = env.funded_keypair()?;
    EntryWrite {
        ring: curator,
        target: EntryTarget::Successor(cleared),
        state: EntryState::Active,
        fee_payer: &relayer,
        env: &env,
    }
    .send(&prover)?;
    send(
        rpc,
        &env.payer,
        &[SetSourceOwner {
            ring: subscriber,
            authority,
            list_id: ListId::Block,
            source: SourceOwner::Own,
        }
        .instruction()?],
    )?;
    let repointed = policy_config(subscriber, rpc)?;
    assert_eq!(
        repointed.source_for(ListId::Block),
        Some(subscriber.namespace_pda()),
        "the Block slot is back on the subscriber entries"
    );
    assert_eq!(repointed.generation(), 2, "a re-point counts a generation");
    assert!(repointed.generation_slot() > stored.generation_slot());
    transfer(&notes[2]).land(&prover)?;

    Ok(())
}
