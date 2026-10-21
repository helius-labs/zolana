//! Two rings share one member registry on localnet + photon + prover. The
//! subscriber's Block list reads the curator ring's registry, so one curator
//! write refuses the subscriber's transfer, and clearing the bit or re-pointing
//! the source re-admits it.

use anyhow::Result;
use custom_ring_sdk::{ListRegistry, SourceOwner};
use custom_ring_test_validator::{
    policy::{
        owner_member, policy_registry, CuratedRings, PolicyTransfer, RegistryWrite, RingNotes,
        BLOCK_ONLY, DEPOSIT, TRANSFER_AMOUNT,
    },
    shared::{send, RegisterRing, Tier},
};
use solana_signer::Signer;
use zolana_keypair::X25519Keypair;
use zolana_ring_policy::ListId;
use zolana_transaction::Utxo;

#[test]
fn a_curator_sourced_blocklist_governs_the_subscriber_ring() -> Result<()> {
    let CuratedRings {
        env,
        curator,
        subscriber,
    } = CuratedRings::setup()?;
    let rpc = env.client.rpc();
    let authority = env.payer.pubkey();
    let transfer = |note: &Utxo| PolicyTransfer {
        ring: subscriber,
        sender: &env.sender.keypair,
        recipient: &env.recipient.keypair,
        note: note.clone(),
        amount: TRANSFER_AMOUNT,
        env: &env,
    };

    // 1. The subscriber pins behind the curator's pin, its Block slot names
    //    the curator's member registry, and it registers with SPP only behind
    //    its own pin.
    RegisterRing {
        ring: subscriber,
        payer: &env.payer,
        auditor_pubkey: X25519Keypair::new().pubkey(),
        tier: Tier::Policy {
            rules: &BLOCK_ONLY,
            shared_sources: vec![(ListId::Block, curator)],
        },
    }
    .send(rpc)?;
    let stored = policy_registry(subscriber, &env)?;
    assert_eq!(
        stored.registry_for(ListId::Block),
        Some(ListRegistry::Curator(curator.registry_pda())),
        "the Block slot names the curator registry"
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

    // 3. The curator registry holds no member yet, the transfer passes on
    //    the absence proof against it.
    transfer(&notes[0]).land()?;

    // 4. One curator write refuses the next transfer before proving.
    let member = owner_member(&env.recipient.keypair)?;
    let curator_block = |present| RegistryWrite {
        ring: curator,
        list_id: ListId::Block,
        member,
        present,
        env: &env,
    };
    curator_block(true).send()?;
    transfer(&notes[1]).expect_refusal()?;

    // 5. Clearing the bit re-admits the refused note, an unrelated deposit
    //    moves the state root between the record read and the proof.
    curator_block(false).send()?;
    RingNotes {
        ring: subscriber,
        owner: &env.sender.keypair,
        amount: DEPOSIT,
        count: 1,
        env: &env,
    }
    .deposit()?;
    transfer(&notes[1]).land()?;

    // 6. With the bit set again, re-pointing Block to the subscriber's own
    //    registry turns curator enforcement off.
    curator_block(true).send()?;
    send(
        rpc,
        &env.payer,
        &[subscriber.set_source_owner(authority, ListId::Block, SourceOwner::Own)?],
    )?;
    let repointed = policy_registry(subscriber, &env)?;
    assert_eq!(
        repointed.registry_for(ListId::Block),
        Some(ListRegistry::Own),
        "the Block slot is back on the subscriber registry"
    );
    assert_eq!(repointed.generation(), 2, "a re-point counts a generation");
    assert!(repointed.generation_slot() > stored.generation_slot());
    transfer(&notes[2]).land()?;

    Ok(())
}
