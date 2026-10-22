//! The pre-proof refusals an anonymous policy ring adds to the confidential rail.

use custom_ring_interface::{
    stream::EPOCH_SLOTS, tag, AnchorRoot, CustomRingError, RingRail, RingTransactData,
};
use solana_address::Address;
use solana_instruction::AccountMeta;
use solana_keypair::{Keypair, Signer};

use crate::{
    common::{key_registration, reaches_verification, refused, register_key, Ring, Sent, Setup},
    forward_rules::{
        deposit_instruction, merge_data, merge_disclosure, merge_instruction_with, ring_deposit,
    },
    transact_rules::{registry_meta, send, spp_list, spp_tree, Fixture, SPP},
};

/// An anonymous policy transfer, `prefix` after the registry, the payer its only signer.
fn transfer(ring: &mut Ring, prefix: Vec<AccountMeta>, data: &RingTransactData<'_>) -> Sent {
    let spp = spp_list(&ring.payer.pubkey(), data, &[]);
    let prefix = [vec![registry_meta()], prefix].concat();
    send(
        ring,
        tag::TRANSACT,
        prefix,
        data.encode().unwrap(),
        spp,
        &[],
    )
}

#[test]
fn an_anonymous_policy_transfer_passing_every_check_reaches_its_keys() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::AnonymousPolicy);
    reaches_verification(transfer(
        &mut ring,
        Vec::new(),
        &fixture.transfer(RingRail::Anonymous, 2, 2, true),
    ));
}

#[test]
fn an_anonymous_policy_transfer_takes_no_signer_but_the_payer() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::AnonymousPolicy);
    let data = fixture.transfer(RingRail::Anonymous, 2, 2, true);
    let owner = Keypair::new();
    let spp = spp_list(
        &ring.payer.pubkey(),
        &data,
        &[AccountMeta::new_readonly(owner.pubkey(), true)],
    );
    refused(
        send(
            &mut ring,
            tag::TRANSACT,
            vec![registry_meta()],
            data.encode().unwrap(),
            spp,
            &[&owner],
        ),
        CustomRingError::InvalidAnonymousSigner,
    );
}

#[test]
fn an_anonymous_policy_transfer_binds_an_epoch_at_or_after_zero() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::AnonymousPolicy);
    let mut data = fixture.transfer(RingRail::Anonymous, 2, 2, true);
    data.previous_epoch = true;
    ring.warp(EPOCH_SLOTS - 1);
    refused(
        transfer(&mut ring, Vec::new(), &data),
        CustomRingError::EpochUnderflow,
    );
    ring.warp(EPOCH_SLOTS);
    reaches_verification(transfer(&mut ring, Vec::new(), &data));
}

#[test]
fn an_anonymous_policy_first_contact_reads_a_live_spp_tree() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::AnonymousPolicy);
    let mut data = fixture.transfer(RingRail::Anonymous, 2, 2, true);
    let tree = Address::new_unique();
    data.anchor = Some(AnchorRoot {
        tree: 2,
        root_index: 0,
    });
    let anchored = vec![AccountMeta::new_readonly(tree, false)];
    refused(
        transfer(&mut ring, anchored.clone(), &data),
        CustomRingError::FirstContactRootMissing,
    );
    ring.store(tree, SPP, spp_tree(&tree, true));
    refused(
        transfer(&mut ring, anchored.clone(), &data),
        CustomRingError::FirstContactTreePaused,
    );
    ring.store(tree, SPP, spp_tree(&tree, false));
    reaches_verification(transfer(&mut ring, anchored, &data));
}

#[test]
fn an_anonymous_policy_ring_escrows_no_key() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::AnonymousPolicy);
    let mut data = fixture.transfer(RingRail::Anonymous, 2, 2, true);
    data.key_escrow = true;
    fixture.disclose(&mut data);
    refused(
        transfer(&mut ring, Vec::new(), &data),
        CustomRingError::FlagNotAllowed,
    );
    let member = Keypair::new();
    let registration = register_key(&member.pubkey(), &key_registration(), None);
    refused(
        ring.send(registration, &[&member]),
        CustomRingError::AnonymousRingRefused,
    );
}

#[test]
fn an_anonymous_policy_ring_refuses_the_delegate_rail() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::AnonymousPolicy);
    let data = fixture.transfer(RingRail::Delegate, 2, 2, true);
    let delegate = Keypair::new();
    let spp = spp_list(&ring.payer.pubkey(), &data, &[]);
    refused(
        send(
            &mut ring,
            tag::DELEGATE_TRANSACT,
            vec![
                registry_meta(),
                AccountMeta::new_readonly(delegate.pubkey(), true),
            ],
            data.encode().unwrap(),
            spp,
            &[&delegate],
        ),
        CustomRingError::AnonymousRingRefused,
    );
}

#[test]
fn an_anonymous_policy_merge_discloses_its_owner_to_the_auditor_alone() {
    let mut ring = Ring::new(Setup::AnonymousPolicy);
    let mut merge = |data| {
        let instruction = merge_instruction_with(&ring, None, &data);
        ring.send(instruction, &[])
    };
    let disclosed = |registry, inputs| {
        let mut data = merge_data(registry, inputs);
        data.disclosure = Some(merge_disclosure(inputs));
        data
    };
    refused(
        merge(merge_data(None, 8)),
        CustomRingError::MissingMergeDisclosure,
    );
    refused(
        merge(disclosed(Some(1), 8)),
        CustomRingError::UnexpectedMemberRegistryRoot,
    );
    let mut narrow = disclosed(None, 8);
    narrow.disclosure.as_mut().unwrap().fields.pop();
    refused(merge(narrow), CustomRingError::MergeDisclosureWidth);
    let mut untagged = disclosed(None, 8);
    untagged.disclosure.as_mut().unwrap().eph_pk[0] = 0;
    refused(merge(untagged), CustomRingError::InvalidMergeDisclosure);
    refused(
        merge(disclosed(None, 25)),
        CustomRingError::UnsupportedCircuit,
    );
    reaches_verification(merge(disclosed(None, 8)));
}

#[test]
fn an_anonymous_policy_deposit_names_no_recipient() {
    let mut ring = Ring::new(Setup::AnonymousPolicy);
    let mut named = ring_deposit();
    named.deposits[0].ring_data_hash = [1; 32];
    let instruction = deposit_instruction(&ring, None, &named);
    refused(
        ring.send(instruction, &[]),
        CustomRingError::InvalidAnonymousOutput,
    );
    let instruction = deposit_instruction(&ring, Some(1), &ring_deposit());
    refused(
        ring.send(instruction, &[]),
        CustomRingError::UnexpectedMemberRegistryRoot,
    );
    let instruction = deposit_instruction(&ring, None, &ring_deposit());
    reaches_verification(ring.send(instruction, &[]));
}
