use custom_ring_interface::{CoSignScope, CustomRingError, RingMode};
use zolana_client::AnonymousRingState;
use zolana_interface::pda;

use super::support::{keypair, owner_identity, ring, Chain, Registry, RingSettings, TREE_ID};
use crate::{DepositAsset, DepositRecipient, RingDeposit, RingError};

fn deposit<'a>(
    payer: &'a (dyn solana_signer::Signer + Sync),
    recipient: DepositRecipient<'a>,
) -> RingDeposit<'a> {
    RingDeposit {
        ring: ring(),
        payer,
        recipient,
        tree: pda::tree(TREE_ID),
        asset: DepositAsset::Sol,
        amount: 5,
        cosigner: None,
    }
}

#[tokio::test]
async fn an_anonymous_ring_takes_deposits_only_for_the_depositors_hidden_owner() {
    let member = keypair(1);
    let payer = keypair(9);
    let anonymous = Chain::ring(RingSettings::new(RingMode::Anonymous));
    let confidential = Chain::ring(RingSettings::new(RingMode::Off));
    let address = member.shielded_address().unwrap();
    let state = AnonymousRingState::new(ring().program_id(), 0);
    let hidden = DepositRecipient::Anonymous {
        keys: &member,
        state: &state,
    };
    assert!(matches!(
        deposit(&payer, DepositRecipient::Confidential(address))
            .prepare(&anonymous)
            .await,
        Err(RingError::Program(CustomRingError::AnonymousRingRefused))
    ));
    assert!(matches!(
        deposit(&payer, hidden).prepare(&confidential).await,
        Err(RingError::NotAnonymousRing)
    ));
    assert!(matches!(
        deposit(&member, hidden).prepare(&anonymous).await,
        Err(RingError::AnonymousPublicSignerLinksOwner)
    ));
    let prepared = deposit(&payer, hidden).prepare(&anonymous).await.unwrap();
    assert_eq!(
        (prepared.utxo().owner, prepared.utxo().amount),
        (member.signing_pubkey(), 5)
    );
}

#[tokio::test]
async fn an_escrowed_ring_refuses_a_deposit_to_a_member_without_an_escrowed_key() {
    let registered = keypair(1);
    let stranger = keypair(2);
    let payer = keypair(9);
    let chain = Chain::ring(RingSettings {
        has_policy: true,
        ..RingSettings::new(RingMode::Registry)
    })
    .with_registry(Registry::new(&[(&registered, 1)]), &super::pipeline_rules());
    let client = chain.client();
    let prepared = deposit(
        &payer,
        DepositRecipient::Confidential(stranger.shielded_address().unwrap()),
    )
    .prepare(&client)
    .await
    .unwrap();
    let owner = owner_identity(&stranger);
    assert!(matches!(
        prepared.prove(&client).await,
        Err(RingError::UnregisteredOutputKey { owner: refused }) if refused == owner
    ));
}

#[tokio::test]
async fn a_deposit_names_the_co_signer_a_deposit_scope_demands() {
    let member = keypair(1);
    let payer = keypair(9);
    let co_signer = keypair(8);
    let chain = Chain::ring(RingSettings {
        co_signer: Some((
            solana_signer::Signer::pubkey(&co_signer),
            CoSignScope::DEPOSITS,
        )),
        ..RingSettings::new(RingMode::Off)
    });
    let recipient = DepositRecipient::Confidential(member.shielded_address().unwrap());
    assert!(matches!(
        deposit(&payer, recipient).prepare(&chain).await,
        Err(RingError::Program(CustomRingError::MissingCoSigner))
    ));
    let named = RingDeposit {
        cosigner: Some(&co_signer),
        ..deposit(&payer, recipient)
    };
    assert!(named.prepare(&chain).await.is_ok());
    let stranger = keypair(7);
    let wrong = RingDeposit {
        cosigner: Some(&stranger),
        ..deposit(&payer, recipient)
    };
    assert!(matches!(
        wrong.prepare(&chain).await,
        Err(RingError::Program(CustomRingError::MissingCoSigner))
    ));
}

#[tokio::test]
async fn a_co_signer_outside_the_deposit_scope_does_not_sign() {
    let member = keypair(1);
    let payer = keypair(9);
    let co_signer = keypair(8);
    let recipient = DepositRecipient::Confidential(member.shielded_address().unwrap());
    for (scope, signs) in [
        (CoSignScope::WITHDRAWALS, false),
        (CoSignScope::DEPOSITS, true),
    ] {
        let chain = Chain::ring(RingSettings {
            co_signer: Some((solana_signer::Signer::pubkey(&co_signer), scope)),
            ..RingSettings::new(RingMode::Off)
        });
        let named = RingDeposit {
            cosigner: Some(&co_signer),
            ..deposit(&payer, recipient)
        };
        let prepared = named.prepare(&chain).await.unwrap();
        assert_eq!(named.signers(&prepared).len(), 1 + usize::from(signs));
    }
}
