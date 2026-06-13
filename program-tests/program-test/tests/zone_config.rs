//! zone-config admin coverage (spec tags 9-11).
//!
//! `create_zone_config` must be driven through the zone wrapper because SPP
//! requires the zone program's `zone_auth` PDA to sign.

mod common;

use common::{assert_custom, rig};
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::{
    instruction::{encode_instruction, tag, CreateZoneConfigData},
    state::{discriminator::ZONE_CONFIG, ZONE_CONFIG_ACCOUNT_LEN},
};
use zolana_program_test::{RigError, ZONE_TEST_PROGRAM_ID};

const UNAUTHORIZED_CALLER: u32 = 3;
const INVALID_ZONE_CONFIG: u32 = 14;

#[test]
fn create_and_update_zone_config() {
    let Some(mut rig) = rig() else {
        return;
    };
    if rig.load_zone_test_program().is_err() {
        eprintln!("skipping: zone_test_program.so missing");
        return;
    }

    let payer = Keypair::new();
    rig.airdrop(&payer.pubkey(), 1_000_000_000)
        .expect("fund payer");
    let authority = Keypair::new();
    let zone_config = rig
        .create_zone_config(&payer, &authority.pubkey(), true)
        .expect("create_zone_config");

    let bytes = rig.account_data(&zone_config).expect("zone config exists");
    assert_eq!(bytes.len(), ZONE_CONFIG_ACCOUNT_LEN);
    assert_eq!(bytes[0], ZONE_CONFIG);
    assert_eq!(&bytes[8..40], authority.pubkey().as_ref());
    assert_eq!(bytes[40], 1);
    assert_eq!(
        bytes[41],
        rig.zone_config_pda(&Pubkey::new_from_array(ZONE_TEST_PROGRAM_ID))
            .1
    );

    rig.update_zone_config(&authority, &zone_config, false)
        .expect("disable zone authority transact");
    let bytes = rig.account_data(&zone_config).expect("zone config exists");
    assert_eq!(&bytes[8..40], authority.pubkey().as_ref());
    assert_eq!(bytes[40], 0);

    let next = Keypair::new();
    rig.update_zone_config_owner(&authority, &zone_config, &next.pubkey())
        .expect("rotate owner");
    let bytes = rig.account_data(&zone_config).expect("zone config exists");
    assert_eq!(&bytes[8..40], next.pubkey().as_ref());

    let err = rig
        .update_zone_config(&authority, &zone_config, true)
        .unwrap_err();
    assert_custom(err, UNAUTHORIZED_CALLER);
    rig.update_zone_config(&next, &zone_config, true)
        .expect("new owner can update");
}

#[test]
fn create_zone_config_rejects_fake_zone_auth() {
    let Some(mut rig) = rig() else {
        return;
    };
    let payer = Keypair::new();
    rig.airdrop(&payer.pubkey(), 1_000_000_000)
        .expect("fund payer");
    let zone_program = Pubkey::new_from_array(ZONE_TEST_PROGRAM_ID);
    let (zone_config, zone_config_bump) = rig.zone_config_pda(&zone_program);
    let (_, zone_auth_bump) = rig.zone_auth_pda();
    let data = CreateZoneConfigData {
        policy_program_id: ZONE_TEST_PROGRAM_ID,
        zone_auth_bump,
        authority: payer.pubkey().to_bytes(),
        zone_authority_transact_is_enabled: true,
        zone_config_bump,
    };
    let ix = Instruction {
        program_id: rig.program_id,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(zone_config, false),
            AccountMeta::new_readonly(payer.pubkey(), true),
            AccountMeta::new_readonly(Pubkey::default(), false),
        ],
        data: encode_instruction(tag::CREATE_ZONE_CONFIG, &data),
    };
    let payer_clone = rig.payer.insecure_clone();
    let payer_pk = payer_clone.pubkey();
    let blockhash = rig.svm.latest_blockhash();
    let msg = solana_message::Message::new(&[ix], Some(&payer_pk));
    let tx = solana_transaction::Transaction::new(&[&payer_clone, &payer], msg, blockhash);
    let err = rig
        .svm
        .send_transaction(tx)
        .map(|_| ())
        .map_err(|e| RigError::Litesvm(format!("send_transaction: {e:?}")))
        .unwrap_err();
    assert_custom(err, INVALID_ZONE_CONFIG);
}
