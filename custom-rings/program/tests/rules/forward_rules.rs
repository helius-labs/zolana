//! A merge and an audited deposit bind an own registry root under the floor.

use bytemuck::Zeroable;
use custom_ring_interface::{
    tag, AuditedDepositPrefix, CustomRingError, CustomRingMergeIxData, MemberRegistry,
    RingDepositAuditCapsule, RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN,
};
use solana_address::Address;
use solana_bn254::compression::prelude::alt_bn128_g2_compress_be;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Signer;
use zolana_interface::{
    instruction::instruction_data::{
        deposit::{
            DepositAssetKind, EncryptedRingDepositData, RingDepositEntry, RingDepositIxData,
        },
        merge_transact::{MergeOutputEncryption, MergeProof, MergeTransactIxData},
    },
    RING_DEPOSIT_DEPOSITOR_INDEX, RING_DEPOSIT_RING_CONFIG_INDEX, RING_MERGE_PAYER_INDEX,
    RING_MERGE_RING_CONFIG_INDEX,
};

use crate::common::{
    auditor_pubkey, config_pda, delegate_ring, floored, off_curve_g2, on_curve_g2,
    reaches_verification, refused, registry_pda, ring_auth, Ring, Sent, Setup, PROGRAM, SYSTEM,
};

/// `registry` the own root index a non-anonymous ring binds, the registry follows the config.
fn merge_instruction(ring: &Ring, registry: Option<u8>) -> Instruction {
    let data = CustomRingMergeIxData {
        registry_root_index: registry.unwrap_or_default(),
        output_ring_data_hash: [8; 32],
        disclosure: None,
        merge: MergeTransactIxData {
            expiry_unix_ts: 1_800_000_000,
            proof: MergeProof {
                b: on_curve_g2(),
                ..MergeProof::zeroed()
            },
            output_utxo_hash: [1; 32],
            output_encryption: MergeOutputEncryption::PoseidonCtrV1 {
                salt: [2; 16],
                ciphertext: [[3; 32]; 3],
            },
            private_tx_hash: [4; 32],
            nullifiers: vec![[5; 32]; 8],
            utxo_tree_root_index: 0,
            nullifier_tree_root_index: 0,
            cache_slot: None,
        },
    };
    let mut spp: Vec<AccountMeta> = (0..RING_MERGE_PAYER_INDEX)
        .map(|_| AccountMeta::new(Address::new_unique(), false))
        .collect();
    spp[RING_MERGE_RING_CONFIG_INDEX] = AccountMeta::new(ring_auth(), false);
    spp.push(AccountMeta::new(ring.payer.pubkey(), true));
    let mut accounts = vec![AccountMeta::new_readonly(config_pda(), false)];
    if registry.is_some() {
        accounts.push(AccountMeta::new_readonly(registry_pda(), false));
    }
    accounts.extend(spp);
    Instruction {
        program_id: PROGRAM,
        accounts,
        data: [&[tag::MERGE][..], &data.serialize().unwrap()].concat(),
    }
}

fn merge(ring: &mut Ring, registry: Option<u8>) -> Sent {
    let instruction = merge_instruction(ring, registry);
    ring.send(instruction, &[])
}

#[test]
fn a_merge_root_below_the_own_floor_is_refused() {
    let mut ring = Ring::new(Setup::AuditOnly);
    let base: MemberRegistry = ring.read(&registry_pda());
    ring.write(&registry_pda(), &floored(&base, 4, 5));
    refused(merge(&mut ring, Some(1)), CustomRingError::RootBelowFloor);
    ring.write(&registry_pda(), &floored(&base, 4, 4));
    // Every ring check passes, the forward stops at the absent pool program.
    refused(
        merge(&mut ring, Some(1)),
        CustomRingError::InvalidShieldedPoolProgram,
    );
}

#[test]
fn a_merge_proof_point_off_the_curve_is_refused_before_the_forward() {
    let mut ring = Ring::new(Setup::AuditOnly);
    let mut instruction = merge_instruction(&ring, Some(0));
    let compressed = alt_bn128_g2_compress_be(&on_curve_g2()).unwrap();
    let at = instruction
        .data
        .windows(compressed.len())
        .position(|window| window == compressed)
        .expect("the merge carries b compressed");
    instruction.data[at..at + compressed.len()].copy_from_slice(&off_curve_g2());
    refused(
        ring.send(instruction, &[]),
        CustomRingError::InvalidSppProofPoint,
    );
}

#[test]
fn an_anonymous_merge_carries_its_disclosure() {
    let mut ring = Ring::new(Setup::Anonymous);
    refused(
        merge(&mut ring, None),
        CustomRingError::MissingMergeDisclosure,
    );
    refused(
        merge(&mut ring, Some(1)),
        CustomRingError::UnexpectedMemberRegistryRoot,
    );
}

/// `registry` the root index a Registry-mode ring binds, the registry account follows the config.
fn audited_deposit(ring: &mut Ring, registry: Option<u8>) -> Sent {
    let capsule = RingDepositAuditCapsule {
        slot_index: 0,
        eph_pk: &auditor_pubkey(),
        ciphertext: &[3; RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN],
        recipient_ciphertext: &[],
    }
    .encode();
    let deposit = RingDepositIxData {
        assets: vec![DepositAssetKind::Sol],
        deposits: vec![RingDepositEntry {
            asset_index: 0,
            view_tag: [1; 32],
            owner_utxo_hash: [0x0f; 32],
            amount: 10,
            ring_data_hash: [0; 32],
            encrypted: EncryptedRingDepositData {
                tx_viewing_pk: auditor_pubkey(),
                salt: [2; 16],
                ciphertext: capsule,
            },
        }],
    };
    let prefix = AuditedDepositPrefix {
        tag: tag::AUDITED_DEPOSIT,
        proof: Zeroable::zeroed(),
        registry_root_index: registry.unwrap_or_default(),
    };
    let data = [
        bytemuck::bytes_of(&prefix),
        &[tag::DEPOSIT],
        &deposit.serialize().unwrap(),
    ]
    .concat();
    let mut spp: Vec<AccountMeta> = (0..=RING_DEPOSIT_RING_CONFIG_INDEX)
        .map(|_| AccountMeta::new(Address::new_unique(), false))
        .collect();
    spp[RING_DEPOSIT_DEPOSITOR_INDEX] = AccountMeta::new(ring.payer.pubkey(), true);
    spp[RING_DEPOSIT_RING_CONFIG_INDEX] = AccountMeta::new(ring_auth(), false);
    spp.extend([
        AccountMeta::new_readonly(Address::new_unique(), false),
        AccountMeta::new_readonly(SYSTEM, false),
        AccountMeta::new(Address::new_unique(), false),
    ]);
    let mut accounts = vec![AccountMeta::new_readonly(config_pda(), false)];
    if registry.is_some() {
        accounts.push(AccountMeta::new_readonly(registry_pda(), false));
    }
    accounts.extend(spp);
    let instruction = Instruction {
        program_id: PROGRAM,
        accounts,
        data,
    };
    ring.send(instruction, &[])
}

#[test]
fn an_escrowing_deposit_root_below_the_own_floor_is_refused() {
    let mut ring = delegate_ring(&Address::new_from_array([5; 32]));
    let base: MemberRegistry = ring.read(&registry_pda());
    ring.write(&registry_pda(), &floored(&base, 4, 5));
    refused(
        audited_deposit(&mut ring, Some(1)),
        CustomRingError::RootBelowFloor,
    );
    ring.write(&registry_pda(), &floored(&base, 4, 4));
    reaches_verification(audited_deposit(&mut ring, Some(1)));
}

#[test]
fn an_audited_deposit_without_a_bound_root_reaches_its_proof() {
    let mut ring = Ring::new(Setup::AuditOnly);
    reaches_verification(audited_deposit(&mut ring, None));
}

#[test]
fn a_merge_naming_the_ring_pda_past_its_slot_is_refused() {
    let mut ring = Ring::new(Setup::AuditOnly);
    let mut instruction = merge_instruction(&ring, Some(0));
    instruction
        .accounts
        .push(AccountMeta::new(ring_auth(), false));
    refused(
        ring.send(instruction, &[]),
        CustomRingError::RingAuthOutOfSlot,
    );
}
