use std::num::NonZeroU64;

use anyhow::Result;
use custom_ring_cli::transact;
use custom_ring_sdk::{
    tree_id, CustomRing, CustomRingTransfer, CustomRingTransferInput, DepositAsset,
    DepositProofEnvironment, ReadEnvironment, ReadSpendRecord, RegisterSpend, RingDeposit,
    TransactSend, TransferProofEnvironment,
};
use custom_ring_test_validator::shared::{
    custom_ring_program_id, send, setup, wait_for_spend_record, RegisterRing, Tier,
};
use solana_signer::Signer;
use zolana_client::ProverClient;
use zolana_interface::SOL_ASSET_FIELD;
use zolana_keypair::{ShieldedKeypair, ViewingKey};
use zolana_ring_policy::{Member, RuleTable, VelocityRow};
use zolana_transaction::instructions::transact::{canonical_shape, ConfidentialTransaction};

const RULES: RuleTable = RuleTable::builder()
    .windowed(NonZeroU64::new(1_000_000).unwrap())
    .velocity(&[VelocityRow {
        asset: SOL_ASSET_FIELD,
        cap: 1_000_000_000,
        cosign_above: 1_000_000_000,
    }])
    .build();

#[test]
#[ignore = "requires isolated local validator and prover"]
fn two_members_land_windowed_transfers_proven_against_the_same_roots() -> Result<()> {
    let env = setup()?;
    let rpc = env.client.rpc();
    let indexer = env.client.indexer();
    let prover = ProverClient::local();
    let ring = CustomRing::new(custom_ring_program_id()?);
    RegisterRing {
        ring,
        payer: &env.payer,
        auditor_pubkey: ViewingKey::new().pubkey(),
        tier: Tier::policy(&RULES, env.tree),
    }
    .send(rpc)?;
    let proving = || TransferProofEnvironment {
        indexer,
        rpc,
        prover: &prover,
    };
    let address_tree_id = tree_id(rpc, env.tree)?;
    let read = |member: Member| {
        ReadSpendRecord {
            ring,
            address_tree_id,
            member,
        }
        .read_current(ReadEnvironment { indexer, rpc })
    };
    let members = [
        ShieldedKeypair::new_ed25519()?,
        ShieldedKeypair::new_ed25519()?,
    ];
    let tags = members
        .iter()
        .map(|member| Member::owner_tag(member.pubkey().as_array()))
        .collect::<Result<Vec<_>, _>>()?;
    let mut transfers = Vec::with_capacity(members.len());
    for (member, &tag) in members.iter().zip(&tags) {
        env.fund(member.pubkey(), 1_000_000_000)?;
        let registration = RegisterSpend {
            ring,
            payer: member.pubkey(),
        }
        .prove(proving())?;
        send(rpc, member, &[registration.instruction()?])?;
        wait_for_spend_record(|| read(tag), 0)?;
        let deposit = RingDeposit {
            ring,
            payer: member,
            recipient: member,
            tree: env.tree,
            asset: DepositAsset::Sol,
            amount: 2_000_000,
            cosigner: None,
        }
        .send(DepositProofEnvironment {
            indexer,
            rpc,
            prover: &prover,
        })?;
        transact::wait_for_indexed_transaction(indexer, deposit.signature)?;
        let input = zolana_test_utils::utxo::indexed(
            deposit.utxo,
            &member.nullifier_key,
            indexer,
            address_tree_id,
        )?;
        let mut transaction = ConfidentialTransaction::new_with_ring(
            vec![input],
            member.pubkey(),
            ring.program_id(),
        )?
        .with_output_tree_id(address_tree_id)?;
        transaction.transfer_sol(&env.recipient.keypair.shielded_address()?, 1_000_000)?;
        transaction.pad_utxos(
            canonical_shape(transaction.inputs().len(), 2)?,
            &member.shielded_address()?,
        )?;
        transfers.push(CustomRingTransfer::new(CustomRingTransferInput {
            ring,
            sender: member,
            nullifier_key: Some(&member.nullifier_key),
            transaction,
        }));
    }

    let proofs = transfers
        .into_iter()
        .map(|transfer| transfer.prove(proving()))
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(proofs[0].policy, proofs[1].policy);
    for (member, proof) in members.iter().zip(&proofs) {
        TransactSend {
            payer: member,
            signers: &[],
            instruction: proof.instruction()?,
        }
        .send(rpc)?;
    }
    for &tag in &tags {
        wait_for_spend_record(|| read(tag), 1)?;
    }
    Ok(())
}

/// The record successor lands in the transfer's output tree, the next transfer
/// spends it from there while its address stays in the address tree.
#[test]
#[ignore = "requires isolated local validator and prover"]
fn a_spend_record_migrates_to_the_output_tree() -> Result<()> {
    let env = setup()?;
    let rpc = env.client.rpc();
    let indexer = env.client.indexer();
    let prover = ProverClient::local();
    let ring = CustomRing::new(custom_ring_program_id()?);
    RegisterRing {
        ring,
        payer: &env.payer,
        auditor_pubkey: ViewingKey::new().pubkey(),
        tier: Tier::policy(&RULES, env.tree),
    }
    .send(rpc)?;
    let proving = || TransferProofEnvironment {
        indexer,
        rpc,
        prover: &prover,
    };
    let address_tree_id = tree_id(rpc, env.tree)?;
    let second_tree_id = env.tree_id(env.create_registered_tree()?)?;
    assert_ne!(address_tree_id, second_tree_id);
    let member = ShieldedKeypair::new_ed25519()?;
    env.fund(member.pubkey(), 1_000_000_000)?;
    let tag = Member::owner_tag(member.pubkey().as_array())?;
    let read = || {
        ReadSpendRecord {
            ring,
            address_tree_id,
            member: tag,
        }
        .read_current(ReadEnvironment { indexer, rpc })
    };
    let registration = RegisterSpend {
        ring,
        payer: member.pubkey(),
    }
    .prove(proving())?;
    send(rpc, &member, &[registration.instruction()?])?;
    wait_for_spend_record(read, 0)?;

    for (version, output_tree_id) in [(1, second_tree_id), (2, address_tree_id)] {
        let deposit = RingDeposit {
            ring,
            payer: &member,
            recipient: &member,
            tree: env.tree,
            asset: DepositAsset::Sol,
            amount: 2_000_000,
            cosigner: None,
        }
        .send(DepositProofEnvironment {
            indexer,
            rpc,
            prover: &prover,
        })?;
        transact::wait_for_indexed_transaction(indexer, deposit.signature)?;
        let input = zolana_test_utils::utxo::indexed(
            deposit.utxo,
            &member.nullifier_key,
            indexer,
            address_tree_id,
        )?;
        let mut transaction = ConfidentialTransaction::new_with_ring(
            vec![input],
            member.pubkey(),
            ring.program_id(),
        )?
        .with_output_tree_id(output_tree_id)?;
        transaction.transfer_sol(&env.recipient.keypair.shielded_address()?, 1_000_000)?;
        transaction.pad_utxos(
            canonical_shape(transaction.inputs().len(), 2)?,
            &member.shielded_address()?,
        )?;
        let proof = CustomRingTransfer::new(CustomRingTransferInput {
            ring,
            sender: &member,
            nullifier_key: Some(&member.nullifier_key),
            transaction,
        })
        .prove(proving())?;
        TransactSend {
            payer: &member,
            signers: &[],
            instruction: proof.instruction()?,
        }
        .send(rpc)?;
        let live = wait_for_spend_record(read, version)?;
        assert_eq!(
            live.tree_id, output_tree_id,
            "the record lands in the output tree"
        );
    }
    Ok(())
}
