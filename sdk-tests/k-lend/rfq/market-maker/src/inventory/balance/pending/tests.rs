use anyhow::Result;
use zolana_keypair::ShieldedKeypair;
use zolana_transaction::{Data, Mint, Utxo, WalletUtxo};

use super::*;
use crate::inventory::balance::reservations::{InsertOutcome, TrackedUtxo};

fn receipt(hash: u8, asset: Address) -> Result<TrackedUtxo> {
    let own = ShieldedKeypair::new_ed25519()?.shielded_address()?;
    Ok(TrackedUtxo {
        leaf_index: Some(0),
        wallet: WalletUtxo {
            utxo: Utxo {
                owner: own.signing_pubkey,
                asset: Mint::new(asset, 2),
                amount: 100,
                blinding: [0; 32],
                ring_program_id: None,
                data: Data::default(),
            },
            nullifier_pubkey: own.nullifier_pubkey,
            utxo_hash: [hash; 32],
            nullifier: [hash; 32],
            data_hash: None,
            ring_data_hash: None,
            tree_id: 0,
            leaf_index: 0,
            slot: 0,
            tx_signature: Signature::default(),
            slot_index: 0,
        },
    })
}

fn queue(pending: &PendingBalance, id: OperationId, inputs: &[UserInput]) -> Result<()> {
    pending.queue_fill(
        id,
        Inflow {
            asset: Address::new_from_array([1; 32]),
            amount: 100,
            utxo_hash: [1; 32],
        },
        Outflow {
            asset: Address::new_from_array([2; 32]),
            amount: 10,
        },
        FillRanges {
            inflow: None,
            outflow: None,
        },
        inputs,
    )?;
    Ok(())
}

#[test]
fn receipt_spent_before_a_balance_check_never_counts_again() -> Result<()> {
    let reservations = Arc::new(Reservations::default());
    let pending = PendingBalance::new(reservations.clone());
    let asset = Address::new_from_array([1; 32]);
    queue(&pending, 1, &[])?;
    assert_eq!(pending.net_balance(&asset), 100);
    reservations.insert(receipt(1, asset)?);
    reservations.remove_spent(&[[1; 32]]);
    reservations.insert(receipt(2, asset)?);
    assert_eq!(pending.net_balance(&asset), 100);
    assert_eq!(pending.net_balance(&asset), 100);
    Ok(())
}

#[test]
fn duplicate_inputs_are_reserved_until_abort_or_confirmation() -> Result<()> {
    let pending = PendingBalance::new(Arc::new(Reservations::default()));
    let input = UserInput {
        tree: Address::new_from_array([3; 32]),
        nullifier: [4; 32],
    };
    queue(&pending, 1, &[input])?;
    assert_eq!(
        queue(&pending, 2, &[input])
            .err()
            .and_then(|error| error.downcast::<MakerError>().ok())
            .and_then(|error| match error {
                MakerError::Swap(error) => Some(error),
                _ => None,
            }),
        Some(SwapError::DuplicateFill {
            nullifier: input.nullifier
        })
    );
    pending.drop_fill(1);
    queue(&pending, 2, &[input])?;
    pending.finish_fill(Some(2), &[], Vec::new());
    assert!(pending.reservations.is_spent(&input.nullifier));
    assert!(queue(&pending, 3, &[input]).is_err());
    Ok(())
}

#[test]
fn a_spend_observed_before_its_note_prevents_a_late_insert() -> Result<()> {
    let reservations = Reservations::default();
    assert_eq!(reservations.remove_spent_nullifiers([[1; 32]]), 0);
    let asset = Address::new_from_array([1; 32]);
    assert_eq!(
        reservations.insert(receipt(1, asset)?),
        InsertOutcome::AlreadySpent
    );
    assert_eq!(reservations.balance(&asset), 0);
    Ok(())
}
