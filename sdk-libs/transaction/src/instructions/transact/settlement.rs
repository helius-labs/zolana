use solana_address::Address;
use zolana_interface::{
    instruction::instruction_data::transact::{amount_field, PublicSlotError, PublicSlots},
    N_PUBLIC_SLOTS,
};

use super::{external_data::validate_settlement_transfers, ConfidentialTransaction};
use crate::{
    error::TransactionError,
    instructions::transact::{SettlementTransfer, SppProofInputs},
    Mint, SOL_MINT,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettlementTarget {
    Sol { user_sol_account: Address },
    Spl { user_spl_token: Address },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicTransferRequest {
    pub asset: Mint,
    pub is_deposit: bool,
    pub amount: u64,
    pub target: SettlementTarget,
}

impl ConfidentialTransaction {
    pub fn public_transfers(&self) -> &[PublicTransferRequest] {
        &self.public_transfers
    }

    pub fn settle(
        &mut self,
        asset: Mint,
        is_deposit: bool,
        amount: u64,
        target: SettlementTarget,
    ) -> Result<&mut Self, TransactionError> {
        if self.padded_inputs.is_some() {
            return Err(TransactionError::OutputUtxosAlreadyPadded);
        }
        if amount == 0 {
            return Err(TransactionError::ZeroInterfaceTransferAmount);
        }
        validate_settlement_target(asset, target)?;
        if self.public_transfers.len() >= zolana_interface::MAX_INTERFACE_TRANSFERS {
            return Err(TransactionError::TooManyInterfaceTransfers {
                got: self.public_transfers.len().saturating_add(1),
                max: zolana_interface::MAX_INTERFACE_TRANSFERS,
            });
        }
        self.public_transfers.push(PublicTransferRequest {
            asset,
            is_deposit,
            amount,
            target,
        });
        Ok(self)
    }

    pub fn interface_transfers(&self) -> Result<Vec<SettlementTransfer>, TransactionError> {
        self.public_transfers
            .iter()
            .map(|transfer| {
                validate_settlement_target(transfer.asset, transfer.target)?;
                Ok(match transfer.target {
                    SettlementTarget::Sol { user_sol_account } => SettlementTransfer::Sol {
                        is_deposit: transfer.is_deposit,
                        amount: transfer.amount,
                        user_sol_account,
                    },
                    SettlementTarget::Spl { user_spl_token } => SettlementTransfer::Spl {
                        mint: transfer.asset.asset,
                        is_deposit: transfer.is_deposit,
                        amount: transfer.amount,
                        user_spl_token,
                    },
                })
            })
            .collect()
    }

    pub(super) fn validate_interface_transfers(&self) -> Result<(), TransactionError> {
        if self.public_transfers.len() > zolana_interface::MAX_INTERFACE_TRANSFERS {
            return Err(TransactionError::TooManyInterfaceTransfers {
                got: self.public_transfers.len(),
                max: zolana_interface::MAX_INTERFACE_TRANSFERS,
            });
        }
        for transfer in &self.public_transfers {
            if transfer.amount == 0 {
                return Err(TransactionError::ZeroInterfaceTransferAmount);
            }
            validate_settlement_target(transfer.asset, transfer.target)?;
        }
        Ok(())
    }

    pub(super) fn public_amount(&self, asset: &Mint) -> Result<i128, TransactionError> {
        let total = self
            .public_transfers
            .iter()
            .filter(|transfer| &transfer.asset == asset)
            .try_fold(0i128, |total, transfer| {
                let amount = i128::from(transfer.amount);
                let signed = if transfer.is_deposit { amount } else { -amount };
                total
                    .checked_add(signed)
                    .ok_or(TransactionError::PublicTransferOverflow { asset: asset.asset })
            })?;
        u64::try_from(total.unsigned_abs())
            .map_err(|_| TransactionError::PublicTransferOverflow { asset: asset.asset })?;
        Ok(total)
    }
}

fn validate_settlement_target(
    asset: Mint,
    target: SettlementTarget,
) -> Result<(), TransactionError> {
    let matches = matches!(
        (asset.asset == SOL_MINT, target),
        (true, SettlementTarget::Sol { .. }) | (false, SettlementTarget::Spl { .. })
    );
    if matches {
        Ok(())
    } else {
        Err(TransactionError::SettlementTargetMismatch { asset: asset.asset })
    }
}

pub const BN254_MODULUS_DEC: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";

pub fn signed_magnitude_to_field(is_deposit: bool, amount: u64) -> [u8; 32] {
    let magnitude = i128::from(amount);
    amount_field(if is_deposit { magnitude } else { -magnitude })
        .expect("a u64 magnitude lies inside the range amount_field accepts")
}

pub fn asset_field(asset: &Address) -> Result<[u8; 32], TransactionError> {
    Ok(zolana_hasher::primitives::hash_bytes(asset.as_array())?)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PublicTransfers {
    pub assets: [[u8; 32]; N_PUBLIC_SLOTS],
    pub amounts: [[u8; 32]; N_PUBLIC_SLOTS],
}

impl PublicTransfers {
    pub fn interleaved(&self) -> [[u8; 32]; 2 * N_PUBLIC_SLOTS] {
        core::array::from_fn(|index| {
            let slot = index / 2;
            if index % 2 == 0 {
                self.assets[slot]
            } else {
                self.amounts[slot]
            }
        })
    }
}

impl SppProofInputs {
    /// Every refusal is the one SPP's fold would make.
    pub fn public_transfers(&self) -> Result<PublicTransfers, TransactionError> {
        let settlements = &self.external_data.interface_transfers;
        validate_settlement_transfers(settlements)?;
        let slots = public_slots(settlements).map_err(public_slot_error)?;
        Ok(PublicTransfers {
            assets: slots.asset_fields()?,
            amounts: slots.amount_fields().map_err(public_slot_error)?,
        })
    }
}

/// SPP's fold of the settlement legs into its public slots.
pub fn public_slots(transfers: &[SettlementTransfer]) -> Result<PublicSlots, PublicSlotError> {
    PublicSlots::fold(transfers.iter().map(|transfer| Ok(transfer.public_leg())))
}

fn public_slot_error(error: PublicSlotError) -> TransactionError {
    match error {
        PublicSlotError::TooManyAssets { .. } => TransactionError::TooManyPublicAssets {
            got: N_PUBLIC_SLOTS + 1,
            max: N_PUBLIC_SLOTS,
        },
        PublicSlotError::AmountOverflow { asset } => TransactionError::PublicTransferOverflow {
            asset: Address::new_from_array(asset),
        },
        PublicSlotError::ZeroNet { asset } => TransactionError::ZeroNetInterfaceTransferAmount {
            asset: Address::new_from_array(asset),
        },
    }
}
