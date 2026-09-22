use num_bigint::BigUint;
use solana_address::Address;
use zolana_interface::{MAX_INTERFACE_TRANSFERS, N_PUBLIC_SLOTS, SOL_ASSET_FIELD};

use super::ConfidentialTransaction;
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
    if amount == 0 {
        return [0u8; 32];
    }
    let magnitude = BigUint::from(amount);
    let field = if is_deposit {
        magnitude
    } else {
        BigUint::parse_bytes(BN254_MODULUS_DEC.as_bytes(), 10).expect("valid BN254 modulus literal")
            - magnitude
    };
    let bytes = field.to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
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
    pub fn public_transfers(&self) -> Result<PublicTransfers, TransactionError> {
        if self.external_data.interface_transfers.len() > MAX_INTERFACE_TRANSFERS {
            return Err(TransactionError::TooManyInterfaceTransfers {
                got: self.external_data.interface_transfers.len(),
                max: MAX_INTERFACE_TRANSFERS,
            });
        }

        let mut aggregated: Vec<(Address, i128)> = Vec::new();
        for transfer in &self.external_data.interface_transfers {
            let asset = transfer.asset();
            let amount = transfer.amount();
            if amount == 0 {
                return Err(TransactionError::ZeroInterfaceTransferAmount);
            }
            if transfer.interface_transfer().is_spl() && asset == SOL_MINT {
                return Err(TransactionError::SettlementTargetMismatch { asset });
            }
            let magnitude = i128::from(amount);
            let signed = if transfer.is_deposit() {
                magnitude
            } else {
                -magnitude
            };
            if let Some((_, total)) = aggregated
                .iter_mut()
                .find(|(existing, _)| *existing == asset)
            {
                *total = total
                    .checked_add(signed)
                    .ok_or(TransactionError::PublicTransferOverflow { asset })?;
                u64::try_from(total.unsigned_abs())
                    .map_err(|_| TransactionError::PublicTransferOverflow { asset })?;
            } else {
                aggregated.push((asset, signed));
            }
        }
        if let Some((asset, _)) = aggregated.iter().find(|(_, total)| *total == 0) {
            return Err(TransactionError::ZeroNetInterfaceTransferAmount { asset: *asset });
        }
        if aggregated.len() > N_PUBLIC_SLOTS {
            return Err(TransactionError::TooManyPublicAssets {
                got: aggregated.len(),
                max: N_PUBLIC_SLOTS,
            });
        }

        let mut transfers = PublicTransfers::default();
        for ((asset_slot, amount_slot), (asset, amount)) in transfers
            .assets
            .iter_mut()
            .zip(transfers.amounts.iter_mut())
            .zip(aggregated)
        {
            let magnitude = u64::try_from(amount.unsigned_abs())
                .map_err(|_| TransactionError::PublicTransferOverflow { asset })?;
            *asset_slot = if asset == SOL_MINT {
                SOL_ASSET_FIELD
            } else {
                asset_field(&asset)?
            };
            *amount_slot = signed_magnitude_to_field(amount > 0, magnitude);
        }
        Ok(transfers)
    }
}
