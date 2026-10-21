use custom_ring_interface::{CoSignScope, CustomRingError};
use pinocchio::{AccountView, Address};
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{
        instruction_data::{
            settlement_mints, validate_interface_transfers, PublicLeg, PublicSlots,
        },
        InterfaceTransfer,
    },
    SOL_ASSET_ADDRESS,
};

const SOL: Address = Address::new_from_array(SOL_ASSET_ADDRESS);

pub(crate) struct PublicLegs<'a> {
    legs: Vec<Leg<'a>>,
}

struct Leg<'a> {
    transfer: &'a InterfaceTransfer,
    /// `None` for a SOL leg.
    mint: Option<&'a Address>,
}

impl<'a> PublicLegs<'a> {
    /// `window` is the `settlement_accounts` window SPP reads.
    pub fn new(
        transfers: &'a [InterfaceTransfer],
        window: &'a [AccountView],
    ) -> Result<Self, CustomRingError> {
        validate_interface_transfers(transfers).map_err(|error| match error {
            ShieldedPoolError::TooManyInterfaceTransfers => CustomRingError::TooManyPublicLegs,
            _ => CustomRingError::ZeroPublicLegAmount,
        })?;
        let legs = transfers
            .iter()
            .zip(settlement_mints(transfers, window))
            .map(|(transfer, mint)| {
                Ok(Leg {
                    transfer,
                    mint: mint?.map(AccountView::address),
                })
            })
            .collect::<Result<_, ShieldedPoolError>>()
            .map_err(|_| CustomRingError::InvalidSettlementAccounts)?;
        Ok(Self { legs })
    }

    pub fn slots(&self) -> Result<PublicSlots, CustomRingError> {
        PublicSlots::fold(self.legs.iter().map(|leg| {
            Ok(PublicLeg {
                transfer: *leg.transfer,
                mint: leg.mint.map(Address::to_bytes),
            })
        }))
    }

    /// A transact is a transfer, each public leg adds its class.
    pub fn classes(&self) -> CoSignScope {
        self.legs
            .iter()
            .fold(CoSignScope::TRANSFERS, |classes, leg| {
                classes
                    | if leg.transfer.is_deposit() {
                        CoSignScope::DEPOSITS
                    } else {
                        CoSignScope::WITHDRAWALS
                    }
            })
    }

    /// Each withdrawn mint once with its total, a u128 sum never overflows.
    pub fn withdrawals(&self) -> impl Iterator<Item = (&'a Address, u128)> + '_ {
        let withdrawn = || {
            self.legs
                .iter()
                .filter(|leg| !leg.transfer.is_deposit())
                .map(|leg| (leg.mint.unwrap_or(&SOL), leg.transfer.amount()))
        };
        withdrawn()
            .enumerate()
            .filter(move |(index, (mint, _))| {
                !withdrawn()
                    .take(*index)
                    .any(|(earlier, _)| earlier == *mint)
            })
            .map(move |(_, (mint, _))| {
                let total = withdrawn()
                    .filter(|(other, _)| other == &mint)
                    .map(|(_, amount)| u128::from(amount))
                    .sum();
                (mint, total)
            })
    }
}
