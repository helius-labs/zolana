use custom_ring_interface::{
    cosign::CoSignDemand, CuratorRoot, CustomRingError, CustomRingProof, InputTrees, RailSigner,
    RingProgramConfig, RingTransactData,
};
use pinocchio::{error::ProgramError, AccountView, Address};
use zolana_hasher::primitives::solana_owner_identity;
use zolana_interface::{
    instruction::instruction_data::{settlement_accounts, PublicSlots},
    RING_TRANSACT_ACCOUNT_PREFIX_LEN, RING_TRANSACT_RING_CONFIG_INDEX, TRANSACT_PAYER_INDEX,
};

use crate::instructions::{
    loader::{check_co_signer, check_funding_signer, load_curator_registry, load_registry},
    public_legs::PublicLegs,
    shared::{PlacedRingAuth, RingAuth},
};

/// The registry follows the config on a policy ring.
const REGISTRY_INDEX: usize = 1;

/// Copied out before the SPP CPI.
pub(super) struct PolicyRoots<'a> {
    pub proof: &'a CustomRingProof,
    pub policy_hash: [u8; 32],
    pub own_root: [u8; 32],
    /// Zero without a curator source.
    pub curator_root: [u8; 32],
}

pub(super) struct TransactAccounts<'a> {
    pub policy: Option<PolicyRoots<'a>>,
    pub sender: [u8; 32],
    pub public_slots: PublicSlots,
    /// Index of the first forwarded SPP account.
    pub spp: usize,
    pub ring_auth: PlacedRingAuth,
}

#[must_use]
pub(super) struct TransactCheck<'a> {
    pub program_id: &'a Address,
    pub config: &'a RingProgramConfig,
    pub data: &'a RingTransactData<'a>,
    pub signer: RailSigner,
    pub slot: u64,
}

impl<'a> TransactCheck<'a> {
    /// The co-signer demand comes first, its slot moves the SPP list.
    #[inline(never)]
    pub fn validate(self, accounts: &[AccountView]) -> Result<TransactAccounts<'a>, ProgramError> {
        let (config, data) = (self.config, self.data);
        let window = settlement_accounts(&data.interface_transfers, data.circuit(), accounts)
            .ok_or(CustomRingError::InvalidSettlementAccounts)?;
        let legs = PublicLegs::new(&data.interface_transfers, window)?;
        let co_signer = CoSignDemand::transact(data.approval_required, legs.legs()).signer(config);
        let binding = match config.has_policy() {
            true => data.check_policy(Some(&*load_registry(
                self.program_id,
                account_at(accounts, REGISTRY_INDEX)?,
            )?))?,
            false => data.check_policy(None)?,
        };
        let prefix = self.prefix(
            binding.and_then(|binding| binding.curator),
            co_signer.as_ref().ok().copied().flatten(),
        );
        let policy = match binding {
            Some(binding) => Some(PolicyRoots {
                proof: binding.proof.proof,
                policy_hash: binding.policy_hash,
                own_root: binding.own_root,
                curator_root: match &prefix.curator {
                    Some(curator) => curator.root(accounts, self.slot)?,
                    None => [0; 32],
                },
            }),
            None => None,
        };

        let spp = accounts
            .get(prefix.spp..)
            .ok_or(ProgramError::NotEnoughAccountKeys)?;
        let ring_auth =
            RingAuth::derive(self.program_id)?.check_slot(spp, RING_TRANSACT_RING_CONFIG_INDEX)?;
        let payer = check_funding_signer(spp, TRANSACT_PAYER_INDEX)?;
        let sender = match prefix.signer {
            SignerSlot::Payer => {
                if spp
                    .iter()
                    .any(|account| account.is_signer() && account.address() != payer.address())
                {
                    return Err(CustomRingError::InvalidAnonymousSigner.into());
                }
                *data.sender_commitment()
            }
            SignerSlot::Owners => {
                let owners = self.owner_signers(spp, window.len())?;
                if owners.iter().any(|owner| !owner.is_signer()) {
                    return Err(CustomRingError::MissingOwnerSigner.into());
                }
                let sender = match policy {
                    Some(_) => solana_owner_identity(sole_owner(owners)?.as_array())
                        .map_err(CustomRingError::from)?,
                    None => [0; 32],
                };
                if prefix.co_signer.as_ref().is_some_and(|co_signer| {
                    owners
                        .iter()
                        .any(|owner| owner.address() == &co_signer.expected)
                }) {
                    return Err(CustomRingError::CoSignerIsOwner.into());
                }
                sender
            }
            SignerSlot::Delegate(slot) => {
                if !data.interface_transfers.is_empty() {
                    return Err(CustomRingError::DelegatePublicLeg.into());
                }
                let delegate = account_at(accounts, slot.index)?;
                if !delegate.is_signer() || delegate.address() != &slot.expected {
                    return Err(CustomRingError::UnauthorizedDelegate.into());
                }
                if prefix
                    .co_signer
                    .as_ref()
                    .is_some_and(|co_signer| co_signer.expected == slot.expected)
                {
                    return Err(CustomRingError::CoSignerIsDelegate.into());
                }
                [0; 32]
            }
        };

        let mut groups = window;
        for transfer in &data.interface_transfers {
            let (group, rest) = groups
                .split_at_checked(transfer.settlement_account_count())
                .ok_or(CustomRingError::InvalidSettlementAccounts)?;
            groups = rest;
            if let Some(funder) = transfer.funder_account_position() {
                check_funding_signer(group, funder)?;
            }
        }
        let public_slots = legs.slots()?;

        co_signer?;
        if let Some(slot) = prefix.co_signer {
            check_co_signer(account_at(accounts, slot.index)?, &slot.expected)?;
        }
        Ok(TransactAccounts {
            policy,
            sender,
            public_slots,
            spp: prefix.spp,
            ring_auth,
        })
    }

    fn prefix(&self, curator: Option<CuratorRoot>, co_signer: Option<Address>) -> Prefix {
        let mut next = Cursor(REGISTRY_INDEX + usize::from(self.config.has_policy()));
        let curator = curator.map(|root| next.slot(root));
        let co_signer = co_signer.map(|expected| next.slot(expected));
        let signer = match self.signer {
            RailSigner::Owners => SignerSlot::Owners,
            RailSigner::Payer => SignerSlot::Payer,
            RailSigner::Delegate(expected) => SignerSlot::Delegate(next.slot(expected)),
        };
        // The first-contact tree sits in the prefix only when the data names its slot.
        if self
            .data
            .anchor
            .is_some_and(|anchor| usize::from(anchor.tree) == next.0)
        {
            next.0 += 1;
        }
        Prefix {
            curator,
            co_signer,
            signer,
            spp: next.0,
        }
    }

    /// The run SPP reads as owner signers, between the nullifier PDAs and the settlement groups.
    fn owner_signers<'s>(
        &self,
        spp: &'s [AccountView],
        settlements: usize,
    ) -> Result<&'s [AccountView], CustomRingError> {
        let trees = match self.data.input_trees {
            InputTrees::One(_) => 1,
            InputTrees::Two { .. } => 2,
        };
        let start = RING_TRANSACT_ACCOUNT_PREFIX_LEN + trees + self.data.nullifiers.len();
        spp.len()
            .checked_sub(settlements)
            .and_then(|end| spp.get(start..end))
            .ok_or(CustomRingError::InvalidSettlementAccounts)
    }
}

struct Slot<T> {
    index: usize,
    expected: T,
}

impl Slot<CuratorRoot> {
    fn root(&self, accounts: &[AccountView], now: u64) -> Result<[u8; 32], ProgramError> {
        let account = account_at(accounts, self.index)?;
        if account.address() != &self.expected.registry {
            return Err(CustomRingError::InvalidCuratorRegistry.into());
        }
        Ok(load_curator_registry(account)?.curator_root(self.expected.root_index, now)?)
    }
}

enum SignerSlot {
    Owners,
    Payer,
    Delegate(Slot<Address>),
}

struct Prefix {
    curator: Option<Slot<CuratorRoot>>,
    co_signer: Option<Slot<Address>>,
    signer: SignerSlot,
    spp: usize,
}

struct Cursor(usize);

impl Cursor {
    fn slot<T>(&mut self, expected: T) -> Slot<T> {
        self.0 += 1;
        Slot {
            index: self.0 - 1,
            expected,
        }
    }
}

fn account_at(accounts: &[AccountView], index: usize) -> Result<&AccountView, ProgramError> {
    accounts
        .get(index)
        .ok_or(ProgramError::NotEnoughAccountKeys)
}

/// A policy transfer spends for exactly one owner, repeats of it are one signer.
fn sole_owner(owners: &[AccountView]) -> Result<&Address, CustomRingError> {
    let (first, rest) = owners
        .split_first()
        .ok_or(CustomRingError::OwnerSignerCount)?;
    if rest.iter().any(|owner| owner.address() != first.address()) {
        return Err(CustomRingError::OwnerSignerCount);
    }
    Ok(first.address())
}
