//! Reads the forwarded SPP `TransactIxData` the ring proof binds to, and selects
//! the SPP settlement rail.

use pinocchio::error::ProgramError;
use zolana_interface::instruction::{
    tag::{RING_AUTHORITY_TRANSACT, RING_TRANSACT},
    CircuitId, InterfaceTransfer, TransactIxData as SppTransactIxData,
};
use zolana_squads_interface::{
    constants::{
        OWNER_KIND_SMART_ACCOUNT, PROOF_LEN, RECIPIENT_CIPHERTEXT_LEN, SENDER_CIPHERTEXT_LEN,
    },
    error::SquadsRingError,
};

/// Output slot of the sender change; a transfer's recipient output follows it.
pub const SENDER_OUTPUT_INDEX: usize = 0;
pub const RECIPIENT_OUTPUT_INDEX: usize = 1;

/// SPP settlement rail a spend is forwarded through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SppSettlementRail {
    /// Keypair owner: SPP `ring_transact` with an `AnonymousRingEddsa` proof;
    /// the Ed25519 signature binds the private transaction and external data.
    Ed25519,
    /// Smart-account owner (a Squads vault, no signing key): SPP
    /// `ring_authority_transact`; the ring authorizes via `ring_auth` and the
    /// co-signer (plus an approved proposal on the async path).
    RingAuthority,
}

impl SppSettlementRail {
    pub fn for_owner_kind(owner_kind: u8) -> Self {
        if owner_kind == OWNER_KIND_SMART_ACCOUNT {
            Self::RingAuthority
        } else {
            Self::Ed25519
        }
    }

    pub fn tag(self) -> u8 {
        match self {
            Self::Ed25519 => RING_TRANSACT,
            Self::RingAuthority => RING_AUTHORITY_TRANSACT,
        }
    }

    /// The forwarded circuit must be this rail's uncached variant.
    pub fn check_circuit(self, circuit: &CircuitId) -> Result<(), ProgramError> {
        let accepted = matches!(
            (self, circuit),
            (Self::Ed25519, CircuitId::AnonymousRingEddsa(..))
                | (Self::RingAuthority, CircuitId::RingAuthority(..))
        );
        if !accepted {
            return Err(SquadsRingError::InvalidInstructionData.into());
        }
        Ok(())
    }
}

/// The ring-relevant view of a forwarded SPP transact: the shape, the public
/// withdrawal amount, and the output ciphertexts the ring proof hashes.
pub struct SppTransact<'a> {
    pub spp: &'a SppTransactIxData,
    /// `Some` for a single-leg withdrawal, `None` for a transfer.
    pub public_amount: Option<u64>,
}

impl<'a> SppTransact<'a> {
    /// Accept exactly the ring's two operations: a `(2, 2)` transfer with no
    /// public leg, or a withdrawal with one published change output and one
    /// SOL/SPL withdrawal leg. Authority withdrawals also carry a dummy input
    /// to fit the supported SPP shape; their ring circuit remains `(1, 1)`.
    pub fn parse(spp: &'a SppTransactIxData) -> Result<Self, ProgramError> {
        let public_amount = match spp.interface_transfers.as_slice() {
            [] => None,
            [InterfaceTransfer::SolWithdrawal { amount }]
            | [InterfaceTransfer::SplWithdrawal { amount, .. }] => Some(*amount),
            _ => return Err(SquadsRingError::InvalidInstructionData.into()),
        };
        let shape = (spp.inputs.len(), spp.outputs.len());
        let valid = if public_amount.is_some() {
            matches!(shape, (1 | 2, 1))
        } else {
            shape == (2, 2)
        };
        if !valid {
            return Err(SquadsRingError::InvalidInstructionData.into());
        }
        Ok(Self { spp, public_amount })
    }

    pub fn is_transfer(&self) -> bool {
        self.public_amount.is_none()
    }

    /// `(n_inputs, n_outputs)`; selects the ring verifying key.
    pub fn shape(&self) -> (u8, u8) {
        if self.is_transfer() {
            (2, 2)
        } else {
            (1, 1)
        }
    }

    /// The public amount as a 32-byte big-endian field element; 0 for a
    /// transfer.
    pub fn public_amount_field(&self) -> [u8; 32] {
        let mut field = [0u8; 32];
        if let (Some(amount), Some(dst)) = (self.public_amount, field.get_mut(24..)) {
            dst.copy_from_slice(&amount.to_be_bytes());
        }
        field
    }

    pub fn sender_ciphertext(&self) -> Result<&'a [u8], ProgramError> {
        output_ciphertext(self.spp, SENDER_OUTPUT_INDEX, SENDER_CIPHERTEXT_LEN)
    }

    /// The recipient ciphertext of a transfer; `None` for a withdrawal.
    pub fn recipient_ciphertext(&self) -> Result<Option<&'a [u8]>, ProgramError> {
        if !self.is_transfer() {
            return Ok(None);
        }
        output_ciphertext(self.spp, RECIPIENT_OUTPUT_INDEX, RECIPIENT_CIPHERTEXT_LEN).map(Some)
    }
}

fn output_ciphertext(
    spp: &SppTransactIxData,
    index: usize,
    len: usize,
) -> Result<&[u8], ProgramError> {
    let ciphertext = spp
        .outputs
        .get(index)
        .and_then(|output| output.data.as_deref())
        .ok_or(SquadsRingError::InvalidInstructionData)?;
    if ciphertext.len() != len {
        return Err(SquadsRingError::InvalidInstructionData.into());
    }
    Ok(ciphertext)
}

/// The forwarded SPP instruction data: the rail tag followed by the SPP payload
/// bytes exactly as received (`ring_ix_data` minus the leading ring proof).
pub fn forwarded_spp_data(
    rail: SppSettlementRail,
    ring_ix_data: &[u8],
) -> Result<Vec<u8>, ProgramError> {
    let payload = ring_ix_data
        .get(PROOF_LEN..)
        .ok_or(SquadsRingError::InvalidInstructionData)?;
    let mut data = Vec::with_capacity(1 + payload.len());
    data.push(rail.tag());
    data.extend_from_slice(payload);
    Ok(data)
}

/// Recompute SPP's external-data hash from the exact forwarded payload and CPI
/// accounts. The settlement suffix and account-referenced owners use the same
/// canonical interface helpers as SPP.
pub fn external_data_hash(
    rail: SppSettlementRail,
    ring_instruction_data: &[u8],
    accounts: &[pinocchio::AccountView],
) -> Result<[u8; 32], ProgramError> {
    use zolana_interface::instruction::instruction_data::transact::{
        settlement_accounts, ExternalDataPreimage, TransactIxDataRef,
    };
    let error = SquadsRingError::InvalidInstructionData;
    let spp_instruction_data = ring_instruction_data.get(PROOF_LEN..).ok_or(error)?;
    let (ix, external_data_prefix) =
        TransactIxDataRef::parse_with_external_data_prefix(spp_instruction_data)
            .map_err(|_| error)?;
    let tag = [rail.tag()];
    let mut preimage = ExternalDataPreimage::new(&tag, external_data_prefix);
    let settlements =
        settlement_accounts(&ix.interface_transfers, ix.circuit, accounts).ok_or(error)?;
    let mut offset = 0usize;
    for transfer in &ix.interface_transfers {
        let group_end = offset
            .checked_add(transfer.settlement_account_count())
            .ok_or(error)?;
        let group = settlements.get(offset..group_end).ok_or(error)?;
        let (asset_index, user_index) = match transfer {
            InterfaceTransfer::SolWithdrawal { .. } => (0, 1),
            InterfaceTransfer::SplWithdrawal { .. } => (1, 3),
            _ => return Err(error.into()),
        };
        preimage
            .push_settlement(
                group.get(asset_index).ok_or(error)?.address().as_array(),
                group.get(user_index).ok_or(error)?.address().as_array(),
            )
            .map_err(|_| error)?;
        offset = group_end;
    }
    // Inline owners add no suffix. Account owners must borrow the actual
    // forwarded account address so the preimage retains valid references.
    for output in &ix.outputs {
        if let zolana_interface::instruction::OwnerTag::Account(index) = output.owner_tag {
            let account = accounts.get(usize::from(index)).ok_or(error)?;
            preimage
                .push_owner_tag(&output.owner_tag, account.address().as_array())
                .map_err(|_| error)?;
        }
    }
    preimage.finish().map_err(|_| error.into())
}
