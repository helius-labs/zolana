//! Exclusive binding of a P256 owner identity to the record that carries it.
//!
//! `merge_transact` is permissionless and derives the merged owner's identity from
//! `UserRecord::owner_p256`. The registry writes that key on trust, so without an
//! exclusivity rule two records can carry the same identity and the pool has no way
//! to tell which one speaks for the owner. Every record that claims a key therefore
//! creates a [`P256OwnerClaim`] for it, and a claim is refused when the identity is
//! already spoken for.
//!
//! Two things can already speak for an identity:
//!
//! - another record's claim, and
//! - a registered Solana owner, because owner identity drops the SEC1 parity
//!   prefix: the identity of `0x02 || x` is the identity of the Solana address `x`.
//!   The registered owner's own record is that reservation, so the claim checks the
//!   record PDA of the x-coordinate read as an address.
//!
//! This is first-claim-wins, not proof of possession: it binds an identity to the
//! first record that asks for it. An attacker who claims a key before its holder
//! registers still holds it. Closing that needs a possession proof at registration.

use pinocchio::{cpi::Seed, error::ProgramError, AccountView, Address, ProgramResult};
use zolana_user_registry_interface::{
    owner_p256_identity, state::P256_PUBKEY_LEN, P256OwnerClaim, UserRecord, P256_OWNER_CLAIM_SEED,
    USER_RECORD_SEED,
};

use super::common::create_pda_account;
use crate::error::{fail, UserRegistryError};

/// A record's claim on the owner identity of `owner_p256`. `claim` is the identity's
/// claim PDA, `identity_record` the user record PDA of the x-coordinate read as a
/// Solana address, and `payer` funds the claim.
pub struct P256IdentityClaim<'a> {
    pub claim: &'a mut AccountView,
    pub identity_record: &'a AccountView,
    pub payer: &'a AccountView,
    pub owner_p256: [u8; P256_PUBKEY_LEN],
    pub record_owner: Address,
}

impl P256IdentityClaim<'_> {
    /// Bind the identity to `record_owner`, creating the claim on first use.
    /// Re-claiming an identity this owner already holds is a no-op, so rotating
    /// other keys or re-setting the same `owner_p256` stays possible.
    pub fn bind(self, program_id: &Address) -> ProgramResult {
        let identity = owner_p256_identity(&self.owner_p256);
        self.check_identity_is_not_a_registered_owner(&identity, program_id)?;

        let (expected_claim, bump) =
            Address::find_program_address(&[P256_OWNER_CLAIM_SEED, &identity], program_id);
        if self.claim.address() != &expected_claim {
            return Err(fail(UserRegistryError::InvalidP256ClaimAccount));
        }

        if self.claim.owned_by(program_id) {
            let data = self.claim.try_borrow()?;
            let held = P256OwnerClaim::try_from_account_data(&data)
                .map_err(|_| fail(UserRegistryError::InvalidP256ClaimAccount))?;
            if held.owner.as_array() != self.record_owner.as_array() {
                return Err(fail(UserRegistryError::P256IdentityAlreadyClaimed));
            }
            return Ok(());
        }

        if !self.claim.is_writable() || !self.claim.is_data_empty() {
            return Err(fail(UserRegistryError::InvalidP256ClaimAccount));
        }

        let bump_seed = [bump];
        let seeds = [
            Seed::from(P256_OWNER_CLAIM_SEED),
            Seed::from(&identity[..]),
            Seed::from(&bump_seed[..]),
        ];
        create_pda_account(
            self.claim,
            self.payer,
            &seeds,
            P256OwnerClaim::SPACE,
            program_id,
        )?;
        write_claim(
            self.claim,
            &P256OwnerClaim {
                owner: (*self.record_owner.as_array()).into(),
                bump,
            },
        )
    }

    /// A key whose x-coordinate is a registered owner's address has that owner's
    /// identity, so only that owner may claim it.
    fn check_identity_is_not_a_registered_owner(
        &self,
        identity: &[u8; 32],
        program_id: &Address,
    ) -> ProgramResult {
        let (expected, _) =
            Address::find_program_address(&[USER_RECORD_SEED, identity], program_id);
        if self.identity_record.address() != &expected {
            return Err(fail(UserRegistryError::InvalidP256IdentityAccount));
        }
        if identity == self.record_owner.as_array() {
            return Ok(());
        }
        if !self.identity_record.owned_by(program_id) {
            return Ok(());
        }
        let data = self.identity_record.try_borrow()?;
        if data.first() == Some(&UserRecord::DISCRIMINATOR) {
            return Err(fail(UserRegistryError::P256IdentityIsRegisteredOwner));
        }
        Ok(())
    }
}

fn write_claim(claim: &mut AccountView, state: &P256OwnerClaim) -> ProgramResult {
    let body = borsh::to_vec(state).map_err(|_| ProgramError::InvalidAccountData)?;
    let needed = P256OwnerClaim::DISCRIMINATOR_LEN + body.len();
    let mut data = claim.try_borrow_mut()?;
    if data.len() < needed {
        return Err(ProgramError::AccountDataTooSmall);
    }
    data[0] = P256OwnerClaim::DISCRIMINATOR;
    data[1..needed].copy_from_slice(&body);
    Ok(())
}
