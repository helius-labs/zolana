use ark_ff::PrimeField;
use pinocchio::{
    cpi::{Seed, Signer},
    error::ProgramError,
    sysvars::clock::Clock,
    AccountView, Address, ProgramResult,
};
use zolana_interface::error::ShieldedPoolError;
use zolana_tree::TreeAccount;

/// Reject a transaction whose `expiry_unix_ts` has passed (or a negative clock).
/// Shared by every instruction that carries an `expiry_unix_ts`.
#[inline(always)]
pub fn check_not_expired(expiry_unix_ts: u64, clock: &Clock) -> ProgramResult {
    if clock.unix_timestamp < 0 || (clock.unix_timestamp as u64) > expiry_unix_ts {
        return Err(ShieldedPoolError::ExpiredTransaction.into());
    }
    Ok(())
}

/// BN254 scalar-field modulus `p` (big-endian) and `p-1` (the nullifier tree's
/// upper sentinel), derived from `ark_bn254` so there is one source of truth and
/// no hand-typed 32-byte literal. Nullifiers are field elements in this order, so
/// `[u8; 32]` ordering matches numeric ordering.
const MODULUS_BE: [u8; 32] = limbs_le_to_be(ark_bn254::Fr::MODULUS.0);
const MODULUS_MINUS_ONE_BE: [u8; 32] = sub_one_be(MODULUS_BE);

/// Little-endian u64 limbs (ark's `BigInt` order) to a big-endian byte array.
const fn limbs_le_to_be(limbs: [u64; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 4 {
        let b = limbs[i].to_be_bytes();
        let start = (3 - i) * 8;
        let mut j = 0;
        while j < 8 {
            out[start + j] = b[j];
            j += 1;
        }
        i += 1;
    }
    out
}

/// `value - 1` on a big-endian byte array (borrow propagates from the low byte).
const fn sub_one_be(mut be: [u8; 32]) -> [u8; 32] {
    let mut i = 32;
    while i > 0 {
        i -= 1;
        if be[i] == 0 {
            be[i] = 0xff;
        } else {
            be[i] -= 1;
            break;
        }
    }
    be
}

/// Reject nullifiers the indexed nullifier tree can never append: the low sentinel
/// `0`, the high sentinel `p-1`, and non-canonical values (`>= p`). Queuing one
/// wedges the forester batch and halts every spend. Private on purpose: the reject
/// is only sound paired with the insert, so [`queue_nullifier`] is the one caller.
#[inline(always)]
fn reject_reserved_nullifier(nullifier: &[u8; 32]) -> ProgramResult {
    if *nullifier == [0u8; 32] || *nullifier == MODULUS_MINUS_ONE_BE || *nullifier >= MODULUS_BE {
        return Err(ShieldedPoolError::ReservedNullifier.into());
    }
    Ok(())
}

/// The one sanctioned path from a program value into a tree's nullifier queue:
/// reject reserved values, then insert. Routing every insertion through here is
/// what makes the guard un-forgettable — a real input nullifier is already an
/// opaque Poseidon output (the circuit pins it), but the `merge_view_tag` shares
/// this queue for its duplicate check and is caller-chosen and unconstrained, so
/// it is the value that actually needs the sentinel reject.
#[inline(always)]
pub fn queue_nullifier(
    tree: &mut TreeAccount<'_>,
    nullifier: &[u8; 32],
    current_slot: &u64,
) -> ProgramResult {
    reject_reserved_nullifier(nullifier)?;
    tree.nullifer_tree()
        .insert_address_into_queue(nullifier, current_slot)
        .map_err(|_| ShieldedPoolError::NullifierTreeUpdateFailed.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Locks the ark-derived byte layout: p = 0x30644e72...f0000001 (big-endian).
    #[test]
    fn reserved_constants_and_reject() {
        assert_eq!(MODULUS_BE[0], 0x30);
        assert_eq!(MODULUS_BE[31], 0x01);
        assert_eq!(MODULUS_MINUS_ONE_BE[31], 0x00);
        assert_eq!(MODULUS_BE[..31], MODULUS_MINUS_ONE_BE[..31]);

        assert!(reject_reserved_nullifier(&[0u8; 32]).is_err()); // low sentinel
        assert!(reject_reserved_nullifier(&MODULUS_MINUS_ONE_BE).is_err()); // high sentinel
        assert!(reject_reserved_nullifier(&MODULUS_BE).is_err()); // == p, non-canonical
        assert!(reject_reserved_nullifier(&[0xffu8; 32]).is_err()); // > p

        let mut ok = [0u8; 32];
        ok[31] = 7;
        assert!(reject_reserved_nullifier(&ok).is_ok());
    }
}

/// Create a program-derived account. Handles both the hot path (the account has
/// no lamports) and the cold path (an attacker pre-funded the address) via the
/// pinocchio system helper; a raw `CreateAccount` would fail on a donated
/// balance and let an attacker DoS the creation.
///
/// `signer_seeds` must NOT include the bump; it is appended automatically.
pub struct CreatePdaAccount<'a, const N: usize> {
    pub fee_payer: &'a AccountView,
    pub new_account: &'a mut AccountView,
    pub space: usize,
    pub owner: &'a Address,
    pub signer_seeds: [&'a [u8]; N],
    pub bump: u8,
}

impl<const N: usize> CreatePdaAccount<'_, N> {
    #[inline(always)]
    pub fn execute(self) -> ProgramResult {
        let bump_seed = [self.bump];
        let s = self.signer_seeds;
        match N {
            1 => {
                let s0 = s.first().ok_or(ProgramError::InvalidArgument)?;
                let seeds = [Seed::from(*s0), Seed::from(bump_seed.as_ref())];
                pinocchio_system::create_account_with_minimum_balance_signed(
                    self.new_account,
                    self.space,
                    self.owner,
                    self.fee_payer,
                    None,
                    &[Signer::from(seeds.as_ref())],
                )
            }
            2 => {
                let s0 = s.first().ok_or(ProgramError::InvalidArgument)?;
                let s1 = s.get(1).ok_or(ProgramError::InvalidArgument)?;
                let seeds = [
                    Seed::from(*s0),
                    Seed::from(*s1),
                    Seed::from(bump_seed.as_ref()),
                ];
                pinocchio_system::create_account_with_minimum_balance_signed(
                    self.new_account,
                    self.space,
                    self.owner,
                    self.fee_payer,
                    None,
                    &[Signer::from(seeds.as_ref())],
                )
            }
            _ => Err(ProgramError::InvalidArgument),
        }
    }
}

/// Derive the canonical PDA from `seeds` and `program_id`, then verify it
/// matches `account_key`. Returns the canonical bump on success.
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
pub fn verify_pda(
    account_key: &Address,
    seeds: &[&[u8]],
    program_id: &Address,
) -> Result<u8, ProgramError> {
    use pinocchio::address::address_eq;
    use zolana_interface::error::ShieldedPoolError;

    let (derived, bump) = Address::find_program_address(seeds, program_id);
    if !address_eq(account_key, &derived) {
        return Err(ShieldedPoolError::InvalidPda.into());
    }
    Ok(bump)
}

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
pub fn verify_pda(
    _account_key: &Address,
    _seeds: &[&[u8]],
    _program_id: &Address,
) -> Result<u8, ProgramError> {
    unimplemented!("verify_pda requires Solana runtime syscalls")
}
