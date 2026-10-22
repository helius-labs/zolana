//! The token account state SPP settles against, one reading for the program and the SDKs.

use solana_address::Address;
use solana_program_error::ProgramError;
use spl_token_2022_interface::{extension::PodStateWithExtensions, pod::PodAccount};

use crate::{error::ShieldedPoolError, SPL_TOKEN_ACCOUNT_INITIALIZED, SYSTEM_PROGRAM_ID};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenAccountControl {
    SoleOwner([u8; 32]),
    /// A delegate or a close authority acts beside the owner.
    Shared([u8; 32]),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenAccountState {
    pub mint: [u8; 32],
    pub control: TokenAccountControl,
}

#[derive(Clone, Copy, Debug)]
pub enum AnonymousExitDestination<'a> {
    Sol {
        recipient: &'a Address,
        owner: &'a Address,
        data_len: usize,
    },
    Spl {
        token_account: &'a Address,
        control: &'a TokenAccountControl,
    },
}

impl TokenAccountState {
    pub fn unpack(data: &[u8]) -> Result<Self, ProgramError> {
        let state = PodStateWithExtensions::<PodAccount>::unpack(data)?;
        if state.base.state != SPL_TOKEN_ACCOUNT_INITIALIZED {
            return Err(ProgramError::InvalidAccountData);
        }
        let owner = state.base.owner.to_bytes();
        let control = if state.base.delegate.is_none() && state.base.close_authority.is_none() {
            TokenAccountControl::SoleOwner(owner)
        } else {
            TokenAccountControl::Shared(owner)
        };
        Ok(Self {
            mint: state.base.mint.to_bytes(),
            control,
        })
    }
}

impl TokenAccountControl {
    pub fn owner(&self) -> &[u8; 32] {
        match self {
            Self::SoleOwner(owner) | Self::Shared(owner) => owner,
        }
    }
}

impl<'a> AnonymousExitDestination<'a> {
    /// The key the circuit proves apart from the hidden owner.
    pub fn named_key(self) -> Result<&'a [u8; 32], ShieldedPoolError> {
        match self {
            // Data or a program owner could name a second key.
            Self::Sol {
                recipient,
                owner,
                data_len,
            } => {
                if *owner == SYSTEM_PROGRAM_ID && data_len == 0 {
                    Ok(recipient.as_array())
                } else {
                    Err(ShieldedPoolError::AnonymousExitAccountHasData)
                }
            }
            // The circuit binds the owner only, a keypair address could be the hidden owner's.
            Self::Spl { token_account, .. } if token_account.is_on_curve() => {
                Err(ShieldedPoolError::AnonymousExitTokenAccountOnCurve)
            }
            Self::Spl {
                control: TokenAccountControl::SoleOwner(owner),
                ..
            } => Ok(owner),
            Self::Spl {
                control: TokenAccountControl::Shared(_),
                ..
            } => Err(ShieldedPoolError::AnonymousExitTokenAccountShared),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use spl_token_2022_interface::pod::PodCOption;

    use super::*;
    use crate::{SPL_TOKEN_ACCOUNT_LEN, SPL_TOKEN_PROGRAM_ID};

    const MINT: [u8; 32] = [1; 32];
    const OWNER: [u8; 32] = [2; 32];

    fn account(edit: impl FnOnce(&mut PodAccount)) -> Vec<u8> {
        let mut state = PodAccount {
            mint: MINT.into(),
            owner: OWNER.into(),
            state: SPL_TOKEN_ACCOUNT_INITIALIZED,
            ..PodAccount::default()
        };
        edit(&mut state);
        bytemuck::bytes_of(&state).to_vec()
    }

    #[test]
    fn a_second_authority_shares_control_of_the_account() {
        let unpacked = |edit: fn(&mut PodAccount)| TokenAccountState::unpack(&account(edit));
        assert_eq!(
            unpacked(|_| {}),
            Ok(TokenAccountState {
                mint: MINT,
                control: TokenAccountControl::SoleOwner(OWNER),
            })
        );
        for edit in [
            (|state| state.delegate = PodCOption::some([3; 32].into())) as fn(&mut PodAccount),
            |state| state.close_authority = PodCOption::some([3; 32].into()),
        ] {
            assert_eq!(
                unpacked(edit).map(|state| state.control),
                Ok(TokenAccountControl::Shared(OWNER))
            );
        }
    }

    #[test]
    fn an_account_reads_only_in_the_layouts_the_token_programs_write() {
        let base = account(|_| {});
        let mut extended = base.clone();
        extended.extend_from_slice(&[2, 0, 0, 0, 0]);
        assert!(TokenAccountState::unpack(&extended).is_ok());
        let mut mint_typed = extended.clone();
        mint_typed[SPL_TOKEN_ACCOUNT_LEN] = 1;
        let mut multisig = base.clone();
        multisig.resize(355, 0);
        let frozen = account(|state| state.state = 2);
        for refused in [&base[..164], &mint_typed, &multisig, &frozen] {
            assert!(TokenAccountState::unpack(refused).is_err());
        }
    }

    #[test]
    fn an_anonymous_exit_names_one_key_or_the_refusal_spp_returns() {
        let (sole, shared) = (
            TokenAccountControl::SoleOwner(OWNER),
            TokenAccountControl::Shared(OWNER),
        );
        let wallet = Address::new_from_array([5; 32]);
        let token_program = Address::new_from_array(SPL_TOKEN_PROGRAM_ID);
        let off_curve = Address::new_from_array([0x44; 32]);
        let on_curve = Address::new_from_array([0x55; 32]);
        assert!(!off_curve.is_on_curve() && on_curve.is_on_curve());
        let sol = |owner, data_len| AnonymousExitDestination::Sol {
            recipient: &wallet,
            owner,
            data_len,
        };
        let spl = |token_account, control| AnonymousExitDestination::Spl {
            token_account,
            control,
        };
        for (exit, named) in [
            (sol(&SYSTEM_PROGRAM_ID, 0), Ok([5; 32])),
            (spl(&off_curve, &sole), Ok(OWNER)),
            (
                sol(&SYSTEM_PROGRAM_ID, 80),
                Err(ShieldedPoolError::AnonymousExitAccountHasData),
            ),
            (
                sol(&token_program, 0),
                Err(ShieldedPoolError::AnonymousExitAccountHasData),
            ),
            (
                spl(&on_curve, &sole),
                Err(ShieldedPoolError::AnonymousExitTokenAccountOnCurve),
            ),
            (
                spl(&off_curve, &shared),
                Err(ShieldedPoolError::AnonymousExitTokenAccountShared),
            ),
        ] {
            assert_eq!(exit.named_key().copied(), named, "{exit:?}");
        }
    }
}
