//! The token account state SPP settles against, one reading for the program and the SDKs.

use solana_program_error::ProgramError;
use spl_token_2022_interface::{extension::PodStateWithExtensions, pod::PodAccount};

use crate::SPL_TOKEN_ACCOUNT_INITIALIZED;

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

impl TokenAccountState {
    pub fn unpack(data: &[u8]) -> Result<Self, ProgramError> {
        let state = PodStateWithExtensions::<PodAccount>::unpack(data)?;
        if state.base.state != SPL_TOKEN_ACCOUNT_INITIALIZED {
            return Err(ProgramError::InvalidAccountData);
        }
        let owner = state.base.owner.to_bytes();
        let control = match state.base.delegate.is_none() && state.base.close_authority.is_none() {
            true => TokenAccountControl::SoleOwner(owner),
            false => TokenAccountControl::Shared(owner),
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

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use spl_token_2022_interface::pod::PodCOption;

    use super::*;
    use crate::SPL_TOKEN_ACCOUNT_LEN;

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
}
