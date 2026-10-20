//! The shielded pool's transact instruction as a CPI from a pinocchio program.

use alloc::vec::Vec;
use core::fmt;

use pinocchio::{
    address::address_eq,
    cpi::{invoke_signed_with_bounds, Signer},
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
    AccountView, Address, ProgramResult,
};
use zolana_interface::{instruction::tag::TRANSACT, PROGRAM_ID_PUBKEY};

/// The accounts a program forwards to the shielded pool's transact
/// instruction, in its layout: payer, output tree, the shielded-pool program,
/// the system program, then one tree per tree context, one nullifier PDA per
/// input, the owner signers and the interface-transfer account groups. The
/// shielded pool validates the layout; this checks the shielded-pool program
/// the CPI targets and the PDAs it signs for.
pub struct SppTransactAccounts<'a> {
    accounts: &'a [AccountView],
    signer_pdas: &'a [&'a Address],
}

impl<'a> SppTransactAccounts<'a> {
    /// `signer_pdas` are the program's PDAs among the transaction's owners.
    /// Each must be in `accounts`; the CPI marks it a signer and signs for it
    /// with the seeds passed to [`Self::invoke`].
    pub fn new(
        accounts: &'a [AccountView],
        signer_pdas: &'a [&'a Address],
    ) -> Result<Self, TransactAccountsError> {
        let spp_program = accounts
            .get(2)
            .ok_or(TransactAccountsError::NotEnoughAccounts)?;
        if !address_eq(spp_program.address(), &PROGRAM_ID_PUBKEY) {
            return Err(TransactAccountsError::InvalidSppProgram);
        }
        if let Some(index) = signer_pdas.iter().position(|pda| {
            !accounts
                .iter()
                .any(|account| address_eq(account.address(), pda))
        }) {
            return Err(TransactAccountsError::MissingPdaSigner { index });
        }
        Ok(Self {
            accounts,
            signer_pdas,
        })
    }

    /// The tree every output is appended to.
    pub fn output_tree(&self) -> Result<&AccountView, TransactAccountsError> {
        self.accounts
            .get(1)
            .ok_or(TransactAccountsError::NotEnoughAccounts)
    }

    /// Whether the CPI signs for `address`.
    pub fn signs_for(&self, address: &Address) -> bool {
        self.signer_pdas.iter().any(|pda| address_eq(address, pda))
    }

    /// Invokes transact with the serialized instruction data
    /// `transact_bytes`. `signers` holds the seeds of every signer PDA;
    /// `MAX_ACCOUNTS` bounds the account list the CPI copies onto the stack.
    pub fn invoke<const MAX_ACCOUNTS: usize>(
        &self,
        transact_bytes: &[u8],
        signers: &[Signer],
    ) -> ProgramResult {
        let metas: Vec<InstructionAccount> = self
            .accounts
            .iter()
            .map(|account| {
                let is_signer = account.is_signer() || self.signs_for(account.address());
                InstructionAccount::new(account.address(), account.is_writable(), is_signer)
            })
            .collect();
        let mut instruction_data = Vec::with_capacity(1 + transact_bytes.len());
        instruction_data.push(TRANSACT);
        instruction_data.extend_from_slice(transact_bytes);
        let instruction = InstructionView {
            program_id: &PROGRAM_ID_PUBKEY,
            accounts: &metas,
            data: &instruction_data,
        };
        invoke_signed_with_bounds::<MAX_ACCOUNTS, _>(&instruction, self.accounts, signers)
    }
}

/// An account list that is not the transact layout. It converts into
/// `ProgramError::Custom` with a code from [`Self::code`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactAccountsError {
    /// The account list is too short for the transact layout.
    NotEnoughAccounts,
    /// The shielded-pool program account is not the shielded pool.
    InvalidSppProgram,
    /// A PDA the program signs with is not in the account list; `index` is its
    /// position in the signer PDAs the program passed.
    MissingPdaSigner { index: usize },
}

impl TransactAccountsError {
    /// The error's `ProgramError::Custom` code. Codes are stable.
    pub fn code(&self) -> u32 {
        match self {
            Self::NotEnoughAccounts => 14100,
            Self::InvalidSppProgram => 14101,
            Self::MissingPdaSigner { .. } => 14102,
        }
    }
}

impl fmt::Display for TransactAccountsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotEnoughAccounts => "too few accounts for the transact layout",
            Self::InvalidSppProgram => "shielded-pool program account is invalid",
            Self::MissingPdaSigner { .. } => "a signing PDA is not in the transact accounts",
        })
    }
}

impl core::error::Error for TransactAccountsError {}

impl From<TransactAccountsError> for ProgramError {
    fn from(error: TransactAccountsError) -> Self {
        ProgramError::Custom(error.code())
    }
}
