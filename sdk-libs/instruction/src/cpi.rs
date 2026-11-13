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
use spr_interface::{instruction::tag::TRANSACT, PROGRAM_ID_PUBKEY};

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
    /// `transact_bytes`, prepending the transact tag. `signers` holds the seeds
    /// of every signer PDA; `MAX_ACCOUNTS` bounds the account list the CPI
    /// copies onto the stack. Copying the data allocates; a program without a
    /// heap allocator uses [`Self::invoke_tagged`].
    pub fn invoke<const MAX_ACCOUNTS: usize>(
        &self,
        transact_bytes: &[u8],
        signers: &[Signer],
    ) -> ProgramResult {
        let mut instruction_data = Vec::with_capacity(1 + transact_bytes.len());
        instruction_data.push(TRANSACT);
        instruction_data.extend_from_slice(transact_bytes);
        self.invoke_tagged::<MAX_ACCOUNTS>(&instruction_data, signers)
    }

    /// Invokes transact with `instruction_data` exactly as given: the transact
    /// tag followed by the serialized transact data. Nothing is copied or
    /// allocated, so a program that receives the tagged bytes inside its own
    /// instruction data forwards that slice directly.
    pub fn invoke_tagged<const MAX_ACCOUNTS: usize>(
        &self,
        instruction_data: &[u8],
        signers: &[Signer],
    ) -> ProgramResult {
        if instruction_data.first() != Some(&TRANSACT) {
            return Err(TransactAccountsError::MissingTransactTag.into());
        }
        let metas = self.instruction_accounts::<MAX_ACCOUNTS>()?;
        let instruction = InstructionView {
            program_id: &PROGRAM_ID_PUBKEY,
            accounts: metas
                .get(..self.accounts.len())
                .ok_or(TransactAccountsError::TooManyAccounts)?,
            data: instruction_data,
        };
        invoke_signed_with_bounds::<MAX_ACCOUNTS, _>(&instruction, self.accounts, signers)
    }

    /// The CPI's account metas on the stack: every account keeps its writable
    /// and signer flags, and the signer PDAs become signers. Entries past
    /// `accounts.len()` are padding the CPI never reads.
    pub fn instruction_accounts<const MAX_ACCOUNTS: usize>(
        &self,
    ) -> Result<[InstructionAccount<'a>; MAX_ACCOUNTS], TransactAccountsError> {
        if self.accounts.len() > MAX_ACCOUNTS {
            return Err(TransactAccountsError::TooManyAccounts);
        }
        Ok(core::array::from_fn(|i| match self.accounts.get(i) {
            Some(account) => InstructionAccount::new(
                account.address(),
                account.is_writable(),
                account.is_signer() || self.signs_for(account.address()),
            ),
            None => InstructionAccount::readonly(&PROGRAM_ID_PUBKEY),
        }))
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
    /// The account list is longer than the CPI's `MAX_ACCOUNTS` bound.
    TooManyAccounts,
    /// The instruction data does not start with the transact tag.
    MissingTransactTag,
}

impl TransactAccountsError {
    /// The error's `ProgramError::Custom` code. Codes are stable.
    pub fn code(&self) -> u32 {
        match self {
            Self::NotEnoughAccounts => 14100,
            Self::InvalidSppProgram => 14101,
            Self::MissingPdaSigner { .. } => 14102,
            Self::TooManyAccounts => 14103,
            Self::MissingTransactTag => 14104,
        }
    }
}

impl fmt::Display for TransactAccountsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotEnoughAccounts => "too few accounts for the transact layout",
            Self::InvalidSppProgram => "shielded-pool program account is invalid",
            Self::MissingPdaSigner { .. } => "a signing PDA is not in the transact accounts",
            Self::TooManyAccounts => "more transact accounts than the CPI bound",
            Self::MissingTransactTag => "instruction data does not start with the transact tag",
        })
    }
}

impl core::error::Error for TransactAccountsError {}

impl From<TransactAccountsError> for ProgramError {
    fn from(error: TransactAccountsError) -> Self {
        ProgramError::Custom(error.code())
    }
}
