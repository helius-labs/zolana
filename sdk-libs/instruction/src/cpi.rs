//! The shielded pool's transact instruction as a CPI from a pinocchio program,
//! and the PDA signer a program signs it with.

use alloc::vec::Vec;
use core::fmt;

use pinocchio::{
    address::address_eq,
    cpi::{invoke_signed_with_bounds, Seed, Signer},
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

/// The seeds of a program-derived address without its bump: an array of one
/// to fifteen seeds, the most a PDA takes besides the bump.
pub trait PdaSeeds {
    /// The seeds with the bump appended, as a CPI signs with them.
    type WithBump<'s>: AsRef<[Seed<'s>]>
    where
        Self: 's;

    /// The seeds, as `Address::find_program_address` takes them.
    fn seeds(&self) -> &[&[u8]];

    /// The signer seeds: these seeds, then `bump`.
    fn signer_seeds<'s>(&'s self, bump: &'s [u8; 1]) -> Self::WithBump<'s>;
}

macro_rules! pda_seeds {
    ($($len:literal => [$($index:literal),+]),+ $(,)?) => {$(
        impl PdaSeeds for [&[u8]; $len] {
            type WithBump<'s> = [Seed<'s>; $len + 1] where Self: 's;

            #[inline(always)]
            fn seeds(&self) -> &[&[u8]] {
                self
            }

            #[inline(always)]
            fn signer_seeds<'s>(&'s self, bump: &'s [u8; 1]) -> Self::WithBump<'s> {
                [$(Seed::from(self[$index]),)+ Seed::from(bump)]
            }
        }
    )+};
}

pda_seeds! {
    1 => [0],
    2 => [0, 1],
    3 => [0, 1, 2],
    4 => [0, 1, 2, 3],
    5 => [0, 1, 2, 3, 4],
    6 => [0, 1, 2, 3, 4, 5],
    7 => [0, 1, 2, 3, 4, 5, 6],
    8 => [0, 1, 2, 3, 4, 5, 6, 7],
    9 => [0, 1, 2, 3, 4, 5, 6, 7, 8],
    10 => [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    11 => [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
    12 => [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
    13 => [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
    14 => [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13],
    15 => [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14],
}

/// A PDA of the calling program at its canonical bump, which the program signs
/// for in a CPI. `seeds` exclude the bump; [`Self::find`] derives it.
pub struct PdaSigner<S> {
    address: Address,
    seeds: S,
    bump: [u8; 1],
}

impl<S: PdaSeeds> PdaSigner<S> {
    /// Derives the PDA of `seeds` under `program_id`.
    #[inline(always)]
    pub fn find(seeds: S, program_id: &Address) -> Self {
        let (address, bump) = Address::find_program_address(seeds.seeds(), program_id);
        Self {
            address,
            seeds,
            bump: [bump],
        }
    }

    pub fn address(&self) -> &Address {
        &self.address
    }

    pub fn bump(&self) -> u8 {
        self.bump[0]
    }

    /// The seeds and the bump, for a [`Signer`] of any CPI.
    #[inline(always)]
    pub fn signer_seeds(&self) -> S::WithBump<'_> {
        self.seeds.signer_seeds(&self.bump)
    }

    /// Invokes transact with the serialized instruction data
    /// `transact_bytes` through `accounts`, signing for this PDA, which must
    /// be one of them. `MAX_ACCOUNTS` is as in [`SppTransactAccounts::invoke`].
    #[inline(always)]
    pub fn invoke_transact<const MAX_ACCOUNTS: usize>(
        &self,
        accounts: &[AccountView],
        transact_bytes: &[u8],
    ) -> ProgramResult {
        let signer_pdas = [&self.address];
        let spp = SppTransactAccounts::new(accounts, &signer_pdas)?;
        let seeds = self.signer_seeds();
        spp.invoke::<MAX_ACCOUNTS>(transact_bytes, &[Signer::from(seeds.as_ref())])
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
