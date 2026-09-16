use borsh::BorshDeserialize;
use pinocchio::{
    cpi::Seed,
    error::ProgramError,
    sysvars::{rent::Rent, Sysvar},
    AccountView, ProgramResult, Resize,
};
use zolana_account_checks::AccountIterator;
use zolana_interface::direct_spend::{BufferInstruction, Root, BUFFER_SEED, MAX_PAYLOAD};

use crate::instructions::{
    create_tree::allocate::{create_account, grow_account, is_unallocated},
    shared::verify_pda,
};

pub const HEADER: usize = 80;
const MAGIC: &[u8; 8] = b"ZSPEND1\0";

pub fn read(bytes: &[u8]) -> Result<Buffer<'_>, ProgramError> {
    if bytes.len() < HEADER || &bytes[..8] != MAGIC {
        return Err(ProgramError::InvalidAccountData);
    }
    let size = u16::from_le_bytes(bytes[40..42].try_into().unwrap()) as usize;
    let written = u16::from_le_bytes(bytes[42..44].try_into().unwrap()) as usize;
    if size == 0 || size > MAX_PAYLOAD || written > size || bytes.len() > HEADER + size {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(Buffer {
        bytes,
        size,
        written,
    })
}

pub struct Buffer<'a> {
    bytes: &'a [u8],
    pub size: usize,
    pub written: usize,
}

impl Buffer<'_> {
    pub fn owner(&self) -> &[u8; 32] {
        self.bytes[8..40].try_into().unwrap()
    }
    pub fn status(&self) -> u8 {
        self.bytes[44]
    }
    pub fn freshness(&self) -> Root {
        Root {
            index: u16::from_le_bytes(self.bytes[46..48].try_into().unwrap()),
            value: self.bytes[48..80].try_into().unwrap(),
        }
    }
    pub fn payload(&self) -> Result<&[u8], ProgramError> {
        if self.written != self.size || self.bytes.len() != HEADER + self.size {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(&self.bytes[HEADER..])
    }
}

pub fn mark_prepared(bytes: &mut [u8], root: Root) {
    bytes[44] = 1;
    bytes[46..48].copy_from_slice(&root.index.to_le_bytes());
    bytes[48..80].copy_from_slice(&root.value);
}

pub fn mark_spent(bytes: &mut [u8]) {
    bytes[44] = 2;
}

pub fn process_buffer(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let instruction = BufferInstruction::try_from_slice(data)
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    let mut iter = AccountIterator::new(accounts);
    let owner = iter.next_signer_mut("owner")?;
    let account = iter.next_mut("buffer")?;
    match instruction {
        BufferInstruction::Create { nonce, size } => {
            let system = iter.next_account("system_program")?;
            if !pinocchio_system::check_id(system.address())
                || !is_unallocated(account)
                || size == 0
                || usize::from(size) > MAX_PAYLOAD
            {
                return Err(ProgramError::InvalidArgument);
            }
            let bump = [verify_pda(
                account.address(),
                &[BUFFER_SEED, owner.address().as_ref(), &nonce],
                &crate::ID,
            )?];
            let seeds = [
                Seed::from(BUFFER_SEED),
                Seed::from(owner.address().as_ref()),
                Seed::from(&nonce),
                Seed::from(&bump),
            ];
            let full_size = HEADER + usize::from(size);
            create_account(
                owner,
                account,
                &seeds,
                full_size,
                Rent::get()?.try_minimum_balance(full_size)?,
            )?;
            let mut bytes = account.try_borrow_mut()?;
            bytes[..8].copy_from_slice(MAGIC);
            bytes[8..40].copy_from_slice(owner.address().as_ref());
            bytes[40..42].copy_from_slice(&size.to_le_bytes());
        }
        BufferInstruction::Write {
            offset,
            bytes: chunk,
        } => {
            if !account.owned_by(&crate::ID) {
                return Err(ProgramError::IllegalOwner);
            }
            let size = {
                let bytes = account.try_borrow()?;
                let buffer = read(&bytes)?;
                if buffer.owner() != owner.address().as_array()
                    || buffer.status() != 0
                    || usize::from(offset) != buffer.written
                    || chunk.is_empty()
                {
                    return Err(ProgramError::InvalidArgument);
                }
                buffer.size
            };
            let end = usize::from(offset)
                .checked_add(chunk.len())
                .filter(|end| *end <= size)
                .ok_or(ProgramError::InvalidArgument)?;
            if account.data_len() < HEADER + end {
                grow_account(account, HEADER + size)?;
            }
            let mut bytes = account.try_borrow_mut()?;
            bytes
                .get_mut(HEADER + usize::from(offset)..HEADER + end)
                .ok_or(ProgramError::InvalidAccountData)?
                .copy_from_slice(&chunk);
            bytes[42..44].copy_from_slice(&(end as u16).to_le_bytes());
        }
        BufferInstruction::Close => {
            if !account.owned_by(&crate::ID)
                || read(&account.try_borrow()?)?.owner() != owner.address().as_array()
            {
                return Err(ProgramError::IllegalOwner);
            }
            let remaining = owner
                .lamports()
                .checked_add(account.lamports())
                .ok_or(ProgramError::ArithmeticOverflow)?;
            owner.set_lamports(remaining);
            account.set_lamports(0);
            account.resize(0)?;
            unsafe {
                account.assign(&pinocchio_system::ID);
            }
        }
    }
    Ok(())
}
