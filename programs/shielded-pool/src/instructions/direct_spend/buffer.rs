use borsh::BorshDeserialize;
use pinocchio::{
    cpi::Seed,
    error::ProgramError,
    sysvars::{rent::Rent, Sysvar},
    AccountView, ProgramResult, Resize,
};
use zolana_account_checks::AccountIterator;
use zolana_interface::direct_spend::{
    BufferInstruction, Root, BUFFER_CHUNK_SIZE, BUFFER_HEADER_SIZE, BUFFER_SEED, MAX_PAYLOAD,
};

use crate::instructions::{
    create_tree::allocate::{create_account, grow_account, is_unallocated},
    shared::verify_pda,
};

pub const HEADER: usize = BUFFER_HEADER_SIZE;
const MAGIC: &[u8; 8] = b"ZSPEND1\0";
const APPEND: u8 = 0;
const CHUNKED: u8 = 1;

const _: () = assert!(MAX_PAYLOAD.div_ceil(BUFFER_CHUNK_SIZE) <= 32);

fn chunk_mask(size: usize) -> u32 {
    u32::MAX >> (32 - size.div_ceil(BUFFER_CHUNK_SIZE))
}

fn chunk_bitmap(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes[46..50].try_into().unwrap())
}

pub fn read(bytes: &[u8]) -> Result<Buffer<'_>, ProgramError> {
    if bytes.len() < HEADER || &bytes[..8] != MAGIC {
        return Err(ProgramError::InvalidAccountData);
    }
    let size = u16::from_le_bytes(bytes[40..42].try_into().unwrap()) as usize;
    let written = u16::from_le_bytes(bytes[42..44].try_into().unwrap()) as usize;
    if size == 0
        || size > MAX_PAYLOAD
        || written > size
        || bytes.len() > HEADER + size
        || bytes[44] > 2
        || bytes[45] > CHUNKED
    {
        return Err(ProgramError::InvalidAccountData);
    }
    if bytes[45] == CHUNKED && bytes[44] == 0 {
        let bitmap = chunk_bitmap(bytes);
        let last = 1 << (size.div_ceil(BUFFER_CHUNK_SIZE) - 1);
        let padding = size.div_ceil(BUFFER_CHUNK_SIZE) * BUFFER_CHUNK_SIZE - size;
        let received = bitmap.count_ones() as usize * BUFFER_CHUNK_SIZE
            - usize::from(bitmap & last != 0) * padding;
        if bitmap & !chunk_mask(size) != 0
            || received != written
            || bytes[50..HEADER].iter().any(|byte| *byte != 0)
        {
            return Err(ProgramError::InvalidAccountData);
        }
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
        if self.written != self.size
            || self.bytes.len() != HEADER + self.size
            || (self.bytes[45] == CHUNKED
                && self.status() == 0
                && chunk_bitmap(self.bytes) != chunk_mask(self.size))
        {
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

fn uploading(
    account: &AccountView,
    owner: &AccountView,
    mode: u8,
) -> Result<(usize, usize), ProgramError> {
    if !account.owned_by(&crate::ID) {
        return Err(ProgramError::IllegalOwner);
    }
    let bytes = account.try_borrow()?;
    let buffer = read(&bytes)?;
    if buffer.owner() != owner.address().as_array() || buffer.status() != 0 || bytes[45] != mode {
        return Err(ProgramError::InvalidArgument);
    }
    Ok((buffer.size, buffer.written))
}

pub fn process_buffer(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let instruction = BufferInstruction::try_from_slice(data)
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    let mut iter = AccountIterator::new(accounts);
    let owner = iter.next_signer_mut("owner")?;
    let account = iter.next_mut("buffer")?;
    let chunked = matches!(&instruction, BufferInstruction::CreateChunked { .. });
    match instruction {
        BufferInstruction::Create { nonce, size }
        | BufferInstruction::CreateChunked { nonce, size } => {
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
            bytes[45] = u8::from(chunked);
        }
        BufferInstruction::Write {
            offset,
            bytes: chunk,
        } => {
            let (size, written) = uploading(account, owner, APPEND)?;
            if usize::from(offset) != written || chunk.is_empty() {
                return Err(ProgramError::InvalidArgument);
            }
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
        BufferInstruction::Grow => {
            let (size, _) = uploading(account, owner, CHUNKED)?;
            grow_account(account, HEADER + size)?;
        }
        BufferInstruction::WriteChunk {
            index,
            bytes: chunk,
        } => {
            let (size, written) = uploading(account, owner, CHUNKED)?;
            let start = usize::from(index) * BUFFER_CHUNK_SIZE;
            if account.data_len() != HEADER + size
                || start >= size
                || chunk.len() != BUFFER_CHUNK_SIZE.min(size - start)
            {
                return Err(ProgramError::InvalidArgument);
            }
            let mut bytes = account.try_borrow_mut()?;
            let bitmap = chunk_bitmap(&bytes);
            let bit = 1u32 << index;
            let destination = &mut bytes[HEADER + start..HEADER + start + chunk.len()];
            if bitmap & bit != 0 {
                return if destination == chunk {
                    Ok(())
                } else {
                    Err(ProgramError::InvalidArgument)
                };
            }
            destination.copy_from_slice(&chunk);
            bytes[42..44].copy_from_slice(&((written + chunk.len()) as u16).to_le_bytes());
            bytes[46..50].copy_from_slice(&(bitmap | bit).to_le_bytes());
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

#[cfg(test)]
mod tests {
    use super::*;

    fn complete() -> Vec<u8> {
        let size = BUFFER_CHUNK_SIZE + 1;
        let mut bytes = vec![0; HEADER + size];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[40..42].copy_from_slice(&(size as u16).to_le_bytes());
        bytes[42..44].copy_from_slice(&(size as u16).to_le_bytes());
        bytes[45] = CHUNKED;
        bytes[46..50].copy_from_slice(&3u32.to_le_bytes());
        bytes
    }

    #[test]
    fn prepared_freshness_replaces_only_a_completed_bitmap() {
        let mut bytes = complete();
        assert!(read(&bytes).unwrap().payload().is_ok());
        let root = Root {
            index: 65535,
            value: [255; 32],
        };
        mark_prepared(&mut bytes, root);
        let buffer = read(&bytes).unwrap();
        assert_eq!(buffer.freshness(), root);
        assert!(buffer.payload().is_ok());
    }

    #[test]
    fn chunk_header_rejects_holes_and_invalid_metadata() {
        let complete = complete();
        for (offset, value) in [(44, 3), (45, 2), (46, 7), (50, 1)] {
            let mut bytes = complete.clone();
            bytes[offset] = value;
            assert!(read(&bytes).is_err());
        }
        let mut missing = complete.clone();
        missing[46..50].copy_from_slice(&1u32.to_le_bytes());
        assert!(read(&missing).is_err());
        missing[42..44].copy_from_slice(&(BUFFER_CHUNK_SIZE as u16).to_le_bytes());
        assert!(read(&missing).unwrap().payload().is_err());
        assert!(read(&complete[..HEADER - 1]).is_err());
    }
}
