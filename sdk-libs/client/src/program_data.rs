//! The upgradeable loader's ProgramData account.

use solana_account::Account;
use solana_address::Address;
use zolana_interface::BPF_LOADER_UPGRADEABLE_ID;

/// Tag, slot and optional authority, the bytes before the program.
pub const PROGRAM_DATA_METADATA_LEN: usize = 45;
const PROGRAM_DATA_TAG: [u8; 4] = [3, 0, 0, 0];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProgramData {
    /// The slot of the last deploy or upgrade.
    pub slot: u64,
    /// `None` for an immutable program.
    pub upgrade_authority: Option<Address>,
    /// Bytes the program can grow into without an extend.
    pub capacity: usize,
}

/// `None` for an account the upgradeable loader does not own as ProgramData.
pub fn program_data(account: &Account) -> Option<ProgramData> {
    let data = &account.data;
    if account.owner.to_bytes() != BPF_LOADER_UPGRADEABLE_ID || data.get(..4)? != PROGRAM_DATA_TAG {
        return None;
    }
    let slot = u64::from_le_bytes(data.get(4..12)?.try_into().ok()?);
    let upgrade_authority = match *data.get(12)? {
        0 => None,
        1 => Some(Address::new_from_array(data.get(13..45)?.try_into().ok()?)),
        _ => return None,
    };
    Some(ProgramData {
        slot,
        upgrade_authority,
        capacity: data.len().saturating_sub(PROGRAM_DATA_METADATA_LEN),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(owner: [u8; 32], data: Vec<u8>) -> Account {
        Account {
            lamports: 1,
            data,
            owner: Address::new_from_array(owner),
            executable: false,
            rent_epoch: 0,
        }
    }

    fn header(slot: u64, authority: Option<[u8; 32]>) -> Vec<u8> {
        let mut data = PROGRAM_DATA_TAG.to_vec();
        data.extend(slot.to_le_bytes());
        match authority {
            Some(key) => {
                data.push(1);
                data.extend(key);
            }
            None => data.extend([0; 33]),
        }
        data
    }

    #[test]
    fn reads_the_slot_authority_and_capacity() {
        let mut data = header(7, Some([6; 32]));
        data.extend([0; 100]);
        assert_eq!(
            program_data(&account(BPF_LOADER_UPGRADEABLE_ID, data)),
            Some(ProgramData {
                slot: 7,
                upgrade_authority: Some(Address::new_from_array([6; 32])),
                capacity: 100,
            })
        );
        let immutable = program_data(&account(BPF_LOADER_UPGRADEABLE_ID, header(9, None)));
        assert_eq!(immutable.map(|data| data.upgrade_authority), Some(None));
    }

    #[test]
    fn refuses_another_owner_tag_or_option() {
        let valid = header(7, Some([6; 32]));
        assert_eq!(program_data(&account([1; 32], valid.clone())), None);
        let mut program = valid.clone();
        program[0] = 2;
        assert_eq!(
            program_data(&account(BPF_LOADER_UPGRADEABLE_ID, program)),
            None
        );
        let mut option = valid.clone();
        option[12] = 2;
        assert_eq!(
            program_data(&account(BPF_LOADER_UPGRADEABLE_ID, option)),
            None
        );
        assert_eq!(
            program_data(&account(BPF_LOADER_UPGRADEABLE_ID, valid[..20].to_vec())),
            None
        );
    }
}
