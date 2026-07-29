//! Canonical parsers for the upgradeable BPF loader's (loader-v3) account
//! state, shared by the on-chain protocol-config initialization gate and
//! off-chain tooling (xtask). Pure byte ops: no allocation, SBF-compatible,
//! and malformed input yields `None` instead of panicking.
//!
//! Layouts are the bincode serialization of `UpgradeableLoaderState` (bincode
//! encodes the enum variant as a u32 tag and `Option` as a single byte):
//!
//! - `Program { programdata_address }`: u32 tag 2 || 32-byte address;
//! - `ProgramData { slot, upgrade_authority_address }`:
//!   u32 tag 3 || u64 slot || u8 option tag || optional 32-byte authority,
//!   followed by the program binary.

/// Parse the `ProgramData` address out of a loader-v3 `Program` account's
/// state (`UpgradeableLoaderState::Program`, variant tag 2).
pub fn parse_loader_v3_programdata_address(program_state: &[u8]) -> Option<[u8; 32]> {
    let (tag, address) = program_state.split_first_chunk::<4>()?;
    if u32::from_le_bytes(*tag) != 2 {
        return None;
    }
    address.first_chunk::<32>().copied()
}

/// Parse the upgrade authority out of a loader-v3 `ProgramData` account's
/// state (`UpgradeableLoaderState::ProgramData`, variant tag 3). Returns
/// `None` for malformed input; `Some(None)` for an unset authority and
/// `Some(Some(authority))` for a set one, including the zeroed authority
/// solana-test-validator writes for `--bpf-program` deployments (callers
/// decide what a zeroed authority means for their policy).
pub fn parse_loader_v3_upgrade_authority(programdata_state: &[u8]) -> Option<Option<[u8; 32]>> {
    let (tag, rest) = programdata_state.split_first_chunk::<4>()?;
    if u32::from_le_bytes(*tag) != 3 {
        return None;
    }
    let (_, rest) = rest.split_first_chunk::<8>()?;
    let (&option_tag, rest) = rest.split_first()?;
    match option_tag {
        0 => Some(None),
        1 => Some(Some(rest.first_chunk::<32>().copied()?)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn program_state(program_data_address: [u8; 32]) -> Vec<u8> {
        let mut state = 2u32.to_le_bytes().to_vec();
        state.extend_from_slice(&program_data_address);
        state
    }

    /// Real bincode layout of a loader-v3 `ProgramData` header:
    /// u32 tag 3 || slot u64 le || u8 option tag || 32-byte authority,
    /// followed by the program binary (ELF magic 0x7f 'E' 'L' 'F').
    fn program_data_state(authority: Option<[u8; 32]>) -> Vec<u8> {
        let mut state = 3u32.to_le_bytes().to_vec();
        state.extend_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
        match authority {
            Some(authority) => {
                state.push(1);
                state.extend_from_slice(&authority);
            }
            None => state.push(0),
        }
        state.extend_from_slice(&[0x7f, 0x45, 0x4c, 0x46]);
        state
    }

    #[test]
    fn parses_programdata_address() {
        let address = [0xAB; 32];
        assert_eq!(
            parse_loader_v3_programdata_address(&program_state(address)),
            Some(address)
        );
        assert_eq!(parse_loader_v3_programdata_address(&[]), None);
        assert_eq!(
            parse_loader_v3_programdata_address(&3u32.to_le_bytes()),
            None
        );
        // Wrong variant tag (ProgramData, not Program).
        assert_eq!(
            parse_loader_v3_programdata_address(&program_data_state(None)),
            None
        );
    }

    #[test]
    fn parses_upgrade_authority() {
        let authority = [0xCD; 32];
        assert_eq!(
            parse_loader_v3_upgrade_authority(&program_data_state(Some(authority))),
            Some(Some(authority))
        );
        assert_eq!(
            parse_loader_v3_upgrade_authority(&program_data_state(None)),
            Some(None)
        );
        // The solana-test-validator `--bpf-program` shape: authority set to
        // the zeroed address, ELF bytecode trailing the header. The parser
        // returns it raw; the zeroed-authority policy is the caller's.
        assert_eq!(
            parse_loader_v3_upgrade_authority(&program_data_state(Some([0u8; 32]))),
            Some(Some([0u8; 32]))
        );
        // Unknown option tag and truncated payloads fail closed.
        let mut bad_option = program_data_state(None);
        *bad_option.get_mut(12).expect("option tag byte") = 9;
        assert_eq!(parse_loader_v3_upgrade_authority(&bad_option), None);
        let mut truncated = program_data_state(Some(authority));
        truncated.truncate(20);
        assert_eq!(parse_loader_v3_upgrade_authority(&truncated), None);
        // Wrong variant tag (Program, not ProgramData).
        assert_eq!(
            parse_loader_v3_upgrade_authority(&program_state(authority)),
            None
        );
    }
}
