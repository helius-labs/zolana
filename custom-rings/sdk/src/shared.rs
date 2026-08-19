//! Addresses the client shares across instruction builders.

use solana_address::Address;
use zolana_interface::{BPF_LOADER_UPGRADEABLE_ID, RING_AUTH_PDA_SEED};

/// The program's singleton config account, holding the authority and the auditor
/// public key.
pub fn config_pda() -> Address {
    let (pda, _bump) = Address::find_program_address(
        &[custom_ring_program::CONFIG_PDA_SEED],
        &custom_ring_program::ID,
    );
    pda
}

/// The ring authority PDA. SPP stores the ring config under this address and
/// requires it as a signer on ring deposits and ring transacts, which is why the
/// program signs its CPIs with it.
pub fn ring_auth_pda() -> Address {
    let (pda, _bump) =
        Address::find_program_address(&[RING_AUTH_PDA_SEED], &custom_ring_program::ID);
    pda
}

/// The program's `ProgramData` account under the upgradeable BPF loader;
/// `create_config` reads the deploy upgrade authority from it.
pub fn program_data_pda() -> Address {
    let (pda, _bump) = Address::find_program_address(
        &[custom_ring_program::ID.as_ref()],
        &Address::new_from_array(BPF_LOADER_UPGRADEABLE_ID),
    );
    pda
}
