//! Addresses the client shares across instruction builders.

use solana_address::Address;
use zolana_interface::RING_AUTH_PDA_SEED;

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
