//! The token program and pool asset id of a mint, read from its accounts.

use std::collections::HashMap;

use solana_account::Account;
use solana_address::Address;
use zolana_client::{
    asset::{fetch_asset_id, fetch_token_program},
    ClientError, Rpc,
};
use zolana_interface::{pda, state::SplAssetRegistry, PROGRAM_ID_PUBKEY};
use zolana_transaction::{SOL_ASSET_ID, SOL_MINT};

const MINT: Address = Address::new_from_array([7; 32]);
const OTHER_PROGRAM: Address = Address::new_from_array([9; 32]);

/// Accounts by address; `get_account` is the only request it answers.
#[derive(Default)]
struct Accounts(HashMap<Address, Account>);

impl Accounts {
    fn with(mut self, address: Address, owner: Address, data: Vec<u8>) -> Self {
        self.0.insert(
            address,
            Account {
                lamports: 1,
                data,
                owner,
                executable: false,
                rent_epoch: 0,
            },
        );
        self
    }

    fn mint(self, token_program: Address) -> Self {
        self.with(MINT, token_program, vec![0; 82])
    }

    fn registry(self, owner: Address, mint: Address, asset_id: u64) -> Self {
        self.with(
            pda::spl_asset_registry(&MINT),
            owner,
            SplAssetRegistry::account_bytes(mint, asset_id).to_vec(),
        )
    }
}

impl Rpc for Accounts {
    fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
        Ok(self.0.get(&address).cloned())
    }
}

/// An `Rpc` that fails every request, so a lookup that succeeds with it made
/// none.
struct Offline;

impl Rpc for Offline {}

#[test]
fn token_program_is_the_mint_owner_for_spl_token_and_token_2022() {
    for token_program in [
        pda::spl_token_program_id(),
        pda::spl_token_2022_program_id(),
    ] {
        let rpc = Accounts::default().mint(token_program);
        assert_eq!(
            fetch_token_program(&rpc, MINT).unwrap(),
            Some(token_program)
        );
    }
}

#[test]
fn sol_has_no_token_program_and_the_reserved_asset_id_without_a_request() {
    assert_eq!(fetch_token_program(&Offline, SOL_MINT).unwrap(), None);
    assert_eq!(fetch_asset_id(&Offline, SOL_MINT).unwrap(), SOL_ASSET_ID);
}

#[test]
fn token_program_refuses_a_missing_mint_and_an_account_no_token_program_owns() {
    assert!(matches!(
        fetch_token_program(&Accounts::default(), MINT),
        Err(ClientError::SplMintNotFound { mint }) if mint == MINT
    ));
    assert!(matches!(
        fetch_token_program(&Accounts::default().mint(OTHER_PROGRAM), MINT),
        Err(ClientError::UnsupportedSplTokenProgram { mint, owner })
            if mint == MINT && owner == OTHER_PROGRAM
    ));
}

#[test]
fn asset_id_is_read_from_the_pool_registry_account_of_the_mint() {
    let rpc = Accounts::default().registry(PROGRAM_ID_PUBKEY, MINT, 5);
    assert_eq!(fetch_asset_id(&rpc, MINT).unwrap(), 5);
}

#[test]
fn a_mint_without_a_pool_owned_registry_account_is_not_registered() {
    let not_registered = |rpc: &Accounts| {
        matches!(
            fetch_asset_id(rpc, MINT),
            Err(ClientError::SplAssetNotRegistered { mint }) if mint == MINT
        )
    };
    assert!(not_registered(
        &Accounts::default().mint(pda::spl_token_program_id())
    ));
    // Lamports sent to the registry address make a system-owned account.
    assert!(not_registered(&Accounts::default().with(
        pda::spl_asset_registry(&MINT),
        Address::default(),
        Vec::new(),
    )));
    assert!(not_registered(&Accounts::default().registry(
        OTHER_PROGRAM,
        MINT,
        5
    )));
}

#[test]
fn a_pool_registry_account_that_does_not_parse_or_names_another_mint_is_invalid() {
    let invalid = |rpc: &Accounts| {
        matches!(
            fetch_asset_id(rpc, MINT),
            Err(ClientError::InvalidSplAssetRegistry { mint }) if mint == MINT
        )
    };
    let mut truncated = SplAssetRegistry::account_bytes(MINT, 5).to_vec();
    truncated.pop();
    assert!(invalid(&Accounts::default().with(
        pda::spl_asset_registry(&MINT),
        PROGRAM_ID_PUBKEY,
        truncated,
    )));
    assert!(invalid(&Accounts::default().registry(
        PROGRAM_ID_PUBKEY,
        OTHER_PROGRAM,
        5
    )));
}
