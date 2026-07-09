//! SPL asset interface lookup and registration.
//!
//! Every SPL mint used in the shielded pool has a per-mint Asset registry PDA,
//! written when its interface is created; it is the canonical source of the
//! mint's `asset_id` on every deployment. SOL is asset id 1 and has no
//! registry entry.
//!
//! # Examples
//!
//! ```no_run
//! use solana_pubkey::Pubkey;
//! use solana_signer::Signer;
//! use zolana_client::{fetch_asset_id, register_spl_interface, ClientError, Rpc};
//!
//! fn asset_id<R: Rpc>(
//!     rpc: &R,
//!     authority: &dyn Signer,
//!     mint: Pubkey,
//! ) -> Result<u64, ClientError> {
//!     // Production path: read the canonical per-mint registry PDA.
//!     match fetch_asset_id(rpc, mint) {
//!         Err(ClientError::AssetNotRegistered { .. }) => {
//!             // Devnet / permissionless deployments only (see gating docs).
//!             register_spl_interface(rpc, authority, mint)
//!         }
//!         result => result,
//!     }
//! }
//! ```

use solana_address::Address;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::{
    instruction::{CreateAssetCounter, CreateSplInterface},
    pda,
    state::SplAssetRegistry,
};

use crate::{error::ClientError, rpc::Rpc};

/// Asset id assigned to `mint`, read from the canonical per-mint Asset
/// registry PDA. Works on every deployment regardless of who registered the
/// asset. SOL (asset id 1) has no registry entry; this lookup is for SPL
/// mints (ids >= 2).
pub fn fetch_asset_id<R: Rpc>(rpc: &R, mint: Pubkey) -> Result<u64, ClientError> {
    let registry_pda = pda::spl_asset_registry(&mint);
    let account = rpc
        .get_account(Address::new_from_array(registry_pda.to_bytes()))?
        .ok_or(ClientError::AssetNotRegistered { mint })?;
    let registry = SplAssetRegistry::from_account_bytes(&account.data).map_err(|err| {
        ClientError::Rpc(format!(
            "invalid asset registry account for {mint}: {err:?}"
        ))
    })?;
    // The PDA binds the mint; a mismatch means a forged account or program bug.
    if registry.mint != Address::new_from_array(mint.to_bytes()) {
        return Err(ClientError::Rpc(format!(
            "asset registry for {mint} stores a different mint"
        )));
    }
    Ok(registry.asset_id)
}

/// Create the SPL interface for `mint` and return its asset id; returns the
/// existing id when the mint is already registered (also when a concurrent
/// caller wins the registration race).
///
/// A devnet / permissionless-deployment tool, not a mainnet user API:
/// `create_spl_interface` requires `protocol_config.protocol_authority` unless
/// the deployment sets `spl_interface_creation_is_permissionless` (rejected
/// on-chain with `UnauthorizedCaller`, code 7003), and the one-time asset
/// counter bootstrap is always authority-gated. On gated deployments read ids
/// with [`fetch_asset_id`] instead.
pub fn register_spl_interface<R: Rpc>(
    rpc: &R,
    authority: &dyn Signer,
    mint: Pubkey,
) -> Result<u64, ClientError> {
    match fetch_asset_id(rpc, mint) {
        Err(ClientError::AssetNotRegistered { .. }) => {}
        result => return result,
    }

    let authority_address = Address::new_from_array(authority.pubkey().to_bytes());
    let counter = pda::spl_asset_counter();
    if rpc
        .get_account(Address::new_from_array(counter.to_bytes()))?
        .is_none()
    {
        let ix = CreateAssetCounter {
            authority: authority.pubkey(),
        }
        .instruction();
        rpc.create_and_send_transaction(&[ix], authority_address, &[authority])?;
    }

    let ix = CreateSplInterface {
        authority: authority.pubkey(),
        mint,
    }
    .instruction();
    if let Err(err) = rpc.create_and_send_transaction(&[ix], authority_address, &[authority]) {
        // A concurrent caller may have registered the mint between the lookup
        // and the send; the id is the outcome that matters.
        return match fetch_asset_id(rpc, mint) {
            Ok(asset_id) => Ok(asset_id),
            Err(_) => Err(ClientError::Rpc(format!(
                "create_spl_interface for {mint} rejected; interface creation is gated to the \
                 protocol authority unless the deployment enables permissionless creation: {err}"
            ))),
        };
    }
    fetch_asset_id(rpc, mint)
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, collections::HashMap};

    use solana_account::Account;
    use solana_hash::Hash;
    use solana_keypair::Keypair;
    use solana_signature::Signature;
    use solana_transaction::Transaction;
    use zolana_interface::SHIELDED_POOL_PROGRAM_ID;

    use super::*;

    #[derive(Default)]
    struct MockRpc {
        accounts: RefCell<HashMap<Address, Account>>,
        sent: RefCell<usize>,
    }

    impl MockRpc {
        fn with_registry(mint: Pubkey, asset_id: u64) -> Self {
            let rpc = Self::default();
            let registry_pda = pda::spl_asset_registry(&mint);
            rpc.accounts.borrow_mut().insert(
                Address::new_from_array(registry_pda.to_bytes()),
                registry_account(mint, asset_id),
            );
            rpc
        }
    }

    fn registry_account(mint: Pubkey, asset_id: u64) -> Account {
        Account {
            lamports: 1,
            data: SplAssetRegistry::account_bytes(
                Address::new_from_array(mint.to_bytes()),
                asset_id,
            )
            .to_vec(),
            owner: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
            executable: false,
            rent_epoch: 0,
        }
    }

    impl Rpc for MockRpc {
        fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
            Ok(self.accounts.borrow().get(&address).cloned())
        }

        fn get_latest_blockhash(&self) -> Result<(Hash, u64), ClientError> {
            Ok((Hash::default(), 0))
        }

        fn send_transaction(&self, _transaction: &Transaction) -> Result<Signature, ClientError> {
            *self.sent.borrow_mut() += 1;
            Ok(Signature::default())
        }
    }

    #[test]
    fn fetch_returns_the_registered_id() {
        let mint = Pubkey::new_unique();
        let rpc = MockRpc::with_registry(mint, 7);
        assert_eq!(fetch_asset_id(&rpc, mint).unwrap(), 7);
    }

    #[test]
    fn fetch_without_registry_is_asset_not_registered() {
        let mint = Pubkey::new_unique();
        let rpc = MockRpc::default();
        assert!(matches!(
            fetch_asset_id(&rpc, mint),
            Err(ClientError::AssetNotRegistered { mint: m }) if m == mint
        ));
    }

    #[test]
    fn fetch_rejects_a_registry_storing_a_different_mint() {
        let mint = Pubkey::new_unique();
        let rpc = MockRpc::default();
        let registry_pda = pda::spl_asset_registry(&mint);
        rpc.accounts.borrow_mut().insert(
            Address::new_from_array(registry_pda.to_bytes()),
            registry_account(Pubkey::new_unique(), 7),
        );
        assert!(matches!(
            fetch_asset_id(&rpc, mint),
            Err(ClientError::Rpc(message)) if message.contains("different mint")
        ));
    }

    #[test]
    fn register_short_circuits_to_the_existing_id() {
        let mint = Pubkey::new_unique();
        let rpc = MockRpc::with_registry(mint, 9);
        let authority = Keypair::new();
        assert_eq!(register_spl_interface(&rpc, &authority, mint).unwrap(), 9);
        assert_eq!(*rpc.sent.borrow(), 0);
    }
}
