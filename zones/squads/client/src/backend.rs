//! `SquadsBackend`: holds the auditor P-256 key and the co-signer, wraps an
//! indexer and a Solana RPC handle, and resolves each account's shared viewing
//! key from the auditor ciphertext so it can decrypt everything the account owns.

use p256::SecretKey;
use solana_keypair::Keypair;
use zolana_client::Rpc;
use zolana_keypair::P256Pubkey;
use zolana_squads_interface::{state::ViewingKeyAccount, types::Address};
use zolana_squads_sdk::{crypto, viewing_key_account::recover_nullifier_secret};

use crate::{
    crank::CrankHandle,
    error::{Result, SquadsBackendError},
};

/// The spec's SOL asset id (`docs/squads_policy_program.md`, Glossary).
pub const SOL_ASSET_ID: u64 = 1;

/// The auditor-recovered secrets for one viewing key account.
pub struct ResolvedAccount {
    /// Shared viewing secret key recovered from the auditor ciphertext.
    pub shared_viewing_sk: SecretKey,
    /// Nullifier secret recovered with the shared viewing key.
    pub nullifier_secret: [u8; 31],
    /// The decoded on-chain account.
    pub account: ViewingKeyAccount,
}

/// In-process Squads backend. Generic over the indexer handle `I` (tag/proof
/// queries) and the Solana RPC handle `R` (account reads + sends); a single type
/// implementing both may be passed for both.
pub struct SquadsBackend<I: Rpc, R: Rpc> {
    auditor_sk: SecretKey,
    zone_authority: Keypair,
    zone_config: Address,
    tree: Address,
    prover_url: String,
    indexer: I,
    rpc: R,
    /// Known assets as `(asset_id, mint)`; SOL (`1`, default mint) is always present.
    assets: Vec<(u64, Address)>,
    /// The background settlement crank, spawned by
    /// `SquadsBackend::new_with_crank`; absent when constructed from pre-built
    /// indexer/RPC instances ([`Self::new`], used by unit tests and the crank
    /// thread itself). Dropping the backend signals it to stop and joins its
    /// thread.
    crank: Option<CrankHandle>,
}

impl<I: Rpc, R: Rpc> SquadsBackend<I, R> {
    /// Construct from caller-supplied indexer/RPC instances, without a crank. Unit
    /// tests pass mocks here; production construction goes through the URL-based
    /// `SquadsBackend::new_with_crank`, which also starts the settlement crank.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        auditor_sk: SecretKey,
        zone_authority: Keypair,
        zone_config: Address,
        tree: Address,
        prover_url: impl Into<String>,
        indexer: I,
        rpc: R,
    ) -> Self {
        Self {
            auditor_sk,
            zone_authority,
            zone_config,
            tree,
            prover_url: prover_url.into(),
            indexer,
            rpc,
            assets: vec![(SOL_ASSET_ID, Address::default())],
            crank: None,
        }
    }

    /// The auditor secret the crank clones to run without the caller's handles.
    pub(crate) fn auditor_secret(&self) -> &SecretKey {
        &self.auditor_sk
    }

    /// The relayer/co-signer keypair the crank clones to sign settlements.
    pub(crate) fn zone_authority(&self) -> &Keypair {
        &self.zone_authority
    }

    /// Register an SPL asset so its UTXOs are attributed to `asset_id` / `mint`.
    pub fn register_asset(&mut self, asset_id: u64, mint: Address) {
        if !self.assets.iter().any(|(id, _)| *id == asset_id) {
            self.assets.push((asset_id, mint));
        }
    }

    pub fn assets(&self) -> &[(u64, Address)] {
        &self.assets
    }

    /// The `asset_id` registered for a mint, if any.
    pub fn asset_id_for_mint(&self, mint: &Address) -> Option<u64> {
        self.assets
            .iter()
            .find(|(_, m)| m == mint)
            .map(|(id, _)| *id)
    }

    /// The mint registered for an `asset_id`, if any.
    pub fn mint_for_asset_id(&self, asset_id: u64) -> Option<Address> {
        self.assets
            .iter()
            .find(|(id, _)| *id == asset_id)
            .map(|(_, m)| *m)
    }

    /// Load and decode a viewing key account's public fields (no decryption).
    pub fn load_viewing_key_account(
        &self,
        address: Address,
    ) -> Result<zolana_squads_interface::state::ViewingKeyAccount> {
        let account = self
            .rpc
            .get_account(address)?
            .ok_or_else(|| SquadsBackendError::AccountNotFound(address.to_string()))?;
        ViewingKeyAccount::deserialize(&account.data)
            .map_err(|_| SquadsBackendError::InvalidViewingKeyAccount(address.to_string()))
    }

    pub fn indexer(&self) -> &I {
        &self.indexer
    }

    pub fn rpc(&self) -> &R {
        &self.rpc
    }

    pub fn zone_authority_pubkey(&self) -> solana_pubkey::Pubkey {
        use solana_signer::Signer;
        solana_pubkey::Pubkey::new_from_array(self.zone_authority.pubkey().to_bytes())
    }

    /// The auditor's P-256 public key (the key published in `zone_config`).
    pub fn auditor_public_key(&self) -> p256::PublicKey {
        self.auditor_sk.public_key()
    }

    pub fn zone_config(&self) -> Address {
        self.zone_config
    }

    pub fn tree(&self) -> Address {
        self.tree
    }

    pub fn prover_url(&self) -> &str {
        &self.prover_url
    }

    /// Find the viewing key account whose `owner` (its `owner_pk_field`) matches
    /// `owner`, scanning the zone program's accounts. A proposal stores only the
    /// sender's / recipient's `owner_pk_field`, so the crank resolves the account
    /// address (and shared key) by this scan.
    pub fn find_viewing_key_account_by_owner(
        &self,
        owner: Address,
    ) -> Result<Option<(Address, ViewingKeyAccount)>> {
        let program_id = Address::new_from_array(zolana_squads_interface::SQUADS_ZONE_PROGRAM_ID);
        for (address, account) in self.rpc.get_program_accounts(program_id)? {
            let Ok(vka) = ViewingKeyAccount::deserialize(&account.data) else {
                continue;
            };
            if vka.discriminator == ViewingKeyAccount::DISCRIMINATOR && vka.owner == owner {
                return Ok(Some((address, vka)));
            }
        }
        Ok(None)
    }

    /// Fetch a viewing key account and recover its shared viewing key + nullifier
    /// secret using the backend's auditor secret. The recovered shared key is
    /// validated against the account's published `shared_viewing_key`.
    pub fn resolve_shared_key(&self, viewing_key_account: Address) -> Result<ResolvedAccount> {
        let account = self
            .rpc
            .get_account(viewing_key_account)?
            .ok_or_else(|| SquadsBackendError::AccountNotFound(viewing_key_account.to_string()))?;

        let vka = ViewingKeyAccount::deserialize(&account.data).map_err(|_| {
            SquadsBackendError::InvalidViewingKeyAccount(viewing_key_account.to_string())
        })?;
        self.resolve_shared_key_from_vka(vka)
    }

    /// Recover a decoded viewing key account's shared viewing key + nullifier
    /// secret with the auditor secret, without re-fetching it (used when the
    /// account bytes are already in hand, e.g. from a program-account scan).
    pub fn resolve_shared_key_from_vka(&self, vka: ViewingKeyAccount) -> Result<ResolvedAccount> {
        if vka.discriminator != ViewingKeyAccount::DISCRIMINATOR {
            return Err(SquadsBackendError::InvalidViewingKeyAccount(
                vka.owner.to_string(),
            ));
        }

        let ephemeral_pk = P256Pubkey::from_bytes(vka.key_ciphertext_ephemeral)
            .map_err(|e| SquadsBackendError::Keypair(format!("{e:?}")))?;
        let auditor_ct = vka.auditor_key_ciphertexts.first().ok_or_else(|| {
            SquadsBackendError::InvalidViewingKeyAccount(format!(
                "{}: no auditor ciphertext",
                vka.owner
            ))
        })?;

        let shared_be = zolana_squads_sdk::viewing_key_account::recover_shared_secret(
            &self.auditor_sk,
            &ephemeral_pk,
            auditor_ct,
        )?;
        let shared_viewing_sk = crypto::secret_key_from_be(&shared_be)
            .map_err(|e| SquadsBackendError::Crypto(format!("{e:?}")))?;

        let recovered_pubkey = P256Pubkey::from_p256(&shared_viewing_sk.public_key());
        if recovered_pubkey.as_bytes() != &vka.shared_viewing_key {
            return Err(SquadsBackendError::SharedKeyCommitmentMismatch);
        }

        let nullifier_secret = recover_nullifier_secret(
            &shared_viewing_sk,
            &ephemeral_pk,
            &vka.encrypted_nullifier_secret,
        )?;

        Ok(ResolvedAccount {
            shared_viewing_sk,
            nullifier_secret,
            account: vka,
        })
    }

    /// Store a spawned crank handle on the backend so dropping the backend stops it.
    pub(crate) fn set_crank(&mut self, handle: CrankHandle) {
        self.crank = Some(handle);
    }
}

impl<I: Rpc, R: Rpc> Drop for SquadsBackend<I, R> {
    fn drop(&mut self) {
        if let Some(crank) = self.crank.take() {
            crank.stop();
        }
    }
}

/// Right-align a 31-byte value into a 32-byte field element (zero top byte).
pub(crate) fn right_align_31(bytes: &[u8; 31]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[1..32].copy_from_slice(bytes);
    out
}
