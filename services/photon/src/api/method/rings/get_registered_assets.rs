use std::collections::HashSet;

use sea_orm::DatabaseConnection;
use solana_account::Account;
use solana_pubkey::Pubkey;
use zolana_indexer_api::{GetRegisteredAssetsResponse, RegisteredAsset, SerializablePubkey};
use zolana_interface::{pda, state::SplAssetRegistry};

use crate::api::error::PhotonApiError;
use crate::common::indexer_context::extract as extract_context;
use crate::rpc::RpcClient;

const MAX_REGISTERED_ASSET_ACCOUNTS: usize = 4096; // parity with ring-rpc audit.rs MAX_ASSET_REGISTRY_ACCOUNTS
const SOL_ASSET_ID: u64 = 1;
const SOL_MINT: [u8; 32] = [0u8; 32];
// Matches `SOL_ASSET_ID` / `SOL_MINT` in sdk-libs/transaction/src/wallet/asset.rs.

fn sol_asset() -> RegisteredAsset {
    RegisteredAsset {
        mint: SerializablePubkey::from(SOL_MINT),
        asset_id: SOL_ASSET_ID,
    }
}

fn assets_from_accounts(
    accounts: Vec<(Pubkey, Account)>,
) -> Result<Vec<RegisteredAsset>, PhotonApiError> {
    if accounts.len() > MAX_REGISTERED_ASSET_ACCOUNTS {
        return Err(PhotonApiError::UnexpectedError(
            "asset registry response is too large".to_string(),
        ));
    }

    let program_id = pda::shielded_pool_program_id();
    let mut seen_ids = HashSet::new();
    let mut seen_mints = HashSet::new();
    let mut assets = Vec::new();

    for (_pubkey, account) in accounts {
        if account.owner != program_id {
            continue;
        }
        let Ok(registry) = SplAssetRegistry::from_account_bytes(&account.data) else {
            continue;
        };
        if registry.asset_id < 2 {
            continue;
        }
        let mint = registry.mint.to_bytes();
        if mint == SOL_MINT {
            continue;
        }
        if seen_ids.contains(&registry.asset_id) || seen_mints.contains(&mint) {
            continue;
        }
        seen_ids.insert(registry.asset_id);
        seen_mints.insert(mint);
        assets.push(RegisteredAsset {
            mint: SerializablePubkey::from(mint),
            asset_id: registry.asset_id,
        });
    }

    assets.sort_by_key(|asset| asset.asset_id);
    assets.insert(0, sol_asset());
    Ok(assets)
}

pub async fn get_registered_assets(
    conn: &DatabaseConnection,
    rpc: &RpcClient,
) -> Result<GetRegisteredAssetsResponse, PhotonApiError> {
    let context = extract_context(conn).await?;
    let accounts = rpc
        .get_spl_asset_registry_accounts(&pda::shielded_pool_program_id())
        .await
        .map_err(|error| PhotonApiError::UnexpectedError(format!("RPC error: {error}")))?;
    Ok(GetRegisteredAssetsResponse {
        context,
        assets: assets_from_accounts(accounts)?,
    })
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread::JoinHandle,
    };

    use super::*;
    use crate::dao::generated::blocks;
    use crate::migration::RingsMigrator;
    use sea_orm::{Database, DatabaseConnection, EntityTrait, Set};
    use sea_orm_migration::MigratorTrait;
    use zolana_interface::state::discriminator::SPL_ASSET_REGISTRY;

    fn serve_once(status: &str, body: &str) -> (String, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 4096];
            let _ = stream.read(&mut request).unwrap();
            stream.write_all(response.as_bytes()).unwrap();
        });
        (format!("http://{address}"), handle)
    }

    fn registry_data(mint: [u8; 32], asset_id: u64) -> Vec<u8> {
        let mut data = vec![0u8; SplAssetRegistry::SIZE];
        data[0] = SPL_ASSET_REGISTRY;
        data[8..40].copy_from_slice(&mint);
        data[40..48].copy_from_slice(&asset_id.to_le_bytes());
        data
    }

    fn account(data: Vec<u8>, owner: Pubkey) -> Account {
        Account {
            lamports: 1,
            data,
            owner,
            executable: false,
            rent_epoch: 0,
        }
    }

    fn registry_account(mint: [u8; 32], asset_id: u64) -> (Pubkey, Account) {
        (
            Pubkey::new_unique(),
            account(
                registry_data(mint, asset_id),
                pda::shielded_pool_program_id(),
            ),
        )
    }

    async fn setup_indexed() -> DatabaseConnection {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        RingsMigrator::up(&db, None).await.unwrap();
        blocks::Entity::insert(blocks::ActiveModel {
            slot: Set(7),
            parent_slot: Set(0),
            parent_blockhash: Set(vec![0; 32]),
            blockhash: Set(vec![1; 32]),
            block_height: Set(1),
            block_time: Set(1),
        })
        .exec(&db)
        .await
        .unwrap();
        db
    }

    #[test]
    fn assets_from_accounts_empty_is_sol_only() {
        assert_eq!(assets_from_accounts(Vec::new()).unwrap(), vec![sol_asset()]);
    }

    #[test]
    fn assets_from_accounts_keeps_one_valid_row() {
        let mint = [2u8; 32];
        let assets = assets_from_accounts(vec![registry_account(mint, 2)]).unwrap();
        assert_eq!(
            assets,
            vec![
                sol_asset(),
                RegisteredAsset {
                    mint: SerializablePubkey::from(mint),
                    asset_id: 2,
                },
            ]
        );
    }

    #[test]
    fn assets_from_accounts_skips_bad_discriminator() {
        let mut data = registry_data([2u8; 32], 2);
        data[0] = 1;
        let accounts = vec![(
            Pubkey::new_unique(),
            account(data, pda::shielded_pool_program_id()),
        )];
        assert_eq!(assets_from_accounts(accounts).unwrap(), vec![sol_asset()]);
    }

    #[test]
    fn assets_from_accounts_skips_reserved_sol_id() {
        let assets = assets_from_accounts(vec![registry_account([2u8; 32], 1)]).unwrap();
        assert_eq!(assets, vec![sol_asset()]);
    }

    #[test]
    fn assets_from_accounts_keeps_first_duplicate_asset_id() {
        let first = [3u8; 32];
        let second = [4u8; 32];
        let assets = assets_from_accounts(vec![
            registry_account(first, 5),
            registry_account(second, 5),
        ])
        .unwrap();
        assert_eq!(
            assets,
            vec![
                sol_asset(),
                RegisteredAsset {
                    mint: SerializablePubkey::from(first),
                    asset_id: 5,
                },
            ]
        );
    }

    #[test]
    fn assets_from_accounts_rejects_over_cap() {
        let accounts = (0..=MAX_REGISTERED_ASSET_ACCOUNTS)
            .map(|_| registry_account([2u8; 32], 2))
            .collect();
        let error = assets_from_accounts(accounts).unwrap_err();
        assert!(matches!(
            error,
            PhotonApiError::UnexpectedError(message)
                if message == "asset registry response is too large"
        ));
    }

    #[tokio::test]
    async fn get_registered_assets_returns_sol_when_gpa_empty() {
        let db = setup_indexed().await;
        let (url, server) = serve_once("200 OK", r#"{"jsonrpc":"2.0","id":1,"result":[]}"#);
        let response = get_registered_assets(&db, &RpcClient::new(url))
            .await
            .unwrap();
        server.join().unwrap();

        assert_eq!(response.context.slot, 7);
        assert_eq!(response.assets, vec![sol_asset()]);
    }

    #[tokio::test]
    async fn get_registered_assets_errors_when_unindexed() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        RingsMigrator::up(&db, None).await.unwrap();
        let error = get_registered_assets(&db, &RpcClient::new("http://127.0.0.1:1".to_string()))
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            PhotonApiError::RecordNotFound(message) if message == "No data has been indexed"
        ));
    }
}
