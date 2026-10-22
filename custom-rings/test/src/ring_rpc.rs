//! The ring rpc a test serves in process for the operator cli.

use std::{
    net::{Ipv4Addr, TcpListener},
    sync::Arc,
    time::Duration,
};

use anyhow::{anyhow, Result};
use solana_address::Address;
use zolana_keypair::X25519Keypair;
use zolana_ring_rpc::{
    run_server, BindPolicy, ChainSource, Hub, ServerOptions, TransactionSource, Upstreams,
};

use crate::shared::TestEnv;

pub struct RingRpcSpec<'a> {
    pub env: &'a TestEnv,
    pub ring: Address,
    pub auditor: X25519Keypair,
}

pub struct LocalRingRpc {
    pub url: String,
    _runtime: tokio::runtime::Runtime,
}

impl RingRpcSpec<'_> {
    pub fn serve(self) -> Result<LocalRingRpc> {
        let runtime = tokio::runtime::Runtime::new()?;
        let source = ChainSource::connect(Upstreams {
            indexer_url: &self.env.indexer_url,
            rpc_url: &self.env.rpc_url,
            timeout: Duration::from_secs(30),
        })
        .map_err(|e| anyhow!("ring rpc upstreams {e:?}"))?;
        let genesis_hash = runtime
            .block_on(source.genesis_hash())
            .map_err(|e| anyhow!("genesis hash {e:?}"))?;
        let hub = Hub::builder(source, genesis_hash)
            .local(self.ring, self.auditor)
            .map_err(|e| anyhow!("hub {e:?}"))?;
        let port = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?
            .local_addr()?
            .port();
        let server = runtime
            .block_on(run_server(
                Arc::new(hub),
                ServerOptions {
                    bind: Ipv4Addr::LOCALHOST.into(),
                    bind_policy: BindPolicy::LoopbackOnly,
                    port,
                    max_connections: 16,
                    request_timeout: Duration::from_secs(30),
                },
            ))
            .map_err(|e| anyhow!("ring rpc server {e:?}"))?;
        // The server stops with its last handle, the task holds one until the
        // runtime goes.
        runtime.spawn(async move {
            let _server = server;
            std::future::pending::<()>().await;
        });
        Ok(LocalRingRpc {
            url: format!("http://127.0.0.1:{port}"),
            _runtime: runtime,
        })
    }
}
