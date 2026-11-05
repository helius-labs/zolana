use spr_api::{BlockingSprApi, SprApi};

use crate::rpc::Blocking;

use super::AsyncSprIndexer;

/// Blocking client for the Zolana indexer: an [`AsyncSprIndexer`] run on a
/// Tokio runtime of its own, as `ProverClient` runs its async client.
pub type SprIndexer = Blocking<AsyncSprIndexer>;

impl Blocking<AsyncSprIndexer> {
    /// An indexer whose requests are each bounded by
    /// [`BlockingSprApi::new`]'s timeout.
    #[cfg(feature = "reqwest")]
    pub fn new(url: impl AsRef<str>) -> Self {
        Self::with_api(BlockingSprApi::new(url))
    }

    pub fn with_api(api: BlockingSprApi) -> Self {
        let (api, runtime) = api.into_parts();
        Self::with_runtime(AsyncSprIndexer::with_api(api), runtime)
    }

    pub fn with_http_trace(self) -> Self {
        self.map(AsyncSprIndexer::with_http_trace)
    }

    pub fn api(&self) -> &SprApi {
        self.get_ref().api()
    }
}

impl AsyncSprIndexer {
    /// This indexer for blocking callers, run on a Tokio runtime of its own.
    /// As with `SprApi::into_blocking`, give it an HTTP client of its own.
    pub fn into_blocking(self) -> SprIndexer {
        Blocking::on_new_runtime(self)
    }
}
