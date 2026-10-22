use core::future::Future;

use zolana_client::IndexerPollConfig;

use crate::{heap::boxed, RingError};

/// `read` re-reads the chain state, a lagging answer holds only for the state it was asked under.
pub(crate) async fn retry_projection_lag<T, F: Future<Output = Result<T, RingError>>>(
    mut read: impl FnMut() -> F,
) -> Result<T, RingError> {
    let poll = IndexerPollConfig::default();
    let mut delays = poll.backoff();
    loop {
        match boxed(&mut read).await {
            Err(error) if error.is_projection_lag() => match delays.next() {
                Some(delay) => tokio::time::sleep(delay).await,
                None => return Err(error),
            },
            result => return result,
        }
    }
}
