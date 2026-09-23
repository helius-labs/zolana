use core::future::Future;

use zolana_client::IndexerPollConfig;

/// Photon trails or passed the chain state the read was asked under.
pub(crate) trait ProjectionLag {
    fn is_projection_lag(&self) -> bool;
}

/// `read` re-reads the chain state, a lagging answer holds only for the state it was asked under.
pub(crate) fn retry_projection_lag<T, E: ProjectionLag>(
    mut read: impl FnMut() -> Result<T, E>,
) -> Result<T, E> {
    let poll = IndexerPollConfig::default();
    let mut delays = poll.backoff();
    loop {
        match read() {
            Err(error) if error.is_projection_lag() => match delays.next() {
                Some(delay) => std::thread::sleep(delay),
                None => return Err(error),
            },
            result => return result,
        }
    }
}

pub(crate) async fn retry_projection_lag_async<T, E: ProjectionLag, F>(
    mut read: impl FnMut() -> F,
) -> Result<T, E>
where
    F: Future<Output = Result<T, E>>,
{
    let poll = IndexerPollConfig::default();
    let mut delays = poll.backoff();
    loop {
        match read().await {
            Err(error) if error.is_projection_lag() => match delays.next() {
                Some(delay) => tokio::time::sleep(delay).await,
                None => return Err(error),
            },
            result => return result,
        }
    }
}
