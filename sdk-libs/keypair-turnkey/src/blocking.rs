//! Driving one async Turnkey call from a synchronous trait method.
//!
//! The [`zolana_keypair::ShieldedKeypairTrait`] signing methods are
//! synchronous while every
//! Turnkey call is async, and `Runtime::block_on` panics when the calling thread
//! is already inside *any* runtime — which is exactly where a wallet service
//! calls from. So the future is driven by this executor's own runtime and the
//! calling thread waits on a channel instead:
//!
//! - inside a multi-thread runtime, the wait is wrapped in `block_in_place` so
//!   tokio hands the parked worker's tasks to another thread;
//! - inside a current-thread runtime there is no worker to hand off, so the
//!   caller's runtime stalls for the duration of the call. That is inherent to
//!   using a synchronous API from an async context, and is why every backend
//!   also exposes an `async` twin — prefer it whenever the caller is async.

use std::{future::Future, sync::mpsc};

use tokio::runtime::{Builder, Handle, Runtime, RuntimeFlavor};

use crate::error::TurnkeyKeypairError;

/// Owns the runtime that Turnkey requests are driven on.
///
/// `Option` only so [`Drop`] can take the runtime out; it is `Some` for the whole
/// useful life of the executor.
#[derive(Debug)]
pub(crate) struct Executor {
    runtime: Option<Runtime>,
}

impl Executor {
    /// One worker thread: the backends issue a single request at a time, and a
    /// synchronous caller is blocked for its duration anyway.
    pub(crate) fn new() -> Result<Self, TurnkeyKeypairError> {
        let runtime = Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("zolana-turnkey")
            .enable_all()
            .build()
            .map_err(|error| TurnkeyKeypairError::Executor(error.to_string()))?;
        Ok(Self {
            runtime: Some(runtime),
        })
    }

    pub(crate) fn block_on<F, T>(&self, future: F) -> Result<T, TurnkeyKeypairError>
    where
        F: Future<Output = Result<T, TurnkeyKeypairError>> + Send + 'static,
        T: Send + 'static,
    {
        let runtime = self
            .runtime
            .as_ref()
            .ok_or_else(|| TurnkeyKeypairError::Executor("the executor has shut down".into()))?;

        let (sender, receiver) = mpsc::sync_channel(1);
        runtime.spawn(async move {
            // A closed channel means the caller is gone; nothing to report to.
            let _ = sender.send(future.await);
        });

        let received = match Handle::try_current() {
            Ok(handle) if handle.runtime_flavor() == RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(|| receiver.recv())
            }
            _ => receiver.recv(),
        };

        // Only reachable if the spawned task was dropped without sending, i.e.
        // the runtime shut down or the task panicked.
        received.map_err(|_| {
            TurnkeyKeypairError::Executor("the Turnkey request did not run to completion".into())
        })?
    }
}

/// Dropping a `Runtime` blocks until its workers stop, and tokio panics when
/// that happens inside an async context — which is exactly where a wallet handle
/// gets released. Hand the shutdown to a detached thread instead, so dropping a
/// backend is safe from anywhere.
impl Drop for Executor {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn ok(value: u8) -> Result<u8, TurnkeyKeypairError> {
        Ok(value)
    }

    /// The plain synchronous case, with no ambient runtime at all.
    #[test]
    fn runs_outside_any_runtime() {
        let executor = Executor::new().unwrap();
        assert_eq!(executor.block_on(ok(7)).unwrap(), 7);
    }

    /// The case a wallet service actually hits: a sync trait method called from
    /// inside a multi-thread runtime. `Runtime::block_on` would panic here.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn runs_inside_a_multi_thread_runtime() {
        let executor = Executor::new().unwrap();
        let value = tokio::task::spawn_blocking(move || executor.block_on(ok(9)))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(value, 9);
    }

    /// Called directly on a multi-thread runtime's worker, without an
    /// intervening `spawn_blocking`, which is the path `block_in_place` covers.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn runs_on_a_runtime_worker_thread() {
        let executor = Executor::new().unwrap();
        assert_eq!(executor.block_on(ok(11)).unwrap(), 11);
    }

    /// A current-thread caller stalls its own runtime but still completes,
    /// rather than panicking the way `Runtime::block_on` would.
    #[tokio::test(flavor = "current_thread")]
    async fn runs_inside_a_current_thread_runtime() {
        let executor = Executor::new().unwrap();
        assert_eq!(executor.block_on(ok(13)).unwrap(), 13);
    }

    /// Dropping the executor inside an async context must not panic. Without the
    /// `Drop` impl this is where tokio aborts with "cannot drop a runtime in a
    /// context where blocking is not allowed", taking the caller down with it.
    #[tokio::test(flavor = "current_thread")]
    async fn dropping_inside_an_async_context_is_safe() {
        drop(Executor::new().unwrap());

        let used = Executor::new().unwrap();
        assert_eq!(used.block_on(ok(15)).unwrap(), 15);
        drop(used);
    }
}
