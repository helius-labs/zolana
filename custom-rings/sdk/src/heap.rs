use core::{future::Future, pin::Pin};

/// Builds the future here and moves it to the heap. An unoptimized poll keeps a
/// stack slot for every future it builds, so the caller must not build it.
pub(crate) fn boxed<F: Future>(make: impl FnOnce() -> F) -> Pin<Box<F>> {
    Box::pin(make())
}
