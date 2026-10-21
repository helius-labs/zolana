use core::{future::Future, pin::Pin};

/// Built here, an unoptimized poll keeps a stack slot for every future its caller builds.
pub(crate) fn boxed<F: Future>(make: impl FnOnce() -> F) -> Pin<Box<F>> {
    Box::pin(make())
}
