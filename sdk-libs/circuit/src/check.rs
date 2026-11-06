//! Requirements that lower to constraints in the circuit build and become
//! recoverable errors when the same code runs natively.
//!
//! Xark's native `require`/`require_eq` panic, which traps a browser WASM
//! module and cannot be caught there. Native execution here records the first
//! failed requirement instead, and [`checked`] turns it into a
//! [`CircuitErrorKind::RequirementFailed`]. Execution continues after a failure
//! only to reach the enclosing [`checked`], which discards the result.
//!
//! Outside [`checked`] a failed requirement still panics, so native code that
//! never reaches a boundary cannot silently accept values the circuit rejects.
//! The panic message names the source location, never the compared values,
//! because those can be private inputs.
//!
//! This covers only the `require` and `require_eq` exported here. Checks inside
//! Xark itself still panic natively, inside [`checked`] too, and their message
//! includes the compared values: `xark::require_ne`, the range check of
//! `to_bits`, and inversion or division by zero. Client code must validate
//! values that could fail those before running circuit logic.

#[cfg(xark)]
pub use xark::{require, require_eq};

/// Runs circuit code. The circuit build has no native failures to collect.
#[cfg(xark)]
pub fn checked<T>(
    run: impl FnOnce() -> Result<T, crate::CircuitError>,
) -> Result<T, crate::CircuitError> {
    run()
}

#[cfg(not(xark))]
pub use native::{checked, require, require_eq};

#[cfg(not(xark))]
mod native {
    extern crate std;

    use core::cell::Cell;
    use core::panic::Location;

    use crate::{CircuitError, CircuitErrorKind};

    #[derive(Clone, Copy)]
    enum Scope {
        Outside,
        Passing,
        Failed(&'static Location<'static>),
    }

    std::thread_local! {
        static SCOPE: Cell<Scope> = const { Cell::new(Scope::Outside) };
    }

    fn fail(location: &'static Location<'static>) {
        SCOPE.with(|scope| match scope.get() {
            Scope::Outside => {
                panic!("requirement failed at {location} (the circuit rejects these values)")
            }
            Scope::Passing => scope.set(Scope::Failed(location)),
            Scope::Failed(_) => {}
        });
    }

    /// Requires `cond`. See the module docs for native behavior.
    #[track_caller]
    pub fn require(cond: bool) {
        if !cond {
            fail(Location::caller());
        }
    }

    /// Requires `a == b`. See the module docs for native behavior.
    #[track_caller]
    pub fn require_eq<A: PartialEq<B>, B>(a: A, b: B) {
        if a != b {
            fail(Location::caller());
        }
    }

    /// Restores the enclosing scope even when `run` unwinds.
    struct Restore(Scope);

    impl Drop for Restore {
        fn drop(&mut self) {
            SCOPE.with(|scope| scope.set(self.0));
        }
    }

    /// Runs circuit code natively and returns the first failed requirement as
    /// an error, ahead of whatever `run` returned.
    pub fn checked<T>(run: impl FnOnce() -> Result<T, CircuitError>) -> Result<T, CircuitError> {
        let restore = Restore(SCOPE.with(|scope| scope.replace(Scope::Passing)));
        let result = run();
        let inner = SCOPE.with(|scope| scope.get());
        drop(restore);
        match inner {
            Scope::Failed(location) => Err(CircuitErrorKind::RequirementFailed {
                file: location.file(),
                line: location.line(),
                column: location.column(),
            }
            .into()),
            Scope::Outside | Scope::Passing => result,
        }
    }
}
