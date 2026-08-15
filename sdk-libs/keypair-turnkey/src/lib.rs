//! Turnkey-backed implementations of [`zolana_keypair::ShieldedKeypairTrait`].
//!
//! The shielded signing key stays in a Turnkey sub-organization and is used
//! remotely; the nullifier and viewing secrets are derived and held in this
//! process, which is what the trait's custody boundary requires — both are
//! private proof inputs, so no signing device can hold them on our behalf.
//!
//! # What Turnkey can and cannot root
//!
//! Both role secrets expand from a rail-specific `derivation_seed`, so whether
//! Turnkey can root an identity comes down to whether it can produce that seed:
//!
//! | | seed | Turnkey |
//! |---|---|---|
//! | ed25519 | RFC 8032 signature over a fixed message | **yes**, `SIGN_RAW_PAYLOAD_V2` |
//! | P-256 | `ECDH(signing_sk, P_derive)` | no key-agreement activity exists |
//!
//! So [`TurnkeyEd25519ShieldedKeypair`] is rooted entirely in Turnkey: one key
//! plus a [`TurnkeyKeyRef`] reproduces the whole identity, and there is no
//! secret to persist or lose. [`TurnkeyP256ShieldedKeypair`] can only borrow
//! Turnkey as a signing device and takes its role secrets from the caller, who
//! must then persist them.
//!
//! # What this is not
//!
//! Turnkey here is a key-availability and policy boundary, not a privacy
//! boundary. On the ed25519 rail the seed is a signature the key can always
//! produce, so a credential authorized to sign with it can re-derive full view
//! and spend capability. The signing methods refuse derivation-shaped payloads,
//! but that guard binds this process, not the credential.
//!
//! # Example
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use std::sync::Arc;
//!
//! use zolana_keypair::ShieldedKeypairTrait;
//! use zolana_keypair_turnkey::{
//!     TurnkeyApiActivities, TurnkeyEd25519ShieldedKeypair, TurnkeyKeyRef,
//! };
//! # let client: Arc<turnkey_client::TurnkeyClient<turnkey_client::TurnkeyP256ApiKey>> =
//! #     unimplemented!();
//!
//! let activities = Arc::new(TurnkeyApiActivities::new(client));
//! let wallet = TurnkeyEd25519ShieldedKeypair::bootstrap(
//!     activities,
//!     TurnkeyKeyRef::new("sub-org-id", "private-key-id"),
//! )
//! .await?;
//!
//! let address = wallet.shielded_address()?;
//! let signature = wallet.sign_message_async(&[7u8; 32]).await?;
//! # let _ = (address, signature);
//! # Ok(())
//! # }
//! ```

pub mod activities;
mod blocking;
mod codec;
pub mod ed25519_rail;
pub mod error;
pub mod p256_rail;

#[cfg(feature = "api")]
pub mod api;

pub use activities::{
    PayloadHashFunction, RawSignature, RemoteKey, TurnkeyActivities, TurnkeyCurve, TurnkeyKeyRef,
};
pub use ed25519_rail::TurnkeyEd25519ShieldedKeypair;
pub use error::TurnkeyKeypairError;
pub use p256_rail::TurnkeyP256ShieldedKeypair;

#[cfg(feature = "api")]
pub use api::TurnkeyApiActivities;
